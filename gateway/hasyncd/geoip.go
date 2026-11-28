package hasyncd

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	geoIPRevisionFileName = ".revision.json"
	geoIPStagingDirName   = ".staging"
	geoIPBackupsDirName   = ".backups"
	geoIPMaxBackups       = 3
	geoIPSourceTypeHASync = "HA_SYNC"

	// XDB binary format constants (ip2region v2/v3).
	xdbHeaderSize        = 256
	xdbVectorIndexSize   = 256 * 256 * 8 // 524288
	xdbMinFileSize       = xdbHeaderSize + xdbVectorIndexSize
	xdbIndexPolicyVector = 1
	xdbSegSizeV4         = 14
	xdbSegSizeV6         = 38

	// MMDB binary format constants (MaxMind DB v2).
	mmdbMaxMetadataSearchBytes = 128 << 10 // 128 KiB tail scan window per MMDB spec
	mmdbDataTypeMap            = 7
)

var (
	mmdbMetadataMarker = []byte("\xab\xcd\xefMaxMind.com")
	geoIPRevisionRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	geoIPBackupIDRE    = regexp.MustCompile(`^[0-9]{10,14}-[0-9a-f]{12}\.(xdb|mmdb)$`)
)

// geoIPSlotSpec mirrors server/internal/apigeo.SlotSpec so hasyncd writes exact canonical files,
// archives shadowed legacy names, and produces rollback-compatible backups and .revision.json.
type geoIPSlotSpec struct {
	Slot              string
	CanonicalFile     string
	Format            string // "xdb" | "mmdb"
	Ext               string // ".xdb" | ".mmdb"
	RequiredIPVersion int    // 4 / 6 / 0
	MaxBytes          int64
	LegacyPatterns    []string
	FallbackPatterns  []string
}

var geoIPSlotOrder = []string{
	"ip2region_v4",
	"ip2region_v6",
	"dbip_city",
	"city_ipv6",
	"country",
}

var geoIPSlotSpecs = map[string]geoIPSlotSpec{
	"ip2region_v4": {
		Slot:              "ip2region_v4",
		CanonicalFile:     "ip2region_v4.xdb",
		Format:            "xdb",
		Ext:               ".xdb",
		RequiredIPVersion: 4,
		MaxBytes:          64 << 20, // 64 MiB
		LegacyPatterns:    []string{"ip2region.xdb"},
		FallbackPatterns:  []string{"ip2region_v4.xdb", "ip2region.xdb"},
	},
	"ip2region_v6": {
		Slot:              "ip2region_v6",
		CanonicalFile:     "ip2region_v6.xdb",
		Format:            "xdb",
		Ext:               ".xdb",
		RequiredIPVersion: 6,
		MaxBytes:          128 << 20, // 128 MiB
		FallbackPatterns:  []string{"ip2region_v6.xdb"},
	},
	"dbip_city": {
		Slot:              "dbip_city",
		CanonicalFile:     "city.mmdb",
		Format:            "mmdb",
		Ext:               ".mmdb",
		RequiredIPVersion: 0,
		MaxBytes:          256 << 20, // 256 MiB
		LegacyPatterns:    []string{"dbip-city-lite*.mmdb", "GeoLite2-City.mmdb"},
		FallbackPatterns:  []string{"dbip-city-lite*.mmdb", "city.mmdb", "GeoLite2-City.mmdb"},
	},
	"city_ipv6": {
		Slot:              "city_ipv6",
		CanonicalFile:     "city-ipv6.mmdb",
		Format:            "mmdb",
		Ext:               ".mmdb",
		RequiredIPVersion: 6,
		MaxBytes:          128 << 20, // 128 MiB
		FallbackPatterns:  []string{"city-ipv6.mmdb"},
	},
	"country": {
		Slot:              "country",
		CanonicalFile:     "country.mmdb",
		Format:            "mmdb",
		Ext:               ".mmdb",
		RequiredIPVersion: 0,
		MaxBytes:          32 << 20, // 32 MiB
		LegacyPatterns:    []string{"dbip-country-lite*.mmdb", "GeoLite2-Country.mmdb"},
		FallbackPatterns:  []string{"dbip-country-lite*.mmdb", "country.mmdb", "GeoLite2-Country.mmdb"},
	},
}

// AllowedGeoIPSlot reports whether slot is in the strict GeoIP slot allowlist.
func AllowedGeoIPSlot(slot string) bool {
	_, ok := geoIPSlotSpecs[slot]
	return ok
}

// ValidateGeoIPRevision validates X-GeoIP-Revision as a safe token without path separators or "..".
func ValidateGeoIPRevision(raw string) (string, error) {
	rev := strings.TrimSpace(raw)
	if rev == "" || strings.Contains(rev, "..") || !geoIPRevisionRE.MatchString(rev) {
		return "", errors.New("invalid X-GeoIP-Revision header")
	}
	return rev, nil
}

// geoIPRevisionState matches server/internal/apigeo.RevisionState JSON schema byte-for-byte
// so standby jiuzhang-api ReloadableEngine.Watch detects updates automatically.
type geoIPRevisionState struct {
	Revision  string                        `json:"revision"`
	UpdatedAt time.Time                     `json:"updated_at"`
	Slots     map[string]geoIPRevisionEntry `json:"slots"`
}

type geoIPRevisionEntry struct {
	Filename   string    `json:"filename"`
	SHA256     string    `json:"sha256"`
	SizeBytes  int64     `json:"size_bytes"`
	SourceType string    `json:"source_type"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (s *Server) handleGeoIPStatus(w http.ResponseWriter, r *http.Request, authInfo VerifiedAuth) {
	if _, ok := readAndVerifyBody(w, r, authInfo.BodySHA256, 1024); !ok {
		return
	}
	if s.geoIPDir == "" {
		writeJSONError(w, http.StatusServiceUnavailable, "geoip sync directory is not configured")
		return
	}

	s.geoIPMu.RLock()
	defer s.geoIPMu.RUnlock()

	ready := s.checkGeoIPReadyLocked()
	rev := s.readGeoIPRevisionLocked()
	slots := make(map[string]GeoIPSlotMeta)

	for _, slotName := range geoIPSlotOrder {
		spec := geoIPSlotSpecs[slotName]
		foundPath, fi := findFirstRegularGeoFile(s.geoIPDir, spec.FallbackPatterns)
		if foundPath == "" || fi == nil {
			continue
		}
		filename := filepath.Base(foundPath)
		sizeBytes := fi.Size()
		meta := GeoIPSlotMeta{
			Filename:  filename,
			SizeBytes: sizeBytes,
		}
		if rev != nil {
			if rec, ok := rev.Slots[slotName]; ok && rec.Filename == filename && rec.SizeBytes == sizeBytes && rec.SHA256 != "" {
				meta.SHA256 = rec.SHA256
				meta.SourceType = rec.SourceType
				if !rec.UpdatedAt.IsZero() {
					t := rec.UpdatedAt.UTC()
					meta.UpdatedAt = &t
				}
			}
		}
		if meta.SHA256 == "" {
			if sum, err := computeFileSHA256(foundPath); err == nil {
				meta.SHA256 = sum
			}
		}
		if meta.UpdatedAt == nil {
			mt := fi.ModTime().UTC()
			meta.UpdatedAt = &mt
		}
		slots[slotName] = meta
	}

	resp := GeoIPStatusResponse{
		Node:       s.cfg.NodeName,
		GeoIPReady: ready,
		Slots:      slots,
	}
	if rev != nil {
		resp.Revision = rev.Revision
		if !rev.UpdatedAt.IsZero() {
			t := rev.UpdatedAt.UTC()
			resp.UpdatedAt = &t
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleGeoIPSlotPut(w http.ResponseWriter, r *http.Request, authInfo VerifiedAuth, slot string) {
	if s.geoIPDir == "" {
		writeJSONError(w, http.StatusServiceUnavailable, "geoip sync directory is not configured")
		return
	}

	spec, ok := geoIPSlotSpecs[slot]
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "geoip slot not in allowlist")
		return
	}

	expectedSHA := strings.ToLower(strings.TrimSpace(r.Header.Get(HeaderGeoIPSHA256)))
	if !isValidHexToken(expectedSHA, 64, 64, true) {
		writeJSONError(w, http.StatusBadRequest, "missing or invalid X-GeoIP-SHA256 header")
		return
	}
	if !hmac.Equal([]byte(expectedSHA), []byte(authInfo.BodySHA256)) {
		writeJSONError(w, http.StatusBadRequest, "X-GeoIP-SHA256 does not match X-JZ-Body-SHA256")
		return
	}
	revision, err := ValidateGeoIPRevision(r.Header.Get(HeaderGeoIPRevision))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Extend deadlines for large GeoIP database streaming uploads, restoring on return.
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(15 * time.Minute))
	_ = rc.SetWriteDeadline(time.Now().Add(15 * time.Minute))
	defer func() {
		_ = rc.SetReadDeadline(time.Now().Add(30 * time.Second))
		_ = rc.SetWriteDeadline(time.Now().Add(60 * time.Second))
	}()

	stagingDir := filepath.Join(s.geoIPDir, geoIPStagingDirName)
	if err := ensureSafeDir(s.geoIPDir, 0o750); err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("prepare geoip dir failed: %v", err))
		return
	}
	if err := ensureSafeDir(stagingDir, 0o750); err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("prepare geoip staging dir failed: %v", err))
		return
	}

	tmp, err := os.CreateTemp(stagingDir, fmt.Sprintf(".%s-*.tmp", spec.Slot))
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "create geoip staging file failed")
		return
	}
	tmpName := tmp.Name()
	cleaned := false
	cleanup := func() {
		if !cleaned {
			cleaned = true
			_ = os.Remove(tmpName)
		}
	}
	defer cleanup()

	if err := tmp.Chmod(0o640); err != nil {
		_ = tmp.Close()
		writeJSONError(w, http.StatusInternalServerError, "chmod geoip staging file failed")
		return
	}

	maxBytes := s.slotMaxBytes(spec)
	hasher := sha256.New()
	limited := io.LimitReader(r.Body, maxBytes+1)
	written, err := io.Copy(tmp, io.TeeReader(limited, hasher))
	if err != nil {
		_ = tmp.Close()
		writeJSONError(w, http.StatusBadRequest, "read geoip stream failed")
		return
	}
	if written > maxBytes {
		_ = tmp.Close()
		writeJSONError(w, http.StatusRequestEntityTooLarge, "geoip file exceeds slot maximum allowed size")
		return
	}
	if written == 0 {
		_ = tmp.Close()
		writeJSONError(w, http.StatusBadRequest, "geoip file body is empty")
		return
	}

	actualSHA := hex.EncodeToString(hasher.Sum(nil))
	if !hmac.Equal([]byte(actualSHA), []byte(authInfo.BodySHA256)) {
		_ = tmp.Close()
		writeJSONError(w, http.StatusUnauthorized, "body sha256 mismatch")
		return
	}
	if !hmac.Equal([]byte(actualSHA), []byte(expectedSHA)) {
		_ = tmp.Close()
		writeJSONError(w, http.StatusBadRequest, "X-GeoIP-SHA256 mismatch")
		return
	}

	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		writeJSONError(w, http.StatusInternalServerError, "fsync geoip staging file failed")
		return
	}
	if err := tmp.Close(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "close geoip staging file failed")
		return
	}

	// Fast binary format validation before touching the active directory.
	if err := validateGeoIPBinaryFile(tmpName, spec); err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("geoip binary validation failed: %v", err))
		return
	}

	// Commit phase serialized across concurrent slot pushes so .revision.json never loses updates.
	s.geoIPMu.Lock()
	defer s.geoIPMu.Unlock()

	if err := s.ensureGeoIPDirsLocked(spec.Slot); err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("prepare geoip dirs failed: %v", err))
		return
	}

	activePath := filepath.Join(s.geoIPDir, spec.CanonicalFile)
	if err := checkNotSymlinkIfExists(activePath); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "geoip target path unsafe")
		return
	}

	var prevSHA string
	if fi, err := os.Lstat(activePath); err == nil && fi.Mode().IsRegular() && fi.Size() > 0 {
		if sum, sumErr := computeFileSHA256(activePath); sumErr == nil {
			prevSHA = sum
		}
	}

	legacyFiles := s.findLegacyGeoFilesLocked(spec)
	now := s.now().UTC()

	// Backup existing active file when content changes.
	if prevSHA != "" && prevSHA != actualSHA {
		if err := s.archiveGeoBackupLocked(spec, activePath, prevSHA, now); err != nil {
			writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("backup active geoip file failed: %v", err))
			return
		}
	}
	// Archive shadowed legacy filenames (e.g. dbip-city-lite*.mmdb when writing city.mmdb).
	for _, lf := range legacyFiles {
		sum, sumErr := computeFileSHA256(lf)
		if sumErr != nil {
			writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("hash legacy geoip file failed: %v", sumErr))
			return
		}
		if err := s.archiveGeoBackupLocked(spec, lf, sum, now); err != nil {
			writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("archive legacy geoip file failed: %v", err))
			return
		}
	}

	// Atomic replace active file over canonical filename.
	if err := os.Rename(tmpName, activePath); err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("commit geoip file failed: %v", err))
		return
	}
	cleaned = true

	// Remove shadowed legacy files now that canonical active file is committed.
	for _, lf := range legacyFiles {
		if filepath.Clean(lf) != filepath.Clean(activePath) {
			_ = os.Remove(lf)
		}
	}

	s.pruneGeoBackupsLocked(spec)

	// Atomically update .revision.json (same schema as server/internal/apigeo.RevisionState).
	rev := s.readGeoIPRevisionLocked()
	if rev == nil {
		rev = &geoIPRevisionState{Slots: make(map[string]geoIPRevisionEntry)}
	}
	if rev.Slots == nil {
		rev.Slots = make(map[string]geoIPRevisionEntry)
	}
	rev.Revision = revision
	rev.UpdatedAt = now
	rev.Slots[spec.Slot] = geoIPRevisionEntry{
		Filename:   spec.CanonicalFile,
		SHA256:     actualSHA,
		SizeBytes:  written,
		SourceType: geoIPSourceTypeHASync,
		UpdatedAt:  now,
	}
	if err := s.writeGeoIPRevisionLocked(rev); err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("write geoip revision failed: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, GeoIPSlotPushResponse{
		OK:        true,
		Node:      s.cfg.NodeName,
		Slot:      spec.Slot,
		Filename:  spec.CanonicalFile,
		SHA256:    actualSHA,
		SizeBytes: written,
		Revision:  revision,
		UpdatedAt: now,
	})
}

func (s *Server) slotMaxBytes(spec geoIPSlotSpec) int64 {
	if s.maxGeoIPBytes > 0 && s.maxGeoIPBytes < spec.MaxBytes {
		return s.maxGeoIPBytes
	}
	return spec.MaxBytes
}

func (s *Server) checkGeoIPReadyLocked() bool {
	if s.geoIPDir == "" {
		return false
	}
	err := checkNonSymlinkDir(s.geoIPDir)
	if err == nil {
		return true
	}
	if errors.Is(err, fs.ErrNotExist) {
		return checkNonSymlinkDir(filepath.Dir(s.geoIPDir)) == nil
	}
	return false
}

func (s *Server) ensureGeoIPDirsLocked(slot string) error {
	dirs := []string{
		s.geoIPDir,
		filepath.Join(s.geoIPDir, geoIPStagingDirName),
		filepath.Join(s.geoIPDir, geoIPBackupsDirName),
		filepath.Join(s.geoIPDir, geoIPBackupsDirName, slot),
	}
	for _, d := range dirs {
		if err := ensureSafeDir(d, 0o750); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) findLegacyGeoFilesLocked(spec geoIPSlotSpec) []string {
	var out []string
	seen := make(map[string]bool)
	for _, pat := range spec.LegacyPatterns {
		matches, err := filepath.Glob(filepath.Join(s.geoIPDir, pat))
		if err != nil {
			continue
		}
		for _, p := range matches {
			clean := filepath.Clean(p)
			if seen[clean] || filepath.Base(clean) == spec.CanonicalFile {
				continue
			}
			fi, err := os.Lstat(clean)
			if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() || fi.Size() <= 0 {
				continue
			}
			seen[clean] = true
			out = append(out, clean)
		}
	}
	sort.Strings(out)
	return out
}

func (s *Server) archiveGeoBackupLocked(spec geoIPSlotSpec, srcPath, sha string, now time.Time) error {
	if len(sha) < 12 {
		return nil
	}
	short := sha[:12]
	backupDir := filepath.Join(s.geoIPDir, geoIPBackupsDirName, spec.Slot)
	if entries, err := os.ReadDir(backupDir); err == nil {
		suffix := "-" + short + spec.Ext
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), suffix) {
				return nil
			}
		}
	}
	backupName := fmt.Sprintf("%d-%s%s", now.Unix(), short, spec.Ext)
	dstPath := filepath.Join(backupDir, backupName)
	if err := checkNotSymlinkIfExists(dstPath); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(backupDir, ".backup-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if err := tmp.Chmod(0o640); err != nil {
		_ = tmp.Close()
		return err
	}

	src, err := os.Open(srcPath)
	if err != nil {
		_ = tmp.Close()
		return err
	}
	written, copyErr := io.Copy(tmp, io.LimitReader(src, spec.MaxBytes+1))
	_ = src.Close()
	if copyErr != nil {
		_ = tmp.Close()
		return copyErr
	}
	if written > spec.MaxBytes {
		_ = tmp.Close()
		return errors.New("existing geoip file exceeds backup size cap")
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, dstPath)
}

func (s *Server) pruneGeoBackupsLocked(spec geoIPSlotSpec) {
	backupDir := filepath.Join(s.geoIPDir, geoIPBackupsDirName, spec.Slot)
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return
	}
	var names []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !geoIPBackupIDRE.MatchString(name) || !strings.HasSuffix(name, spec.Ext) {
			continue
		}
		names = append(names, name)
	}
	if len(names) <= geoIPMaxBackups {
		return
	}
	sort.Slice(names, func(i, j int) bool {
		return names[i] > names[j]
	})
	for _, old := range names[geoIPMaxBackups:] {
		_ = os.Remove(filepath.Join(backupDir, old))
	}
}

func (s *Server) readGeoIPRevisionLocked() *geoIPRevisionState {
	revPath := filepath.Join(s.geoIPDir, geoIPRevisionFileName)
	fi, err := os.Lstat(revPath)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() || fi.Size() <= 0 {
		return nil
	}
	f, err := os.Open(revPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, MaxJSONControlBytes+1))
	if err != nil || int64(len(raw)) > MaxJSONControlBytes {
		return nil
	}
	var rev geoIPRevisionState
	if err := json.Unmarshal(raw, &rev); err != nil {
		return nil
	}
	return &rev
}

func (s *Server) writeGeoIPRevisionLocked(rev *geoIPRevisionState) error {
	revPath := filepath.Join(s.geoIPDir, geoIPRevisionFileName)
	if err := checkNotSymlinkIfExists(revPath); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(rev, "", "  ")
	if err != nil {
		return err
	}
	stagingDir := filepath.Join(s.geoIPDir, geoIPStagingDirName)
	return writeBytesAtomic(stagingDir, revPath, ".revision-*.tmp", raw, 0o640)
}

func findFirstRegularGeoFile(dir string, patterns []string) (string, os.FileInfo) {
	for _, pat := range patterns {
		matches, err := filepath.Glob(filepath.Join(dir, pat))
		if err != nil {
			continue
		}
		sort.Strings(matches)
		for _, p := range matches {
			fi, err := os.Lstat(p)
			if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() || fi.Size() <= 0 {
				continue
			}
			return p, fi
		}
	}
	return "", nil
}

// validateGeoIPBinaryFile performs fast, zero-third-party-dependency format validation
// on a staged GeoIP database before atomic commit.
func validateGeoIPBinaryFile(path string, spec geoIPSlotSpec) error {
	switch spec.Format {
	case "xdb":
		return validateXDBFile(path, spec.RequiredIPVersion)
	case "mmdb":
		return validateMMDBFile(path)
	default:
		return fmt.Errorf("unsupported geoip format %q", spec.Format)
	}
}

// validateXDBFile verifies ip2region XDB v2/v3 header fields, size >= 524544 bytes,
// vector index policy == 1, index pointer bounds, and ip_version matching the slot.
func validateXDBFile(path string, expectedIPVersion int) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open xdb: %w", err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat xdb: %w", err)
	}
	fileSize := fi.Size()
	if fileSize < xdbMinFileSize {
		return fmt.Errorf("xdb too small (%d bytes, min %d)", fileSize, xdbMinFileSize)
	}

	var hdr [xdbHeaderSize]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return fmt.Errorf("read xdb header: %w", err)
	}

	version := binary.LittleEndian.Uint16(hdr[0:2])
	if version != 2 && version != 3 {
		return fmt.Errorf("xdb unsupported version %d", version)
	}
	policy := binary.LittleEndian.Uint16(hdr[2:4])
	if policy != xdbIndexPolicyVector {
		return fmt.Errorf("xdb unsupported index policy %d", policy)
	}
	startIdx := binary.LittleEndian.Uint32(hdr[8:12])
	endIdx := binary.LittleEndian.Uint32(hdr[12:16])
	if startIdx < xdbMinFileSize || endIdx < startIdx || uint64(endIdx) >= uint64(fileSize) {
		return fmt.Errorf("xdb invalid index range [%d, %d] (file size %d)", startIdx, endIdx, fileSize)
	}

	var ipVersion uint16 = 4
	var ptrBytes uint16 = 4
	if version >= 3 {
		ipVersion = binary.LittleEndian.Uint16(hdr[16:18])
		if ipVersion == 0 {
			ipVersion = 4
		}
		ptrBytes = binary.LittleEndian.Uint16(hdr[18:20])
		if ptrBytes == 0 {
			ptrBytes = 4
		}
	}
	if ptrBytes != 4 {
		return fmt.Errorf("xdb unsupported runtime_ptr_bytes %d", ptrBytes)
	}

	var segSize uint64
	switch ipVersion {
	case 4:
		segSize = xdbSegSizeV4
	case 6:
		segSize = xdbSegSizeV6
	default:
		return fmt.Errorf("xdb unsupported ip_version %d", ipVersion)
	}
	if uint64(endIdx)+segSize > uint64(fileSize) {
		return errors.New("xdb end index out of file bounds")
	}
	if expectedIPVersion != 0 && int(ipVersion) != expectedIPVersion {
		return fmt.Errorf("xdb ip_version %d does not match slot requirement IPv%d", ipVersion, expectedIPVersion)
	}
	return nil
}

// validateMMDBFile checks that the file tail (within MaxMind DB's 128 KiB metadata window)
// contains the "\xab\xcd\xefMaxMind.com" metadata marker followed by a metadata map tag.
func validateMMDBFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open mmdb: %w", err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat mmdb: %w", err)
	}
	fileSize := fi.Size()
	if fileSize < int64(len(mmdbMetadataMarker)+16) {
		return fmt.Errorf("mmdb too small (%d bytes)", fileSize)
	}

	readLen := fileSize
	if readLen > mmdbMaxMetadataSearchBytes {
		readLen = mmdbMaxMetadataSearchBytes
	}
	tail := make([]byte, readLen)
	if _, err := f.ReadAt(tail, fileSize-readLen); err != nil {
		return fmt.Errorf("read mmdb tail: %w", err)
	}

	markerAt := bytes.LastIndex(tail, mmdbMetadataMarker)
	if markerAt < 0 {
		return errors.New("mmdb metadata marker not found")
	}
	metaStart := markerAt + len(mmdbMetadataMarker)
	if metaStart >= len(tail) {
		return errors.New("mmdb metadata section is empty")
	}
	// MaxMind DB metadata MUST begin with a map data type (top 3 bits == 7).
	if (tail[metaStart] >> 5) != mmdbDataTypeMap {
		return errors.New("mmdb metadata root is not a map")
	}
	return nil
}
