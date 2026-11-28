package hasyncd

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// rulePackReleasePublicKeyPEM is the embedded production Ed25519 release public key
// (identical to server/internal/rulepacks/artifact.go and ops/offline-package/release-signing.pub).
// Never overridable via environment variable or CLI flag.
const rulePackReleasePublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAJBzjZs04R6NVLDuKoJsViPuBEGlo70z/zpnKi6ZHq2s=
-----END PUBLIC KEY-----`

const (
	rulePackSchemaVersion = 1
	rulePackProductWDSP   = "wdsp"
	rulePackPackageType   = "rulepack"
)

var (
	rulePackVersionRE     = regexp.MustCompile(`^([0-9]{8})\.([0-9]{1,3})$`)
	rulePackBuiltinRE     = regexp.MustCompile(`^builtin-[0-9A-Za-z._-]+$`)
	rulePackArchivePathRE = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

	rulePackRequiredAnchors = []string{
		"rules/coraza.conf",
		"rules/crs/crs-setup.conf",
		"rules/exclusions/before-crs.conf",
		"rules/exclusions/after-crs.conf",
		"rules/jiuzhang/jiuzhang-custom.conf",
		"rules/jiuzhang/post-contrib-blocking.conf",
	}

	rulePackCoreDiskAnchors = []string{
		"coraza.conf",
		"crs/crs-setup.conf",
		"jiuzhang/post-contrib-blocking.conf",
	}

	rulePackAllowedExts = map[string]bool{
		".conf":      true,
		".data":      true,
		".txt":       true,
		".md":        true,
		".example":   true,
		".gitkeep":   true,
		".gitignore": true,
	}

	rulePackAllowedBaseNames = map[string]bool{
		"LICENSE":   true,
		"NOTICE":    true,
		"INSTALL":   true,
		"PINNED":    true,
		"README":    true,
		"CHANGELOG": true,
	}
)

// ReleaseRulePackPublicKey parses and returns the embedded production Ed25519 public key.
func ReleaseRulePackPublicKey() (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(rulePackReleasePublicKeyPEM))
	if block == nil {
		return nil, errors.New("embedded rulepack public key PEM is invalid")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse embedded rulepack public key: %w", err)
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("embedded rulepack public key is not a valid Ed25519 key")
	}
	return append(ed25519.PublicKey(nil), pub...), nil
}

// ValidateRulePackVersion validates a formal offline rulepack version (YYYYMMDD.N with valid date and seq >= 1).
func ValidateRulePackVersion(v string) error {
	v = strings.TrimSpace(v)
	m := rulePackVersionRE.FindStringSubmatch(v)
	if m == nil {
		return fmt.Errorf("invalid rulepack version %q (expect YYYYMMDD.N)", v)
	}
	if _, err := time.Parse("20060102", m[1]); err != nil {
		return fmt.Errorf("invalid rulepack version date %q", v)
	}
	seq, err := strconv.Atoi(m[2])
	if err != nil || seq <= 0 {
		return fmt.Errorf("invalid rulepack version sequence %q", v)
	}
	return nil
}

// IsBuiltinRulePackVersion reports whether v matches builtin-<token>.
func IsBuiltinRulePackVersion(v string) bool {
	return rulePackBuiltinRE.MatchString(strings.TrimSpace(v))
}

// ValidateAnyRulePackReleaseVersion accepts either formal YYYYMMDD.N or builtin-* versions.
func ValidateAnyRulePackReleaseVersion(v string) error {
	v = strings.TrimSpace(v)
	if IsBuiltinRulePackVersion(v) {
		return nil
	}
	return ValidateRulePackVersion(v)
}

type rulePackManifest struct {
	SchemaVersion       int                    `json:"schema_version"`
	Product             string                 `json:"product"`
	PackageType         string                 `json:"package_type"`
	RulePackVersion     string                 `json:"rulepack_version"`
	CRSVersion          string                 `json:"crs_version"`
	MinSystemVersion    string                 `json:"min_system_version"`
	Files               []rulePackManifestFile `json:"files"`
	FilesManifestSHA256 string                 `json:"files_manifest_sha256"`
}

type rulePackManifestFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type rulePackArchiveFileInfo struct {
	size int64
	hash string
}

type rulePackRawEntry struct {
	path    string
	size    int64
	hash    string
	content []byte
}

type rulePackScannedArchive struct {
	root          string
	manifestBytes []byte
	manifestSig   []byte
	files         map[string]rulePackArchiveFileInfo
}

type verifiedRulePackArtifact struct {
	version        string
	manifestSHA256 string
	commonRoot     string
}

type rulePackSidecarMeta struct {
	Version        string    `json:"version"`
	ManifestSHA256 string    `json:"manifest_sha256"`
	FileSHA256     string    `json:"file_sha256,omitempty"`
	StagedAt       time.Time `json:"staged_at"`
}

func (s *Server) rulePackReleasesDir() string {
	return filepath.Join(s.rulesDir, "releases")
}

func (s *Server) rulePackStagingDir() string {
	return filepath.Join(s.rulesDir, ".staging")
}

func (s *Server) rulePackMetaDir() string {
	return filepath.Join(s.rulesDir, ".meta")
}

func (s *Server) rulePackMetaPath(version string) string {
	return filepath.Join(s.rulePackMetaDir(), version+".json")
}

func (s *Server) rulePackReleaseDir(version string) string {
	return filepath.Join(s.rulePackReleasesDir(), version)
}

func (s *Server) rulePackCurrentPath() string {
	return filepath.Join(s.rulesDir, "current")
}

// checkRulePackReady returns true only when RulesDir is configured, is a non-symlink directory,
// its releases/.staging/.meta subdirectories are safe, and the directory is writable.
func (s *Server) checkRulePackReady() bool {
	if s.rulesDir == "" {
		return false
	}
	if err := checkNonSymlinkDir(s.rulesDir); err != nil {
		return false
	}
	for _, sub := range []string{s.rulePackReleasesDir(), s.rulePackStagingDir(), s.rulePackMetaDir()} {
		if !isMissingOrSafeDir(sub) {
			return false
		}
	}
	if !isDirWritableProbe(s.rulesDir) {
		return false
	}
	if fi, err := os.Lstat(s.rulePackReleasesDir()); err == nil && fi.IsDir() {
		if !isDirWritableProbe(s.rulePackReleasesDir()) {
			return false
		}
	}
	return true
}

func isDirWritableProbe(dir string) bool {
	f, err := os.CreateTemp(dir, ".rulepack-write-probe-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
}

func (s *Server) readActiveRulePackSymlink() (activeSymlink, activeVersion string) {
	target, err := os.Readlink(s.rulePackCurrentPath())
	if err != nil {
		return "", ""
	}
	cleaned := filepath.ToSlash(filepath.Clean(target))
	if !strings.HasPrefix(cleaned, "releases/") {
		return "", ""
	}
	ver := strings.TrimPrefix(cleaned, "releases/")
	if err := ValidateAnyRulePackReleaseVersion(ver); err != nil {
		return "", ""
	}
	return cleaned, ver
}

func (s *Server) readRulePackMeta(version string) (*rulePackSidecarMeta, error) {
	metaPath := s.rulePackMetaPath(version)
	fi, err := os.Lstat(metaPath)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return nil, errors.New("rulepack metadata file is unsafe")
	}
	raw, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, err
	}
	var meta rulePackSidecarMeta
	if err := json.Unmarshal(raw, &meta); err != nil {
		return nil, err
	}
	meta.ManifestSHA256 = strings.ToLower(strings.TrimSpace(meta.ManifestSHA256))
	if meta.Version != version || !isValidHexToken(meta.ManifestSHA256, 64, 64, true) {
		return nil, errors.New("rulepack metadata is malformed")
	}
	return &meta, nil
}

func (s *Server) writeRulePackMeta(meta rulePackSidecarMeta) error {
	metaDir := s.rulePackMetaDir()
	if err := ensureSafeDir(metaDir, 0o750); err != nil {
		return err
	}
	metaPath := s.rulePackMetaPath(meta.Version)
	if err := checkNotSymlinkIfExists(metaPath); err != nil {
		return err
	}
	raw, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return writeBytesAtomic(metaDir, metaPath, ".meta-*.tmp", raw, 0o640)
}

func hasRulePackReleaseOnDisk(releaseDir string) bool {
	if checkNonSymlinkDir(releaseDir) != nil {
		return false
	}
	for _, rel := range rulePackCoreDiskAnchors {
		p := filepath.Join(releaseDir, filepath.FromSlash(rel))
		fi, err := os.Lstat(p)
		if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() || fi.Size() == 0 {
			return false
		}
	}
	return true
}

func hasAllRulePackAnchorsOnDisk(releaseDir string) bool {
	if checkNonSymlinkDir(releaseDir) != nil {
		return false
	}
	for _, anchor := range rulePackRequiredAnchors {
		sub := strings.TrimPrefix(anchor, "rules/")
		p := filepath.Join(releaseDir, filepath.FromSlash(sub))
		fi, err := os.Lstat(p)
		if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() || fi.Size() == 0 {
			return false
		}
	}
	return true
}

// handleRulePackStage implements POST /v1/rulepacks/stage.
func (s *Server) handleRulePackStage(w http.ResponseWriter, r *http.Request, authInfo VerifiedAuth) {
	if s.rulesDir == "" {
		writeJSONError(w, http.StatusServiceUnavailable, "rulepack storage not configured (HASYNC_RULES_DIR is empty)")
		return
	}

	version := strings.TrimSpace(r.Header.Get(HeaderRulePackVersion))
	if err := ValidateRulePackVersion(version); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	pkgSHA := strings.ToLower(strings.TrimSpace(r.Header.Get(HeaderRulePackPackageSHA256)))
	if !isValidHexToken(pkgSHA, 64, 64, true) {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("missing or invalid %s", HeaderRulePackPackageSHA256))
		return
	}
	if !hmac.Equal([]byte(pkgSHA), []byte(authInfo.BodySHA256)) {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("%s does not match %s", HeaderRulePackPackageSHA256, HeaderBodySHA256))
		return
	}

	// Extend deadlines for streaming up to 64 MiB archives, restoring on return.
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(5 * time.Minute))
	_ = rc.SetWriteDeadline(time.Now().Add(5 * time.Minute))
	defer func() {
		_ = rc.SetReadDeadline(time.Now().Add(30 * time.Second))
		_ = rc.SetWriteDeadline(time.Now().Add(60 * time.Second))
	}()

	if err := checkNonSymlinkDir(s.rulesDir); err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "rules directory unavailable or unsafe")
		return
	}
	stagingDir := s.rulePackStagingDir()
	releasesDir := s.rulePackReleasesDir()
	if err := ensureSafeDir(stagingDir, 0o750); err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("prepare staging dir failed: %v", err))
		return
	}
	if err := ensureSafeDir(releasesDir, 0o750); err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("prepare releases dir failed: %v", err))
		return
	}

	// Stream archive body to temp file inside .staging while computing SHA-256.
	tmpFile, err := os.CreateTemp(stagingDir, ".rp-upload-*.tar.gz")
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "create temp rulepack file failed")
		return
	}
	tmpPath := tmpFile.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if err := tmpFile.Chmod(0o600); err != nil {
		_ = tmpFile.Close()
		writeJSONError(w, http.StatusInternalServerError, "chmod temp rulepack failed")
		return
	}

	hasher := sha256.New()
	limited := io.LimitReader(r.Body, s.maxRulePackBytes+1)
	written, err := io.Copy(tmpFile, io.TeeReader(limited, hasher))
	if err != nil {
		_ = tmpFile.Close()
		writeJSONError(w, http.StatusBadRequest, "read rulepack stream failed")
		return
	}
	if written > s.maxRulePackBytes {
		_ = tmpFile.Close()
		writeJSONError(w, http.StatusRequestEntityTooLarge, "rulepack archive exceeds maximum allowed size")
		return
	}
	if written == 0 {
		_ = tmpFile.Close()
		writeJSONError(w, http.StatusBadRequest, "rulepack body is empty")
		return
	}
	if err := tmpFile.Close(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "close temp rulepack failed")
		return
	}

	actualSHA := hex.EncodeToString(hasher.Sum(nil))
	if !hmac.Equal([]byte(actualSHA), []byte(authInfo.BodySHA256)) {
		writeJSONError(w, http.StatusUnauthorized, "body sha256 mismatch")
		return
	}

	// Independent Ed25519 signature + manifest + 1-to-1 file digest + anchor verification.
	art, err := verifyRulePackArchiveFile(tmpPath, version, s.rulePackVerifyKey)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	destDir := s.rulePackReleaseDir(version)
	// Fast-path idempotency / conflict check under read lock before extracting.
	s.rulePackMu.RLock()
	if exists, idemp, conflictMsg, checkErr := s.checkExistingStagedRelease(destDir, version, art.manifestSHA256); checkErr != nil {
		s.rulePackMu.RUnlock()
		writeJSONError(w, http.StatusInternalServerError, checkErr.Error())
		return
	} else if exists {
		s.rulePackMu.RUnlock()
		if idemp {
			writeJSON(w, http.StatusOK, RulePackStageResponse{
				OK:             true,
				Version:        version,
				ManifestSHA256: art.manifestSHA256,
				FileSHA256:     actualSHA,
				FileSize:       written,
				Idempotent:     true,
			})
			return
		}
		writeJSONError(w, http.StatusConflict, conflictMsg)
		return
	}
	s.rulePackMu.RUnlock()

	// Extract verified rules/ into a private staging subdirectory.
	extractDir, err := os.MkdirTemp(stagingDir, "extract-"+version+"-")
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "create rulepack extract dir failed")
		return
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(extractDir)
		}
	}()
	if err := os.Chmod(extractDir, 0o750); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "chmod rulepack extract dir failed")
		return
	}
	if err := extractVerifiedRulePackRules(tmpPath, art.commonRoot, extractDir); err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("extract rulepack failed: %v", err))
		return
	}
	if !hasAllRulePackAnchorsOnDisk(extractDir) {
		writeJSONError(w, http.StatusBadRequest, "extracted rulepack missing required anchor files")
		return
	}

	// Atomically commit into releases/<version>/ and write clean sidecar metadata.
	s.rulePackMu.Lock()
	defer s.rulePackMu.Unlock()

	if exists, idemp, conflictMsg, checkErr := s.checkExistingStagedRelease(destDir, version, art.manifestSHA256); checkErr != nil {
		writeJSONError(w, http.StatusInternalServerError, checkErr.Error())
		return
	} else if exists {
		if idemp {
			writeJSON(w, http.StatusOK, RulePackStageResponse{
				OK:             true,
				Version:        version,
				ManifestSHA256: art.manifestSHA256,
				FileSHA256:     actualSHA,
				FileSize:       written,
				Idempotent:     true,
			})
			return
		}
		writeJSONError(w, http.StatusConflict, conflictMsg)
		return
	}

	if err := os.Rename(extractDir, destDir); err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("commit rulepack release failed: %v", err))
		return
	}
	committed = true

	if err := s.writeRulePackMeta(rulePackSidecarMeta{
		Version:        version,
		ManifestSHA256: art.manifestSHA256,
		FileSHA256:     actualSHA,
		StagedAt:       s.now().UTC(),
	}); err != nil {
		_ = os.RemoveAll(destDir)
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("write rulepack metadata failed: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, RulePackStageResponse{
		OK:             true,
		Version:        version,
		ManifestSHA256: art.manifestSHA256,
		FileSHA256:     actualSHA,
		FileSize:       written,
	})
}

func (s *Server) checkExistingStagedRelease(destDir, version, manifestSHA256 string) (exists, idempotent bool, conflictMsg string, err error) {
	fi, statErr := os.Lstat(destDir)
	if statErr != nil {
		if errors.Is(statErr, fs.ErrNotExist) {
			return false, false, "", nil
		}
		return false, false, "", fmt.Errorf("stat release dir failed: %w", statErr)
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return false, false, "", errors.New("existing release path is unsafe")
	}
	meta, metaErr := s.readRulePackMeta(version)
	if metaErr == nil && hmac.Equal([]byte(meta.ManifestSHA256), []byte(manifestSHA256)) && hasAllRulePackAnchorsOnDisk(destDir) {
		return true, true, "", nil
	}
	return true, false, fmt.Sprintf("rulepack version %s is already staged with a different manifest_sha256", version), nil
}

// handleRulePackStatus implements GET /v1/rulepacks/status.
func (s *Server) handleRulePackStatus(w http.ResponseWriter, r *http.Request, authInfo VerifiedAuth) {
	if s.rulesDir == "" {
		writeJSONError(w, http.StatusServiceUnavailable, "rulepack storage not configured (HASYNC_RULES_DIR is empty)")
		return
	}
	if _, ok := readAndVerifyBody(w, r, authInfo.BodySHA256, 1024); !ok {
		return
	}

	s.rulePackMu.RLock()
	defer s.rulePackMu.RUnlock()

	writable := s.checkRulePackReady()
	activeSymlink, activeVer := s.readActiveRulePackSymlink()
	staged := make(map[string]string)
	releases := make([]RulePackReleaseInfo, 0)

	releasesDir := s.rulePackReleasesDir()
	if entries, err := os.ReadDir(releasesDir); err == nil {
		for _, e := range entries {
			if e.Type()&os.ModeSymlink != 0 || !e.IsDir() {
				continue
			}
			ver := e.Name()
			if ValidateAnyRulePackReleaseVersion(ver) != nil {
				continue
			}
			relDir := filepath.Join(releasesDir, ver)
			if !hasRulePackReleaseOnDisk(relDir) {
				continue
			}
			manifestSHA := ""
			var stagedAt time.Time
			if meta, merr := s.readRulePackMeta(ver); merr == nil {
				manifestSHA = meta.ManifestSHA256
				stagedAt = meta.StagedAt.UTC()
			} else if info, ierr := e.Info(); ierr == nil {
				stagedAt = info.ModTime().UTC()
			}
			staged[ver] = manifestSHA
			releases = append(releases, RulePackReleaseInfo{
				Version:        ver,
				ManifestSHA256: manifestSHA,
				StagedAt:       stagedAt,
			})
		}
	}
	sort.Slice(releases, func(i, j int) bool {
		return releases[i].Version < releases[j].Version
	})

	writeJSON(w, http.StatusOK, RulePackStatusResponse{
		RulesDirWritable: writable,
		ActiveSymlink:    activeSymlink,
		ActiveVersion:    activeVer,
		StagedVersions:   staged,
		Releases:         releases,
		DiskFreeBytes:    diskFreeBytes(s.rulesDir),
	})
}

// handleRulePackActivate implements POST /v1/rulepacks/activate.
func (s *Server) handleRulePackActivate(w http.ResponseWriter, r *http.Request, authInfo VerifiedAuth) {
	if s.rulesDir == "" {
		writeJSONError(w, http.StatusServiceUnavailable, "rulepack storage not configured (HASYNC_RULES_DIR is empty)")
		return
	}
	body, ok := readAndVerifyBody(w, r, authInfo.BodySHA256, MaxJSONControlBytes)
	if !ok {
		return
	}
	var req RulePackActivateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid rulepack activate JSON")
		return
	}
	ver := strings.TrimSpace(req.Version)
	if err := ValidateAnyRulePackReleaseVersion(ver); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	wantSHA := strings.ToLower(strings.TrimSpace(req.ManifestSHA256))
	if wantSHA != "" && !isValidHexToken(wantSHA, 64, 64, true) {
		writeJSONError(w, http.StatusBadRequest, "invalid manifest_sha256")
		return
	}

	s.rulePackMu.Lock()
	defer s.rulePackMu.Unlock()

	if err := checkNonSymlinkDir(s.rulesDir); err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "rules directory unavailable or unsafe")
		return
	}
	releaseDir := s.rulePackReleaseDir(ver)
	fi, err := os.Lstat(releaseDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			writeJSONError(w, http.StatusNotFound, fmt.Sprintf("rulepack release %s not found", ver))
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "stat rulepack release failed")
		return
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		writeJSONError(w, http.StatusInternalServerError, "rulepack release path is unsafe")
		return
	}
	if !hasRulePackReleaseOnDisk(releaseDir) {
		writeJSONError(w, http.StatusConflict, fmt.Sprintf("rulepack release %s is incomplete", ver))
		return
	}

	actualSHA := ""
	if meta, merr := s.readRulePackMeta(ver); merr == nil {
		actualSHA = meta.ManifestSHA256
	}
	if wantSHA != "" {
		if actualSHA == "" || !hmac.Equal([]byte(actualSHA), []byte(wantSHA)) {
			writeJSONError(w, http.StatusConflict, fmt.Sprintf("rulepack %s manifest_sha256 mismatch", ver))
			return
		}
	}

	relTarget := "releases/" + ver
	if err := s.atomicSwitchRulePackSymlink(relTarget); err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("switch current symlink failed: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, RulePackActivateResponse{
		OK:             true,
		Version:        ver,
		ActiveSymlink:  relTarget,
		ManifestSHA256: actualSHA,
	})
}

func (s *Server) atomicSwitchRulePackSymlink(relTarget string) error {
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmpLink := filepath.Join(s.rulesDir, ".current.tmp."+hex.EncodeToString(rnd[:]))
	if err := os.Symlink(relTarget, tmpLink); err != nil {
		return err
	}
	if err := os.Rename(tmpLink, s.rulePackCurrentPath()); err != nil {
		_ = os.Remove(tmpLink)
		return err
	}
	return nil
}

// handleRulePackDeleteRelease implements DELETE /v1/rulepacks/releases/{version}.
func (s *Server) handleRulePackDeleteRelease(w http.ResponseWriter, r *http.Request, authInfo VerifiedAuth, rawVersion string) {
	if s.rulesDir == "" {
		writeJSONError(w, http.StatusServiceUnavailable, "rulepack storage not configured (HASYNC_RULES_DIR is empty)")
		return
	}
	if _, ok := readAndVerifyBody(w, r, authInfo.BodySHA256, 1024); !ok {
		return
	}

	ver := strings.TrimSpace(rawVersion)
	if IsBuiltinRulePackVersion(ver) || strings.HasPrefix(ver, "builtin-") {
		writeJSONError(w, http.StatusConflict, "refusing to delete builtin baseline release")
		return
	}
	if err := ValidateRulePackVersion(ver); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.rulePackMu.Lock()
	defer s.rulePackMu.Unlock()

	if err := checkNonSymlinkDir(s.rulesDir); err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "rules directory unavailable or unsafe")
		return
	}
	_, activeVer := s.readActiveRulePackSymlink()
	if activeVer == ver {
		writeJSONError(w, http.StatusConflict, fmt.Sprintf("refusing to delete active current rulepack release %s", ver))
		return
	}

	releasesRoot := filepath.Clean(s.rulePackReleasesDir())
	releaseDir := filepath.Clean(s.rulePackReleaseDir(ver))
	if !strings.HasPrefix(releaseDir, releasesRoot+string(filepath.Separator)) || filepath.Dir(releaseDir) != releasesRoot {
		writeJSONError(w, http.StatusBadRequest, "invalid rulepack release path")
		return
	}

	fi, err := os.Lstat(releaseDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			_ = os.Remove(s.rulePackMetaPath(ver))
			writeJSON(w, http.StatusOK, RulePackDeleteResponse{
				OK:      true,
				Version: ver,
				Deleted: false,
			})
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "stat rulepack release failed")
		return
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		writeJSONError(w, http.StatusInternalServerError, "rulepack release path is unsafe")
		return
	}
	if err := os.RemoveAll(releaseDir); err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("remove rulepack release failed: %v", err))
		return
	}
	_ = os.Remove(s.rulePackMetaPath(ver))

	writeJSON(w, http.StatusOK, RulePackDeleteResponse{
		OK:      true,
		Version: ver,
		Deleted: true,
	})
}

// ---------- Independent Ed25519 + Manifest + Archive Verification ----------

func verifyRulePackArchiveFile(archivePath, expectedVersion string, pub ed25519.PublicKey) (*verifiedRulePackArtifact, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("invalid Ed25519 verification key")
	}
	f, err := os.Open(archivePath)
	if err != nil {
		return nil, fmt.Errorf("open rulepack archive: %w", err)
	}
	defer func() { _ = f.Close() }()

	scan, err := scanRulePackTarGz(f)
	if err != nil {
		return nil, err
	}
	if len(scan.manifestBytes) == 0 {
		return nil, errors.New("rulepack archive missing manifest.json")
	}
	if len(scan.manifestSig) == 0 {
		return nil, errors.New("rulepack archive missing embedded manifest.sig")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(scan.manifestSig)))
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return nil, errors.New("manifest.sig is not a valid base64 Ed25519 signature")
	}
	// Verify Ed25519 signature BEFORE unmarshaling manifest.json (fail-closed root of trust).
	if !ed25519.Verify(pub, scan.manifestBytes, sigBytes) {
		return nil, errors.New("Ed25519 signature verification failed")
	}

	var manifest rulePackManifest
	if err := json.Unmarshal(scan.manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("invalid manifest.json: %w", err)
	}
	if manifest.SchemaVersion != rulePackSchemaVersion {
		return nil, fmt.Errorf("unsupported rulepack schema_version=%d", manifest.SchemaVersion)
	}
	if manifest.Product != rulePackProductWDSP {
		return nil, fmt.Errorf("invalid product=%q (expect %q)", manifest.Product, rulePackProductWDSP)
	}
	if manifest.PackageType != rulePackPackageType {
		return nil, fmt.Errorf("invalid package_type=%q (expect %q)", manifest.PackageType, rulePackPackageType)
	}
	if err := ValidateRulePackVersion(manifest.RulePackVersion); err != nil {
		return nil, err
	}
	if expectedVersion != "" && manifest.RulePackVersion != expectedVersion {
		return nil, fmt.Errorf("manifest rulepack_version %q does not match header version %q", manifest.RulePackVersion, expectedVersion)
	}
	manifest.CRSVersion = strings.TrimSpace(manifest.CRSVersion)
	if manifest.CRSVersion == "" || len(manifest.CRSVersion) > 32 {
		return nil, errors.New("manifest missing valid crs_version")
	}
	if len(manifest.Files) == 0 || len(manifest.Files) > MaxRulePackEntries {
		return nil, errors.New("manifest files list is empty or exceeds limit")
	}

	filesJSON, err := json.Marshal(manifest.Files)
	if err != nil {
		return nil, fmt.Errorf("marshal manifest.files: %w", err)
	}
	filesDigest := sha256.Sum256(filesJSON)
	if !strings.EqualFold(hex.EncodeToString(filesDigest[:]), strings.TrimSpace(manifest.FilesManifestSHA256)) {
		return nil, errors.New("files_manifest_sha256 mismatch")
	}

	listed := make(map[string]struct{}, len(manifest.Files))
	hasCRSRule := false
	for _, item := range manifest.Files {
		norm, err := normalizeRulePackArchivePath(item.Path)
		if err != nil {
			return nil, fmt.Errorf("invalid manifest file path: %w", err)
		}
		if norm == "" || norm == "manifest.json" || norm == "manifest.sig" {
			return nil, fmt.Errorf("manifest.files must not include reserved path %q", norm)
		}
		if !strings.HasPrefix(norm, "rules/") {
			return nil, fmt.Errorf("rulepack file must reside under rules/: %s", norm)
		}
		if !isAllowedRulePackArchiveFile(norm) {
			return nil, fmt.Errorf("disallowed rulepack file extension or name: %s", norm)
		}
		if _, dup := listed[norm]; dup {
			return nil, fmt.Errorf("duplicate path in manifest.files: %s", norm)
		}
		listed[norm] = struct{}{}

		actual, ok := scan.files[norm]
		if !ok {
			return nil, fmt.Errorf("file declared in manifest missing from archive: %s", norm)
		}
		if actual.size != item.Size || !strings.EqualFold(actual.hash, strings.TrimSpace(item.SHA256)) {
			return nil, fmt.Errorf("file size or sha256 mismatch: %s", norm)
		}
		if strings.HasPrefix(norm, "rules/crs/rules/") && strings.HasSuffix(norm, ".conf") &&
			!strings.HasSuffix(norm, ".example") && !strings.Contains(filepath.Base(norm), "EXCLUSION") && actual.size > 0 {
			hasCRSRule = true
		}
	}
	if len(scan.files) != len(listed) {
		return nil, errors.New("archive contains undeclared files outside manifest.files")
	}
	for _, anchor := range rulePackRequiredAnchors {
		info, ok := scan.files[anchor]
		if !ok || info.size <= 0 {
			return nil, fmt.Errorf("missing or empty required anchor file: %s", anchor)
		}
	}
	if !hasCRSRule {
		return nil, errors.New("rules/crs/rules/ contains no usable CRS rule files")
	}

	manifestSum := sha256.Sum256(scan.manifestBytes)
	return &verifiedRulePackArtifact{
		version:        manifest.RulePackVersion,
		manifestSHA256: hex.EncodeToString(manifestSum[:]),
		commonRoot:     scan.root,
	}, nil
}

func scanRulePackTarGz(r io.Reader) (*rulePackScannedArchive, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("invalid gzip header: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	var entries []rulePackRawEntry
	var expanded int64
	var buffered int64
	var possibleRoot string
	seen := make(map[string]struct{})
	entryCount := 0

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("corrupt tar archive: %w", err)
		}
		entryCount++
		if entryCount > MaxRulePackEntries {
			return nil, fmt.Errorf("archive entry count exceeds limit (%d)", MaxRulePackEntries)
		}
		norm, err := normalizeRulePackArchivePath(hdr.Name)
		if err != nil {
			return nil, err
		}
		if norm == "" {
			continue
		}
		if hdr.Typeflag != tar.TypeDir && hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			return nil, fmt.Errorf("forbidden archive entry type (only regular files and dirs allowed): %s", hdr.Name)
		}
		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		if _, dup := seen[norm]; dup {
			return nil, fmt.Errorf("duplicate archive file path: %s", norm)
		}
		seen[norm] = struct{}{}

		if len(entries) == 0 {
			possibleRoot = rulePackFirstComponent(norm)
		} else if rulePackFirstComponent(norm) != possibleRoot {
			possibleRoot = ""
		}

		if hdr.Size < 0 || hdr.Size > MaxRulePackSingleFileBytes {
			return nil, fmt.Errorf("archive file %s exceeds max single-file size", norm)
		}
		if expanded > MaxRulePackExpandedBytes-hdr.Size {
			return nil, errors.New("archive expanded size exceeds safety limit")
		}
		expanded += hdr.Size

		metaPath := rulePackStripRoot(norm, possibleRoot)
		if norm == "manifest.json" || norm == "manifest.sig" {
			metaPath = norm
		}

		h := sha256.New()
		entry := rulePackRawEntry{path: norm, size: hdr.Size}
		if metaPath == "manifest.json" || metaPath == "manifest.sig" {
			if metaPath == "manifest.json" && hdr.Size > MaxRulePackManifestBytes {
				return nil, errors.New("manifest.json exceeds safety limit")
			}
			if metaPath == "manifest.sig" && hdr.Size > MaxRulePackManifestSigBytes {
				return nil, errors.New("manifest.sig exceeds safety limit")
			}
			maxMetaBuf := 2 * (MaxRulePackManifestBytes + MaxRulePackManifestSigBytes)
			if buffered > maxMetaBuf-hdr.Size {
				return nil, errors.New("manifest metadata buffer exceeds safety limit")
			}
			buffered += hdr.Size
			entry.content = make([]byte, hdr.Size)
			n, rerr := io.ReadFull(io.TeeReader(io.LimitReader(tr, hdr.Size), h), entry.content)
			if rerr != nil || int64(n) != hdr.Size {
				return nil, fmt.Errorf("incomplete read of %s", norm)
			}
		} else {
			n, cerr := io.Copy(h, io.LimitReader(tr, hdr.Size))
			if cerr != nil || n != hdr.Size {
				return nil, fmt.Errorf("incomplete read of %s", norm)
			}
		}
		entry.hash = hex.EncodeToString(h.Sum(nil))
		entries = append(entries, entry)
	}

	root := detectRulePackCommonRoot(entries)
	scan := &rulePackScannedArchive{
		root:  root,
		files: make(map[string]rulePackArchiveFileInfo, len(entries)),
	}
	for _, e := range entries {
		rel := rulePackStripRoot(e.path, root)
		if rel == "" {
			continue
		}
		switch rel {
		case "manifest.json":
			if scan.manifestBytes != nil {
				return nil, errors.New("duplicate manifest.json in archive")
			}
			scan.manifestBytes = e.content
		case "manifest.sig":
			if scan.manifestSig != nil {
				return nil, errors.New("duplicate manifest.sig in archive")
			}
			scan.manifestSig = e.content
		default:
			if _, dup := scan.files[rel]; dup {
				return nil, fmt.Errorf("duplicate file in archive: %s", rel)
			}
			scan.files[rel] = rulePackArchiveFileInfo{size: e.size, hash: e.hash}
		}
	}
	return scan, nil
}

func extractVerifiedRulePackRules(archivePath, commonRoot, destRulesDir string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer func() { _ = gz.Close() }()

	cleanDest := filepath.Clean(destRulesDir)
	var expanded int64
	entryCount := 0
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		entryCount++
		if entryCount > MaxRulePackEntries {
			return errors.New("archive entry count exceeds limit")
		}
		norm, err := normalizeRulePackArchivePath(hdr.Name)
		if err != nil {
			return err
		}
		if norm == "" || hdr.Typeflag == tar.TypeDir {
			continue
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			return fmt.Errorf("rejecting non-regular entry %s during extraction", hdr.Name)
		}
		rel := rulePackStripRoot(norm, commonRoot)
		if !strings.HasPrefix(rel, "rules/") {
			continue
		}
		sub := strings.TrimPrefix(rel, "rules/")
		if sub == "" || !isAllowedRulePackArchiveFile(rel) {
			return fmt.Errorf("disallowed path during extraction: %s", rel)
		}
		if hdr.Size < 0 || hdr.Size > MaxRulePackSingleFileBytes || expanded > MaxRulePackExpandedBytes-hdr.Size {
			return errors.New("extracted size exceeds safety limit")
		}
		expanded += hdr.Size

		target := filepath.Join(cleanDest, filepath.FromSlash(sub))
		if !strings.HasPrefix(target, cleanDest+string(filepath.Separator)) {
			return fmt.Errorf("extracted path escapes destination: %s", sub)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
		if err != nil {
			return err
		}
		n, copyErr := io.Copy(out, io.LimitReader(tr, hdr.Size))
		syncErr := out.Sync()
		closeErr := out.Close()
		if copyErr != nil || n != hdr.Size {
			return fmt.Errorf("write %s incomplete: %v", sub, copyErr)
		}
		if syncErr != nil {
			return fmt.Errorf("fsync %s: %w", sub, syncErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close %s: %w", sub, closeErr)
		}
	}
	return nil
}

func isAllowedRulePackArchiveFile(rel string) bool {
	base := filepath.Base(rel)
	if rulePackAllowedBaseNames[base] {
		return true
	}
	ext := strings.ToLower(filepath.Ext(base))
	if ext != "" && rulePackAllowedExts[ext] {
		return true
	}
	return rulePackAllowedExts[strings.ToLower(base)]
}

func normalizeRulePackArchivePath(name string) (string, error) {
	if name == "" || strings.ContainsRune(name, '\x00') {
		return "", errors.New("archive entry has empty path or NUL byte")
	}
	if strings.Contains(name, "\\") || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("archive path must not be absolute or contain backslash: %s", name)
	}
	trimmed := strings.TrimPrefix(name, "./")
	trimmed = strings.TrimSuffix(trimmed, "/")
	if trimmed == "" || trimmed == "." {
		return "", nil
	}
	for _, part := range strings.Split(trimmed, "/") {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("archive contains unsafe path segment or traversal: %s", name)
		}
	}
	if !rulePackArchivePathRE.MatchString(trimmed) {
		return "", fmt.Errorf("archive path contains disallowed characters: %s", name)
	}
	return trimmed, nil
}

func rulePackFirstComponent(p string) string {
	if idx := strings.IndexByte(p, '/'); idx >= 0 {
		return p[:idx]
	}
	return p
}

func detectRulePackCommonRoot(entries []rulePackRawEntry) string {
	if len(entries) == 0 {
		return ""
	}
	root := rulePackFirstComponent(entries[0].path)
	if root == "" || root == "manifest.json" || root == "manifest.sig" || root == "rules" {
		return ""
	}
	for _, e := range entries[1:] {
		if rulePackFirstComponent(e.path) != root {
			return ""
		}
	}
	return root
}

func rulePackStripRoot(p, root string) string {
	if root == "" {
		return p
	}
	prefix := root + "/"
	if strings.HasPrefix(p, prefix) {
		return strings.TrimPrefix(p, prefix)
	}
	if p == root {
		return ""
	}
	return p
}

func diskFreeBytes(dir string) int64 {
	if strings.TrimSpace(dir) == "" {
		return -1
	}
	checkDir := dir
	for {
		if st, err := os.Stat(checkDir); err == nil && st.IsDir() {
			break
		}
		parent := filepath.Dir(checkDir)
		if parent == checkDir {
			return -1
		}
		checkDir = parent
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(checkDir, &st); err != nil {
		return -1
	}
	return int64(st.Bavail) * int64(st.Bsize)
}
