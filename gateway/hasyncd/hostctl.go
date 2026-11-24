package hasyncd

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	hostctlActionFirewallEnsure = "firewall_ensure"
	hostctlSecretFileName       = ".hostctl-secret"
	hostctlFirewallSignVersion  = "v2"
)

// hostctlCommand matches server/internal/systemops.Command JSON wire format byte-for-byte.
type hostctlCommand struct {
	Action       string `json:"action"`
	RequestedBy  string `json:"requestedBy"`
	UserID       string `json:"userID"`
	RequestID    string `json:"requestID"`
	RequestedAt  string `json:"requestedAt"`
	DelaySeconds int    `json:"delaySeconds"`
	Ports        []int  `json:"ports,omitempty"`
	HMAC         string `json:"hmac"`
}

// hostctlCanonicalPayloadV2 matches server/internal/systemops.CanonicalPayload for firewall_ensure
// and ops/system/hostctl-exec.sh v2 verification byte-for-byte:
//
//	v2\nfirewall_ensure\n<requestedBy>\n<userID>\n<requestID>\n<requestedAt>\n0\n<portsCSV>
func hostctlCanonicalPayloadV2(cmd hostctlCommand) string {
	ports := sortedUniquePorts(cmd.Ports)
	portStrs := make([]string, len(ports))
	for i, p := range ports {
		portStrs[i] = strconv.Itoa(p)
	}
	fields := []string{
		hostctlFirewallSignVersion,
		cmd.Action,
		cmd.RequestedBy,
		cmd.UserID,
		cmd.RequestID,
		cmd.RequestedAt,
		strconv.Itoa(cmd.DelaySeconds),
		strings.Join(portStrs, ","),
	}
	return strings.Join(fields, "\n")
}

// signHostctlCommand computes HMAC-SHA256 using the 64-byte ASCII hex secret string,
// matching server/internal/systemops.SignCommand and ops/system/hostctl-exec.sh.
func signHostctlCommand(cmd *hostctlCommand, secretASCIIHex []byte) {
	mac := hmac.New(sha256.New, secretASCIIHex)
	_, _ = mac.Write([]byte(hostctlCanonicalPayloadV2(*cmd)))
	cmd.HMAC = hex.EncodeToString(mac.Sum(nil))
}

func sortedUniquePorts(ports []int) []int {
	out := append([]int(nil), ports...)
	sort.Ints(out)
	w := 0
	for _, p := range out {
		if w > 0 && out[w-1] == p {
			continue
		}
		out[w] = p
		w++
	}
	return out[:w]
}

// loadOrCreateHostctlSecret mirrors server/internal/systemops.LoadOrCreateHostctlSecret:
// refuses symlinks, validates 64 lowercase hex chars, and atomically bootstraps with O_EXCL 0600
// if the secret file does not yet exist in an existing hostctl directory.
func loadOrCreateHostctlSecret(dir string) ([]byte, error) {
	if err := checkNonSymlinkDir(dir); err != nil {
		return nil, fmt.Errorf("hostctl dir unavailable: %w", err)
	}
	path := filepath.Join(dir, hostctlSecretFileName)
	readValid := func() ([]byte, error) {
		fi, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
			return nil, errors.New("hostctl secret must be a regular non-symlink file")
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read hostctl secret: %w", err)
		}
		key := strings.TrimSpace(string(b))
		if !isValidHexToken(key, 64, 64, true) {
			return nil, fmt.Errorf("hostctl secret malformed: expect 64 lowercase hex chars, got len %d", len(key))
		}
		return []byte(key), nil
	}
	key, err := readValid()
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("generate hostctl secret: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return readValid()
		}
		return nil, fmt.Errorf("create hostctl secret: %w", err)
	}
	if _, err := f.WriteString(hex.EncodeToString(raw) + "\n"); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("write hostctl secret: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("fsync hostctl secret: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("close hostctl secret: %w", err)
	}
	return readValid()
}

func checkHostctlReady(dir string) bool {
	if strings.TrimSpace(dir) == "" {
		return false
	}
	fi, err := os.Lstat(dir)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return false
	}
	if fi.Mode().Perm()&0o002 != 0 {
		return false
	}
	secretPath := filepath.Join(dir, hostctlSecretFileName)
	sfi, err := os.Lstat(secretPath)
	if err != nil {
		return errors.Is(err, fs.ErrNotExist)
	}
	if sfi.Mode()&os.ModeSymlink != 0 || !sfi.Mode().IsRegular() {
		return false
	}
	b, err := os.ReadFile(secretPath)
	if err != nil {
		return false
	}
	return isValidHexToken(strings.TrimSpace(string(b)), 64, 64, true)
}

func isSafeHostctlSegment(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	if strings.Contains(s, "..") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x20 || c == 0x7f || c == '/' || c == '\\' {
			return false
		}
	}
	return true
}

func isSafeHostctlTextField(s string) bool {
	if len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\r' || c == '\n' || c == 0 || (c < 0x20 && c != '\t') || c == 0x7f {
			return false
		}
	}
	return true
}

func generateRandomUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// writeFirewallEnsureFlag validates inputs, signs a v2 firewall_ensure command using local
// hostctlDir/.hostctl-secret, and atomically writes firewall_ensure-<unixts>-<requestid>.json.
func writeFirewallEnsureFlag(dir string, rawPorts []int, requestID, requestedBy, userID string, now time.Time) (string, string, []int, error) {
	if len(rawPorts) == 0 {
		return "", "", nil, errors.New("ports must not be empty")
	}
	if len(rawPorts) > MaxFirewallPorts {
		return "", "", nil, fmt.Errorf("too many firewall ports: %d (max %d)", len(rawPorts), MaxFirewallPorts)
	}
	for _, p := range rawPorts {
		if p < 1 || p > 65535 {
			return "", "", nil, fmt.Errorf("firewall port out of range: %d", p)
		}
	}
	ports := sortedUniquePorts(rawPorts)

	reqID := strings.TrimSpace(requestID)
	if reqID == "" {
		genID, err := generateRandomUUIDv4()
		if err != nil {
			return "", "", nil, fmt.Errorf("generate request_id: %w", err)
		}
		reqID = genID
	} else if !isSafeHostctlSegment(reqID) {
		return "", "", nil, errors.New("invalid request_id")
	}

	reqBy := strings.TrimSpace(requestedBy)
	if reqBy == "" {
		reqBy = "hasyncd"
	}
	if !isSafeHostctlTextField(reqBy) {
		return "", "", nil, errors.New("invalid requested_by")
	}
	uid := strings.TrimSpace(userID)
	if !isSafeHostctlTextField(uid) {
		return "", "", nil, errors.New("invalid user_id")
	}

	secret, err := loadOrCreateHostctlSecret(dir)
	if err != nil {
		return "", "", nil, err
	}

	nowUTC := now.UTC()
	cmd := hostctlCommand{
		Action:       hostctlActionFirewallEnsure,
		RequestedBy:  reqBy,
		UserID:       uid,
		RequestID:    reqID,
		RequestedAt:  nowUTC.Format(time.RFC3339),
		DelaySeconds: 0,
		Ports:        ports,
	}
	signHostctlCommand(&cmd, secret)

	payload, err := json.Marshal(cmd)
	if err != nil {
		return "", "", nil, fmt.Errorf("marshal hostctl command: %w", err)
	}
	payload = append(payload, '\n')

	fileName := fmt.Sprintf("%s-%d-%s.json", hostctlActionFirewallEnsure, nowUTC.Unix(), reqID)
	finalPath := filepath.Join(dir, fileName)
	if err := checkNotSymlinkIfExists(finalPath); err != nil {
		return "", "", nil, err
	}

	tmp, err := os.CreateTemp(dir, ".hostctl-*.tmp")
	if err != nil {
		return "", "", nil, fmt.Errorf("create temp flag file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return "", "", nil, fmt.Errorf("write flag file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", "", nil, fmt.Errorf("fsync flag file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", "", nil, fmt.Errorf("close flag file: %w", err)
	}
	if err := os.Rename(tmpName, finalPath); err != nil {
		return "", "", nil, fmt.Errorf("rename flag file: %w", err)
	}
	return finalPath, reqID, ports, nil
}
