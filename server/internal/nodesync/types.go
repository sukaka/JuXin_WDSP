// Package nodesync provides the management-plane secure client for communicating with
// gateway hasyncd node sync sidecars over the internal management network.
package nodesync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Shared HMAC-SHA256 authentication protocol headers (byte-for-byte identical to gateway/hasyncd).
const (
	HeaderNode                  = "X-JZ-Node"
	HeaderTimestamp             = "X-JZ-Timestamp"
	HeaderNonce                 = "X-JZ-Nonce"
	HeaderBodySHA256            = "X-JZ-Body-SHA256"
	HeaderSignature             = "X-JZ-Signature"
	HeaderPackageFilename       = "X-JZ-Package-Filename"
	HeaderPackageSHA256         = "X-JZ-Package-SHA256"
	HeaderRulePackVersion       = "X-JiuZhang-RulePack-Version"
	HeaderRulePackPackageSHA256 = "X-JiuZhang-Package-SHA256"

	// MaxRulePackArchiveBytes matches gateway/hasyncd and server/internal/rulepacks 64 MiB cap.
	MaxRulePackArchiveBytes int64 = 64 << 20
)

// Allowlisted sidecar filenames synchronized via PUT/DELETE /v1/sidecars/{name}.
const (
	SidecarHaVip     = "ha-vip.json"
	SidecarNetwork   = "network.json"
	SidecarTproxyd   = "tproxyd.json"
	SidecarMirrorcap = "mirrorcap.json"
)

var (
	allowedSidecars = map[string]struct{}{
		SidecarHaVip:     {},
		SidecarNetwork:   {},
		SidecarTproxyd:   {},
		SidecarMirrorcap: {},
	}
	packageFilenameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(\.tar\.gz|\.run)$`)
	uuidRE            = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	rulePackVersionRE = regexp.MustCompile(`^([0-9]{8})\.([0-9]{1,3})$`)
	rulePackBuiltinRE = regexp.MustCompile(`^builtin-[0-9A-Za-z._-]+$`)
)

// AllowedSidecarFile reports whether name is in the strict sidecar allowlist.
func AllowedSidecarFile(name string) bool {
	_, ok := allowedSidecars[name]
	return ok
}

// ValidatePackageFilename enforces the exact package filename policy accepted by hasyncd.
func ValidatePackageFilename(name string) error {
	if name == "" || len(name) > 255 {
		return errors.New("package filename must be 1..255 characters")
	}
	if strings.Contains(name, "..") || strings.ContainsAny(name, `/\`) || strings.ContainsRune(name, 0) {
		return errors.New("package filename contains unsafe path characters")
	}
	if filepath.Base(name) != name {
		return errors.New("package filename must not contain path separators")
	}
	if !packageFilenameRE.MatchString(name) {
		return errors.New("package filename must match [A-Za-z0-9][A-Za-z0-9._-]*(.tar.gz|.run)")
	}
	return nil
}

// ValidateUUID validates a standard UUID string and returns its lowercase canonical form.
func ValidateUUID(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if !uuidRE.MatchString(trimmed) {
		return "", errors.New("invalid UUID job_id")
	}
	return strings.ToLower(trimmed), nil
}

// ValidateRulePackVersion enforces the formal offline rulepack version format YYYYMMDD.N.
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

// CanonicalBusinessConfigHash computes the canonical JSON SHA-256 with top-level "admin" stripped,
// matching gateway/hasyncd and gatewayconfig.CanonicalBusinessConfigHash.
func CanonicalBusinessConfigHash(configJSON []byte) (string, error) {
	var root map[string]any
	if err := json.Unmarshal(configJSON, &root); err != nil {
		return "", fmt.Errorf("parse config json: %w", err)
	}
	if root == nil {
		return "", errors.New("config json must be an object")
	}
	delete(root, "admin")
	canonical, err := json.Marshal(root)
	if err != nil {
		return "", fmt.Errorf("canonicalize config json: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// HealthResponse is returned by GET /v1/health.
type HealthResponse struct {
	Node           string    `json:"node"`
	Version        string    `json:"version"`
	CaddyReachable bool      `json:"caddy_reachable"`
	HostctlReady   bool      `json:"hostctl_ready"`
	UpgradeReady   bool      `json:"upgrade_ready"`
	RulePackReady  bool      `json:"rulepack_ready"`
	Now            time.Time `json:"now"`
}

// NodeHealth aliases HealthResponse for callers checking remote node readiness.
type NodeHealth = HealthResponse

// InterfaceSnapshot mirrors gateway/modules/jiuzhang_guard/netif.Record.
type InterfaceSnapshot struct {
	NodeName    string    `json:"node_name"`
	IfName      string    `json:"ifname"`
	MAC         string    `json:"mac"`
	IPAddresses []string  `json:"ip_addresses"`
	PCIPath     string    `json:"pci_path,omitempty"`
	Driver      string    `json:"driver,omitempty"`
	MediaType   string    `json:"media_type"`
	LinkSpeed   int       `json:"link_speed"`
	OperState   string    `json:"operstate"`
	CollectedAt time.Time `json:"collected_at"`
}

// StatusResponse is returned by GET /v1/status.
type StatusResponse struct {
	Node               string              `json:"node"`
	Version            string              `json:"version"`
	PolicyVersion      string              `json:"policy_version"`
	ConfigHash         string              `json:"config_hash"`
	CaddyReachable     bool                `json:"caddy_reachable"`
	HaVipStatus        json.RawMessage     `json:"ha_vip_status,omitempty"`
	HaVipStatusMtime   *time.Time          `json:"ha_vip_status_mtime,omitempty"`
	NetworkStatus      json.RawMessage     `json:"network_status,omitempty"`
	NetworkStatusMtime *time.Time          `json:"network_status_mtime,omitempty"`
	Interfaces         []InterfaceSnapshot `json:"interfaces"`
	CollectedAt        time.Time           `json:"collected_at"`
}

// CaddyLoadResponse is returned by POST /v1/caddy/load.
type CaddyLoadResponse struct {
	OK          bool   `json:"ok"`
	CaddyStatus int    `json:"caddy_status"`
	Error       string `json:"error,omitempty"`
}

// CaddyConfigHashResponse is returned by GET /v1/caddy/config-hash.
type CaddyConfigHashResponse struct {
	ConfigHash    string `json:"config_hash"`
	PolicyVersion string `json:"policy_version"`
}

// SidecarWriteResponse is returned by PUT /v1/sidecars/{name}.
type SidecarWriteResponse struct {
	OK     bool   `json:"ok"`
	Name   string `json:"name"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
}

// SidecarDeleteResponse is returned by DELETE /v1/sidecars/{name}.
type SidecarDeleteResponse struct {
	OK      bool   `json:"ok"`
	Name    string `json:"name"`
	Deleted bool   `json:"deleted"`
}

// FirewallEnsureRequest is the JSON body for POST /v1/firewall/ensure.
type FirewallEnsureRequest struct {
	Ports       []int  `json:"ports"`
	RequestID   string `json:"request_id"`
	RequestedBy string `json:"requested_by"`
	UserID      string `json:"user_id,omitempty"`
}

// FirewallEnsureResponse is returned by POST /v1/firewall/ensure.
type FirewallEnsureResponse struct {
	OK        bool   `json:"ok"`
	File      string `json:"file"`
	Ports     []int  `json:"ports"`
	RequestID string `json:"request_id"`
}

// UpgradePackageUploadResponse is returned by POST /v1/upgrades/packages.
type UpgradePackageUploadResponse struct {
	OK       bool   `json:"ok"`
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
}

// UpgradeExecuteRequest matches server/internal/upgrades.ExecutorRequest schema.
type UpgradeExecuteRequest struct {
	JobID         string    `json:"job_id"`
	PackageFile   string    `json:"package_file"`
	PackageSHA256 string    `json:"package_sha256"`
	VersionFrom   string    `json:"version_from"`
	VersionTo     string    `json:"version_to"`
	RequestedAt   time.Time `json:"requested_at"`
}

// UpgradeExecuteResponse is returned by POST /v1/upgrades/execute.
type UpgradeExecuteResponse struct {
	OK     bool   `json:"ok"`
	JobID  string `json:"job_id"`
	Status string `json:"status"`
}

// UpgradeJobResult is returned by GET /v1/upgrades/jobs/{job_id}.
type UpgradeJobResult struct {
	Pending    bool      `json:"pending"`
	JobID      string    `json:"job_id"`
	Status     string    `json:"status,omitempty"`
	Stage      string    `json:"stage,omitempty"`
	ErrorCode  string    `json:"error_code,omitempty"`
	Message    string    `json:"message,omitempty"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
}

// RulePackStageResponse is returned by POST /v1/rulepacks/stage.
type RulePackStageResponse struct {
	OK             bool   `json:"ok"`
	Version        string `json:"version"`
	ManifestSHA256 string `json:"manifest_sha256"`
	FileSHA256     string `json:"file_sha256"`
	FileSize       int64  `json:"file_size"`
	Idempotent     bool   `json:"idempotent,omitempty"`
}

// RulePackReleaseInfo describes one staged rulepack snapshot reported by hasyncd.
type RulePackReleaseInfo struct {
	Version        string    `json:"version"`
	ManifestSHA256 string    `json:"manifest_sha256"`
	StagedAt       time.Time `json:"staged_at,omitempty"`
}

// RulePackStatusResponse is returned by GET /v1/rulepacks/status.
type RulePackStatusResponse struct {
	RulesDirWritable bool                  `json:"rules_dir_writable"`
	ActiveSymlink    string                `json:"active_symlink"`
	ActiveVersion    string                `json:"active_version,omitempty"`
	StagedVersions   map[string]string     `json:"staged_versions"`
	Releases         []RulePackReleaseInfo `json:"releases,omitempty"`
	DiskFreeBytes    int64                 `json:"disk_free_bytes"`
}

// RulePackActivateRequest is the JSON body for POST /v1/rulepacks/activate.
type RulePackActivateRequest struct {
	Version        string `json:"version"`
	ManifestSHA256 string `json:"manifest_sha256,omitempty"`
}

// RulePackActivateResponse is returned by POST /v1/rulepacks/activate.
type RulePackActivateResponse struct {
	OK             bool   `json:"ok"`
	Version        string `json:"version"`
	ActiveSymlink  string `json:"active_symlink"`
	ManifestSHA256 string `json:"manifest_sha256,omitempty"`
}

// RulePackDeleteResponse is returned by DELETE /v1/rulepacks/releases/{version}.
type RulePackDeleteResponse struct {
	OK      bool   `json:"ok"`
	Version string `json:"version"`
	Deleted bool   `json:"deleted"`
}

// NodeRulePackStatus aggregates remote /v1/health rulepack readiness and /v1/rulepacks/status.
type NodeRulePackStatus struct {
	Reachable        bool              `json:"reachable"`
	RulePackReady    bool              `json:"rulepack_ready"`
	RulesDirWritable bool              `json:"rules_dir_writable"`
	ActiveSymlink    string            `json:"active_symlink"`
	ActiveVersion    string            `json:"active_version"`
	StagedVersions   map[string]string `json:"staged_versions"`
	DiskFreeBytes    int64             `json:"disk_free_bytes"`
	Error            string            `json:"error,omitempty"`
}

// RulePackSyncClient defines the HA standby rulepack sync contract implemented by *Manager.
type RulePackSyncClient interface {
	CheckNodeHealth(ctx context.Context, nodeID uuid.UUID) (*HealthResponse, error)
	CheckNodeRulePackStatus(ctx context.Context, nodeID uuid.UUID) (*NodeRulePackStatus, error)
	StageRulePack(ctx context.Context, nodeID uuid.UUID, version, archivePath, expectedSHA256 string) (*RulePackStageResponse, error)
	ActivateRulePack(ctx context.Context, nodeID uuid.UUID, version, manifestSHA256 string) (*RulePackActivateResponse, error)
	DeleteRulePackRelease(ctx context.Context, nodeID uuid.UUID, version string) (*RulePackDeleteResponse, error)
}

// APIError represents a non-2xx response returned by hasyncd.
type APIError struct {
	StatusCode int
	Message    string
	Body       string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("hasyncd returned HTTP %d: %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("hasyncd returned HTTP %d", e.StatusCode)
}
