// Package hasyncd implements the zero-third-party-dependency HA node sync sidecar.
//
// It runs as non-root (uid 1000:1000) without docker.sock or NET_ADMIN, exposing a
// minimal HMAC-SHA256 authenticated HTTP(S) control API over the internal management
// network to proxy local Caddy Admin reloads, synchronize sidecar configs, write
// locally signed hostctl firewall rules, collect node status telemetry, and stage
// verified offline upgrade packages/jobs for the host upgrade executor.
package hasyncd

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"time"
)

// Shared HMAC-SHA256 authentication protocol headers.
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
)

// Default configuration paths and safety limits.
const (
	DefaultListenAddr      = "127.0.0.1:18443"
	DefaultCaddySocket     = "/var/run/caddy/admin.sock"
	DefaultSidecarDir      = "/var/run/caddy/sidecars"
	DefaultHostctlDir      = "/app/runtime/hostctl"
	DefaultUpgradesDir     = "/app/runtime/upgrades"
	DefaultNodeIfacesLog   = "/var/log/caddy/node-interfaces.jsonl"
	DefaultHealthStampPath = "/tmp/wdsp-hasyncd-health.json"

	// Auth protocol security boundaries.
	MinSecretBytes       = 32
	MaxSecretFileBytes   = 4096
	MaxTimestampSkew     = 60 * time.Second
	NonceTTL             = 120 * time.Second
	MinNonceHexLen       = 16
	MaxNonceHexLen       = 128
	DefaultMaxNonceCount = 65536

	// Endpoint payload caps.
	MaxCaddyLoadBytes           int64 = 16 << 20  // 16 MiB
	MaxSidecarBytes             int64 = 4 << 20   // 4 MiB
	MaxJSONControlBytes         int64 = 1 << 20   // 1 MiB
	DefaultMaxPackageSize       int64 = 8 << 30   // 8 GiB
	MaxRulePackArchiveBytes     int64 = 64 << 20  // 64 MiB
	MaxRulePackExpandedBytes    int64 = 256 << 20 // 256 MiB
	MaxRulePackSingleFileBytes  int64 = 16 << 20  // 16 MiB
	MaxRulePackEntries                = 10000
	MaxRulePackManifestBytes    int64 = 4 << 20 // 4 MiB
	MaxRulePackManifestSigBytes int64 = 4096
	MaxFirewallPorts                  = 64

	// Health stamp intervals.
	DefaultHealthStampInterval = 5 * time.Second
	DefaultHealthStampMaxAge   = 30 * time.Second

	// Status file names written by sibling sidecars.
	haVipStatusFileName   = "ha-vip-status.json"
	networkStatusFileName = "network-status.json"
)

// allowedSidecars defines the strict allowlist of writable/deletable sidecar files
// and their required file permissions.
var allowedSidecars = map[string]os.FileMode{
	"ha-vip.json":    0o640,
	"network.json":   0o644,
	"tproxyd.json":   0o644,
	"mirrorcap.json": 0o644,
}

// AllowedSidecarMode returns the file permission mode if name is in the strict sidecar allowlist.
func AllowedSidecarMode(name string) (os.FileMode, bool) {
	mode, ok := allowedSidecars[name]
	return mode, ok
}

// Config configures a hasyncd Server instance.
type Config struct {
	ListenAddr         string
	NodeName           string
	SecretFile         string
	SecretBytes        []byte // Optional direct secret bytes (used in tests when SecretFile is empty)
	TLSCertFile        string
	TLSKeyFile         string
	CaddySocket        string
	SidecarDir         string
	HostctlDir         string
	UpgradesDir        string
	UpgradePackagesDir string // Optional override; defaults to <UpgradesDir>/packages
	UpgradeExecutorDir string // Optional override; defaults to <UpgradesDir>/executor
	RulesDir           string // Optional versioned WAF rules directory (empty disables rulepack endpoints)
	RulePackVerifyKey  ed25519.PublicKey // Test-only override for Ed25519 verification key; never populated from env/flags
	MaxRulePackBytes   int64             // Optional test cap (defaults to MaxRulePackArchiveBytes = 64 MiB)
	NodeIfacesLog      string
	Version            string
	VersionFile        string
	HealthStampPath    string
	HealthStampPeriod  time.Duration
	MaxPackageBytes    int64
	MaxNonceEntries    int
	NowFunc            func() time.Time
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
// Matches server/internal/upgrades.ExecutorResult plus the pending indicator.
type UpgradeJobResult struct {
	Pending    bool      `json:"pending"`
	JobID      string    `json:"job_id"`
	Status     string    `json:"status,omitempty"`
	Stage      string    `json:"stage,omitempty"`
	ErrorCode  string    `json:"error_code,omitempty"`
	Message    string    `json:"message,omitempty"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
}

// ErrorResponse is the standard JSON error envelope.
type ErrorResponse struct {
	Error string `json:"error"`
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

// RulePackReleaseInfo describes one staged rulepack snapshot on disk.
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

// HealthStamp is periodically written atomically to the local health stamp file
// and inspected by `hasyncd --healthcheck`.
type HealthStamp struct {
	PID       int       `json:"pid"`
	Node      string    `json:"node"`
	Listen    string    `json:"listen"`
	Ready     bool      `json:"ready"`
	UpdatedAt time.Time `json:"updated_at"`
}
