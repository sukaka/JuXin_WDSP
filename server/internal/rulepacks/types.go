// Package rulepacks 提供纯离线 WAF 规则包的链式验签、静态门禁、差异预检、
// 版本化隔离存储、一键原子生效（联动配置发布与元数据同步）以及历史回滚能力。
//
// 安全约束：
//   - 100% 纯离线，不发起任何外部网络请求；
//   - 验签公钥固定内嵌于生产二进制，不允许通过环境变量或配置替换；
//   - 所有归档解析、版本比较、静态检查、备机落盘与回滚路径均 fail-closed；
//   - 绝不自动篡改客户已有的 custom_rules / exceptions / rule_overrides，仅在预检中预警。
package rulepacks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/wafrules"
)

// 规则包协议与归档常量
const (
	ProductWDSP         = "wdsp"
	PackageTypeRulePack = "rulepack"
	SchemaVersion       = 1

	// 资源上限（防压缩炸弹与 DoS）
	MaxArchiveBytes     int64 = 64 << 20  // 64 MiB
	MaxExpandedBytes    int64 = 256 << 20 // 256 MiB
	MaxSingleFileBytes  int64 = 16 << 20  // 16 MiB
	MaxArchiveEntries         = 10000
	MaxManifestBytes    int64 = 4 << 20 // 4 MiB
	MaxManifestSigBytes int64 = 4096

	// 历史快照保留数量策略（§十一已锁定：默认 5，可配 2-20）
	DefaultRetention = 5
	MinRetention     = 2
	MaxRetention     = 20

	// 默认网关容器/宿主机规则挂载根路径
	DefaultGatewayRulesRoot = "/etc/caddy/rules"
)

// 规则包档案状态
const (
	StatusVerified   = "VERIFIED"
	StatusRejected   = "REJECTED"
	StatusApplied    = "APPLIED"
	StatusSuperseded = "SUPERSEDED"
	StatusRolledBack = "ROLLED_BACK"
)

// 执行任务类型与状态机
const (
	JobTypeApply    = "APPLY"
	JobTypeRollback = "ROLLBACK"

	JobPending         = "PENDING"
	JobStagingLocal    = "STAGING_LOCAL"
	JobStagingStandby  = "STAGING_STANDBY"
	JobPublishing      = "PUBLISHING"
	JobActivating      = "ACTIVATING"
	JobSyncingMetadata = "SYNCING_METADATA"
	JobSuccess         = "SUCCESS"
	JobRollingBack     = "ROLLING_BACK"
	JobRolledBack      = "ROLLED_BACK"
	JobFailed          = "FAILED"
)

// HA 逐节点角色与阶段状态
const (
	NodeRolePrimary = "PRIMARY"
	NodeRoleStandby = "STANDBY"

	NodeStatusPending = "PENDING"
	NodeStatusSuccess = "SUCCESS"
	NodeStatusFailed  = "FAILED"
	NodeStatusSkipped = "SKIPPED"
)

// 存储模式描述
const (
	StorageModeVersioned = "VERSIONED"
	StorageModeLegacy    = "LEGACY_FLAT"
)

// 哨兵错误
var (
	ErrNotFound           = errors.New("规则包或任务不存在")
	ErrInvalidInput       = errors.New("规则包参数无效")
	ErrInvalidSignature   = errors.New("规则包 Ed25519 签名验证失败")
	ErrInvalidArchive     = errors.New("规则包归档格式或内容校验失败")
	ErrStaticGateFailed   = errors.New("规则包静态安全门禁未通过")
	ErrVersionDowngrade   = errors.New("规则包版本不得低于或等于当前生效版本")
	ErrVersionConflict    = errors.New("相同版本号的规则包已存在且摘要不一致")
	ErrIncompatibleSystem = errors.New("当前系统版本低于规则包要求的最低系统版本")
	ErrInvalidState       = errors.New("当前规则包状态不允许此操作")
	ErrActiveJob          = errors.New("已有规则包应用或回滚任务正在执行")
	ErrUpgradeActive      = errors.New("系统升级任务正在执行，请等待完成后再更新规则包")
	ErrRollbackUnavailable = errors.New("目标历史规则包快照已不可用，无法回滚")
	ErrSplitBrain         = errors.New("检测到未处置的主备脑裂告警，禁止应用规则包")
	ErrStandbyStageFailed = errors.New("HA 备节点规则包落盘校验失败")
	ErrStorageUnavailable = errors.New("规则包版本化存储目录未配置或不可写")
	ErrClusterUnsupported = errors.New("当前为单机模式或未启用 HA 节点协同代理")
	ErrConcurrentUpload   = errors.New("当前并发上传任务已达上限，请稍后重试")
)

var (
	// rulePackVersionRe 严格约束外部离线规则包版本号格式：YYYYMMDD.N（如 20261201.1）
	rulePackVersionRe = regexp.MustCompile(`^([0-9]{8})\.([0-9]{1,3})$`)
	// builtinVersionRe 约束系统内置基线种子版本名：builtin-<semver/token>
	builtinVersionRe = regexp.MustCompile(`^builtin-[0-9A-Za-z._-]+$`)
	// semverRe 简版语义化版本号
	semverRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?$`)
)

// IsBuiltinVersion 判断是否为内置基线种子版本名。
func IsBuiltinVersion(v string) bool {
	return builtinVersionRe.MatchString(strings.TrimSpace(v))
}

// ValidateRulePackVersion 校验外部上传离线规则包版本号（须为 YYYYMMDD.N 且日期合法）。
func ValidateRulePackVersion(v string) error {
	v = strings.TrimSpace(v)
	m := rulePackVersionRe.FindStringSubmatch(v)
	if m == nil {
		return fmt.Errorf("%w: 无效规则包版本号 %q（须为 YYYYMMDD.N，如 20261201.1）", ErrInvalidInput, v)
	}
	if _, err := time.Parse("20060102", m[1]); err != nil {
		return fmt.Errorf("%w: 规则包版本号日期段无效 %q", ErrInvalidInput, v)
	}
	seq, err := strconv.Atoi(m[2])
	if err != nil || seq <= 0 {
		return fmt.Errorf("%w: 规则包版本号序号段须为正整数 %q", ErrInvalidInput, v)
	}
	return nil
}

// ValidateAnyReleaseVersion 校验任意允许落盘的快照版本名（外部 YYYYMMDD.N 或 builtin-*）。
func ValidateAnyReleaseVersion(v string) error {
	v = strings.TrimSpace(v)
	if IsBuiltinVersion(v) {
		return nil
	}
	return ValidateRulePackVersion(v)
}

// CompareRulePackVersion 比较两个规则包版本号（-1 小于 / 0 等于 / 1 大于）。
// 内置种子（builtin-*）始终小于任意正式日期规则包（YYYYMMDD.N）；同为 builtin-* 时按语义版本/字典序比较。
func CompareRulePackVersion(a, b string) (int, error) {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == b {
		return 0, nil
	}
	aBuiltin := IsBuiltinVersion(a)
	bBuiltin := IsBuiltinVersion(b)
	if aBuiltin && !bBuiltin {
		if err := ValidateRulePackVersion(b); err != nil {
			return 0, err
		}
		return -1, nil
	}
	if !aBuiltin && bBuiltin {
		if err := ValidateRulePackVersion(a); err != nil {
			return 0, err
		}
		return 1, nil
	}
	if aBuiltin && bBuiltin {
		va := strings.TrimPrefix(a, "builtin-")
		vb := strings.TrimPrefix(b, "builtin-")
		if c, err := CompareSemver(va, vb); err == nil {
			return c, nil
		}
		if a < b {
			return -1, nil
		}
		return 1, nil
	}
	if err := ValidateRulePackVersion(a); err != nil {
		return 0, err
	}
	if err := ValidateRulePackVersion(b); err != nil {
		return 0, err
	}
	ma := rulePackVersionRe.FindStringSubmatch(a)
	mb := rulePackVersionRe.FindStringSubmatch(b)
	if ma[1] != mb[1] {
		if ma[1] < mb[1] {
			return -1, nil
		}
		return 1, nil
	}
	sa, _ := strconv.Atoi(ma[2])
	sb, _ := strconv.Atoi(mb[2])
	if sa < sb {
		return -1, nil
	}
	if sa > sb {
		return 1, nil
	}
	return 0, nil
}

// CompareSemver 比较两个 MAJOR.MINOR.PATCH 版本号。
func CompareSemver(a, b string) (int, error) {
	pa, err := parseSemver(a)
	if err != nil {
		return 0, err
	}
	pb, err := parseSemver(b)
	if err != nil {
		return 0, err
	}
	for i := 0; i < 3; i++ {
		if pa[i] < pb[i] {
			return -1, nil
		}
		if pa[i] > pb[i] {
			return 1, nil
		}
	}
	return 0, nil
}

func parseSemver(s string) ([3]int, error) {
	m := semverRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return [3]int{}, fmt.Errorf("invalid semver %q", s)
	}
	maj, _ := strconv.Atoi(m[1])
	min, _ := strconv.Atoi(m[2])
	pat, _ := strconv.Atoi(m[3])
	return [3]int{maj, min, pat}, nil
}

// IsTerminalJobStatus 判断执行任务是否处于终态。
func IsTerminalJobStatus(s string) bool {
	return s == JobSuccess || s == JobRolledBack || s == JobFailed
}

// Manifest 是离线规则包内 manifest.json 的结构定义。
type Manifest struct {
	SchemaVersion       int            `json:"schema_version"`
	Product             string         `json:"product"`
	PackageType         string         `json:"package_type"`
	RulePackVersion     string         `json:"rulepack_version"`
	CRSVersion          string         `json:"crs_version"`
	MinSystemVersion    string         `json:"min_system_version"`
	CorazaCompat        string         `json:"coraza_compat,omitempty"`
	ReleasedAt          string         `json:"released_at,omitempty"`
	Changelog           []string       `json:"changelog,omitempty"`
	RuleSummary         *RuleSummary   `json:"rule_summary,omitempty"`
	Files               []ManifestFile `json:"files"`
	FilesManifestSHA256 string         `json:"files_manifest_sha256"`
}

// RuleSummary 是规则包清单中声明的规则统计摘要。
type RuleSummary struct {
	TotalRules      int            `json:"total_rules"`
	BySource        map[string]int `json:"by_source,omitempty"`
	HighlightedCVEs []string       `json:"highlighted_cves,omitempty"`
}

// ManifestFile 描述归档内单个文件的精确校验信息。
type ManifestFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// RulePack 是 waf_rule_packs 表对应的规则包档案记录。
type RulePack struct {
	ID               uuid.UUID       `json:"id"`
	RulePackVersion  string          `json:"rulepack_version"`
	CRSVersion       string          `json:"crs_version"`
	MinSystemVersion string          `json:"min_system_version"`
	CorazaCompat     string          `json:"coraza_compat"`
	IsBuiltin        bool            `json:"is_builtin"`
	FileName         string          `json:"file_name"`
	FileSize         int64           `json:"file_size"`
	FileSHA256       string          `json:"file_sha256"`
	ManifestSHA256   string          `json:"manifest_sha256"`
	ManifestJSON     json.RawMessage `json:"manifest_json"`
	PreviewReport    json.RawMessage `json:"preview_report"`
	ArchivePath      string          `json:"-"` // 内部路径不外泄给前端
	Status           string          `json:"status"`
	RejectReason     string          `json:"reject_reason,omitempty"`
	UploadedBy       *uuid.UUID      `json:"uploaded_by,omitempty"`
	UploadedAt       time.Time       `json:"uploaded_at"`
	AppliedBy        *uuid.UUID      `json:"applied_by,omitempty"`
	AppliedAt        *time.Time      `json:"applied_at,omitempty"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
	// CanRollback 运行时计算字段：是否具备磁盘快照或签名归档可供一键回滚。
	CanRollback bool `json:"can_rollback"`
}

// PreviewReport 是上传即校验阶段生成的预检差异与影响报告。
type PreviewReport struct {
	VerifiedAt         time.Time             `json:"verified_at"`
	SignatureVerified  bool                  `json:"signature_verified"`
	IntegrityVerified  bool                  `json:"integrity_verified"`
	StaticGatePassed   bool                  `json:"static_gate_passed"`
	PreviousVersion    string                `json:"previous_version,omitempty"`
	PreviousCRSVersion string                `json:"previous_crs_version,omitempty"`
	TargetVersion      string                `json:"target_version"`
	TargetCRSVersion   string                `json:"target_crs_version"`
	Changelog          []string              `json:"changelog,omitempty"`
	HighlightedCVEs    []string              `json:"highlighted_cves,omitempty"`
	Diff               RuleDiffSummary       `json:"diff"`
	PolicyWarnings     []PolicyImpactWarning `json:"policy_warnings"`
	NodePrechecks      []NodePrecheckStatus  `json:"node_prechecks"`
	DiskFreeBytes      int64                 `json:"disk_free_bytes"`
	DiskOK             bool                  `json:"disk_ok"`
	SplitBrainDetected bool                  `json:"split_brain_detected"`
	ActiveUpgradeJob   bool                  `json:"active_upgrade_job"`
}

// RuleDiffSummary 统计候选规则包与当前激活规则集之间的规则差异。
type RuleDiffSummary struct {
	TotalRules     int              `json:"total_rules"`
	AddedCount     int              `json:"added_count"`
	UpdatedCount   int              `json:"updated_count"`
	RemovedCount   int              `json:"removed_count"`
	UnchangedCount int              `json:"unchanged_count"`
	BySource       map[string]int   `json:"by_source"`
	ByAttackType   map[string]int   `json:"by_attack_type"`
	AddedSamples   []RuleChangeItem `json:"added_samples,omitempty"`
	UpdatedSamples []RuleChangeItem `json:"updated_samples,omitempty"`
	RemovedSamples []RuleChangeItem `json:"removed_samples,omitempty"`
}

// RuleChangeItem 是规则增删改预览的抽样条目。
type RuleChangeItem struct {
	RuleID     int    `json:"rule_id"`
	RuleSource string `json:"rule_source"`
	FileName   string `json:"file_name"`
	Name       string `json:"name"`
	AttackType string `json:"attack_type"`
	Severity   string `json:"severity"`
}

// PolicyImpactWarning 描述规则变更对客户既有规则覆盖或例外策略的影响预警（只提示、不篡改）。
type PolicyImpactWarning struct {
	Kind       string `json:"kind"` // OVERRIDE_RULE_REMOVED / OVERRIDE_RULE_UPDATED / EXCEPTION_RULE_REMOVED / EXCEPTION_RULE_UPDATED / EXCEPTION_TAG_NEW_RULES
	ObjectID   string `json:"object_id"`
	ObjectName string `json:"object_name,omitempty"`
	RuleID     int    `json:"rule_id,omitempty"`
	Tag        string `json:"tag,omitempty"`
	Message    string `json:"message"`
}

// NodePrecheckStatus 是预检时各节点就绪态快照。
type NodePrecheckStatus struct {
	NodeID          *uuid.UUID `json:"node_id,omitempty"`
	NodeName        string     `json:"node_name"`
	Role            string     `json:"role"`
	Reachable       bool       `json:"reachable"`
	RulePackReady   bool       `json:"rulepack_ready"`
	CurrentVersion  string     `json:"current_version,omitempty"`
	Aligned         bool       `json:"aligned"`
	Error           string     `json:"error,omitempty"`
}

// Job 是 waf_rule_pack_jobs 表对应的应用/回滚任务。
type Job struct {
	ID              uuid.UUID       `json:"id"`
	JobType         string          `json:"job_type"`
	TargetPackID    uuid.UUID       `json:"target_pack_id"`
	TargetVersion   string          `json:"target_version,omitempty"`
	PreviousPackID  *uuid.UUID      `json:"previous_pack_id,omitempty"`
	PreviousVersion string          `json:"previous_version,omitempty"`
	PublishTaskID   *uuid.UUID      `json:"publish_task_id,omitempty"`
	Status          string          `json:"status"`
	CurrentStep     string          `json:"current_step"`
	Progress        int             `json:"progress"`
	AllowDegradedHA bool            `json:"allow_degraded_ha"`
	DegradedReason  string          `json:"degraded_reason,omitempty"`
	SyncReport      json.RawMessage `json:"sync_report,omitempty"`
	FailureCode     string          `json:"failure_code,omitempty"`
	FailureMessage  string          `json:"failure_message,omitempty"`
	RequestedBy     *uuid.UUID      `json:"requested_by,omitempty"`
	RequestID       string          `json:"request_id,omitempty"`
	StartedAt       *time.Time      `json:"started_at,omitempty"`
	FinishedAt      *time.Time      `json:"finished_at,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
	NodeStates      []NodeState     `json:"node_states,omitempty"`
}

// NodeState 是 waf_rule_pack_node_states 表对应的逐节点执行明细。
type NodeState struct {
	ID             uuid.UUID  `json:"id"`
	JobID          uuid.UUID  `json:"job_id"`
	NodeID         *uuid.UUID `json:"node_id,omitempty"`
	NodeName       string     `json:"node_name"`
	Role           string     `json:"role"`
	StageStatus    string     `json:"stage_status"`
	LoadStatus     string     `json:"load_status"`
	ActivateStatus string     `json:"activate_status"`
	ErrorCode      string     `json:"error_code,omitempty"`
	ErrorMessage   string     `json:"error_message,omitempty"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// ActiveRulesInfo 描述当前正在生效的规则目录与版本信息，供 gatewayconfig 与 wafrules 共享消费。
type ActiveRulesInfo struct {
	RulePackVersion      string
	CRSVersion           string
	StoreDir             string // API 侧规则版本目录根（版本化模式为 <store>/releases/<ver>）
	CRSRulesDir          string // API 侧 CRS rules 目录（<StoreDir>/crs/rules）
	GatewayRulesBasePath string // 网关侧 Include 根路径（如 /etc/caddy/rules/releases/20261201.1）
	IsBuiltin            bool
	StorageMode          string
	AppliedAt            *time.Time
}

// CurrentStatusResponse 是 GET /api/v1/rule-packs/current 的返回结构。
type CurrentStatusResponse struct {
	StorageMode          string               `json:"storage_mode"`
	Writable             bool                 `json:"writable"`
	Retention            int                  `json:"retention"`
	ActivePack           *RulePack            `json:"active_pack"`
	ActiveVersion        string               `json:"active_version"`
	ActiveCRSVersion     string               `json:"active_crs_version"`
	GatewayRulesBasePath string               `json:"gateway_rules_base_path"`
	LatestJob            *Job                 `json:"latest_job,omitempty"`
	HASyncEnabled        bool                 `json:"ha_sync_enabled"`
	Nodes                []NodePrecheckStatus `json:"nodes"`
	DriftDetected        bool                 `json:"drift_detected"`
}

// ApplyRequest 是 POST /api/v1/rule-packs/{id}/apply 与 /rollback 的请求体。
type ApplyRequest struct {
	AllowDegradedHA bool   `json:"allow_degraded_ha"`
	DegradedReason  string `json:"degraded_reason"`
}

// PublishResult 是规则包联动网关发布后的执行回执。
type PublishResult struct {
	PublishTaskID *uuid.UUID
	ZeroApps      bool
	Summary       string
}

// PublisherAdapter 抽象规则包切换时对网关发布器的调用（消除循环依赖并便于单测）。
type PublisherAdapter interface {
	// PublishWithRulePack 使用指定规则包版本与网关侧路径触发配置校验、加载、冒烟与 HA 扇出；
	// 零业务应用时执行独立 Coraza 指令校验（ValidateConfig）并返回 ZeroApps=true。
	PublishWithRulePack(ctx context.Context, rulePackVersion, gatewayRulesBasePath string, requestedBy uuid.UUID, requestID string) (*PublishResult, error)
	// RefreshSidecars 在激活完成后刷新 mirrorcap.json（携带最新 rules_dir）等边车配置。
	RefreshSidecars(ctx context.Context) error
}

// MetaSyncer 抽象规则包激活后的数据库规则元数据同步与原文缓存失效。
type MetaSyncer interface {
	SyncActiveRulePack(ctx context.Context, crsDir, crsVersion, rulePackVersion string) (*wafrules.SyncReport, error)
}

// UpgradeActiveChecker 检查当前是否存在活跃的系统升级任务（避免与规则包更新并发冲突）。
type UpgradeActiveChecker interface {
	HasActiveJob(ctx context.Context) (bool, error)
}

// ClusterNode 表示登记参与规则包协同的远端 HA 备节点。
type ClusterNode struct {
	NodeID        uuid.UUID
	NodeName      string
	SyncAgentAddr string
	SyncEnabled   bool
}

// RemoteRulePackStatus 表示远端 hasyncd GET /v1/rulepacks/status 的返回摘要。
type RemoteRulePackStatus struct {
	Reachable       bool
	RulePackReady   bool
	ActiveSymlink   string
	StagedVersions  map[string]string // version -> manifest_sha256
	DiskFreeBytes   int64
	Error           string
}

// ClusterRulePackSyncer 抽象 R2 HA 备节点规则包协同接口（R1 单机下为 nil，R2 由 nodesync.Manager 实现）。
type ClusterRulePackSyncer interface {
	ListStandbyNodes(ctx context.Context) ([]ClusterNode, error)
	HasOpenSplitBrain(ctx context.Context) (bool, error)
	CheckNodeRulePackStatus(ctx context.Context, nodeID uuid.UUID) (*RemoteRulePackStatus, error)
	StageRulePack(ctx context.Context, nodeID uuid.UUID, version, archivePath, fileSHA256 string) error
	ActivateRulePack(ctx context.Context, nodeID uuid.UUID, version, manifestSHA256 string) error
	PruneRulePack(ctx context.Context, nodeID uuid.UUID, version string) error
	RetryNodeConfigSync(ctx context.Context, nodeID uuid.UUID) error
}

// AlertEmitter 系统告警发射器（用于 HA 降级漂移告警与执行失败告警）。
type AlertEmitter func(ctx context.Context, alertType, severity, component, title, message string)
