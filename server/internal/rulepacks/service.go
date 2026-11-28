package rulepacks

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/cache"
	"github.com/jiuzhang-waf/server/internal/wafrules"
	"github.com/redis/go-redis/v9"
)

const (
	applyLockKey = "lock:rulepack:apply"
	applyLockTTL = 5 * time.Minute
	maxDiffSample = 30
)

// Config 描述规则包管理服务的运行期参数。
type Config struct {
	StoreDir             string // API 侧可写规则包版本存储目录（如 /app/runtime/rules）
	ArchivesDir          string // 签名原始规则包归档存储目录（如 /app/runtime/rulepack-archives）
	SeedDir              string // 内置规则种子目录（如 /app/gateway/rules 或 gateway/rules）
	FallbackCRSDir       string // 未启用版本化存储时的兜底 CRS 目录（WAF_CRS_DIR）
	FallbackCRSVersion   string // 兜底 CRS 版本（WAF_CRS_VERSION）
	GatewayRulesRoot     string // 网关侧 Include 根路径（默认 /etc/caddy/rules）
	CurrentSystemVersion string // 当前系统版本号（供 min_system_version 兼容性门禁校验）
	LocalNodeName        string // 本机主节点名称
	Retention            int    // 历史快照保留数量（2-20，默认 5）
}

// Service 编排离线规则包的初始化、上传预检、一键生效、HA 协同与回滚。
type Service struct {
	cfg            Config
	store          *Store
	storage        *Storage
	cache          *cache.Client
	publisher      PublisherAdapter
	metaSyncer     MetaSyncer
	upgradeChecker UpgradeActiveChecker
	clusterSyncer  ClusterRulePackSyncer
	alertEmitter   AlertEmitter
	verifyKey      ed25519.PublicKey // nil 时使用内嵌生产公钥 releasePublicKeyPEM
	diskFreeFn     func(string) int64

	applyMu sync.Mutex
}

// NewService 创建规则包编排服务。
func NewService(cfg Config, store *Store, cacheClient *cache.Client) *Service {
	if strings.TrimSpace(cfg.GatewayRulesRoot) == "" {
		cfg.GatewayRulesRoot = DefaultGatewayRulesRoot
	}
	if cfg.Retention < MinRetention || cfg.Retention > MaxRetention {
		cfg.Retention = DefaultRetention
	}
	if strings.TrimSpace(cfg.LocalNodeName) == "" {
		cfg.LocalNodeName = "primary"
	}
	if strings.TrimSpace(cfg.FallbackCRSVersion) == "" {
		cfg.FallbackCRSVersion = "4.28.0"
	}
	storage := NewStorage(cfg.StoreDir, cfg.ArchivesDir)
	return &Service{
		cfg:     cfg,
		store:   store,
		storage: storage,
		cache:   cacheClient,
	}
}

// SetPublisher 注入网关发布适配器。
func (s *Service) SetPublisher(p PublisherAdapter) *Service {
	s.publisher = p
	return s
}

// SetMetaSyncer 注入规则库元数据同步器。
func (s *Service) SetMetaSyncer(m MetaSyncer) *Service {
	s.metaSyncer = m
	return s
}

// SetUpgradeChecker 注入系统升级活跃任务检查器。
func (s *Service) SetUpgradeChecker(u UpgradeActiveChecker) *Service {
	s.upgradeChecker = u
	return s
}

// SetClusterSyncer 注入 HA 备节点规则包协同客户端（R2 接线）。
func (s *Service) SetClusterSyncer(c ClusterRulePackSyncer) *Service {
	s.clusterSyncer = c
	return s
}

// SetAlertEmitter 注入系统告警回调。
func (s *Service) SetAlertEmitter(fn AlertEmitter) *Service {
	s.alertEmitter = fn
	return s
}

// SetVerifyPublicKeyForTest 仅用于单元测试覆盖验签公钥（生产代码不调用）。
func (s *Service) SetVerifyPublicKeyForTest(pub ed25519.PublicKey) *Service {
	s.verifyKey = pub
	return s
}

// Storage 返回底层规则存储管理器。
func (s *Service) Storage() *Storage {
	return s.storage
}

// Store 返回底层数据库仓储。
func (s *Service) Store() *Store {
	return s.store
}

// EnsureInitialized 启动引导：若启用了版本化存储且尚未初始化，则自动从种子目录初始化基线快照并在库中登记。
func (s *Service) EnsureInitialized(ctx context.Context) error {
	if !s.storage.Enabled() {
		return nil
	}
	builtinVer := "builtin-" + strings.TrimPrefix(strings.TrimSpace(s.cfg.CurrentSystemVersion), "v")
	if !IsBuiltinVersion(builtinVer) {
		builtinVer = "builtin-0.0.0"
	}
	seeded, activeVer, err := s.storage.EnsureSeeded(s.cfg.SeedDir, builtinVer)
	if err != nil {
		return err
	}
	if s.store != nil {
		crsVer := readCRSVersionFromDir(s.storage.ReleaseDir(activeVer), s.cfg.FallbackCRSVersion)
		if _, err := s.store.EnsureBuiltinPack(ctx, activeVer, crsVer); err != nil {
			return err
		}
	}
	if seeded {
		slog.Info("initialized versioned waf rules store from seed", "version", activeVer, "store_dir", s.storage.StoreDir())
	}
	return nil
}

// ActiveRulesInfo 返回当前生效规则集路径与版本，供 gatewayconfig 与 wafrules 统一消费。
func (s *Service) ActiveRulesInfo(ctx context.Context) ActiveRulesInfo {
	// 1. 优先读数据库中当前 APPLIED 规则包（且本地快照存在）
	if s.storage.Enabled() && s.store != nil {
		if pack, err := s.store.GetAppliedPack(ctx); err == nil && pack != nil && s.storage.HasRelease(pack.RulePackVersion) {
			return ActiveRulesInfo{
				RulePackVersion:      pack.RulePackVersion,
				CRSVersion:           pack.CRSVersion,
				StoreDir:             s.storage.ReleaseDir(pack.RulePackVersion),
				CRSRulesDir:          s.storage.ReleaseCRSDir(pack.RulePackVersion),
				GatewayRulesBasePath: path.Join(s.cfg.GatewayRulesRoot, "releases", pack.RulePackVersion),
				IsBuiltin:            pack.IsBuiltin,
				StorageMode:          StorageModeVersioned,
				AppliedAt:            pack.AppliedAt,
			}
		}
	}
	// 2. 次优读磁盘 current 软链
	if s.storage.Enabled() {
		if ver, err := s.storage.CurrentSymlinkVersion(); err == nil && ver != "" && s.storage.HasRelease(ver) {
			return ActiveRulesInfo{
				RulePackVersion:      ver,
				CRSVersion:           readCRSVersionFromDir(s.storage.ReleaseDir(ver), s.cfg.FallbackCRSVersion),
				StoreDir:             s.storage.ReleaseDir(ver),
				CRSRulesDir:          s.storage.ReleaseCRSDir(ver),
				GatewayRulesBasePath: path.Join(s.cfg.GatewayRulesRoot, "releases", ver),
				IsBuiltin:            IsBuiltinVersion(ver),
				StorageMode:          StorageModeVersioned,
			}
		}
	}
	// 3. 回退旧版扁平目录（开发模式或未迁移环境）
	resolvedCRS := wafrules.ResolveCRSDir(s.cfg.FallbackCRSDir)
	return ActiveRulesInfo{
		RulePackVersion:      "",
		CRSVersion:           s.cfg.FallbackCRSVersion,
		StoreDir:             filepath.Dir(filepath.Dir(resolvedCRS)),
		CRSRulesDir:          resolvedCRS,
		GatewayRulesBasePath: s.cfg.GatewayRulesRoot,
		IsBuiltin:            true,
		StorageMode:          StorageModeLegacy,
	}
}

// GetCurrentStatus 聚合当前激活规则包、最近任务与 HA 节点对齐状态。
func (s *Service) GetCurrentStatus(ctx context.Context) (*CurrentStatusResponse, error) {
	activeInfo := s.ActiveRulesInfo(ctx)
	var activePack *RulePack
	var latestJob *Job
	if s.store != nil {
		if p, err := s.store.GetAppliedPack(ctx); err == nil {
			p.CanRollback = false
			activePack = p
		}
		if j, err := s.store.GetLatestJob(ctx); err == nil {
			latestJob = j
		}
	}
	nodes, drift, haEnabled := s.collectNodeStatuses(ctx, activeInfo.RulePackVersion)
	return &CurrentStatusResponse{
		StorageMode:          activeInfo.StorageMode,
		Writable:             s.storage.Writable(),
		Retention:            s.cfg.Retention,
		ActivePack:           activePack,
		ActiveVersion:        activeInfo.RulePackVersion,
		ActiveCRSVersion:     activeInfo.CRSVersion,
		GatewayRulesBasePath: activeInfo.GatewayRulesBasePath,
		LatestJob:            latestJob,
		HASyncEnabled:        haEnabled,
		Nodes:                nodes,
		DriftDetected:        drift,
	}, nil
}

// ListPacks 分页列出规则包，并动态计算 CanRollback。
func (s *Service) ListPacks(ctx context.Context, page, pageSize int) ([]RulePack, int64, error) {
	items, total, err := s.store.ListPacks(ctx, page, pageSize)
	if err != nil {
		return nil, 0, err
	}
	for i := range items {
		items[i].CanRollback = s.canRollbackPack(&items[i])
	}
	return items, total, nil
}

// GetPack 查询单个规则包详情。
func (s *Service) GetPack(ctx context.Context, id uuid.UUID) (*RulePack, error) {
	p, err := s.store.GetPack(ctx, id)
	if err != nil {
		return nil, err
	}
	p.CanRollback = s.canRollbackPack(p)
	return p, nil
}

// GetJob 查询任务详情。
func (s *Service) GetJob(ctx context.Context, id uuid.UUID) (*Job, error) {
	return s.store.GetJob(ctx, id)
}

func (s *Service) canRollbackPack(p *RulePack) bool {
	if p == nil || p.Status == StatusApplied || p.Status == StatusRejected || p.Status == StatusVerified {
		return false
	}
	if s.storage.HasRelease(p.RulePackVersion) {
		return true
	}
	if p.ArchivePath != "" {
		if st, err := os.Stat(p.ArchivePath); err == nil && st.Mode().IsRegular() {
			return true
		}
	}
	return false
}

// UploadAndVerify 阶段一：上传即校验（零现网副作用）。
// 依次执行 Ed25519 验签 → 归档完整性 → 版本防降级 → 临时解压静态门禁 → 差异与客户策略影响预览 → 节点预检，
// 通过后持久化签名原始归档并登记 VERIFIED 记录；失败则清理临时文件并返回明确错误。
func (s *Service) UploadAndVerify(ctx context.Context, tmpArchivePath, origFileName string, uploadedBy *uuid.UUID) (*RulePack, error) {
	if !s.storage.Writable() {
		return nil, ErrStorageUnavailable
	}
	if s.store == nil {
		return nil, errors.New("rulepack store unavailable")
	}
	if err := s.EnsureInitialized(ctx); err != nil {
		return nil, fmt.Errorf("初始化规则存储失败: %w", err)
	}

	// 1. 信任根验签 + 归档完整性 + 系统最低版本门禁
	art, err := s.verifyArtifact(tmpArchivePath)
	if err != nil {
		return nil, err
	}

	// 2. 防降级与同版本重传幂等校验
	activeInfo := s.ActiveRulesInfo(ctx)
	if existing, err := s.store.GetPackByVersion(ctx, art.Manifest.RulePackVersion); err == nil && existing != nil {
		if !strings.EqualFold(existing.FileSHA256, art.FileSHA256) {
			return nil, fmt.Errorf("%w: 版本 %s 已登记（SHA256 %.12s），拒绝以不同内容覆盖",
				ErrVersionConflict, art.Manifest.RulePackVersion, existing.FileSHA256)
		}
		if existing.Status == StatusVerified {
			// 同版本同哈希重复上传：刷新预检报告并幂等返回
			preview, perr := s.buildPreviewReport(ctx, tmpArchivePath, art, activeInfo)
			if perr == nil {
				if raw, merr := json.Marshal(preview); merr == nil {
					_ = s.store.UpdatePackPreview(ctx, existing.ID, raw)
					existing.PreviewReport = raw
				}
			}
			_ = os.Remove(tmpArchivePath)
			return existing, nil
		}
		return nil, fmt.Errorf("%w: 版本 %s 当前状态为 %s（如需回退历史版本请使用「回滚」功能）",
			ErrVersionDowngrade, art.Manifest.RulePackVersion, existing.Status)
	}

	if activeInfo.RulePackVersion != "" {
		cmp, err := CompareRulePackVersion(art.Manifest.RulePackVersion, activeInfo.RulePackVersion)
		if err != nil {
			return nil, err
		}
		if cmp <= 0 {
			return nil, fmt.Errorf("%w: 上传版本 %s 必须高于当前生效版本 %s（历史版本恢复请走「回滚」通道）",
				ErrVersionDowngrade, art.Manifest.RulePackVersion, activeInfo.RulePackVersion)
		}
	}

	// 3. 临时目录解压 + 静态安全门禁 + 差异与影响预检（零现网副作用）
	preview, err := s.buildPreviewReport(ctx, tmpArchivePath, art, activeInfo)
	if err != nil {
		return nil, err
	}
	previewRaw, err := json.Marshal(preview)
	if err != nil {
		return nil, fmt.Errorf("序列化预检报告失败: %w", err)
	}

	// 4. 持久化签名归档并落库 VERIFIED
	packID := uuid.New()
	archivePath, err := s.storage.PersistArchive(tmpArchivePath, packID)
	if err != nil {
		return nil, fmt.Errorf("保存规则包归档失败: %w", err)
	}
	pack := &RulePack{
		ID:               packID,
		RulePackVersion:  art.Manifest.RulePackVersion,
		CRSVersion:       art.Manifest.CRSVersion,
		MinSystemVersion: art.Manifest.MinSystemVersion,
		CorazaCompat:     art.Manifest.CorazaCompat,
		IsBuiltin:        false,
		FileName:         filepath.Base(origFileName),
		FileSize:         art.FileSize,
		FileSHA256:       art.FileSHA256,
		ManifestSHA256:   art.ManifestSHA256,
		ManifestJSON:     art.ManifestRaw,
		PreviewReport:    previewRaw,
		ArchivePath:      archivePath,
		Status:           StatusVerified,
		UploadedBy:       uploadedBy,
	}
	created, err := s.store.CreatePack(ctx, pack)
	if err != nil {
		_ = os.Remove(archivePath)
		return nil, err
	}
	return created, nil
}

func (s *Service) buildPreviewReport(ctx context.Context, archivePath string, art *VerifiedArtifact, activeInfo ActiveRulesInfo) (*PreviewReport, error) {
	tmpDir, err := os.MkdirTemp(s.storage.StagingDir(), "preview-"+art.Manifest.RulePackVersion+"-")
	if err != nil {
		return nil, fmt.Errorf("创建预检临时目录失败: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	if err := ExtractRulesToDir(archivePath, tmpDir); err != nil {
		return nil, err
	}
	staticRes, err := StaticGateCheckDir(tmpDir)
	if err != nil {
		return nil, err
	}

	// 解析当前激活规则集以计算精确差异
	var curRules []*wafrules.Rule
	if activeInfo.CRSRulesDir != "" {
		curRules = loadAllRulesBestEffort(activeInfo.CRSRulesDir)
	}
	diff, addedByTag, removedIDs, updatedIDs := computeRuleDiff(curRules, staticRes.Rules)

	// 客户策略影响预警（只读扫描 rule_overrides 与 exceptions）
	warnings := s.computePolicyWarnings(ctx, addedByTag, removedIDs, updatedIDs)

	// 节点与磁盘/互斥预检
	nodes, _, _ := s.collectNodeStatuses(ctx, activeInfo.RulePackVersion)
	splitBrain := false
	if s.clusterSyncer != nil {
		if sb, serr := s.clusterSyncer.HasOpenSplitBrain(ctx); serr == nil {
			splitBrain = sb
		}
	}
	upgradeActive := false
	if s.upgradeChecker != nil {
		if ua, uerr := s.upgradeChecker.HasActiveJob(ctx); uerr == nil {
			upgradeActive = ua
		}
	}
	freeBytes := s.diskFree(s.storage.StoreDir())
	needBytes := art.FileSize * 4
	if needBytes < 32<<20 {
		needBytes = 32 << 20
	}
	diskOK := freeBytes < 0 || freeBytes >= needBytes

	highlightedCVEs := staticRes.DetectedCVEs
	if art.Manifest.RuleSummary != nil && len(art.Manifest.RuleSummary.HighlightedCVEs) > 0 {
		highlightedCVEs = art.Manifest.RuleSummary.HighlightedCVEs
	}
	return &PreviewReport{
		VerifiedAt:         time.Now().UTC(),
		SignatureVerified:  true,
		IntegrityVerified:  true,
		StaticGatePassed:   true,
		PreviousVersion:    activeInfo.RulePackVersion,
		PreviousCRSVersion: activeInfo.CRSVersion,
		TargetVersion:      art.Manifest.RulePackVersion,
		TargetCRSVersion:   art.Manifest.CRSVersion,
		Changelog:          art.Manifest.Changelog,
		HighlightedCVEs:    highlightedCVEs,
		Diff:               diff,
		PolicyWarnings:     warnings,
		NodePrechecks:      nodes,
		DiskFreeBytes:      freeBytes,
		DiskOK:             diskOK,
		SplitBrainDetected: splitBrain,
		ActiveUpgradeJob:   upgradeActive,
	}, nil
}

// StartApply 阶段二入口：校验前置门禁并异步启动一键生效任务。
func (s *Service) StartApply(ctx context.Context, packID uuid.UUID, req ApplyRequest, requestedBy uuid.UUID, requestID string) (*Job, error) {
	job, pack, prevPack, err := s.prepareJob(ctx, JobTypeApply, packID, req, requestedBy, requestID)
	if err != nil {
		return nil, err
	}
	go s.executeJob(context.Background(), job, pack, prevPack, requestedBy, requestID)
	return job, nil
}

// ApplySync 同步执行一键生效（供集成测试与单测使用）。
func (s *Service) ApplySync(ctx context.Context, packID uuid.UUID, req ApplyRequest, requestedBy uuid.UUID, requestID string) (*Job, error) {
	job, pack, prevPack, err := s.prepareJob(ctx, JobTypeApply, packID, req, requestedBy, requestID)
	if err != nil {
		return nil, err
	}
	s.executeJob(ctx, job, pack, prevPack, requestedBy, requestID)
	return s.store.GetJob(ctx, job.ID)
}

// StartRollback 阶段三入口：校验历史快照并异步启动一键回滚任务。
func (s *Service) StartRollback(ctx context.Context, targetPackID uuid.UUID, req ApplyRequest, requestedBy uuid.UUID, requestID string) (*Job, error) {
	job, pack, prevPack, err := s.prepareJob(ctx, JobTypeRollback, targetPackID, req, requestedBy, requestID)
	if err != nil {
		return nil, err
	}
	go s.executeJob(context.Background(), job, pack, prevPack, requestedBy, requestID)
	return job, nil
}

// RollbackSync 同步执行一键回滚（供集成测试与单测使用）。
func (s *Service) RollbackSync(ctx context.Context, targetPackID uuid.UUID, req ApplyRequest, requestedBy uuid.UUID, requestID string) (*Job, error) {
	job, pack, prevPack, err := s.prepareJob(ctx, JobTypeRollback, targetPackID, req, requestedBy, requestID)
	if err != nil {
		return nil, err
	}
	s.executeJob(ctx, job, pack, prevPack, requestedBy, requestID)
	return s.store.GetJob(ctx, job.ID)
}

func (s *Service) prepareJob(ctx context.Context, jobType string, targetPackID uuid.UUID, req ApplyRequest, requestedBy uuid.UUID, requestID string) (*Job, *RulePack, *RulePack, error) {
	if !s.storage.Writable() {
		return nil, nil, nil, ErrStorageUnavailable
	}
	if req.AllowDegradedHA && strings.TrimSpace(req.DegradedReason) == "" {
		return nil, nil, nil, fmt.Errorf("%w: 开启 HA 备机离线降级生效时必须填写应急原因", ErrInvalidInput)
	}
	if s.upgradeChecker != nil {
		active, err := s.upgradeChecker.HasActiveJob(ctx)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("检查系统升级状态失败: %w", err)
		}
		if active {
			return nil, nil, nil, ErrUpgradeActive
		}
	}
	if s.clusterSyncer != nil {
		sb, err := s.clusterSyncer.HasOpenSplitBrain(ctx)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("检查主备脑裂状态失败: %w", err)
		}
		if sb {
			return nil, nil, nil, ErrSplitBrain
		}
	}

	targetPack, err := s.store.GetPack(ctx, targetPackID)
	if err != nil {
		return nil, nil, nil, err
	}
	if jobType == JobTypeApply {
		if targetPack.Status != StatusVerified {
			return nil, nil, nil, fmt.Errorf("%w: 仅 VERIFIED 状态的规则包可执行应用（当前状态: %s）", ErrInvalidState, targetPack.Status)
		}
		if targetPack.ArchivePath == "" {
			return nil, nil, nil, fmt.Errorf("%w: 规则包签名归档路径缺失", ErrInvalidArchive)
		}
		// 应用前强制复验磁盘归档的 SHA-256 与 Ed25519 签名（防落盘后被篡改）
		art, verr := s.verifyArtifact(targetPack.ArchivePath)
		if verr != nil {
			return nil, nil, nil, verr
		}
		if !strings.EqualFold(art.FileSHA256, targetPack.FileSHA256) || !strings.EqualFold(art.ManifestSHA256, targetPack.ManifestSHA256) {
			return nil, nil, nil, fmt.Errorf("%w: 磁盘规则包归档摘要与登记记录不一致，拒绝应用", ErrInvalidArchive)
		}
	} else {
		if targetPack.Status == StatusApplied || targetPack.Status == StatusRejected || targetPack.Status == StatusVerified {
			return nil, nil, nil, fmt.Errorf("%w: 目标规则包状态 (%s) 不允许回滚", ErrInvalidState, targetPack.Status)
		}
		if !s.canRollbackPack(targetPack) {
			return nil, nil, nil, ErrRollbackUnavailable
		}
	}

	var prevPack *RulePack
	var prevID *uuid.UUID
	if cur, err := s.store.GetAppliedPack(ctx); err == nil && cur != nil {
		prevPack = cur
		id := cur.ID
		prevID = &id
	}

	var reqByPtr *uuid.UUID
	if requestedBy != uuid.Nil {
		id := requestedBy
		reqByPtr = &id
	}
	job, err := s.store.CreateJobIfNoActive(ctx, &Job{
		JobType:         jobType,
		TargetPackID:    targetPack.ID,
		PreviousPackID:  prevID,
		Status:          JobPending,
		CurrentStep:     "准备执行规则包任务",
		Progress:        5,
		AllowDegradedHA: req.AllowDegradedHA,
		DegradedReason:  strings.TrimSpace(req.DegradedReason),
		RequestedBy:     reqByPtr,
		RequestID:       requestID,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	job.TargetVersion = targetPack.RulePackVersion
	if prevPack != nil {
		job.PreviousVersion = prevPack.RulePackVersion
	}
	return job, targetPack, prevPack, nil
}

func (s *Service) executeJob(ctx context.Context, job *Job, targetPack, prevPack *RulePack, requestedBy uuid.UUID, requestID string) {
	releaseLock, err := s.acquireApplyLock(ctx, job.ID.String())
	if err != nil {
		_ = s.store.FinishJob(ctx, job.ID, JobFailed, "获取分布式锁失败", "LOCK_BUSY", err.Error(), nil)
		return
	}
	defer releaseLock()

	// 创建主节点明细记录
	primaryState, _ := s.store.CreateNodeState(ctx, &NodeState{
		JobID:          job.ID,
		NodeName:       s.cfg.LocalNodeName,
		Role:           NodeRolePrimary,
		StageStatus:    NodeStatusPending,
		LoadStatus:     NodeStatusPending,
		ActivateStatus: NodeStatusPending,
	})

	failJob := func(code, msg string) {
		slog.Warn("rulepack job failed", "job_id", job.ID, "type", job.JobType, "version", targetPack.RulePackVersion, "code", code, "error", msg)
		_ = s.store.FinishJob(ctx, job.ID, JobFailed, "执行失败（现网保持原版本）", code, msg, nil)
		if s.alertEmitter != nil {
			s.alertEmitter(ctx, "RULEPACK_APPLY_FAILED", "HIGH", "waf_rule_packs",
				fmt.Sprintf("离线规则包 %s 执行失败", targetPack.RulePackVersion),
				fmt.Sprintf("任务类型=%s 失败码=%s 原因=%s", job.JobType, code, msg))
		}
	}

	// Step 1: 主节点隔离解包（不触碰旧版本快照）
	_ = s.store.UpdateJobStep(ctx, job.ID, JobStagingLocal, "主节点解包并校验规则快照", 15)
	if job.JobType == JobTypeApply || !s.storage.HasRelease(targetPack.RulePackVersion) {
		if targetPack.ArchivePath == "" {
			if primaryState != nil {
				_ = s.store.UpdateNodeState(ctx, primaryState.ID, NodeStatusFailed, NodeStatusSkipped, NodeStatusSkipped, "ARCHIVE_MISSING", "签名归档缺失")
			}
			failJob("STAGE_LOCAL_FAILED", "规则包签名归档不可用，无法解包")
			return
		}
		if _, err := s.storage.StageArchive(targetPack.ArchivePath, targetPack.RulePackVersion); err != nil {
			if primaryState != nil {
				_ = s.store.UpdateNodeState(ctx, primaryState.ID, NodeStatusFailed, NodeStatusSkipped, NodeStatusSkipped, "STAGE_LOCAL_FAILED", err.Error())
			}
			failJob("STAGE_LOCAL_FAILED", "主节点解包失败: "+err.Error())
			return
		}
	}
	if primaryState != nil {
		_ = s.store.UpdateNodeState(ctx, primaryState.ID, NodeStatusSuccess, NodeStatusPending, NodeStatusPending, "", "")
	}

	// Step 2: HA 备节点先备后主落盘（Stage）
	var stagedStandbys []struct {
		node  ClusterNode
		state *NodeState
	}
	if s.clusterSyncer != nil {
		standbys, err := s.clusterSyncer.ListStandbyNodes(ctx)
		if err != nil {
			failJob("HA_NODE_LIST_FAILED", "查询 HA 备节点失败: "+err.Error())
			return
		}
		if len(standbys) > 0 {
			_ = s.store.UpdateJobStep(ctx, job.ID, JobStagingStandby, "向 HA 备节点分发并独立验签落盘", 30)
			for _, node := range standbys {
				nst, _ := s.store.CreateNodeState(ctx, &NodeState{
					JobID:          job.ID,
					NodeID:         &node.NodeID,
					NodeName:       node.NodeName,
					Role:           NodeRoleStandby,
					StageStatus:    NodeStatusPending,
					LoadStatus:     NodeStatusPending,
					ActivateStatus: NodeStatusPending,
				})
				var stageErr error
				if job.JobType == JobTypeRollback {
					st, serr := s.clusterSyncer.CheckNodeRulePackStatus(ctx, node.NodeID)
					if serr != nil {
						stageErr = serr
					} else if st == nil || !st.RulePackReady {
						stageErr = errors.New("备节点 hasyncd 未就绪或不支持规则包协议")
					} else if _, hasVer := st.StagedVersions[targetPack.RulePackVersion]; !hasVer {
						if targetPack.ArchivePath == "" {
							stageErr = fmt.Errorf("备节点缺少目标历史快照 %s 且主节点无原始归档补发", targetPack.RulePackVersion)
						} else {
							stageErr = s.clusterSyncer.StageRulePack(ctx, node.NodeID, targetPack.RulePackVersion, targetPack.ArchivePath, targetPack.FileSHA256)
						}
					}
				} else {
					stageErr = s.clusterSyncer.StageRulePack(ctx, node.NodeID, targetPack.RulePackVersion, targetPack.ArchivePath, targetPack.FileSHA256)
				}

				if stageErr != nil {
					if nst != nil {
						_ = s.store.UpdateNodeState(ctx, nst.ID, NodeStatusFailed, NodeStatusSkipped, NodeStatusSkipped, "STANDBY_STAGE_FAILED", stageErr.Error())
					}
					if !job.AllowDegradedHA {
						failJob("STANDBY_STAGE_FAILED", fmt.Sprintf("备节点 %s 规则包落盘失败（已中止，未触碰主节点）: %v", node.NodeName, stageErr))
						return
					}
					// 显式降级：发高危漂移告警后继续
					if s.alertEmitter != nil {
						s.alertEmitter(ctx, "RULEPACK_NODE_DRIFT", "HIGH", "waf_rule_packs",
							fmt.Sprintf("规则包 %s 降级仅主节点生效（备机 %s 未同步）", targetPack.RulePackVersion, node.NodeName),
							fmt.Sprintf("原因=%s 错误=%v", job.DegradedReason, stageErr))
					}
					continue
				}
				if nst != nil {
					_ = s.store.UpdateNodeState(ctx, nst.ID, NodeStatusSuccess, NodeStatusPending, NodeStatusPending, "", "")
				}
				stagedStandbys = append(stagedStandbys, struct {
					node  ClusterNode
					state *NodeState
				}{node: node, state: nst})
			}
		}
	}

	// Step 3: 联动配置发布到网关（显式指向 releases/<target_ver>/，含 ValidateConfig /load + 冒烟 + HA 扇出）
	_ = s.store.UpdateJobStep(ctx, job.ID, JobPublishing, "校验并发布新规则集到网关", 55)
	gatewayRulesBase := path.Join(s.cfg.GatewayRulesRoot, "releases", targetPack.RulePackVersion)
	if s.publisher != nil {
		pubRes, err := s.publisher.PublishWithRulePack(ctx, targetPack.RulePackVersion, gatewayRulesBase, requestedBy, requestID)
		if err != nil {
			if primaryState != nil {
				_ = s.store.UpdateNodeState(ctx, primaryState.ID, NodeStatusSuccess, NodeStatusFailed, NodeStatusSkipped, "GATEWAY_PUBLISH_FAILED", err.Error())
			}
			failJob("GATEWAY_PUBLISH_FAILED", "网关发布验证失败，已自动保持旧规则版本: "+err.Error())
			return
		}
		if pubRes != nil && pubRes.PublishTaskID != nil {
			_ = s.store.SetJobPublishTask(ctx, job.ID, *pubRes.PublishTaskID)
		}
	}
	if primaryState != nil {
		_ = s.store.UpdateNodeState(ctx, primaryState.ID, NodeStatusSuccess, NodeStatusSuccess, NodeStatusPending, "", "")
	}
	for _, sb := range stagedStandbys {
		if sb.state != nil {
			_ = s.store.UpdateNodeState(ctx, sb.state.ID, NodeStatusSuccess, NodeStatusSuccess, NodeStatusPending, "", "")
		}
	}

	// Step 4: 原子切换 current 相对软链、切换数据库 APPLIED 指针、刷新 mirrorcap.json
	_ = s.store.UpdateJobStep(ctx, job.ID, JobActivating, "原子切换激活规则版本与旁路配置", 75)
	if err := s.storage.SwitchCurrentSymlink(targetPack.RulePackVersion); err != nil {
		if primaryState != nil {
			_ = s.store.UpdateNodeState(ctx, primaryState.ID, NodeStatusSuccess, NodeStatusSuccess, NodeStatusFailed, "SYMLINK_SWITCH_FAILED", err.Error())
		}
		failJob("ACTIVATE_FAILED", "切换 current 软链失败: "+err.Error())
		return
	}
	prevTargetStatus := StatusSuperseded
	if job.JobType == JobTypeRollback {
		prevTargetStatus = StatusRolledBack
	}
	var appliedByPtr *uuid.UUID
	if requestedBy != uuid.Nil {
		id := requestedBy
		appliedByPtr = &id
	}
	if err := s.store.ActivatePack(ctx, targetPack.ID, prevTargetStatus, appliedByPtr); err != nil {
		if prevPack != nil {
			_ = s.storage.SwitchCurrentSymlink(prevPack.RulePackVersion)
		}
		failJob("ACTIVATE_DB_FAILED", "切换数据库激活版本失败: "+err.Error())
		return
	}
	if primaryState != nil {
		_ = s.store.UpdateNodeState(ctx, primaryState.ID, NodeStatusSuccess, NodeStatusSuccess, NodeStatusSuccess, "", "")
	}
	// 切换备节点 current 软链（附加：不回滚已成功加载的网关，失败记告警并可重试）
	for _, sb := range stagedStandbys {
		if err := s.clusterSyncer.ActivateRulePack(ctx, sb.node.NodeID, targetPack.RulePackVersion, targetPack.ManifestSHA256); err != nil {
			if sb.state != nil {
				_ = s.store.UpdateNodeState(ctx, sb.state.ID, NodeStatusSuccess, NodeStatusSuccess, NodeStatusFailed, "STANDBY_ACTIVATE_FAILED", err.Error())
			}
			slog.Warn("activate rulepack symlink on standby failed", "node", sb.node.NodeName, "version", targetPack.RulePackVersion, "error", err)
		} else if sb.state != nil {
			_ = s.store.UpdateNodeState(ctx, sb.state.ID, NodeStatusSuccess, NodeStatusSuccess, NodeStatusSuccess, "", "")
		}
	}
	if s.publisher != nil {
		if err := s.publisher.RefreshSidecars(ctx); err != nil {
			slog.Warn("refresh mirrorcap sidecar after rulepack switch failed", "version", targetPack.RulePackVersion, "error", err)
		}
	}

	// Step 5: 自动同步规则元数据到 waf_rules 表（并软归档旧版本规则）
	_ = s.store.UpdateJobStep(ctx, job.ID, JobSyncingMetadata, "自动同步规则库元数据与中文详述", 90)
	var syncReportRaw json.RawMessage
	if s.metaSyncer != nil {
		rep, err := s.metaSyncer.SyncActiveRulePack(ctx, s.storage.ReleaseCRSDir(targetPack.RulePackVersion), targetPack.CRSVersion, targetPack.RulePackVersion)
		if err != nil {
			slog.Warn("auto sync waf_rules metadata after rulepack activation failed", "version", targetPack.RulePackVersion, "error", err)
			// 网关已实际生效新规则，元数据同步失败不得伪装已回滚；写入诊断供人工点「同步CRS规则」兜底
			failJob("METADATA_SYNC_FAILED", "网关已切换至新规则包，但规则库元数据同步失败（可点击「同步CRS规则」补同步）: "+err.Error())
			return
		}
		if rep != nil {
			syncReportRaw, _ = json.Marshal(rep)
		}
	}

	// Step 6: 清理超限旧快照（严格保护当前/上一版/内置基线/最近配置版本引用的快照）
	s.runSnapshotGC(ctx, targetPack.RulePackVersion, prevPack)

	finalStep := "离线规则包已生效并完成规则库同步"
	if job.JobType == JobTypeRollback {
		finalStep = "已回滚至目标规则包并完成规则库同步"
	}
	_ = s.store.FinishJob(ctx, job.ID, JobSuccess, finalStep, "", "", syncReportRaw)
}

// RetryNodeSync 为指定 HA 备节点补发当前激活规则包并重同步网关配置。
func (s *Service) RetryNodeSync(ctx context.Context, nodeID uuid.UUID) error {
	if s.clusterSyncer == nil {
		return ErrClusterUnsupported
	}
	activePack, err := s.store.GetAppliedPack(ctx)
	if err != nil {
		return err
	}
	if !activePack.IsBuiltin {
		if activePack.ArchivePath == "" {
			return fmt.Errorf("%w: 当前激活规则包 %s 缺少签名归档，无法向备节点补发", ErrInvalidArchive, activePack.RulePackVersion)
		}
		if err := s.clusterSyncer.StageRulePack(ctx, nodeID, activePack.RulePackVersion, activePack.ArchivePath, activePack.FileSHA256); err != nil {
			return fmt.Errorf("备节点补发规则包失败: %w", err)
		}
	}
	if err := s.clusterSyncer.RetryNodeConfigSync(ctx, nodeID); err != nil {
		return fmt.Errorf("备节点重同步网关配置失败: %w", err)
	}
	if !activePack.IsBuiltin {
		if err := s.clusterSyncer.ActivateRulePack(ctx, nodeID, activePack.RulePackVersion, activePack.ManifestSHA256); err != nil {
			return fmt.Errorf("备节点切换规则软链失败: %w", err)
		}
	}
	return nil
}

func (s *Service) runSnapshotGC(ctx context.Context, activeVersion string, prevPack *RulePack) {
	protected := map[string]bool{activeVersion: true}
	if prevPack != nil && prevPack.RulePackVersion != "" {
		protected[prevPack.RulePackVersion] = true
	}
	if cfgVers, err := s.store.ProtectedConfigRulePackVersions(ctx); err == nil {
		for v := range cfgVers {
			protected[v] = true
		}
	}
	pruned, err := s.storage.PruneReleases(s.cfg.Retention, protected)
	if err != nil {
		slog.Warn("prune old rulepack releases failed", "error", err)
		return
	}
	if len(pruned) > 0 && s.clusterSyncer != nil {
		if standbys, serr := s.clusterSyncer.ListStandbyNodes(ctx); serr == nil {
			for _, node := range standbys {
				for _, v := range pruned {
					_ = s.clusterSyncer.PruneRulePack(ctx, node.NodeID, v)
				}
			}
		}
	}
}

func (s *Service) collectNodeStatuses(ctx context.Context, activeVersion string) ([]NodePrecheckStatus, bool, bool) {
	nodes := []NodePrecheckStatus{{
		NodeName:       s.cfg.LocalNodeName,
		Role:           NodeRolePrimary,
		Reachable:      true,
		RulePackReady:  s.storage.Writable(),
		CurrentVersion: activeVersion,
		Aligned:        true,
	}}
	if s.clusterSyncer == nil {
		return nodes, false, false
	}
	standbys, err := s.clusterSyncer.ListStandbyNodes(ctx)
	if err != nil || len(standbys) == 0 {
		return nodes, false, false
	}
	drift := false
	for _, sb := range standbys {
		id := sb.NodeID
		item := NodePrecheckStatus{
			NodeID:   &id,
			NodeName: sb.NodeName,
			Role:     NodeRoleStandby,
		}
		st, err := s.clusterSyncer.CheckNodeRulePackStatus(ctx, sb.NodeID)
		if err != nil {
			item.Error = err.Error()
			drift = true
		} else if st != nil {
			item.Reachable = st.Reachable
			item.RulePackReady = st.RulePackReady
			item.CurrentVersion = st.ActiveSymlink
			item.Error = st.Error
			item.Aligned = st.Reachable && st.RulePackReady && (activeVersion == "" || st.ActiveSymlink == activeVersion)
			if !item.Aligned {
				drift = true
			}
		}
		nodes = append(nodes, item)
	}
	return nodes, drift, true
}

func (s *Service) verifyArtifact(archivePath string) (*VerifiedArtifact, error) {
	if len(s.verifyKey) == ed25519.PublicKeySize {
		return VerifyArchiveFileWithKey(archivePath, s.cfg.CurrentSystemVersion, s.verifyKey)
	}
	return VerifyArchiveFile(archivePath, s.cfg.CurrentSystemVersion)
}

func (s *Service) diskFree(dir string) int64 {
	if s.diskFreeFn != nil {
		return s.diskFreeFn(dir)
	}
	return DiskFreeBytes(dir)
}

func (s *Service) acquireApplyLock(ctx context.Context, owner string) (func(), error) {
	if !s.applyMu.TryLock() {
		return nil, ErrActiveJob
	}
	if s.cache == nil || s.cache.Redis() == nil {
		return func() { s.applyMu.Unlock() }, nil
	}
	token := owner + ":" + uuid.NewString()
	ok, err := s.cache.Redis().SetNX(ctx, applyLockKey, token, applyLockTTL).Result()
	if err != nil {
		s.applyMu.Unlock()
		return nil, fmt.Errorf("获取规则包分布式锁失败: %w", err)
	}
	if !ok {
		s.applyMu.Unlock()
		return nil, ErrActiveJob
	}
	return func() {
		releaseScript := redis.NewScript(`if redis.call("GET", KEYS[1]) == ARGV[1] then return redis.call("DEL", KEYS[1]) else return 0 end`)
		_, _ = releaseScript.Run(context.Background(), s.cache.Redis(), []string{applyLockKey}, token).Result()
		s.applyMu.Unlock()
	}, nil
}

func (s *Service) computePolicyWarnings(ctx context.Context, addedByTag map[string]int, removedIDs, updatedIDs map[int]bool) []PolicyImpactWarning {
	warnings := make([]PolicyImpactWarning, 0)
	if s.store == nil {
		return warnings
	}
	overrides, excs, err := s.store.QueryPolicyImpactTargets(ctx)
	if err != nil {
		slog.Warn("query policy impact targets failed during rulepack preview", "error", err)
		return warnings
	}
	for _, ov := range overrides {
		if removedIDs[ov.RuleID] {
			warnings = append(warnings, PolicyImpactWarning{
				Kind:       "OVERRIDE_RULE_REMOVED",
				ObjectID:   ov.ID.String(),
				ObjectName: fmt.Sprintf("规则覆盖 #%d (%s)", ov.RuleID, ov.Action),
				RuleID:     ov.RuleID,
				Message:    fmt.Sprintf("已启用的规则覆盖指向规则 %d，但该规则在新规则包中已移除（覆盖将不再匹配）", ov.RuleID),
			})
		} else if updatedIDs[ov.RuleID] {
			warnings = append(warnings, PolicyImpactWarning{
				Kind:       "OVERRIDE_RULE_UPDATED",
				ObjectID:   ov.ID.String(),
				ObjectName: fmt.Sprintf("规则覆盖 #%d (%s)", ov.RuleID, ov.Action),
				RuleID:     ov.RuleID,
				Message:    fmt.Sprintf("已启用的规则覆盖指向规则 %d，新规则包更新了该规则检测内容，建议复核是否仍需覆盖", ov.RuleID),
			})
		}
	}
	for _, ex := range excs {
		allIDs := map[int]bool{}
		for _, id := range ex.RuleIDs {
			allIDs[id] = true
		}
		for _, id := range ex.ResolvedRuleIDs {
			allIDs[id] = true
		}
		for id := range allIDs {
			if removedIDs[id] {
				warnings = append(warnings, PolicyImpactWarning{
					Kind:       "EXCEPTION_RULE_REMOVED",
					ObjectID:   ex.ID.String(),
					ObjectName: ex.Name,
					RuleID:     id,
					Message:    fmt.Sprintf("例外策略「%s」包含规则 %d，但该规则在新规则包中已移除", ex.Name, id),
				})
			} else if updatedIDs[id] {
				warnings = append(warnings, PolicyImpactWarning{
					Kind:       "EXCEPTION_RULE_UPDATED",
					ObjectID:   ex.ID.String(),
					ObjectName: ex.Name,
					RuleID:     id,
					Message:    fmt.Sprintf("例外策略「%s」包含规则 %d，该规则在新规则包中有更新，建议复核", ex.Name, id),
				})
			}
		}
		for _, tag := range ex.RuleTags {
			if cnt := addedByTag[tag]; cnt > 0 {
				warnings = append(warnings, PolicyImpactWarning{
					Kind:       "EXCEPTION_TAG_NEW_RULES",
					ObjectID:   ex.ID.String(),
					ObjectName: ex.Name,
					Tag:        tag,
					Message:    fmt.Sprintf("按标签冻结的例外策略「%s」关联标签 %q，新规则包在该标签下新增了 %d 条规则（系统不会自动放行新规则，如需豁免请人工重新编辑保存例外）", ex.Name, tag, cnt),
				})
			}
		}
	}
	return warnings
}

func loadAllRulesBestEffort(crsDir string) []*wafrules.Rule {
	var out []*wafrules.Rule
	for _, sd := range wafrules.BuildSyncSources(crsDir) {
		files, err := filepath.Glob(filepath.Join(sd.Dir, "*.conf"))
		if err != nil {
			continue
		}
		sort.Strings(files)
		for _, f := range files {
			base := filepath.Base(f)
			if strings.HasSuffix(base, ".example") || strings.Contains(base, "EXCLUSION") {
				continue
			}
			rules, _, err := wafrules.ParseCRSFile(f, sd.Source)
			if err != nil {
				continue
			}
			out = append(out, rules...)
		}
	}
	return out
}

func computeRuleDiff(oldRules, newRules []*wafrules.Rule) (RuleDiffSummary, map[string]int, map[int]bool, map[int]bool) {
	oldMap := make(map[int]*wafrules.Rule, len(oldRules))
	for _, r := range oldRules {
		oldMap[r.RuleID] = r
	}
	newMap := make(map[int]*wafrules.Rule, len(newRules))
	diff := RuleDiffSummary{
		TotalRules:   len(newRules),
		BySource:     make(map[string]int),
		ByAttackType: make(map[string]int),
	}
	addedByTag := make(map[string]int)
	removedIDs := make(map[int]bool)
	updatedIDs := make(map[int]bool)

	for _, r := range newRules {
		newMap[r.RuleID] = r
		diff.BySource[r.RuleSource]++
		diff.ByAttackType[r.AttackType]++
		prev, existed := oldMap[r.RuleID]
		if !existed {
			diff.AddedCount++
			if len(diff.AddedSamples) < maxDiffSample {
				diff.AddedSamples = append(diff.AddedSamples, toChangeItem(r))
			}
			for _, t := range wafrules.ParseTagsJSON(r.Tags) {
				addedByTag[t]++
			}
		} else if prev.ContentHash != r.ContentHash {
			diff.UpdatedCount++
			updatedIDs[r.RuleID] = true
			if len(diff.UpdatedSamples) < maxDiffSample {
				diff.UpdatedSamples = append(diff.UpdatedSamples, toChangeItem(r))
			}
		} else {
			diff.UnchangedCount++
		}
	}
	for id, r := range oldMap {
		if _, stillPresent := newMap[id]; !stillPresent {
			diff.RemovedCount++
			removedIDs[id] = true
			if len(diff.RemovedSamples) < maxDiffSample {
				diff.RemovedSamples = append(diff.RemovedSamples, toChangeItem(r))
			}
		}
	}
	return diff, addedByTag, removedIDs, updatedIDs
}

func toChangeItem(r *wafrules.Rule) RuleChangeItem {
	return RuleChangeItem{
		RuleID:     r.RuleID,
		RuleSource: r.RuleSource,
		FileName:   r.FileName,
		Name:       r.Name,
		AttackType: r.AttackType,
		Severity:   r.Severity,
	}
}

func readCRSVersionFromDir(rulesRoot, fallback string) string {
	raw, err := os.ReadFile(filepath.Join(rulesRoot, "crs", "VERSION.txt"))
	if err != nil {
		return fallback
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		tok := strings.TrimPrefix(fields[0], "v")
		if tok != "" && len(tok) <= 32 {
			return tok
		}
	}
	return fallback
}
