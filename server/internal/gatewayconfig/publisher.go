package gatewayconfig

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/applications"
	"github.com/jiuzhang-waf/server/internal/cache"
	"github.com/jiuzhang-waf/server/internal/certificates"
)

// 发布任务状态
const (
	TaskPending     = "PENDING"
	TaskValidating  = "VALIDATING"
	TaskGenerating  = "GENERATING"
	TaskPublishing  = "PUBLISHING"
	TaskVerifying   = "VERIFYING"
	TaskSuccess     = "SUCCESS"
	TaskFailed      = "FAILED"
	TaskRollingBack = "ROLLING_BACK"
	TaskRolledBack  = "ROLLED_BACK"
)

// 任务类型
const (
	TaskTypePublish  = "PUBLISH"
	TaskTypeRollback = "ROLLBACK"
)

// 发布错误
var (
	ErrLockBusy      = errors.New("another publish task is running")
	ErrInvalidState  = errors.New("invalid publish state")
	ErrNoApps        = errors.New("no applications to publish")
	ErrPublishFailed = errors.New("publish failed")
)

// PublishTask 是发布任务。
type PublishTask struct {
	ID                uuid.UUID  `json:"id"`
	TaskType          string     `json:"task_type"`
	Status            string     `json:"status"`
	RequestedBy       *uuid.UUID `json:"requested_by"`
	RequestedAt       time.Time  `json:"requested_at"`
	StartedAt         *time.Time `json:"started_at"`
	FinishedAt        *time.Time `json:"finished_at"`
	TargetVersionID   *uuid.UUID `json:"target_version_id"`
	PreviousVersionID *uuid.UUID `json:"previous_version_id"`
	CurrentStep       string     `json:"current_step"`
	Progress          int        `json:"progress"`
	ResultSummary     string     `json:"result_summary"`
	FailureCode       string     `json:"failure_code"`
	FailureMessage    string     `json:"failure_message"`
	RequestID         string     `json:"request_id"`
}

// PolicyParams 是应用策略参数。
type PolicyParams struct {
	PolicyID          string // 绑定策略 ID（可空）
	ProtectionMode    string
	ParanoiaLevel     int
	InboundThreshold  int
	OutboundThreshold int
}

// PolicyProvider 是应用策略查询接口（由 protectionpolicies.Store 实现）。
type PolicyProvider interface {
	GetApplicationPolicyParams(ctx context.Context, appID uuid.UUID) (*PolicyParams, error)
}

// ExceptionRule 是下发到网关的例外规则（SecLang 文本）。
type ExceptionRule struct {
	RuleID  int
	SecLang string
}

// ExceptionProvider 是启用例外策略查询接口（由 exceptions.Store 实现）。
type ExceptionProvider interface {
	GetEnabledExceptions(ctx context.Context) ([]ExceptionRule, error)
}

// CustomRulesProvider 是启用自定义规则 SecLang 查询接口（由 customrules.Store 实现）。
type CustomRulesProvider interface {
	ListEnabledSecLang(ctx context.Context) ([]string, error)
}

// RuleOverridesProvider 是规则覆盖查询接口（由 ruleoverrides.Store 实现）。
type RuleOverridesProvider interface {
	// SecLangForApp 返回该应用生效的 DISABLE 覆盖 SecLang（已按优先级解析）。
	SecLangForApp(ctx context.Context, appID uuid.UUID, policyID *uuid.UUID) ([]string, error)
}

// GuardProvider 是阶段5访问控制/CC 配置提供者（由 guardconfig.Provider 实现）。
type GuardProvider interface {
	BuildGuardConfig(ctx context.Context) (*GuardConfig, error)
	SaveVersionSnapshot(ctx context.Context, cfg *GuardConfig, taskID, createdBy uuid.UUID) (uuid.UUID, error)
	MarkVersionResult(ctx context.Context, id uuid.UUID, result string) error
	GetVersionConfig(ctx context.Context, versionID uuid.UUID) (*GuardConfig, error)
}

// Publisher 是配置发布控制器。
type Publisher struct {
	db         *pgxpool.Pool
	cache      *cache.Client
	apps       *applications.Store
	certs      *certificates.Store
	caddy      *CaddyClient
	dataDir    string // 配置与证书文件目录（runtime）
	policies      PolicyProvider
	exceptions    ExceptionProvider
	customRules   CustomRulesProvider
	ruleOverrides RuleOverridesProvider
	guard         GuardProvider
}

// NewPublisher 创建发布控制器。
func NewPublisher(db *pgxpool.Pool, c *cache.Client, apps *applications.Store, certs *certificates.Store, socketPath, dataDir string, policies PolicyProvider, exceptions ExceptionProvider) *Publisher {
	return &Publisher{
		db:         db,
		cache:      c,
		apps:       apps,
		certs:      certs,
		caddy:      NewCaddyClient(socketPath),
		dataDir:    dataDir,
		policies:   policies,
		exceptions: exceptions,
	}
}

// SetGuardProvider 注入阶段5访问控制配置提供者（可选，注入后发布包含 guard 配置）。
func (p *Publisher) SetGuardProvider(g GuardProvider) {
	p.guard = g
}

// SetCustomRulesProvider 注入自定义规则提供者（启用规则写入发布配置）。
func (p *Publisher) SetCustomRulesProvider(c CustomRulesProvider) {
	p.customRules = c
}

// SetRuleOverridesProvider 注入规则覆盖提供者。
func (p *Publisher) SetRuleOverridesProvider(r RuleOverridesProvider) {
	p.ruleOverrides = r
}

const publishLockKey = "jiuzhang:gateway:publish_lock"
const publishLockTTL = 120 * time.Second

// acquireLock 获取发布锁（同一时间仅一个发布任务）。
func (p *Publisher) acquireLock(ctx context.Context, owner string) (bool, error) {
	ok, err := p.cache.Redis().SetNX(ctx, publishLockKey, owner, publishLockTTL).Result()
	if err != nil {
		return false, err
	}
	return ok, nil
}

// releaseLock 释放发布锁（仅持有者可释放）。
func (p *Publisher) releaseLock(ctx context.Context, owner string) {
	val, err := p.cache.Redis().Get(ctx, publishLockKey).Result()
	if err == nil && val == owner {
		_ = p.cache.Redis().Del(ctx, publishLockKey).Err()
	}
}

// PublishInput 是发布输入。
type PublishInput struct {
	RequestedBy    uuid.UUID
	RequestID      string
	IdempotencyKey string
	// AppIDs 限定发布的应用（为空表示全部活动应用）。
	AppIDs []uuid.UUID
	// GuardOverride 阶段5访问控制配置覆盖（回滚历史版本时使用；nil 表示从数据库实时组装）。
	GuardOverride *GuardConfig
}

// Publish 执行完整发布流程。
func (p *Publisher) Publish(ctx context.Context, in PublishInput) (*PublishTask, error) {
	// 幂等检查
	if in.IdempotencyKey != "" {
		if existing, err := p.getTaskByIdempotencyKey(ctx, in.IdempotencyKey); err == nil && existing != nil {
			return existing, nil
		}
	}

	// 创建任务
	task, err := p.createTask(ctx, TaskTypePublish, in.RequestedBy, in.RequestID, in.IdempotencyKey)
	if err != nil {
		return nil, err
	}

	// 异步执行（调用方决定是否同步等待）
	go p.executePublish(context.Background(), task.ID, in)

	return task, nil
}

// PublishSync 同步执行发布（返回最终任务状态）。
func (p *Publisher) PublishSync(ctx context.Context, in PublishInput) (*PublishTask, error) {
	if in.IdempotencyKey != "" {
		if existing, err := p.getTaskByIdempotencyKey(ctx, in.IdempotencyKey); err == nil && existing != nil {
			return existing, nil
		}
	}
	task, err := p.createTask(ctx, TaskTypePublish, in.RequestedBy, in.RequestID, in.IdempotencyKey)
	if err != nil {
		return nil, err
	}
	p.executePublish(ctx, task.ID, in)
	return p.GetTask(ctx, task.ID)
}

// executePublish 执行发布流程（状态机）。
func (p *Publisher) executePublish(ctx context.Context, taskID uuid.UUID, in PublishInput) {
	lockOwner := taskID.String()
	// 获取发布锁
	ok, err := p.acquireLock(ctx, lockOwner)
	if err != nil || !ok {
		p.finishTask(ctx, taskID, TaskFailed, "LOCK_BUSY", "其他发布任务正在执行，请稍后重试", nil)
		return
	}
	defer p.releaseLock(context.Background(), lockOwner)

	// 步骤1：读取业务数据快照
	p.updateTaskStep(ctx, taskID, TaskGenerating, "读取业务数据快照", 10)
	appsData, snapshot, err := p.buildSnapshot(ctx, in.AppIDs)
	if err != nil {
		p.finishTask(ctx, taskID, TaskFailed, "SNAPSHOT_FAILED", err.Error(), nil)
		return
	}

	// 读取启用的例外策略（下发到网关；失败则中止发布，禁止静默清空例外）
	var exceptionRules []ExceptionRule
	if p.exceptions != nil {
		exceptionRules, err = p.exceptions.GetEnabledExceptions(ctx)
		if err != nil {
			p.finishTask(ctx, taskID, TaskFailed, "EXCEPTIONS_SNAPSHOT_FAILED", err.Error(), nil)
			return
		}
	}

	// 启用的自定义规则 SecLang
	var customSecLang []string
	if p.customRules != nil {
		customSecLang, err = p.customRules.ListEnabledSecLang(ctx)
		if err != nil {
			p.finishTask(ctx, taskID, TaskFailed, "CUSTOM_RULES_SNAPSHOT_FAILED", err.Error(), nil)
			return
		}
	}

	// 阶段5：组装访问控制/CC 配置（或回滚覆盖）
	var guardCfg *GuardConfig
	if p.guard != nil {
		if in.GuardOverride != nil {
			guardCfg = in.GuardOverride
		} else {
			guardCfg, err = p.guard.BuildGuardConfig(ctx)
			if err != nil {
				p.finishTask(ctx, taskID, TaskFailed, "GUARD_SNAPSHOT_FAILED", err.Error(), nil)
				return
			}
		}
	}

	// 步骤2：生成候选配置
	p.updateTaskStep(ctx, taskID, TaskGenerating, "生成候选配置", 25)
	gen, err := Generate(GenerateInput{
		Apps:         appsData,
		AdminSocket:  p.caddy.SocketPath(),
		Exceptions:   exceptionRules,
		CustomRules:  customSecLang,
		Guard:        guardCfg,
	})
	if err != nil {
		p.finishTask(ctx, taskID, TaskFailed, "GENERATE_FAILED", err.Error(), nil)
		return
	}

	// 步骤3：配置校验
	p.updateTaskStep(ctx, taskID, TaskValidating, "校验配置", 40)
	if err := p.caddy.ValidateConfig(ctx, gen.JSON); err != nil {
		p.saveFailedCandidate(gen, snapshot, err)
		p.finishTask(ctx, taskID, TaskFailed, "VALIDATE_FAILED", err.Error(), nil)
		return
	}

	// 步骤4：保存版本（不可变）
	version, err := p.saveVersion(ctx, gen, snapshot, in, taskID)
	if err != nil {
		p.finishTask(ctx, taskID, TaskFailed, "SAVE_VERSION_FAILED", err.Error(), nil)
		return
	}
	_ = p.setTaskTargetVersion(ctx, taskID, version.ID)

	// 阶段5：保存访问控制配置版本快照（PENDING，结果后续回填）
	var acVersionID uuid.UUID
	if p.guard != nil && guardCfg != nil {
		acVersionID, err = p.guard.SaveVersionSnapshot(ctx, guardCfg, taskID, in.RequestedBy)
		if err != nil {
			// 快照失败不阻断发布，但记录不静默
			p.finishTask(ctx, taskID, TaskFailed, "AC_VERSION_SAVE_FAILED", err.Error(), nil)
			return
		}
	}

	// 阶段5：回填访问控制版本结果（背景 ctx，避免请求取消丢失）
	markAC := func(result string) {
		if p.guard != nil && acVersionID != uuid.Nil {
			if err := p.guard.MarkVersionResult(context.Background(), acVersionID, result); err != nil {
				slog.Warn("mark access control version result failed", "version", acVersionID, "error", err)
			}
		}
	}

	// 步骤5：发布到 Caddy
	p.updateTaskStep(ctx, taskID, TaskPublishing, "发布到网关", 60)
	prevConfig, _ := p.caddy.GetCurrentConfig(ctx)
	if err := p.caddy.LoadConfig(ctx, gen.JSON); err != nil {
		p.markVersionResult(ctx, version.ID, "FAILED")
		markAC("FAILED")
		p.finishTask(ctx, taskID, TaskFailed, "PUBLISH_FAILED", sanitizeCaddyError(err), &version.ID)
		return
	}

	// 步骤6：发布验证
	p.updateTaskStep(ctx, taskID, TaskVerifying, "发布验证", 80)
	verifyErr := p.verifyPublish(ctx, gen, appsData)
	if verifyErr != nil {
		// 发布验证失败：自动回滚到上一配置
		p.updateTaskStep(ctx, taskID, TaskRollingBack, "验证失败，自动回滚", 90)
		rollbackErr := p.rollbackToConfig(ctx, prevConfig)
		p.markVersionResult(ctx, version.ID, "VERIFY_FAILED")
		markAC("FAILED")
		if rollbackErr != nil {
			p.finishTask(ctx, taskID, TaskFailed, "ROLLBACK_FAILED",
				fmt.Sprintf("验证失败(%s)且回滚失败(%s)", verifyErr.Error(), rollbackErr.Error()), &version.ID)
			return
		}
		p.finishTask(ctx, taskID, TaskFailed, "VERIFY_FAILED_ROLLED_BACK",
			"发布后验证失败，已自动回滚: "+verifyErr.Error(), &version.ID)
		return
	}

	// 成功
	p.markVersionResult(ctx, version.ID, "SUCCESS")
	markAC("SUCCESS")
	_ = p.setCurrentVersion(ctx, version.ID)
	p.updateAppsDeployment(ctx, in.AppIDs, applications.DeployPublished, version.ID)
	p.finishTask(ctx, taskID, TaskSuccess, "", "发布成功", &version.ID)
}

// buildSnapshot 读取业务数据并组装生成输入。
func (p *Publisher) buildSnapshot(ctx context.Context, appIDs []uuid.UUID) ([]AppData, map[string]interface{}, error) {
	var appList []applications.Application
	if len(appIDs) > 0 {
		for _, id := range appIDs {
			a, err := p.apps.GetByID(ctx, id)
			if err != nil {
				return nil, nil, err
			}
			appList = append(appList, *a)
		}
	} else {
		// 全部活动应用
		list, _, err := p.apps.List(ctx, applications.ListFilter{Status: applications.StatusActive, PageSize: 1000})
		if err != nil {
			return nil, nil, err
		}
		appList = list
	}

	var appsData []AppData
	snapshot := map[string]interface{}{"apps": []map[string]interface{}{}}
	for _, app := range appList {
		if app.Status != applications.StatusActive {
			continue
		}
		domains, err := p.apps.ListDomains(ctx, app.ID)
		if err != nil {
			return nil, nil, err
		}
		upstreams, err := p.apps.ListUpstreams(ctx, app.ID)
		if err != nil {
			return nil, nil, err
		}
		ad := AppData{
			AppID:          app.ID.String(),
			Code:           app.Code,
			ProtectionMode: app.ProtectionMode,
			Domains:        domains,
			Upstreams:      upstreams,
		}
		// 阶段4：读取应用绑定的策略参数（策略模式优先于应用字段）
		var boundPolicyID *uuid.UUID
		if p.policies != nil {
			pp, err := p.policies.GetApplicationPolicyParams(ctx, app.ID)
			if err != nil {
				slog.Warn("get application policy params failed", "app", app.Code, "error", err)
			}
			if err == nil && pp != nil {
				if pp.ProtectionMode != "" {
					ad.ProtectionMode = pp.ProtectionMode
				}
				ad.ParanoiaLevel = pp.ParanoiaLevel
				ad.InboundThreshold = pp.InboundThreshold
				ad.OutboundThreshold = pp.OutboundThreshold
				if pp.PolicyID != "" {
					if pid, err := uuid.Parse(pp.PolicyID); err == nil {
						boundPolicyID = &pid
					}
				}
			}
		}
		// 规则覆盖（应用级 > 策略级 > 全局）
		if p.ruleOverrides != nil {
			lines, err := p.ruleOverrides.SecLangForApp(ctx, app.ID, boundPolicyID)
			if err != nil {
				return nil, nil, fmt.Errorf("应用 %s 规则覆盖快照失败: %w", app.Code, err)
			}
			ad.RuleOverrideSecLang = lines
		}
		// 证书（HTTPS 应用）
		hasHTTPS := false
		for _, d := range domains {
			if d.HTTPSEnabled {
				hasHTTPS = true
				break
			}
		}
		if hasHTTPS {
			cert, err := p.certs.GetApplicationCertificate(ctx, app.ID)
			if err != nil {
				return nil, nil, fmt.Errorf("应用 %s 查询证书失败: %w", app.Code, err)
			}
			if cert == nil {
				return nil, nil, fmt.Errorf("应用 %s 启用 HTTPS 但未绑定证书", app.Code)
			}
			// 写入证书文件到数据目录（发布时解密）
			certFile, err := p.writeCertFiles(ctx, cert)
			if err != nil {
				return nil, nil, fmt.Errorf("应用 %s 证书文件准备失败: %w", app.Code, err)
			}
			ad.HasCert = true
			ad.CertID = cert.ID.String()
			ad.CertFileName = certFile
		}
		appsData = append(appsData, ad)
		snapshot["apps"] = append(snapshot["apps"].([]map[string]interface{}), map[string]interface{}{
			"code": app.Code, "mode": app.ProtectionMode,
			"domains": len(domains), "upstreams": len(upstreams),
		})
	}
	return appsData, snapshot, nil
}

// writeCertFiles 将证书与私钥写入数据目录（权限0600）。
func (p *Publisher) writeCertFiles(ctx context.Context, cert *certificates.Certificate) (string, error) {
	certPEM, chainPEM, err := p.certs.GetCertPEM(ctx, cert.ID)
	if err != nil {
		return "", err
	}
	keyPEM, err := p.certs.GetDecryptedKey(ctx, cert.ID)
	if err != nil {
		return "", err
	}
	_ = chainPEM // 链可并入 cert 文件
	return WriteCertificateFiles(p.dataDir, cert.ID.String(), certPEM, keyPEM)
}

// verifyPublish 发布后验证（Caddy 可用 + 配置已加载）。
func (p *Publisher) verifyPublish(ctx context.Context, gen *Generated, appsData []AppData) error {
	// 1. Caddy Admin 可用
	if err := p.caddy.Ping(ctx); err != nil {
		return fmt.Errorf("发布后网关管理接口不可用: %w", err)
	}
	// 2. 当前配置非空且包含预期 server
	current, err := p.caddy.GetCurrentConfig(ctx)
	if err != nil {
		return fmt.Errorf("读取当前配置失败: %w", err)
	}
	if gen.ServerCount > 0 && !strings.Contains(current, "servers") {
		return fmt.Errorf("发布后配置未包含预期的 server 定义")
	}
	return nil
}

// rollbackToConfig 回滚到指定配置。
func (p *Publisher) rollbackToConfig(ctx context.Context, configJSON string) error {
	if configJSON == "" {
		return fmt.Errorf("无可用历史配置")
	}
	return p.caddy.LoadConfig(ctx, configJSON)
}

// RollbackInput 是回滚输入。
type RollbackInput struct {
	VersionID   uuid.UUID
	RequestedBy uuid.UUID
	RequestID   string
}

// Rollback 回滚到历史版本。
func (p *Publisher) Rollback(ctx context.Context, in RollbackInput) (*PublishTask, error) {
	task, err := p.createTask(ctx, TaskTypeRollback, in.RequestedBy, in.RequestID, "")
	if err != nil {
		return nil, err
	}
	lockOwner := task.ID.String()
	ok, err := p.acquireLock(ctx, lockOwner)
	if err != nil || !ok {
		p.finishTask(ctx, task.ID, TaskFailed, "LOCK_BUSY", "其他发布任务正在执行", nil)
		return p.GetTask(ctx, task.ID)
	}
	defer p.releaseLock(context.Background(), lockOwner)

	// 读取目标版本
	version, err := p.getVersion(ctx, in.VersionID)
	if err != nil {
		p.finishTask(ctx, task.ID, TaskFailed, "VERSION_NOT_FOUND", "目标版本不存在", nil)
		return p.GetTask(ctx, task.ID)
	}
	if version.PublishResult != "SUCCESS" {
		p.finishTask(ctx, task.ID, TaskFailed, "VERSION_NOT_PUBLISHED", "目标版本未成功发布，不能回滚", nil)
		return p.GetTask(ctx, task.ID)
	}

	p.updateTaskStep(ctx, task.ID, TaskPublishing, "回滚发布", 50)
	prevConfig, _ := p.caddy.GetCurrentConfig(ctx)
	if err := p.caddy.LoadConfig(ctx, version.ConfigurationJSON); err != nil {
		p.finishTask(ctx, task.ID, TaskFailed, "ROLLBACK_PUBLISH_FAILED", sanitizeCaddyError(err), nil)
		return p.GetTask(ctx, task.ID)
	}

	// 验证
	if err := p.verifyPublish(ctx, &Generated{JSON: version.ConfigurationJSON, ServerCount: 1}, nil); err != nil {
		_ = p.rollbackToConfig(ctx, prevConfig)
		p.finishTask(ctx, task.ID, TaskFailed, "ROLLBACK_VERIFY_FAILED", "回滚后验证失败，已恢复", nil)
		return p.GetTask(ctx, task.ID)
	}

	_ = p.setCurrentVersion(ctx, in.VersionID)
	p.finishTask(ctx, task.ID, TaskSuccess, "", "回滚成功", &in.VersionID)
	return p.GetTask(ctx, task.ID)
}

// RollbackAccessControl 回滚访问控制配置到历史版本（以快照覆盖重新走完整发布流程）。
func (p *Publisher) RollbackAccessControl(ctx context.Context, versionID uuid.UUID, requestedBy uuid.UUID, requestID string) (*PublishTask, error) {
	if p.guard == nil {
		return nil, fmt.Errorf("guard provider not configured")
	}
	override, err := p.guard.GetVersionConfig(ctx, versionID)
	if err != nil {
		return nil, fmt.Errorf("读取访问控制版本快照失败: %w", err)
	}
	return p.PublishSync(ctx, PublishInput{
		RequestedBy:   requestedBy,
		RequestID:     requestID,
		GuardOverride: override,
	})
}

// sanitizeCaddyError 清理 Caddy 错误信息（不泄露内部细节）。
func sanitizeCaddyError(err error) string {
	msg := err.Error()
	if len(msg) > 500 {
		msg = msg[:500] + "...(truncated)"
	}
	return msg
}

// saveFailedCandidate 保存失败候选配置（供排查）。
func (p *Publisher) saveFailedCandidate(gen *Generated, snapshot map[string]interface{}, cause error) {
	_ = WriteFailedCandidate(p.dataDir, gen.JSON, cause.Error())
}
