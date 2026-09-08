// service.go 离线授权服务：导入（解析→验签→字段校验→指纹校验→产品形态绑定校验→落库 ACTIVE）、
// 内存状态快照（atomic.Value，门控中间件/装配层只读）、周期复核 Run（60s：
// raw_file 重验签篡改检测翻转 INVALID、到期翻转 EXPIRED、指纹材料变化翻转 FINGERPRINT_MISMATCH、
// 指纹恢复翻回 ACTIVE、告警回调、状态翻转触发重发布钩子）。
// SetRepublishHook/SetAlertHook 由后续装配接线（网关透传发布与系统告警），本包只提供机制。
package license

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// 告警事件类型（装配层转换为系统告警；本包不依赖 systemalerts，保持解耦）。
const (
	// AlertLicenseInvalid 无有效授权（未导入/已过期/指纹不匹配/数据非法），CRITICAL。
	AlertLicenseInvalid = "LICENSE_INVALID"
	// AlertLicenseExpiringSoon 授权临期（剩余 ≤ 7 天），HIGH。
	AlertLicenseExpiringSoon = "LICENSE_EXPIRING_SOON"
)

// 告警级别提示（与 systemalerts severity 词表一致，装配层映射）。
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
)

// expiringSoonWindow 临期告警阈值：剩余有效期 ≤ 7 天。
const expiringSoonWindow = 7 * 24 * time.Hour

// DefaultSweepInterval 周期复核间隔（任务书口径 60s）。
const DefaultSweepInterval = 60 * time.Second

// AlertEvent 授权状态告警事件（SetAlertHook 注入后由 Service 抛出）。
type AlertEvent struct {
	Type     string // AlertLicenseInvalid / AlertLicenseExpiringSoon
	Severity string // SeverityCritical / SeverityHigh
	Title    string
	Message  string
}

// State 授权内存状态快照（status 接口出参与门控判定共用）。
// Valid=false 时 Reason 为中文无效原因；HostFingerprint 为本机指纹（无材料时 ”）。
type State struct {
	Valid           bool            `json:"valid"`
	Product         string          `json:"product"` // 生效产品形态 waf/wdsp/api；无有效授权时 ''
	Quotas          Quotas          `json:"quotas"`
	Features        []string        `json:"features"`
	ExpiresAt       *time.Time      `json:"expires_at"` // 到期日；nil = 永久或无授权
	LicenseID       string          `json:"license_id"`
	Customer        string          `json:"customer"`
	LicenseType     string          `json:"license_type"`
	Reason          string          `json:"reason"`           // 无效原因（中文）；有效时 ''
	IntegrityStatus string          `json:"integrity_status"` // 原始签名授权与数据库缓存复核状态
	ProtectionState ProtectionState `json:"protection_state"`
	HostFingerprint string          `json:"host_fingerprint"`
}

// ProtectionState 是对外展示的多维事实快照。各维度必须来自可验证事实，
// 不允许仅凭“商业授权有效”推导出网关已保护或机密计算已启用。
type ProtectionState struct {
	SchemaVersion           string `json:"schema_version"`
	ProtectionForm          string `json:"protection_form"`
	CommercialAuthorization string `json:"commercial_authorization"`
	ArtifactIntegrity       string `json:"artifact_integrity"`
	GatewayProtection       string `json:"gateway_protection"`
	ConfidentialComputing   string `json:"confidential_computing"`
	Recovery                string `json:"recovery"`
	Reason                  string `json:"reason,omitempty"`
}

// IntegrityStatus 描述签名原始 .lic 与数据库缓存的可验证状态。
const (
	IntegrityNotImported           = "NOT_IMPORTED"
	IntegrityVerified              = "VERIFIED"
	IntegrityOriginalMissing       = "ORIGINAL_MISSING"
	IntegrityEncryptionUnavailable = "ENCRYPTION_UNAVAILABLE"
	IntegrityDecryptionFailed      = "DECRYPTION_FAILED"
	IntegritySignatureInvalid      = "SIGNATURE_INVALID"
	IntegrityDBInconsistent        = "DB_INCONSISTENT"
	IntegrityExpired               = "EXPIRED"
	IntegrityDeviceMismatch        = "DEVICE_MISMATCH"
	IntegrityDatabaseUnavailable   = "DATABASE_UNAVAILABLE"
)

const protectionSchemaVersion = "wdsp-protection/v1"

// Encryptor 加解密接口（*encryption.Service 实现，与 apiscan 同一注入口径；
// raw_file 密文落库不落明文；nil 时授权导入被拒绝，避免形成 DB-only 事实源）。
type Encryptor interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(encoded string) (string, error)
}

// Service 离线授权服务。
type Service struct {
	repo Repository
	enc  Encryptor
	keys map[string]ed25519.PublicKey

	// fpPath 宿主机指纹文件路径（构造时按 env 解析；测试可改）
	fpPath string
	// now 时钟（测试注入）
	now func() time.Time
	// sweepInterval 复核间隔（测试可缩短）
	sweepInterval time.Duration

	mu          sync.Mutex // 串行化 Import/Refresh 的状态翻转
	state       atomic.Value
	hasBaseline bool // 首次评估为基线（见 commitStateLocked）

	hookMu        sync.RWMutex
	republishHook func(ctx context.Context)
	alertHook     func(ctx context.Context, ev AlertEvent)

	// capProvider 包装配能力集（装配层注入 cfg.Product 能力开关；nil 跳过一致性告警）
	capProvider func() (apiEnabled, webWAFEnabled bool)
	// capWarned 授权形态宽于包装配能力的 WARN 只抛一次
	capWarned bool
}

// NewService 创建授权服务（keys 由装配层经 LoadVendorKeys 加载；enc 为空时保持 fail-closed）。
func NewService(repo Repository, enc Encryptor, keys map[string]ed25519.PublicKey) *Service {
	s := &Service{
		repo:          repo,
		enc:           enc,
		keys:          keys,
		fpPath:        HostFingerprintFile(),
		now:           func() time.Time { return time.Now().UTC() },
		sweepInterval: DefaultSweepInterval,
	}
	fp, _ := ReadHostFingerprint(s.fpPath)
	s.state.Store(State{Valid: false, Reason: "未导入授权", IntegrityStatus: IntegrityNotImported,
		ProtectionState: protectionState(IntegrityNotImported, "未导入授权"), Features: []string{}, HostFingerprint: fp})
	return s
}

// State 返回当前授权内存状态快照。
func (s *Service) State() State {
	if v, ok := s.state.Load().(State); ok {
		return v
	}
	return State{Valid: false, Reason: "授权状态未初始化", IntegrityStatus: IntegrityDatabaseUnavailable,
		ProtectionState: protectionState(IntegrityDatabaseUnavailable, "授权状态未初始化"), Features: []string{}}
}

// SetRepublishHook 设置授权状态翻转后的整站重发布钩子（装配层接 publisher；nil 跳过）。
func (s *Service) SetRepublishHook(fn func(ctx context.Context)) {
	s.hookMu.Lock()
	s.republishHook = fn
	s.hookMu.Unlock()
}

// SetAlertHook 设置授权告警回调（装配层接 systemalerts；nil 跳过）。
func (s *Service) SetAlertHook(fn func(ctx context.Context, ev AlertEvent)) {
	s.hookMu.Lock()
	s.alertHook = fn
	s.hookMu.Unlock()
}

// SetCapabilityProvider 注入包装配能力集查询（装配层接 cfg.Product 的
// APIDynamicProtectionEnabled/WebWAFProtectionEnabled；nil 跳过一致性告警）。
// 仅用于"授权形态宽于本包能力"的启动 WARN，env 只能收窄不能放宽的语义不变。
func (s *Service) SetCapabilityProvider(fn func() (apiEnabled, webWAFEnabled bool)) {
	s.hookMu.Lock()
	s.capProvider = fn
	s.hookMu.Unlock()
}

// Import 导入 .lic：解析 → 验签 → 字段校验 → 到期检查 → 指纹校验 → 产品形态绑定检查 →
// 原文加密 → 落库 ACTIVE（同事务旧候选行置 SUPERSEDED）→ 刷新内存状态 → 触发重发布钩子。
// 错误类别：ErrMalformed（400）/ ErrSignature（422）/ ErrFingerprintMismatch（409）/
// ErrDuplicate（409）/ ErrProductBound（409）；错误信息不含签名与原文。
func (s *Service) Import(ctx context.Context, fileBytes []byte, importedBy *uuid.UUID) (*Payload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := ParseFile(fileBytes)
	if err != nil {
		return nil, err
	}
	m, err := Verify(f.Payload, f.Signature, s.keys)
	if err != nil {
		return nil, err
	}
	p, err := ParsePayload(m)
	if err != nil {
		return nil, err
	}
	p.Raw = f.Payload
	// 已到期授权拒绝导入（如实告知，避免导入即锁定）
	if p.Expired(s.now()) {
		return nil, fmt.Errorf("%w：授权已到期（expires_at %s）", ErrMalformed, p.ExpiresAt.Format("2006-01-02"))
	}
	// 指纹材料缺失按 '' 处理：绑定指纹的授权将判不匹配（如实报错不绕过）
	hostFP, _ := ReadHostFingerprint(s.fpPath)
	if err := p.CheckFingerprint(hostFP); err != nil {
		return nil, err
	}
	// 产品形态绑定：首次导入后产品形态永久绑定（全表最早记录为准，任何状态均计入，
	// 历史不可绕过）；不同 product 的授权一律拒绝——切换产品形态必须重新安装部署。
	bound, err := s.repo.EarliestProduct(ctx)
	if err != nil {
		return nil, fmt.Errorf("查询产品形态绑定失败: %w", err)
	}
	if bound != "" && bound != p.Product {
		return nil, fmt.Errorf("%w：当前系统已绑定产品形态 %s，本次导入为 %s；如需切换产品形态请重新安装部署",
			ErrProductBound, bound, p.Product)
	}
	// 签名原文是唯一事实源；无法加密保存就拒绝导入，绝不落一个只有 DB 字段的可信记录。
	if s.enc == nil {
		return nil, ErrEncryptionUnavailable
	}
	rawCipherText, err := s.enc.Encrypt(string(fileBytes))
	if err != nil || rawCipherText == "" {
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrEncryptionUnavailable, err)
		}
		return nil, fmt.Errorf("%w: 加密结果为空", ErrEncryptionUnavailable)
	}
	rawCipher := []byte(rawCipherText)
	rec := recordFromPayload(p, f.Signature, importedBy)
	if err := s.repo.InsertActive(ctx, rec, rawCipher); err != nil {
		return nil, err
	}
	// 导入成功即生效：刷新内存状态并触发重发布（配额/产品形态随配置下发，
	// 无论前后状态是否相同都需重发布一次）。
	s.hasBaseline = true
	s.state.Store(stateFromPayload(p, hostFP))
	s.triggerRepublish(ctx)
	return p, nil
}

// Refresh 重新评估当前生效授权（启动基线与周期复核共用）。
// 数据库错误如实返回（调用方记日志，不静默吞掉）。
func (s *Service) Refresh(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.evaluateLocked(ctx)
}

// Run 周期复核循环（60s ticker；启动时先做一次基线评估）。ctx 取消即退出。
func (s *Service) Run(ctx context.Context) {
	if err := s.Refresh(ctx); err != nil {
		slog.Error("license: 启动基线评估失败", "error", err)
	}
	t := time.NewTicker(s.sweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.Refresh(ctx); err != nil {
				slog.Error("license: 周期复核失败", "error", err)
			}
		}
	}
}

// History 导入历史分页（pageSize 边界归一化）。
func (s *Service) History(ctx context.Context, page, pageSize int) ([]Record, int64, error) {
	return s.repo.ListHistory(ctx, page, pageSize)
}

// evaluateLocked 评估最新生效候选行：篡改检测（raw_file 重验签）翻 INVALID、到期翻 EXPIRED、
// 指纹失配翻 FINGERPRINT_MISMATCH、指纹恢复翻回 ACTIVE、落库数据非法翻 INVALID；
// 随后提交内存状态。完整性事实源暂不可用时，状态会如实标记为不可验证，
// 但不会将该不确定故障等同于授权失效而发布旁路配置。
func (s *Service) evaluateLocked(ctx context.Context) error {
	// 每轮重读指纹文件：安装/换机后材料可能变化；缺失按 '' 处理
	hostFP, _ := ReadHostFingerprint(s.fpPath)
	row, err := s.repo.LatestCandidate(ctx)
	if err != nil && !errors.Is(err, ErrNoEffective) {
		// 候选记录与 raw_file 都是完整性判断的事实源。读取失败时不能沿用
		// 上一次 VERIFIED 状态，也不能把不确定性误判为授权失效而重发布旁路。
		st := invalidState("读取授权候选记录失败", IntegrityDatabaseUnavailable, hostFP)
		s.commitStateLocked(ctx, st)
		return fmt.Errorf("查询生效授权失败: %w", err)
	}
	var st State
	switch {
	case row == nil:
		st = invalidState("未导入授权", IntegrityNotImported, hostFP)
	default:
		p, integrity, terr := s.verifyStoredRecordLocked(ctx, row)
		if terr != nil {
			st = invalidState("读取授权事实源失败", IntegrityDatabaseUnavailable, hostFP)
			s.commitStateLocked(ctx, st)
			return terr
		}
		switch {
		case integrity != IntegrityVerified:
			if integrity == IntegrityDBInconsistent || integrity == IntegritySignatureInvalid {
				if _, ferr := s.repo.SetStatus(ctx, row.ID, StatusInvalid, StatusActive, StatusFingerprintMismatch); ferr != nil {
					return fmt.Errorf("翻转授权状态失败: %w", ferr)
				}
			}
			st = invalidState(integrityReason(integrity), integrity, hostFP)
		case p.Expired(s.now()):
			if _, ferr := s.repo.SetStatus(ctx, row.ID, StatusExpired, StatusActive, StatusFingerprintMismatch); ferr != nil {
				return fmt.Errorf("翻转授权状态失败: %w", ferr)
			}
			st = invalidState("授权已到期", IntegrityExpired, hostFP)
		case p.CheckFingerprint(hostFP) != nil:
			if _, ferr := s.repo.SetStatus(ctx, row.ID, StatusFingerprintMismatch, StatusActive); ferr != nil {
				return fmt.Errorf("翻转授权状态失败: %w", ferr)
			}
			reason := "机器指纹不匹配"
			if hostFP == "" {
				reason = "宿主机指纹材料缺失"
			}
			st = invalidState(reason, IntegrityDeviceMismatch, hostFP)
		default:
			// 校验通过：指纹失配行材料恢复后翻回 ACTIVE（恢复防护）
			if row.Status == StatusFingerprintMismatch {
				if _, ferr := s.repo.SetStatus(ctx, row.ID, StatusActive, StatusFingerprintMismatch); ferr != nil {
					return fmt.Errorf("恢复授权状态失败: %w", ferr)
				}
			}
			st = stateFromPayload(p, hostFP)
		}
	}
	s.commitStateLocked(ctx, st)
	return nil
}

func integrityReason(status string) string {
	switch status {
	case IntegrityOriginalMissing:
		return "授权原文缺失，无法验证完整性"
	case IntegrityEncryptionUnavailable:
		return "授权原文加密服务不可用，无法验证完整性"
	case IntegrityDecryptionFailed:
		return "授权原文解密失败，无法验证完整性"
	case IntegritySignatureInvalid:
		return "授权原文签名校验失败"
	case IntegrityDBInconsistent:
		return "数据库授权缓存与签名原文不一致"
	default:
		return "授权完整性无法验证"
	}
}

// protectionState 将可验证的授权/原文结果映射到管理面契约。
// gateway_protection 故意保持 PRESERVE_EXISTING：授权服务不拥有网关运行态证据，
// 不能把授权有效误报成“网关已保护”。当前产品线也未实现 CC 交付，因此标准离线形态为 DISABLED。
func protectionState(integrityStatus, reason string) ProtectionState {
	commercial := "UNKNOWN"
	integrity := "UNVERIFIABLE"
	recovery := "SUPPORT_REQUIRED"
	switch integrityStatus {
	case IntegrityNotImported:
		commercial = "NOT_IMPORTED"
		recovery = "IMPORT_LICENSE"
	case IntegrityVerified:
		commercial = "AUTHORIZED"
		integrity = "VERIFIED"
		recovery = "NONE"
	case IntegrityExpired:
		commercial = "EXPIRED"
		integrity = "VERIFIED"
		recovery = "IMPORT_LICENSE"
	case IntegrityDeviceMismatch:
		commercial = "DEVICE_MISMATCH"
		integrity = "VERIFIED"
		recovery = "IMPORT_LICENSE"
	case IntegritySignatureInvalid, IntegrityDBInconsistent:
		commercial = "INVALID"
		integrity = "FAILED"
		recovery = "REVALIDATE_PACKAGE"
	case IntegrityOriginalMissing, IntegrityEncryptionUnavailable, IntegrityDecryptionFailed:
		commercial = "UNKNOWN"
		integrity = "UNVERIFIABLE"
		recovery = "REVALIDATE_PACKAGE"
	case IntegrityDatabaseUnavailable:
		commercial = "UNKNOWN"
		integrity = "UNKNOWN"
		recovery = "SUPPORT_REQUIRED"
	}
	return ProtectionState{
		SchemaVersion:           protectionSchemaVersion,
		ProtectionForm:          "STANDARD_OFFLINE",
		CommercialAuthorization: commercial,
		ArtifactIntegrity:       integrity,
		GatewayProtection:       "PRESERVE_EXISTING",
		ConfidentialComputing:   "DISABLED",
		Recovery:                recovery,
		Reason:                  reason,
	}
}

// commitStateLocked 提交内存状态：首次评估为基线——如实抛出当前状态告警（供下游
// 合并冷却），但不触发重发布（启动首发由装配层按 State() 驱动，避免重复发布）；
// 之后状态翻转（Valid/LicenseID/Reason 任一变化）时无效化告警 + 触发重发布。
//
// 完整性事实源不可用不是确定的授权失效：此时只更新可观测状态，保留最近已下发
// 的网关配置，且不以 LICENSE_INVALID 告警混淆故障语义。调用方仍会收到 Refresh
// 错误并记录；需要恢复后重新复核，见 AllowsGatewayConfigPublish。
func (s *Service) commitStateLocked(ctx context.Context, st State) {
	prev := s.State()
	s.state.Store(st)
	if st.Valid {
		s.maybeWarnCapabilityLocked(st)
	}
	if !s.hasBaseline {
		s.hasBaseline = true
		if !st.Valid && !holdsGatewayConfiguration(st.IntegrityStatus) {
			s.fireAlert(ctx, AlertEvent{Type: AlertLicenseInvalid, Severity: SeverityCritical, Title: "授权无效", Message: st.Reason})
		} else {
			s.maybeAlertExpiringSoon(ctx, st)
		}
		return
	}
	changed := prev.Valid != st.Valid || prev.LicenseID != st.LicenseID || prev.Reason != st.Reason ||
		prev.IntegrityStatus != st.IntegrityStatus || prev.ProtectionState != st.ProtectionState
	if !changed {
		if st.Valid {
			s.maybeAlertExpiringSoon(ctx, st)
		}
		return
	}
	if holdsGatewayConfiguration(st.IntegrityStatus) {
		return
	}
	if !st.Valid {
		s.fireAlert(ctx, AlertEvent{Type: AlertLicenseInvalid, Severity: SeverityCritical, Title: "授权失效", Message: st.Reason})
	}
	s.triggerRepublish(ctx)
}

// AllowsGatewayConfigPublish 表示当前授权状态是否允许生成并下发新的网关配置。
// 完整性事实源暂不可用时，不能据此确认授权已经失效，也不能将正在运行的防护配置
// 自动替换为旁路配置；发布器应暂停发布，待复核恢复后再继续。
func (s *Service) AllowsGatewayConfigPublish() bool {
	return !holdsGatewayConfiguration(s.State().IntegrityStatus)
}

// holdsGatewayConfiguration 仅覆盖无法从事实源作出确定判断的完整性状态。
// 明确的验签失败、缓存不一致、到期和设备不匹配仍按既有授权策略处理。
func holdsGatewayConfiguration(integrityStatus string) bool {
	switch integrityStatus {
	case IntegrityDatabaseUnavailable, IntegrityOriginalMissing, IntegrityEncryptionUnavailable, IntegrityDecryptionFailed:
		return true
	default:
		return false
	}
}

// maybeWarnCapabilityLocked 授权产品形态宽于本包装配能力时 WARN 一次
// （如授权 wdsp 但包未启 API 能力）。只告警不改变行为：
// env 仅为交付能力上限（只能收窄不能放宽），生效形态仍由签名授权决定。
func (s *Service) maybeWarnCapabilityLocked(st State) {
	s.hookMu.RLock()
	fn := s.capProvider
	s.hookMu.RUnlock()
	if fn == nil || s.capWarned {
		return
	}
	apiEnabled, webWAFEnabled := fn()
	var needAPI, needWeb bool
	switch st.Product {
	case "waf":
		needWeb = true
	case "api":
		needAPI = true
	default: // wdsp：两个能力域都需要
		needAPI, needWeb = true, true
	}
	if (needAPI && !apiEnabled) || (needWeb && !webWAFEnabled) {
		s.capWarned = true
		slog.Warn("license: 授权产品形态宽于本包能力，部分能力不可用",
			"product", st.Product, "api_enabled", apiEnabled, "web_waf_enabled", webWAFEnabled)
	}
}

// maybeAlertExpiringSoon 有效且剩余有效期 ≤ 7 天时抛出临期告警
// （每轮复核重复抛出，下游系统告警按指纹合并冷却，不产生风暴）。
func (s *Service) maybeAlertExpiringSoon(ctx context.Context, st State) {
	if !st.Valid || st.ExpiresAt == nil {
		return
	}
	remain := endOfDayUTC(*st.ExpiresAt).Sub(s.now())
	if remain <= 0 || remain > expiringSoonWindow {
		return
	}
	s.fireAlert(ctx, AlertEvent{
		Type:     AlertLicenseExpiringSoon,
		Severity: SeverityHigh,
		Title:    "授权即将到期",
		Message:  fmt.Sprintf("授权将于 %s 到期，请及时续期", st.ExpiresAt.Format("2006-01-02")),
	})
}

// triggerRepublish 异步触发整站重发布（发布可能耗时秒级，不阻塞导入/复核主流程；
// WithoutCancel 切断请求取消传播，钩子 panic 仅记日志——发布链路自身有版本/审计记录）。
func (s *Service) triggerRepublish(ctx context.Context) {
	s.hookMu.RLock()
	fn := s.republishHook
	s.hookMu.RUnlock()
	if fn == nil {
		return
	}
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("license: 重发布钩子 panic", "panic", rec)
			}
		}()
		fn(context.WithoutCancel(ctx))
	}()
}

// fireAlert 同步抛出告警事件（Raise 为轻量合并写；钩子 panic 仅记日志，不扩散主流程）。
func (s *Service) fireAlert(ctx context.Context, ev AlertEvent) {
	s.hookMu.RLock()
	fn := s.alertHook
	s.hookMu.RUnlock()
	if fn == nil {
		return
	}
	defer func() {
		if rec := recover(); rec != nil {
			slog.Error("license: 告警钩子 panic", "panic", rec)
		}
	}()
	fn(ctx, ev)
}

// recordFromPayload 由校验通过的 payload 构造 ACTIVE 记录行。
func recordFromPayload(p *Payload, signature string, importedBy *uuid.UUID) *Record {
	quotasJSON, _ := json.Marshal(p.Quotas)
	featuresJSON, _ := json.Marshal(p.Features)
	return &Record{
		LicenseID:          p.LicenseID,
		LicenseType:        p.LicenseType,
		Product:            p.Product,
		Customer:           p.Customer,
		Status:             StatusActive,
		ImportedBy:         importedBy,
		ExpiresAt:          p.ExpiresAt,
		Perpetual:          p.Perpetual,
		MachineFingerprint: p.MachineFingerprint,
		Payload:            p.Raw,
		Signature:          signature,
		Quotas:             quotasJSON,
		Features:           featuresJSON,
	}
}

// verifyStoredRecordLocked 以签名原始 .lic 为事实源，解密、验签后逐字段核对数据库缓存。
// 任何事实源不可用都返回明确完整性状态，绝不把 DB-only 记录报告为已验证。
func (s *Service) verifyStoredRecordLocked(ctx context.Context, row *Record) (*Payload, string, error) {
	if s.enc == nil {
		return nil, IntegrityEncryptionUnavailable, nil
	}
	cipher, err := s.repo.RawFileCipher(ctx, row.ID)
	if err != nil {
		return nil, IntegrityDatabaseUnavailable, fmt.Errorf("读取授权原文失败: %w", err)
	}
	if len(cipher) == 0 {
		return nil, IntegrityOriginalMissing, nil
	}
	plain, err := s.enc.Decrypt(string(cipher))
	if err != nil {
		return nil, IntegrityDecryptionFailed, nil
	}
	f, err := ParseFile([]byte(plain))
	if err != nil {
		return nil, IntegritySignatureInvalid, nil
	}
	m, err := Verify(f.Payload, f.Signature, s.keys)
	if err != nil {
		return nil, IntegritySignatureInvalid, nil
	}
	p, err := ParsePayload(m)
	if err != nil {
		return nil, IntegritySignatureInvalid, nil
	}
	p.Raw = f.Payload
	if !recordMatchesPayload(row, p, f.Signature) {
		return nil, IntegrityDBInconsistent, nil
	}
	return p, IntegrityVerified, nil
}

func recordMatchesPayload(row *Record, p *Payload, signature string) bool {
	expected := recordFromPayload(p, signature, nil)
	if row.Signature != expected.Signature || row.LicenseID != expected.LicenseID ||
		row.LicenseType != expected.LicenseType || row.Product != expected.Product ||
		row.Customer != expected.Customer || row.Perpetual != expected.Perpetual ||
		row.MachineFingerprint != expected.MachineFingerprint ||
		!sameExpiryDate(row.ExpiresAt, expected.ExpiresAt) {
		return false
	}
	if !jsonValuesEqual(row.Quotas, expected.Quotas) || !jsonValuesEqual(row.Features, expected.Features) {
		return false
	}
	signed, _, err := canonicalPayload(p.Raw)
	if err != nil {
		return false
	}
	stored, _, err := canonicalPayload(row.Payload)
	return err == nil && string(signed) == string(stored)
}

func jsonValuesEqual(a, b json.RawMessage) bool {
	var av, bv interface{}
	if json.Unmarshal(a, &av) != nil || json.Unmarshal(b, &bv) != nil {
		return false
	}
	return reflect.DeepEqual(av, bv)
}

// sameExpiryDate 到期日按 YYYY-MM-DD 日历日比较（各自时区格式化，
// 对 DATE 列扫描时区差异免疫，避免误判）。
func sameExpiryDate(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Format("2006-01-02") == b.Format("2006-01-02")
}

// parseStoredPayload 重解析落库 payload（jsonb 规范化字节 → map → 结构化校验）。
func parseStoredPayload(raw json.RawMessage) (*Payload, error) {
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	p, err := ParsePayload(m)
	if err != nil {
		return nil, err
	}
	p.Raw = raw
	return p, nil
}

// stateFromPayload 有效授权 → 内存状态快照。
func stateFromPayload(p *Payload, hostFP string) State {
	features := p.Features
	if features == nil {
		features = []string{}
	}
	return State{
		Valid:           true,
		Product:         p.Product,
		Quotas:          p.Quotas,
		Features:        features,
		ExpiresAt:       p.ExpiresAt,
		LicenseID:       p.LicenseID,
		Customer:        p.Customer,
		LicenseType:     p.LicenseType,
		IntegrityStatus: IntegrityVerified,
		ProtectionState: protectionState(IntegrityVerified, ""),
		HostFingerprint: hostFP,
	}
}

// invalidState 无效授权内存状态快照（仅原因与本机指纹）。
func invalidState(reason, integrityStatus, hostFP string) State {
	return State{Valid: false, Reason: reason, IntegrityStatus: integrityStatus,
		ProtectionState: protectionState(integrityStatus, reason), Features: []string{}, HostFingerprint: hostFP}
}
