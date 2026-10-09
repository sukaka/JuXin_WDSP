// service.go 无副作用模拟管理面服务（NG-COV-03；NG-BASE-02 §4.4 / RD_PLAN §5.3）。
//
// 输入纪律（契约，不得偏离）：
//   - 输入为脱敏 Finding 批次：matches 仅 detector/rule_id/category/severity/
//     score_delta 等结构化字段，服务端拒绝携带 evidence 原文、超长批次与超长字段
//     （批次 ≤100、matches/批 ≤200、单字段 ≤256 字符）；不解析原始请求体/凭据；
//   - 报告与策略/语料/输入摘要绑定；STALE 在读出时求值——落库存创建时摘要，
//     读取时用当前策略摘要（发布链当前生效版本 configuration_hash）与库存输入
//     重算的语料摘要比较，不一致即响应 STALE，不回写数据库（读出求值恒最新，
//     免写路径）；
//   - 当前策略摘要来源：gateway_config_versions 当前生效行（is_current=TRUE）的
//     configuration_hash（发布链实发配置哈希，唯一事实源；无生效版本——从未发布
//     ——时以 "unpublished:<mode>" 占位，不编造）；API 防护模式由装配层注入
//     （cfg.Product.EffectiveAPIProtectionMode 同口径）；
//   - would_block 为模拟判定语义（非已执行）；模拟不是 PROTECT 实测，报告不能
//     单独满足上线条件（NG-T-C08 联动：策略/语料变更使旧报告 STALE）。
package validations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
)

// 输入上限（契约 §4.4；与服务端校验单测锚定）。
const (
	maxBatches         = 100
	maxMatchesPerBatch = 200
	maxFieldLen        = 256
	maxExceptionsPerB  = 50
)

// PolicyProvider 当前策略来源接口（发布链适配注入；测试用 fake）。
type PolicyProvider interface {
	CurrentPolicy(ctx context.Context) (mode decision.Mode, digest string, err error)
}

// PublishPolicySource 发布链策略来源（gateway_config_versions 当前生效行）。
type PublishPolicySource struct {
	db   *pgxpool.Pool
	mode func() decision.Mode
}

// NewPublishPolicySource 创建发布链策略来源（modeFn 装配注入当前 API 防护模式）。
func NewPublishPolicySource(db *pgxpool.Pool, modeFn func() decision.Mode) *PublishPolicySource {
	return &PublishPolicySource{db: db, mode: modeFn}
}

// CurrentPolicy 当前生效策略（模式 + 配置摘要）。
func (s *PublishPolicySource) CurrentPolicy(ctx context.Context) (decision.Mode, string, error) {
	mode := decision.ModeOff
	if s.mode != nil {
		mode = s.mode()
	}
	var digest string
	err := s.db.QueryRow(ctx,
		`SELECT configuration_hash FROM gateway_config_versions WHERE is_current = TRUE LIMIT 1`).Scan(&digest)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// 从未发布：无生效策略可绑定——占位摘要如实标记（任何首次发布后旧报告即 STALE）
			return mode, "unpublished:" + string(mode), nil
		}
		return mode, "", fmt.Errorf("query current config version: %w", err)
	}
	return mode, digest, nil
}

// StoredReport 落库行（report_json 存完整报告 + 脱敏输入批次，支撑读出复核）。
type StoredReport struct {
	ID           uuid.UUID
	PolicyDigest string
	CorpusDigest string
	InputsDigest string
	Status       string
	ReportJSON   []byte
	CreatedBy    uuid.UUID // uuid.Nil = 无主体（系统/匿名不允许创建，仅防御性默认）
	CreatedAt    time.Time
}

// Store 报告存储接口（PGStore 实现；测试注入内存 fake）。
type Store interface {
	InsertReport(ctx context.Context, rec StoredReport) error
	GetReport(ctx context.Context, id uuid.UUID) (StoredReport, error)
	ListReports(ctx context.Context, page, pageSize int) ([]StoredReport, int64, error)
}

// ErrReportNotFound 报告不存在。
var ErrReportNotFound = errors.New("validation report not found")

// PGStore 报告 PostgreSQL 存储（迁移 000170）。
type PGStore struct {
	db *pgxpool.Pool
}

// NewStore 创建 PG 存储。
func NewStore(db *pgxpool.Pool) *PGStore { return &PGStore{db: db} }

// InsertReport 报告落库（status 恒存创建时 COMPLETED；STALE 读出时求值）。
func (s *PGStore) InsertReport(ctx context.Context, rec StoredReport) error {
	var createdBy *uuid.UUID
	if rec.CreatedBy != uuid.Nil {
		createdBy = &rec.CreatedBy
	}
	_, err := s.db.Exec(ctx, `
INSERT INTO validation_reports (id, policy_digest, corpus_digest, inputs_digest, status, report_json, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		rec.ID, rec.PolicyDigest, rec.CorpusDigest, rec.InputsDigest, rec.Status, rec.ReportJSON, createdBy)
	if err != nil {
		return fmt.Errorf("insert validation_report: %w", err)
	}
	return nil
}

const reportColumns = `id, policy_digest, corpus_digest, inputs_digest, status, report_json, COALESCE(created_by::text,''), created_at`

func scanReport(row pgx.Row) (StoredReport, error) {
	var rec StoredReport
	var createdBy string
	err := row.Scan(&rec.ID, &rec.PolicyDigest, &rec.CorpusDigest, &rec.InputsDigest,
		&rec.Status, &rec.ReportJSON, &createdBy, &rec.CreatedAt)
	if err != nil {
		return StoredReport{}, err
	}
	if createdBy != "" {
		if id, perr := uuid.Parse(createdBy); perr == nil {
			rec.CreatedBy = id
		}
	}
	return rec, nil
}

// GetReport 按 ID 读单份。
func (s *PGStore) GetReport(ctx context.Context, id uuid.UUID) (StoredReport, error) {
	rec, err := scanReport(s.db.QueryRow(ctx,
		`SELECT `+reportColumns+` FROM validation_reports WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return StoredReport{}, ErrReportNotFound
		}
		return StoredReport{}, fmt.Errorf("get validation_report: %w", err)
	}
	return rec, nil
}

// ListReports 按创建时间倒序分页。
func (s *PGStore) ListReports(ctx context.Context, page, pageSize int) ([]StoredReport, int64, error) {
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM validation_reports`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count validation_reports: %w", err)
	}
	offset := (page - 1) * pageSize
	rows, err := s.db.Query(ctx,
		`SELECT `+reportColumns+` FROM validation_reports ORDER BY created_at DESC, id LIMIT $1 OFFSET $2`,
		pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list validation_reports: %w", err)
	}
	defer rows.Close()
	out := []StoredReport{}
	for rows.Next() {
		rec, err := scanReport(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan validation_report: %w", err)
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate validation_reports: %w", err)
	}
	return out, total, nil
}

// Service 模拟管理面服务。
type Service struct {
	store  Store
	policy PolicyProvider
	sim    *Simulator
}

// NewService 创建服务。
func NewService(store Store, policy PolicyProvider) *Service {
	return &Service{store: store, policy: policy, sim: NewSimulator()}
}

// InputError 输入校验错误（handler 映射 400；与内部错误 500 显式分流）。
type InputError struct{ msg string }

func (e InputError) Error() string { return e.msg }

// inputErr 构造输入校验错误。
func inputErr(format string, args ...interface{}) InputError {
	return InputError{msg: fmt.Sprintf(format, args...)}
}

// storedPayload report_json 内容（报告 + 脱敏输入批次；读出时重算语料摘要用）。
type storedPayload struct {
	Report  Report         `json:"report"`
	Batches []FindingBatch `json:"batches"`
}

// Create 创建模拟报告：输入校验 → 决策层重放（Simulator 零依赖，无副作用）→ 落库。
// 返回的报告 ID 即落库 uuid（覆盖 Simulator 占位 ID，API 路径/响应/库三者同键）。
func (s *Service) Create(ctx context.Context, actorID uuid.UUID, batches []FindingBatch) (Report, error) {
	if err := validateBatches(batches); err != nil {
		return Report{}, err
	}
	mode, digest, err := s.policy.CurrentPolicy(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("current policy: %w", err)
	}
	rep := s.sim.Simulate(PolicyRef{Mode: mode, Digest: digest}, batches)
	rep.ID = uuid.NewString()
	id, _ := uuid.Parse(rep.ID)
	payload, err := json.Marshal(storedPayload{Report: rep, Batches: batches})
	if err != nil {
		return Report{}, fmt.Errorf("marshal report: %w", err)
	}
	rec := StoredReport{
		ID:           id,
		PolicyDigest: rep.PolicyDigest,
		CorpusDigest: rep.CorpusDigest,
		InputsDigest: rep.InputsDigest,
		Status:       rep.Status, // 恒 COMPLETED（创建时）
		ReportJSON:   payload,
		CreatedBy:    actorID,
		CreatedAt:    rep.CreatedAt,
	}
	if err := s.store.InsertReport(ctx, rec); err != nil {
		return Report{}, err
	}
	return rep, nil
}

// Get 读单份报告（读出时 STALE 求值，不回写数据库）。
func (s *Service) Get(ctx context.Context, id uuid.UUID) (Report, error) {
	rec, err := s.store.GetReport(ctx, id)
	if err != nil {
		return Report{}, err
	}
	return s.evaluateStale(ctx, rec)
}

// List 分页列表（每份读出时 STALE 求值；策略摘要一次取用，避免逐行查询）。
func (s *Service) List(ctx context.Context, page, pageSize int) ([]Report, int64, error) {
	recs, total, err := s.store.ListReports(ctx, page, pageSize)
	if err != nil {
		return nil, 0, err
	}
	_, policyDigest, err := s.policy.CurrentPolicy(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("current policy: %w", err)
	}
	out := make([]Report, 0, len(recs))
	for _, rec := range recs {
		rep, err := evaluateStaleWith(rec, policyDigest)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, rep)
	}
	return out, total, nil
}

// evaluateStale 读出时求值：当前策略摘要（发布链实时取）与库存输入重算的语料
// 摘要，对报告绑定摘要比较——不一致即 STALE（只改响应，不回写数据库）。
func (s *Service) evaluateStale(ctx context.Context, rec StoredReport) (Report, error) {
	_, policyDigest, err := s.policy.CurrentPolicy(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("current policy: %w", err)
	}
	return evaluateStaleWith(rec, policyDigest)
}

// evaluateStaleWith 按给定策略摘要求值（语料摘要从库存输入重算——输入不可变，
// 重算恒等于库存值，除非摘要算法变更；算法变更视同语料变更如实 STALE）。
func evaluateStaleWith(rec StoredReport, policyDigest string) (Report, error) {
	var payload storedPayload
	if err := json.Unmarshal(rec.ReportJSON, &payload); err != nil {
		return Report{}, fmt.Errorf("unmarshal stored report %s: %w", rec.ID, err)
	}
	rep := payload.Report
	rep.ID = rec.ID.String()
	MarkStale(&rep, policyDigest, digestBatches(payload.Batches))
	return rep, nil
}

// validateBatches 输入校验（契约上限与白名单；违反即拒绝——不解析不截断）。
// 返回 InputError（handler 映射 400）。
func validateBatches(batches []FindingBatch) error {
	if len(batches) == 0 {
		return inputErr("batches 不能为空")
	}
	if len(batches) > maxBatches {
		return inputErr("batches 超过上限 %d（实际 %d）", maxBatches, len(batches))
	}
	for i, b := range batches {
		if b.InputID == "" {
			return inputErr("batches[%d].input_id 必填", i)
		}
		if len(b.InputID) > maxFieldLen {
			return inputErr("batches[%d].input_id 超过 %d 字符", i, maxFieldLen)
		}
		if len(b.MissingReason) > maxFieldLen {
			return inputErr("batches[%d].missing_reason 超过 %d 字符", i, maxFieldLen)
		}
		if len(b.Matches) > maxMatchesPerBatch {
			return inputErr("batches[%d].matches 超过上限 %d（实际 %d）", i, maxMatchesPerBatch, len(b.Matches))
		}
		if len(b.Exceptions) > maxExceptionsPerB {
			return inputErr("batches[%d].exceptions 超过上限 %d", i, maxExceptionsPerB)
		}
		for j, m := range b.Matches {
			if m.Detector == "" {
				return inputErr("batches[%d].matches[%d].detector 必填", i, j)
			}
			if len(m.Evidence) > 0 {
				return inputErr("batches[%d].matches[%d] 禁止携带 evidence 原文（脱敏输入纪律）", i, j)
			}
			for name, v := range map[string]string{
				"detector": m.Detector, "rule_id": m.RuleID, "category": m.Category,
				"severity": m.Severity, "message": m.Message,
				"model_version": m.ModelVersion, "policy_version": m.PolicyVersion,
			} {
				if len(v) > maxFieldLen {
					return inputErr("batches[%d].matches[%d].%s 超过 %d 字符", i, j, name, maxFieldLen)
				}
			}
		}
		for j, e := range b.Exceptions {
			if len(e.ExceptionID) > maxFieldLen || len(e.DetectorID) > maxFieldLen ||
				len(e.RuleID) > maxFieldLen || len(e.ModelVersion) > maxFieldLen {
				return inputErr("batches[%d].exceptions[%d] 字段超过 %d 字符", i, j, maxFieldLen)
			}
		}
	}
	return nil
}
