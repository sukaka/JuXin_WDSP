package guardjanitor

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/server/internal/audits"
)

// fakeAIRow 内存行：protected 模拟 SQL 层的引用保护
// （被 AI 审计引用的会话/任务/草稿、已采纳或待审核的草稿）。
type fakeAIRow struct {
	ts        time.Time
	protected bool
}

// fakeAIStore 是 AIRetentionStore 的内存实现，复刻 SQL 实现的删除语义：
// 仅删除早于 cutoff 且未被引用保护的行，每批最多 limit 行。
type fakeAIStore struct {
	sessions  []fakeAIRow
	toolCalls []fakeAIRow
	drafts    []fakeAIRow
	usage     []fakeAIRow

	errs        map[string]error // 表名 → 注入错误
	batchLimits []int            // 记录每批 limit（分批行为断言用）
}

func (f *fakeAIStore) deleteExpired(table string, rows *[]fakeAIRow, cutoff time.Time, limit int) (int64, error) {
	if err := f.errs[table]; err != nil {
		return 0, err
	}
	f.batchLimits = append(f.batchLimits, limit)
	var deleted int64
	kept := (*rows)[:0]
	for _, r := range *rows {
		if !r.protected && r.ts.Before(cutoff) && deleted < int64(limit) {
			deleted++
			continue
		}
		kept = append(kept, r)
	}
	*rows = kept
	return deleted, nil
}

func (f *fakeAIStore) DeleteSessionsBatch(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	return f.deleteExpired("ai_sessions", &f.sessions, cutoff, limit)
}

func (f *fakeAIStore) DeleteToolCallsBatch(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	return f.deleteExpired("ai_tool_calls", &f.toolCalls, cutoff, limit)
}

func (f *fakeAIStore) DeleteDraftsBatch(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	return f.deleteExpired("ai_recommendations", &f.drafts, cutoff, limit)
}

func (f *fakeAIStore) DeleteUsageBatch(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	return f.deleteExpired("ai_usage_records", &f.usage, cutoff, limit)
}

// fakeAISettings 内存设置（group:key → 值）。
type fakeAISettings map[string]int

func (s fakeAISettings) GetInt(_ context.Context, group, key string, def int) int {
	if v, ok := s[group+":"+key]; ok {
		return v
	}
	return def
}

// fakeAIAudit 记录系统审计输入。
type fakeAIAudit struct {
	records []audits.RecordInput
}

func (a *fakeAIAudit) Record(_ context.Context, in audits.RecordInput) error {
	a.records = append(a.records, in)
	return nil
}

// fakeAIChain 哈希链校验桩。
type fakeAIChain struct {
	mismatches int
	err        error
}

func (c *fakeAIChain) VerifyChain(_ context.Context, _ int) (int, error) {
	return c.mismatches, c.err
}

// newTestCleaner 测试用清理器：小批次、无批间暂停。
func newTestCleaner(store AIRetentionStore, settings aiIntGetter, audit aiAuditRecorder, chain aiChainVerifier) *AIRetentionCleaner {
	return &AIRetentionCleaner{
		store:      store,
		settings:   settings,
		audit:      audit,
		chain:      chain,
		batchSize:  3,
		maxBatches: 5,
		batchSleep: 0,
	}
}

// TestAIRetentionConfigNormalized 边界：0/负数一律回落默认值，正数保留。
func TestAIRetentionConfigNormalized(t *testing.T) {
	cfg := AIRetentionConfig{SessionDays: 0, ToolCallDays: -5, DraftDays: 30, UsageDays: 0, AuditDays: 0}.normalized()
	if cfg.SessionDays != DefaultAISessionRetentionDays {
		t.Errorf("SessionDays = %d, want %d", cfg.SessionDays, DefaultAISessionRetentionDays)
	}
	if cfg.ToolCallDays != DefaultAIToolCallRetentionDays {
		t.Errorf("ToolCallDays = %d, want %d", cfg.ToolCallDays, DefaultAIToolCallRetentionDays)
	}
	if cfg.DraftDays != 30 {
		t.Errorf("DraftDays = %d, want 30", cfg.DraftDays)
	}
	if cfg.UsageDays != DefaultAIUsageRetentionDays || cfg.AuditDays != DefaultAIAuditRetentionDays {
		t.Errorf("Usage/Audit 默认值回落错误: %+v", cfg)
	}
}

// TestAIRetentionResolveConfig 配置读取：无设置走默认值；设置覆盖生效；非法设置回落默认。
func TestAIRetentionResolveConfig(t *testing.T) {
	// 无 settings：全部默认
	c := newTestCleaner(&fakeAIStore{}, nil, nil, nil)
	cfg := c.ResolveConfig(context.Background())
	want := AIRetentionConfig{
		SessionDays:  DefaultAISessionRetentionDays,
		ToolCallDays: DefaultAIToolCallRetentionDays,
		DraftDays:    DefaultAIDraftRetentionDays,
		UsageDays:    DefaultAIUsageRetentionDays,
		AuditDays:    DefaultAIAuditRetentionDays,
	}
	if cfg != want {
		t.Errorf("默认配置 = %+v, want %+v", cfg, want)
	}

	// 覆盖 + 非法值回落
	c2 := newTestCleaner(&fakeAIStore{}, fakeAISettings{
		"ai:retention_session_days": 7,
		"ai:retention_draft_days":   -1,
	}, nil, nil)
	cfg2 := c2.ResolveConfig(context.Background())
	if cfg2.SessionDays != 7 {
		t.Errorf("SessionDays = %d, want 7（设置覆盖）", cfg2.SessionDays)
	}
	if cfg2.DraftDays != DefaultAIDraftRetentionDays {
		t.Errorf("DraftDays = %d, want %d（非法值回落默认）", cfg2.DraftDays, DefaultAIDraftRetentionDays)
	}
}

// TestAIRetentionSweepBatching 分批：存量大于单批上限时按批循环直到删完。
func TestAIRetentionSweepBatching(t *testing.T) {
	old := time.Now().UTC().Add(-400 * 24 * time.Hour)
	store := &fakeAIStore{}
	for i := 0; i < 8; i++ { // batchSize=3 → 3 批（3+3+2）
		store.usage = append(store.usage, fakeAIRow{ts: old})
	}
	audit := &fakeAIAudit{}
	c := newTestCleaner(store, nil, audit, nil)
	result, err := c.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("SweepOnce err = %v", err)
	}
	if result.UsageDeleted != 8 {
		t.Errorf("UsageDeleted = %d, want 8", result.UsageDeleted)
	}
	if len(store.usage) != 0 {
		t.Errorf("剩余 usage = %d, want 0", len(store.usage))
	}
	// 每批 limit 均为 batchSize
	for _, l := range store.batchLimits {
		if l != 3 {
			t.Errorf("批 limit = %d, want 3", l)
		}
	}
	// 有删除 → 写系统审计成功
	if len(audit.records) != 1 || audit.records[0].Result != audits.ResultSuccess {
		t.Fatalf("审计记录 = %+v, want 1 条 SUCCESS", audit.records)
	}
}

// TestAIRetentionSweepBatchCap 限量：单次 sweep 达 maxBatches 上限后停止，余量留待下轮。
func TestAIRetentionSweepBatchCap(t *testing.T) {
	old := time.Now().UTC().Add(-400 * 24 * time.Hour)
	store := &fakeAIStore{}
	for i := 0; i < 100; i++ { // batchSize=3, maxBatches=5 → 单次最多 15
		store.usage = append(store.usage, fakeAIRow{ts: old})
	}
	c := newTestCleaner(store, nil, nil, nil)
	result, err := c.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("SweepOnce err = %v", err)
	}
	if result.UsageDeleted != 15 {
		t.Errorf("UsageDeleted = %d, want 15（5 批 × 3 行封顶）", result.UsageDeleted)
	}
	if len(store.usage) != 85 {
		t.Errorf("剩余 usage = %d, want 85（余量留待下轮）", len(store.usage))
	}
}

// TestAIRetentionReferenceProtection 引用保护：被审计引用的会话/Tool 调用即使超期也不得删除；
// 未引用且超期的删除，未超期的一律保留。
func TestAIRetentionReferenceProtection(t *testing.T) {
	now := time.Now().UTC()
	old := now.Add(-200 * 24 * time.Hour) // 超 90 天默认会话/Tool 保留期
	fresh := now.Add(-24 * time.Hour)
	store := &fakeAIStore{
		sessions: []fakeAIRow{
			{ts: old, protected: true},  // 被审计 session_id/task_id 引用
			{ts: old, protected: false}, // 超期无引用 → 删除
			{ts: fresh},                 // 未超期 → 保留
		},
		toolCalls: []fakeAIRow{
			{ts: old, protected: true},  // 所属任务被审计引用
			{ts: old, protected: false}, // 超期无引用 → 删除
		},
		drafts: []fakeAIRow{
			{ts: old, protected: true},  // ACCEPTED/PENDING_REVIEW/被审计 draft_reference 引用
			{ts: old, protected: false}, // DRAFT/REJECTED/EXPIRED 超期无引用 → 删除
		},
	}
	c := newTestCleaner(store, nil, nil, nil)
	result, err := c.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("SweepOnce err = %v", err)
	}
	if result.SessionsDeleted != 1 || len(store.sessions) != 2 {
		t.Errorf("会话: 删除 %d 剩 %d, want 删 1 剩 2（引用与未超期保留）", result.SessionsDeleted, len(store.sessions))
	}
	if store.sessions[0].protected != true {
		t.Errorf("被引用会话被提前清理")
	}
	if result.ToolCallsDeleted != 1 || len(store.toolCalls) != 1 || !store.toolCalls[0].protected {
		t.Errorf("Tool 调用: 删除 %d 剩 %+v, want 删 1 且被引用保留", result.ToolCallsDeleted, store.toolCalls)
	}
	if result.DraftsDeleted != 1 || len(store.drafts) != 1 || !store.drafts[0].protected {
		t.Errorf("草稿: 删除 %d 剩 %+v, want 删 1 且受保护草稿保留", result.DraftsDeleted, store.drafts)
	}
}

// TestAIRetentionCutoffBoundary 边界：时间恰等于 cutoff 的记录不删（严格小于）。
func TestAIRetentionCutoffBoundary(t *testing.T) {
	store := &fakeAIStore{}
	c := newTestCleaner(store, nil, nil, nil)
	cfg := c.ResolveConfig(context.Background())
	// 恰好等于 cutoff 边界（usage 180 天）：边界内（<cutoff 才算超期）
	exact := time.Now().UTC().Add(-time.Duration(cfg.UsageDays) * 24 * time.Hour)
	store.usage = []fakeAIRow{{ts: exact.Add(time.Second)}} // 比 cutoff 晚 1 秒 → 保留
	result, err := c.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("SweepOnce err = %v", err)
	}
	if result.UsageDeleted != 0 || len(store.usage) != 1 {
		t.Errorf("边界记录被误删: 删除 %d 剩 %d", result.UsageDeleted, len(store.usage))
	}
}

// TestAIRetentionErrorNotSilent 失败不静默：单表错误如实返回且包含表名，其他表继续清理。
func TestAIRetentionErrorNotSilent(t *testing.T) {
	old := time.Now().UTC().Add(-400 * 24 * time.Hour)
	store := &fakeAIStore{
		errs:  map[string]error{"ai_sessions": errors.New("db down")},
		usage: []fakeAIRow{{ts: old}},
	}
	c := newTestCleaner(store, nil, nil, nil)
	result, err := c.SweepOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "ai_sessions") {
		t.Fatalf("err = %v, want 含 ai_sessions 的错误", err)
	}
	if result.UsageDeleted != 1 {
		t.Errorf("UsageDeleted = %d, want 1（单表失败不阻断其他表）", result.UsageDeleted)
	}
}

// TestAIRetentionNilStore 未装配存储：报错而非 panic。
func TestAIRetentionNilStore(t *testing.T) {
	c := newTestCleaner(nil, nil, nil, nil)
	if _, err := c.SweepOnce(context.Background()); err == nil {
		t.Fatal("err = nil, want store 未装配错误")
	}
}

// TestAIRetentionNoDeletionNoAudit 无删除且无链异常：不写系统审计。
func TestAIRetentionNoDeletionNoAudit(t *testing.T) {
	audit := &fakeAIAudit{}
	c := newTestCleaner(&fakeAIStore{}, nil, audit, &fakeAIChain{})
	if _, err := c.SweepOnce(context.Background()); err != nil {
		t.Fatalf("SweepOnce err = %v", err)
	}
	if len(audit.records) != 0 {
		t.Fatalf("审计记录 = %d 条, want 0（无变更不记账）", len(audit.records))
	}
}

// TestAIRetentionChainMismatch 审计哈希链不符：如实上报、系统审计记 FAILURE，且不删除审计表。
func TestAIRetentionChainMismatch(t *testing.T) {
	audit := &fakeAIAudit{}
	c := newTestCleaner(&fakeAIStore{}, nil, audit, &fakeAIChain{mismatches: 2})
	result, err := c.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("SweepOnce err = %v（链不符不视为 sweep 失败）", err)
	}
	if result.AuditMismatches != 2 {
		t.Errorf("AuditMismatches = %d, want 2", result.AuditMismatches)
	}
	if len(audit.records) != 1 || audit.records[0].Result != audits.ResultFailure {
		t.Fatalf("审计记录 = %+v, want 1 条 FAILURE", audit.records)
	}
}

// TestAIRetentionChainVerifyError 链校验执行失败：错误如实返回不静默。
func TestAIRetentionChainVerifyError(t *testing.T) {
	c := newTestCleaner(&fakeAIStore{}, nil, nil, &fakeAIChain{err: errors.New("verify io error")})
	if _, err := c.SweepOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "verify ai audit chain") {
		t.Fatalf("err = %v, want 链校验错误", err)
	}
}
