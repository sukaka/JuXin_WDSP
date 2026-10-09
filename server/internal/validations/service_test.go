// service_test.go 模拟管理面服务测试（fake store + fake policy provider 解耦注入）：
// 创建 would_block 语义、上限/白名单拒绝（InputError）、STALE 读出时求值且不回写、
// CANNOT_REPRODUCE / EVIDENCE_INSUFFICIENT、列表分页。
package validations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
)

// fakeStore 内存报告存储（插入有序，Get/List 模拟 PG 倒序分页）。
type fakeStore struct {
	reports map[uuid.UUID]StoredReport
	order   []uuid.UUID
}

func newFakeStore() *fakeStore { return &fakeStore{reports: map[uuid.UUID]StoredReport{}} }

func (f *fakeStore) InsertReport(ctx context.Context, rec StoredReport) error {
	f.reports[rec.ID] = rec
	f.order = append([]uuid.UUID{rec.ID}, f.order...) // created_at 倒序等价（新报告在前）
	return nil
}

func (f *fakeStore) GetReport(ctx context.Context, id uuid.UUID) (StoredReport, error) {
	rec, ok := f.reports[id]
	if !ok {
		return StoredReport{}, ErrReportNotFound
	}
	return rec, nil
}

func (f *fakeStore) ListReports(ctx context.Context, page, pageSize int) ([]StoredReport, int64, error) {
	total := int64(len(f.order))
	start := (page - 1) * pageSize
	if start >= len(f.order) {
		return []StoredReport{}, total, nil
	}
	end := start + pageSize
	if end > len(f.order) {
		end = len(f.order)
	}
	out := make([]StoredReport, 0, end-start)
	for _, id := range f.order[start:end] {
		out = append(out, f.reports[id])
	}
	return out, total, nil
}

// fakePolicy fake 策略来源（digest 可变以触发 STALE）。
type fakePolicy struct {
	mode   decision.Mode
	digest string
	err    error
}

func (f *fakePolicy) CurrentPolicy(ctx context.Context) (decision.Mode, string, error) {
	return f.mode, f.digest, f.err
}

func newTestService(digest string) (*Service, *fakeStore, *fakePolicy) {
	store := newFakeStore()
	pol := &fakePolicy{mode: decision.ModeProtect, digest: digest}
	return NewService(store, pol), store, pol
}

func oneBatch() []FindingBatch {
	return []FindingBatch{{
		InputID: "req-1",
		Matches: []dsctx.DetectorMatch{{
			Detector: "api_schema", RuleID: "schema.type_mismatch", Category: "BLOCK",
			Severity: "CRITICAL", ScoreDelta: 10,
		}},
	}}
}

// 创建：PROTECT 下 CRITICAL 正向分 → would_block=true（模拟语义）；状态 COMPLETED；
// 报告 ID 为落库 uuid；策略摘要绑定创建时取值；created_by 落库。
func TestServiceCreateWouldBlock(t *testing.T) {
	svc, store, _ := newTestService("pol-digest-a")
	actor := uuid.New()
	rep, err := svc.Create(context.Background(), actor, oneBatch())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if rep.Status != "COMPLETED" {
		t.Fatalf("status=%s want COMPLETED", rep.Status)
	}
	if rep.PolicyDigest != "pol-digest-a" {
		t.Fatalf("policy_digest=%s want 创建时策略摘要", rep.PolicyDigest)
	}
	id, err := uuid.Parse(rep.ID)
	if err != nil {
		t.Fatalf("报告 ID 应为落库 uuid: %q", rep.ID)
	}
	if len(rep.Verdicts) != 1 {
		t.Fatalf("verdicts=%d want 1", len(rep.Verdicts))
	}
	v := rep.Verdicts[0]
	if v.Status != VerdictEvaluated || !v.WouldBlock || v.FinalAction != string(dsctx.ActionBlock) {
		t.Fatalf("CRITICAL/PROTECT 应 would_block=true: %+v", v)
	}
	// 落库内容：状态 COMPLETED + created_by + report_json 含输入批次
	rec, err := store.GetReport(context.Background(), id)
	if err != nil {
		t.Fatalf("落库读取: %v", err)
	}
	if rec.Status != "COMPLETED" || rec.CreatedBy != actor {
		t.Fatalf("落库行不符: status=%s created_by=%v", rec.Status, rec.CreatedBy)
	}
	var payload storedPayload
	if err := json.Unmarshal(rec.ReportJSON, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Batches) != 1 || payload.Batches[0].InputID != "req-1" {
		t.Fatalf("report_json 应含脱敏输入批次: %+v", payload.Batches)
	}
}

// OBSERVE 模式：同一证据 would_block=false（模式语义透传）。
func TestServiceCreateObserveMode(t *testing.T) {
	svc, _, pol := newTestService("pol-x")
	pol.mode = decision.ModeObserve
	rep, err := svc.Create(context.Background(), uuid.New(), oneBatch())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verdicts[0].WouldBlock {
		t.Fatalf("OBSERVE 模式不得 would_block: %+v", rep.Verdicts[0])
	}
}

// 上限/白名单拒绝：空批次、101 批、201 matches、evidence 原文、空 input_id、超长字段——
// 全部 InputError（handler 映射 400），且不得有落库副作用。
func TestServiceCreateValidationRejects(t *testing.T) {
	cases := []struct {
		name    string
		batches []FindingBatch
	}{
		{"空批次", []FindingBatch{}},
		{"101 批", make([]FindingBatch, 101)},
		{"空 input_id", []FindingBatch{{Matches: oneBatch()[0].Matches}}},
		{"超长 input_id", []FindingBatch{{InputID: strings.Repeat("x", 257), Matches: oneBatch()[0].Matches}}},
		{"201 matches", func() []FindingBatch {
			b := oneBatch()[0]
			b.Matches = make([]dsctx.DetectorMatch, 201)
			return []FindingBatch{b}
		}()},
		{"evidence 原文", func() []FindingBatch {
			b := oneBatch()[0]
			b.Matches[0].Evidence = map[string]string{"body": "raw-secret"}
			return []FindingBatch{b}
		}()},
		{"空 detector", []FindingBatch{{InputID: "r", Matches: []dsctx.DetectorMatch{{RuleID: "x"}}}}},
		{"超长 message", func() []FindingBatch {
			b := oneBatch()[0]
			b.Matches[0].Message = strings.Repeat("m", 257)
			return []FindingBatch{b}
		}()},
		{"超长 missing_reason", []FindingBatch{{InputID: "r", MissingReason: strings.Repeat("z", 257)}}},
		{"51 exceptions", func() []FindingBatch {
			b := oneBatch()[0]
			b.Exceptions = make([]decision.ExceptionRef, 51)
			return []FindingBatch{b}
		}()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc, store, _ := newTestService("pol-a")
			// 101 批用例需要合法元素填满（避免先触发 input_id 必填）
			if c.name == "101 批" {
				for i := range c.batches {
					c.batches[i] = oneBatch()[0]
					c.batches[i].InputID = fmt.Sprintf("r-%d", i)
				}
			}
			_, err := svc.Create(context.Background(), uuid.New(), c.batches)
			var ie InputError
			if err == nil || !errors.As(err, &ie) {
				t.Fatalf("%s 应 InputError: %v", c.name, err)
			}
			if len(store.reports) != 0 {
				t.Fatalf("%s 拒绝后不得落库", c.name)
			}
		})
	}
}

// STALE 读出时求值：创建后策略摘要变化 → Get 返回 STALE；落库行保持 COMPLETED（不回写）。
func TestServiceGetStaleReadTimeNoWriteback(t *testing.T) {
	svc, store, pol := newTestService("pol-a")
	rep, err := svc.Create(context.Background(), uuid.New(), oneBatch())
	if err != nil {
		t.Fatal(err)
	}
	id, _ := uuid.Parse(rep.ID)

	// 摘要未变：COMPLETED
	got, err := svc.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "COMPLETED" {
		t.Fatalf("摘要未变不得 STALE: %s", got.Status)
	}

	// 策略摘要变化（模拟一次新发布）：STALE
	pol.digest = "pol-b"
	got, err = svc.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "STALE" {
		t.Fatalf("策略摘要变化后应为 STALE: %s", got.Status)
	}
	// 落库行不回写（读出求值恒最新，免写路径）
	rec, _ := store.GetReport(context.Background(), id)
	if rec.Status != "COMPLETED" {
		t.Fatalf("落库行不得回写 STALE: %s", rec.Status)
	}
	// 列表同样读出求值
	items, total, err := svc.List(context.Background(), 1, 20)
	if err != nil || total != 1 || len(items) != 1 {
		t.Fatalf("List: total=%d items=%d err=%v", total, len(items), err)
	}
	if items[0].Status != "STALE" {
		t.Fatalf("列表读出应为 STALE: %s", items[0].Status)
	}
}

// CANNOT_REPRODUCE / EVIDENCE_INSUFFICIENT 如实标记（不补造输入）。
func TestServiceCannotReproduceAndInsufficient(t *testing.T) {
	svc, _, _ := newTestService("pol-a")
	rep, err := svc.Create(context.Background(), uuid.New(), []FindingBatch{
		{InputID: "r-noinput", MissingReason: "协议不可复现（grpc stream）"},
		{InputID: "r-empty"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verdicts[0].Status != VerdictCannotReproduce || rep.Verdicts[0].Notes == "" {
		t.Fatalf("缺输入应 CANNOT_REPRODUCE: %+v", rep.Verdicts[0])
	}
	if rep.Verdicts[1].Status != VerdictEvidenceInsufficient {
		t.Fatalf("无 Finding 应 EVIDENCE_INSUFFICIENT: %+v", rep.Verdicts[1])
	}
}

// 列表分页：3 份报告 page_size=2 → 2+1，total=3；按创建倒序（新报告在前）。
func TestServiceListPaging(t *testing.T) {
	svc, _, _ := newTestService("pol-a")
	ctx := context.Background()
	var ids []string
	for i := 0; i < 3; i++ {
		b := oneBatch()
		b[0].InputID = fmt.Sprintf("req-%d", i)
		rep, err := svc.Create(ctx, uuid.New(), b)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, rep.ID)
	}
	items, total, err := svc.List(ctx, 1, 2)
	if err != nil || total != 3 || len(items) != 2 {
		t.Fatalf("page1: total=%d items=%d err=%v", total, len(items), err)
	}
	if items[0].ID != ids[2] {
		t.Fatalf("应按创建倒序（最新在前）: %s want %s", items[0].ID, ids[2])
	}
	items, total, err = svc.List(ctx, 2, 2)
	if err != nil || total != 3 || len(items) != 1 {
		t.Fatalf("page2: total=%d items=%d err=%v", total, len(items), err)
	}
	if items[0].ID != ids[0] {
		t.Fatalf("page2 应为最旧报告: %s want %s", items[0].ID, ids[0])
	}
}

// 报告排序稳定性辅助（防 map 序污染断言；当前用例单报告不涉及，留作扩展点）。
var _ = sort.Strings

// 时间戳存在性（报告创建时刻非零）。
func TestServiceReportCreatedAt(t *testing.T) {
	svc, _, _ := newTestService("pol-a")
	rep, err := svc.Create(context.Background(), uuid.New(), oneBatch())
	if err != nil {
		t.Fatal(err)
	}
	if rep.CreatedAt.IsZero() || time.Since(rep.CreatedAt) > time.Minute {
		t.Fatalf("created_at 异常: %v", rep.CreatedAt)
	}
}
