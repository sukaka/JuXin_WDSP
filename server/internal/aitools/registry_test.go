package aitools

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fakeTool 测试用 Tool（内嵌元数据基座，Run 可注入）。
type fakeTool struct {
	baseTool
	run func(ctx context.Context, input json.RawMessage) (interface{}, error)
}

func (f *fakeTool) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	return f.run(ctx, input)
}

func newFakeTool(code, perm string, run func(ctx context.Context, input json.RawMessage) (interface{}, error)) *fakeTool {
	return &fakeTool{
		baseTool: baseTool{meta: toolMeta{
			code: code, name: "测试" + code, description: "测试工具", version: "1.0.0",
			risk: RiskReadOnly, permission: perm, timeout: 5, maxResults: 100,
			schema: map[string]interface{}{"type": "object"},
		}},
		run: run,
	}
}

func okRun(_ context.Context, _ json.RawMessage) (interface{}, error) {
	return map[string]interface{}{"ok": true}, nil
}

// fakeAuditor 内存审计器。
type fakeAuditor struct{ records []AuditRecord }

func (a *fakeAuditor) RecordToolCall(_ context.Context, rec AuditRecord) (string, error) {
	a.records = append(a.records, rec)
	return "ref-" + rec.ToolCode, nil
}

func adminPrincipal(perms ...string) *Principal {
	p := &Principal{UserID: uuid.New(), Username: "admin", Permissions: map[string]bool{}}
	for _, perm := range perms {
		p.Permissions[perm] = true
	}
	return p
}

// TestPrincipalHasPermission 权限点检查：nil/空权限点/未授权/已授权。
func TestPrincipalHasPermission(t *testing.T) {
	var nilP *Principal
	if nilP.HasPermission("event:view") {
		t.Error("nil Principal 不应有任何权限")
	}
	p := &Principal{}
	if p.HasPermission("") {
		t.Error("空权限点应返回 false")
	}
	if p.HasPermission("event:view") {
		t.Error("未授权权限点应返回 false")
	}
	p.Permissions = map[string]bool{"event:view": true}
	if !p.HasPermission("event:view") {
		t.Error("已授权权限点应返回 true")
	}
}

// TestRegisterGetList 注册、获取与元数据列表。
func TestRegisterGetList(t *testing.T) {
	r := NewRegistry()
	r.Register(newFakeTool("security_event.search", "event:view", okRun))
	r.Register(newFakeTool("log.query", "", okRun))

	if _, ok := r.Get("security_event.search"); !ok {
		t.Error("Get 已注册 Tool 应命中")
	}
	if _, ok := r.Get("not.exist"); ok {
		t.Error("Get 未注册 Tool 应返回 false")
	}
	list := r.List()
	if len(list) != 2 {
		t.Fatalf("List 长度 = %d, want 2", len(list))
	}
	found := map[string]bool{}
	for _, m := range list {
		code, _ := m["code"].(string)
		found[code] = true
		for _, k := range []string{"name", "description", "version", "risk_level",
			"required_permission", "timeout_seconds", "max_results", "input_schema"} {
			if _, ok := m[k]; !ok {
				t.Errorf("Tool %s 元数据缺少字段 %s", code, k)
			}
		}
		if m["risk_level"] != RiskReadOnly {
			t.Errorf("Tool %s risk_level = %v", code, m["risk_level"])
		}
	}
	if !found["security_event.search"] || !found["log.query"] {
		t.Errorf("List 缺少已注册 Tool: %v", found)
	}
}

// TestExecuteSuccess 成功路径：结果、审计引用与审计记录字段。
func TestExecuteSuccess(t *testing.T) {
	r := NewRegistry()
	r.Register(newFakeTool("log.query", "", okRun))
	aud := &fakeAuditor{}
	taskID := uuid.New()
	res, ref, err := r.Execute(context.Background(), adminPrincipal(), taskID, nil,
		"log.query", json.RawMessage(`{"q":"x"}`), aud)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if res.(map[string]interface{})["ok"] != true {
		t.Errorf("result = %v", res)
	}
	if ref != "ref-log.query" {
		t.Errorf("审计引用 = %q", ref)
	}
	if len(aud.records) != 1 {
		t.Fatalf("审计记录数 = %d, want 1", len(aud.records))
	}
	rec := aud.records[0]
	if rec.Status != "SUCCESS" || rec.ToolCode != "log.query" || rec.ToolVersion != "1.0.0" ||
		rec.TaskID != taskID || rec.RiskLevel != RiskReadOnly || rec.ErrorCode != "" {
		t.Errorf("审计记录 = %+v", rec)
	}
	if rec.InputSummary != `{"q":"x"}` {
		t.Errorf("InputSummary = %q", rec.InputSummary)
	}
	if rec.DurationMs < 0 {
		t.Errorf("DurationMs = %d", rec.DurationMs)
	}
}

// TestExecuteToolNotFound 未注册 Tool 直接报错且不产生审计。
func TestExecuteToolNotFound(t *testing.T) {
	r := NewRegistry()
	aud := &fakeAuditor{}
	_, _, err := r.Execute(context.Background(), adminPrincipal(), uuid.New(), nil, "missing", nil, aud)
	if !errors.Is(err, ErrToolNotFound) {
		t.Errorf("err = %v, want ErrToolNotFound", err)
	}
	if len(aud.records) != 0 {
		t.Error("未注册 Tool 不应产生审计记录")
	}
}

// TestExecuteDisabled 管理面禁用的 Tool 拒绝执行。
func TestExecuteDisabled(t *testing.T) {
	r := NewRegistry()
	r.Register(newFakeTool("log.query", "", okRun))
	r.SetEnabledChecker(func(_ context.Context, _ string) bool { return false })
	aud := &fakeAuditor{}
	_, _, err := r.Execute(context.Background(), adminPrincipal(), uuid.New(), nil, "log.query", nil, aud)
	if !errors.Is(err, ErrToolDisabled) {
		t.Errorf("err = %v, want ErrToolDisabled", err)
	}
	// 启用检查通过则正常执行
	r.SetEnabledChecker(func(_ context.Context, _ string) bool { return true })
	if _, _, err := r.Execute(context.Background(), adminPrincipal(), uuid.New(), nil, "log.query", nil, aud); err != nil {
		t.Errorf("启用后 Execute() error = %v", err)
	}
}

// TestExecutePermissionDenied 权限不足拒绝执行并审计 DENIED。
func TestExecutePermissionDenied(t *testing.T) {
	r := NewRegistry()
	r.Register(newFakeTool("security_event.search", "event:view", okRun))
	aud := &fakeAuditor{}
	ctx := context.Background()

	// 权限点不匹配
	_, _, err := r.Execute(ctx, adminPrincipal("other:perm"), uuid.New(), nil, "security_event.search", nil, aud)
	if !errors.Is(err, ErrPermission) {
		t.Errorf("err = %v, want ErrPermission", err)
	}
	if len(aud.records) != 1 || aud.records[0].Status != "DENIED" || aud.records[0].ErrorCode != "PERMISSION_DENIED" {
		t.Errorf("DENIED 审计记录缺失或字段错误: %+v", aud.records)
	}
	// nil Principal 视为无权限
	if _, _, err := r.Execute(ctx, nil, uuid.New(), nil, "security_event.search", nil, aud); !errors.Is(err, ErrPermission) {
		t.Errorf("nil Principal err = %v, want ErrPermission", err)
	}
	// 具备权限点 → 放行
	if _, _, err := r.Execute(ctx, adminPrincipal("event:view"), uuid.New(), nil, "security_event.search", nil, aud); err != nil {
		t.Errorf("具备权限点应放行: %v", err)
	}
}

// TestExecuteNoPermissionRequired Tool 无权限点要求时 nil Principal 也可执行。
func TestExecuteNoPermissionRequired(t *testing.T) {
	r := NewRegistry()
	r.Register(newFakeTool("log.query", "", okRun))
	if _, _, err := r.Execute(context.Background(), nil, uuid.New(), nil, "log.query", nil, nil); err != nil {
		t.Errorf("Execute() error = %v", err)
	}
}

// TestExecuteTimeout Tool 执行超过 TimeoutSeconds 判定超时并审计 TIMEOUT。
func TestExecuteTimeout(t *testing.T) {
	r := NewRegistry()
	tool := newFakeTool("slow.query", "", func(ctx context.Context, _ json.RawMessage) (interface{}, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	tool.meta.timeout = 1 // 1 秒超时
	r.Register(tool)
	aud := &fakeAuditor{}
	start := time.Now()
	_, _, err := r.Execute(context.Background(), adminPrincipal(), uuid.New(), nil, "slow.query", nil, aud)
	if !errors.Is(err, ErrTimeout) {
		t.Errorf("err = %v, want ErrTimeout", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("超时控制未生效, 耗时 %v", elapsed)
	}
	if len(aud.records) != 1 || aud.records[0].Status != "TIMEOUT" || aud.records[0].ErrorCode != "TIMEOUT" {
		t.Errorf("TIMEOUT 审计记录缺失或字段错误: %+v", aud.records)
	}
}

// TestExecuteRunError 普通执行错误透传并审计 FAILED，不误判超时。
func TestExecuteRunError(t *testing.T) {
	r := NewRegistry()
	r.Register(newFakeTool("fail.query", "", func(_ context.Context, _ json.RawMessage) (interface{}, error) {
		return nil, errors.New("backend boom")
	}))
	aud := &fakeAuditor{}
	_, _, err := r.Execute(context.Background(), adminPrincipal(), uuid.New(), nil, "fail.query", nil, aud)
	if err == nil || !strings.Contains(err.Error(), "backend boom") {
		t.Errorf("err = %v, 应透传原始错误", err)
	}
	if errors.Is(err, ErrTimeout) {
		t.Error("普通错误不应误判为超时")
	}
	if len(aud.records) != 1 || aud.records[0].Status != "FAILED" || aud.records[0].ErrorCode != "RUN_ERROR" {
		t.Errorf("FAILED 审计记录缺失或字段错误: %+v", aud.records)
	}
}

// TestExecuteInputSummaryTruncated 入参摘要超过 400 字符截断。
func TestExecuteInputSummaryTruncated(t *testing.T) {
	r := NewRegistry()
	r.Register(newFakeTool("log.query", "", okRun))
	aud := &fakeAuditor{}
	long := json.RawMessage(`{"q":"` + strings.Repeat("x", 500) + `"}`)
	if _, _, err := r.Execute(context.Background(), adminPrincipal(), uuid.New(), nil, "log.query", long, aud); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	got := aud.records[0].InputSummary
	if len(got) != 403 || !strings.HasSuffix(got, "...") {
		t.Errorf("InputSummary 长度 = %d, want 403 且以 ... 结尾", len(got))
	}
}

// TestDecode 入参解码：正常 / 空输入 / 非法 JSON。
func TestDecode(t *testing.T) {
	type input struct {
		Keyword string `json:"keyword"`
		Limit   int    `json:"limit"`
	}
	var v input
	if err := Decode(json.RawMessage(`{"keyword":"xss","limit":10}`), &v); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if v.Keyword != "xss" || v.Limit != 10 {
		t.Errorf("Decode = %+v", v)
	}
	var empty input
	if err := Decode(nil, &empty); err != nil {
		t.Errorf("空输入应无错误: %v", err)
	}
	if err := Decode(json.RawMessage(`{bad`), &v); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("非法 JSON err = %v, want ErrInvalidInput", err)
	}
}

// TestFieldHelpers StrField/IntField/BoolField 边界。
func TestFieldHelpers(t *testing.T) {
	m := map[string]interface{}{"name": "abcdef", "count": float64(7), "enabled": true}
	if got := StrField(m, "name", 3); got != "abc" {
		t.Errorf("StrField 截断 = %q", got)
	}
	if got := StrField(m, "name", 0); got != "abcdef" {
		t.Errorf("StrField 不限长 = %q", got)
	}
	if got := StrField(m, "missing", 5); got != "" {
		t.Errorf("StrField 缺失字段 = %q", got)
	}
	if got := IntField(m, "count", 0); got != 7 {
		t.Errorf("IntField = %d", got)
	}
	if got := IntField(m, "missing", 42); got != 42 {
		t.Errorf("IntField 默认值 = %d", got)
	}
	if !BoolField(m, "enabled") {
		t.Error("BoolField 应为 true")
	}
	if BoolField(m, "missing") {
		t.Error("BoolField 缺失字段应为 false")
	}
}
