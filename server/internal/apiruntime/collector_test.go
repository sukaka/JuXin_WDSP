package apiruntime

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/events"
	"github.com/jiuzhang-waf/server/internal/apiassets"
)

type fakeSaver struct{ saved []*events.PrimaryEvent }

func (f *fakeSaver) SavePrimary(_ context.Context, ev *events.PrimaryEvent) error {
	cp := *ev
	f.saved = append(f.saved, &cp)
	return nil
}

type discoveryCall struct {
	in apiassets.DiscoveryInput
}

type fakeDiscovery struct{ calls []discoveryCall }

func (f *fakeDiscovery) UpsertDiscovery(_ context.Context, in apiassets.DiscoveryInput) (*apiassets.Endpoint, error) {
	f.calls = append(f.calls, discoveryCall{in})
	return &apiassets.Endpoint{}, nil
}

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// 采集：发现 upsert 全量、主事件仅 notable、坏行进错误文件、断点保存。
func TestCollectOnce_Ingests(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-runtime-events.log")
	cpPath := filepath.Join(dir, "checkpoint")

	allow := Record{
		RequestID: "r-1", EndpointKey: "GET /v1/users/{id}", Method: "GET", PathTemplate: "/v1/users/{id}",
		IsAPI: true, APIConfidence: 0.6, FinalAction: "ALLOW", RiskLevel: "NONE",
		OccurredAt: time.Now().UTC(),
	}
	block := Record{
		RequestID: "r-2", EndpointKey: "POST /v1/orders", Method: "POST", PathTemplate: "/v1/orders",
		IsAPI: true, APIConfidence: 0.9, FinalAction: "BLOCK", RiskLevel: "MEDIUM", RiskScore: 40,
		Details: []dsctx.DetectorMatch{{
			Detector: "api_schema", RuleID: "schema.type_mismatch", Category: "BLOCK",
			Severity: "HIGH", Message: "type mismatch for id", ScoreDelta: 40,
		}},
		OccurredAt: time.Now().UTC(),
	}
	writeLines(t, logPath, []string{
		mustJSON(t, allow),
		mustJSON(t, block),
		`{"not":"a valid record"}`,
		"{bad json",
	})

	saver := &fakeSaver{}
	disc := &fakeDiscovery{}
	c := NewCollector(saver, "test-01", logPath, cpPath, "node-1")
	c.SetDiscoveryUpserter(disc)

	n, err := c.CollectOnce(context.Background())
	if err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if n != 4 {
		t.Fatalf("want 4 processed lines, got %d", n)
	}
	// 发现 upsert：仅两条有效记录（坏行不进发现）
	if len(disc.calls) != 2 {
		t.Fatalf("want 2 discovery upserts, got %d", len(disc.calls))
	}
	if disc.calls[0].in.Method != "GET" || disc.calls[0].in.PathTemplate != "/v1/users/{id}" || !disc.calls[0].in.IsAPI {
		t.Fatalf("bad discovery call: %+v", disc.calls[0])
	}
	// 主事件：仅 BLOCK 一条
	if len(saver.saved) != 1 {
		t.Fatalf("want 1 primary saved, got %d", len(saver.saved))
	}
	ev := saver.saved[0]
	if ev.RequestID != "r-2" || ev.FinalAction != "BLOCK" || ev.RiskScore != 40 || len(ev.Details) != 1 {
		t.Fatalf("bad primary event: %+v", ev)
	}
	// 错误文件两行（JSON 结构合法但缺字段 1 行 + 坏 JSON 1 行）
	errData, err := os.ReadFile(logPath + ".errors")
	if err != nil {
		t.Fatalf("read errors file: %v", err)
	}
	if got := len(strings.Split(strings.TrimSpace(string(errData)), "\n")); got != 2 {
		t.Fatalf("want 2 error lines, got %d", got)
	}
	// 断点已保存；重复采集无新增
	if _, err := os.Stat(cpPath); err != nil {
		t.Fatalf("checkpoint not saved: %v", err)
	}
	n2, err := c.CollectOnce(context.Background())
	if err != nil || n2 != 0 {
		t.Fatalf("second CollectOnce want (0,nil), got (%d,%v)", n2, err)
	}
	if len(saver.saved) != 1 || len(disc.calls) != 2 {
		t.Fatal("second CollectOnce duplicated work")
	}
}

// 轮转：文件被重建（inode 变化）后从头重读；SavePrimary 幂等由 store 层 request_id 去重承担。
func TestCollectOnce_RotationRereads(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-runtime-events.log")
	cpPath := filepath.Join(dir, "checkpoint")

	rec := Record{RequestID: "r-9", EndpointKey: "GET /a", Method: "GET", PathTemplate: "/a",
		IsAPI: true, FinalAction: "ALLOW", OccurredAt: time.Now().UTC()}
	writeLines(t, logPath, []string{mustJSON(t, rec)})

	saver := &fakeSaver{}
	c := NewCollector(saver, "test-02", logPath, cpPath, "node-1")
	if _, err := c.CollectOnce(context.Background()); err != nil {
		t.Fatalf("first CollectOnce: %v", err)
	}

	// 删除重建（新 inode），同路径写入更多行
	if err := os.Remove(logPath); err != nil {
		t.Fatal(err)
	}
	writeLines(t, logPath, []string{mustJSON(t, rec), mustJSON(t, rec)})

	n, err := c.CollectOnce(context.Background())
	if err != nil {
		t.Fatalf("second CollectOnce after rotation: %v", err)
	}
	if n != 2 {
		t.Fatalf("want re-read 2 lines after rotation, got %d", n)
	}
}

func TestParseRecordLine(t *testing.T) {
	if _, err := parseRecordLine([]byte(`{"request_id":"r","endpoint_key":"GET /a"}`)); err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}
	if _, err := parseRecordLine([]byte(`{"foo":1}`)); err == nil {
		t.Fatal("record without request_id and endpoint_key must be rejected")
	}
	if _, err := parseRecordLine([]byte(`{bad`)); err == nil {
		t.Fatal("bad json must be rejected")
	}
}

// 归属解析：带 app_code/domain 的发现记录经 Resolver 回填 application_id/domain_id。
func TestCollectOnce_ResolvesSiteAndDomain(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-runtime-events.log")
	cpPath := filepath.Join(dir, "checkpoint")

	appID := uuid.New()
	domID := uuid.New()
	rec := Record{
		RequestID: "r-site-1", EndpointKey: "POST /v1/orders", Method: "POST", PathTemplate: "/v1/orders",
		AppCode: "shop", Domain: "www.example.com", IsAPI: true, APIConfidence: 0.9,
		FinalAction: "ALLOW", OccurredAt: time.Now().UTC(),
	}
	writeLines(t, logPath, []string{mustJSON(t, rec)})

	saver := &fakeSaver{}
	disc := &fakeDiscovery{}
	c := NewCollector(saver, "test-site", logPath, cpPath, "node-1")
	c.SetDiscoveryUpserter(disc)
	c.SetResolver(&fakeResolver{appID: appID, domID: domID})

	if _, err := c.CollectOnce(context.Background()); err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if len(disc.calls) != 1 {
		t.Fatalf("want 1 discovery call, got %d", len(disc.calls))
	}
	in := disc.calls[0].in
	if in.ApplicationID == nil || *in.ApplicationID != appID {
		t.Fatalf("application not resolved: %+v", in)
	}
	if in.DomainID == nil || *in.DomainID != domID {
		t.Fatalf("domain not resolved: %+v", in)
	}
}

// 无解析器时按未归属处理（nil 归属，不报错）。
func TestCollectOnce_WithoutResolverLeavesUnassigned(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-runtime-events.log")
	cpPath := filepath.Join(dir, "checkpoint")

	rec := Record{
		RequestID: "r-site-2", EndpointKey: "GET /v1/items/{id}", Method: "GET", PathTemplate: "/v1/items/{id}",
		AppCode: "shop", IsAPI: true, FinalAction: "ALLOW", OccurredAt: time.Now().UTC(),
	}
	writeLines(t, logPath, []string{mustJSON(t, rec)})

	saver := &fakeSaver{}
	disc := &fakeDiscovery{}
	c := NewCollector(saver, "test-noresolver", logPath, cpPath, "node-1")
	c.SetDiscoveryUpserter(disc)

	if _, err := c.CollectOnce(context.Background()); err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if len(disc.calls) != 1 || disc.calls[0].in.ApplicationID != nil || disc.calls[0].in.DomainID != nil {
		t.Fatalf("expect nil site/domain without resolver: %+v", disc.calls)
	}
}

type fakeResolver struct {
	appID, domID uuid.UUID
}

func (f *fakeResolver) ResolveApplication(_ context.Context, code string) (*uuid.UUID, error) {
	if code == "" {
		return nil, nil
	}
	id := f.appID
	return &id, nil
}

func (f *fakeResolver) ResolveDomain(_ context.Context, appID *uuid.UUID, hostname string) (*uuid.UUID, error) {
	if appID == nil || hostname == "" {
		return nil, nil
	}
	id := f.domID
	return &id, nil
}
