// collector_heartbeat_test.go 心跳记录采集容忍（W17-HB）单测：
// 心跳不产生任何业务数据（端点发现/学习样本/schema 违例/findings/参数·响应·文件·
// LLM 观测/流量桶/主事件表全部零贡献），仅透传给 HeartbeatRecorder。
package apiruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/server/internal/apillm"
)

type fakeHeartbeatRecorder struct {
	calls []Heartbeat
	err   error
}

func (f *fakeHeartbeatRecorder) RecordHeartbeat(_ context.Context, hb Heartbeat) error {
	if f.err != nil {
		return f.err
	}
	f.calls = append(f.calls, hb)
	return nil
}

type fakeLLMObsRecorder struct{ calls int }

func (f *fakeLLMObsRecorder) RecordLLMObservation(_ context.Context, _ apillm.ObservationInput) error {
	f.calls++
	return nil
}

type fakeParamObsRecorder struct{ calls int }

func (f *fakeParamObsRecorder) RecordParamObservations(_ context.Context, _ string, _ []ParamObservation) error {
	f.calls++
	return nil
}

// 全接线采集器：一条心跳 + 一条 ALLOW 通行 + 一条 BLOCK 明细混合输入，
// 断言心跳对所有业务物化零贡献，且透传字段完整。
func TestCollectOnce_HeartbeatTolerance(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-runtime-events.log")
	cpPath := filepath.Join(dir, "checkpoint")
	now := time.Now().UTC()

	// 心跳记录（网关 W17-HB 形态：endpoint_key 占位 + heartbeat=true + 版本维度）
	hb := Record{
		RequestID: "hb-1", EndpointKey: "__heartbeat__", Heartbeat: true,
		FinalAction: "ALLOW", RiskLevel: "NONE",
		GatewayNode: "gw-hb-1", PolicyVersion: "v2026.3",
		OccurredAt: now,
	}
	allow := Record{
		RequestID: "r-allow", EndpointKey: "GET /v1/a", Method: "GET", PathTemplate: "/v1/a",
		IsAPI: true, FinalAction: "ALLOW", GatewayNode: "gw-hb-1", PolicyVersion: "v2026.3",
		OccurredAt: now,
	}
	block := Record{
		RequestID: "r-block", EndpointKey: "POST /v1/b", Method: "POST", PathTemplate: "/v1/b",
		IsAPI: true, FinalAction: "BLOCK", RiskLevel: "MEDIUM", RiskScore: 40,
		GatewayNode: "gw-hb-1", OccurredAt: now,
		Details: []dsctx.DetectorMatch{{
			Detector: "api_schema", RuleID: "schema.type_mismatch", Category: "BLOCK",
			Severity: "HIGH", Message: "type mismatch for id", ScoreDelta: 40,
		}},
	}
	writeLines(t, logPath, []string{mustJSON(t, hb), mustJSON(t, allow), mustJSON(t, block)})

	saver := &fakeSaver{}
	disc := &fakeDiscovery{}
	samples := &fakeSampleRecorder{}
	violations := &fakeViolationSaver{}
	findings := &fakeFindingSaver{}
	paramObs := &fakeParamObsRecorder{}
	respSchemas := &fakeRespSchemaRecorder{}
	fileObs := &fakeFileObsRecorder{}
	llmObs := &fakeLLMObsRecorder{}
	traffic := &fakeTraffic{}
	heartbeats := &fakeHeartbeatRecorder{}

	c := NewCollector(saver, "test-hb", logPath, cpPath, "node-1")
	c.SetDiscoveryUpserter(disc)
	c.SetResolver(&fakeResolver{})
	c.SetSampleRecorder(samples)
	c.SetViolationSaver(violations)
	c.SetFindingSaver(findings)
	c.SetParamObsRecorder(paramObs)
	c.SetRespSchemaRecorder(respSchemas)
	c.SetFileObsRecorder(fileObs)
	c.SetLLMObsRecorder(llmObs)
	c.SetTrafficRecorder(traffic)
	c.SetHeartbeatRecorder(heartbeats)

	n, err := c.CollectOnce(context.Background())
	if err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if n != 3 {
		t.Fatalf("processed = %d, want 3", n)
	}
	// 主事件表：仅 BLOCK 一条（心跳不落表——不落表评估见 collector.go 分支注释；
	// ALLOW 纯通行不 notable 属既有口径）
	if len(saver.saved) != 1 || saver.saved[0].RequestID != "r-block" {
		t.Fatalf("primary saved = %+v, want only r-block", saver.saved)
	}
	// 端点发现：仅两条业务记录（心跳不产端点资产——__heartbeat__ 不得进发现）
	if len(disc.calls) != 2 {
		t.Fatalf("discovery calls = %d, want 2 (heartbeat must not create endpoint asset)", len(disc.calls))
	}
	for _, call := range disc.calls {
		if call.in.Method == "" || call.in.PathTemplate == "__heartbeat__" {
			t.Fatalf("heartbeat leaked into discovery: %+v", call.in)
		}
	}
	// 业务物化计数全部等于「仅业务记录」口径：样本 2（ALLOW+BLOCK）、违例 1（BLOCK
	// schema 明细）、findings 1 批 1 条（BLOCK 明细）、流量桶 2（两次发现成功）；
	// 参数/响应/文件/LLM 观测零调用（输入记录本身无观测，心跳亦零贡献）
	if len(samples.calls) != 2 {
		t.Fatalf("sample calls = %d, want 2 (business only)", len(samples.calls))
	}
	for _, s := range samples.calls {
		if s.EndpointKey == "__heartbeat__" {
			t.Fatalf("heartbeat leaked into samples: %+v", s)
		}
	}
	if len(violations.inputs) != 1 || violations.inputs[0].RequestID != "r-block" {
		t.Fatalf("violation inputs = %+v, want only r-block", violations.inputs)
	}
	if len(findings.batches) != 1 || len(findings.batches[0]) != 1 ||
		findings.batches[0][0].RequestID != "r-block" {
		t.Fatalf("finding batches = %+v, want one batch for r-block", findings.batches)
	}
	if paramObs.calls != 0 || respSchemas.calls != 0 || len(fileObs.recs) != 0 || llmObs.calls != 0 {
		t.Fatalf("param/resp/file/llm = %d/%d/%d/%d, want all 0",
			paramObs.calls, respSchemas.calls, len(fileObs.recs), llmObs.calls)
	}
	if len(traffic.calls) != 2 {
		t.Fatalf("traffic buckets = %d, want 2 (business discoveries only)", len(traffic.calls))
	}
	// 心跳透传：节点/版本/时间/请求 ID 完整到达 recorder
	if len(heartbeats.calls) != 1 {
		t.Fatalf("heartbeat calls = %d, want 1", len(heartbeats.calls))
	}
	got := heartbeats.calls[0]
	if got.NodeName != "gw-hb-1" || got.PolicyVersion != "v2026.3" ||
		got.RequestID != "hb-1" || !got.OccurredAt.Equal(now) {
		t.Fatalf("heartbeat payload = %+v", got)
	}
	// 指标可观测：心跳计数与处理/入库计数分离
	m := c.Metrics()
	if m["heartbeat_count"].(int64) != 1 || m["processed_count"].(int64) != 3 || m["saved_count"].(int64) != 1 {
		t.Fatalf("metrics = %+v", m)
	}
	// 错误文件不存在（心跳是合法记录，不是坏行）
	if _, err := os.Stat(logPath + ".errors"); !os.IsNotExist(err) {
		t.Fatalf("heartbeat must not land in error file: %v", err)
	}
	// 重采幂等：断点前移后重复采集无新增副作用
	if n2, err := c.CollectOnce(context.Background()); err != nil || n2 != 0 {
		t.Fatalf("second CollectOnce = (%d,%v), want (0,nil)", n2, err)
	}
	if len(heartbeats.calls) != 1 || len(saver.saved) != 1 {
		t.Fatal("second CollectOnce duplicated work")
	}
}

// recorder 未接线：心跳仅计数不报错（节点视图退化为业务事件口径，与既有行为一致）。
func TestCollectOnce_HeartbeatWithoutRecorder(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-runtime-events.log")
	cpPath := filepath.Join(dir, "checkpoint")
	hb := Record{RequestID: "hb-1", EndpointKey: "__heartbeat__", Heartbeat: true,
		FinalAction: "ALLOW", GatewayNode: "gw-1", OccurredAt: time.Now().UTC()}
	writeLines(t, logPath, []string{mustJSON(t, hb)})

	saver := &fakeSaver{}
	c := NewCollector(saver, "test-hb-nil", logPath, cpPath, "node-1")
	if _, err := c.CollectOnce(context.Background()); err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if len(saver.saved) != 0 {
		t.Fatalf("heartbeat must not be saved as primary event: %+v", saver.saved)
	}
	if m := c.Metrics(); m["heartbeat_count"].(int64) != 1 {
		t.Fatalf("metrics = %+v", m)
	}
}

// recorder 失败：仅记录日志（注入错误），采集主流程不报错、断点照常前移
// （下一周期心跳自愈；失败可观测性由 slog 承担，不静默吞错）。
func TestCollectOnce_HeartbeatRecorderErrorTolerated(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-runtime-events.log")
	cpPath := filepath.Join(dir, "checkpoint")
	hb := Record{RequestID: "hb-1", EndpointKey: "__heartbeat__", Heartbeat: true,
		FinalAction: "ALLOW", GatewayNode: "gw-1", OccurredAt: time.Now().UTC()}
	writeLines(t, logPath, []string{mustJSON(t, hb)})

	c := NewCollector(&fakeSaver{}, "test-hb-err", logPath, cpPath, "node-1")
	c.SetHeartbeatRecorder(&fakeHeartbeatRecorder{err: errors.New("db down")})
	n, err := c.CollectOnce(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("CollectOnce = (%d,%v), want (1,nil) — recorder error must not break collection", n, err)
	}
	// 断点已前移：重采不重放失败拍（自愈依赖下一周期心跳）
	if n2, err := c.CollectOnce(context.Background()); err != nil || n2 != 0 {
		t.Fatalf("second CollectOnce = (%d,%v), want (0,nil)", n2, err)
	}
}

// 心跳缺 gateway_node：跳过消费并告警（不落半个节点行），采集继续。
func TestCollectOnce_HeartbeatWithoutNodeSkipped(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-runtime-events.log")
	cpPath := filepath.Join(dir, "checkpoint")
	hb := Record{RequestID: "hb-x", EndpointKey: "__heartbeat__", Heartbeat: true,
		FinalAction: "ALLOW", OccurredAt: time.Now().UTC()}
	writeLines(t, logPath, []string{mustJSON(t, hb)})

	heartbeats := &fakeHeartbeatRecorder{}
	c := NewCollector(&fakeSaver{}, "test-hb-nonode", logPath, cpPath, "node-1")
	c.SetHeartbeatRecorder(heartbeats)
	if _, err := c.CollectOnce(context.Background()); err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if len(heartbeats.calls) != 0 {
		t.Fatalf("node-less heartbeat must be skipped: %+v", heartbeats.calls)
	}
}
