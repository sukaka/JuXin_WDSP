// grpc_test.go gRPC 安全检测测试（W14-GW / P2-05）：
// 帧观测明细（不落内容）、畸形帧 BLOCK 类按模式定案、压缩策略 OBSERVE。
package detectors

import (
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// findMatch 按 rule_id 找明细。
func findGRPCMatch(ms []dsctx.DetectorMatch, ruleID string) *dsctx.DetectorMatch {
	for i := range ms {
		if ms[i].RuleID == ruleID {
			return &ms[i]
		}
	}
	return nil
}

// 帧结构观测：消息计数与声明体量入 INFO 明细（不落内容）；无体流量计数为零。
func TestCheckGRPCObserved(t *testing.T) {
	ctx := dsctx.New("req-grpc-det-1", dsctx.DefaultParseLimits())
	p := &parser.Parsed{GRPC: &parser.GRPCInfo{MessageCount: 3, DeclaredBytes: 128, CompressedSeen: true}}
	CheckGRPC(ctx, p, true, nil) // 允许压缩：不产压缩明细
	obs := findGRPCMatch(ctx.CopyMatches(), "grpc.observed")
	if obs == nil {
		t.Fatalf("grpc.observed missing: %+v", ctx.CopyMatches())
	}
	if obs.Category != "INFO" || obs.Severity != "INFO" {
		t.Fatalf("observed must be INFO/INFO: %s/%s", obs.Category, obs.Severity)
	}
	if obs.Evidence["message_count"] != "3" || obs.Evidence["declared_bytes"] != "128" {
		t.Fatalf("evidence = %+v", obs.Evidence)
	}
	// 无描述符下发（nil scan）：观测证据与 v1 逐键一致，不含 decoded/descriptor
	if len(obs.Evidence) != 2 {
		t.Fatalf("nil scan must keep v1 evidence shape, got %+v", obs.Evidence)
	}
	if m := findGRPCMatch(ctx.CopyMatches(), "grpc.unexpected_compression"); m != nil {
		t.Fatalf("compression allowed must not flag: %+v", m)
	}
	// 无体（GRPC 信息为 nil）：计数为零仍产观测
	ctx2 := dsctx.New("req-grpc-det-2", dsctx.DefaultParseLimits())
	CheckGRPC(ctx2, &parser.Parsed{}, false, nil)
	obs2 := findGRPCMatch(ctx2.CopyMatches(), "grpc.observed")
	if obs2 == nil || obs2.Evidence["message_count"] != "0" {
		t.Fatalf("bodyless observed = %+v", obs2)
	}
	if m := findGRPCMatch(ctx2.CopyMatches(), "grpc.malformed_frame"); m != nil {
		t.Fatalf("bodyless must not be malformed: %+v", m)
	}
	// nil 入参不 panic
	CheckGRPC(nil, nil, false, nil)
}

// 畸形帧：BLOCK 类明细（证据只含结构形态）；PROTECT 定案 403 类 BLOCK，OBSERVE 降级记录。
func TestCheckGRPCMalformedDecision(t *testing.T) {
	mk := func() *dsctx.RequestContext {
		ctx := dsctx.New("req-grpc-det-3", dsctx.DefaultParseLimits())
		CheckGRPC(ctx, &parser.Parsed{GRPC: &parser.GRPCInfo{
			MessageCount: 1, DeclaredBytes: 2, Malformed: true, MalformedKind: "length_exceeds_remaining",
		}}, false, nil)
		return ctx
	}
	ctx := mk()
	m := findGRPCMatch(ctx.CopyMatches(), "grpc.malformed_frame")
	if m == nil {
		t.Fatalf("grpc.malformed_frame missing: %+v", ctx.CopyMatches())
	}
	if m.Category != "BLOCK" || m.Severity != "HIGH" {
		t.Fatalf("malformed must be BLOCK/HIGH: %s/%s", m.Category, m.Severity)
	}
	if m.Evidence["kind"] != "length_exceeds_remaining" {
		t.Fatalf("evidence = %+v", m.Evidence)
	}
	if act := decision.Decide(ctx, decision.Input{Mode: decision.ModeProtect}); act != dsctx.ActionBlock {
		t.Fatalf("PROTECT must block malformed frame, got %s", act)
	}
	if act := decision.Decide(mk(), decision.Input{Mode: decision.ModeObserve}); act != dsctx.ActionObserve {
		t.Fatalf("OBSERVE must only record, got %s", act)
	}
}

// 压缩策略：标志位置位且配置不允许 → OBSERVE/MEDIUM；健康流量仅 INFO → ALLOW。
func TestCheckGRPCCompression(t *testing.T) {
	ctx := dsctx.New("req-grpc-det-4", dsctx.DefaultParseLimits())
	CheckGRPC(ctx, &parser.Parsed{GRPC: &parser.GRPCInfo{MessageCount: 1, CompressedSeen: true}}, false, nil)
	m := findGRPCMatch(ctx.CopyMatches(), "grpc.unexpected_compression")
	if m == nil {
		t.Fatalf("grpc.unexpected_compression missing: %+v", ctx.CopyMatches())
	}
	if m.Category != "OBSERVE" || m.Severity != "MEDIUM" {
		t.Fatalf("compression must be OBSERVE/MEDIUM: %s/%s", m.Category, m.Severity)
	}
	if act := decision.Decide(ctx, decision.Input{Mode: decision.ModeProtect}); act != dsctx.ActionObserve {
		t.Fatalf("compression observe must not block, got %s", act)
	}
	// 健康流量（仅观测 INFO）：不参与动作决策 → ALLOW
	ctx2 := dsctx.New("req-grpc-det-5", dsctx.DefaultParseLimits())
	CheckGRPC(ctx2, &parser.Parsed{GRPC: &parser.GRPCInfo{MessageCount: 2, DeclaredBytes: 8}}, false, nil)
	if act := decision.Decide(ctx2, decision.Input{Mode: decision.ModeProtect}); act != dsctx.ActionAllow {
		t.Fatalf("healthy grpc must allow, got %s", act)
	}
}
