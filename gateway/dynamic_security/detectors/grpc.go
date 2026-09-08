// grpc.go gRPC 安全检测（W14-GW / P2-05 首批 + W14-DESC / P2-05 深化）：
//   - 帧结构观测：消息帧计数与声明长度合计入观测明细（INFO，不落消息内容）；
//   - 畸形帧：parser 逐帧校验判定的三种形态（截断帧头/单帧超上限/声明长度超体剩余）
//     产 grpc.malformed_frame（Category=BLOCK：PROTECT 升级 BLOCK 类定案 403，
//     OBSERVE 仅记录，由统一决策按模式定案，检测器不擅自执行）；
//   - 压缩策略：帧压缩标志位置位且配置不允许压缩（api_grpc_allow_compression 未下发/false）
//     产 grpc.unexpected_compression OBSERVE/MEDIUM——压缩帧内容不解，绕过内容检测的
//     通道形态如实记录；
//   - 描述符驱动字段级解析（深化，见 grpc_desc.go）：有注册表下发时观测增加
//     decoded=true/false 与 descriptor 集名（不落字段值）；敏感命中产
//     grpc.sensitive_field（OBSERVE）；解码失败产 grpc.decode_error（OBSERVE/LOW）。
//     无描述符下发（scan 为 nil 或 Registry 为 nil）时行为与 v1 完全一致。
//
// 不挂 api.IsAPI 分类门槛：gRPC 二进制体在 JSON 信号驱动的分类下天然低分，
// 分类漏判不应关掉帧校验（与扫描/LLM 识别同一纪律）。
package detectors

import (
	"strconv"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// CheckGRPC gRPC 帧结构检测：观测明细恒产（识别为 gRPC 即调用）；
// allowCompression 为发布通道下发（false = 压缩标志位置位产 OBSERVE 明细）；
// scan 为描述符驱动字段级解析输入（nil 或 Registry 为 nil = 无描述符下发，
// 观测证据不含 decoded/descriptor 键，与 v1 完全一致）。
func CheckGRPC(ctx *dsctx.RequestContext, p *parser.Parsed, allowCompression bool, scan *GRPCDescriptorScan) {
	if ctx == nil || p == nil {
		return
	}
	info := p.GRPC
	count, declared := 0, int64(0)
	if info != nil {
		count, declared = info.MessageCount, info.DeclaredBytes
	}
	// 描述符驱动字段级解析（仅注册表下发时；失败降级为 v1 观测不报错）
	var outcome *grpcDescriptorOutcome
	if scan != nil && scan.Registry != nil {
		o := scanGRPCDescriptor(ctx, info, scan)
		outcome = &o
	}
	// 帧结构观测（INFO）：消息计数与声明体量合计，不落消息内容；
	// 有描述符下发时追加 decoded（首帧是否成功解码）与 descriptor（命中集名，
	// 仅方法在集内登记时），重复字段计数随解码成功给出（不落字段值）
	obsEvidence := map[string]string{
		"message_count":  strconv.Itoa(count),
		"declared_bytes": strconv.FormatInt(declared, 10),
	}
	if outcome != nil {
		obsEvidence["decoded"] = strconv.FormatBool(outcome.decoded)
		if outcome.matched {
			obsEvidence["descriptor"] = outcome.setName
		}
		if outcome.decoded && outcome.repeated > 0 {
			obsEvidence["repeated_fields"] = strconv.Itoa(outcome.repeated)
		}
	}
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector: "grpc",
		RuleID:   "grpc.observed",
		Category: "INFO",
		Severity: "INFO",
		Message:  "grpc frames observed",
		Evidence: obsEvidence,
	})
	if info == nil {
		return
	}
	if info.Malformed {
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector:   "grpc",
			RuleID:     "grpc.malformed_frame",
			Category:   "BLOCK", // PROTECT 升级 BLOCK 类；OBSERVE 由统一决策降级记录
			Severity:   "HIGH",
			Message:    "grpc malformed frame",
			Evidence:   map[string]string{"kind": info.MalformedKind},
			ScoreDelta: 30,
		})
	}
	if info.CompressedSeen && !allowCompression {
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector:   "grpc",
			RuleID:     "grpc.unexpected_compression",
			Category:   "OBSERVE",
			Severity:   "MEDIUM",
			Message:    "grpc compressed frame observed while compression not allowed",
			Evidence:   map[string]string{"grpc_encoding": "compressed_flag_set"},
			ScoreDelta: 10,
		})
	}
}
