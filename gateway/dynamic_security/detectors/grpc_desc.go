// grpc_desc.go gRPC 描述符驱动字段级解析（W14-DESC / P2-05 深化）：
// 有描述符注册表下发时，按 :path 的 /package.Service/Method 查找方法描述符，
// 解码请求消息（frames[0]，仅未压缩完整帧；失败降级为 v1 行为不报错），
// 提取 string 字段（proto 字段名点路径，重复字段只统计）跑值级敏感规则
// （与 JSON 体同规则）：命中产 grpc.sensitive_field（OBSERVE，证据只含字段路径+
// 规则名不落值）；线格式损坏产 grpc.decode_error（OBSERVE/LOW，与帧结构畸形的
// grpc.malformed_frame 严格区分——前者帧头/边界合法、消息体 protobuf 线格式损坏，
// 后者 5 字节前缀帧结构与体边界不符）。
//
// 体量护栏：单消息解码输入已被帧上限约束（≤ MaxGRPCFrameBytes，默认 4MiB，
// 与单消息解码上限一致，parseGRPCFrames 超上限帧判畸形不进入解码）；
// 每请求字段遍历/规则求值/命中条数上限见下方常量（防超大消息撑爆 CPU 与事件）。
package detectors

import (
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/grpcdesc"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// 描述符字段级解析护栏。
const (
	maxGRPCFieldWalkDepth = 8   // 嵌套消息递归深度上限
	maxGRPCStringFields   = 256 // 单请求 string 字段遍历产出上限
	maxGRPCValueScans     = 512 // 单请求值级规则求值次数（值 × 规则）上限
	maxGRPCSensitiveHits  = 20  // 单请求敏感字段命中明细上限
)

// GRPCDescriptorScan 描述符驱动字段级解析输入（装配层组装）。
// Registry 为 nil 时零行为（与 v1 完全一致）；ValueRules 为值级敏感规则编译产物
// （与 JSON 体同规则；nil/空 = 只解码观测不做敏感判定）。
type GRPCDescriptorScan struct {
	Registry   *grpcdesc.Registry
	Service    string // :path 服务段（package.Service 全名，分类器拆分口径）
	Method     string // :path 方法段
	ValueRules []CompiledSensitiveValueRule
}

// grpcDescriptorOutcome 描述符解析结果（CheckGRPC 合并进 grpc.observed 证据）。
type grpcDescriptorOutcome struct {
	matched  bool   // 方法在描述符集中命中
	setName  string // 命中的描述符集名（证据 descriptor 字段）
	decoded  bool   // 首帧消息解码成功
	repeated int    // 重复字段计数（只统计不求值）
}

// scanGRPCDescriptor 执行描述符驱动字段级解析：查找方法 → 解码首帧 →
// 字段遍历 → 值级敏感判定。任何失败（方法未登记/无完整首帧/解码失败）降级为
// v1 观测口径，绝不返回错误；解码失败产 grpc.decode_error，敏感命中产
// grpc.sensitive_field（证据纪律：字段路径+规则名+集名，绝不落值）。
func scanGRPCDescriptor(ctx *dsctx.RequestContext, info *parser.GRPCInfo, scan *GRPCDescriptorScan) grpcDescriptorOutcome {
	md, setName, ok := scan.Registry.Lookup(scan.Service, scan.Method)
	if !ok {
		return grpcDescriptorOutcome{} // 方法未登记：decoded=false 且不指名描述符集
	}
	out := grpcDescriptorOutcome{matched: true, setName: setName}
	if info == nil || info.FirstMessage == nil {
		return out // 无完整未压缩首帧（无体/首帧压缩/截断样本）：decoded=false
	}
	msg, err := grpcdesc.DecodeRequest(md, info.FirstMessage)
	if err != nil {
		// 线格式损坏（帧结构合法但消息体非合法 protobuf）：与 malformed_frame 区分
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector:   "grpc",
			RuleID:     "grpc.decode_error",
			Category:   "OBSERVE",
			Severity:   "LOW",
			Message:    "grpc message decode failed",
			Evidence:   map[string]string{"descriptor": setName},
			ScoreDelta: 5,
		})
		return out
	}
	out.decoded = true
	if len(scan.ValueRules) == 0 {
		return out
	}
	fields, repeated := grpcdesc.WalkStringFields(msg, maxGRPCFieldWalkDepth, maxGRPCStringFields)
	out.repeated = repeated
	scans := 0
	hits := 0
	for _, f := range fields {
		if hits >= maxGRPCSensitiveHits || scans >= maxGRPCValueScans {
			break
		}
		// 与 JSON 体同规则：按 json 位置口径筛选规则；证据 location 标 grpc
		if r, ok := matchValueRules(f.Value, "json", scan.ValueRules, &scans); ok {
			evidence := map[string]string{
				"field":      f.Path,
				"data_type":  r.dataType,
				"location":   "grpc",
				"descriptor": setName,
			}
			if r.level != "" {
				evidence["level"] = r.level
			}
			ctx.AddMatch(dsctx.DetectorMatch{
				Detector:   "grpc",
				RuleID:     "grpc.sensitive_field",
				Category:   "OBSERVE",
				Severity:   "MEDIUM",
				Message:    "grpc sensitive field value observed",
				Evidence:   evidence,
				ScoreDelta: 10,
			})
			hits++
		}
	}
	return out
}
