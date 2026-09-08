// relationcheck.go 参数条件关系运行时检测（W11-REL / P0-02 闭环，任务书 §45）：
// 发布通道下发 api_parameter_relations（仅管理面 confirmed 关系），按关系类型做存在性判定：
//
//	REQUIRES：A 存在则 B 必须存在（B 缺失 → schema.relation_requires）；
//	MUTEX / EXCLUDES：A 与 B 互斥（同现 → schema.relation_mutex）；
//	CO_OCCURS：统计共现（单侧出现 → schema.relation_cooccurs，仅 INFO 观察，决策引擎忽略，永不阻断）。
//
// REQUIRES/MUTEX 违例在 PROTECT 升级 BLOCK 类（可定案阻断），OBSERVE/OFF 维持 OBSERVE 级观察
// （与 schema.param_required 的类别语义一致——类别描述违例等级，模式决定是否执行）。
// 证据只含参数名/路径/位置/关系类型，永不写原始值。
package detectors

import (
	"fmt"
	"strings"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// ParamRelationRef 关系一端参数引用（发布通道下发；server apimodels.ParamRelationRef 镜像）。
type ParamRelationRef struct {
	Location string `json:"location"` // QUERY / HEADER / BODY / PATH / COOKIE
	Path     string `json:"path"`     // 结构化路径（BODY 点路径；PATH 可为段序号）
	Name     string `json:"name"`     // 参数名（QUERY/HEADER 键名；BODY 末段名；PATH 占位名）
}

// ParamRelation 已确认参数条件关系（发布通道下发；server apimodels.ParamRelation 镜像）。
type ParamRelation struct {
	EndpointKey  string           `json:"endpoint_key"`  // 作用端点（METHOD + 空格 + 路径模板）
	RelationType string           `json:"relation_type"` // REQUIRES / MUTEX / EXCLUDES / CO_OCCURS
	ParamA       ParamRelationRef `json:"param_a"`
	ParamB       ParamRelationRef `json:"param_b"`
}

// 关系类型词表（与发布侧迁移 000068 CHECK 一致）。
const (
	RelationTypeRequires = "REQUIRES"
	RelationTypeMutex    = "MUTEX"
	// RelationTypeExcludes 历史词表（语义同 MUTEX，按同一互斥检测处理）。
	RelationTypeExcludes = "EXCLUDES"
	RelationTypeCoOccurs = "CO_OCCURS"
)

// GroupParamRelations 按 endpoint_key 归组（装配层一次归组，运行期按端点 O(1) 选取）。
func GroupParamRelations(rels []ParamRelation) map[string][]ParamRelation {
	if len(rels) == 0 {
		return nil
	}
	out := make(map[string][]ParamRelation, len(rels))
	for _, r := range rels {
		out[r.EndpointKey] = append(out[r.EndpointKey], r)
	}
	return out
}

// ValidateParamRelations 配置校验（装配层调用）：端点键/关系类型/参数引用非法如实报错，
// 不静默吞错（配置错误拒绝加载，与 ValidateAuthzRules 同一纪律）。
func ValidateParamRelations(rels []ParamRelation) error {
	for i := range rels {
		r := rels[i]
		if strings.TrimSpace(r.EndpointKey) == "" {
			return &RelationConfigError{Index: i, Reason: "endpoint_key 为空"}
		}
		switch strings.ToUpper(r.RelationType) {
		case RelationTypeRequires, RelationTypeMutex, RelationTypeExcludes, RelationTypeCoOccurs:
		default:
			return &RelationConfigError{Index: i, Reason: "未知 relation_type: " + r.RelationType}
		}
		if strings.TrimSpace(r.ParamA.Name) == "" || strings.TrimSpace(r.ParamB.Name) == "" {
			return &RelationConfigError{Index: i, Reason: "参数引用 name 为空"}
		}
	}
	return nil
}

// RelationConfigError 参数关系配置错误（含序号与原因；不含任何参数值）。
type RelationConfigError struct {
	Index  int
	Reason string
}

func (e *RelationConfigError) Error() string {
	return fmt.Sprintf("api_parameter_relations: 第 %d 条配置非法: %s", e.Index, e.Reason)
}

// CheckParamRelations 按已确认参数条件关系检测请求参数存在性。
// mode 为已解析的防护模式（REQUIRES/MUTEX 违例升级的判定依据；与决策定案同一模式）。
// 证据只写参数名/路径/位置/关系类型，不写值；未知关系类型忽略（读取侧宽容）。
func CheckParamRelations(ctx *dsctx.RequestContext, p *parser.Parsed, rels []ParamRelation, mode decision.Mode) {
	if ctx == nil || p == nil || len(rels) == 0 {
		return
	}
	for i := range rels {
		rel := rels[i]
		aPresent := relationParamPresent(p, rel.ParamA)
		bPresent := relationParamPresent(p, rel.ParamB)
		switch strings.ToUpper(rel.RelationType) {
		case RelationTypeRequires:
			// A 存在要求 B 存在（单向：param_a → param_b）
			if aPresent && !bPresent {
				addRelationViolation(ctx, rel, "schema.relation_requires",
					"required companion parameter missing (REQUIRES relation)", mode)
			}
		case RelationTypeMutex, RelationTypeExcludes:
			// A 与 B 互斥：同现违例
			if aPresent && bPresent {
				addRelationViolation(ctx, rel, "schema.relation_mutex",
					"mutually exclusive parameters co-occur (MUTEX relation)", mode)
			}
		case RelationTypeCoOccurs:
			// 统计共现：单侧出现为偏离；仅 INFO 观察（决策引擎忽略 INFO，永不阻断）
			if aPresent != bPresent {
				ctx.AddMatch(dsctx.DetectorMatch{
					Detector: "api_schema",
					RuleID:   "schema.relation_cooccurs",
					Category: "INFO",
					Severity: "INFO",
					Message:  "co-occurrence relation deviated (observe only)",
					Evidence: relationEvidence(rel),
				})
			}
		default:
			// 未知关系类型忽略（读取侧宽容）
		}
	}
}

// addRelationViolation REQUIRES/MUTEX 违例明细：PROTECT 升级 BLOCK 类（决策引擎可定案阻断），
// OBSERVE/OFF 维持 OBSERVE 级观察；证据只写参数名/路径/位置/关系类型，不写值。
func addRelationViolation(ctx *dsctx.RequestContext, rel ParamRelation, ruleID, message string, mode decision.Mode) {
	if mode == decision.ModeProtect {
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector:   "api_schema",
			RuleID:     ruleID,
			Category:   "BLOCK",
			Severity:   "HIGH",
			Message:    message,
			Evidence:   relationEvidence(rel),
			ScoreDelta: 40,
		})
		return
	}
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector:   "api_schema",
		RuleID:     ruleID,
		Category:   "OBSERVE",
		Severity:   "MEDIUM",
		Message:    message,
		Evidence:   relationEvidence(rel),
		ScoreDelta: 15,
	})
}

// relationEvidence 关系证据：只含关系类型与两端参数标识（位置+名/路径），不落值。
func relationEvidence(rel ParamRelation) map[string]string {
	return map[string]string{
		"relation_type": strings.ToUpper(rel.RelationType),
		"param_a":       relationParamLabel(rel.ParamA),
		"param_b":       relationParamLabel(rel.ParamB),
	}
}

// relationParamLabel 参数标识（LOCATION:name 形态；BODY 带结构化路径时用路径）。
func relationParamLabel(ref ParamRelationRef) string {
	loc := strings.ToUpper(ref.Location)
	name := ref.Name
	if loc == "BODY" && ref.Path != "" {
		name = ref.Path
	}
	return loc + ":" + name
}

// relationParamPresent 关系一端参数的存在性判定（与 CheckParamConstraints 的位置语义一致；
// 仅看存在性，不取值——脱敏头/cookie 仅存在性可用）。
func relationParamPresent(p *parser.Parsed, ref ParamRelationRef) bool {
	switch strings.ToUpper(ref.Location) {
	case "QUERY":
		_, ok := p.Query[ref.Name]
		return ok
	case "HEADER":
		_, ok := p.Headers[strings.ToLower(ref.Name)]
		return ok
	case "BODY":
		path := ref.Path
		if path == "" {
			path = ref.Name
		}
		_, ok := p.JSONFields[path]
		return ok
	case "PATH":
		// PATH：按归一化段占位名（{id}/{uuid}/{hex}）或段序号匹配（复用 schema.go 同包实现）
		_, ok := pathSegmentValue(p, ref.Name, ref.Path)
		return ok
	case "COOKIE":
		// Cookie 整头脱敏：仅能做粗粒度存在性（cookie 头存在即视为存在）
		return p.Headers["cookie"] == "[redacted]"
	default:
		return false
	}
}
