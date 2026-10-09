// validate.go 强流程定义校验（§1.1 冻结规则逐条；与 server 侧管理面
// server/internal/strongflow/validate.go 同词表同边界双保险——管理面入库前
// 拒绝的非法配置网关装配期永远不应再遇到，遇到即快照异常 fail-closed 拒载）。
//
// 逐条映射：
//   - step_key 定义内唯一（必填 ≤128 字符）；
//   - sequence 单调：≥1 且定义内唯一（严格递增即首步唯一最小的承载，
//     server 侧 UNIQUE(definition_id, sequence) 同约束）；
//   - 首步唯一最小：sequence 最小值恰一步（唯一性承载 + minCount 显式复核）；
//   - success_rule 三形态词表（状态码集合 100~599 / body JSONPath 受限子集
//     等值——仅点路径+等值 / GraphQL errors 为空，可组合与；白名单键未知拒收；
//     至少一形态；判定式必填——无配置步骤恒 UNKNOWN 不产出 CONFIRMED，§9.3/D4）；
//   - parallel_group 内步骤 sequence 相邻（同组排序后连续区间；单步组拒收，
//     单步请置空串行）；
//   - timeout_seconds 15~600 / lease_seconds 15~300 夹紧区间，越界拒收
//     （词表外拒收不夹紧猜义，server 应用层 400 + 库层 CHECK 同边界）；
//   - retry_semantics 词表 IDEMPOTENT|NOT_RETRYABLE|REQUIRES_REVIEW（必填）；
//   - mode 词表 OBSERVE|PROTECT（缺省 OBSERVE）；
//   - status 词表 ACTIVE|RETIRED（缺省归一 ACTIVE；联调裁决 §8.4-1 育龄窗——
//     存在非终态实例的 RETIRED 版本随发布面下发供存量实例续跑；DRAFT 出现即
//     快照异常拒载）；
//   - 端点归属核对（endpoint_key 须属绑定前缀下已 CONFIRMED 端点）需管理面
//     端点清单，属 server 侧 activate 路径职责，网关不重复核对。
package flowguard

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// jsonPathSubset 点路径受限子集（§1.4 冻结：仅 $.a.b 点路径形态；
// 与 server 侧同一正则。运行期求值属 FLOW-03，本批只锁形态防止
// 不可解析表达式进入装配产物）。
var jsonPathSubset = regexp.MustCompile(`^\$\.[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$`)

// ConfigError 强流程定义配置错误（装配层校验失败如实报错，拒绝加载，不静默吞错；
// 与 detectors.FlowConfigError 同一形态）。
type ConfigError struct {
	Index  int    // 定义在切片中的下标
	Reason string // 失败原因
}

func (e *ConfigError) Error() string {
	return fmt.Sprintf("strong flow definition[%d]: %s", e.Index, e.Reason)
}

// ValidateDefinitions 定义集校验（装配层调用）：§1.1 冻结规则逐条，
// 返回首个违规；nil/空输入 = 无定义，零行为不报错。
func ValidateDefinitions(defs []Definition) error {
	for i := range defs {
		if err := validateDefinition(&defs[i]); err != nil {
			return &ConfigError{Index: i, Reason: err.Error()}
		}
	}
	return nil
}

// validateDefinition 单定义校验（返回首个违规）。
func validateDefinition(d *Definition) error {
	if strings.TrimSpace(d.ID) == "" {
		return fmt.Errorf("id 必填")
	}
	if strings.TrimSpace(d.ApplicationID) == "" {
		return fmt.Errorf("application_id 必填")
	}
	name := strings.TrimSpace(d.Name)
	if name == "" || utf8.RuneCountInString(name) > maxNameLen {
		return fmt.Errorf("name 必填且不超过 %d 字符", maxNameLen)
	}
	if d.Version < 1 {
		return fmt.Errorf("version 必须 ≥1（单调递增，激活即冻结）")
	}
	if d.Status != "" && d.Status != StatusActive && d.Status != StatusRetired {
		return fmt.Errorf("status 非法（发布面词表 ACTIVE|RETIRED，got %q；DRAFT 出现即快照异常——育龄窗 RETIRED 随发布面下发供存量实例续跑，§8.4-1 裁决）", d.Status)
	}
	prefix := strings.TrimSpace(d.BindingPathPrefix)
	if prefix == "" || !strings.HasPrefix(prefix, "/") || utf8.RuneCountInString(prefix) > maxBindingPrefixLen {
		return fmt.Errorf("binding_path_prefix 必填且为 / 开头路径前缀（≤%d 字符）", maxBindingPrefixLen)
	}
	if !validInstanceKeyParam(strings.TrimSpace(d.InstanceKeyParam)) {
		return fmt.Errorf("instance_key_param 非法（形态 query:<参数名> 或 path:<段序>——与对象段词表同纪律）")
	}
	if d.Mode != "" && d.Mode != ModeObserve && d.Mode != ModeProtect {
		return fmt.Errorf("mode 非法（OBSERVE|PROTECT；缺省 OBSERVE）")
	}
	if len(d.Steps) == 0 {
		return fmt.Errorf("定义至少包含一个步骤")
	}
	if len(d.Steps) > MaxStepsPerDefinition {
		return fmt.Errorf("步骤数超上限 %d", MaxStepsPerDefinition)
	}
	return validateSteps(d.Steps)
}

// validInstanceKeyParam 实例引用来源形态（query:<非空名> / path:<非负段序>；
// 与 server 侧 validInstanceKeyParam 同口径）。
func validInstanceKeyParam(v string) bool {
	if v == "" || utf8.RuneCountInString(v) > maxInstanceParamLen {
		return false
	}
	if rest, ok := strings.CutPrefix(v, "query:"); ok {
		name := strings.TrimSpace(rest)
		return name != "" && !strings.ContainsAny(name, " \t\r\n")
	}
	if rest, ok := strings.CutPrefix(v, "path:"); ok {
		pos := strings.TrimSpace(rest)
		if pos == "" {
			return false
		}
		for _, c := range pos {
			if c < '0' || c > '9' {
				return false
			}
		}
		return true
	}
	return false
}

// validateSteps 步骤集结构校验（§1.1 逐条；与 server 侧 validateSteps 同口径）。
func validateSteps(steps []Step) error {
	seenKey := make(map[string]bool, len(steps))
	seenSeq := make(map[int]bool, len(steps))
	minSeq, minCount := 0, 0
	parallelSeqs := map[string][]int{}
	for i, st := range steps {
		key := strings.TrimSpace(st.StepKey)
		if key == "" || utf8.RuneCountInString(key) > maxStepKeyLen {
			return fmt.Errorf("steps[%d].step_key 必填且不超过 %d 字符", i, maxStepKeyLen)
		}
		// step_key 进入 Valkey 键形（sflow:v1:{...}:step:<step_key>，FLOW-02）：
		// 大括号会破坏集群 hash tag 同槽语义，装配期拒收（网关侧加固，hash tag 安全）
		if strings.ContainsAny(key, "{}") {
			return fmt.Errorf("steps[%d].step_key 含大括号（Valkey hash tag 安全拒收）", i)
		}
		if seenKey[key] {
			return fmt.Errorf("step_key %q 重复（定义内唯一）", key)
		}
		seenKey[key] = true
		if st.Sequence < 1 {
			return fmt.Errorf("steps[%d].sequence 必须 ≥1", i)
		}
		if seenSeq[st.Sequence] {
			return fmt.Errorf("sequence %d 重复（定义内唯一——严格递增即首步唯一最小的承载）", st.Sequence)
		}
		seenSeq[st.Sequence] = true
		if minCount == 0 || st.Sequence < minSeq {
			minSeq, minCount = st.Sequence, 1
		} else if st.Sequence == minSeq {
			minCount++
		}
		ek := strings.TrimSpace(st.EndpointKey)
		if ek == "" || utf8.RuneCountInString(ek) > maxEndpointKeyLen {
			return fmt.Errorf("steps[%d].endpoint_key 必填且不超过 %d 字符", i, maxEndpointKeyLen)
		}
		if err := validateSuccessRule(st.SuccessRule); err != nil {
			return fmt.Errorf("steps[%d].success_rule：%s", i, err)
		}
		if st.TimeoutSeconds < TimeoutSecondsMin || st.TimeoutSeconds > TimeoutSecondsMax {
			return fmt.Errorf("steps[%d].timeout_seconds 词表外（%d~%d；词表外拒收不夹紧猜义）", i, TimeoutSecondsMin, TimeoutSecondsMax)
		}
		if st.LeaseSeconds < LeaseSecondsMin || st.LeaseSeconds > LeaseSecondsMax {
			return fmt.Errorf("steps[%d].lease_seconds 词表外（%d~%d；词表外拒收不夹紧猜义）", i, LeaseSecondsMin, LeaseSecondsMax)
		}
		switch st.RetrySemantics {
		case RetryIdempotent, RetryNotRetryable, RetryRequiresReview:
		default:
			return fmt.Errorf("steps[%d].retry_semantics 非法（IDEMPOTENT|NOT_RETRYABLE|REQUIRES_REVIEW）", i)
		}
		if utf8.RuneCountInString(st.ParallelGroup) > maxParallelGroupLen {
			return fmt.Errorf("steps[%d].parallel_group 超 %d 字符", i, maxParallelGroupLen)
		}
		if g := strings.TrimSpace(st.ParallelGroup); g != "" {
			parallelSeqs[g] = append(parallelSeqs[g], st.Sequence)
		}
	}
	// 首步唯一最小（sequence 最小值恰一步；唯一性承载之上的显式复核）
	if minCount != 1 {
		return fmt.Errorf("首步须唯一（sequence 最小值恰一步；当前最小值 %d 出现 %d 次）", minSeq, minCount)
	}
	// parallel_group 相邻：同组步骤 sequence 连续（排序后相邻差恰 1）
	for g, seqs := range parallelSeqs {
		if len(seqs) < 2 {
			return fmt.Errorf("parallel_group %q 仅一步（并行组至少两步；单步请置空串行）", g)
		}
		sort.Ints(seqs)
		for i := 1; i < len(seqs); i++ {
			if seqs[i]-seqs[i-1] != 1 {
				return fmt.Errorf("parallel_group %q 步骤 sequence 不相邻（同组须连续区间）", g)
			}
		}
	}
	return nil
}

// validateSuccessRule 成功判定式词表与形态校验（严格解码白名单键；
// 判定式必填且至少一形态；运行期求值属 FLOW-03）。
func validateSuccessRule(raw json.RawMessage) error {
	rule, err := ParseSuccessRule(raw)
	if err != nil {
		return err
	}
	if rule == nil {
		return fmt.Errorf("必填（无成功判定式的步骤恒 UNKNOWN——判定式必须显式配置，§9.3）")
	}
	has := false
	if len(rule.StatusCodes) > 0 {
		has = true
		for _, c := range rule.StatusCodes {
			if c < 100 || c > 599 {
				return fmt.Errorf("status_codes 元素须为合法 HTTP 状态码（100~599）")
			}
		}
	}
	if rule.BodyJSONPathEquals != nil {
		has = true
		if !jsonPathSubset.MatchString(rule.BodyJSONPathEquals.Path) {
			return fmt.Errorf("body_jsonpath_equals.path 形态非法（仅点路径子集 $.a.b；非法形态拒收）")
		}
		if rule.BodyJSONPathEquals.Value == nil {
			return fmt.Errorf("body_jsonpath_equals.value 必填（等值目标）")
		}
	}
	if rule.GraphQLErrorsEmpty {
		has = true
	}
	if !has {
		return fmt.Errorf("至少配置一种成功判定形态（status_codes / body_jsonpath_equals / graphql_errors_empty）")
	}
	return nil
}
