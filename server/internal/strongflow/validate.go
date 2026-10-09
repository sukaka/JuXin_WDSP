// validate.go 强流程定义校验（§1.1 冻结规则逐条；管理面入库前拒绝的非法配置，
// 网关装配期永远不应再遇到——与网关侧独立校验同口径双保险）。
package strongflow

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

// jsonPathSubset 点路径子集（§1.4 冻结：仅 $.a.b 形态——运行期解析属 FLOW-03，
// 本层只锁形态防止不可解析表达式入库）。
var jsonPathSubset = regexp.MustCompile(`^\$\.[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$`)

// validateDefinitionInput 定义载荷校验（返回首个违规；空串=合法）。
// 逐条映射 §1.1：词表/护栏/步骤集结构/首步唯一最小/parallel_group 相邻。
// 端点归属核对（绑定前缀下已 CONFIRMED）需要数据库，见 store.go activate 路径。
func validateDefinitionInput(in DefinitionInput) string {
	name := strings.TrimSpace(in.Name)
	if name == "" || utf8.RuneCountInString(name) > maxNameLen {
		return "name 必填且不超过 255 字符"
	}
	if !validUUID(in.ApplicationID) {
		return "application_id 非法（UUID）"
	}
	prefix := strings.TrimSpace(in.BindingPathPrefix)
	if prefix == "" || !strings.HasPrefix(prefix, "/") || utf8.RuneCountInString(prefix) > maxBindingPrefixLen {
		return "binding_path_prefix 必填且为 / 开头路径前缀（≤512 字符）"
	}
	param := strings.TrimSpace(in.InstanceKeyParam)
	if !validInstanceKeyParam(param) {
		return "instance_key_param 非法（形态 query:<参数名> 或 path:<段序>——与对象段词表同纪律）"
	}
	mode := strings.ToUpper(strings.TrimSpace(in.Mode))
	if mode != "" && mode != ModeObserve && mode != ModeProtect {
		return "mode 非法（OBSERVE|PROTECT；缺省 OBSERVE）"
	}
	if len(in.Steps) == 0 {
		return ErrNoSteps.Error()
	}
	if len(in.Steps) > maxStepsPerDefinition {
		return invalidf("步骤数超上限 %d", maxStepsPerDefinition).Error()
	}
	return validateSteps(in.Steps)
}

// validInstanceKeyParam 实例引用来源形态（query:<非空名> / path:<非负段序>）。
func validInstanceKeyParam(v string) bool {
	if utf8.RuneCountInString(v) > maxInstanceParamLen {
		return false
	}
	if strings.HasPrefix(v, "query:") {
		name := strings.TrimSpace(strings.TrimPrefix(v, "query:"))
		return name != "" && !strings.ContainsAny(name, " \t\r\n")
	}
	if strings.HasPrefix(v, "path:") {
		pos := strings.TrimSpace(strings.TrimPrefix(v, "path:"))
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

// validateSteps 步骤集结构校验（§1.1 逐条）。
func validateSteps(steps []StepInput) string {
	seenKey := map[string]bool{}
	seenSeq := map[int]bool{}
	minSeq, minCount := 0, 0
	parallelSeqs := map[string][]int{}
	for i, st := range steps {
		key := strings.TrimSpace(st.StepKey)
		if key == "" || utf8.RuneCountInString(key) > maxStepKeyLen {
			return invalidf("steps[%d].step_key 必填且不超过 %d 字符", i, maxStepKeyLen).Error()
		}
		if seenKey[key] {
			return invalidf("step_key %q 重复（定义内唯一）", key).Error()
		}
		seenKey[key] = true
		if st.Sequence < 1 {
			return invalidf("steps[%d].sequence 必须 ≥1", i).Error()
		}
		if seenSeq[st.Sequence] {
			return invalidf("sequence %d 重复（定义内唯一——严格递增即首步唯一最小的承载）", st.Sequence).Error()
		}
		seenSeq[st.Sequence] = true
		if minCount == 0 || st.Sequence < minSeq {
			minSeq, minCount = st.Sequence, 1
		} else if st.Sequence == minSeq {
			minCount++
		}
		if strings.TrimSpace(st.EndpointKey) == "" {
			return invalidf("steps[%d].endpoint_key 必填", i).Error()
		}
		if msg := validateSuccessRule(st.SuccessRule); msg != "" {
			return invalidf("steps[%d].success_rule：%s", i, msg).Error()
		}
		if st.TimeoutSeconds < timeoutMinSeconds || st.TimeoutSeconds > timeoutMaxSeconds {
			return invalidf("steps[%d].timeout_seconds 词表外（%d~%d；词表外拒收不夹紧猜义）", i, timeoutMinSeconds, timeoutMaxSeconds).Error()
		}
		if st.LeaseSeconds < leaseMinSeconds || st.LeaseSeconds > leaseMaxSeconds {
			return invalidf("steps[%d].lease_seconds 词表外（%d~%d；词表外拒收不夹紧猜义）", i, leaseMinSeconds, leaseMaxSeconds).Error()
		}
		rs := strings.ToUpper(strings.TrimSpace(st.RetrySemantics))
		if rs != RetryIdempotent && rs != RetryNotRetryable && rs != RetryRequiresReview {
			return invalidf("steps[%d].retry_semantics 非法（IDEMPOTENT|NOT_RETRYABLE|REQUIRES_REVIEW）", i).Error()
		}
		if utf8.RuneCountInString(st.ParallelGroup) > maxParallelGroupLen {
			return invalidf("steps[%d].parallel_group 超 %d 字符", i, maxParallelGroupLen).Error()
		}
		if g := strings.TrimSpace(st.ParallelGroup); g != "" {
			parallelSeqs[g] = append(parallelSeqs[g], st.Sequence)
		}
	}
	// 首步唯一最小（sequence 最小值恰一步）
	if minCount != 1 {
		return invalidf("首步须唯一（sequence 最小值恰一步；当前最小值 %d 出现 %d 次）", minSeq, minCount).Error()
	}
	// parallel_group 相邻：同组步骤 sequence 连续（排序后相邻差恰 1）
	for g, seqs := range parallelSeqs {
		if len(seqs) < 2 {
			return invalidf("parallel_group %q 仅一步（并行组至少两步；单步请置空串行）", g).Error()
		}
		sortInts(seqs)
		for i := 1; i < len(seqs); i++ {
			if seqs[i]-seqs[i-1] != 1 {
				return invalidf("parallel_group %q 步骤 sequence 不相邻（同组须连续区间）", g).Error()
			}
		}
	}
	return ""
}

// validateSuccessRule 成功判定式校验（白名单键；至少一形态；未知键拒收——
// 未知键在 JSON 解码层经 DisallowUnknownFields 拒绝，此处校验形态与值域）。
func validateSuccessRule(r *SuccessRule) string {
	if r == nil {
		return "必填（无成功判定式的步骤恒 UNKNOWN——判定式必须显式配置，§9.3）"
	}
	has := false
	if len(r.StatusCodes) > 0 {
		has = true
		for _, c := range r.StatusCodes {
			if c < 100 || c > 599 {
				return "status_codes 元素须为合法 HTTP 状态码（100~599）"
			}
		}
	}
	if r.BodyJSONPathEquals != nil {
		has = true
		if !jsonPathSubset.MatchString(r.BodyJSONPathEquals.Path) {
			return invalidf("body_jsonpath_equals.path 形态非法（仅点路径子集 $.a.b；非法形态拒收）").Error()
		}
		if r.BodyJSONPathEquals.Value == nil {
			return "body_jsonpath_equals.value 必填（等值目标）"
		}
	}
	if r.GraphQLErrorsEmpty {
		has = true
	}
	if !has {
		return "至少配置一种成功判定形态（status_codes / body_jsonpath_equals / graphql_errors_empty）"
	}
	return ""
}

func sortInts(v []int) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j] < v[j-1]; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}

func validUUID(v string) bool {
	_, err := uuid.Parse(strings.TrimSpace(v))
	return err == nil
}
