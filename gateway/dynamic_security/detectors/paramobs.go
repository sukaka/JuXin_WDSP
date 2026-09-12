package detectors

import (
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// ParamObservation 参数值观测事实（脱敏）：只含形态统计，永不含明文值。
// 经运行时事件 JSONL 上报管理面，用于回填 api_parameter_statistics 长度/值域/基数。
type ParamObservation struct {
	Location  string   `json:"location"`            // QUERY / HEADER / BODY / PATH / COOKIE
	Name      string   `json:"name"`                // 参数名或末段名
	Path      string   `json:"path,omitempty"`      // BODY 点路径
	BaseType  string   `json:"base_type"`           // string|number|bool
	Length    int      `json:"length"`              // 字符数（非字节）
	ValueHash string   `json:"value_hash"`          // HMAC-SHA256（盐 identity_salt）截断 16 hex，供 distinct 估计
	NumValue  *float64 `json:"num_value,omitempty"` // 仅 number 类型；用于 min/max 聚合
}

// 单请求观测上限，防止大报文撑爆事件行。
const maxParamObservations = 64

// CollectParamObservations 从解析结果提取脱敏观测（QUERY/BODY 标量 + PATH 对象段）。
// HEADER 中 authorization/cookie/x-api-key 已脱敏，跳过；其余头默认不观测（噪声大）。
// COOKIE 解析值不可得（整头脱敏），跳过。
//
// 兼容入口：等价于 CollectParamObservationsSecure(p, "", nil, nil)——未加盐
// （固定域分隔前缀，缺盐纪律同 fingerprint.go）且不做敏感命中抑制；
// 新接入方应传入 identity_salt 与敏感词表编译产物（调用约定见 Secure 版注释）。
func CollectParamObservations(p *parser.Parsed) []ParamObservation {
	return CollectParamObservationsSecure(p, "", nil, nil)
}

// CollectParamObservationsSecure 隐私增强版参数观测（隐私修复）：
//   - salt：identity_salt（与 Fingerprint 同一盐源；空 = 固定域分隔前缀，未加盐，
//     跨部署可复现仅作域分隔——缺盐行为与 fingerprint.go 现有纪律一致）；
//   - namePatterns/valueRules：敏感检测同一编译产物（装配层 CompileSensitivePatterns/
//     CompileSensitiveValueRules 产出，缓存命中零重复编译）。命中敏感词表
//     （键名或值级规则）的参数不上报 NumValue/ValueHash，仅保留长度/类型形态统计。
//
// 调用约定：观测在管线敏感检测（Process 内 CheckSensitiveData）之后由挂点侧触发，
// 跨包复用检测结果不便，此处对敏感词表做最小复判（与敏感检测同一词表/规则产物）。
func CollectParamObservationsSecure(p *parser.Parsed, salt string, namePatterns []CompiledSensitivePattern, valueRules []CompiledSensitiveValueRule) []ParamObservation {
	if p == nil {
		return nil
	}
	st := &paramObsState{salt: salt, namePatterns: namePatterns, valueRules: valueRules}
	out := make([]ParamObservation, 0, 16)
	// QUERY
	if len(p.Query) > 0 {
		names := make([]string, 0, len(p.Query))
		for n := range p.Query {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			if len(out) >= maxParamObservations {
				return out
			}
			out = append(out, st.observeScalar("QUERY", name, "", p.Query[name]))
		}
	}
	// BODY 标量（JSONValues：仅 RetainJSONScalarValues 时有值；否则用 JSONFields 只记类型无长度）
	if len(p.JSONValues) > 0 {
		paths := make([]string, 0, len(p.JSONValues))
		for path := range p.JSONValues {
			paths = append(paths, path)
		}
		sort.Strings(paths)
		for _, path := range paths {
			if len(out) >= maxParamObservations {
				return out
			}
			name := pathLeaf(path)
			typ := p.JSONFields[path]
			if typ == "" {
				typ = "string"
			}
			obs := st.observeScalar("BODY", name, path, p.JSONValues[path])
			if typ == "number" || typ == "bool" {
				obs.BaseType = typ
			}
			out = append(out, obs)
		}
	} else if len(p.JSONFields) > 0 {
		// 无标量值时只上报字段存在与类型（length=0, hash 空）——仍可用于 required/类型学习触发
		paths := make([]string, 0, len(p.JSONFields))
		for path, typ := range p.JSONFields {
			if typ == "object" || typ == "array" || typ == "null" {
				continue
			}
			paths = append(paths, path)
		}
		sort.Strings(paths)
		for _, path := range paths {
			if len(out) >= maxParamObservations {
				return out
			}
			out = append(out, ParamObservation{
				Location: "BODY",
				Name:     pathLeaf(path),
				Path:     path,
				BaseType: p.JSONFields[path],
			})
		}
	}
	// PATH 对象段：长度与 hash 来自原始路径段
	if p.RawPath != "" && p.NormalizedPath != "" {
		norm := strings.Split(strings.Trim(p.NormalizedPath, "/"), "/")
		raw := strings.Split(strings.Trim(p.RawPath, "/"), "/")
		for i, s := range norm {
			if s != "{id}" && s != "{uuid}" && s != "{hex}" {
				continue
			}
			if len(out) >= maxParamObservations {
				return out
			}
			val := ""
			if i < len(raw) {
				val = raw[i]
			}
			out = append(out, st.observeScalar("PATH", s, strconv.Itoa(i), val))
		}
	}
	return out
}

// paramObsState 单次观测的隐私输入与值级复判状态。
type paramObsState struct {
	salt         string
	namePatterns []CompiledSensitivePattern
	valueRules   []CompiledSensitiveValueRule
	scans        int // 值级复判求值计数（与敏感检测同一上限纪律，见 matchValueRules）
}

// paramObsValueLocations 观测位置到值级规则位置词表的映射
// （HEADER/COOKIE 不观测，无需映射）。
var paramObsValueLocations = map[string]string{"QUERY": "query", "BODY": "json", "PATH": "path"}

func pathLeaf(path string) string {
	if i := strings.LastIndex(path, "."); i >= 0 {
		path = path[i+1:]
	}
	return strings.TrimSuffix(path, "[]")
}

// observeScalar 构造标量观测：敏感命中（键名/值级）时抑制 NumValue/ValueHash，
// 仅保留长度/类型形态统计（敏感参数的值域信息概不出网关）。
func (st *paramObsState) observeScalar(location, name, path, value string) ParamObservation {
	obs := ParamObservation{
		Location: location,
		Name:     name,
		Path:     path,
		BaseType: "string",
		Length:   utf8.RuneCountInString(value),
	}
	// 尝试 number/bool（抑制时数值本体同样不回传）
	if f, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err == nil && value != "" {
		obs.BaseType = "number"
		obs.NumValue = &f
	} else if value == "true" || value == "false" {
		obs.BaseType = "bool"
	}
	if st.sensitiveHit(location, name, path, value) {
		obs.ValueHash, obs.NumValue = "", nil
		return obs
	}
	if value != "" {
		obs.ValueHash = paramValueHash(st.salt, value)
	}
	return obs
}

// sensitiveHit 敏感最小复判：键名命中字段名词表（BODY 以结构化全路径为键名，
// 与敏感检测 scanFieldNames 同一口径，词表子串正则同样覆盖末段名）或值命中值级规则。
func (st *paramObsState) sensitiveHit(location, name, path, value string) bool {
	if len(st.namePatterns) == 0 && len(st.valueRules) == 0 {
		return false
	}
	key := name
	if location == "BODY" && path != "" {
		key = path
	}
	if _, ok := matchSensitive(key, st.namePatterns); ok {
		return true
	}
	loc, ok := paramObsValueLocations[location]
	if !ok || value == "" {
		return false
	}
	_, hit := matchValueRules(value, loc, st.valueRules, &st.scans)
	return hit
}

// paramValueHash 参数值脱敏哈希：HMAC-SHA256(key=salt, value) 前 8 字节 hex（16 字符，
// 与原无盐 SHA-256 截断格式一致）；与 Fingerprint 同一实现，盐空走固定域分隔前缀。
func paramValueHash(salt, value string) string {
	return Fingerprint(salt, value)[:16] // Fingerprint 输出 16 字节 hex（32 字符），取前 8 字节
}
