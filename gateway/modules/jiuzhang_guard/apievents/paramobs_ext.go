// paramobs_ext.go 参数值观测统计增强（阶段8 §16/§17 观测上报挂接）：
// 在 detectors.ParamObservation 既有口径上扩展 null 标记 / 字符直方图增量 /
// 前后缀脱敏哈希 / 固定格式样本与候选，供管理面 apiruntime 合并写入
// api_parameter_value_obs 扩展列（迁移 000145），由 apimodels 按窗口重算
// P50-P99/字符熵/前后缀 TopN/离群与格式候选。
//
// 脱敏纪律：扩展字段不含明文值——直方图只落字节计数，前后缀只落 HMAC 截断
// 哈希（口径同 value_hash），格式只落有限枚举；敏感词表命中的参数沿用 detectors
// 抑制结果（base 观测 value_hash 缺省），其值域信息概不出网关。
package apievents

import (
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// ParamObservation 参数值脱敏观测（事件 param_observations 元素，线上契约）：
// 内嵌 detectors.ParamObservation（location/name/path/base_type/length/value_hash/
// num_value 既有口径），扩展字段全部 omitempty——旧版网关上报无这些键，
// 新旧采集端互相容忍（解码忽略未知键、缺省零值）。
type ParamObservation struct {
	detectors.ParamObservation
	// Null 显式 null 值标记（JSON null 字面量；此时 base_type=null，length/value_hash 缺省）。
	Null bool `json:"null,omitempty"`
	// CharHist 字符直方图增量（稀疏桶：字节值十进制串 → 计数，仅非零桶；
	// 单值采样上限 histSampleByteCap 字节），供管理面合并 256 桶直方图重算香农熵。
	CharHist map[string]int64 `json:"char_hist,omitempty"`
	// PrefixHash/SuffixHash 前/后缀脱敏哈希（前/后 affixRuneLen 个字符，HMAC 截断
	// 口径同 value_hash；短值整体哈希，此时与 value_hash 同输入）。仅非敏感非空值产出。
	PrefixHash string `json:"prefix_hash,omitempty"`
	SuffixHash string `json:"suffix_hash,omitempty"`
	// FormatSample 标记一个可计入格式统计分母的非敏感非空字符串样本。
	FormatSample bool `json:"format_sample,omitempty"`
	// FormatCandidate 仅输出固定格式枚举；未知格式保持空串且仍保留 FormatSample。
	FormatCandidate string `json:"format_candidate,omitempty"`
}

// 观测体积约束（防大报文撑爆事件行）：
const (
	// histSampleByteCap 单值直方图采样字节上限。parser 标量值留存本身截断 256 字符，
	// query/path 段值未截断——统一只统计值的前 256 字节：桶数 ≤256、单桶计数 ≤256。
	histSampleByteCap = 256
	// affixRuneLen 前后缀截取字符数（短于该长度取整体）。
	affixRuneLen = 8
	// maxNullObservations 单请求 null 观测上限（与 detectors 观测上限同额 64）。
	maxNullObservations = 64
)

// ExtendParamObservations 在 detectors 基础观测上补挂统计增强字段：
//   - 值派生字段（直方图/前后缀哈希/格式样本）仅对 base 带 value_hash 的观测产出——
//     value_hash 缺省 = 敏感抑制或空值，其值域形态概不出网关；
//   - 格式样本额外要求 base_type=string；未知格式仍计入分母，但 candidate 为空；
//   - 显式 null（parser.JSONFields type=null）补充独立观测元素（base 观测不含 null），
//     供管理面计入 null_count 与样本数（null_rate 口径见迁移 000145 注释）。
//
// 长度/数值样本沿用 base 的 length/num_value 字段（口径即单条样本），不重复扩展。
func ExtendParamObservations(base []detectors.ParamObservation, p *parser.Parsed, salt string) []ParamObservation {
	out := make([]ParamObservation, 0, len(base)+4)
	for _, b := range base {
		out = append(out, ParamObservation{ParamObservation: b})
	}
	if p == nil {
		return out
	}
	type obsKey struct{ loc, name, path string }
	index := make(map[obsKey]int, len(out))
	for i, o := range out {
		index[obsKey{o.Location, o.Name, o.Path}] = i
	}
	extend := func(loc, name, path, value string) {
		if value == "" {
			return
		}
		i, ok := index[obsKey{loc, name, path}]
		if !ok || out[i].ValueHash == "" {
			return // 无对应 base 观测（超上限截断）或敏感抑制/空值：不产出值派生字段
		}
		out[i].CharHist = charHistIncrement(value)
		out[i].PrefixHash = affixHash(salt, value, true)
		out[i].SuffixHash = affixHash(salt, value, false)
		if out[i].BaseType == "string" {
			out[i].FormatSample = true
			out[i].FormatCandidate = detectStringFormat(value)
		}
	}
	// 遍历键与 detectors.CollectParamObservations 同一数据源（按键索引对齐，无需保序）
	for name, v := range p.Query {
		extend("QUERY", name, "", v)
	}
	for path, v := range p.JSONValues {
		extend("BODY", jsonPathLeaf(path), path, v)
	}
	// PATH 对象段：归一化 {id}/{uuid}/{hex} 段取原始段值（同 detectors 口径）
	if p.RawPath != "" && p.NormalizedPath != "" {
		norm := strings.Split(strings.Trim(p.NormalizedPath, "/"), "/")
		raw := strings.Split(strings.Trim(p.RawPath, "/"), "/")
		for i, s := range norm {
			if s != "{id}" && s != "{uuid}" && s != "{hex}" {
				continue
			}
			v := ""
			if i < len(raw) {
				v = raw[i]
			}
			extend("PATH", s, strconv.Itoa(i), v)
		}
	}
	// 显式 null 观测（base 不含 null 元素；排序保证输出确定性）
	nulls := make([]string, 0, 4)
	for path, typ := range p.JSONFields {
		if typ == "null" {
			nulls = append(nulls, path)
		}
	}
	sort.Strings(nulls)
	for _, path := range nulls {
		if len(out) >= len(base)+maxNullObservations {
			break
		}
		k := obsKey{"BODY", jsonPathLeaf(path), path}
		if _, dup := index[k]; dup {
			continue
		}
		index[k] = len(out)
		out = append(out, ParamObservation{
			ParamObservation: detectors.ParamObservation{
				Location: "BODY",
				Name:     jsonPathLeaf(path),
				Path:     path,
				BaseType: "null",
			},
			Null: true,
		})
	}
	return out
}

var (
	canonicalUUIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	emailLocalPattern    = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*$")
	emailDomainPattern   = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	rfc3339Pattern       = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})$`)
)

// detectStringFormat 仅按完整值识别有限固定格式，返回线上枚举而非原值。
func detectStringFormat(value string) string {
	switch {
	case canonicalUUIDPattern.MatchString(value):
		return "UUID"
	case isEmail(value):
		return "EMAIL"
	}
	if addr, err := netip.ParseAddr(value); err == nil && addr.Zone() == "" {
		if addr.Is4() {
			return "IPV4"
		}
		if addr.Is6() {
			return "IPV6"
		}
	}
	if isISODate(value) {
		return "DATE"
	}
	if isRFC3339(value) {
		return "DATETIME"
	}
	return ""
}

// isEmail 接受 ASCII dot-atom 本地部分与 DNS 形域名，拒绝显示名、空白及宽松正则误匹配。
func isEmail(value string) bool {
	if len(value) == 0 || len(value) > 254 {
		return false
	}
	local, domain, ok := strings.Cut(value, "@")
	if !ok || len(local) == 0 || len(local) > 64 || len(domain) == 0 || strings.Contains(domain, "@") {
		return false
	}
	if !emailLocalPattern.MatchString(local) {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if !emailDomainPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func isISODate(value string) bool {
	if len(value) != len("2006-01-02") {
		return false
	}
	_, err := time.Parse("2006-01-02", value)
	return err == nil
}

func isRFC3339(value string) bool {
	if !rfc3339Pattern.MatchString(value) {
		return false
	}
	if _, err := time.Parse(time.RFC3339, value); err != nil {
		return false
	}
	if value[len(value)-1] == 'Z' {
		return true
	}
	offset := value[len(value)-6:]
	hour, _ := strconv.Atoi(offset[1:3])
	minute, _ := strconv.Atoi(offset[4:6])
	return hour <= 23 && minute <= 59
}

// charHistIncrement 单值字符直方图增量（稀疏桶：字节值 → 计数，仅非零桶；
// 只采样值的前 histSampleByteCap 字节）。字节口径与 server 侧 256 桶直方图对齐。
func charHistIncrement(value string) map[string]int64 {
	b := value
	if len(b) > histSampleByteCap {
		b = b[:histSampleByteCap]
	}
	if len(b) == 0 {
		return nil
	}
	hist := make(map[string]int64, 16)
	for i := 0; i < len(b); i++ {
		hist[strconv.Itoa(int(b[i]))]++
	}
	return hist
}

// affixHash 前/后缀脱敏哈希：取前/后 affixRuneLen 个字符（按字符不按字节），
// HMAC 截断口径同 detectors 的 value_hash（Fingerprint 前 8 字节 hex）；空值返回空。
func affixHash(salt, value string, prefix bool) string {
	r := []rune(value)
	if len(r) == 0 {
		return ""
	}
	affix := value
	if len(r) > affixRuneLen {
		if prefix {
			affix = string(r[:affixRuneLen])
		} else {
			affix = string(r[len(r)-affixRuneLen:])
		}
	}
	return detectors.Fingerprint(salt, affix)[:16]
}

// jsonPathLeaf 点路径末段名（与 detectors.pathLeaf 同口径：去 [] 后缀）。
func jsonPathLeaf(path string) string {
	if i := strings.LastIndex(path, "."); i >= 0 {
		path = path[i+1:]
	}
	return strings.TrimSuffix(path, "[]")
}
