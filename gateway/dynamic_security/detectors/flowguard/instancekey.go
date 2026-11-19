// instancekey.go 强流程实例键构造（NG-FLOW-02 §1.2 冻结：实例键 = 应用 + 可信租户
// + 可信主体 + 流程定义版本 + 实例引用；实例引用值经域隔离 HMAC——sflow 独立域，
// 与授权对象引用 objref 域物理区分，跨域不可混用）。
//
// 与 server 侧 server/internal/strongflow/instancekey.go 同算法同输入（线契约）：
// sfref = "sfref:" + hex(HMAC-SHA256(key, domain || message))，HMAC 全量 32 字节。
// message = application_id | 可信租户 | 可信主体 | definition_version | 实例引用值。
// HMAC 密钥复用快照已下发的 object HMAC key（api_authz_object_hmac_key_hex，
// 同 api_authz.object_hmac_key 纪律）；密钥缺席 → 该应用强流程恒 UNKNOWN 放行+披露
// （dependency_unavailable，不阻断——UNKNOWN 恒不阻断红线）。
package flowguard

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"

	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// InstanceRefHMACDomain 实例引用 HMAC 域（版本化；与 server 侧 InstanceRefHMACDomain
// 逐字节一致——独立于 objref 域「jiuzhang-wdsp-authz-objref-v1\x00」，同输入在两域
// 输出必不同）。
const InstanceRefHMACDomain = "jiuzhang-wdsp-strongflow-sfref-v1\x00"

// InstanceRefPrefix 实例引用脱敏形态前缀（独立前缀 sfref:，与 objref: 同纪律）。
const InstanceRefPrefix = "sfref:"

// InstanceID 计算实例键（sfref 脱敏形态；同时用作 Valkey 键 hash tag 内容——
// 全量 64 位小写 hex 无前导歧义，集群同槽安全）。key 缺席（非 32 字节）返回空串，
// 调用方按 UNKNOWN 放行+披露处理（不阻断）。
func InstanceID(key []byte, applicationID, tenant, principal string, definitionVersion int, refValue string) string {
	if len(key) != 32 || refValue == "" {
		return ""
	}
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte(InstanceRefHMACDomain))
	// message = 应用|可信租户|可信主体|definition_version|实例引用值（| 分隔；
	// 各分量内的 | 不转义——分量取值域（UUID/指纹/段值）天然不含结构性歧义可接受，
	// 域隔离 HMAC 保证跨域不可伪造）
	_, _ = m.Write([]byte(applicationID))
	_, _ = m.Write([]byte("|"))
	_, _ = m.Write([]byte(tenant))
	_, _ = m.Write([]byte("|"))
	_, _ = m.Write([]byte(principal))
	_, _ = m.Write([]byte("|"))
	_, _ = m.Write([]byte(strconv.Itoa(definitionVersion)))
	_, _ = m.Write([]byte("|"))
	_, _ = m.Write([]byte(refValue))
	return InstanceRefPrefix + hex.EncodeToString(m.Sum(nil))
}

// ExtractInstanceRef 按定义 instance_key_param 提取实例引用值（批准的参数提取器键
// 两形态，与 server 侧 object_segment 同词表纪律）：
//   - "query:<参数名>"：query 参数值（parsed.Query 已按单值归一）；
//   - "path:<段序>"：原始路径段值——段序为去掉一个前导斜杠后的 0 起段序号
//     （与 server apiassets.derivePathSegments 同口径：/v1/users/{id} 的 {id} 段序为 2；
//     RawPath 与 NormalizedPath 段数一致，位置对齐取原始段值）。
//
// 取不到（参数缺失/段序越界/空值）返回空串——调用方按 UNKNOWN 放行+披露处理，
// 不编造实例归属。
func ExtractInstanceRef(instanceKeyParam string, p *parser.Parsed) string {
	if p == nil {
		return ""
	}
	if name, ok := strings.CutPrefix(instanceKeyParam, "query:"); ok {
		return strings.TrimSpace(p.Query[name])
	}
	if posStr, ok := strings.CutPrefix(instanceKeyParam, "path:"); ok {
		pos, err := strconv.Atoi(strings.TrimSpace(posStr))
		if err != nil || pos < 0 {
			return ""
		}
		segs := normalizer.CanonicalSegments(p.RawPath)
		if pos >= len(segs) {
			return ""
		}
		return segs[pos]
	}
	return ""
}

// 幂等键请求头词表（按优先级序；与 detectors/flow.go idempotencyKeyHeaders
// 同一词表纪律——客户端生成标识，一律哈希后使用，明文不出本包）。
var idempotencyKeyHeaders = []string{"Idempotency-Key", "X-Idempotency-Key"}

// IdempotencyKeyHash 幂等键哈希（sha256 域分隔前缀 + 头值；空 = 请求未携带
// 幂等键——该请求不参与幂等重放/冲突语义，仅占槽）。
func IdempotencyKeyHash(header func(string) string) string {
	for _, h := range idempotencyKeyHeaders {
		if v := strings.TrimSpace(header(h)); v != "" {
			s := sha256.Sum256([]byte("sflow-idem\x00" + v))
			return hex.EncodeToString(s[:])
		}
	}
	return ""
}

// maxParamDigestValueLen 参数摘要单值截断（与 parser 标值留存 256 截断同量纲，
// 防超长值拖慢哈希）。
const maxParamDigestValueLen = 256

// ParamDigest 操作参数摘要（F03：幂等键绑定「实例+步骤+主体+参数摘要 SHA-256」）。
// 输入为解析产物的确定性规范化串行：query / body JSON 标量值（管线已开启
// RetainJSONScalarValues）/ form 标量值（留存开启时）各自排序后拼接；
// 单值截断 256（与 parser 留存截断同界——超出部分本就不可得，摘要不夸大精度）。
// 空输入仍产出合法摘要（空集哈希），保证「同键同摘要」判定确定性。
func ParamDigest(p *parser.Parsed) string {
	h := sha256.New()
	writeSorted := func(tag string, m map[string]string) {
		if len(m) == 0 {
			return
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := m[k]
			if len(v) > maxParamDigestValueLen {
				v = v[:maxParamDigestValueLen]
			}
			_, _ = h.Write([]byte(tag))
			_, _ = h.Write([]byte{0})
			_, _ = h.Write([]byte(k))
			_, _ = h.Write([]byte{0})
			_, _ = h.Write([]byte(v))
			_, _ = h.Write([]byte{0})
		}
	}
	if p != nil {
		writeSorted("q", p.Query)
		writeSorted("j", p.JSONValues)
		writeSorted("f", p.FormValues)
	}
	return hex.EncodeToString(h.Sum(nil))
}
