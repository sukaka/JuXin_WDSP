// contextfields.go 统一上下文 §7 字段产出：device_fingerprint（被动客户端指纹）与
// object_identifiers（对象标识哈希）。纯函数、热路径零网络 IO、开销有界
// （定长 HMAC + 条数/值长双封顶）。
package parser

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// identityDomainPrefix 与 detectors.Fingerprint 缺盐时的固定域分隔前缀完全一致。
// 重复原因：detectors 包依赖 parser（detectors→parser），parser 不能反向 import
// 形成环；identitybehavior 位于上层 jiuzhang_guard 模块同样不可达。故 HMAC 构造
// 在此按同一算法重复实现，跨模块一致性由 jiuzhang_guard 侧对拍测试锁定。
const identityDomainPrefix = "jiuzhang/wdsp-identity-fingerprint/v1"

// fingerprint 与 detectors.Fingerprint 同一构造：HMAC-SHA256(key=salt, v)
// 截断前 16 字节 hex（32 字符）；salt 为空走固定域分隔前缀（未加盐，仅域分隔）。
func fingerprint(salt, v string) string {
	key := salt
	if key == "" {
		key = identityDomainPrefix
	}
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(v))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

// fingerprintParts 与 identitybehavior.fingerprintParts 同一构造：每段 4 字节
// 大端长度前缀 + 原文拼接后统一 fingerprint（防分段歧义拼接碰撞）。
func fingerprintParts(salt string, parts ...string) string {
	var sb strings.Builder
	for _, p := range parts {
		var lb [4]byte
		binary.BigEndian.PutUint32(lb[:], uint32(len(p)))
		sb.Write(lb[:])
		sb.WriteString(p)
	}
	return fingerprint(salt, sb.String())
}

// DeriveDeviceFingerprint 纯被动设备指纹（任务书 §7 device_fingerprint）：
// UA/Accept-Language/Accept-Encoding/Accept 四头经 fingerprintParts("br", ...) 哈希，
// 与 identitybehavior.BrowserFingerprint 同口径同构造（同输入同盐输出逐字节一致，
// 对拍测试见 jiuzhang_guard.apicontext 测试）。纯被动口径：不做客户端采集
// （无 JS/Canvas/主动探测），不伪装成设备唯一标识。
//
// 粒度限制：UA 族头是低熵群体特征——同型号浏览器 + 同语言/编码环境的大量客户端
// 共享同一指纹，仅适合群体级关联与异常对照，不得作为封禁/归因的唯一依据。
// UA 为空时返回空串（与 identitybehavior 一致：无 UA 不产出指纹）。
func DeriveDeviceFingerprint(salt string, h http.Header) string {
	ua := h.Get("User-Agent")
	if ua == "" {
		return ""
	}
	return fingerprintParts(salt, "br",
		ua, h.Get("Accept-Language"), h.Get("Accept-Encoding"), h.Get("Accept"))
}

// maxObjectIDValueLen 参与哈希的对象标识原始值长度上限：超长值非典型对象标识
// （更可能是内容载荷），跳过以保持哈希前输入有界、热路径开销可控。
const maxObjectIDValueLen = 128

// bodyPrimaryKeyExact 请求体主键字段名精确集合（末段、小写）。
var bodyPrimaryKeyExact = map[string]struct{}{
	"id": {}, "uuid": {}, "guid": {},
}

// placeholderName 归一化路径段为模板占位符时返回占位符名（{id}→id）；否则 ok=false。
func placeholderName(seg string) (string, bool) {
	if len(seg) > 2 && seg[0] == '{' && seg[len(seg)-1] == '}' {
		return seg[1 : len(seg)-1], true
	}
	return "", false
}

// bodyPrimaryKeyName 判断 body 字段路径末段是否为主键形态：精确集合（id/uuid/guid）
// 或 *_id 后缀（user_id/order_id 等）。数组段标记 [] 先剥离。
func bodyPrimaryKeyName(fieldPath string) bool {
	name := fieldPath
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		name = name[i+1:]
	}
	name = strings.TrimSuffix(name, "[]")
	name = strings.ToLower(name)
	if _, ok := bodyPrimaryKeyExact[name]; ok {
		return true
	}
	return strings.HasSuffix(name, "_id")
}

// ExtractObjectIdentifiers 从解析产物提取对象标识（任务书 §7 object_identifiers）：
//   - path：归一化模板位置参数（{id}/{uuid}/{hex} 段）对应的原始路径段值；
//   - body_json / body_form：请求体主键字段（末段 id/uuid/guid 或 *_id）的标量值
//     （标量值留存仅在管线开启时存在，未留存时零产出零变化）。
//
// 只记哈希不落明文：值经 fingerprintParts("obj", value) HMAC 后入库，原始值不出
// 本函数。条数封顶 dsctx.MaxObjectIdentifiers，单值封顶 maxObjectIDValueLen，
// 输出按来源内确定性顺序（body 按键名排序），同 (source, param, hash) 去重。
func ExtractObjectIdentifiers(p *Parsed, salt string) []dsctx.ObjectIdentifier {
	if p == nil {
		return nil
	}
	out := make([]dsctx.ObjectIdentifier, 0, 4)
	seen := make(map[string]struct{}, 8)
	add := func(source, param, raw string) {
		if len(out) >= dsctx.MaxObjectIdentifiers || raw == "" || len(raw) > maxObjectIDValueLen {
			return
		}
		h := fingerprintParts(salt, "obj", raw)
		key := source + "\x00" + param + "\x00" + h
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		out = append(out, dsctx.ObjectIdentifier{Source: source, Param: param, ValueHash: h})
	}
	// 路径位置参数：模板段与原始段逐位对齐（NormalizePath 不改段数，仅替换段文本）
	rawSegs := strings.Split(strings.Trim(p.RawPath, "/"), "/")
	normSegs := strings.Split(strings.Trim(p.NormalizedPath, "/"), "/")
	for i, ns := range normSegs {
		if i >= len(rawSegs) {
			break
		}
		name, ok := placeholderName(ns)
		if !ok {
			continue
		}
		add("path", name, rawSegs[i])
	}
	// body 主键字段（确定性顺序：键名排序）
	for _, body := range []struct {
		source string
		values map[string]string
	}{
		{"body_json", p.JSONValues},
		{"body_form", p.FormValues},
	} {
		sorted := make([]string, 0, len(body.values))
		for k := range body.values {
			sorted = append(sorted, k)
		}
		sort.Strings(sorted)
		for _, k := range sorted {
			if bodyPrimaryKeyName(k) {
				add(body.source, k, body.values[k])
			}
		}
	}
	return out
}
