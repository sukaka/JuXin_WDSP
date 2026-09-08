package jwtverify

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// tokenError 解析/格式错误，携带映射到冻结契约的 reason_code。
type tokenError struct {
	reason ReasonCode
	msg    string
}

func (e *tokenError) Error() string { return fmt.Sprintf("jwtverify: %s: %s", e.reason, e.msg) }

func tokErr(reason ReasonCode, msg string) *tokenError {
	return &tokenError{reason: reason, msg: msg}
}

// tokenCharset 允许的 compact JWS 字符集（base64url + 段分隔符）。
const tokenCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_."

// extractBearer 从 Authorization 头值集合中提取唯一 Bearer Token。
// 重复 Authorization、多 Token、错误 Bearer 格式均有界拒绝（MALFORMED_TOKEN）。
// 返回值 present=false 表示完全没有 Authorization 头（非错误）。
func extractBearer(values []string) (token string, present bool, err error) {
	if len(values) == 0 {
		return "", false, nil
	}
	if len(values) > 1 {
		return "", false, tokErr(ReasonMalformedToken, "重复 Authorization 头")
	}
	fields := strings.Fields(values[0])
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
		return "", false, tokErr(ReasonMalformedToken, "Bearer 格式错误")
	}
	token = fields[1]
	if len(token) > MaxTokenBytes {
		return "", false, tokErr(ReasonMalformedToken, "Token 超过 16KiB 上限")
	}
	if strings.ContainsAny(token, ", ") || strings.IndexFunc(token, func(r rune) bool {
		return !strings.ContainsRune(tokenCharset, r)
	}) >= 0 {
		return "", false, tokErr(ReasonMalformedToken, "Token 含非法字符")
	}
	return token, true, nil
}

// parsedToken 严格解析后的 JWS/JWT 结构；claims 尚未验签，不得信任。
type parsedToken struct {
	raw     string
	alg     string
	kid     string
	header  map[string]json.RawMessage
	claims  *tokenClaims
	payload []byte
}

// tokenClaims 严格解析后的声明子集；raw 保留以支持配置的 tenant_claim。
type tokenClaims struct {
	issuer       string
	hasIssuer    bool
	subject      string
	hasSubject   bool
	audiences    []string
	hasAudiences bool
	expiry       time.Time
	hasExpiry    bool
	notBefore    time.Time
	hasNotBefore bool
	raw          map[string]json.RawMessage
}

// parseTokenStrict 严格解析 compact JWS：段数、尺寸、base64url、重复 JSON 键、
// header/claims 类型全部校验。失败均映射 MALFORMED_TOKEN 或 ALGORITHM_REJECTED。
func parseTokenStrict(token string) (*parsedToken, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, tokErr(ReasonMalformedToken, "JWT 段数错误（须为 3 段 compact JWS）")
	}
	for _, p := range parts {
		if p == "" {
			return nil, tokErr(ReasonMalformedToken, "JWT 存在空段")
		}
	}
	headerRaw, err := decodeSegment(parts[0])
	if err != nil {
		return nil, tokErr(ReasonMalformedToken, "header base64url 解码失败")
	}
	payloadRaw, err := decodeSegment(parts[1])
	if err != nil {
		return nil, tokErr(ReasonMalformedToken, "payload base64url 解码失败")
	}
	header, err := strictJSONObject(headerRaw)
	if err != nil {
		return nil, tokErr(ReasonMalformedToken, "header JSON 非法: "+err.Error())
	}
	alg, err := requiredString(header, "alg")
	if err != nil {
		return nil, tokErr(ReasonMalformedToken, "header 缺合法 alg")
	}
	kid, err := requiredString(header, "kid")
	if err != nil {
		return nil, tokErr(ReasonMalformedToken, "header 缺合法 kid")
	}
	if len(kid) > MaxKidBytes {
		return nil, tokErr(ReasonMalformedToken, "kid 超过 256 字节上限")
	}
	// crit：本实现不支持任何 critical 扩展，出现即拒绝。
	if _, hasCrit := header["crit"]; hasCrit {
		return nil, tokErr(ReasonMalformedToken, "含未知 critical header")
	}
	// 嵌入式 jwk 不得作为信任来源；jku/x5u 仅忽略、绝不解引用（见 JWT-09）。
	claims, err := parseClaimsStrict(payloadRaw)
	if err != nil {
		return nil, err
	}
	return &parsedToken{
		raw:     token,
		alg:     alg,
		kid:     kid,
		header:  header,
		claims:  claims,
		payload: payloadRaw,
	}, nil
}

func decodeSegment(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func requiredString(m map[string]json.RawMessage, key string) (string, error) {
	raw, ok := m[key]
	if !ok {
		return "", errors.New("缺字段 " + key)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("字段 %s 类型非法", key)
	}
	if s == "" {
		return "", fmt.Errorf("字段 %s 为空", key)
	}
	return s, nil
}

// parseClaimsStrict 严格解析 claims：iss/sub 为字符串；aud 仅合法字符串或
// 非空字符串数组；exp/nbf 为 NumericDate（严格数字解析，拒绝弱类型与溢出）。
func parseClaimsStrict(payload []byte) (*tokenClaims, error) {
	m, err := strictJSONObject(payload)
	if err != nil {
		return nil, tokErr(ReasonMalformedToken, "payload JSON 非法: "+err.Error())
	}
	c := &tokenClaims{raw: m}
	if raw, ok := m["iss"]; ok {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, tokErr(ReasonMalformedToken, "iss 类型非法")
		}
		c.issuer, c.hasIssuer = s, true
	}
	if raw, ok := m["sub"]; ok {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, tokErr(ReasonMalformedToken, "sub 类型非法")
		}
		c.subject, c.hasSubject = s, true
	}
	if raw, ok := m["aud"]; ok {
		auds, err := parseAudience(raw)
		if err != nil {
			return nil, err
		}
		c.audiences, c.hasAudiences = auds, true
	}
	if raw, ok := m["exp"]; ok {
		t, err := parseNumericDate(raw)
		if err != nil {
			return nil, tokErr(ReasonMalformedToken, "exp 非合法 NumericDate")
		}
		c.expiry, c.hasExpiry = t, true
	}
	if raw, ok := m["nbf"]; ok {
		t, err := parseNumericDate(raw)
		if err != nil {
			return nil, tokErr(ReasonMalformedToken, "nbf 非合法 NumericDate")
		}
		c.notBefore, c.hasNotBefore = t, true
	}
	return c, nil
}

func parseAudience(raw json.RawMessage) ([]string, error) {
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		if single == "" {
			return nil, tokErr(ReasonMalformedToken, "aud 为空字符串")
		}
		return []string{single}, nil
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, tokErr(ReasonMalformedToken, "aud 类型非法（须为字符串或字符串数组）")
	}
	if len(arr) == 0 {
		return nil, tokErr(ReasonMalformedToken, "aud 为空数组")
	}
	for _, a := range arr {
		if a == "" {
			return nil, tokErr(ReasonMalformedToken, "aud 数组含空元素")
		}
	}
	return arr, nil
}

// maxNumericDateSeconds NumericDate 幅度上限（2^53），防止整数/浮点溢出。
const maxNumericDateSeconds = 1 << 53

// parseNumericDate 严格解析 NumericDate：仅接受 JSON 数字（整数或小数秒），
// 拒绝字符串弱转换、NaN/Inf 与超幅度值。
func parseNumericDate(raw json.RawMessage) (time.Time, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return time.Time{}, err
	}
	if dec.More() { // 拒绝 "1.2.3" 之类尾部数据
		return time.Time{}, errors.New("NumericDate 存在尾部数据")
	}
	num, ok := v.(json.Number)
	if !ok {
		return time.Time{}, errors.New("NumericDate 必须为 JSON 数字")
	}
	s := num.String()
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(i, 0).UTC(), nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || math.Abs(f) > maxNumericDateSeconds {
		return time.Time{}, errors.New("NumericDate 数值非法或超界")
	}
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(frac*1e9)).UTC(), nil
}
