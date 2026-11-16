package detectors

import (
	"encoding/json"
	"sort"
	"strconv"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

const responseSensitiveValueLocation = "response_body"

var responseSensitiveValueLocations = map[string]bool{responseSensitiveValueLocation: true}

// CompileResponseSensitiveValueRules 编译响应体值级规则，仅保留 response_body 位置。
// 与请求侧共享校验和缓存，方向前缀防止相同配置复用错误的编译产物。
func CompileResponseSensitiveValueRules(in []SensitiveValueRule) ([]CompiledSensitiveValueRule, error) {
	key := "\x00response_body\x00" + sensitiveValueRulesCacheKey(in)
	if v, ok := sensitiveValueRuleCache.load(key); ok {
		r := v.(sensitiveValueRulesResult)
		return r.rules, r.err
	}
	rules, err := compileSensitiveValueRulesForLocations(in, responseSensitiveValueLocations)
	sensitiveValueRuleCache.store(key, sensitiveValueRulesResult{rules, err})
	return rules, err
}

// CheckResponseSensitiveValues 检测已解码 JSON 树的标量值，证据与上下文均不留存值。
func CheckResponseSensitiveValues(ctx *dsctx.RequestContext, root any, rules []CompiledSensitiveValueRule, limits dsctx.ParseLimits) {
	if ctx == nil || root == nil || !hasResponseSensitiveValueLocation(rules) {
		return
	}
	if limits.MaxJSONDepth <= 0 {
		limits = dsctx.DefaultParseLimits()
	}
	s := responseSensitiveValueScanner{ctx: ctx, rules: rules, limits: limits}
	s.walk(root, "", 0)
}

func hasResponseSensitiveValueLocation(rules []CompiledSensitiveValueRule) bool {
	for _, r := range rules {
		if r.locations[responseSensitiveValueLocation] {
			return true
		}
	}
	return false
}

type responseSensitiveValueScanner struct {
	ctx     *dsctx.RequestContext
	rules   []CompiledSensitiveValueRule
	limits  dsctx.ParseLimits
	fields  int
	matches int
	scans   int
}

func (s *responseSensitiveValueScanner) walk(v any, path string, depth int) {
	if depth > s.limits.MaxJSONDepth || s.fields >= s.limits.MaxFieldCount ||
		s.matches >= maxSensitiveMatches || s.scans >= maxSensitiveValueScans {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		if path != "" {
			s.fields++
		}
		keys := make([]string, 0, len(t))
		for key := range t {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if s.fields >= s.limits.MaxFieldCount || s.matches >= maxSensitiveMatches || s.scans >= maxSensitiveValueScans {
				return
			}
			next := key
			if path != "" {
				next = path + "." + key
			}
			s.walk(t[key], next, depth+1)
		}
	case []any:
		s.fields++
		for _, item := range t {
			if s.fields >= s.limits.MaxFieldCount || s.matches >= maxSensitiveMatches || s.scans >= maxSensitiveValueScans {
				return
			}
			s.walk(item, path+"[]", depth+1)
		}
	default:
		s.fields++
		value, ok := responseSensitiveScalarValue(v)
		if !ok {
			return
		}
		rule, matched := matchValueRules(value, responseSensitiveValueLocation, s.rules, &s.scans)
		if matched {
			s.addMatch(path, rule)
		}
	}
}

func responseSensitiveScalarValue(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case json.Number:
		return t.String(), true
	case float64:
		return strconv.FormatFloat(t, 'g', -1, 64), true
	case bool:
		return strconv.FormatBool(t), true
	default:
		return "", false
	}
}

func (s *responseSensitiveValueScanner) addMatch(path string, rule CompiledSensitiveValueRule) {
	if s.ctx.Response != nil {
		s.ctx.Response.SensitiveFields = append(s.ctx.Response.SensitiveFields, dsctx.SensitiveFieldHit{
			Path: path, DataType: rule.dataType,
		})
	}
	evidence := map[string]string{
		"field":     path,
		"data_type": rule.dataType,
		"location":  responseSensitiveValueLocation,
		"direction": "RESPONSE",
	}
	if rule.level != "" {
		evidence["level"] = rule.level
	}
	s.ctx.AddMatch(dsctx.DetectorMatch{
		Detector:   "sensitive_data",
		RuleID:     "sensitive.response_value",
		Category:   "OBSERVE",
		Severity:   "MEDIUM",
		Message:    "sensitive value observed in response body",
		Evidence:   evidence,
		ScoreDelta: 15,
		Confidence: 1.0,
	})
	s.matches++
}
