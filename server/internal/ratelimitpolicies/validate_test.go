package ratelimitpolicies

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// validPolicy 返回一个可通过校验的全局策略基准。
func validPolicy() *Policy {
	return &Policy{
		Name:          "全局CC防护",
		ScopeType:     ScopeGlobal,
		URIMatchType:  URIMatchAll,
		Dimension:     DimensionClientIP,
		Algorithm:     AlgorithmTokenBucket,
		RequestsLimit: 100,
		WindowSeconds: 60,
		BurstCapacity: 0,
		Action:        ActionReject,
		Priority:      100,
	}
}

func appID() *uuid.UUID {
	id := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	return &id
}

func hasFieldErr(errs []FieldError, field string) bool {
	for _, e := range errs {
		if e.Field == field {
			return true
		}
	}
	return false
}

func TestValidPolicies(t *testing.T) {
	cases := map[string]func() *Policy{
		"全局策略": validPolicy,
		"应用策略": func() *Policy {
			p := validPolicy()
			p.ScopeType = ScopeApplication
			p.ApplicationID = appID()
			return p
		},
		"URI精确策略": func() *Policy {
			p := validPolicy()
			p.ScopeType = ScopeURI
			p.ApplicationID = appID()
			p.URIMatchType = URIMatchExact
			p.URIPattern = "/api/login"
			return p
		},
		"URI前缀策略": func() *Policy {
			p := validPolicy()
			p.ScopeType = ScopeURI
			p.ApplicationID = appID()
			p.URIMatchType = URIMatchPrefix
			p.URIPattern = "/api/"
			return p
		},
		"URI正则策略": func() *Policy {
			p := validPolicy()
			p.ScopeType = ScopeURI
			p.ApplicationID = appID()
			p.URIMatchType = URIMatchRegex
			p.URIPattern = `^/api/v\d+/upload$`
			return p
		},
		"临时封禁策略": func() *Policy {
			p := validPolicy()
			p.Action = ActionTempBlock
			p.BlockDurationSeconds = 600
			return p
		},
		"观察动作": func() *Policy {
			p := validPolicy()
			p.Action = ActionObserve
			return p
		},
		"滑动窗口算法": func() *Policy {
			p := validPolicy()
			p.Algorithm = AlgorithmSlidingWindow
			return p
		},
		"边界值": func() *Policy {
			p := validPolicy()
			p.RequestsLimit = maxRequestsLimit
			p.WindowSeconds = maxWindowSeconds
			p.BurstCapacity = maxRequestsLimit * burstLimitMultiple
			p.Priority = maxPriority
			return p
		},
		"嵌套量词正则RE2可线性处理": func() *Policy {
			p := validPolicy()
			p.ScopeType = ScopeURI
			p.ApplicationID = appID()
			p.URIMatchType = URIMatchRegex
			p.URIPattern = `^/(a+)+$` // 传统回溯引擎的ReDoS模式，Go RE2 线性时间编译执行，允许
			return p
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			if errs := ValidateInput(build()); len(errs) > 0 {
				t.Errorf("valid policy rejected: %v", errs)
			}
		})
	}
}

func TestInvalidPolicies(t *testing.T) {
	now := time.Now()
	cases := map[string]struct {
		mutate func(p *Policy)
		field  string
	}{
		"名称为空":            {func(p *Policy) { p.Name = "" }, "name"},
		"名称超长":            {func(p *Policy) { p.Name = strings.Repeat("a", 201) }, "name"},
		"描述超长":            {func(p *Policy) { p.Description = strings.Repeat("a", 501) }, "description"},
		"非法scope":         {func(p *Policy) { p.ScopeType = "HOST" }, "scope_type"},
		"GLOBAL带应用":       {func(p *Policy) { p.ApplicationID = appID() }, "application_id"},
		"APPLICATION缺应用":  {func(p *Policy) { p.ScopeType = ScopeApplication }, "application_id"},
		"URI缺应用":          {func(p *Policy) { p.ScopeType = ScopeURI }, "application_id"},
		"非法dimension":     {func(p *Policy) { p.Dimension = "SESSION" }, "dimension"},
		"非法algorithm":     {func(p *Policy) { p.Algorithm = "LEAKY_BUCKET" }, "algorithm"},
		"非法action":        {func(p *Policy) { p.Action = "BLOCK" }, "action"},
		"负数阈值":            {func(p *Policy) { p.RequestsLimit = -1 }, "requests_limit"},
		"零阈值":             {func(p *Policy) { p.RequestsLimit = 0 }, "requests_limit"},
		"超大阈值":            {func(p *Policy) { p.RequestsLimit = 1000001 }, "requests_limit"},
		"零窗口":             {func(p *Policy) { p.WindowSeconds = 0 }, "window_seconds"},
		"负数窗口":            {func(p *Policy) { p.WindowSeconds = -60 }, "window_seconds"},
		"超大窗口":            {func(p *Policy) { p.WindowSeconds = 86401 }, "window_seconds"},
		"负数突发":            {func(p *Policy) { p.BurstCapacity = -1 }, "burst_capacity"},
		"突发超阈值10倍":        {func(p *Policy) { p.BurstCapacity = 100*10 + 1 }, "burst_capacity"},
		"TEMP_BLOCK缺封禁时长": {func(p *Policy) { p.Action = ActionTempBlock }, "block_duration_seconds"},
		"封禁时长过短": {func(p *Policy) {
			p.Action = ActionTempBlock
			p.BlockDurationSeconds = 59
		}, "block_duration_seconds"},
		"封禁时长超长": {func(p *Policy) {
			p.Action = ActionTempBlock
			p.BlockDurationSeconds = 86400*30 + 1
		}, "block_duration_seconds"},
		"封禁时长负数":        {func(p *Policy) { p.BlockDurationSeconds = -1 }, "block_duration_seconds"},
		"非法URI匹配方式":     {func(p *Policy) { p.URIMatchType = "CONTAINS" }, "uri_match_type"},
		"ALL带pattern":   {func(p *Policy) { p.URIPattern = "/api" }, "uri_pattern"},
		"EXACT缺pattern": {func(p *Policy) { p.URIMatchType = URIMatchExact }, "uri_pattern"},
		"EXACT非斜杠开头": {func(p *Policy) {
			p.URIMatchType = URIMatchExact
			p.URIPattern = "api/login"
		}, "uri_pattern"},
		"EXACT超长": {func(p *Policy) {
			p.URIMatchType = URIMatchExact
			p.URIPattern = "/" + strings.Repeat("a", 256)
		}, "uri_pattern"},
		"EXACT含控制字符": {func(p *Policy) {
			p.URIMatchType = URIMatchExact
			p.URIPattern = "/api/\nadmin"
		}, "uri_pattern"},
		"PREFIX含NUL": {func(p *Policy) {
			p.URIMatchType = URIMatchPrefix
			p.URIPattern = "/api/\x00"
		}, "uri_pattern"},
		"危险正则未闭合": {func(p *Policy) {
			p.URIMatchType = URIMatchRegex
			p.URIPattern = `^/api/[0-9+$`
		}, "uri_pattern"},
		"非法正则语法": {func(p *Policy) {
			p.URIMatchType = URIMatchRegex
			p.URIPattern = `(?P<`
		}, "uri_pattern"},
		"正则超长": {func(p *Policy) {
			p.URIMatchType = URIMatchRegex
			p.URIPattern = strings.Repeat("a", 257)
		}, "uri_pattern"},
		"REGEX缺pattern": {func(p *Policy) { p.URIMatchType = URIMatchRegex }, "uri_pattern"},
		"生效晚于失效": {func(p *Policy) {
			from := now.Add(48 * time.Hour)
			until := now.Add(time.Hour)
			p.EffectiveFrom = &from
			p.EffectiveUntil = &until
		}, "effective_until"},
		"负数优先级":    {func(p *Policy) { p.Priority = -1 }, "priority"},
		"优先级超限":    {func(p *Policy) { p.Priority = 10001 }, "priority"},
		"非法status": {func(p *Policy) { p.Status = "ENABLED" }, "status"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p := validPolicy()
			tc.mutate(p)
			errs := ValidateInput(p)
			if len(errs) == 0 {
				t.Fatalf("invalid policy accepted")
			}
			if !hasFieldErr(errs, tc.field) {
				t.Errorf("expected error on field %q, got %v", tc.field, errs)
			}
		})
	}
}

func TestValidateAggregatesErrors(t *testing.T) {
	p := validPolicy()
	p.Name = ""
	p.RequestsLimit = -5
	p.WindowSeconds = 0
	errs := ValidateInput(p)
	if len(errs) < 3 {
		t.Fatalf("expected at least 3 aggregated errors, got %v", errs)
	}
	for _, field := range []string{"name", "requests_limit", "window_seconds"} {
		if !hasFieldErr(errs, field) {
			t.Errorf("expected error on %q in %v", field, errs)
		}
	}
}

func TestValidationErrorUnwrap(t *testing.T) {
	ve := &ValidationError{Errors: []FieldError{{Field: "name", Message: "策略名称不能为空"}}}
	if !errors.Is(ve, ErrInvalidInput) {
		t.Error("ValidationError should unwrap to ErrInvalidInput")
	}
	if ve.Error() == "" {
		t.Error("ValidationError.Error() should not be empty")
	}
}
