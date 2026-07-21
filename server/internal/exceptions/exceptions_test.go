package exceptions

import (
	"strings"
	"testing"
	"time"
)

func preciseException() *Exception {
	return &Exception{
		Name:            "富文本误报例外",
		ScopeType:       "APPLICATION",
		URIPrefix:       "/api/richtext",
		ParamNames:      []string{"content"},
		RuleIDs:         []int{942100},
		ExceptionAction: ActionRemoveRule,
		Status:          "ENABLED",
	}
}

func TestPreciseExceptionValid(t *testing.T) {
	e := preciseException()
	if err := ValidateInput(e); err != nil {
		t.Fatalf("precise exception rejected: %v", err)
	}
	if e.IsBroad() {
		t.Error("precise exception should not be broad")
	}
}

func TestBroadExceptionNeedsAck(t *testing.T) {
	// 对全部 SQLi 攻击类型的例外 = 宽泛
	e := &Exception{
		Name:            "全部SQLi例外",
		ScopeType:       "GLOBAL",
		AttackTypes:     []string{"SQL_INJECTION"},
		ExceptionAction: ActionRemoveRuleTag,
		RuleTags:        []string{"attack-sqli"},
		Status:          "ENABLED",
	}
	if !e.IsBroad() {
		t.Error("attack-type exception should be broad")
	}
	if err := ValidateInput(e); err == nil {
		t.Error("broad exception without ack should be rejected")
	}
	// 确认风险后允许
	e.RiskAcknowledged = true
	if err := ValidateInput(e); err != nil {
		t.Errorf("broad exception with ack should pass: %v", err)
	}
}

func TestGlobalBroadRejected(t *testing.T) {
	e := &Exception{
		Name:            "全局无条件例外",
		ScopeType:       "GLOBAL",
		ExceptionAction: ActionRemoveRule,
		Status:          "ENABLED",
	}
	if !e.IsBroad() {
		t.Error("global unconditional should be broad")
	}
	if err := ValidateInput(e); err == nil {
		t.Error("global broad should be rejected")
	}
}

func TestTemporaryRequiresExpiry(t *testing.T) {
	e := preciseException()
	e.IsTemporary = true
	e.EffectiveUntil = nil
	if err := ValidateInput(e); err == nil {
		t.Error("temporary without expiry should be rejected")
	}
	now := time.Now()
	later := now.Add(24 * time.Hour)
	e.EffectiveFrom = &now
	e.EffectiveUntil = &later
	if err := ValidateInput(e); err != nil {
		t.Errorf("temporary with expiry should pass: %v", err)
	}
}

func TestInvalidTimeRange(t *testing.T) {
	e := preciseException()
	now := time.Now()
	earlier := now.Add(-time.Hour)
	e.EffectiveFrom = &now
	e.EffectiveUntil = &earlier
	if err := ValidateInput(e); err == nil {
		t.Error("invalid time range should be rejected")
	}
}

func TestInvalidSourceIP(t *testing.T) {
	e := preciseException()
	e.SourceIPs = []string{"not-an-ip"}
	if err := ValidateInput(e); err == nil {
		t.Error("invalid source ip should be rejected")
	}
	e.SourceIPs = []string{"192.0.2.0/24"}
	if err := ValidateInput(e); err != nil {
		t.Errorf("valid CIDR should pass: %v", err)
	}
}

func TestGenerateSecLangPrecise(t *testing.T) {
	e := preciseException()
	gen := GenerateSecLang(e, 8000001)
	if !strings.Contains(gen, "8000001") {
		t.Errorf("generated missing rule id: %s", gen)
	}
	if !strings.Contains(gen, "942100") {
		t.Errorf("generated missing target rule id: %s", gen)
	}
	if !strings.Contains(gen, "ARGS:content") {
		t.Errorf("generated missing param: %s", gen)
	}
	if !strings.Contains(gen, "beginsWith") {
		t.Errorf("prefix exception should use beginsWith: %s", gen)
	}
}

func TestGenerateSecLangEscapes(t *testing.T) {
	e := preciseException()
	e.URIExact = "/api/x\"injection"
	gen := GenerateSecLang(e, 8000001)
	if strings.Contains(gen, `x"injection"`) && !strings.Contains(gen, `\"`) {
		t.Error("quote should be escaped")
	}
}
