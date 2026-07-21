package customrules

import (
	"strings"
	"testing"
)

func validRule() *CustomRule {
	return &CustomRule{
		RuleID:         7100001,
		Name:           "测试SQLi规则",
		AttackType:     "SQL_INJECTION",
		Severity:       "CRITICAL",
		Phase:          2,
		Operator:       "rx",
		OperatorValue:  `(?i)union\s+select`,
		TargetVariables: []string{"ARGS"},
		Action:         "BLOCK",
	}
}

func TestValidateInputValid(t *testing.T) {
	gen, err := ValidateInput(validRule())
	if err != nil {
		t.Fatalf("valid rule rejected: %v", err)
	}
	if !strings.Contains(gen, "id:7100001") {
		t.Errorf("generated rule missing id: %s", gen)
	}
	if !strings.Contains(gen, "deny") {
		t.Errorf("BLOCK action should produce deny: %s", gen)
	}
	if !strings.Contains(gen, "phase:2") {
		t.Errorf("missing phase: %s", gen)
	}
}

func TestIDOutOfRange(t *testing.T) {
	r := validRule()
	r.RuleID = 942100 // CRS 段，非法
	if _, err := ValidateInput(r); err == nil {
		t.Error("CRS-range id should be rejected")
	}
	r.RuleID = 7100000
	if _, err := ValidateInput(r); err != nil {
		t.Errorf("boundary id 7100000 should pass: %v", err)
	}
	r.RuleID = 7199999
	if _, err := ValidateInput(r); err != nil {
		t.Errorf("boundary id 7199999 should pass: %v", err)
	}
}

func TestDangerousContent(t *testing.T) {
	dangerous := []string{
		"@exec(/bin/cat)",
		"`cat /etc/passwd`",
		"$(cat /etc/passwd)",
		"/etc/passwd",
		"@pmFromFile /etc/hosts",
	}
	for _, d := range dangerous {
		r := validRule()
		r.OperatorValue = d
		if _, err := ValidateInput(r); err == nil {
			t.Errorf("dangerous content %q should be rejected", d)
		}
	}
}

func TestDisallowedOperator(t *testing.T) {
	r := validRule()
	r.Operator = "pmFromFile"
	if _, err := ValidateInput(r); err == nil {
		t.Error("pmFromFile should be rejected (arbitrary file read)")
	}
	r.Operator = "shell_exec"
	if _, err := ValidateInput(r); err == nil {
		t.Error("shell operator should be rejected")
	}
}

func TestDisallowedVariable(t *testing.T) {
	r := validRule()
	r.TargetVariables = []string{"REQUEST_BODY_RAW"}
	if _, err := ValidateInput(r); err == nil {
		t.Error("unsupported variable should be rejected")
	}
	r.TargetVariables = []string{}
	if _, err := ValidateInput(r); err == nil {
		t.Error("empty variables should be rejected")
	}
}

func TestDisallowedAction(t *testing.T) {
	r := validRule()
	r.Action = "EXEC"
	if _, err := ValidateInput(r); err == nil {
		t.Error("non-whitelist action should be rejected")
	}
}

func TestInvalidRegex(t *testing.T) {
	r := validRule()
	r.OperatorValue = "(?i)(unclosed"
	if _, err := ValidateInput(r); err == nil {
		t.Error("invalid regex should be rejected")
	}
}

func TestSecLangEscaping(t *testing.T) {
	r := validRule()
	r.Name = "test'quote\"and\nnewline"
	gen, err := ValidateInput(r)
	if err != nil {
		t.Fatalf("ValidateInput: %v", err)
	}
	if strings.Contains(gen, "\n") {
		t.Error("generated rule contains control character")
	}
}

func TestGenerateActions(t *testing.T) {
	actions := map[string]string{
		"BLOCK":   "deny",
		"OBSERVE": "DetectionOnly",
		"LOG":     "log",
	}
	for action, expect := range actions {
		r := validRule()
		r.Action = action
		gen, err := ValidateInput(r)
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		if !strings.Contains(gen, expect) {
			t.Errorf("action %s should contain %q: %s", action, expect, gen)
		}
	}
}
