package accesscontrolversions

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDiffConfigsBasic(t *testing.T) {
	oldCfg := json.RawMessage(`{
		"trusted_proxies": ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
		"rate_limits": [{"name": "cc1", "limit": 100}],
		"mode": "enforce"
	}`)
	newCfg := json.RawMessage(`{
		"trusted_proxies": ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"],
		"rate_limits": [{"name": "cc1", "limit": 200}],
		"mode": "enforce",
		"ip_rules": []
	}`)

	lines, err := DiffConfigs(oldCfg, newCfg)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "trusted_proxies: 3 -> 5 项") {
		t.Errorf("expected array length change line, got:\n%s", joined)
	}
	if !strings.Contains(joined, "rate_limits: 数组内容已修改（1 项）") {
		t.Errorf("expected array modified line, got:\n%s", joined)
	}
	if !strings.Contains(joined, "ip_rules: 新增") {
		t.Errorf("expected added key line, got:\n%s", joined)
	}
	if strings.Contains(joined, "mode") {
		t.Errorf("unchanged scalar should not appear, got:\n%s", joined)
	}
}

func TestDiffConfigsRemovedAndScalar(t *testing.T) {
	oldCfg := json.RawMessage(`{"a": 1, "b": {"x": true}, "c": [1]}`)
	newCfg := json.RawMessage(`{"a": 2, "c": "not-array"}`)
	lines, err := DiffConfigs(oldCfg, newCfg)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "a: 1 -> 2") {
		t.Errorf("expected scalar change, got:\n%s", joined)
	}
	if !strings.Contains(joined, "b: 移除") {
		t.Errorf("expected removed key, got:\n%s", joined)
	}
	if !strings.Contains(joined, "c: 类型变化（数组 -> 字符串）") {
		t.Errorf("expected type change, got:\n%s", joined)
	}
}

func TestDiffConfigsNoDiff(t *testing.T) {
	cfg := json.RawMessage(`{"a": [1,2], "b": {"x": 1}}`)
	// 键顺序不同、内容相同 → 无差异
	cfg2 := json.RawMessage(`{"b": {"x": 1}, "a": [1,2]}`)
	lines, err := DiffConfigs(cfg, cfg2)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 0 {
		t.Errorf("expected no diff, got: %v", lines)
	}
}

func TestDiffConfigsObjectModified(t *testing.T) {
	oldCfg := json.RawMessage(`{"app": {"shop": {"limit": 100}}}`)
	newCfg := json.RawMessage(`{"app": {"shop": {"limit": 200}}}`)
	lines, err := DiffConfigs(oldCfg, newCfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 || lines[0] != "app: 配置已修改" {
		t.Errorf("expected object modified line, got: %v", lines)
	}
}

func TestDiffConfigsInvalidJSON(t *testing.T) {
	if _, err := DiffConfigs(json.RawMessage(`{bad`), json.RawMessage(`{}`)); err == nil {
		t.Error("invalid base config should error")
	}
	if _, err := DiffConfigs(json.RawMessage(`{}`), json.RawMessage(`{bad`)); err == nil {
		t.Error("invalid target config should error")
	}
}

func TestCreateInputValidate(t *testing.T) {
	in := &CreateInput{Config: json.RawMessage(`{"a":1}`)}
	if err := in.Validate(); err != nil {
		t.Errorf("valid input rejected: %v", err)
	}
	if err := (&CreateInput{}).Validate(); err == nil {
		t.Error("empty config should be rejected")
	}
	if err := (&CreateInput{Config: json.RawMessage(`not-json`)}).Validate(); err == nil {
		t.Error("invalid json should be rejected")
	}
	long := &CreateInput{Config: json.RawMessage(`{}`), ChangeSummary: strings.Repeat("x", 1001)}
	if err := long.Validate(); err == nil {
		t.Error("overlong change_summary should be rejected")
	}
}
