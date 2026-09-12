package aiorchestrator

import (
	"strings"
	"testing"
)

// TestEvidenceSetAdd 编号递增、计数、存在性判断与 Items 副本语义。
func TestEvidenceSetAdd(t *testing.T) {
	s := NewEvidenceSet()
	if s.Count() != 0 {
		t.Fatalf("新证据集 Count = %d, want 0", s.Count())
	}
	id1 := s.Add("security_event.search", "命中 3 条事件", nil)
	id2 := s.Add("log.query", "返回 10 条日志", map[string]int{"total": 10})
	if id1 != "E1" || id2 != "E2" {
		t.Errorf("引用编号 = %s, %s, want E1, E2", id1, id2)
	}
	if s.Count() != 2 {
		t.Errorf("Count = %d, want 2", s.Count())
	}
	if !s.ContainsID("E1") || !s.ContainsID("E2") || s.ContainsID("E9") {
		t.Error("ContainsID 判断错误")
	}
	items := s.Items()
	if len(items) != 2 || items[0].Source != "security_event.search" || items[1].Summary != "返回 10 条日志" {
		t.Errorf("Items = %+v", items)
	}
	// Items 返回副本，外部修改不影响内部
	items[0].ID = "HACK"
	if s.Items()[0].ID != "E1" {
		t.Error("Items 应返回副本，外部修改不应影响内部状态")
	}
}

// TestValidateCitations 合法引用保留、非法引用剔除并登记。
func TestValidateCitations(t *testing.T) {
	s := NewEvidenceSet()
	s.Add("tool.a", "证据一", nil)
	s.Add("tool.b", "证据二", nil)

	cases := []struct {
		name        string
		in          string
		wantClean   string
		wantInvalid []string
	}{
		{"valid single", "根据 [E1] 的结论", "根据 [E1] 的结论", nil},
		{"valid multiple sorted", "见 [E2,E1]", "见 [E1,E2]", nil},
		{"valid with space", "见 [E1, E2]", "见 [E1,E2]", nil},
		{"chinese comma", "见 [E1、E2]", "见 [E1,E2]", nil},
		{"invalid removed", "见 [E9] 的结论", "见  的结论", []string{"E9"}},
		{"mixed valid invalid", "见 [E1，E9]", "见 [E1]", []string{"E9"}},
		{"all invalid removed", "见 [E8,E9]", "见 ", []string{"E8", "E9"}},
		{"non citation untouched", "见 [注意] 内容", "见 [注意] 内容", nil},
		{"plain text", "没有引用的回答", "没有引用的回答", nil},
		{"empty", "", "", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cleaned, invalid := s.ValidateCitations(c.in)
			if cleaned != c.wantClean {
				t.Errorf("cleaned = %q, want %q", cleaned, c.wantClean)
			}
			if len(invalid) != len(c.wantInvalid) {
				t.Fatalf("invalid = %v, want %v", invalid, c.wantInvalid)
			}
			for i, id := range c.wantInvalid {
				if invalid[i] != id {
					t.Errorf("invalid[%d] = %s, want %s", i, invalid[i], id)
				}
			}
		})
	}
}

// TestValidateCitationsMultiple 同一回答中多处引用分别校验。
func TestValidateCitationsMultiple(t *testing.T) {
	s := NewEvidenceSet()
	s.Add("tool.a", "证据一", nil)
	answer := "结论一 [E1]，结论二 [E5]，结论三 [E1]"
	cleaned, invalid := s.ValidateCitations(answer)
	if cleaned != "结论一 [E1]，结论二 ，结论三 [E1]" {
		t.Errorf("cleaned = %q", cleaned)
	}
	if len(invalid) != 1 || invalid[0] != "E5" {
		t.Errorf("invalid = %v, want [E5]", invalid)
	}
}

// TestComposeEvidenceBlock 空集为空串，非空包含标题与每条证据行。
func TestComposeEvidenceBlock(t *testing.T) {
	s := NewEvidenceSet()
	if got := s.ComposeEvidenceBlock(); got != "" {
		t.Errorf("空证据集应返回空串, got %q", got)
	}
	s.Add("security_event.search", "命中事件 3 条", nil)
	s.Add("log.query", "日志 10 条", nil)
	block := s.ComposeEvidenceBlock()
	if !strings.Contains(block, "**证据引用**") {
		t.Error("缺少证据引用标题")
	}
	if !strings.Contains(block, "[E1] 安全事件查询：命中事件 3 条") {
		t.Errorf("缺少 E1 证据行: %q", block)
	}
	if !strings.Contains(block, "[E2] 日志查询：日志 10 条") {
		t.Errorf("缺少 E2 证据行: %q", block)
	}
}

func TestEvidenceSourceDisplayNameKeepsUnknownSource(t *testing.T) {
	if got, want := evidenceSourceDisplayName("custom.internal.tool"), "custom.internal.tool"; got != want {
		t.Fatalf("evidenceSourceDisplayName() = %q, want %q", got, want)
	}
}
