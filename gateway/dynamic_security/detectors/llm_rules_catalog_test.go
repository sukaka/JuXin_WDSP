package detectors

import "testing"

func TestBuiltinLLMSecurityRulesCatalogMatchesEngine(t *testing.T) {
	cat := BuiltinLLMSecurityRulesCatalog()
	if len(cat.Categories) != 3 {
		t.Fatalf("categories = %d, want 3", len(cat.Categories))
	}
	if len(cat.Categories[0].Rules) != len(llmInjectionRules) {
		t.Errorf("injection rules = %d, want %d", len(cat.Categories[0].Rules), len(llmInjectionRules))
	}
	if len(cat.Categories[1].Rules) != len(llmOutputContentRules) {
		t.Errorf("content rules = %d, want %d", len(cat.Categories[1].Rules), len(llmOutputContentRules))
	}
	if len(cat.Categories[2].Rules) != len(llmPIIPatterns) {
		t.Errorf("pii rules = %d, want %d", len(cat.Categories[2].Rules), len(llmPIIPatterns))
	}
	for i, r := range llmInjectionRules {
		got := cat.Categories[0].Rules[i]
		if got.ID != r.name || got.Pattern != r.re.String() {
			t.Errorf("injection[%d] mismatch: got (%q, %q), want (%q, %q)", i, got.ID, got.Pattern, r.name, r.re.String())
		}
	}
	for i, r := range llmOutputContentRules {
		got := cat.Categories[1].Rules[i]
		if got.ID != r.name || got.Pattern != r.re.String() {
			t.Errorf("content[%d] mismatch: got (%q, %q)", i, got.ID, got.Pattern)
		}
	}
	for i, r := range llmPIIPatterns {
		got := cat.Categories[2].Rules[i]
		if got.ID != r.dataType || got.Pattern != r.re.String() {
			t.Errorf("pii[%d] mismatch: got (%q, %q)", i, got.ID, got.Pattern)
		}
	}
	if len(cat.PromptPaths) != len(llmPromptValuePaths) {
		t.Errorf("prompt paths = %d, want %d", len(cat.PromptPaths), len(llmPromptValuePaths))
	}
}
