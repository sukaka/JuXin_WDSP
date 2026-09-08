package applications

import "testing"

func TestDefaultMode(t *testing.T) {
	for _, m := range []string{ModeOff, ModeObserve, ModeProtect, ModeBypass} {
		if got := defaultMode(m); got != m {
			t.Errorf("defaultMode(%s) = %s, want %s", m, got, m)
		}
	}
	for _, m := range []string{"", "INVALID", "bypass"} {
		if got := defaultMode(m); got != ModeObserve {
			t.Errorf("defaultMode(%q) = %s, want %s", m, got, ModeObserve)
		}
	}
}
