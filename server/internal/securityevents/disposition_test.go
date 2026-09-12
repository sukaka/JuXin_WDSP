package securityevents

import "testing"

func TestValidateDispositionTransition(t *testing.T) {
	tests := []struct {
		name       string
		current    string
		target     string
		idempotent bool
		wantErr    bool
	}{
		{"new to analyzing", "UNPROCESSED", "ANALYZING", false, false},
		{"analyzing to attack", "ANALYZING", "CONFIRMED_ATTACK", false, false},
		{"same final is idempotent", "CONFIRMED_ATTACK", "CONFIRMED_ATTACK", true, false},
		{"final cannot flip", "CONFIRMED_ATTACK", "CONFIRMED_FALSE_POSITIVE", false, true},
		{"empty defaults", "", "ANALYZING", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idempotent, err := ValidateDispositionTransition(tt.current, tt.target)
			if idempotent != tt.idempotent {
				t.Fatalf("idempotent = %v, want %v", idempotent, tt.idempotent)
			}
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
