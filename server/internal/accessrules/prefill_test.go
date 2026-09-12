package accessrules

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestSuggestBlockDurationHours(t *testing.T) {
	cases := []struct {
		name     string
		severity string
		related  int64
		want     int
	}{
		{"high_single", "HIGH", 1, 24},
		{"medium_single", "MEDIUM", 1, 6},
		{"low_single", "LOW", 1, 2},
		{"info_single", "INFO", 1, 1},
		{"unknown_single", "", 1, 1},
		{"high_frequent_escalate", "HIGH", 10, 72},
		{"medium_frequent_escalate", "MEDIUM", 10, 24},
		{"low_frequent_escalate", "LOW", 10, 6},
		{"info_frequent_escalate", "INFO", 10, 2},
		{"burst_cap72", "LOW", 50, 72},
		{"high_burst_cap72", "HIGH", 200, 72},
		{"below_threshold_no_escalate", "MEDIUM", 9, 6},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := SuggestBlockDurationHours(c.severity, c.related); got != c.want {
				t.Fatalf("SuggestBlockDurationHours(%q, %d) = %d, want %d", c.severity, c.related, got, c.want)
			}
		})
	}
}

func TestValidateAPISource(t *testing.T) {
	eventID := uuid.New()
	cases := []struct {
		name    string
		in      CreateInput
		wantErr string
	}{
		{"manual_default", CreateInput{}, ""},
		{"manual_explicit", CreateInput{SourceType: SourceManual}, ""},
		{"security_event_ok", CreateInput{SourceType: SourceSecurityEvent, SourceEventID: &eventID}, ""},
		{"security_event_missing_id", CreateInput{SourceType: SourceSecurityEvent}, "source_event_id"},
		{"manual_with_event_id", CreateInput{SourceType: SourceManual, SourceEventID: &eventID}, "仅 SECURITY_EVENT"},
		{"empty_with_event_id", CreateInput{SourceEventID: &eventID}, "仅 SECURITY_EVENT"},
		{"import_rejected", CreateInput{SourceType: SourceImport}, "仅支持 MANUAL 或 SECURITY_EVENT"},
		{"auto_block_rejected", CreateInput{SourceType: SourceAutoBlock}, "仅支持 MANUAL 或 SECURITY_EVENT"},
		{"system_rejected", CreateInput{SourceType: SourceSystem}, "仅支持 MANUAL 或 SECURITY_EVENT"},
		{"garbage_rejected", CreateInput{SourceType: "HACK"}, "仅支持 MANUAL 或 SECURITY_EVENT"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateAPISource(&c.in)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("validateAPISource() = %v, want nil", err)
				}
				return
			}
			if err == nil || !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("validateAPISource() = %v, want ErrInvalidInput containing %q", err, c.wantErr)
			}
		})
	}
	// nil UUID 视同缺失
	nilID := uuid.Nil
	if err := validateAPISource(&CreateInput{SourceType: SourceSecurityEvent, SourceEventID: &nilID}); err == nil {
		t.Fatal("validateAPISource() with nil UUID = nil, want error")
	}
}

func TestSuggestBlacklistNameAndReason(t *testing.T) {
	name := suggestBlacklistName("203.0.113.9")
	if name != "事件封禁-203.0.113.9" {
		t.Fatalf("suggestBlacklistName = %q", name)
	}
	id := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	reason := suggestBlacklistReason("SQL_INJECTION", id)
	if !strings.Contains(reason, "SQL_INJECTION") || !strings.Contains(reason, id.String()) {
		t.Fatalf("suggestBlacklistReason = %q, 应包含攻击类型与事件ID", reason)
	}
	if len([]rune(reason)) > 500 {
		t.Fatalf("suggestBlacklistReason 超过500字符上限")
	}
}
