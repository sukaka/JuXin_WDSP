package aiorchestrator

import (
	"testing"
	"time"
)

func TestParseQueryTimeRange(t *testing.T) {
	location := time.FixedZone("CST", 8*60*60)
	now := time.Date(2026, time.September, 2, 15, 30, 0, 0, location)

	tests := []struct {
		name      string
		message   string
		wantStart time.Time
		wantEnd   time.Time
		wantLabel string
		explicit  bool
	}{
		{
			name:      "yesterday",
			message:   "统计昨天的攻击事件",
			wantStart: time.Date(2026, time.September, 1, 0, 0, 0, 0, location),
			wantEnd:   time.Date(2026, time.September, 2, 0, 0, 0, 0, location),
			wantLabel: "昨天",
			explicit:  true,
		},
		{
			name:      "recent hours",
			message:   "最近 6 小时攻击趋势",
			wantStart: now.Add(-6 * time.Hour),
			wantEnd:   now,
			wantLabel: "最近 6 小时",
			explicit:  true,
		},
		{
			name:      "follow-up overrides previous range",
			message:   "统计最近 24 小时攻击趋势\n当前追问：昨天呢",
			wantStart: time.Date(2026, time.September, 1, 0, 0, 0, 0, location),
			wantEnd:   time.Date(2026, time.September, 2, 0, 0, 0, 0, location),
			wantLabel: "昨天",
			explicit:  true,
		},
		{
			name:      "follow-up without range inherits previous range",
			message:   "统计最近 7 天攻击趋势\n当前追问：继续",
			wantStart: now.Add(-7 * 24 * time.Hour),
			wantEnd:   now,
			wantLabel: "最近 7 天",
			explicit:  true,
		},
		{
			name:      "default",
			message:   "分析攻击事件",
			wantStart: now.Add(-24 * time.Hour),
			wantEnd:   now,
			wantLabel: "最近 24 小时",
			explicit:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseQueryTimeRange(tt.message, now)
			if !got.Start.Equal(tt.wantStart) || !got.End.Equal(tt.wantEnd) {
				t.Fatalf("range = %s..%s, want %s..%s", got.Start, got.End, tt.wantStart, tt.wantEnd)
			}
			if got.Label != tt.wantLabel || got.Explicit != tt.explicit {
				t.Fatalf("label/explicit = %q/%v, want %q/%v", got.Label, got.Explicit, tt.wantLabel, tt.explicit)
			}
		})
	}
}
