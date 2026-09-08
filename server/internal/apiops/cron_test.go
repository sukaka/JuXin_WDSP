// cron_test.go 最小五段 cron 解析器测试：解析矩阵（通配/步进/范围/列表/宏/周日归一）、
// 日/周「或」语义、下次触发时间计算、非法与永不命中表达式。
package apiops

import (
	"errors"
	"testing"
	"time"
)

// mustNext 解析并计算下次触发时间（失败即 t.Fatal）。
func mustNext(t *testing.T, expr string, from time.Time) time.Time {
	t.Helper()
	next, err := NextCronAfter(expr, from)
	if err != nil {
		t.Fatalf("NextCronAfter(%q): %v", expr, err)
	}
	return next
}

func TestParseCronValid(t *testing.T) {
	valid := []string{
		"* * * * *", "*/15 * * * *", "0 9 * * *", "30 8 1 * *", "0 9 * * 1-5",
		"0 9 * * 0", "0 9 * * 7", "0 0 29 2 *", "5/10 * * * *", "0 9-18/2 * * *",
		"0,30 9,18 * * *", "  0   9  *  *  *  ", "@hourly", "@daily", "@midnight",
		"@weekly", "@monthly", "@yearly", "@annually",
	}
	for _, expr := range valid {
		if _, err := ParseCron(expr); err != nil {
			t.Fatalf("ParseCron(%q) should succeed: %v", expr, err)
		}
	}
}

func TestParseCronInvalid(t *testing.T) {
	invalid := []string{
		"", "0 9 * *", "0 9 * * * *", "61 * * * *", "0 24 * * *", "0 9 0 * *",
		"0 9 32 * *", "0 9 * 13 *", "0 9 * * 8", "*/0 * * * *", "*/-1 * * * *",
		"a b c d e", "0 9 * * MON", "5-2 * * * *", "0 9 * * 3-9", ", * * * *",
		"0 9 * * * extra", "@reboot", "0/ * * * *",
	}
	for _, expr := range invalid {
		if _, err := ParseCron(expr); err == nil {
			t.Fatalf("ParseCron(%q) should fail", expr)
		} else if !errors.Is(err, ErrInvalidCron) {
			t.Fatalf("ParseCron(%q) error should wrap ErrInvalidCron: %v", expr, err)
		}
	}
}

func TestCronNextAfterDaily(t *testing.T) {
	// 每天 09:00：08:59:30（含秒，验证分钟截断）→ 当天 09:00
	from := time.Date(2026, 8, 18, 8, 59, 30, 0, time.UTC)
	next := mustNext(t, "0 9 * * *", from)
	if !next.Equal(time.Date(2026, 8, 18, 9, 0, 0, 0, time.UTC)) {
		t.Fatalf("next=%v, want 2026-08-18 09:00", next)
	}
	// 恰好 09:00 → 次日 09:00（不含 from 本身）
	next = mustNext(t, "0 9 * * *", time.Date(2026, 8, 18, 9, 0, 0, 0, time.UTC))
	if !next.Equal(time.Date(2026, 8, 19, 9, 0, 0, 0, time.UTC)) {
		t.Fatalf("next=%v, want 2026-08-19 09:00", next)
	}
}

func TestCronNextAfterStep(t *testing.T) {
	next := mustNext(t, "*/15 * * * *", time.Date(2026, 8, 18, 10, 7, 0, 0, time.UTC))
	if !next.Equal(time.Date(2026, 8, 18, 10, 15, 0, 0, time.UTC)) {
		t.Fatalf("next=%v, want 10:15", next)
	}
	next = mustNext(t, "5/10 * * * *", time.Date(2026, 8, 18, 10, 5, 0, 0, time.UTC))
	if !next.Equal(time.Date(2026, 8, 18, 10, 15, 0, 0, time.UTC)) {
		t.Fatalf("next=%v, want 10:15 (a/n 等价 a-max/n)", next)
	}
}

func TestCronNextAfterWeekdayRange(t *testing.T) {
	// 工作日 09:00：从某个周五 09:00 起，下次必为周一 09:00
	from := time.Date(2026, 8, 14, 9, 0, 0, 0, time.UTC) // 2026-08-14 为周五
	if from.Weekday() != time.Friday {
		t.Fatalf("test premise wrong: %v is %v", from, from.Weekday())
	}
	next := mustNext(t, "0 9 * * 1-5", from)
	if !next.Equal(time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC)) || next.Weekday() != time.Monday {
		t.Fatalf("next=%v (%v), want 2026-08-17 09:00 Monday", next, next.Weekday())
	}
}

func TestCronDowSevenIsSunday(t *testing.T) {
	// 2026-08-16 为周日；7 与 0 均表示周日
	sunday := time.Date(2026, 8, 16, 0, 0, 0, 0, time.UTC)
	if sunday.Weekday() != time.Sunday {
		t.Fatalf("test premise wrong: %v is %v", sunday, sunday.Weekday())
	}
	from := time.Date(2026, 8, 15, 10, 0, 0, 0, time.UTC) // 周六
	for _, expr := range []string{"0 9 * * 7", "0 9 * * 0"} {
		next := mustNext(t, expr, from)
		if !next.Equal(time.Date(2026, 8, 16, 9, 0, 0, 0, time.UTC)) {
			t.Fatalf("%q next=%v, want 2026-08-16 09:00 (Sunday)", expr, next)
		}
	}
}

func TestCronDomDowOrSemantics(t *testing.T) {
	// 「0 0 1 * 1」：每月 1 日「或」周一（Vixie 语义，双受限取或）
	// 从 2026-08-18（周二）起：最近命中应为 2026-08-24（周一），而非 09-01
	from := time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)
	if from.Weekday() != time.Tuesday {
		t.Fatalf("test premise wrong: %v is %v", from, from.Weekday())
	}
	next := mustNext(t, "0 0 1 * 1", from)
	if !next.Equal(time.Date(2026, 8, 24, 0, 0, 0, 0, time.UTC)) || next.Weekday() != time.Monday {
		t.Fatalf("next=%v (%v), want 2026-08-24 00:00 Monday (OR 语义)", next, next.Weekday())
	}
	// 仅日受限：「0 0 1 * *」→ 09-01
	next = mustNext(t, "0 0 1 * *", from)
	if !next.Equal(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("next=%v, want 2026-09-01 00:00", next)
	}
}

func TestCronNextAfterLeapDay(t *testing.T) {
	// 2 月 29 日：2026-01-01 起 → 2028-02-29（2028 为闰年；长区间搜索正确性）
	next := mustNext(t, "0 0 29 2 *", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if !next.Equal(time.Date(2028, 2, 29, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("next=%v, want 2028-02-29 00:00", next)
	}
}

func TestCronImpossible(t *testing.T) {
	// 2 月 30 日永不命中：解析合法，NextAfter 须报错而非死循环
	if _, err := NextCronAfter("0 0 30 2 *", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("2 月 30 日应返回无触发时间错误")
	}
}

func TestCronMacros(t *testing.T) {
	from := time.Date(2026, 8, 18, 10, 30, 0, 0, time.UTC)
	cases := []struct {
		expr string
		want time.Time
	}{
		{"@hourly", time.Date(2026, 8, 18, 11, 0, 0, 0, time.UTC)},
		{"@daily", time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)},
		{"@monthly", time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)},
		{"@yearly", time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)},
		{"@weekly", time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC)}, // 下个周日
	}
	for _, c := range cases {
		if next := mustNext(t, c.expr, from); !next.Equal(c.want) {
			t.Fatalf("%s next=%v, want %v", c.expr, next, c.want)
		}
	}
}
