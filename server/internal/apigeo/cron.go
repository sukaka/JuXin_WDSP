// cron.go 五段 Cron 表达式解析与分钟级匹配器（分 时 日 月 周）。
//
// 口径与 server/internal/apiops/cron.go 完全一致（不引入第三方依赖）：
//   - 支持 `*`、`*/n`、`a`、`a-b`、`a-b/n`、`a/n` 与逗号列表；
//   - 周字段 0 与 7 均表示周日；
//   - 日/周同时受限时按 Vixie 语义取「或」，仅一方受限时取「与」；
//   - 支持宏：@hourly / @daily / @midnight / @weekly / @monthly / @yearly / @annually。
package apigeo

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ErrInvalidCron 表示 Cron 表达式格式错误或无有效触发时间。
var ErrInvalidCron = errors.New("无效的 Cron 表达式")

var cronMacros = map[string]string{
	"@hourly":   "0 * * * *",
	"@daily":    "0 0 * * *",
	"@midnight": "0 0 * * *",
	"@weekly":   "0 0 * * 0",
	"@monthly":  "0 0 1 * *",
	"@yearly":   "0 0 1 1 *",
	"@annually": "0 0 1 1 *",
}

type cronField struct {
	allowed map[int]bool
	any     bool
}

// CronSpec 是已解析的五段 Cron 表达式。
type CronSpec struct {
	minute cronField // 0-59
	hour   cronField // 0-23
	dom    cronField // 1-31
	month  cronField // 1-12
	dow    cronField // 0-6（0=周日）
}

// ParseCron 解析五段 Cron 表达式（支持常用宏）。
func ParseCron(expr string) (*CronSpec, error) {
	expr = strings.TrimSpace(strings.ToLower(expr))
	if expr == "" {
		return nil, fmt.Errorf("%w：表达式为空", ErrInvalidCron)
	}
	if macro, ok := cronMacros[expr]; ok {
		expr = macro
	}
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return nil, fmt.Errorf("%w：须为五段（分 时 日 月 周）或宏，实际 %d 段", ErrInvalidCron, len(fields))
	}
	bounds := [5][2]int{{0, 59}, {0, 23}, {1, 31}, {1, 12}, {0, 7}}
	names := [5]string{"分", "时", "日", "月", "周"}
	out := make([]cronField, 5)
	for i, f := range fields {
		parsed, err := parseCronField(f, bounds[i][0], bounds[i][1])
		if err != nil {
			return nil, fmt.Errorf("%w：%s段 %q：%v", ErrInvalidCron, names[i], f, err)
		}
		out[i] = parsed
	}
	spec := &CronSpec{
		minute: out[0],
		hour:   out[1],
		dom:    out[2],
		month:  out[3],
		dow:    out[4],
	}
	if spec.dow.allowed[7] {
		spec.dow.allowed[0] = true
		delete(spec.dow.allowed, 7)
	}
	return spec, nil
}

func parseCronField(field string, min, max int) (cronField, error) {
	res := cronField{allowed: map[int]bool{}}
	for _, part := range strings.Split(field, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return res, fmt.Errorf("存在空项")
		}
		base, step := part, 1
		if i := strings.Index(part, "/"); i >= 0 {
			base = part[:i]
			n, err := strconv.Atoi(part[i+1:])
			if err != nil || n <= 0 {
				return res, fmt.Errorf("步进须为正整数")
			}
			step = n
		}
		lo, hi := min, max
		switch {
		case base == "*":
		case strings.Contains(base, "-"):
			bounds := strings.SplitN(base, "-", 2)
			a, err1 := strconv.Atoi(bounds[0])
			b, err2 := strconv.Atoi(bounds[1])
			if err1 != nil || err2 != nil {
				return res, fmt.Errorf("范围端点须为数字")
			}
			lo, hi = a, b
		default:
			a, err := strconv.Atoi(base)
			if err != nil {
				return res, fmt.Errorf("取值须为数字")
			}
			lo = a
			if step == 1 {
				hi = a
			}
		}
		if lo < min || hi > max || lo > hi {
			return res, fmt.Errorf("取值范围 [%d,%d] 超出允许 [%d,%d]", lo, hi, min, max)
		}
		for v := lo; v <= hi; v += step {
			res.allowed[v] = true
		}
	}
	if len(res.allowed) == 0 {
		return res, fmt.Errorf("无有效取值")
	}
	res.any = len(res.allowed) == max-min+1
	return res, nil
}

// Match 判断给定时刻是否命中 Cron 表达式（分钟级精度）。
func (s *CronSpec) Match(t time.Time) bool {
	if s == nil {
		return false
	}
	if !s.minute.allowed[t.Minute()] || !s.hour.allowed[t.Hour()] || !s.month.allowed[int(t.Month())] {
		return false
	}
	domHit := s.dom.allowed[t.Day()]
	dowHit := s.dow.allowed[int(t.Weekday())]
	if !s.dom.any && !s.dow.any {
		return domHit || dowHit
	}
	return domHit && dowHit
}

const cronSearchHorizon = 5*366*24*time.Hour + time.Hour

// NextAfter 计算 from 之后的下一次触发时间（不含 from 本身，分钟级精度）。
func (s *CronSpec) NextAfter(from time.Time) (time.Time, error) {
	if s == nil {
		return time.Time{}, fmt.Errorf("%w：空规格", ErrInvalidCron)
	}
	t := from.Truncate(time.Minute).Add(time.Minute)
	deadline := t.Add(cronSearchHorizon)
	for t.Before(deadline) {
		if s.Match(t) {
			return t, nil
		}
		t = t.Add(time.Minute)
	}
	return time.Time{}, fmt.Errorf("%w：表达式在未来 5 年内无触发时间（请检查日/月组合）", ErrInvalidCron)
}
