// cron.go 最小五段 cron 解析与分钟级匹配器（分 时 日 月 周，支持标准 Vixie 子集与常用宏）。
// 不新增第三方依赖，风格对齐 server/internal/apiops/cron.go。
package threatintel

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

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

// CronSchedule 是解析后的五段 cron 调度表达式。
type CronSchedule struct {
	minute cronField // 0-59
	hour   cronField // 0-23
	dom    cronField // 1-31
	month  cronField // 1-12
	dow    cronField // 0-6（0=周日；7 已归一为 0）
}

// ParseCron 解析五段 cron 表达式（支持常见宏），非法时返回包装的 ErrInvalidCron。
func ParseCron(expr string) (*CronSchedule, error) {
	raw := strings.TrimSpace(strings.ToLower(expr))
	if raw == "" {
		return nil, fmt.Errorf("%w: 表达式不能为空", ErrInvalidCron)
	}
	if len(raw) > 64 {
		return nil, fmt.Errorf("%w: 表达式长度不能超过 64 字符", ErrInvalidCron)
	}
	if macro, ok := cronMacros[raw]; ok {
		raw = macro
	}
	fields := strings.Fields(raw)
	if len(fields) != 5 {
		return nil, fmt.Errorf("%w: 须为五段（分 时 日 月 周）或标准宏，实际 %d 段", ErrInvalidCron, len(fields))
	}
	bounds := [5][2]int{{0, 59}, {0, 23}, {1, 31}, {1, 12}, {0, 7}}
	names := [5]string{"分", "时", "日", "月", "周"}
	parsed := make([]cronField, 5)
	for i, f := range fields {
		cf, err := parseCronField(f, bounds[i][0], bounds[i][1])
		if err != nil {
			return nil, fmt.Errorf("%w: %s段 %q: %v", ErrInvalidCron, names[i], f, err)
		}
		parsed[i] = cf
	}
	spec := &CronSchedule{
		minute: parsed[0],
		hour:   parsed[1],
		dom:    parsed[2],
		month:  parsed[3],
		dow:    parsed[4],
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
			// [min, max]
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

// Match 判断时刻 t（按分钟精度）是否命中该 cron 表达式。
func (s *CronSchedule) Match(t time.Time) bool {
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

// NextAfter 返回 from 之后的下一次命中时刻（分钟精度）。
func (s *CronSchedule) NextAfter(from time.Time) (time.Time, error) {
	t := from.Truncate(time.Minute).Add(time.Minute)
	deadline := t.Add(cronSearchHorizon)
	for t.Before(deadline) {
		if s.Match(t) {
			return t, nil
		}
		t = t.Add(time.Minute)
	}
	return time.Time{}, fmt.Errorf("%w: 表达式在未来 5 年内无触发时间", ErrInvalidCron)
}

// ValidateCron 校验五段 cron 表达式语法及可达性（拒绝如 2 月 30 日等永不触发的表达式）。
func ValidateCron(expr string) error {
	spec, err := ParseCron(expr)
	if err != nil {
		return err
	}
	_, err = spec.NextAfter(time.Now().UTC())
	return err
}
