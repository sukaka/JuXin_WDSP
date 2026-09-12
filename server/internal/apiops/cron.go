// cron.go 最小五段 cron 解析器（分 时 日 月 周）——server/go.mod 无 robfig/cron，
// 按任务书口径不新增第三方依赖，自实现分钟级「到点判定」所需的解析与下次时间计算。
//
// 支持语法（标准 Vixie 子集，仅数字，不支持 JAN/MON 等名字）：
//   - `*`（任意）、`*/n`（步进）、`a`（单值）、`a-b`（范围）、`a-b/n`（范围步进）、
//     `a/n`（等价 a-max/n）、逗号列表（如 `1,15`、`0-6/2,9`）；
//   - 周字段 0 与 7 均表示周日；
//   - 日/周同时受限时按 Vixie 语义取「或」（任一命中即执行），仅一方受限时取「与」；
//   - 宏：@hourly / @daily / @midnight / @weekly / @monthly / @yearly / @annually。
package apiops

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// cronMacros 宏展开表。
var cronMacros = map[string]string{
	"@hourly":   "0 * * * *",
	"@daily":    "0 0 * * *",
	"@midnight": "0 0 * * *",
	"@weekly":   "0 0 * * 0",
	"@monthly":  "0 0 1 * *",
	"@yearly":   "0 0 1 1 *",
	"@annually": "0 0 1 1 *",
}

// cronField 单段解析结果：allowed 命中值集合，any 表示该段为「*」（日/周「或」语义判定用）。
type cronField struct {
	allowed map[int]bool
	any     bool
}

// cronSpec 五段 cron 解析结果。
type cronSpec struct {
	minute cronField // 0-59
	hour   cronField // 0-23
	dom    cronField // 1-31
	month  cronField // 1-12
	dow    cronField // 0-6（0=周日；表达式中的 7 已归一为 0）
}

// ParseCron 解析五段 cron 表达式（含宏），非法返回包装后的 ErrInvalidCron。
func ParseCron(expr string) (*cronSpec, error) {
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
	spec := &cronSpec{}
	out := make([]cronField, 5)
	for i, f := range fields {
		parsed, err := parseCronField(f, bounds[i][0], bounds[i][1])
		if err != nil {
			return nil, fmt.Errorf("%w：%s段 %q：%v", ErrInvalidCron, names[i], f, err)
		}
		out[i] = parsed
	}
	spec.minute, spec.hour, spec.dom, spec.month, spec.dow = out[0], out[1], out[2], out[3], out[4]
	// 周日归一：7 → 0
	if spec.dow.allowed[7] {
		spec.dow.allowed[0] = true
		delete(spec.dow.allowed, 7)
	}
	return spec, nil
}

// parseCronField 解析单段：逗号分隔的若干项，每项为 `*` / `a` / `a-b`，可带 `/n` 步进。
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
			// 保持 [min, max]
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
			} // 带步进的单值 a/n 表示 a-max/n
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

// match 判定时刻是否命中（调用方须保证 t 精确到分钟）。
func (s *cronSpec) match(t time.Time) bool {
	if !s.minute.allowed[t.Minute()] || !s.hour.allowed[t.Hour()] || !s.month.allowed[int(t.Month())] {
		return false
	}
	domHit := s.dom.allowed[t.Day()]
	dowHit := s.dow.allowed[int(t.Weekday())]
	if !s.dom.any && !s.dow.any {
		return domHit || dowHit // Vixie 语义：日/周同时受限取「或」
	}
	return domHit && dowHit
}

// cronSearchHorizon 下次时间搜索上限（5 年：覆盖 2 月 29 日等稀疏表达式；永不命中的
// 表达式——如 2 月 30 日——超限报错而非死循环）。
const cronSearchHorizon = 5*366*24*time.Hour + time.Hour

// NextAfter 计算 from 之后的下一次触发时间（不含 from 本身，分钟精度，继承 from 时区）。
func (s *cronSpec) NextAfter(from time.Time) (time.Time, error) {
	t := from.Truncate(time.Minute).Add(time.Minute)
	deadline := t.Add(cronSearchHorizon)
	for t.Before(deadline) {
		if s.match(t) {
			return t, nil
		}
		t = t.Add(time.Minute)
	}
	return time.Time{}, fmt.Errorf("%w：表达式在未来 5 年内无触发时间（检查日/月组合是否自相矛盾）", ErrInvalidCron)
}

// NextCronAfter 解析并计算下次触发时间（计划写入/启停/调度共用的便利入口）。
func NextCronAfter(expr string, from time.Time) (time.Time, error) {
	spec, err := ParseCron(expr)
	if err != nil {
		return time.Time{}, err
	}
	return spec.NextAfter(from)
}
