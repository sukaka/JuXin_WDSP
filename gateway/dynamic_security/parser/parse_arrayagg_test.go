// parse_arrayagg_test.go 数组长度登记与数值聚合留存单测（任务书 §23 数量一致/汇总关系原料）：
// 长度登记无条件 O(1)；聚合趟仅 RetainJSONScalarValues 时执行，只留 sum/count 聚合量；
// 单数组超 maxArrayAggElements 置 Truncated（只记前 N 个）；聚合趟超 maxNumAggOps 置
// NumAggCapped；嵌套数组不重复累计。
package parser

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// parseAggBody 以 RetainJSONScalarValues=on 解析 JSON body。
func parseAggBody(t *testing.T, body string) *Parsed {
	t.Helper()
	r, _ := http.NewRequest(http.MethodPost, "http://x/api", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	limits := dsctx.DefaultParseLimits()
	limits.RetainJSONScalarValues = true
	p, err := ParseRequest(r, dsctx.New("r-agg", limits))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// 数组长度登记：无条件（含 RetainJSONScalarValues=off），object 内数组与根数组均登记。
func TestParseRequestArrayLen(t *testing.T) {
	p := parseAggBody(t, `{"items":[{"price":1},{"price":2},{"price":3}],"tags":["a","b"],"empty":[],"item_count":3}`)
	if p.JSONArrayLen["items"] != 3 || p.JSONArrayLen["tags"] != 2 || p.JSONArrayLen["empty"] != 0 {
		t.Fatalf("array lengths wrong: %v", p.JSONArrayLen)
	}
	if _, ok := p.JSONArrayLen["item_count"]; ok {
		t.Fatalf("scalar must not be registered as array: %v", p.JSONArrayLen)
	}

	// 关闭标量留存：长度登记仍在（O(1) 元数据），聚合趟不执行
	r, _ := http.NewRequest(http.MethodPost, "http://x/api", strings.NewReader(`{"items":[1,2,3]}`))
	r.Header.Set("Content-Type", "application/json")
	p2, err := ParseRequest(r, dsctx.New("r-agg-off", dsctx.DefaultParseLimits()))
	if err != nil {
		t.Fatal(err)
	}
	if p2.JSONArrayLen["items"] != 3 {
		t.Fatalf("array length must be registered without retention: %v", p2.JSONArrayLen)
	}
	if len(p2.JSONNumAgg) != 0 {
		t.Fatalf("aggregation must be off without retention: %v", p2.JSONNumAgg)
	}
}

// 数值聚合：对象数组子孙数值（items[].price）与纯数值数组（scores[]）均只留 sum/count。
func TestParseRequestNumAgg(t *testing.T) {
	p := parseAggBody(t, `{"items":[{"price":10.5,"name":"a"},{"price":20,"name":"b"},{"price":30.25}],"scores":[1,2,3],"total":60.75}`)

	agg, ok := p.JSONNumAgg["items[].price"]
	if !ok || agg.Count != 3 || agg.Truncated {
		t.Fatalf("items[].price agg wrong: %+v", agg)
	}
	if agg.Sum < 60.75-1e-9 || agg.Sum > 60.75+1e-9 {
		t.Fatalf("items[].price sum = %v, want ~60.75", agg.Sum)
	}
	agg, ok = p.JSONNumAgg["scores[]"]
	if !ok || agg.Count != 3 || agg.Sum != 6 {
		t.Fatalf("scores[] agg wrong: %+v", agg)
	}
	// 非数组子孙数值（total / items[].name 字符串）不登记聚合
	if _, ok := p.JSONNumAgg["total"]; ok {
		t.Fatalf("non-array numeric must not be aggregated: %v", p.JSONNumAgg)
	}
	if _, ok := p.JSONNumAgg["items[].name"]; ok {
		t.Fatalf("string elements must not be aggregated: %v", p.JSONNumAgg)
	}
	if p.NumAggCapped {
		t.Fatal("small doc must not cap aggregation")
	}
}

// 单数组超 maxArrayAggElements：只聚合前 N 个并置 Truncated（汇总关系据此不判定）。
func TestParseRequestNumAggTruncated(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`{"scores":[`)
	for i := 0; i < maxArrayAggElements+10; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprint(&sb, i+1) // 1..N+10
	}
	sb.WriteString(`]}`)
	p := parseAggBody(t, sb.String())

	if p.JSONArrayLen["scores"] != maxArrayAggElements+10 {
		t.Fatalf("full array length must be registered: %d", p.JSONArrayLen["scores"])
	}
	agg, ok := p.JSONNumAgg["scores[]"]
	if !ok || !agg.Truncated {
		t.Fatalf("oversized array agg must be truncated: %+v", agg)
	}
	if agg.Count != maxArrayAggElements {
		t.Fatalf("agg count = %d, want first %d elements only", agg.Count, maxArrayAggElements)
	}
	want := float64(maxArrayAggElements*(maxArrayAggElements+1)) / 2 // 1..N 求和
	if agg.Sum != want {
		t.Fatalf("agg sum = %v, want %v (first N only)", agg.Sum, want)
	}
}

// 聚合趟总预算：超 maxNumAggOps 置 NumAggCapped（本请求汇总关系全部不判定）。
func TestParseRequestNumAggBudgetCapped(t *testing.T) {
	// 宽对象：字段数在 FieldCount 配额内（2048）但聚合步数预算更小……
	// 默认 maxNumAggOps=2048 与 MaxFieldCount=2048 同量级，用窄预算放大扇出：
	// 嵌套数组 8×8×8=512 叶数值 + 容器开销仍小于默认预算，改为直接断言
	// 预算语义：构造超过预算步数的文档（每层 64 元素 × 3 层 = 26 万步潜在）。
	var sb strings.Builder
	sb.WriteString(`{"m":[`)
	for i := 0; i < maxArrayAggElements; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteByte('[')
		for j := 0; j < maxArrayAggElements; j++ {
			if j > 0 {
				sb.WriteByte(',')
			}
			fmt.Fprintf(&sb, "[%d,%d]", j+1, j+2)
		}
		sb.WriteByte(']')
	}
	sb.WriteString(`]}`)
	p := parseAggBody(t, sb.String())
	if !p.NumAggCapped {
		t.Fatal("fan-out doc must exhaust aggregation budget")
	}
}

// 嵌套数组不重复累计：items[].tags[] 的 sum 须恰好等于全体元素的和（首元素不被双计）。
func TestParseRequestNumAggNestedNoDoubleCount(t *testing.T) {
	p := parseAggBody(t, `{"items":[{"tags":[1,2]},{"tags":[3]}]}`)
	agg, ok := p.JSONNumAgg["items[].tags[]"]
	if !ok || agg.Count != 3 || agg.Sum != 6 {
		t.Fatalf("nested agg must count each element exactly once: %+v", agg)
	}
	if p.JSONArrayLen["items"] != 2 || p.JSONArrayLen["items[].tags"] != 2 {
		t.Fatalf("nested array lengths wrong: %v", p.JSONArrayLen)
	}
}

// 非 JSON / 截断体：聚合趟不执行（截断体非完整 JSON，walkJSON 同样跳过）。
func TestParseRequestNumAggSkipsNonJSON(t *testing.T) {
	r, _ := http.NewRequest(http.MethodPost, "http://x/api", strings.NewReader("a=1&b=2"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	limits := dsctx.DefaultParseLimits()
	limits.RetainJSONScalarValues = true
	p, err := ParseRequest(r, dsctx.New("r-agg-form", limits))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.JSONNumAgg) != 0 || len(p.JSONArrayLen) != 0 {
		t.Fatalf("form body must not produce array aggregates: %v %v", p.JSONNumAgg, p.JSONArrayLen)
	}
}
