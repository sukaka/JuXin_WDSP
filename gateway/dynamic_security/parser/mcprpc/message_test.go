// message_test.go JSON-RPC 消息解析黄金矩阵：正常提取/五维预算逐层边界
// （恰等/超 1）/重复键登记（深层嵌套）/批处理 ErrShape/非 JSON-RPC ErrMalformed/
// 全量解析不截断（M03 断言形态）。
package mcprpc

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// validMsg 合法消息基线（各用例在其上变异）。
const validMsg = `{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello"}}}`

func TestParseMessageOK(t *testing.T) {
	m, err := ParseMessage([]byte(validMsg), Budgets{})
	if err != nil {
		t.Fatalf("合法消息应通过: %v", err)
	}
	if m.Method != "tools/call" || !m.HasID || string(m.ID) != "42" {
		t.Fatalf("提取 = %+v", m)
	}
	if string(m.Params) != `{"name":"echo","arguments":{"text":"hello"}}` {
		t.Fatalf("params 原文 = %s", m.Params)
	}
	if string(m.Raw) != validMsg {
		t.Fatal("Raw 应为全体原文")
	}
	if m.Stats.Bytes != len(validMsg) || m.Stats.Values == 0 || m.Stats.Depth == 0 {
		t.Fatalf("读数 = %+v", m.Stats)
	}
	if len(m.Stats.DuplicatePaths) != 0 {
		t.Fatalf("无重复键: %v", m.Stats.DuplicatePaths)
	}
	// id 形态：字符串/ null / 缺席
	for _, tc := range []struct {
		raw, wantID string
		hasID       bool
	}{
		{`{"jsonrpc":"2.0","id":"abc-1","method":"ping"}`, `"abc-1"`, true},
		{`{"jsonrpc":"2.0","id":null,"method":"ping"}`, `null`, true}, // null id 视为存在
		{`{"jsonrpc":"2.0","method":"ping"}`, ``, false},
		{`{"jsonrpc":"2.0","id":1.5e3,"method":"ping"}`, `1.5e3`, true},
	} {
		m, err := ParseMessage([]byte(tc.raw), Budgets{})
		if err != nil {
			t.Fatalf("%s: %v", tc.raw, err)
		}
		if m.HasID != tc.hasID || string(m.ID) != tc.wantID {
			t.Errorf("%s: HasID=%v ID=%s", tc.raw, m.HasID, m.ID)
		}
	}
	// params 缺席 / 数组形态
	m2, err := ParseMessage([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`), Budgets{})
	if err != nil || m2.Params != nil {
		t.Fatalf("params 缺席应 nil: %v %s", err, m2.Params)
	}
	m3, err := ParseMessage([]byte(`{"jsonrpc":"2.0","id":1,"method":"x","params":[1,2,3]}`), Budgets{})
	if err != nil || string(m3.Params) != `[1,2,3]` {
		t.Fatalf("数组 params 原文: %v %s", err, m3.Params)
	}
}

// nestChain 构造 n 层嵌套（对象套对象）。
func nestChain(n int) string {
	var sb strings.Builder
	sb.WriteString(`{"jsonrpc":"2.0","method":"x","params":`)
	for i := 0; i < n; i++ {
		sb.WriteString(`{"a":`)
	}
	sb.WriteString(`1`)
	for i := 0; i < n; i++ {
		sb.WriteString(`}`)
	}
	sb.WriteString(`}`)
	return sb.String()
}

// nestArrayChain 构造 n 层数组嵌套。
func nestArrayChain(n int) string {
	var sb strings.Builder
	sb.WriteString(`{"jsonrpc":"2.0","method":"x","params":`)
	for i := 0; i < n; i++ {
		sb.WriteString(`[`)
	}
	for i := 0; i < n; i++ {
		sb.WriteString(`]`)
	}
	sb.WriteString(`}`)
	return sb.String()
}

func TestBudgetDepth(t *testing.T) {
	// params 容器为第 1 层：嵌套 31 层对象 + params = 32 层恰等通过；32 层对象 + params = 33 拒
	if _, err := ParseMessage([]byte(nestChain(31)), Budgets{}); err != nil {
		t.Fatalf("深度 32 恰等应通过: %v", err)
	}
	_, err := ParseMessage([]byte(nestChain(32)), Budgets{})
	var be *BudgetError
	if !errors.As(err, &be) || be.Rule != "depth_exceeded" || be.Limit != 32 || be.Actual != 33 {
		t.Fatalf("深度 33 应 depth_exceeded: %v", err)
	}
	// 数组嵌套同口径
	if _, err := ParseMessage([]byte(nestArrayChain(31)), Budgets{}); err != nil {
		t.Fatalf("数组深度 32 应通过: %v", err)
	}
	if _, err := ParseMessage([]byte(nestArrayChain(32)), Budgets{}); !errors.As(err, &be) || be.Rule != "depth_exceeded" {
		t.Fatalf("数组深度 33 应拒: %v", err)
	}
}

func TestBudgetArrayElements(t *testing.T) {
	mk := func(n int) string {
		parts := make([]string, n)
		for i := range parts {
			parts[i] = "1"
		}
		return `{"jsonrpc":"2.0","method":"x","params":[` + strings.Join(parts, ",") + `]}`
	}
	if _, err := ParseMessage([]byte(mk(4096)), Budgets{}); err != nil {
		t.Fatalf("4096 恰等应通过: %v", err)
	}
	_, err := ParseMessage([]byte(mk(4097)), Budgets{})
	var be *BudgetError
	if !errors.As(err, &be) || be.Rule != "array_exceeded" || be.Actual != 4097 {
		t.Fatalf("4097 应 array_exceeded: %v", err)
	}
}

func TestBudgetObjectMembers(t *testing.T) {
	mk := func(n int) string {
		parts := make([]string, n)
		for i := range parts {
			parts[i] = fmt.Sprintf(`"k%d":1`, i)
		}
		return `{"jsonrpc":"2.0","method":"x","params":{` + strings.Join(parts, ",") + `}}`
	}
	if _, err := ParseMessage([]byte(mk(2048)), Budgets{}); err != nil {
		t.Fatalf("2048 恰等应通过: %v", err)
	}
	_, err := ParseMessage([]byte(mk(2049)), Budgets{})
	var be *BudgetError
	if !errors.As(err, &be) || be.Rule != "object_members_exceeded" || be.Actual != 2049 {
		t.Fatalf("2049 应 object_members_exceeded: %v", err)
	}
}

func TestBudgetStringBytes(t *testing.T) {
	// 512KiB 恰等通过（原文内容口径）；512KiB+1 拒
	if _, err := ParseMessage([]byte(`{"jsonrpc":"2.0","method":"x","params":{"s":"`+strings.Repeat("a", 512<<10)+`"}}`), Budgets{}); err != nil {
		t.Fatalf("512KiB 恰等应通过: %v", err)
	}
	_, err := ParseMessage([]byte(`{"jsonrpc":"2.0","method":"x","params":{"s":"`+strings.Repeat("a", 512<<10+1)+`"}}`), Budgets{})
	var be *BudgetError
	if !errors.As(err, &be) || be.Rule != "string_exceeded" {
		t.Fatalf("512KiB+1 应 string_exceeded: %v", err)
	}
}

func TestBudgetValues(t *testing.T) {
	// 值数恰等与超 1（绕开数组 4096 单维上限——外层 16 个子数组：
	// 15×4096 + 1×4076 元素；总 = jsonrpc/method/params 3 + 根对象 1 +
	// 外层数组 1 + 子数组 16 + 元素 61440+4076 = 65536 恰等）
	mk := func(extra int) string {
		var sb strings.Builder
		sb.WriteString(`{"jsonrpc":"2.0","method":"x","params":[`)
		ones := strings.Repeat("1,", 4095) + "1"
		for i := 0; i < 15; i++ {
			sb.WriteString("[" + ones + "],")
		}
		last := make([]string, 4076+extra)
		for i := range last {
			last[i] = "1"
		}
		sb.WriteString("[" + strings.Join(last, ",") + "]]}")
		return sb.String()
	}
	m, err := ParseMessage([]byte(mk(0)), Budgets{})
	if err != nil {
		t.Fatalf("65536 恰等应通过: %v", err)
	}
	if m.Stats.Values != 65536 {
		t.Fatalf("读数 = %d，应恰 65536", m.Stats.Values)
	}
	_, err = ParseMessage([]byte(mk(1)), Budgets{})
	var be *BudgetError
	if !errors.As(err, &be) || be.Rule != "value_count_exceeded" {
		t.Fatalf("65537 应 value_count_exceeded: %v", err)
	}
}

func TestBudgetMessageBytes(t *testing.T) {
	_, err := ParseMessage(make([]byte, 4<<20+1), Budgets{})
	var be *BudgetError
	if !errors.As(err, &be) || be.Rule != "message_bytes_exceeded" {
		t.Fatalf("超 4MiB 应 message_bytes_exceeded: %v", err)
	}
}

// TestFullParseNotTruncated M03 断言形态：300KiB 串之后的深层内容仍全量解析
// （重复键在 300KiB 串之后仍登记——解析不经 256 字符截留）。
func TestFullParseNotTruncated(t *testing.T) {
	big := strings.Repeat("b", 300<<10)
	raw := `{"jsonrpc":"2.0","method":"x","params":{"pad":"` + big + `","tail":{"k":1,"k":2}}}`
	m, err := ParseMessage([]byte(raw), Budgets{})
	if err != nil {
		t.Fatalf("300KiB 串应全量解析: %v", err)
	}
	if len(m.Stats.DuplicatePaths) != 1 || m.Stats.DuplicatePaths[0] != "params.tail.k" {
		t.Fatalf("尾部重复键应命中（非截断解析）: %v", m.Stats.DuplicatePaths)
	}
}

func TestDuplicateKeyRegistration(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{"顶层重复", `{"jsonrpc":"2.0","method":"a","method":"b"}`, []string{"method"}},
		{"params 内重复", `{"jsonrpc":"2.0","method":"x","params":{"a":1,"a":2}}`, []string{"params.a"}},
		{"深层嵌套", `{"jsonrpc":"2.0","method":"x","params":{"a":{"b":{"c":1,"c":2}}}}`, []string{"params.a.b.c"}},
		{"数组内对象", `{"jsonrpc":"2.0","method":"x","params":{"arr":[{"k":1,"k":2}]}}`, []string{"params.arr[0].k"}},
		{"数组嵌数组内对象", `{"jsonrpc":"2.0","method":"x","params":[[[{"k":1,"k":2}]]]}`, []string{"params[0][0][0].k"}},
		{"转义键自身重复", `{"jsonrpc":"2.0","method":"x","params":{"a":1,"a":2,"a":3}}`, []string{"params.a", "params.a"}},
	}
	for _, tc := range cases {
		m, err := ParseMessage([]byte(tc.raw), Budgets{})
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if fmt.Sprint(m.Stats.DuplicatePaths) != fmt.Sprint(tc.want) {
			t.Errorf("%s: dups = %v，应 %v", tc.name, m.Stats.DuplicatePaths, tc.want)
		}
	}
	// 上限 16：第 17 条不再登记（校验继续不报错）
	var sb strings.Builder
	sb.WriteString(`{"jsonrpc":"2.0","method":"x","params":{`)
	for i := 0; i < 20; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `"k%d":[1,{"dup":1,"dup":2}]`, i)
	}
	sb.WriteString(`}}`)
	m, err := ParseMessage([]byte(sb.String()), Budgets{})
	if err != nil {
		t.Fatalf("超 16 登记上限应继续解析: %v", err)
	}
	if len(m.Stats.DuplicatePaths) != 16 {
		t.Fatalf("登记应恰 16 条: %d", len(m.Stats.DuplicatePaths))
	}
	if m.Stats.DuplicatePaths[0] != "params.k0[1].dup" {
		t.Fatalf("首条路径形态: %q", m.Stats.DuplicatePaths[0])
	}
}

func TestBatchShapeErrShape(t *testing.T) {
	for _, raw := range []string{
		`[{"jsonrpc":"2.0","id":1,"method":"a"}]`,
		`[{"jsonrpc":"2.0","id":1,"method":"a"},{"jsonrpc":"2.0","id":2,"method":"b"}]`,
		`[]`,
		" \t\n[1,2]",
	} {
		_, err := ParseMessage([]byte(raw), Budgets{})
		if !errors.Is(err, ErrShape) {
			t.Errorf("%s: 应 ErrShape: %v", raw, err)
		}
	}
}

func TestMalformedClassification(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"顶层字符串", `"hello"`},
		{"顶层数值", `123`},
		{"顶层布尔", `true`},
		{"顶层 null", `null`},
		{"缺 jsonrpc", `{"id":1,"method":"x"}`},
		{"jsonrpc 非 2.0", `{"jsonrpc":"1.0","method":"x"}`},
		{"jsonrpc 非字符串", `{"jsonrpc":2,"method":"x"}`},
		{"缺 method", `{"jsonrpc":"2.0","id":1}`},
		{"method 非字符串", `{"jsonrpc":"2.0","method":123}`},
		{"method 为对象", `{"jsonrpc":"2.0","method":{"x":1}}`},
		{"尾缀垃圾", `{"jsonrpc":"2.0","method":"x"} extra`},
		{"非法 JSON", `{"jsonrpc":`},
		{"未闭合对象", `{"jsonrpc":"2.0"`},
		{"未闭合字符串", `{"jsonrpc":"2.0","method":"x`},
		{"非法转义", `{"jsonrpc":"2.0","method":"\x"}`},
		{"非法 \\u 转义", `{"jsonrpc":"2.0","method":"\u12"}`},
		{"串内控制字符", "{\"jsonrpc\":\"2.0\",\"method\":\"a\x01b\"}"},
		{"前导零数值", `{"jsonrpc":"2.0","id":01,"method":"x"}`},
		{"非法字面量", `{"jsonrpc":"2.0","id":tru,"method":"x"}`},
		{"成员缺冒号", `{"jsonrpc" "2.0"}`},
		{"成员名非字符串", `{1:2}`},
		{"空输入", ``},
	}
	for _, tc := range cases {
		_, err := ParseMessage([]byte(tc.raw), Budgets{})
		if !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: 应 ErrMalformed: %v", tc.name, err)
		}
		if errors.Is(err, ErrBudget) || errors.Is(err, ErrShape) {
			t.Errorf("%s: 错误分类越界: %v", tc.name, err)
		}
	}
}

func TestBudgetsZeroValueDefaults(t *testing.T) {
	// 零值 Budgets 全字段按冻结默认兜底
	b := Budgets{}
	if _, err := ParseMessage([]byte(validMsg), b); err != nil {
		t.Fatal(err)
	}
	// 单字段覆盖：MaxDepth 收紧即拒，其余默认
	_, err := ParseMessage([]byte(nestChain(3)), Budgets{MaxDepth: 2})
	var be *BudgetError
	if !errors.As(err, &be) || be.Rule != "depth_exceeded" || be.Limit != 2 {
		t.Fatalf("单字段覆盖: %v", err)
	}
}

func TestParseMessageEscapes(t *testing.T) {
	// 合法转义全族 + \u 转义
	m, err := ParseMessage([]byte(`{"jsonrpc":"2.0","method":"a\/bA\"\\","id":"x"}`), Budgets{})
	if err != nil {
		t.Fatalf("转义族应通过: %v", err)
	}
	if m.Method != `a/bA"\` {
		t.Fatalf("method 解码 = %q", m.Method)
	}
}
