// fuzz_test.go mcprpc Go native fuzz（M03 断言形态：任意字节序列无 panic 无
// 越界读；错误必属三分类（ErrMalformed/ErrBudget/ErrShape）；成功者读数必在
// 预算内——语料覆盖合法消息变异/嵌套/大串/重复键/批处理/标量/截断/随机）。
package mcprpc

import (
	"errors"
	"strings"
	"testing"
)

// FuzzParseMessage 消息解析模糊目标。
func FuzzParseMessage(f *testing.F) {
	seeds := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`,
		`{"jsonrpc":"2.0","method":"x","params":{"a":{"b":{"c":[1,{"d":2,"d":3}]}}}}`,
		`{"jsonrpc":"2.0","method":"x","params":{"s":"` + strings.Repeat("a", 1024) + `"}}`,
		`[{"jsonrpc":"2.0","id":1,"method":"a"}]`,
		`{"jsonrpc":"1.0","method":"x"}`,
		`{"jsonrpc":"2.0","method":123}`,
		`{"jsonrpc":"2.0","method":"x"}`,
		`{"jsonrpc":"2.0"`,
		`"scalar"`, `123`, `true`, `null`, `[]`, `{}`,
		`{"jsonrpc":"2.0","id":null,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":"` + strings.Repeat("i", 512) + `","method":"ping"}`,
		`{"jsonrpc":"2.0","method":"x","params":[[[[[[[[[[1]]]]]]]]]]}`,
		`{"jsonrpc":"2.0","method":"x","params":{"k":1,"k":2,"k":3}}`,
		`{"jsonrpc":"2.0","method":"x","params":{"esc":"a\/b\"\\"}}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := ParseMessage(data, Budgets{})
		if err != nil {
			// 错误必须已分类（三分类哨兵之一）——未知错误类即契约破坏
			if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrBudget) && !errors.Is(err, ErrShape) {
				t.Fatalf("未分类错误: %v", err)
			}
			return
		}
		// 成功路径：读数必在预算内；形态字段一致（method 可为空串——
		// JSON-RPC 语义上空方法名合法（词表核对属 B2），解析层不误拒）
		b := DefaultBudgets()
		if m.Stats.Depth > b.MaxDepth || m.Stats.Values > b.MaxValues || m.Stats.Bytes > b.MaxMessageBytes {
			t.Fatalf("预算逃逸: %+v", m.Stats)
		}
		if len(m.Stats.DuplicatePaths) > maxDuplicatePaths {
			t.Fatalf("重复键登记超上限: %d", len(m.Stats.DuplicatePaths))
		}
		if m.HasID && m.ID == nil {
			t.Fatal("HasID 与 ID 不一致")
		}
		if !m.HasID && m.ID != nil {
			t.Fatal("HasID=false 但 ID 非 nil")
		}
	})
}

// FuzzSSEReader SSE 读取器模糊目标：任意字节序列无 panic、无挂死、
// 错误仅 io.EOF/ErrBudget 二类、事件 data 不超单事件预算。
func FuzzSSEReader(f *testing.F) {
	seeds := []string{
		"data: a\n\ndata: b\n\n",
		"data: l1\ndata: l2\n\n",
		": keepalive\n\n",
		"event: x\nid: 1\ndata: y\n\n",
		"data: a\r\n\r\ndata: b\r\r",
		"garbage\n\n\n",
		"data: partial",
		"\xef\xbb\xbfdata: bom\n\n",
		"data: " + strings.Repeat("x", 4096) + "\n\n",
		"\n\n\n\n",
		"da\rta: x\n\n",
	}
	for _, s := range seeds {
		f.Add(s, uint16(1024))
	}
	f.Fuzz(func(t *testing.T, data string, maxEvent uint16) {
		cap := int(maxEvent%4096) + 1
		r := NewSSEReader(strings.NewReader(data), cap)
		for i := 0; i < 10000; i++ { // 迭代硬上限（不得挂死）
			ev, err := r.Next()
			if err != nil {
				if err != nil && !errors.Is(err, ErrBudget) && err.Error() != "EOF" {
					t.Fatalf("未分类错误: %v", err)
				}
				return
			}
			if ev == nil {
				t.Fatal("nil 事件 nil 错误")
			}
			if len(ev.Data) > cap {
				t.Fatalf("事件 data 超预算: %d > %d", len(ev.Data), cap)
			}
		}
		t.Fatal("迭代超上限（疑似挂死）")
	})
}
