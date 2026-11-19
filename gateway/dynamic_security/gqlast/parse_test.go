package gqlast

import (
	"strings"
	"testing"
)

func mustParse(t *testing.T, q string) *Document {
	t.Helper()
	d, err := ParseBounded(q, Limits{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return d
}

func mustErr(t *testing.T, q string, kind ErrorKind) *Error {
	t.Helper()
	_, err := ParseBounded(q, Limits{})
	if err == nil {
		t.Fatalf("期望错误 %s，实际成功", kind)
	}
	e, ok := err.(*Error)
	if !ok || e.Kind != kind {
		t.Fatalf("err=%v（期望 kind=%s）", err, kind)
	}
	return e
}

func TestNormalDeepQueryPasses(t *testing.T) {
	// GQ-N01：深度≈8 的正常查询 + 合法 fragment + 变量
	q := `query GetOrder($id: ID!, $detail: Boolean = true) {
  order(id: $id) {
    id
    buyer { ...UserParts }
    items {
      sku
      price
      attrs {
        k
        v
      }
    }
  }
}
fragment UserParts on User {
  id
  name
  profile {
    level
  }
}`
	d := mustParse(t, q)
	if d.Stats.Operations != 1 || d.Stats.Fragments != 1 {
		t.Fatalf("stats=%+v", d.Stats)
	}
	if !d.Stats.HasVariable {
		t.Fatal("变量未识别")
	}
	if d.Stats.Depth < 3 || d.Stats.Depth > 20 {
		t.Fatalf("depth=%d 不合理", d.Stats.Depth)
	}
	op, err := SelectOperation(d, "")
	if err != nil {
		t.Fatal(err)
	}
	if op.Kind != "query" || op.Name != "GetOrder" {
		t.Fatalf("op=%+v", op)
	}
}

func TestDocTooLarge(t *testing.T) {
	big := "query { f1" + strings.Repeat(" a", 70*1024) + " }"
	e := mustErr(t, big, ErrDocTooLarge)
	if !strings.Contains(e.Message, "超过硬上限") {
		t.Fatalf("msg=%s", e.Message)
	}
}

func TestTooDeepLexical(t *testing.T) {
	var b strings.Builder
	b.WriteString("query { ")
	for i := 0; i < 25; i++ {
		b.WriteString("a { ")
	}
	e := mustErr(t, b.String(), ErrTooDeep)
	if e.Kind != ErrTooDeep {
		t.Fatalf("e=%v", e)
	}
}

func TestTooManyAliases(t *testing.T) {
	var b strings.Builder
	b.WriteString("query { ")
	for i := 0; i < 120; i++ {
		b.WriteString("a: b ")
	}
	b.WriteString("}")
	e := mustErr(t, b.String(), ErrTooManyAliases)
	if e.Kind != ErrTooManyAliases {
		t.Fatalf("e=%v", e)
	}
}

func TestFragmentCycle(t *testing.T) {
	q := `query { user { ...A } }
fragment A on User { ...B }
fragment B on User { ...A }`
	e := mustErr(t, q, ErrFragmentCycle)
	if !strings.Contains(e.Message, "循环") {
		t.Fatalf("msg=%s", e.Message)
	}
}

func TestSyntaxError(t *testing.T) {
	e := mustErr(t, "query { user {{{ ", ErrSyntax)
	if e.Kind != ErrSyntax {
		t.Fatalf("e=%v", e)
	}
}

func TestSelectSingleOperationIgnoresName(t *testing.T) {
	d := mustParse(t, `mutation Incr { incr { n } }`)
	op, err := SelectOperation(d, "")
	if err != nil {
		t.Fatal(err)
	}
	if op.Kind != "mutation" {
		t.Fatalf("kind=%s", op.Kind)
	}
}

func TestMultiOperationWithoutName(t *testing.T) {
	d := mustParse(t, `query A { a } query B { b }`)
	if _, err := SelectOperation(d, ""); err == nil || err.(*Error).Kind != ErrMultipleOps {
		t.Fatalf("err=%v", err)
	}
}

func TestMultiOperationWithName(t *testing.T) {
	d := mustParse(t, `query A { a } mutation B { b }`)
	op, err := SelectOperation(d, "B")
	if err != nil {
		t.Fatal(err)
	}
	if op.Kind != "mutation" || op.Name != "B" {
		t.Fatalf("op=%+v", op)
	}
}

func TestMultiOperationNameNotFound(t *testing.T) {
	d := mustParse(t, `query A { a } query B { b }`)
	if _, err := SelectOperation(d, "C"); err == nil || err.(*Error).Kind != ErrOpNotFound {
		t.Fatalf("err=%v", err)
	}
}

func TestNoOperation(t *testing.T) {
	// 纯 fragment 文档（无 operation）
	e := mustErr(t, `fragment A on User { id }`, ErrNoOperation)
	if e.Kind != ErrNoOperation {
		t.Fatalf("e=%v", e)
	}
}

func TestSubscription(t *testing.T) {
	d := mustParse(t, `subscription OnMsg { msg { id } }`)
	op, err := SelectOperation(d, "")
	if err != nil {
		t.Fatal(err)
	}
	if op.Kind != "subscription" {
		t.Fatalf("kind=%s（首期仅登记不承诺流式，识别须如实）", op.Kind)
	}
}

func TestUnicodeAndCommentSafe(t *testing.T) {
	q := `query { # 注释含 { alias }
  user(name: "张三{alias}") {
    id
  }
}`
	d := mustParse(t, q)
	if d.Stats.Depth > 20 || d.Stats.Aliases > 100 {
		t.Fatalf("字符串/注释内容不得计入边界: %+v", d.Stats)
	}
}

func TestNodesBudget(t *testing.T) {
	var b strings.Builder
	b.WriteString("query { ")
	for i := 0; i < 30; i++ {
		b.WriteString("a { b { c } } ")
	}
	b.WriteString("}")
	lim := DefaultLimits()
	lim.MaxNodes = 10
	_, err := ParseBounded(b.String(), lim)
	if err == nil || err.(*Error).Kind != ErrTooManyNodes {
		t.Fatalf("err=%v", err)
	}
}

func TestC11FragmentDepthAliasAndDAGBomb(t *testing.T) {
	t.Run("fragment 链深度绕过被拦截", func(t *testing.T) {
		var b strings.Builder
		b.WriteString("query { a { ...F0 } }\n")
		for i := 0; i < 25; i++ {
			b.WriteString("fragment F")
			b.WriteString(strings.Repeat("", 0))
			b.WriteString(itoaForTest(i))
			b.WriteString(" on T { x { ...F")
			b.WriteString(itoaForTest(i + 1))
			b.WriteString(" } }\n")
		}
		b.WriteString("fragment F25 on T { leaf }\n")
		mustErr(t, b.String(), ErrTooDeep)
	})

	t.Run("fragment 展开 alias 绕过被拦截", func(t *testing.T) {
		q := `query { a { ...F1 } b { ...F1 } c { ...F1 } }
fragment F1 on T { ...F2 ...F3 }
fragment F2 on T { x1: f x2: f x3: f x4: f x5: f }
fragment F3 on T { y1: f y2: f y3: f y4: f y5: f }`
		lim := DefaultLimits()
		lim.MaxAliases = 20 // 展开后 3 * 10 = 30 > 20
		_, err := ParseBounded(q, lim)
		if err == nil || err.(*Error).Kind != ErrTooManyAliases {
			t.Fatalf("展开后超 alias 上限应返回 ErrTooManyAliases, got %v", err)
		}
	})

	t.Run("DAG 指数展开炸弹在线性时间内被拦截", func(t *testing.T) {
		var b strings.Builder
		b.WriteString("query { ...F0 }\n")
		for i := 0; i < 30; i++ {
			b.WriteString("fragment F" + itoaForTest(i) + " on T { x { ...F" + itoaForTest(i+1) + " } y { ...F" + itoaForTest(i+1) + " } }\n")
		}
		b.WriteString("fragment F30 on T { leaf }\n")
		lim := DefaultLimits()
		lim.MaxDepth = 50
		lim.MaxNodes = 1 << 20
		lim.MaxFragmentExp = 1000
		_, err := ParseBounded(b.String(), lim)
		if err == nil || err.(*Error).Kind != ErrTooManyNodes {
			t.Fatalf("DAG fragment 炸弹应触发 ErrTooManyNodes, got %v", err)
		}
	})

	t.Run("prescan 正确识别语法 alias 且不误伤字面量/参数/字段名 alias", func(t *testing.T) {
		// 正常查询含大量名为 "alias" 的字段与参数键值不误拒
		var benign strings.Builder
		benign.WriteString("query Q($id: ID!) { ")
		for i := 0; i < 15; i++ {
			benign.WriteString("alias(filter: { key: \"a:b\", k2: \"c:d\" }) ")
		}
		benign.WriteString("}")
		lim := DefaultLimits()
		lim.MaxAliases = 5
		if _, err := ParseBounded(benign.String(), lim); err != nil {
			t.Fatalf("字面量 alias 与参数键值不应触发 ErrTooManyAliases: %v", err)
		}

		// prescan 自身应对真实语法 alias 计数
		var bad strings.Builder
		bad.WriteString("query { ")
		for i := 0; i < 10; i++ {
			bad.WriteString("a" + itoaForTest(i) + ": field ")
		}
		bad.WriteString("}")
		if _, err := prescan(bad.String(), lim); err == nil || err.(*Error).Kind != ErrTooManyAliases {
			t.Fatalf("prescan 应识别真实语法 alias 超限, got %v", err)
		}
	})
}

func itoaForTest(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
