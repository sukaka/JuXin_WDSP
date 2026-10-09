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
