package detectors

import (
	"strings"
	"testing"
)

// 缓存基本机制：未命中→写入→命中同一产物；超容按 FIFO 逐出最旧键。
func TestCompileCacheHitAndFIFO(t *testing.T) {
	c := newCompileCache(2)
	if _, ok := c.load("a"); ok {
		t.Fatal("empty cache must miss")
	}
	c.store("a", 1)
	c.store("b", 2)
	if v, ok := c.load("a"); !ok || v.(int) != 1 {
		t.Fatal("stored value must hit")
	}
	c.store("c", 3) // 超容：逐出最旧的 a
	if _, ok := c.load("a"); ok {
		t.Fatal("oldest key must be evicted FIFO")
	}
	if _, ok := c.load("b"); !ok {
		t.Fatal("newer key must survive eviction")
	}
	// 重复写同键不产生新顺序项（不提前逐出）
	c.store("b", 22)
	if v, _ := c.load("b"); v.(int) != 22 {
		t.Fatal("rewrite same key must update value")
	}
}

// 敏感字段名模式编译缓存：同一内容两次编译返回同一产物（正则指针相同）；
// 错误同为确定性结果被缓存；内容不同键不同互不污染。
func TestCompileSensitivePatternsCached(t *testing.T) {
	in := []SensitivePattern{{DataType: "phone", Pattern: `(?i)phone`}}
	p1, err1 := CompileSensitivePatterns(in)
	p2, err2 := CompileSensitivePatterns(in)
	if err1 != nil || err2 != nil {
		t.Fatalf("compile: %v / %v", err1, err2)
	}
	if len(p1) != 1 || len(p2) != 1 || p1[0].re != p2[0].re {
		t.Fatal("same content must return cached compiled product")
	}
	// nil 入参（内置默认表）同样缓存
	d1, err := CompileSensitivePatterns(nil)
	if err != nil {
		t.Fatalf("compile default: %v", err)
	}
	d2, _ := CompileSensitivePatterns(nil)
	if len(d1) == 0 || d1[0].re != d2[0].re {
		t.Fatal("default table must be cached")
	}
	// 错误结果缓存：非法模式两次返回 error
	bad := []SensitivePattern{{DataType: "x", Pattern: "([unclosed"}}
	if _, err := CompileSensitivePatterns(bad); err == nil {
		t.Fatal("bad pattern must error")
	}
	if _, err := CompileSensitivePatterns(bad); err == nil {
		t.Fatal("cached bad pattern must still error (validation semantics unchanged)")
	}
}

// 值级规则编译缓存：同一内容命中同一产物；非法规则错误语义不变。
func TestCompileSensitiveValueRulesCached(t *testing.T) {
	in := []SensitiveValueRule{{DataType: "phone", Regex: `^1\d{10}$`, Locations: []string{"query"}}}
	r1, err := CompileSensitiveValueRules(in)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	r2, _ := CompileSensitiveValueRules(in)
	if len(r1) != 1 || len(r2) != 1 || r1[0].re != r2[0].re {
		t.Fatal("same content must return cached compiled product")
	}
	if _, err := CompileSensitiveValueRules([]SensitiveValueRule{{DataType: "x", Regex: "([bad", Locations: []string{"query"}}}); err == nil {
		t.Fatal("bad regex must error")
	}
}

// 约束正则编译缓存：同一 pattern 返回同一 *regexp.Regexp；超长/语法错误结果缓存且语义不变。
func TestCompileConstraintRegexCached(t *testing.T) {
	re1, err := CompileConstraintRegex("^[a-z]{1,3}$")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	re2, _ := CompileConstraintRegex("^[a-z]{1,3}$")
	if re1 != re2 {
		t.Fatal("same pattern must return cached *regexp.Regexp")
	}
	if _, err := CompileConstraintRegex(strings.Repeat("a", maxConstraintRegexLen+1)); err == nil {
		t.Fatal("oversized pattern must error")
	}
	if _, err := CompileConstraintRegex("([0-9"); err == nil {
		t.Fatal("syntax error must error")
	}
}
