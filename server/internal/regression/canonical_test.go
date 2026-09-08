// canonical_test.go 确定字节编码校验测试（重复键/非规范形/尾随内容/嵌套深度）。
package regression

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCanonicalAcceptsSortedCompact(t *testing.T) {
	v, err := ValidateCanonicalJSON([]byte(`{"a":1,"b":{"x":[1,1e2],"y":"<tag>"}}`))
	if err != nil {
		t.Fatalf("canonical rejected: %v", err)
	}
	if v["a"].(json.Number).String() != "1" {
		t.Fatalf("number not preserved: %v", v["a"])
	}
}

func TestCanonicalRejectsDuplicateKeys(t *testing.T) {
	for _, doc := range []string{
		`{"a":1,"a":2}`,
		`{"a":{"b":1,"b":2}}`,
		`{"a":[{"c":1,"c":2}]}`,
	} {
		if _, err := ValidateCanonicalJSON([]byte(doc)); err == nil {
			t.Fatalf("duplicate keys accepted: %s", doc)
		}
	}
}

func TestCanonicalRejectsNonCanonicalBytes(t *testing.T) {
	for _, doc := range []string{
		`{"b":1,"a":2}`,  // 键未排序
		`{ "a": 1 }`,     // 冗余空白
		"{\"a\":1}\n",    // 尾换行
		`{"a":"\u003c"}`, // 转义形态（规范形不转义 HTML，再编码必不等）
	} {
		if _, err := ValidateCanonicalJSON([]byte(doc)); err == nil {
			t.Fatalf("non-canonical accepted: %q", doc)
		}
	}
}

func TestCanonicalRejectsTrailingAndEmpty(t *testing.T) {
	if _, err := ValidateCanonicalJSON([]byte(`{"a":1} {"b":2}`)); err == nil {
		t.Fatal("trailing content accepted")
	}
	if _, err := ValidateCanonicalJSON([]byte(``)); err == nil {
		t.Fatal("empty accepted")
	}
}

func TestCanonicalRejectsDeepNesting(t *testing.T) {
	deep := strings.Repeat(`{"a":`, 201) + `1` + strings.Repeat(`}`, 201)
	if _, err := ValidateCanonicalJSON([]byte(deep)); err == nil {
		t.Fatal("deep nesting accepted")
	}
}
