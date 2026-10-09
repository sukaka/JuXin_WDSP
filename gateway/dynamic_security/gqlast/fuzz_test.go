package gqlast

import (
	"strings"
	"testing"
)

// FuzzParseBounded 恶意输入快验：任意字节序列不得导致 panic 或超限返回
// （解析资源硬边界对所有输入成立——递归下降库的栈放大由词法预扫兜底）。
func FuzzParseBounded(f *testing.F) {
	seeds := []string{
		"query { a }",
		"query { " + strings.Repeat("a { ", 40),
		`query { user(name: "张三alias{") { id } }`,
		"query A { a } query B { b } fragment X on T { ...X }",
		strings.Repeat("}", 500),
		"query { a(b: [1,2,3",
		"query { ...",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		doc, err := ParseBounded(in, Limits{})
		if err == nil && doc != nil {
			op, oerr := SelectOperation(doc, "")
			if oerr == nil {
				_ = CostOf(doc, op, WeightsConfig{}, BudgetConfig{})
			}
		}
	})
}
