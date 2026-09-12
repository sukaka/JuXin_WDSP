// semantic.go 参数语义类型护栏（字符串语义强制）：
// 口令/令牌/邮箱/手机号/UUID 类参数本质上是字符串——即使学习样本里的取值恰好
// 全是数字（如口令 "123456"、手机号 "13800001111"），也不得被学成 number/bool，
// 数值上下界（minimum/maximum）对这类参数没有意义（口令本身可以是任意复杂字符串）。
//
// 词表与 statistics.go 1c 语义推断 SQL 同口径，此处只取「字符串语义」子集
// （id/money 等允许数值形态的语义不在本护栏范围内）。
package apimodels

import "strings"

// stringOnlySemantics 字符串语义集合：命中这些语义的参数强制 base_type=string，
// 且不产出数值上下界约束。
var stringOnlySemantics = map[string]struct{}{
	"secret": {}, // 口令/密码类（password/passwd/pwd/secret）
	"token":  {}, // 令牌/密钥类（token/access_token/refresh_token/api_key/apikey）
	"email":  {},
	"phone":  {},
	"uuid":   {},
}

// inferStringSemantic 按参数名/结构化路径启发式识别字符串语义（与 statistics.go 1c
// 词表对齐；未命中返回空串）。供候选构建与观测物化在写 base_type 前做护栏判定。
func inferStringSemantic(name, path string) string {
	n := strings.ToLower(name)
	p := strings.ToLower(path)
	switch {
	case n == "password" || n == "passwd" || n == "pwd" || n == "secret":
		return "secret"
	case n == "token" || n == "access_token" || n == "refresh_token" || n == "api_key" || n == "apikey":
		return "token"
	case n == "email" || n == "mail" || n == "e_mail" || strings.Contains(n, "email"):
		return "email"
	case n == "phone" || n == "mobile" || n == "tel" || n == "telephone":
		return "phone"
	case strings.Contains(n, "uuid") || strings.Contains(p, "uuid"):
		return "uuid"
	}
	return ""
}

// isStringOnlySemantic 判定语义类型是否为字符串语义（含人工已确认的语义值）。
func isStringOnlySemantic(sem string) bool {
	_, ok := stringOnlySemantics[sem]
	return ok
}

// guardCandidateField 字符串语义护栏：命中字符串语义的观测字段强制 string 并清空
// 数值上下界（长度统计保留——长度约束对口令类参数仍有意义）。
func guardCandidateField(name, path string, f *CandidateField) {
	if sem := inferStringSemantic(name, path); isStringOnlySemantic(sem) {
		f.BaseType = "string"
		f.MinValue = nil
		f.MaxValue = nil
	}
}
