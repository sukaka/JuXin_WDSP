// sf_test.go RFC 8941 结构化字段解析子集黄金样本（规范 §3/附录原文示例逐字）
// + 畸形形态分类。
package httpsig

import (
	"strings"
	"testing"
)

// TestSFDictionaryGolden RFC 8941 原文示例黄金样本（逐字）。
func TestSFDictionaryGolden(t *testing.T) {
	// RFC 8941 §3.3 字典示例：en="Applepie", da=:w4ZibGV0w6ZydGU=:
	members, err := parseSFDictionary(`en="Applepie", da=:w4ZibGV0w6ZydGU=:`)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 2 || members[0].Key != "en" || members[0].Item.Value.Str != "Applepie" ||
		members[1].Key != "da" || string(members[1].Item.Value.Bytes) != "Æbletærte" {
		t.Fatalf("字典 1 = %+v", members)
	}
	// RFC 8941 §3.3：a=?0, b, c; foo=bar（布尔假/裸名真/参数）
	members, err = parseSFDictionary(`a=?0, b, c; foo=bar`)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 3 || members[0].Item.Value.Bool != false ||
		members[1].Item.Value.Kind != sfValueBool || members[1].Item.Value.Bool != true ||
		members[2].Item.Params[0].Name != "foo" || members[2].Item.Params[0].Value.Str != "bar" {
		t.Fatalf("字典 2 = %+v", members)
	}
	// RFC 8941 §3.3：a=(1 2), b=3, c=4;aa=bb, d=(5 6);valid（内列表+字典参数）
	members, err = parseSFDictionary(`a=(1 2), b=3, c=4;aa=bb, d=(5 6);valid`)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 4 || !members[0].IsList || len(members[0].Items) != 2 ||
		members[0].Items[0].Value.Int != 1 || members[1].Item.Value.Int != 3 ||
		members[2].Item.Params[0].Name != "aa" || !members[3].IsList ||
		members[3].ListParams[0].Name != "valid" || members[3].ListParams[0].Value.Kind != sfValueNone {
		t.Fatalf("字典 3 = %+v", members)
	}
	// 空字典合法
	members, err = parseSFDictionary("")
	if err != nil || len(members) != 0 {
		t.Fatalf("空字典 = %+v %v", members, err)
	}
	// 参数字符串转义（\" 与 \\ 仅此两形态）
	members, err = parseSFDictionary(`a="say \"hi\" \\"`)
	if err != nil || members[0].Item.Value.Str != `say "hi" \` {
		t.Fatalf("转义 = %+v %v", members, err)
	}
	// 整数负值与位宽
	members, err = parseSFDictionary(`a=-42`)
	if err != nil || members[0].Item.Value.Int != -42 {
		t.Fatalf("负整数 = %+v %v", members, err)
	}
	if _, err := parseSFDictionary(`a=1234567890123456`); err == nil {
		t.Fatal("16 位整数应拒（RFC 位宽上限）")
	}
}

// TestSFMalformed 畸形形态（ErrMalformed 经 ParseHeaders 包装层；本层为解析器
// 原文错误）。
func TestSFMalformed(t *testing.T) {
	for _, bad := range []string{
		`a="unterminated`,    // 未闭合字符串
		`a="bad\escape"`,     // 非法转义（仅 \" \\ 合法）
		"a=\"bad\x01char\"",  // 控制字符
		"a=1.5",              // decimal 不在 G1 子集
		"a=@1618884473",      // date 不在 G1 子集
		`a=%"display"`,       // display-string 不在 G1 子集
		`a=:c3VkZQ`,          // 未闭合 byte sequence
		"a=:c3Vk*ZQ==:",      // base64 非法字符
		`a=?2`,               // 非法布尔
		`A=1`,                // key 大写非法
		`a=1,,b=2`,           // 空成员
		`a=1,`,               // 尾逗号
		`a=(1 2`,             // 未闭合内列表
		`a=("x""y")`,         // 项间缺 SP
		`a=("x";q) trailing`, // 尾缀垃圾在字典层由成员分隔符校验拦截
	} {
		if _, err := parseSFDictionary(bad); err == nil {
			t.Errorf("%q 应拒", bad)
		}
	}
	// 参数 ';' 后 SP 合法（RFC 8941 §4.1.4 `*( ";" *SP parameter )`——
	// `a=(1; b=2)` = 内列表单项带参数 b=2，非畸形）
	members2, err := parseSFDictionary(`a=(1; b=2)`)
	if err != nil || len(members2) != 1 || members2[0].Items[0].Params[0].Name != "b" {
		t.Fatalf("参数 SP 形态应合法: %v %+v", err, members2)
	}
	// 键字符集：首字符数字非法
	if _, err := parseSFDictionary(`1a=1`); err == nil {
		t.Fatal("数字首键应拒")
	}
	// 未知参数裸名形态合法（;req 裸真值——RFC 9421 req 参数形态）
	members, err := parseSFDictionary(`sig1=("@method";req "@path")`)
	if err != nil {
		t.Fatalf("裸名参数应合法: %v", err)
	}
	if members[0].Items[0].Params[0].Name != "req" || members[0].Items[0].Params[0].Value.Kind != sfValueNone {
		t.Fatalf("裸名参数 = %+v", members[0].Items[0].Params)
	}
}

// TestSFRenderRoundtrip 参数序忠实重现（基线重构承载）：解析→渲染逐字节还原。
func TestSFRenderRoundtrip(t *testing.T) {
	input := `sig-b22=("@authority" "content-digest" "@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss";tag="header-example"`
	members, err := parseSFDictionary(input)
	if err != nil {
		t.Fatal(err)
	}
	m := members[0]
	// 重现：key=(items);params
	var sb strings.Builder
	sb.WriteString(m.Key)
	sb.WriteString("=(")
	for i, item := range m.Items {
		if i > 0 {
			sb.WriteString(" ")
		}
		sb.WriteString(renderSFValue(item.Value))
		sb.WriteString(renderSFParams(item.Params))
	}
	sb.WriteString(")")
	sb.WriteString(renderSFParams(m.ListParams))
	if sb.String() != input {
		t.Fatalf("重现不符:\n%q\n%q", sb.String(), input)
	}
}
