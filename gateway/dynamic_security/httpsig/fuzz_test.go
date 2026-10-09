// fuzz_test.go httpsig Go native fuzz（SF 头输入变异+随机语料——无 panic 无
// 越界读；错误必属三分类（ErrMalformed/ErrBudget/ErrVerify）之一或成功）。
package httpsig

import (
	"errors"
	"testing"
)

// FuzzParseHeaders 头解析模糊目标（语料：合法签名头/缺参/多标签/畸形 SF/
// 预算边界形态/随机）。
func FuzzParseHeaders(f *testing.F) {
	validInput := `sig1=("@method" "@authority" "@path");created=1618884473;expires=1618884593;nonce="n8f6kfs9.2gkf0s9";keyid="k1";alg="ed25519"`
	validSig := `sig1=:dGVzdA==:`
	seeds := []struct{ input, sig string }{
		{validInput, validSig},
		{`sig1=();created=1;expires=2;nonce="n";keyid="k";alg="ed25519"`, `sig1=::`},
		{`sig1=("@query-param";name="x");created=1;expires=2;nonce="n";keyid="k";alg="rsa-pss-sha512"`, validSig},
		{validInput + `;tag="header-example"`, validSig},
		{validInput + "," + validInput, validSig},
		{`sig1=("@method")`, validSig},
		{`sig1=42;created=1;expires=2;nonce="n";keyid="k";alg="x"`, validSig},
		{validInput, `sig1="notbytes"`},
		{validInput, validSig + "," + validSig},
		{``, ``},
		{`sig1=("@method",`, validSig},
		{`sig1=("@method");created=abc;expires=2;nonce="n";keyid="k";alg="x"`, validSig},
		{`sig1=("@method" ; req "@path") ;created=1;expires=2;nonce="n";keyid="k";alg="ed25519"`, validSig},
	}
	for _, s := range seeds {
		f.Add(s.input, s.sig)
	}
	f.Fuzz(func(t *testing.T, input, sig string) {
		p, err := ParseHeaders(input, sig, Budgets{})
		if err != nil {
			if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrBudget) {
				t.Fatalf("未分类错误: %v", err)
			}
			return
		}
		// 成功不变量：五参数齐全 + 成分预算内
		if p.KeyID == "" || p.Alg == "" || p.Nonce == "" || p.Created == 0 || p.Expires == 0 {
			t.Fatal("齐全性逃逸")
		}
		b := DefaultBudgets()
		if len(p.CoveredComponents) > b.MaxComponents {
			t.Fatal("成分数预算逃逸")
		}
		for _, c := range p.CoveredComponents {
			if len(c) > b.MaxComponentNameLen {
				t.Fatal("成分名长预算逃逸")
			}
			if !validComponentName(c) {
				t.Fatalf("非法成分名 %q 逃逸", c)
			}
		}
	})
}
