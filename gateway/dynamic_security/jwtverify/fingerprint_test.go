package jwtverify

import (
	"testing"
)

func TestPrincipalIDLengthPrefixDisambiguation(t *testing.T) {
	// ("ab","c") 与 ("a","bc") 简单拼接会产生相同输入，长度前缀必须区分。
	a, err := PrincipalID(testSecret, "ab", "c", "sub", "", false)
	if err != nil {
		t.Fatal(err)
	}
	b, err := PrincipalID(testSecret, "a", "bc", "sub", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("长度前缀未消除拼接歧义")
	}
}

func TestPrincipalIDTenantPresenceFlag(t *testing.T) {
	withFlag, _ := PrincipalID(testSecret, "app", "iss", "sub", "", true)
	without, _ := PrincipalID(testSecret, "app", "iss", "sub", "", false)
	if withFlag == without {
		t.Fatalf("tenant 存在标志位必须参与指纹")
	}
}

func TestPrincipalIDEmptySecret(t *testing.T) {
	if _, err := PrincipalID(nil, "app", "iss", "sub", "", false); err != ErrIdentitySecretRequired {
		t.Fatalf("空密钥应显式报错: %v", err)
	}
}

func TestPrincipalIDDeterministicAndKeyed(t *testing.T) {
	a1, _ := PrincipalID(testSecret, "app", "iss", "sub", "t", true)
	a2, _ := PrincipalID(testSecret, "app", "iss", "sub", "t", true)
	if a1 != a2 || len(a1) != 32 {
		t.Fatalf("指纹应稳定且为 32 字符 hex: %q", a1)
	}
	b, _ := PrincipalID([]byte("another-test-secret-key"), "app", "iss", "sub", "t", true)
	if a1 == b {
		t.Fatalf("不同密钥必须产生不同指纹")
	}
}
