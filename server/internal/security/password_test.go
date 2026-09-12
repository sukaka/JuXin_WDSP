package security

import (
	"strings"
	"testing"
)

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := HashPassword("S3cure!Passw0rd")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Errorf("unexpected hash format: %s", hash)
	}
	if err := VerifyPassword("S3cure!Passw0rd", hash); err != nil {
		t.Errorf("VerifyPassword(correct) error = %v", err)
	}
	if err := VerifyPassword("wrong", hash); err != ErrPasswordMismatch {
		t.Errorf("VerifyPassword(wrong) = %v, want ErrPasswordMismatch", err)
	}
}

func TestHashPasswordUniqueSalt(t *testing.T) {
	h1, _ := HashPassword("same-password-1A!")
	h2, _ := HashPassword("same-password-1A!")
	if h1 == h2 {
		t.Error("same password produced identical hashes (salt not random)")
	}
}

func TestValidatePassword(t *testing.T) {
	policy := DefaultPasswordPolicy()
	cases := []struct {
		name     string
		password string
		username string
		wantErr  bool
	}{
		{"valid", "Tr0ub4dor&3xtra", "zhangsan", false},
		{"too short", "Ab1!xyz", "zhangsan", true},
		{"no upper", "tr0ub4dor&extra", "zhangsan", true},
		{"no lower", "TR0UB4DOR&EXTRA", "zhangsan", true},
		{"no digit", "Troubadour&extra", "zhangsan", true},
		{"no special", "Tr0ub4dor3xtra", "zhangsan", true},
		{"equals username", "Zhangsan123!", "zhangsan", true},
		{"contains username", "xZhangsanY9!", "zhangsan", true},
		{"weak password", "admin123", "zhangsan", true},
		{"weak password2", "P@ssw0rd", "zhangsan", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidatePassword(c.password, c.username, policy)
			if c.wantErr && err == nil {
				t.Errorf("ValidatePassword(%q) = nil, want error", c.password)
			}
			if !c.wantErr && err != nil {
				t.Errorf("ValidatePassword(%q) = %v, want nil", c.password, err)
			}
		})
	}
}

func TestGenerateTemporaryPassword(t *testing.T) {
	policy := DefaultPasswordPolicy()
	for i := 0; i < 100; i++ {
		pwd, err := GenerateTemporaryPassword(16)
		if err != nil {
			t.Fatalf("GenerateTemporaryPassword() error = %v", err)
		}
		if len(pwd) != 16 {
			t.Errorf("length = %d, want 16", len(pwd))
		}
		if err := ValidatePassword(pwd, "anyuser", policy); err != nil {
			t.Errorf("generated password violates policy: %v (pwd=%s)", err, pwd)
		}
	}
}

func TestNewRandomToken(t *testing.T) {
	t1, err := NewRandomToken(32)
	if err != nil {
		t.Fatalf("NewRandomToken() error = %v", err)
	}
	t2, _ := NewRandomToken(32)
	if t1 == t2 {
		t.Error("tokens not random")
	}
	if len(t1) < 40 {
		t.Errorf("token too short: %d", len(t1))
	}
}
