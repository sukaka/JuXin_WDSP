package securityevents

import (
	"testing"

	"github.com/google/uuid"
)

func TestMatchApplication(t *testing.T) {
	shopID := uuid.New()
	wildID := uuid.New()
	entries := map[string]appLinkEntry{
		"shop.example.com": {applicationID: shopID, applicationName: "商城"},
		"*.example.com":    {applicationID: wildID, applicationName: "泛域"},
	}
	cases := []struct {
		name     string
		host     string
		wantID   uuid.UUID
		wantName string
		wantOK   bool
	}{
		{"精确命中", "shop.example.com", shopID, "商城", true},
		{"带端口 Host", "shop.example.com:8080", shopID, "商城", true},
		{"大小写混合", "Shop.Example.COM", shopID, "商城", true},
		{"泛域名匹配子域", "a.example.com", wildID, "泛域", true},
		{"泛域名匹配根域", "example.com", wildID, "泛域", true},
		{"未命中", "other.test", uuid.Nil, "", false},
		{"非数字端口不剥离", "shop.example.com:abc", uuid.Nil, "", false},
		{"空 Host", "", uuid.Nil, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotID, gotName, gotOK := matchApplication(c.host, entries)
			if gotOK != c.wantOK {
				t.Fatalf("matchApplication(%q) ok = %v, want %v", c.host, gotOK, c.wantOK)
			}
			if gotID != c.wantID || gotName != c.wantName {
				t.Errorf("matchApplication(%q) = (%v, %q), want (%v, %q)",
					c.host, gotID, gotName, c.wantID, c.wantName)
			}
		})
	}
}

func TestMatchApplicationEmptyEntries(t *testing.T) {
	if _, _, ok := matchApplication("shop.example.com", nil); ok {
		t.Error("empty entries should not match")
	}
}
