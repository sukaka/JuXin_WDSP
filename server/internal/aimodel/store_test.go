package aimodel

import (
	"context"
	"strings"
	"testing"
)

// TestCreateProviderKeyWithoutEncFails 携带密钥但加密服务未装配：创建整体报错，
// 不得静默丢弃用户密钥建出无密钥供应商（修复前 plainKey 被静默忽略）。
// 该路径在接触数据库之前返回，纯单元测试可覆盖；事务化落库链路需集成测试。
func TestCreateProviderKeyWithoutEncFails(t *testing.T) {
	s := NewStore(nil, nil)
	p := &Provider{Name: "p", Type: ProviderOpenAICompatible, BaseURL: "http://example.internal"}
	err := s.CreateProvider(context.Background(), p, "sk-plain")
	if err == nil || !strings.Contains(err.Error(), "encryption service unavailable") {
		t.Fatalf("err = %v, want encryption service unavailable", err)
	}
}

// TestSaveSecretWithoutEncFails saveSecret 在 enc 缺失时返回错误（RotateKey 同路径兜底）。
func TestSaveSecretWithoutEncFails(t *testing.T) {
	s := NewStore(nil, nil)
	if err := s.saveSecret(context.Background(), nil, "ref-1", "sk-plain"); err == nil {
		t.Fatal("enc 缺失时 saveSecret 应返回错误")
	}
}

func TestProviderOriginChanged(t *testing.T) {
	tests := []struct {
		name       string
		oldOrigin  string
		oldBaseURL string
		newOrigin  string
		want       bool
	}{
		{name: "same persisted origin", oldOrigin: "https://api.example.com:443", newOrigin: "https://api.example.com:443"},
		{name: "path change keeps credential", oldOrigin: "https://api.example.com:443", newOrigin: "https://api.example.com:443"},
		{name: "host change invalidates credential", oldOrigin: "https://api.example.com:443", newOrigin: "https://other.example.com:443", want: true},
		{name: "legacy row derives origin", oldBaseURL: "HTTPS://API.EXAMPLE.COM/v1", newOrigin: "https://api.example.com:443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := providerOriginChanged(tt.oldOrigin, tt.oldBaseURL, tt.newOrigin)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("changed=%v, want %v", got, tt.want)
			}
		})
	}
}
