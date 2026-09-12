//go:build wdsp_testkeys

package license

import (
	"encoding/hex"
	"testing"
)

func TestLoadVendorKeysTestBuildAllowsExplicitRuntimeKey(t *testing.T) {
	embeddedPub, _ := newTestKey(t, "embedded-key")
	envPub, _ := newTestKey(t, "env-key")
	original := embeddedVendorKeys
	t.Cleanup(func() { embeddedVendorKeys = original })
	embeddedVendorKeys = "embedded-key:" + hex.EncodeToString(embeddedPub)
	t.Setenv("LICENSE_VENDOR_PUBLIC_KEY", "env-key:"+hex.EncodeToString(envPub))

	keys := LoadVendorKeys()
	if _, ok := keys["embedded-key"]; ok {
		t.Fatal("测试构建应使用显式临时公钥，而不是内嵌正式信任根")
	}
	if len(keys) != 1 || !keys["env-key"].Equal(envPub) {
		t.Fatalf("应只加载测试环境变量中的公钥，got %d 条", len(keys))
	}
}
