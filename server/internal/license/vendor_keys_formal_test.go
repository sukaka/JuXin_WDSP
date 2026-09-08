//go:build !wdsp_testkeys

package license

import (
	"encoding/hex"
	"testing"
)

func TestLoadVendorKeysIgnoresRuntimeEnvOverride(t *testing.T) {
	embeddedPub, _ := newTestKey(t, "embedded-key")
	envPub, _ := newTestKey(t, "env-key")
	original := embeddedVendorKeys
	t.Cleanup(func() { embeddedVendorKeys = original })
	embeddedVendorKeys = "embedded-key:" + hex.EncodeToString(embeddedPub)
	t.Setenv("LICENSE_VENDOR_PUBLIC_KEY", "env-key:"+hex.EncodeToString(envPub))

	keys := LoadVendorKeys()
	if _, ok := keys["env-key"]; ok {
		t.Fatal("正式构建不应允许运行时环境变量替换内嵌信任根")
	}
	if len(keys) != 1 || !keys["embedded-key"].Equal(embeddedPub) {
		t.Fatalf("应只加载内嵌公钥表，got %d 条", len(keys))
	}
}
