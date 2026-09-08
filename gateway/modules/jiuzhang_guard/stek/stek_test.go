// stek 模块测试：注册、固定键供给、非法键拒绝、静态不轮换语义。
package stek

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func keyHex(b byte) string {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return hex.EncodeToString(k)
}

func TestModuleRegistered(t *testing.T) {
	m := JiuzhangSTEK{}
	info := m.CaddyModule()
	if info.ID != "tls.stek.jiuzhang" {
		t.Fatalf("模块 ID: %s", info.ID)
	}
}

func TestInitializeReturnsStaticKeys(t *testing.T) {
	j := &JiuzhangSTEK{KeysHex: []string{keyHex(0x01), keyHex(0x02)}}
	keys, err := j.Initialize(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0][0] != 0x01 || keys[1][0] != 0x02 {
		t.Fatalf("键不符: %v", keys)
	}
}

func TestInitializeRejectsBadKeys(t *testing.T) {
	cases := []struct {
		name string
		keys []string
		want string
	}{
		{"空列表", nil, "至少 1 个"},
		{"非 hex", []string{"zz"}, "32 字节 hex"},
		{"长度不足", []string{"abcd"}, "32 字节 hex"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			j := &JiuzhangSTEK{KeysHex: tc.keys}
			_, err := j.Initialize(nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("期望错误含 %q: %v", tc.want, err)
			}
		})
	}
}

func TestNextNeverRotates(t *testing.T) {
	j := &JiuzhangSTEK{}
	done := make(chan struct{})
	ch := j.Next(done)
	select {
	case keys := <-ch:
		t.Fatalf("静态键不应推新: %v", keys)
	case <-time.After(50 * time.Millisecond):
	}
	close(done)
	// done 关闭后通道应关闭（资源清理）
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("done 关闭后通道应关闭")
		}
	case <-time.After(50 * time.Millisecond):
		t.Fatal("done 关闭后通道未及时关闭")
	}
}
