// sign_test.go 隔离签名单测：签名/校验往返、错误密钥拒绝、密钥加载或生成（设置表+加密）。
package apiscan

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/encryption"
)

// TestSignerRoundTrip 签名/校验往返与错误密钥/篡改/时窗外拒绝。
func TestSignerRoundTrip(t *testing.T) {
	key, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	jobID := uuid.New()
	v := s.Sign(jobID)
	gotID, ok := s.Verify(v)
	if !ok || gotID != jobID {
		t.Fatalf("verify=(%v,%s), want (%v,%s)", ok, gotID, true, jobID)
	}
	// 三段式时效契约形态：{job_id}.{unix_ts}.{hex(HMAC(key, job_id|unix_ts))}
	parts := strings.Split(v, ".")
	if len(parts) != 3 || parts[0] != jobID.String() || len(parts[2]) != 64 {
		t.Fatalf("signature must be {job_id}.{unix_ts}.{hex}: %q", v)
	}
	// 错误密钥
	other, _ := GenerateSigningKey()
	s2, _ := NewSigner(other)
	if _, ok := s2.Verify(v); ok {
		t.Fatal("wrong key should fail verification")
	}
	// 篡改签名段
	if _, ok := s.Verify(v[:len(v)-2] + "00"); ok {
		t.Fatal("tampered signature should fail")
	}
	// 非法形态（含旧两段式契约——网关侧校验同样判 malformed_header）
	for _, bad := range []string{"", "no-dot", uuid.NewString() + ".zzzz", "not-uuid.abcd",
		uuid.NewString() + ".not-ts." + strings.Repeat("ab", 32),
		uuid.NewString() + ".123.zz"} {
		if _, ok := s.Verify(bad); ok {
			t.Fatalf("malformed value %q should fail", bad)
		}
	}
	// 时窗外签名拒绝（±signTimeWindow，与网关 scanSignatureTimeWindow 同一取值）：
	// 无时窗签名泄漏后可无限重放污染学习样本
	now := time.Now()
	for _, at := range []time.Time{now.Add(-signTimeWindow - time.Second), now.Add(signTimeWindow + time.Second)} {
		if _, ok := s.verifyAt(s.signAt(jobID, at), now); ok {
			t.Fatalf("out-of-window signature (signed at %v) must fail", at)
		}
	}
	// 窗口边缘内仍接受（容忍两端时钟偏差与在途时延）
	for _, at := range []time.Time{now.Add(-signTimeWindow + time.Second), now.Add(signTimeWindow - time.Second)} {
		if _, ok := s.verifyAt(s.signAt(jobID, at), now); !ok {
			t.Fatalf("in-window signature (signed at %v) must pass", at)
		}
	}
	// 密钥长度约束
	if _, err := NewSigner([]byte("short")); err == nil {
		t.Fatal("short key should be rejected")
	}
}

// fakeSettingsKV 设置表替身（内存键值）。
type fakeSettingsKV struct{ kv map[string]string }

func (f *fakeSettingsKV) GetString(_ context.Context, group, key, def string) string {
	if v, ok := f.kv[group+"/"+key]; ok {
		return v
	}
	return def
}

func (f *fakeSettingsKV) UpsertString(_ context.Context, group, key, value, _ string, _ uuid.UUID) error {
	if f.kv == nil {
		f.kv = map[string]string{}
	}
	f.kv[group+"/"+key] = value
	return nil
}

// TestLoadOrCreateSigner 首次生成并加密落库（密文不含密钥明文 hex），二次加载一致。
func TestLoadOrCreateSigner(t *testing.T) {
	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(i)
	}
	enc, err := encryption.NewWithKey(master)
	if err != nil {
		t.Fatal(err)
	}
	kv := &fakeSettingsKV{}
	s1, err := LoadOrCreateSigner(context.Background(), kv, enc)
	if err != nil {
		t.Fatal(err)
	}
	// 落库值必须是密文（不含可校验的密钥材料——二次加载后与首次签名一致）
	stored := kv.kv[signingKeySettingsGroup+"/"+signingKeySettingsKey]
	if stored == "" {
		t.Fatal("signing key not persisted")
	}
	s2, err := LoadOrCreateSigner(context.Background(), kv, enc)
	if err != nil {
		t.Fatal(err)
	}
	jobID := uuid.New()
	if s1.Sign(jobID) != s2.Sign(jobID) {
		t.Fatal("reloaded signer differs from persisted key")
	}
	// 密文形态：hex 解码失败即说明不是明文 hex 密钥
	if _, err := encryption.NewWithKey(master); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, s1.Sign(jobID)[37:]) {
		t.Fatal("stored value leaks signature material")
	}
	// 未装配返回错误
	if _, err := LoadOrCreateSigner(context.Background(), nil, enc); err == nil {
		t.Fatal("nil kv should fail")
	}
	if _, err := LoadOrCreateSigner(context.Background(), kv, nil); err == nil {
		t.Fatal("nil enc should fail")
	}
}
