// businesssec_test.go Business 滥用三判定器用例（内存假 BusinessRepository，无 DB）：
// 阈值判定、IP 反查归属（歧义跳过）、冷却去重、错误向上返回。
package attacksessions

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fakeBizRepo 滥用检测仓储假实现。
type fakeBizRepo struct {
	loginHits  []LoginAbuseHit
	exportHits []ExportAbuseHit
	enumHits   []ObjectEnumHit
	// ipIdentities ip → 身份；键存在但值为 nil = 多身份歧义（存疑不挂）
	ipIdentities map[string]*bizIdentity
	emitted      []BusinessEventInput
	emitErr      error
	fetchErr     error
}

type bizIdentity struct {
	id  uuid.UUID
	key string
}

func newFakeBizRepo() *fakeBizRepo {
	return &fakeBizRepo{ipIdentities: map[string]*bizIdentity{}}
}

func (f *fakeBizRepo) FetchLoginAbuseCandidates(_ context.Context, _ time.Time, _ int) ([]LoginAbuseHit, error) {
	if f.fetchErr != nil {
		return nil, f.fetchErr
	}
	return f.loginHits, nil
}

func (f *fakeBizRepo) FetchExportAbuse(_ context.Context, _ time.Time, _ int) ([]ExportAbuseHit, error) {
	if f.fetchErr != nil {
		return nil, f.fetchErr
	}
	return f.exportHits, nil
}

func (f *fakeBizRepo) FetchObjectEnum(_ context.Context, _ time.Time, _ int) ([]ObjectEnumHit, error) {
	if f.fetchErr != nil {
		return nil, f.fetchErr
	}
	return f.enumHits, nil
}

func (f *fakeBizRepo) ResolveIdentityByIP(_ context.Context, ip string) (*uuid.UUID, string, error) {
	ident, ok := f.ipIdentities[ip]
	if !ok || ident == nil {
		return nil, "", nil // 未知 IP / 歧义：未归属
	}
	id := ident.id
	return &id, ident.key, nil
}

func (f *fakeBizRepo) EmitBusinessEvent(_ context.Context, in BusinessEventInput) (bool, error) {
	if f.emitErr != nil {
		return false, f.emitErr
	}
	// 模拟冷却去重：同身份同规则只收第一次
	for _, e := range f.emitted {
		if e.IdentityID == in.IdentityID && e.RuleCode == in.RuleCode {
			return false, nil
		}
	}
	f.emitted = append(f.emitted, in)
	return true, nil
}

func TestDetectLoginAbuse(t *testing.T) {
	repo := newFakeBizRepo()
	identityID := uuid.New()
	repo.loginHits = []LoginAbuseHit{
		{IdentityID: identityID, IdentityKey: "ik-1", CredentialCount: 6, AuthFailCount: 12}, // 达双阈
		{IdentityID: uuid.New(), IdentityKey: "ik-2", CredentialCount: 6, AuthFailCount: 3},  // 失败未达阈
	}
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	n, err := NewBusinessDetector(repo).DetectOnce(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("emitted = %d, want 1", n)
	}
	e := repo.emitted[0]
	if e.RuleCode != RuleLoginAbuse || e.Signal != SignalLoginAbuse || e.ScoreDelta != 15 {
		t.Errorf("event = %+v", e)
	}
	if e.Metadata["credential_count"] != 6 || e.Metadata["auth_fail_count"] != int64(12) {
		t.Errorf("metadata = %+v", e.Metadata)
	}
}

func TestDetectExportAbuse(t *testing.T) {
	repo := newFakeBizRepo()
	identityID := uuid.New()
	repo.ipIdentities["203.0.113.10"] = &bizIdentity{id: identityID, key: "ik-exp"}
	repo.ipIdentities["198.51.100.7"] = nil // NAT 歧义：存疑不挂
	repo.exportHits = []ExportAbuseHit{
		{ClientIP: "203.0.113.10", IdentityFingerprint: "fp-1", RequestCount: 25},
		{ClientIP: "198.51.100.7", IdentityFingerprint: "fp-2", RequestCount: 99}, // 歧义跳过
		{ClientIP: "", IdentityFingerprint: "fp-3", RequestCount: 50},             // 无 IP 跳过
	}
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	n, err := NewBusinessDetector(repo).DetectOnce(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("emitted = %d, want 1（歧义/无 IP 跳过）", n)
	}
	e := repo.emitted[0]
	if e.RuleCode != RuleExportAbuse || e.IdentityID != identityID || e.IdentityKey != "ik-exp" {
		t.Errorf("event = %+v", e)
	}
}

func TestDetectObjectEnum(t *testing.T) {
	repo := newFakeBizRepo()
	identityID := uuid.New()
	repo.ipIdentities["203.0.113.10"] = &bizIdentity{id: identityID, key: "ik-obj"}
	repo.enumHits = []ObjectEnumHit{
		{ClientIP: "203.0.113.10", IdentityFingerprint: "fp-1", EndpointKey: "GET /api/user/{id}",
			DistinctObjectIDs: 12, RequestCount: 12},
	}
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	n, err := NewBusinessDetector(repo).DetectOnce(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("emitted = %d, want 1", n)
	}
	e := repo.emitted[0]
	if e.RuleCode != RuleObjectEnum || e.Signal != SignalObjectEnum {
		t.Errorf("event = %+v", e)
	}
	if e.Metadata["endpoint_key"] != "GET /api/user/{id}" || e.Metadata["distinct_object_ids"] != int64(12) {
		t.Errorf("metadata = %+v", e.Metadata)
	}
}

// 冷却去重：同身份同规则重复候选只产出一次（防止每轮重复产出膨胀会话风险分）。
func TestDetectCooldownDedup(t *testing.T) {
	repo := newFakeBizRepo()
	identityID := uuid.New()
	repo.loginHits = []LoginAbuseHit{
		{IdentityID: identityID, IdentityKey: "ik-1", CredentialCount: 6, AuthFailCount: 12},
		{IdentityID: identityID, IdentityKey: "ik-1", CredentialCount: 7, AuthFailCount: 20},
	}
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	n, err := NewBusinessDetector(repo).DetectOnce(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || len(repo.emitted) != 1 {
		t.Fatalf("emitted = %d/%d, want 1（冷却去重）", n, len(repo.emitted))
	}
}

// 仓储错误向上返回（聚合器记录日志下轮重试，不静默吞错）。
func TestDetectFetchErrorPropagates(t *testing.T) {
	repo := newFakeBizRepo()
	repo.fetchErr = errors.New("db down")
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	if _, err := NewBusinessDetector(repo).DetectOnce(context.Background(), now); err == nil {
		t.Fatal("want error")
	}
}
