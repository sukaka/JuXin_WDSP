// apimachineid_test.go 机器身份登记管理面单测（NG-ID g1 批次 B1）：
// Validate* 词表/selector 矩阵、ParsePublicKey PEM 解析校验（算法词表与密钥形态一致性核对）、
// CRUD+轮换/撤销状态机 HTTP 映射（200/400/404/409）、权限（jwt_trust.read/manage 零新增；
// 越权全 403）、写操作 HIGH 审计、身份/键/绑定/水位变更全触发发布（设计 §1.12）。
// fake 仓储承载 HTTP 映射；事务/唯一键/FK/水位原子语义由 PG 契约测试覆盖。
package apimachineid

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
)

// ---------- 测试内公钥生成（PEM 形态） ----------

// mustPublicKeyPEM 生成指定算法词表的新鲜公钥 PKIX PEM。
func mustPublicKeyPEM(t *testing.T, alg string) string {
	t.Helper()
	var pub any
	switch alg {
	case AlgEd25519:
		p, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub = p
	case AlgECDSAP256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub = &k.PublicKey
	case AlgRSAPSSSHA512:
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		pub = &k.PublicKey
	default:
		t.Fatalf("未知测试算法: %s", alg)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// keyBody 公钥载荷 JSON（PEM 含换行，经 json.Marshal 安全转义）。
func keyBody(t *testing.T, kid, alg, pemText string, extra map[string]any) string {
	t.Helper()
	m := map[string]any{"kid": kid, "alg": alg, "public_key_pem": pemText}
	for k, v := range extra {
		m[k] = v
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// ---------- Validate* 词表/selector 矩阵 ----------

func TestValidateIdentityInput(t *testing.T) {
	tenant, principal := "tenant-a", "fp:abc123"
	cases := []struct {
		name string
		in   IdentityInput
		want string
	}{
		{"合法全字段", IdentityInput{IdentityName: "pay-gateway", TenantID: &tenant, PrincipalBinding: &principal,
			Status: StatusEnabled, BotChallengeExempt: true}, ""},
		{"缺省合法（仅名称）", IdentityInput{IdentityName: "pay-gateway"}, ""},
		{"status 小写归一", IdentityInput{IdentityName: "a", Status: "disabled"}, ""},
		{"status DISABLED", IdentityInput{IdentityName: "a", Status: StatusDisabled}, ""},
		{"identity_name 空", IdentityInput{Status: StatusEnabled}, "identity_name"},
		{"identity_name 超长", IdentityInput{IdentityName: strings.Repeat("n", 129)}, "identity_name"},
		{"tenant_id 超长", IdentityInput{IdentityName: "a", TenantID: strPtr(strings.Repeat("t", 129))}, "tenant_id"},
		{"principal_binding 超长", IdentityInput{IdentityName: "a", PrincipalBinding: strPtr(strings.Repeat("p", 129))}, "principal_binding"},
		{"status 词表外", IdentityInput{IdentityName: "a", Status: "SUSPENDED"}, "status"},
	}
	for _, c := range cases {
		got := ValidateIdentityInput(c.in)
		if c.want == "" && got != "" {
			t.Fatalf("%s 应合法: %s", c.name, got)
		}
		if c.want != "" && !strings.Contains(got, c.want) {
			t.Fatalf("%s 应含 %q: %s", c.name, c.want, got)
		}
	}
}

func strPtr(v string) *string { return &v }

func TestValidateKeyInput(t *testing.T) {
	validPEM := mustPublicKeyPEM(t, AlgEd25519)
	overlap1, overlap168, overlap169, overlap0 := 1, 168, 169, 0
	cases := []struct {
		name string
		in   KeyInput
		want string
	}{
		{"合法最小", KeyInput{Kid: "k1", Alg: AlgEd25519, PublicKeyPEM: validPEM}, ""},
		{"合法全字段", KeyInput{Kid: "k1", Alg: AlgECDSAP256, PublicKeyPEM: validPEM,
			NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z", OverlapHours: &overlap168}, ""},
		{"alg 词表外 rsa-v1_5-sha256", KeyInput{Kid: "k1", Alg: "rsa-v1_5-sha256", PublicKeyPEM: validPEM}, "alg"},
		{"alg 词表外 hmac-sha256", KeyInput{Kid: "k1", Alg: "hmac-sha256", PublicKeyPEM: validPEM}, "alg"},
		{"kid 空", KeyInput{Alg: AlgEd25519, PublicKeyPEM: validPEM}, "kid"},
		{"kid 超长", KeyInput{Kid: strings.Repeat("k", 129), Alg: AlgEd25519, PublicKeyPEM: validPEM}, "kid"},
		{"public_key_pem 空", KeyInput{Kid: "k1", Alg: AlgEd25519}, "public_key_pem"},
		{"not_before 非 RFC3339", KeyInput{Kid: "k1", Alg: AlgEd25519, PublicKeyPEM: validPEM, NotBefore: "2026-01-01"}, "not_before"},
		{"not_after 非 RFC3339", KeyInput{Kid: "k1", Alg: AlgEd25519, PublicKeyPEM: validPEM, NotAfter: "昨天"}, "not_after"},
		{"有效期倒置", KeyInput{Kid: "k1", Alg: AlgEd25519, PublicKeyPEM: validPEM,
			NotBefore: "2027-01-01T00:00:00Z", NotAfter: "2026-01-01T00:00:00Z"}, "not_before 必须早于"},
		{"overlap_hours 0", KeyInput{Kid: "k1", Alg: AlgEd25519, PublicKeyPEM: validPEM, OverlapHours: &overlap0}, "overlap_hours"},
		{"overlap_hours 超上限", KeyInput{Kid: "k1", Alg: AlgEd25519, PublicKeyPEM: validPEM, OverlapHours: &overlap169}, "overlap_hours"},
		{"overlap_hours 下限合法", KeyInput{Kid: "k1", Alg: AlgEd25519, PublicKeyPEM: validPEM, OverlapHours: &overlap1}, ""},
	}
	for _, c := range cases {
		got := ValidateKeyInput(c.in)
		if c.want == "" && got != "" {
			t.Fatalf("%s 应合法: %s", c.name, got)
		}
		if c.want != "" && !strings.Contains(got, c.want) {
			t.Fatalf("%s 应含 %q: %s", c.name, c.want, got)
		}
	}
}

func TestValidateBindingInput(t *testing.T) {
	app := uuid.NewString()
	cases := []struct {
		name string
		in   BindingInput
		want string
	}{
		{"path_exact 合法", BindingInput{ApplicationID: app, PathExact: "/api/pay"}, ""},
		{"path_prefix 合法", BindingInput{ApplicationID: app, PathPrefix: "/api"}, ""},
		{"path_prefix 根 / 合法", BindingInput{ApplicationID: app, PathPrefix: "/", Mode: ModeProtect}, ""},
		{"mode 缺省合法", BindingInput{ApplicationID: app, PathExact: "/api/pay"}, ""},
		{"mode 小写归一", BindingInput{ApplicationID: app, PathExact: "/api/pay", Mode: "protect"}, ""},
		{"两 selector 都给", BindingInput{ApplicationID: app, PathExact: "/a", PathPrefix: "/a"}, "必须且仅须"},
		{"两 selector 都空", BindingInput{ApplicationID: app}, "必须且仅须"},
		{"application_id 非法", BindingInput{ApplicationID: "xx", PathExact: "/a"}, "application_id"},
		{"path_exact 非斜杠开头", BindingInput{ApplicationID: app, PathExact: "api"}, "必须以 / 开头"},
		{"path_exact 超长", BindingInput{ApplicationID: app, PathExact: "/" + strings.Repeat("p", 512)}, "长度不能超过"},
		{"path 含 query", BindingInput{ApplicationID: app, PathExact: "/a?x=1"}, "不得包含"},
		{"path 含 fragment", BindingInput{ApplicationID: app, PathPrefix: "/a#frag"}, "不得包含"},
		{"path 含控制字符", BindingInput{ApplicationID: app, PathExact: "/a\tb"}, "控制字符"},
		{"path_prefix 以 / 结尾", BindingInput{ApplicationID: app, PathPrefix: "/api/"}, "完整路径段"},
		{"mode 词表外", BindingInput{ApplicationID: app, PathExact: "/a", Mode: "BLOCK"}, "mode"},
	}
	for _, c := range cases {
		got := ValidateBindingInput(c.in)
		if c.want == "" && got != "" {
			t.Fatalf("%s 应合法: %s", c.name, got)
		}
		if c.want != "" && !strings.Contains(got, c.want) {
			t.Fatalf("%s 应含 %q: %s", c.name, c.want, got)
		}
	}
}

// ---------- ParsePublicKey 解析校验 ----------

// PEM 解析校验：三算法词表 PKIX 全通过+指纹确定性；PKCS1 RSA 块接受；垃圾 PEM/块外内容/
// 块类型拒收/alg 与键型不符/P-384 曲线拒收 全负例（§1.3 一致性核对）。
func TestParsePublicKey(t *testing.T) {
	for _, alg := range []string{AlgEd25519, AlgECDSAP256, AlgRSAPSSSHA512} {
		pemText := mustPublicKeyPEM(t, alg)
		norm, fp, err := ParsePublicKey(alg, pemText)
		if err != nil {
			t.Fatalf("%s 应通过: %v", alg, err)
		}
		if norm != strings.TrimSpace(pemText) {
			t.Fatalf("%s 规范化 PEM 应原样 trim: %q", alg, norm)
		}
		if len(fp) != 16 {
			t.Fatalf("%s 指纹形态（sha256 前 16 hex）: %q", alg, fp)
		}
		// 指纹确定性（同键恒同指纹）
		_, fp2, err := ParsePublicKey(alg, "  \n"+pemText+"\n")
		if err != nil || fp2 != fp {
			t.Fatalf("%s 指纹确定性: %q vs %q err=%v", alg, fp, fp2, err)
		}
	}
	// PKCS1（RSA PUBLIC KEY）块接受
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs1 := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)}))
	if _, fp, err := ParsePublicKey(AlgRSAPSSSHA512, pkcs1); err != nil || len(fp) != 16 {
		t.Fatalf("PKCS1 RSA 块应接受: fp=%q err=%v", fp, err)
	}
	// 负例矩阵
	edPEM := mustPublicKeyPEM(t, AlgEd25519)
	rsaPEM := mustPublicKeyPEM(t, AlgRSAPSSSHA512)
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384DER, err := x509.MarshalPKIXPublicKey(&p384Key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	p384PEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: p384DER}))
	privDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}))

	for _, c := range []struct {
		name    string
		alg     string
		pemText string
		want    string
	}{
		{"垃圾 PEM", AlgEd25519, "not-a-pem", "非合法 PEM"},
		{"块外内容拒收", AlgEd25519, edPEM + "\nextra", "恰一个公钥块"},
		{"私钥块类型拒收", AlgEd25519, privPEM, "块类型拒收"},
		{"alg 不符（声明 ed25519 实 rsa）", AlgEd25519, rsaPEM, "不一致"},
		{"alg 不符（声明 rsa 实 ed25519）", AlgRSAPSSSHA512, edPEM, "不一致"},
		{"P-384 曲线拒收", AlgECDSAP256, p384PEM, "仅 P-256"},
	} {
		if _, _, err := ParsePublicKey(c.alg, c.pemText); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s 应拒收含 %q: %v", c.name, c.want, err)
		}
	}
}

// ---------- fake 仓储 ----------

type fakeRepo struct {
	identities map[uuid.UUID]*Identity
	keys       map[uuid.UUID][]*Key // identity_id → 键行
	bindings   map[uuid.UUID]*Binding
	nameIdx    map[string]uuid.UUID
	appExists  bool
	watermark  int64
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		identities: map[uuid.UUID]*Identity{}, keys: map[uuid.UUID][]*Key{},
		bindings: map[uuid.UUID]*Binding{}, nameIdx: map[string]uuid.UUID{},
		appExists: true,
	}
}

func normStatus(v, def string) string {
	v = strings.ToUpper(strings.TrimSpace(v))
	if v == "" {
		return def
	}
	return v
}

func (f *fakeRepo) CreateIdentity(_ context.Context, in IdentityInput, by string) (*Identity, error) {
	name := strings.TrimSpace(in.IdentityName)
	if _, dup := f.nameIdx[name]; dup {
		return nil, ErrDuplicateName
	}
	m := &Identity{ID: uuid.New(), IdentityName: name, TenantID: in.TenantID,
		PrincipalBinding: in.PrincipalBinding, Status: normStatus(in.Status, StatusEnabled),
		BotChallengeExempt: in.BotChallengeExempt, Version: 1,
		CreatedBy: by, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	f.identities[m.ID] = m
	f.nameIdx[name] = m.ID
	return m, nil
}

func (f *fakeRepo) ListIdentities(_ context.Context) ([]IdentitySummary, int64, error) {
	out := []IdentitySummary{}
	for _, m := range f.identities {
		sm := IdentitySummary{Identity: *m}
		for _, k := range f.keys[m.ID] {
			sm.KeyCount++
			switch k.Status {
			case KeyStatusActive:
				sm.ActiveKeys++
			case KeyStatusRetired:
				sm.RetiredKeys++
			case KeyStatusRevoked:
				sm.RevokedKeys++
			}
		}
		out = append(out, sm)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IdentityName < out[j].IdentityName })
	return out, f.watermark, nil
}

func (f *fakeRepo) GetIdentity(_ context.Context, id uuid.UUID) (*Identity, []Key, error) {
	m, ok := f.identities[id]
	if !ok {
		return nil, nil, ErrNotFound
	}
	keys := []Key{}
	for _, k := range f.keys[id] {
		keys = append(keys, *k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Kid < keys[j].Kid })
	return m, keys, nil
}

func (f *fakeRepo) UpdateIdentity(_ context.Context, id uuid.UUID, in IdentityInput) (*Identity, error) {
	m, ok := f.identities[id]
	if !ok {
		return nil, ErrNotFound
	}
	if m.Version != in.Version {
		return nil, ErrVersionConflict
	}
	name := strings.TrimSpace(in.IdentityName)
	if other, dup := f.nameIdx[name]; dup && other != id {
		return nil, ErrDuplicateName
	}
	delete(f.nameIdx, m.IdentityName)
	m.IdentityName = name
	m.TenantID = in.TenantID
	m.PrincipalBinding = in.PrincipalBinding
	m.Status = normStatus(in.Status, StatusEnabled)
	m.BotChallengeExempt = in.BotChallengeExempt
	m.Version++
	m.UpdatedAt = time.Now().UTC()
	f.nameIdx[name] = id
	return m, nil
}

func (f *fakeRepo) DeleteIdentity(_ context.Context, id uuid.UUID) error {
	if len(f.bindings) > 0 {
		return ErrIdentityInUse
	}
	m, ok := f.identities[id]
	if !ok {
		return ErrNotFound
	}
	delete(f.nameIdx, m.IdentityName)
	delete(f.identities, id)
	delete(f.keys, id)
	return nil
}

func (f *fakeRepo) findKey(identityID, keyID uuid.UUID) *Key {
	for _, k := range f.keys[identityID] {
		if k.ID == keyID {
			return k
		}
	}
	return nil
}

func (f *fakeRepo) ImportKey(_ context.Context, identityID uuid.UUID, in KeyInput, by string) (*Key, error) {
	if _, ok := f.identities[identityID]; !ok {
		return nil, ErrNotFound
	}
	kid := strings.TrimSpace(in.Kid)
	for _, k := range f.keys[identityID] {
		if k.Kid == kid {
			return nil, ErrKeyDuplicate
		}
	}
	pemText, fp, err := ParsePublicKey(strings.TrimSpace(in.Alg), in.PublicKeyPEM)
	if err != nil {
		return nil, err
	}
	k := &Key{ID: uuid.New(), IdentityID: identityID, Kid: kid, Alg: strings.TrimSpace(in.Alg),
		PublicKeyPEM: pemText, KeyFingerprint: fp, Status: KeyStatusActive,
		CreatedBy: by, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	if nb, _ := parseRFC3339Ptr(in.NotBefore); nb != nil {
		k.NotBefore = nb
	}
	if na, _ := parseRFC3339Ptr(in.NotAfter); na != nil {
		k.NotAfter = na
	}
	f.keys[identityID] = append(f.keys[identityID], k)
	return k, nil
}

func (f *fakeRepo) RotateKey(_ context.Context, identityID, keyID uuid.UUID, in KeyInput, by string) (*Key, *Key, error) {
	if _, ok := f.identities[identityID]; !ok {
		return nil, nil, ErrNotFound
	}
	old := f.findKey(identityID, keyID)
	if old == nil {
		return nil, nil, ErrKeyNotFound
	}
	if old.Status != KeyStatusActive {
		return nil, nil, ErrKeyStateConflict
	}
	kid := strings.TrimSpace(in.Kid)
	for _, k := range f.keys[identityID] {
		if k.Kid == kid {
			return nil, nil, ErrKeyDuplicate
		}
	}
	overlap := RotateOverlapDefaultHours
	if in.OverlapHours != nil {
		overlap = *in.OverlapHours
	}
	until := time.Now().UTC().Add(time.Duration(overlap) * time.Hour)
	old.Status = KeyStatusRetired
	old.RetireOverlapUntil = &until
	old.UpdatedAt = time.Now().UTC()
	pemText, fp, err := ParsePublicKey(strings.TrimSpace(in.Alg), in.PublicKeyPEM)
	if err != nil {
		return nil, nil, err
	}
	newKey := &Key{ID: uuid.New(), IdentityID: identityID, Kid: kid, Alg: strings.TrimSpace(in.Alg),
		PublicKeyPEM: pemText, KeyFingerprint: fp, Status: KeyStatusActive,
		CreatedBy: by, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	f.keys[identityID] = append(f.keys[identityID], newKey)
	return newKey, old, nil
}

func (f *fakeRepo) RevokeKey(_ context.Context, identityID, keyID uuid.UUID) (*Key, error) {
	k := f.findKey(identityID, keyID)
	if k == nil {
		return nil, ErrKeyNotFound
	}
	if k.Status != KeyStatusActive && k.Status != KeyStatusRetired {
		return nil, ErrKeyStateConflict
	}
	k.Status = KeyStatusRevoked
	k.UpdatedAt = time.Now().UTC()
	f.watermark++
	seq := f.watermark
	k.RevokedSeq = &seq
	return k, nil
}

func (f *fakeRepo) CreateBinding(_ context.Context, in BindingInput, by string) (*Binding, error) {
	if !f.appExists {
		return nil, ErrAppNotFound
	}
	appID, _ := uuid.Parse(strings.TrimSpace(in.ApplicationID))
	exact, prefix := strings.TrimSpace(in.PathExact), strings.TrimSpace(in.PathPrefix)
	for _, b := range f.bindings {
		if b.ApplicationID == appID && b.PathExact == exact && b.PathPrefix == prefix {
			return nil, ErrBindingDuplicate
		}
	}
	b := &Binding{ID: uuid.New(), ApplicationID: appID, PathExact: exact, PathPrefix: prefix,
		Mode: normStatus(in.Mode, ModeObserve), ProofRequired: in.ProofRequired, Version: 1,
		CreatedBy: by, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	f.bindings[b.ID] = b
	return b, nil
}

func (f *fakeRepo) ListBindings(_ context.Context, applicationID uuid.UUID) ([]Binding, error) {
	out := []Binding{}
	for _, b := range f.bindings {
		if applicationID == uuid.Nil || b.ApplicationID == applicationID {
			out = append(out, *b)
		}
	}
	return out, nil
}

func (f *fakeRepo) UpdateBinding(_ context.Context, id uuid.UUID, in BindingInput) (*Binding, error) {
	b, ok := f.bindings[id]
	if !ok {
		return nil, ErrBindingNotFound
	}
	if b.Version != in.Version {
		return nil, ErrVersionConflict
	}
	b.Mode = normStatus(in.Mode, ModeObserve)
	b.ProofRequired = in.ProofRequired
	b.Version++
	b.UpdatedAt = time.Now().UTC()
	return b, nil
}

func (f *fakeRepo) DeleteBinding(_ context.Context, id uuid.UUID) error {
	if _, ok := f.bindings[id]; !ok {
		return ErrBindingNotFound
	}
	delete(f.bindings, id)
	return nil
}

// ---------- HTTP 映射 harness ----------

type spyAudits struct{ entries []audits.RecordInput }

func (s *spyAudits) Record(_ context.Context, in audits.RecordInput) error {
	s.entries = append(s.entries, in)
	return nil
}

func injectPerms(perms ...string) func(http.Handler) http.Handler {
	set := map[string]bool{}
	for _, p := range perms {
		set[p] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: uuid.New(), Username: "tester", PermsSet: set}
			next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
		})
	}
}

func doReq(t *testing.T, mux *http.ServeMux, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func decodeData(t *testing.T, rr *httptest.ResponseRecorder, v any) {
	t.Helper()
	var env map[string]json.RawMessage
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(env["data"], v); err != nil {
		t.Fatalf("data 解码: %v body=%s", err, rr.Body.String())
	}
}

const identitiesPath = "/api/v1/api-security/machine-identities"
const midBindingsPath = "/api/v1/api-security/machine-identity-bindings"

// 身份 CRUD 全链：create 200（缺省 ENABLED）→ 同名 409 → 校验 400 → list（键摘要+水位）
// → get 200/404/400 → update 乐观锁两态 → delete 200/404。
func TestIdentityCRUDHTTP(t *testing.T) {
	repo := newFakeRepo()
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPerms("jwt_trust.read", "jwt_trust.manage"), NewHandler(repo, nil))

	rr := doReq(t, mux, http.MethodPost, identitiesPath, `{"identity_name":"pay-gateway"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	var created struct {
		Identity Identity `json:"identity"`
	}
	decodeData(t, rr, &created)
	if created.Identity.Version != 1 || created.Identity.Status != StatusEnabled ||
		created.Identity.CreatedBy != "tester" {
		t.Fatalf("身份归一: %+v", created.Identity)
	}
	id := created.Identity.ID.String()

	// 同名 → 409
	if rr := doReq(t, mux, http.MethodPost, identitiesPath, `{"identity_name":"pay-gateway"}`); rr.Code != http.StatusConflict {
		t.Fatalf("同名应 409: %d %s", rr.Code, rr.Body.String())
	}
	// 校验 400（identity_name 空 / status 词表外）
	if rr := doReq(t, mux, http.MethodPost, identitiesPath, `{"identity_name":" "}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("名称空应 400: %d", rr.Code)
	}
	if rr := doReq(t, mux, http.MethodPost, identitiesPath, `{"identity_name":"x","status":"SUSPENDED"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("status 词表应 400: %d", rr.Code)
	}
	// list：键摘要+撤销水位（种子 0）
	rr = doReq(t, mux, http.MethodGet, identitiesPath, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("list: %d", rr.Code)
	}
	var list struct {
		Items               []IdentitySummary `json:"items"`
		Total               int               `json:"total"`
		RevocationWatermark int64             `json:"revocation_watermark"`
	}
	decodeData(t, rr, &list)
	if list.Total != 1 || list.Items[0].KeyCount != 0 || list.RevocationWatermark != 0 {
		t.Fatalf("list 摘要: %+v", list)
	}
	// get 200 / 404 / 400
	if rr := doReq(t, mux, http.MethodGet, identitiesPath+"/"+id, ""); rr.Code != http.StatusOK {
		t.Fatalf("get: %d", rr.Code)
	}
	if rr := doReq(t, mux, http.MethodGet, identitiesPath+"/"+uuid.NewString(), ""); rr.Code != http.StatusNotFound {
		t.Fatalf("不存在应 404: %d", rr.Code)
	}
	if rr := doReq(t, mux, http.MethodGet, identitiesPath+"/not-a-uuid", ""); rr.Code != http.StatusBadRequest {
		t.Fatalf("非法 id 应 400: %d", rr.Code)
	}
	// update：version 缺失 400 / 冲突 409 / 合法 200（DISABLED+exempt）
	if rr := doReq(t, mux, http.MethodPut, identitiesPath+"/"+id, `{"identity_name":"pay-gateway"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("version 缺失应 400: %d", rr.Code)
	}
	if rr := doReq(t, mux, http.MethodPut, identitiesPath+"/"+id, `{"identity_name":"pay-gateway","version":9}`); rr.Code != http.StatusConflict {
		t.Fatalf("乐观锁冲突应 409: %d", rr.Code)
	}
	rr = doReq(t, mux, http.MethodPut, identitiesPath+"/"+id,
		`{"identity_name":"pay-gw","status":"DISABLED","bot_challenge_exempt":true,"version":1}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rr.Code, rr.Body.String())
	}
	var updated struct {
		Identity Identity `json:"identity"`
	}
	decodeData(t, rr, &updated)
	if updated.Identity.Version != 2 || updated.Identity.Status != StatusDisabled ||
		!updated.Identity.BotChallengeExempt || updated.Identity.IdentityName != "pay-gw" {
		t.Fatalf("更新落账: %+v", updated.Identity)
	}
	// delete 200；重复 404
	if rr := doReq(t, mux, http.MethodDelete, identitiesPath+"/"+id, ""); rr.Code != http.StatusOK {
		t.Fatalf("delete: %d", rr.Code)
	}
	if rr := doReq(t, mux, http.MethodDelete, identitiesPath+"/"+id, ""); rr.Code != http.StatusNotFound {
		t.Fatalf("重复 delete 应 404: %d", rr.Code)
	}
}

// 公钥生命周期全链（§1.3/§1.6 状态机）：import 200（ACTIVE+指纹）→ kid 重 409 →
// rotate 200（新 ACTIVE+旧 RETIRED+重叠窗口）→ RETIRED 再轮换 409 → revoke 200
// （REVOKED+revoked_seq 回填+水位推进）→ 重复 revoke 409 → 水位单调 → 404 两态。
func TestKeyLifecycleHTTP(t *testing.T) {
	repo := newFakeRepo()
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPerms("jwt_trust.read", "jwt_trust.manage"), NewHandler(repo, nil))

	rr := doReq(t, mux, http.MethodPost, identitiesPath, `{"identity_name":"pay-gateway"}`)
	var created struct {
		Identity Identity `json:"identity"`
	}
	decodeData(t, rr, &created)
	id := created.Identity.ID.String()
	keysPath := identitiesPath + "/" + id + "/keys"

	// import 200：ACTIVE+指纹+created_by
	edPEM1 := mustPublicKeyPEM(t, AlgEd25519)
	rr = doReq(t, mux, http.MethodPost, keysPath, keyBody(t, "k1", AlgEd25519, edPEM1, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("import: %d %s", rr.Code, rr.Body.String())
	}
	var k1 Key
	decodeData(t, rr, &k1)
	if k1.Status != KeyStatusActive || k1.Kid != "k1" || k1.Alg != AlgEd25519 ||
		len(k1.KeyFingerprint) != 16 || k1.CreatedBy != "tester" {
		t.Fatalf("导入落账: %+v", k1)
	}
	// kid 身份内重复 → 409
	if rr := doReq(t, mux, http.MethodPost, keysPath, keyBody(t, "k1", AlgEd25519, mustPublicKeyPEM(t, AlgEd25519), nil)); rr.Code != http.StatusConflict {
		t.Fatalf("kid 重应 409: %d %s", rr.Code, rr.Body.String())
	}
	// 身份不存在 → 404
	if rr := doReq(t, mux, http.MethodPost, identitiesPath+"/"+uuid.NewString()+"/keys",
		keyBody(t, "k9", AlgEd25519, mustPublicKeyPEM(t, AlgEd25519), nil)); rr.Code != http.StatusNotFound {
		t.Fatalf("身份缺失应 404: %d", rr.Code)
	}
	// 校验 400：alg 词表外 / PEM 与声明不符（§1.3 一致性核对）
	if rr := doReq(t, mux, http.MethodPost, keysPath, keyBody(t, "k2", "hmac-sha256", edPEM1, nil)); rr.Code != http.StatusBadRequest {
		t.Fatalf("alg 词表应 400: %d", rr.Code)
	}
	if rr := doReq(t, mux, http.MethodPost, keysPath, keyBody(t, "k2", AlgRSAPSSSHA512, edPEM1, nil)); rr.Code != http.StatusBadRequest {
		t.Fatalf("alg/键型不符应 400: %d %s", rr.Code, rr.Body.String())
	}
	// rotate 200：新 ACTIVE+旧 RETIRED+重叠窗口（显式 48h）
	edPEM2 := mustPublicKeyPEM(t, AlgEd25519)
	rotatePath := keysPath + "/" + k1.ID.String() + "/rotate"
	rr = doReq(t, mux, http.MethodPost, rotatePath, keyBody(t, "k2", AlgEd25519, edPEM2, map[string]any{"overlap_hours": 48}))
	if rr.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", rr.Code, rr.Body.String())
	}
	var rot struct {
		Key        Key `json:"key"`
		RetiredKey Key `json:"retired_key"`
	}
	decodeData(t, rr, &rot)
	if rot.Key.Status != KeyStatusActive || rot.Key.Kid != "k2" {
		t.Fatalf("新键形态: %+v", rot.Key)
	}
	if rot.RetiredKey.Status != KeyStatusRetired || rot.RetiredKey.RetireOverlapUntil == nil {
		t.Fatalf("旧键 RETIRED+窗口: %+v", rot.RetiredKey)
	}
	if d := time.Until(*rot.RetiredKey.RetireOverlapUntil); d < 47*time.Hour || d > 49*time.Hour {
		t.Fatalf("重叠窗口应约 48h: %v", d)
	}
	// RETIRED 键再轮换 → 409（仅 ACTIVE 可轮换）
	if rr := doReq(t, mux, http.MethodPost, rotatePath,
		keyBody(t, "k3", AlgEd25519, mustPublicKeyPEM(t, AlgEd25519), nil)); rr.Code != http.StatusConflict {
		t.Fatalf("RETIRED 再轮换应 409: %d %s", rr.Code, rr.Body.String())
	}
	// rotate 新 kid 与身份内既有冲突 → 409
	if rr := doReq(t, mux, http.MethodPost, keysPath+"/"+rot.Key.ID.String()+"/rotate",
		keyBody(t, "k1", AlgEd25519, mustPublicKeyPEM(t, AlgEd25519), nil)); rr.Code != http.StatusConflict {
		t.Fatalf("新 kid 冲突应 409: %d", rr.Code)
	}
	// keyId 非法 400 / 不存在 404
	if rr := doReq(t, mux, http.MethodPost, keysPath+"/xx/rotate", keyBody(t, "k9", AlgEd25519, edPEM1, nil)); rr.Code != http.StatusBadRequest {
		t.Fatalf("非法 keyId 应 400: %d", rr.Code)
	}
	if rr := doReq(t, mux, http.MethodPost, keysPath+"/"+uuid.NewString()+"/rotate",
		keyBody(t, "k9", AlgEd25519, edPEM1, nil)); rr.Code != http.StatusNotFound {
		t.Fatalf("键不存在应 404: %d", rr.Code)
	}
	// revoke 旧（RETIRED）键 → 200：REVOKED+revoked_seq=1（水位推进回填）
	rr = doReq(t, mux, http.MethodPost, keysPath+"/"+k1.ID.String()+"/revoke", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", rr.Code, rr.Body.String())
	}
	var rk Key
	decodeData(t, rr, &rk)
	if rk.Status != KeyStatusRevoked || rk.RevokedSeq == nil || *rk.RevokedSeq != 1 {
		t.Fatalf("撤销落账（水位回填）: %+v", rk)
	}
	// 重复 revoke → 409
	if rr := doReq(t, mux, http.MethodPost, keysPath+"/"+k1.ID.String()+"/revoke", ""); rr.Code != http.StatusConflict {
		t.Fatalf("重复 revoke 应 409: %d", rr.Code)
	}
	// 撤销新键 → revoked_seq=2（水位只增单调）
	rr = doReq(t, mux, http.MethodPost, keysPath+"/"+rot.Key.ID.String()+"/revoke", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("revoke2: %d", rr.Code)
	}
	var rk2 Key
	decodeData(t, rr, &rk2)
	if rk2.RevokedSeq == nil || *rk2.RevokedSeq != 2 {
		t.Fatalf("水位单调: %+v", rk2)
	}
	// list 水位随列表响应带出=2
	rr = doReq(t, mux, http.MethodGet, identitiesPath, "")
	var list struct {
		Items               []IdentitySummary `json:"items"`
		RevocationWatermark int64             `json:"revocation_watermark"`
	}
	decodeData(t, rr, &list)
	if list.RevocationWatermark != 2 || list.Items[0].RevokedKeys != 2 {
		t.Fatalf("列表水位/摘要: %+v", list)
	}
	// REVOKED 键不可轮换 → 409
	if rr := doReq(t, mux, http.MethodPost, keysPath+"/"+rk.ID.String()+"/rotate",
		keyBody(t, "k4", AlgEd25519, mustPublicKeyPEM(t, AlgEd25519), nil)); rr.Code != http.StatusConflict {
		t.Fatalf("REVOKED 轮换应 409: %d", rr.Code)
	}
	// revoke 不存在 → 404
	if rr := doReq(t, mux, http.MethodPost, keysPath+"/"+uuid.NewString()+"/revoke", ""); rr.Code != http.StatusNotFound {
		t.Fatalf("revoke 不存在应 404: %d", rr.Code)
	}
	// get 详情键行可见（状态/窗口/revoked_seq）
	rr = doReq(t, mux, http.MethodGet, identitiesPath+"/"+id, "")
	var detail struct {
		Identity Identity `json:"identity"`
		Keys     []Key    `json:"keys"`
	}
	decodeData(t, rr, &detail)
	if len(detail.Keys) != 2 || detail.Keys[0].Kid != "k1" || detail.Keys[1].Kid != "k2" {
		t.Fatalf("详情键行（kid 稳定序）: %+v", detail.Keys)
	}
}

// 绑定 CRUD 全链：create 200（缺省 OBSERVE）→ 同（应用,path）409 → 应用缺失 400 →
// list 过滤 → update 乐观锁两态 → 存在绑定时删除身份 409 → delete 200/404。
func TestBindingCRUDHTTP(t *testing.T) {
	repo := newFakeRepo()
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPerms("jwt_trust.read", "jwt_trust.manage"), NewHandler(repo, nil))
	appID := uuid.NewString()
	body := `{"application_id":"` + appID + `","path_prefix":"/api","mode":"PROTECT","proof_required":true}`

	rr := doReq(t, mux, http.MethodPost, midBindingsPath, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	var b Binding
	decodeData(t, rr, &b)
	if b.Mode != ModeProtect || !b.ProofRequired || b.Version != 1 || b.PathPrefix != "/api" {
		t.Fatalf("绑定归一: %+v", b)
	}
	// 同（应用,path）→ 409
	if rr := doReq(t, mux, http.MethodPost, midBindingsPath, body); rr.Code != http.StatusConflict {
		t.Fatalf("重复绑定应 409: %d %s", rr.Code, rr.Body.String())
	}
	// selector 校验 400（二选一）
	if rr := doReq(t, mux, http.MethodPost, midBindingsPath,
		`{"application_id":"`+appID+`","path_exact":"/a","path_prefix":"/a"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("selector 二缺一应 400: %d", rr.Code)
	}
	// 应用引用缺失 → 400
	repo.appExists = false
	if rr := doReq(t, mux, http.MethodPost, midBindingsPath,
		`{"application_id":"`+uuid.NewString()+`","path_exact":"/x"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("应用缺失应 400: %d", rr.Code)
	}
	repo.appExists = true
	// list（application_id 过滤 + 非法过滤 400）
	rr = doReq(t, mux, http.MethodGet, midBindingsPath+"?application_id="+appID, "")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "/api") {
		t.Fatalf("list: %d %s", rr.Code, rr.Body.String())
	}
	if rr := doReq(t, mux, http.MethodGet, midBindingsPath+"?application_id=xx", ""); rr.Code != http.StatusBadRequest {
		t.Fatalf("过滤参数非法应 400: %d", rr.Code)
	}
	// update：version 缺失 400 / 冲突 409 / 合法 200（改 mode/proof_required）
	if rr := doReq(t, mux, http.MethodPut, midBindingsPath+"/"+b.ID.String(), `{"mode":"OBSERVE"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("version 缺失应 400: %d", rr.Code)
	}
	if rr := doReq(t, mux, http.MethodPut, midBindingsPath+"/"+b.ID.String(), `{"mode":"OBSERVE","version":9}`); rr.Code != http.StatusConflict {
		t.Fatalf("乐观锁冲突应 409: %d", rr.Code)
	}
	if rr := doReq(t, mux, http.MethodPut, midBindingsPath+"/"+b.ID.String(), `{"mode":"BLOCK","version":1}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("mode 词表应 400: %d", rr.Code)
	}
	rr = doReq(t, mux, http.MethodPut, midBindingsPath+"/"+b.ID.String(), `{"mode":"OBSERVE","proof_required":false,"version":1}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rr.Code, rr.Body.String())
	}
	var ub Binding
	decodeData(t, rr, &ub)
	if ub.Mode != ModeObserve || ub.ProofRequired || ub.Version != 2 {
		t.Fatalf("更新落账: %+v", ub)
	}
	// 存在任一绑定 → 删除身份 409（ErrIdentityInUse：先解绑再删除——登记册全局生效）
	rr = doReq(t, mux, http.MethodPost, identitiesPath, `{"identity_name":"pay-gateway"}`)
	var created struct {
		Identity Identity `json:"identity"`
	}
	decodeData(t, rr, &created)
	if rr := doReq(t, mux, http.MethodDelete, identitiesPath+"/"+created.Identity.ID.String(), ""); rr.Code != http.StatusConflict {
		t.Fatalf("存在绑定删除身份应 409: %d %s", rr.Code, rr.Body.String())
	}
	// delete 绑定 200 → 身份删除放行 200；重复 delete 404
	if rr := doReq(t, mux, http.MethodDelete, midBindingsPath+"/"+b.ID.String(), ""); rr.Code != http.StatusOK {
		t.Fatalf("delete: %d", rr.Code)
	}
	if rr := doReq(t, mux, http.MethodDelete, identitiesPath+"/"+created.Identity.ID.String(), ""); rr.Code != http.StatusOK {
		t.Fatalf("解绑后删除身份应 200: %d", rr.Code)
	}
	if rr := doReq(t, mux, http.MethodDelete, midBindingsPath+"/"+b.ID.String(), ""); rr.Code != http.StatusNotFound {
		t.Fatalf("重复 delete 应 404: %d", rr.Code)
	}
}

// 越权对照（jiuzhang_admin 形态全 403；jwt_trust.read/manage 权限点零新增实证）。
func TestEndpointsForbiddenForSysAdmin(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPerms("system.read", "applications.edit"), NewHandler(newFakeRepo(), nil))
	id, keyID := uuid.NewString(), uuid.NewString()
	keyPayload := keyBody(t, "k1", AlgEd25519, mustPublicKeyPEM(t, AlgEd25519), nil)
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodPost, identitiesPath, `{"identity_name":"a"}`},
		{http.MethodGet, identitiesPath, ""},
		{http.MethodGet, identitiesPath + "/" + id, ""},
		{http.MethodPut, identitiesPath + "/" + id, `{"identity_name":"a","version":1}`},
		{http.MethodDelete, identitiesPath + "/" + id, ""},
		{http.MethodPost, identitiesPath + "/" + id + "/keys", keyPayload},
		{http.MethodPost, identitiesPath + "/" + id + "/keys/" + keyID + "/rotate", keyPayload},
		{http.MethodPost, identitiesPath + "/" + id + "/keys/" + keyID + "/revoke", ""},
		{http.MethodGet, midBindingsPath, ""},
		{http.MethodPost, midBindingsPath, `{"application_id":"` + uuid.NewString() + `","path_prefix":"/api"}`},
		{http.MethodPut, midBindingsPath + "/" + id, `{"mode":"OBSERVE","version":1}`},
		{http.MethodDelete, midBindingsPath + "/" + id, ""},
	} {
		rr := doReq(t, mux, tc.method, tc.path, tc.body)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s %s: 应 403, got %d", tc.method, tc.path, rr.Code)
		}
	}
}

// 写操作 HIGH 审计（object_type + after 摘要 JSON；公钥摘要指纹引用不落 PEM 原文）。
func TestAuditHigh(t *testing.T) {
	repo := newFakeRepo()
	spy := &spyAudits{}
	h := NewHandler(repo, nil)
	h.audits = spy
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPerms("jwt_trust.manage"), h)

	rr := doReq(t, mux, http.MethodPost, identitiesPath,
		`{"identity_name":"pay-gateway","tenant_id":"tenant-a","bot_challenge_exempt":true}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("create: %d", rr.Code)
	}
	if len(spy.entries) != 1 {
		t.Fatalf("审计条数: %d", len(spy.entries))
	}
	e := spy.entries[0]
	if e.ObjectType != "machine_identity" || e.RiskLevel != "HIGH" || e.Action != "create" ||
		!strings.Contains(e.AfterSummary, `"identity_name":"pay-gateway"`) ||
		!strings.Contains(e.AfterSummary, `"bot_challenge_exempt":true`) {
		t.Fatalf("身份审计内容: %+v", e)
	}
	var created struct {
		Identity Identity `json:"identity"`
	}
	decodeData(t, rr, &created)
	id := created.Identity.ID.String()

	pemText := mustPublicKeyPEM(t, AlgEd25519)
	rr = doReq(t, mux, http.MethodPost, identitiesPath+"/"+id+"/keys", keyBody(t, "k1", AlgEd25519, pemText, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("import: %d", rr.Code)
	}
	e = spy.entries[1]
	if e.ObjectType != "machine_identity_key" || e.Action != "import_key" || e.RiskLevel != "HIGH" ||
		!strings.Contains(e.AfterSummary, `"kid":"k1"`) || !strings.Contains(e.AfterSummary, `"key_fingerprint":"`) {
		t.Fatalf("键审计内容: %+v", e)
	}
	if strings.Contains(e.AfterSummary, "BEGIN PUBLIC KEY") {
		t.Fatalf("审计摘要不应落 PEM 原文（指纹引用）: %s", e.AfterSummary)
	}
	var k Key
	decodeData(t, rr, &k)

	rr = doReq(t, mux, http.MethodPost, identitiesPath+"/"+id+"/keys/"+k.ID.String()+"/revoke", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("revoke: %d", rr.Code)
	}
	e = spy.entries[2]
	if e.Action != "revoke_key" || !strings.Contains(e.AfterSummary, `"status":"REVOKED"`) ||
		!strings.Contains(e.AfterSummary, `"revoked_seq":1`) {
		t.Fatalf("撤销审计内容（水位回填）: %+v", e)
	}

	rr = doReq(t, mux, http.MethodPost, midBindingsPath,
		`{"application_id":"`+uuid.NewString()+`","path_prefix":"/api","mode":"PROTECT"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("binding create: %d", rr.Code)
	}
	e = spy.entries[3]
	if e.ObjectType != "machine_identity_binding" || e.RiskLevel != "HIGH" ||
		!strings.Contains(e.AfterSummary, `"path_prefix":"/api"`) || !strings.Contains(e.AfterSummary, `"mode":"PROTECT"`) {
		t.Fatalf("绑定审计内容: %+v", e)
	}
	if e.Module != "api_security" {
		t.Fatalf("审计模块: %s", e.Module)
	}
}

// 身份/键/绑定/水位变更全触发既有发布链（设计 §1.12——与 MCP「目录不触发」口径不同，
// 登记册九类写操作全部触发）；发布通道不可用时主流程不受影响（warn 降级）。
func TestWriteOpsTriggerPublish(t *testing.T) {
	repo := newFakeRepo()
	h := NewHandler(repo, nil)
	var calls int
	h.SetPublishFunc(func(_ context.Context, _ uuid.UUID, _ string) { calls++ })
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPerms("jwt_trust.manage"), h)

	// 1. 身份 create
	rr := doReq(t, mux, http.MethodPost, identitiesPath, `{"identity_name":"pay-gateway"}`)
	var created struct {
		Identity Identity `json:"identity"`
	}
	decodeData(t, rr, &created)
	id := created.Identity.ID.String()
	// 2. 身份 update
	doReq(t, mux, http.MethodPut, identitiesPath+"/"+id, `{"identity_name":"pay-gateway","version":1}`)
	// 3. 键 import
	rr = doReq(t, mux, http.MethodPost, identitiesPath+"/"+id+"/keys",
		keyBody(t, "k1", AlgEd25519, mustPublicKeyPEM(t, AlgEd25519), nil))
	var k Key
	decodeData(t, rr, &k)
	// 4. 键 rotate
	rr = doReq(t, mux, http.MethodPost, identitiesPath+"/"+id+"/keys/"+k.ID.String()+"/rotate",
		keyBody(t, "k2", AlgEd25519, mustPublicKeyPEM(t, AlgEd25519), nil))
	var rot struct {
		Key Key `json:"key"`
	}
	decodeData(t, rr, &rot)
	// 5. 键 revoke（水位推进）
	doReq(t, mux, http.MethodPost, identitiesPath+"/"+id+"/keys/"+rot.Key.ID.String()+"/revoke", "")
	// 6. 绑定 create
	appID := uuid.NewString()
	rr = doReq(t, mux, http.MethodPost, midBindingsPath, `{"application_id":"`+appID+`","path_prefix":"/api"}`)
	var b Binding
	decodeData(t, rr, &b)
	// 7. 绑定 update
	doReq(t, mux, http.MethodPut, midBindingsPath+"/"+b.ID.String(), `{"mode":"PROTECT","version":1}`)
	// 8. 绑定 delete
	doReq(t, mux, http.MethodDelete, midBindingsPath+"/"+b.ID.String(), "")
	// 9. 身份 delete
	doReq(t, mux, http.MethodDelete, identitiesPath+"/"+id, "")
	if calls != 9 {
		t.Fatalf("九类写操作应触发九次发布: %d", calls)
	}
	// 发布通道不可用时主流程不受影响（warn 降级）
	h2 := NewHandler(newFakeRepo(), nil)
	mux2 := http.NewServeMux()
	RegisterRoutes(mux2, injectPerms("jwt_trust.manage"), h2)
	if rr := doReq(t, mux2, http.MethodPost, identitiesPath, `{"identity_name":"x"}`); rr.Code != http.StatusOK {
		t.Fatalf("无发布通道 create 仍 200: %d", rr.Code)
	}
}
