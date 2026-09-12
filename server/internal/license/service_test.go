// service_test.go 授权服务状态机单元测试：导入（含 SUPERSEDED 流转）、
// 周期复核（到期翻转 EXPIRED、指纹失配翻转 FINGERPRINT_MISMATCH、指纹恢复翻回 ACTIVE）、
// 告警与重发布钩子。仓储用内存 fake（接口拆分使纯逻辑可测，不 mock 冒充 PG 行为）。
package license

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fakeRepo 内存仓储（接口契约级 fake：唯一约束/候选行选择/条件翻转语义与 Store 一致）。
type fakeRepo struct {
	mu         sync.Mutex
	rows       []*Record
	rawFiles   map[uuid.UUID][]byte // id → raw_file 密文（nil = NULL）
	latestErr  error
	rawFileErr error
}

func (r *fakeRepo) InsertActive(_ context.Context, rec *Record, rawFileCipher []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, row := range r.rows {
		if row.LicenseID == rec.LicenseID {
			return ErrDuplicate
		}
	}
	for _, row := range r.rows {
		if row.Status == StatusActive || row.Status == StatusFingerprintMismatch {
			row.Status = StatusSuperseded
		}
	}
	rec.ID = uuid.New()
	rec.ImportedAt = time.Now().UTC()
	rec.CreatedAt = rec.ImportedAt
	cp := *rec
	r.rows = append(r.rows, &cp)
	if r.rawFiles == nil {
		r.rawFiles = map[uuid.UUID][]byte{}
	}
	r.rawFiles[rec.ID] = rawFileCipher
	return nil
}

func (r *fakeRepo) LatestCandidate(_ context.Context) (*Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.latestErr != nil {
		return nil, r.latestErr
	}
	var best *Record
	for _, row := range r.rows {
		if row.Status != StatusActive && row.Status != StatusFingerprintMismatch {
			continue
		}
		if best == nil || row.ImportedAt.After(best.ImportedAt) {
			best = row
		}
	}
	if best == nil {
		return nil, ErrNoEffective
	}
	cp := *best
	return &cp, nil
}

func (r *fakeRepo) SetStatus(_ context.Context, id uuid.UUID, to string, from ...string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, row := range r.rows {
		if row.ID != id {
			continue
		}
		for _, f := range from {
			if row.Status == f {
				row.Status = to
				return true, nil
			}
		}
		return false, nil
	}
	return false, nil
}

func (r *fakeRepo) ListHistory(_ context.Context, page, pageSize int) ([]Record, int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Record, 0, len(r.rows))
	for _, row := range r.rows {
		out = append(out, *row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ImportedAt.After(out[j].ImportedAt) })
	total := int64(len(out))
	start := (page - 1) * pageSize
	if start >= len(out) {
		return []Record{}, total, nil
	}
	end := start + pageSize
	if end > len(out) {
		end = len(out)
	}
	return out[start:end], total, nil
}

func (r *fakeRepo) EarliestProduct(_ context.Context) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.rows) == 0 {
		return "", nil
	}
	// rows 按导入顺序追加，首条即最早导入（任何状态均计入）
	return r.rows[0].Product, nil
}

func (r *fakeRepo) RawFileCipher(_ context.Context, id uuid.UUID) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.rawFileErr != nil {
		return nil, r.rawFileErr
	}
	return r.rawFiles[id], nil
}

// mutateRow 模拟 root 直接改库：就地修改指定授权行。
func (r *fakeRepo) mutateRow(t *testing.T, licenseID string, fn func(row *Record)) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, row := range r.rows {
		if row.LicenseID == licenseID {
			fn(row)
			return
		}
	}
	t.Fatalf("行不存在: %s", licenseID)
}

// setRawFile 设置 raw_file（nil 模拟 enc 未装配时导入的 NULL 历史行）。
func (r *fakeRepo) setRawFile(t *testing.T, licenseID string, cipher []byte) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, row := range r.rows {
		if row.LicenseID == licenseID {
			r.rawFiles[row.ID] = cipher
			return
		}
	}
	t.Fatalf("行不存在: %s", licenseID)
}

func (r *fakeRepo) setRawFileError(err error) {
	r.mu.Lock()
	r.rawFileErr = err
	r.mu.Unlock()
}

func (r *fakeRepo) setLatestError(err error) {
	r.mu.Lock()
	r.latestErr = err
	r.mu.Unlock()
}

// fakeEnc 测试加解密（前缀标记可逆变换，模拟 *encryption.Service 契约）。
type fakeEnc struct{}

func (fakeEnc) Encrypt(plaintext string) (string, error) { return "fakeenc:" + plaintext, nil }

func (fakeEnc) Decrypt(encoded string) (string, error) {
	if !strings.HasPrefix(encoded, "fakeenc:") {
		return "", errors.New("fakeEnc: 非法密文")
	}
	return strings.TrimPrefix(encoded, "fakeenc:"), nil
}

func (r *fakeRepo) statusOf(t *testing.T, licenseID string) string {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, row := range r.rows {
		if row.LicenseID == licenseID {
			return row.Status
		}
	}
	t.Fatalf("行不存在: %s", licenseID)
	return ""
}

// hookSpy 重发布/告警钩子记录器。
type hookSpy struct {
	mu          sync.Mutex
	republishN  int
	alertEvents []AlertEvent
}

func (s *hookSpy) republish(_ context.Context) {
	s.mu.Lock()
	s.republishN++
	s.mu.Unlock()
}

func (s *hookSpy) alert(_ context.Context, ev AlertEvent) {
	s.mu.Lock()
	s.alertEvents = append(s.alertEvents, ev)
	s.mu.Unlock()
}

func (s *hookSpy) republishCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.republishN
}

func (s *hookSpy) alerts() []AlertEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]AlertEvent{}, s.alertEvents...)
}

// testSvcEnv 测试服务环境：内存仓储 + 测试密钥对 + 临时指纹文件 + 可控时钟。
type testSvcEnv struct {
	svc    *Service
	repo   *fakeRepo
	spy    *hookSpy
	priv   ed25519.PrivateKey
	keys   map[string]ed25519.PublicKey
	fpPath string
	now    time.Time
}

func newTestSvcEnv(t *testing.T, hostFP string) *testSvcEnv {
	t.Helper()
	return newTestSvcEnvWithEnc(t, hostFP, fakeEnc{})
}

// newTestSvcEnvWithEnc 可注入 Encryptor 的测试环境（篡改检测用 fakeEnc）。
func newTestSvcEnvWithEnc(t *testing.T, hostFP string, enc Encryptor) *testSvcEnv {
	t.Helper()
	pub, priv := newTestKey(t, testKeyID)
	dir := t.TempDir()
	fpPath := filepath.Join(dir, "host_fingerprint")
	if hostFP != "" {
		if err := os.WriteFile(fpPath, []byte(hostFP+"\n"), 0600); err != nil {
			t.Fatalf("write fp: %v", err)
		}
	}
	env := &testSvcEnv{
		repo:   &fakeRepo{},
		spy:    &hookSpy{},
		priv:   priv,
		keys:   map[string]ed25519.PublicKey{testKeyID: pub},
		fpPath: fpPath,
		now:    time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC),
	}
	svc := NewService(env.repo, enc, env.keys)
	svc.fpPath = fpPath
	svc.now = func() time.Time { return env.now }
	svc.SetRepublishHook(env.spy.republish)
	svc.SetAlertHook(env.spy.alert)
	env.svc = svc
	return env
}

// importSample 构造并导入样本授权。
func (e *testSvcEnv) importSample(t *testing.T, rec testLicenseRec) error {
	t.Helper()
	fileBytes := signTestLicense(t, e.priv, buildPayloadForTest(rec, e.now, testKeyID))
	_, err := e.svc.Import(context.Background(), fileBytes, nil)
	return err
}

// waitRepublish 等待异步重发布钩子计数到达 n（triggerRepublish 为异步 goroutine）。
func (e *testSvcEnv) waitRepublish(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if e.spy.republishCount() >= n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("重发布钩子计数未到 %d（当前 %d）", n, e.spy.republishCount())
}

func TestServiceImportAndState(t *testing.T) {
	env := newTestSvcEnv(t, "")
	if err := env.importSample(t, validSample()); err != nil {
		t.Fatalf("Import: %v", err)
	}
	st := env.svc.State()
	if !st.Valid || st.Product != "wdsp" || st.LicenseID != "LIC-2026-0001" {
		t.Fatalf("状态应为有效: %+v", st)
	}
	if st.Customer != "测试<>&客户" || st.LicenseType != TypeFormal {
		t.Fatalf("状态字段错误: %+v", st)
	}
	if st.Quotas != (Quotas{MaxApplications: 10, MaxAPIEndpoints: 100, MaxQPS: 50}) {
		t.Fatalf("状态配额错误: %+v", st)
	}
	if st.ExpiresAt == nil || st.ExpiresAt.Format("2006-01-02") != "2099-12-31" {
		t.Fatalf("状态到期日错误: %+v", st)
	}
	if st.IntegrityStatus != IntegrityVerified || st.ProtectionState.CommercialAuthorization != "AUTHORIZED" ||
		st.ProtectionState.ArtifactIntegrity != "VERIFIED" || st.ProtectionState.GatewayProtection != "PRESERVE_EXISTING" ||
		st.ProtectionState.ConfidentialComputing != "DISABLED" || st.ProtectionState.Recovery != "NONE" {
		t.Fatalf("多维授权与防护状态错误: %+v", st.ProtectionState)
	}
	if got := env.repo.statusOf(t, "LIC-2026-0001"); got != StatusActive {
		t.Fatalf("落库状态应为 ACTIVE，got %s", got)
	}
	env.waitRepublish(t, 1)
}

func TestServiceImportRequiresEncryptedOriginal(t *testing.T) {
	env := newTestSvcEnvWithEnc(t, "", nil)
	if err := env.importSample(t, validSample()); !errors.Is(err, ErrEncryptionUnavailable) {
		t.Fatalf("缺少原文加密服务应拒绝导入，got %v", err)
	}
	if env.svc.State().Valid {
		t.Fatal("加密服务不可用时不得形成有效授权状态")
	}
	if len(env.repo.rows) != 0 {
		t.Fatalf("加密服务不可用时不得写入授权行，got %d", len(env.repo.rows))
	}
}

func TestServiceImportSupersedes(t *testing.T) {
	env := newTestSvcEnv(t, "")
	if err := env.importSample(t, validSample()); err != nil {
		t.Fatalf("Import A: %v", err)
	}
	// 第二次导入替换旧授权（旧 ACTIVE → SUPERSEDED）
	recB := validSample()
	recB.LicenseID = "LIC-2026-0002"
	if err := env.importSample(t, recB); err != nil {
		t.Fatalf("Import B: %v", err)
	}
	if got := env.repo.statusOf(t, "LIC-2026-0001"); got != StatusSuperseded {
		t.Fatalf("旧授权应置 SUPERSEDED，got %s", got)
	}
	if got := env.repo.statusOf(t, "LIC-2026-0002"); got != StatusActive {
		t.Fatalf("新授权应为 ACTIVE，got %s", got)
	}
	st := env.svc.State()
	if !st.Valid || st.LicenseID != "LIC-2026-0002" {
		t.Fatalf("内存状态应切换到新授权: %+v", st)
	}
	env.waitRepublish(t, 2)
}

func TestServiceImportDuplicate(t *testing.T) {
	env := newTestSvcEnv(t, "")
	if err := env.importSample(t, validSample()); err != nil {
		t.Fatalf("Import: %v", err)
	}
	if err := env.importSample(t, validSample()); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("重复导入应判 ErrDuplicate，got %v", err)
	}
}

func TestServiceImportExpiredRejected(t *testing.T) {
	env := newTestSvcEnv(t, "")
	expires := env.now.AddDate(0, 0, -1) // 昨天到期
	rec := validSample()
	rec.ExpiresAt = &expires
	if err := env.importSample(t, rec); !errors.Is(err, ErrMalformed) {
		t.Fatalf("已到期授权应拒绝导入，got %v", err)
	}
	if env.svc.State().Valid {
		t.Fatal("拒绝后状态应保持无效")
	}
}

func TestServiceImportBadSignature(t *testing.T) {
	env := newTestSvcEnv(t, "")
	payload := buildPayloadForTest(validSample(), env.now, testKeyID)
	fileBytes := signTestLicense(t, env.priv, payload)
	// 篡改文件内 payload（验签应失败）
	var file map[string]json.RawMessage
	if err := json.Unmarshal(fileBytes, &file); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(file["payload"], &m); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	m["customer"] = "篡改"
	tampered, _ := json.Marshal(m)
	repacked, _ := json.Marshal(map[string]interface{}{
		"payload":   json.RawMessage(tampered),
		"signature": json.RawMessage(file["signature"]),
	})
	if _, err := env.svc.Import(context.Background(), repacked, nil); !errors.Is(err, ErrSignature) {
		t.Fatalf("篡改文件应判验签失败，got %v", err)
	}
}

func TestServiceImportFingerprintMismatch(t *testing.T) {
	env := newTestSvcEnv(t, "sha256:host-A")
	rec := validSample()
	rec.MachineFingerprint = "sha256:host-B"
	if err := env.importSample(t, rec); !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("绑定指纹与本机不一致应判 409 类错误，got %v", err)
	}
}

func TestServiceSweepExpiryFlip(t *testing.T) {
	env := newTestSvcEnv(t, "")
	expires := time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC) // 今天到期（含当天）
	rec := validSample()
	rec.ExpiresAt = &expires
	if err := env.importSample(t, rec); err != nil {
		t.Fatalf("Import: %v", err)
	}
	if !env.svc.State().Valid {
		t.Fatal("到期日当天应有效")
	}
	env.waitRepublish(t, 1)
	// 时钟推进到次日：周期复核翻转 EXPIRED
	env.now = env.now.AddDate(0, 0, 1)
	if err := env.svc.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	st := env.svc.State()
	if st.Valid || st.Reason != "授权已到期" {
		t.Fatalf("到期后状态应无效: %+v", st)
	}
	if got := env.repo.statusOf(t, "LIC-2026-0001"); got != StatusExpired {
		t.Fatalf("落库状态应翻转为 EXPIRED，got %s", got)
	}
	env.waitRepublish(t, 2)
	alerts := env.spy.alerts()
	if len(alerts) == 0 || alerts[len(alerts)-1].Type != AlertLicenseInvalid {
		t.Fatalf("到期翻转应抛出 LICENSE_INVALID 告警: %+v", alerts)
	}
}

func TestServiceSweepFingerprintFlipAndRecover(t *testing.T) {
	env := newTestSvcEnv(t, "sha256:host-A")
	rec := validSample()
	rec.MachineFingerprint = "sha256:host-A"
	if err := env.importSample(t, rec); err != nil {
		t.Fatalf("Import: %v", err)
	}
	env.waitRepublish(t, 1)
	// 指纹材料被替换为其他值：复核翻转 FINGERPRINT_MISMATCH
	if err := os.WriteFile(env.fpPath, []byte("sha256:host-C"), 0600); err != nil {
		t.Fatalf("write fp: %v", err)
	}
	if err := env.svc.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	st := env.svc.State()
	if st.Valid || st.Reason != "机器指纹不匹配" {
		t.Fatalf("指纹失配后状态应无效: %+v", st)
	}
	if got := env.repo.statusOf(t, "LIC-2026-0001"); got != StatusFingerprintMismatch {
		t.Fatalf("落库状态应翻转为 FINGERPRINT_MISMATCH，got %s", got)
	}
	env.waitRepublish(t, 2)
	// 指纹材料恢复：复核翻回 ACTIVE（恢复防护）
	if err := os.WriteFile(env.fpPath, []byte("sha256:host-A"), 0600); err != nil {
		t.Fatalf("write fp: %v", err)
	}
	if err := env.svc.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	st = env.svc.State()
	if !st.Valid || st.LicenseID != "LIC-2026-0001" {
		t.Fatalf("指纹恢复后状态应重新有效: %+v", st)
	}
	if got := env.repo.statusOf(t, "LIC-2026-0001"); got != StatusActive {
		t.Fatalf("落库状态应翻回 ACTIVE，got %s", got)
	}
	env.waitRepublish(t, 3)
}

func TestServiceSweepFingerprintMaterialMissing(t *testing.T) {
	env := newTestSvcEnv(t, "sha256:host-A")
	rec := validSample()
	rec.MachineFingerprint = "sha256:host-A"
	if err := env.importSample(t, rec); err != nil {
		t.Fatalf("Import: %v", err)
	}
	if err := os.Remove(env.fpPath); err != nil {
		t.Fatalf("remove fp: %v", err)
	}
	if err := env.svc.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	st := env.svc.State()
	if st.Valid || st.Reason != "宿主机指纹材料缺失" {
		t.Fatalf("指纹材料缺失应如实呈现: %+v", st)
	}
}

func TestServiceIntegrityDependencyFailurePreservesGatewayConfiguration(t *testing.T) {
	tests := []struct {
		name    string
		inject  func(*fakeRepo, error)
		recover func(*fakeRepo)
	}{
		{
			name:    "候选记录读取失败",
			inject:  func(repo *fakeRepo, err error) { repo.setLatestError(err) },
			recover: func(repo *fakeRepo) { repo.setLatestError(nil) },
		},
		{
			name:    "授权原文读取失败",
			inject:  func(repo *fakeRepo, err error) { repo.setRawFileError(err) },
			recover: func(repo *fakeRepo) { repo.setRawFileError(nil) },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newTestSvcEnv(t, "")
			if err := env.importSample(t, validSample()); err != nil {
				t.Fatalf("Import: %v", err)
			}
			env.waitRepublish(t, 1)
			tt.inject(env.repo, errors.New("temporary database read failure"))

			if err := env.svc.Refresh(context.Background()); err == nil {
				t.Fatal("事实源临时故障应如实返回错误")
			}
			st := env.svc.State()
			if st.Valid || st.IntegrityStatus != IntegrityDatabaseUnavailable ||
				st.ProtectionState.CommercialAuthorization != "UNKNOWN" ||
				st.ProtectionState.ArtifactIntegrity != "UNKNOWN" ||
				st.ProtectionState.GatewayProtection != "PRESERVE_EXISTING" ||
				st.ProtectionState.Recovery != "SUPPORT_REQUIRED" {
				t.Fatalf("临时完整性故障状态不准确: %+v", st)
			}
			if env.svc.AllowsGatewayConfigPublish() {
				t.Fatal("完整性事实源不可用时必须暂停网关配置发布")
			}
			time.Sleep(50 * time.Millisecond)
			if n := env.spy.republishCount(); n != 1 {
				t.Fatalf("临时完整性故障不得触发旁路重发布，got %d", n)
			}
			for _, ev := range env.spy.alerts() {
				if ev.Type == AlertLicenseInvalid {
					t.Fatalf("临时完整性故障不得误报为 LICENSE_INVALID: %+v", ev)
				}
			}

			tt.recover(env.repo)
			if err := env.svc.Refresh(context.Background()); err != nil {
				t.Fatalf("事实源恢复后 Refresh: %v", err)
			}
			if st := env.svc.State(); !st.Valid || st.IntegrityStatus != IntegrityVerified || !env.svc.AllowsGatewayConfigPublish() {
				t.Fatalf("事实源恢复后应重新验证并允许发布: %+v", st)
			}
			env.waitRepublish(t, 2)
		})
	}
}

func TestServiceBaselineNoRepublish(t *testing.T) {
	env := newTestSvcEnv(t, "")
	// 首次 Refresh（基线）：无授权 → 抛 LICENSE_INVALID 告警但不触发重发布
	if err := env.svc.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	st := env.svc.State()
	if st.Valid || st.Reason != "未导入授权" {
		t.Fatalf("基线状态应为未导入: %+v", st)
	}
	time.Sleep(50 * time.Millisecond) // 给异步钩子留执行窗口
	if n := env.spy.republishCount(); n != 0 {
		t.Fatalf("基线评估不应触发重发布，got %d", n)
	}
	alerts := env.spy.alerts()
	if len(alerts) != 1 || alerts[0].Type != AlertLicenseInvalid || alerts[0].Severity != SeverityCritical {
		t.Fatalf("基线应抛 LICENSE_INVALID(CRITICAL) 告警: %+v", alerts)
	}
}

func TestServiceExpiringSoonAlert(t *testing.T) {
	env := newTestSvcEnv(t, "")
	expires := env.now.AddDate(0, 0, 3) // 3 天后到期（≤7 天阈值）
	rec := validSample()
	rec.ExpiresAt = &expires
	if err := env.importSample(t, rec); err != nil {
		t.Fatalf("Import: %v", err)
	}
	if err := env.svc.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	alerts := env.spy.alerts()
	found := false
	for _, ev := range alerts {
		if ev.Type == AlertLicenseExpiringSoon && ev.Severity == SeverityHigh {
			found = true
		}
	}
	if !found {
		t.Fatalf("临期授权应抛 LICENSE_EXPIRING_SOON(HIGH) 告警: %+v", alerts)
	}
}

func TestServiceHistory(t *testing.T) {
	env := newTestSvcEnv(t, "")
	if err := env.importSample(t, validSample()); err != nil {
		t.Fatalf("Import A: %v", err)
	}
	recB := validSample()
	recB.LicenseID = "LIC-2026-0002"
	if err := env.importSample(t, recB); err != nil {
		t.Fatalf("Import B: %v", err)
	}
	items, total, err := env.svc.History(context.Background(), 1, 20)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if total != 2 || len(items) != 2 {
		t.Fatalf("历史应为 2 条: total=%d len=%d", total, len(items))
	}
	if items[0].LicenseID != "LIC-2026-0002" || items[1].LicenseID != "LIC-2026-0001" {
		t.Fatalf("历史应按导入时间倒序: %+v", items)
	}
	if items[0].Status != StatusActive || items[1].Status != StatusSuperseded {
		t.Fatalf("历史状态口径错误: %+v", items)
	}
}

func TestServiceImportProductBound(t *testing.T) {
	env := newTestSvcEnv(t, "")
	recA := validSample()
	recA.Product = "waf"
	if err := env.importSample(t, recA); err != nil {
		t.Fatalf("首导 waf: %v", err)
	}
	// 不同 product 拒绝：ErrProductBound，信息含绑定形态与重装提示
	recB := validSample()
	recB.LicenseID = "LIC-2026-0002"
	recB.Product = "wdsp"
	err := env.importSample(t, recB)
	if !errors.Is(err, ErrProductBound) {
		t.Fatalf("不同 product 应判 ErrProductBound，got %v", err)
	}
	if !strings.Contains(err.Error(), "waf") || !strings.Contains(err.Error(), "wdsp") ||
		!strings.Contains(err.Error(), "重新安装") {
		t.Fatalf("错误信息应含绑定形态/本次形态/重装提示: %v", err)
	}
	if !env.svc.State().Valid || env.svc.State().LicenseID != "LIC-2026-0001" {
		t.Fatalf("拒绝后状态应保持原授权有效: %+v", env.svc.State())
	}
	// 同 product 续期照常放行
	recC := validSample()
	recC.LicenseID = "LIC-2026-0003"
	recC.Product = "waf"
	if err := env.importSample(t, recC); err != nil {
		t.Fatalf("同 product 续期应放行: %v", err)
	}
	if got := env.repo.statusOf(t, "LIC-2026-0001"); got != StatusSuperseded {
		t.Fatalf("旧授权应置 SUPERSEDED，got %s", got)
	}
	if st := env.svc.State(); !st.Valid || st.LicenseID != "LIC-2026-0003" {
		t.Fatalf("续期后状态应切换到新授权: %+v", st)
	}
}

func TestServiceImportProductBoundAcrossSuperseded(t *testing.T) {
	env := newTestSvcEnv(t, "")
	// 首导 waf → 同 product 续期（旧行 SUPERSEDED）→ 历史仍按最早记录绑定 waf
	recA := validSample()
	recA.Product = "waf"
	if err := env.importSample(t, recA); err != nil {
		t.Fatalf("首导 waf: %v", err)
	}
	recB := validSample()
	recB.LicenseID = "LIC-2026-0002"
	recB.Product = "waf"
	if err := env.importSample(t, recB); err != nil {
		t.Fatalf("续期 waf: %v", err)
	}
	if got := env.repo.statusOf(t, "LIC-2026-0001"); got != StatusSuperseded {
		t.Fatalf("旧行应 SUPERSEDED，got %s", got)
	}
	recC := validSample()
	recC.LicenseID = "LIC-2026-0003"
	recC.Product = "api"
	if err := env.importSample(t, recC); !errors.Is(err, ErrProductBound) {
		t.Fatalf("SUPERSEDED 历史存在时仍应按最早绑定拒绝，got %v", err)
	}
}

func TestServiceImportProductFreshRepoAnyProduct(t *testing.T) {
	// 全新库（重装）：任意 product 均可导入
	for _, prod := range []string{"waf", "wdsp", "api"} {
		env := newTestSvcEnv(t, "")
		rec := validSample()
		rec.Product = prod
		if err := env.importSample(t, rec); err != nil {
			t.Fatalf("全新库导入 %s 应放行: %v", prod, err)
		}
		if st := env.svc.State(); !st.Valid || st.Product != prod {
			t.Fatalf("导入后形态应为 %s: %+v", prod, st)
		}
	}
}

func TestServiceSweepTamperDetection(t *testing.T) {
	env := newTestSvcEnvWithEnc(t, "", fakeEnc{})
	rec := validSample()
	rec.Product = "waf"
	if err := env.importSample(t, rec); err != nil {
		t.Fatalf("Import: %v", err)
	}
	env.waitRepublish(t, 1)
	// 未篡改时复核不误判（raw_file 重验签 + 全文比对通过）
	if err := env.svc.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if st := env.svc.State(); !st.Valid || st.Product != "waf" {
		t.Fatalf("未篡改应保持有效: %+v", st)
	}
	// 模拟 root 改库：UPDATE payload.product 与 product 列 waf → wdsp
	env.repo.mutateRow(t, "LIC-2026-0001", func(row *Record) {
		row.Product = "wdsp"
		var m map[string]interface{}
		if err := json.Unmarshal(row.Payload, &m); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		m["product"] = "wdsp"
		row.Payload, _ = json.Marshal(m)
	})
	if err := env.svc.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	st := env.svc.State()
	if st.Valid || st.IntegrityStatus != IntegrityDBInconsistent || !strings.Contains(st.Reason, "不一致") {
		t.Fatalf("数据库缓存不一致后状态应无效且原因明确: %+v", st)
	}
	if got := env.repo.statusOf(t, "LIC-2026-0001"); got != StatusInvalid {
		t.Fatalf("篡改行应翻转 INVALID，got %s", got)
	}
	env.waitRepublish(t, 2)
	alerts := env.spy.alerts()
	found := false
	for _, ev := range alerts {
		if ev.Type == AlertLicenseInvalid && ev.Severity == SeverityCritical &&
			strings.Contains(ev.Message, "不一致") {
			found = true
		}
	}
	if !found {
		t.Fatalf("篡改翻转应抛 LICENSE_INVALID(CRITICAL) 告警: %+v", alerts)
	}
}

func TestServiceSweepOriginalMissingDoesNotClaimValid(t *testing.T) {
	env := newTestSvcEnvWithEnc(t, "", fakeEnc{})
	if err := env.importSample(t, validSample()); err != nil {
		t.Fatalf("Import: %v", err)
	}
	// raw_file 置 NULL：授权原文事实源缺失，必须明确显示不可验证，不能继续声称有效。
	env.repo.setRawFile(t, "LIC-2026-0001", nil)
	env.repo.mutateRow(t, "LIC-2026-0001", func(row *Record) {
		var m map[string]interface{}
		if err := json.Unmarshal(row.Payload, &m); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		m["customer"] = "root 改库"
		row.Payload, _ = json.Marshal(m)
	})
	if err := env.svc.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if st := env.svc.State(); st.Valid || st.IntegrityStatus != IntegrityOriginalMissing ||
		st.ProtectionState.ArtifactIntegrity != "UNVERIFIABLE" || st.ProtectionState.Recovery != "REVALIDATE_PACKAGE" {
		t.Fatalf("raw_file NULL 时应明确呈现原文缺失: %+v", st)
	}
	if got := env.repo.statusOf(t, "LIC-2026-0001"); got != StatusActive {
		t.Fatalf("raw_file NULL 时行状态应保持 ACTIVE，got %s", got)
	}
}

func TestServiceCapabilityWarnOnce(t *testing.T) {
	env := newTestSvcEnv(t, "")
	// 包装配仅 Web 能力（API 未启），授权 wdsp → 形态宽于本包能力
	env.svc.SetCapabilityProvider(func() (bool, bool) { return false, true })
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(prev)
	if err := env.importSample(t, validSample()); err != nil {
		t.Fatalf("Import: %v", err)
	}
	if err := env.svc.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if err := env.svc.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh 2: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "授权产品形态宽于本包能力") {
		t.Fatalf("应 WARN 一次授权形态宽于本包能力: %s", out)
	}
	if strings.Count(out, "授权产品形态宽于本包能力") != 1 {
		t.Fatalf("WARN 应只抛一次: %s", out)
	}
	// 能力覆盖时不告警
	buf.Reset()
	env2 := newTestSvcEnv(t, "")
	env2.svc.SetCapabilityProvider(func() (bool, bool) { return true, true })
	if err := env2.importSample(t, validSample()); err != nil {
		t.Fatalf("Import: %v", err)
	}
	if err := env2.svc.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if strings.Contains(buf.String(), "授权产品形态宽于本包能力") {
		t.Fatalf("能力覆盖时不应 WARN: %s", buf.String())
	}
}
