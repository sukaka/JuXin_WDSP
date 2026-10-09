package upgrades

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
)

// ---------- 内存版登记/执行依赖（同 artifactVerifier 的测试替换模式） ----------

type fakePackageRegistrar struct {
	byHash map[string]*Package
}

func (f *fakePackageRegistrar) FindPackageByHash(_ context.Context, hash string) (*Package, error) {
	if p, ok := f.byHash[hash]; ok {
		return p, nil
	}
	return nil, ErrNotFound
}

func (f *fakePackageRegistrar) CreatePackage(_ context.Context, pkg *Package) error {
	pkg.ID = uuid.New()
	pkg.UploadedAt = time.Now().UTC()
	if f.byHash == nil {
		f.byHash = map[string]*Package{}
	}
	f.byHash[pkg.FileHash] = pkg
	return nil
}

type fakeUpgradeExecutor struct {
	err            error
	calls          int
	scheduleCalls  int
	lastPackageID  uuid.UUID
	lastScheduleAt time.Time
}

func (f *fakeUpgradeExecutor) Execute(_ context.Context, packageID, _ uuid.UUID, _ string) (*Job, error) {
	f.calls++
	f.lastPackageID = packageID
	if f.err != nil {
		return nil, f.err
	}
	return &Job{ID: uuid.New(), PackageID: &packageID, Status: StatusPending, RequestedAt: time.Now().UTC()}, nil
}

func (f *fakeUpgradeExecutor) Schedule(_ context.Context, packageID, _ uuid.UUID, _ string, scheduledAt time.Time) (*Job, error) {
	f.scheduleCalls++
	f.lastPackageID = packageID
	f.lastScheduleAt = scheduledAt
	if f.err != nil {
		return nil, f.err
	}
	at := scheduledAt.UTC()
	return &Job{ID: uuid.New(), PackageID: &packageID, Status: StatusScheduled, ScheduledAt: &at, RequestedAt: time.Now().UTC()}, nil
}

// ---------- 请求构造与响应解码 ----------

func buildUploadRequest(t *testing.T, fileName string, content []byte, fields map[string]string) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for k, v := range fields {
		if err := writer.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	part, err := writer.CreateFormFile("file", fileName)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/upgrades/packages/upload", &body)
	r.Header.Set("Content-Type", writer.FormDataContentType())
	principal := &authz.Principal{UserID: uuid.New(), Username: "tester"}
	return r.WithContext(authz.WithPrincipal(r.Context(), principal))
}

type uploadResult struct {
	Package   *Package `json:"package"`
	Execution *Job     `json:"execution"`
	Warning   string   `json:"warning"`
	Message   string   `json:"message"`
}

func serveUpload(t *testing.T, h *Handler, r *http.Request) (int, string, uploadResult) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.UploadPackage(rec, r)
	var body struct {
		Code    string          `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应不是合法 JSON: %v, body=%s", err, rec.Body.String())
	}
	var result uploadResult
	if len(body.Data) > 0 {
		if err := json.Unmarshal(body.Data, &result); err != nil {
			t.Fatalf("响应 data 不是合法 JSON: %v", err)
		}
	}
	return rec.Code, body.Code + " " + body.Message, result
}

func newUploadTestHandler(t *testing.T, pub ed25519.PublicKey) (*Handler, *fakePackageRegistrar, *fakeUpgradeExecutor, string) {
	t.Helper()
	dir := t.TempDir()
	reg := &fakePackageRegistrar{}
	exec := &fakeUpgradeExecutor{}
	h := NewHandler(nil, nil, audits.NewService(nil)).
		SetUploadDir(dir, 0).
		SetArtifactVerifier(func(path string, pkg *Package) error {
			return verifyPackageArtifactWithKey(path, pkg, pub)
		}).
		SetUploadDeps(reg, exec)
	return h, reg, exec, dir
}

// embeddedPackageBytes 构造内嵌签名新格式包，返回归档字节与公钥。
func embeddedPackageBytes(t *testing.T, versionFrom, versionTo string, targetSchema int) ([]byte, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	payload := map[string][]byte{"payload/app.bin": []byte("signed payload")}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	manifest := testManifestWithProtocol(t, versionTo, versionFrom, versionTo, targetSchema, payload)
	sig := ed25519.Sign(priv, manifest)
	archivePath := filepath.Join(t.TempDir(), "pkg.tar.gz")
	content := writeTestArchive(t, archivePath, []testArchiveEntry{
		{name: "release-" + versionTo + "/manifest.json", data: manifest},
		{name: "release-" + versionTo + "/manifest.sig", data: []byte(base64.StdEncoding.EncodeToString(sig) + "\n")},
		{name: "release-" + versionTo + "/payload/app.bin", data: payload["payload/app.bin"]},
	})
	return content, pub, priv
}

// legacyPackageBytes 构造旧格式包（无 manifest.sig、manifest 无版本字段），
// 返回归档字节、公钥与整包 detached 签名（base64）。
func legacyPackageBytes(t *testing.T, versionTo string) ([]byte, ed25519.PublicKey, string) {
	t.Helper()
	payload := []byte("legacy payload")
	manifest := testManifest(t, versionTo, map[string][]byte{"payload/app.bin": payload})
	archivePath := filepath.Join(t.TempDir(), "pkg.tar.gz")
	content := writeTestArchive(t, archivePath, []testArchiveEntry{
		{name: "release/manifest.json", data: manifest},
		{name: "release/payload/app.bin", data: payload},
	})
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return content, pub, base64.StdEncoding.EncodeToString(ed25519.Sign(priv, content))
}

// ---------- 上传全流程 ----------

// TestUploadPackageEmbeddedAutoExecute 新格式包仅传 file：内嵌验签 + 版本从包内读取，
// 登记 VERIFIED 后自动创建升级执行。
func TestUploadPackageEmbeddedAutoExecute(t *testing.T) {
	content, pub, _ := embeddedPackageBytes(t, "2.0.0", "2.1.0", 0)
	h, _, exec, _ := newUploadTestHandler(t, pub)

	code, msg, result := serveUpload(t, h, buildUploadRequest(t, "jiuzhang-offline-2.1.0.tar.gz", content, nil))
	if code != http.StatusOK {
		t.Fatalf("状态码 = %d, want 200 (%s)", code, msg)
	}
	if result.Package == nil {
		t.Fatalf("响应缺少 package: %s", msg)
	}
	if result.Package.Status != PackageVerified {
		t.Errorf("包状态 = %s, want VERIFIED", result.Package.Status)
	}
	if result.Package.VersionFrom != "2.0.0" || result.Package.VersionTo != "2.1.0" {
		t.Errorf("版本 = %s -> %s, want 2.0.0 -> 2.1.0（应来自包内 manifest）",
			result.Package.VersionFrom, result.Package.VersionTo)
	}
	if result.Execution == nil {
		t.Fatal("验证通过后应自动创建升级执行")
	}
	if result.Warning != "" {
		t.Errorf("执行创建成功时不应有 warning: %s", result.Warning)
	}
	if exec.calls != 1 || exec.lastPackageID != result.Package.ID {
		t.Errorf("自动执行调用次数 = %d, packageID 匹配 = %v", exec.calls, exec.lastPackageID == result.Package.ID)
	}
	if result.Execution.PackageID == nil || *result.Execution.PackageID != result.Package.ID {
		t.Error("执行应关联新登记的升级包")
	}
}

// TestUploadPackageFormVersionMismatch 表单与包内 manifest 版本不一致 → 400。
func TestUploadPackageFormVersionMismatch(t *testing.T) {
	content, pub, _ := embeddedPackageBytes(t, "2.0.0", "2.1.0", 0)
	h, _, exec, _ := newUploadTestHandler(t, pub)

	code, _, _ := serveUpload(t, h, buildUploadRequest(t, "pkg.tar.gz", content,
		map[string]string{"version_to": "2.2.0"}))
	if code != http.StatusBadRequest {
		t.Fatalf("version_to 不一致状态码 = %d, want 400", code)
	}
	if exec.calls != 0 {
		t.Error("版本不一致不得创建执行")
	}

	// 表单与包内一致则放行
	h2, _, _, _ := newUploadTestHandler(t, pub)
	code, msg, result := serveUpload(t, h2, buildUploadRequest(t, "pkg.tar.gz", content,
		map[string]string{"version_from": "2.0.0", "version_to": "2.1.0"}))
	if code != http.StatusOK || result.Package == nil || result.Package.Status != PackageVerified {
		t.Fatalf("版本一致应验证通过: code=%d msg=%s", code, msg)
	}
}

// TestUploadPackageLegacyRequiresSignature 旧格式包无内嵌签名时回落旧行为：
// 缺少 multipart signature → 400；提供签名与版本 → 旁车验签通过。
func TestUploadPackageLegacyRequiresSignature(t *testing.T) {
	content, pub, signature := legacyPackageBytes(t, "2.1.0")

	h, _, _, _ := newUploadTestHandler(t, pub)
	code, msg, _ := serveUpload(t, h, buildUploadRequest(t, "legacy.tar.gz", content,
		map[string]string{"version_from": "2.0.0", "version_to": "2.1.0"}))
	if code != http.StatusBadRequest {
		t.Fatalf("缺签名状态码 = %d, want 400 (%s)", code, msg)
	}

	h2, _, exec, dir := newUploadTestHandler(t, pub)
	code, msg, result := serveUpload(t, h2, buildUploadRequest(t, "legacy.tar.gz", content,
		map[string]string{"signature": signature, "version_from": "2.0.0", "version_to": "2.1.0"}))
	if code != http.StatusOK || result.Package == nil || result.Package.Status != PackageVerified {
		t.Fatalf("旧格式包旁车验签应通过: code=%d msg=%s", code, msg)
	}
	if result.Execution == nil || exec.calls != 1 {
		t.Error("旧格式包验证通过后同样应自动创建执行")
	}
	if _, err := os.Stat(filepath.Join(dir, "legacy.tar.gz.sig")); err != nil {
		t.Errorf("旧格式包应落盘旁车签名: %v", err)
	}
}

// TestUploadPackageLegacyMissingVersions 旧格式包且表单未提供版本 → 400。
func TestUploadPackageLegacyMissingVersions(t *testing.T) {
	content, pub, signature := legacyPackageBytes(t, "2.1.0")
	h, _, _, _ := newUploadTestHandler(t, pub)

	code, msg, _ := serveUpload(t, h, buildUploadRequest(t, "legacy.tar.gz", content,
		map[string]string{"signature": signature}))
	if code != http.StatusBadRequest {
		t.Fatalf("缺版本状态码 = %d, want 400 (%s)", code, msg)
	}
}

// TestUploadPackageVerifyFailureRejected 内嵌验签失败：包以 REJECTED 落库，
// 响应如实说明原因，不创建执行，落盘文件被清理。
func TestUploadPackageVerifyFailureRejected(t *testing.T) {
	payload := []byte("signed payload")
	manifest := testManifestWithProtocol(t, "2.1.0", "2.0.0", "2.1.0", 0,
		map[string][]byte{"payload/app.bin": payload})
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	badSig := ed25519.Sign(priv, []byte("tampered manifest"))
	content := writeTestArchive(t, filepath.Join(t.TempDir(), "pkg.tar.gz"), []testArchiveEntry{
		{name: "release/manifest.json", data: manifest},
		{name: "release/manifest.sig", data: []byte(base64.StdEncoding.EncodeToString(badSig))},
		{name: "release/payload/app.bin", data: payload},
	})

	h, _, exec, dir := newUploadTestHandler(t, pub)
	code, _, result := serveUpload(t, h, buildUploadRequest(t, "tampered.tar.gz", content, nil))
	if code != http.StatusOK {
		t.Fatalf("状态码 = %d, want 200（REJECTED 留证语义）", code)
	}
	if result.Package == nil || result.Package.Status != PackageRejected {
		t.Fatalf("验签失败包状态应为 REJECTED: %+v", result.Package)
	}
	if result.Message == "" {
		t.Error("响应应包含失败原因 message")
	}
	if result.Execution != nil || exec.calls != 0 {
		t.Error("验签失败不得创建执行")
	}
	if _, err := os.Stat(filepath.Join(dir, "tampered.tar.gz")); !os.IsNotExist(err) {
		t.Error("REJECTED 后落盘文件应被清理")
	}
}

// TestUploadPackageAutoExecuteConflictWarning 自动执行创建失败（已有执行中任务）：
// 包保持 VERIFIED，响应 execution:null + warning，不算上传失败。
func TestUploadPackageAutoExecuteConflictWarning(t *testing.T) {
	content, pub, _ := embeddedPackageBytes(t, "2.0.0", "2.1.0", 0)
	h, _, exec, _ := newUploadTestHandler(t, pub)
	exec.err = ErrActiveUpgrade

	code, _, result := serveUpload(t, h, buildUploadRequest(t, "jiuzhang-offline-2.1.0.tar.gz", content, nil))
	if code != http.StatusOK {
		t.Fatalf("状态码 = %d, want 200", code)
	}
	if result.Package == nil || result.Package.Status != PackageVerified {
		t.Fatalf("包应保持 VERIFIED: %+v", result.Package)
	}
	if result.Execution != nil {
		t.Error("执行创建失败时 execution 应为 null")
	}
	if !strings.Contains(result.Warning, "手动执行") {
		t.Errorf("warning 应说明可手动执行: %q", result.Warning)
	}
}

// TestUploadPackageManifestTargetSchema target_schema_version 来源：
// 包内 manifest 优先，表单 manifest 字段可覆盖。
func TestUploadPackageManifestTargetSchema(t *testing.T) {
	content, pub, _ := embeddedPackageBytes(t, "2.0.0", "2.1.0", 9)

	h, _, _, _ := newUploadTestHandler(t, pub)
	code, _, result := serveUpload(t, h, buildUploadRequest(t, "pkg-a.tar.gz", content, nil))
	if code != http.StatusOK || result.Package == nil {
		t.Fatalf("上传失败: code=%d", code)
	}
	if got := ManifestTargetSchema(result.Package.Manifest); got != 9 {
		t.Errorf("登记 manifest 目标迁移号 = %d, want 9（包内）", got)
	}

	h2, _, _, _ := newUploadTestHandler(t, pub)
	code, _, result = serveUpload(t, h2, buildUploadRequest(t, "pkg-b.tar.gz", content,
		map[string]string{"manifest": `{"target_schema_version":12}`}))
	if code != http.StatusOK || result.Package == nil {
		t.Fatalf("上传失败: code=%d", code)
	}
	if got := ManifestTargetSchema(result.Package.Manifest); got != 12 {
		t.Errorf("表单覆盖后目标迁移号 = %d, want 12", got)
	}
}
