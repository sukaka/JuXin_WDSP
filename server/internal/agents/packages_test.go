package agents

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/server/internal/audits"
)

type fakeTokenChecker struct {
	active map[string]bool
	calls  int
}

func (f *fakeTokenChecker) IsEnrollmentTokenActive(_ context.Context, tokenHash string, _ time.Time) (bool, error) {
	f.calls++
	return f.active[tokenHash], nil
}

type spyAuditRecorder struct {
	records []audits.RecordInput
}

func (s *spyAuditRecorder) Record(_ context.Context, in audits.RecordInput) error {
	s.records = append(s.records, in)
	return nil
}

func writeTestPackagesDir(t *testing.T) (string, map[string][]byte) {
	t.Helper()
	dir := t.TempDir()
	files := map[string][]byte{
		"wdsp-agent-2.4.0-1.x86_64.rpm":      []byte("fake-rpm-payload-amd64"),
		"wdsp-agent_2.4.0_amd64.deb":         []byte("fake-deb-payload-amd64"),
		"wdsp-agent-2.4.0-darwin-arm64.pkg":  []byte("fake-pkg-payload-arm64"),
		"wdsp-agent-2.4.0-windows-amd64.zip": []byte("fake-zip-payload-amd64"),
	}
	var items []PackageItem
	meta := map[string][3]string{
		"wdsp-agent-2.4.0-1.x86_64.rpm":      {"linux", "amd64", "rpm"},
		"wdsp-agent_2.4.0_amd64.deb":         {"linux", "amd64", "deb"},
		"wdsp-agent-2.4.0-darwin-arm64.pkg":  {"darwin", "arm64", "pkg"},
		"wdsp-agent-2.4.0-windows-amd64.zip": {"windows", "amd64", "zip"},
	}
	for fname, content := range files {
		if err := os.WriteFile(filepath.Join(dir, fname), content, 0o644); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(content)
		m := meta[fname]
		items = append(items, PackageItem{
			OS:       m[0],
			Distro:   m[2],
			Arch:     m[1],
			Format:   m[2],
			Filename: fname,
			Size:     int64(len(content)),
			SHA256:   hex.EncodeToString(sum[:]),
		})
	}
	// 额外注入恶意/异常条目，断言 PackageStore 严格过滤
	outside := filepath.Join(t.TempDir(), "secret.txt")
	_ = os.WriteFile(outside, []byte("top-secret"), 0o600)
	_ = os.Symlink(outside, filepath.Join(dir, "symlink.rpm"))
	fakeHash := strings.Repeat("a", 64)
	items = append(items,
		PackageItem{OS: "linux", Arch: "arm64", Format: "rpm", Filename: "../secret.txt", Size: 10, SHA256: fakeHash},
		PackageItem{OS: "linux", Arch: "arm64", Format: "deb", Filename: "symlink.rpm", Size: 10, SHA256: fakeHash},
		PackageItem{OS: "windows", Arch: "arm64", Format: "zip", Filename: "missing.zip", Size: 10, SHA256: fakeHash},
	)
	manifestBytes, err := json.Marshal(PackageManifest{
		Version:  "2.4.0",
		BuiltAt:  "2026-11-24T05:00:00Z",
		Packages: items,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), manifestBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, files
}

func TestEmbeddedScriptsMatchPackagingSource(t *testing.T) {
	pairs := [][2]string{
		{"scripts/install-agent.sh", "../../../packaging/wdsp-agent/scripts/install-agent.sh"},
		{"scripts/install-agent.ps1", "../../../packaging/wdsp-agent/scripts/install-agent.ps1"},
	}
	for _, pair := range pairs {
		embedded, err := embeddedBootstrapScripts.ReadFile(pair[0])
		if err != nil {
			t.Fatalf("read embedded %s: %v", pair[0], err)
		}
		src, err := os.ReadFile(pair[1])
		if err != nil {
			t.Fatalf("read source %s: %v", pair[1], err)
		}
		if !bytes.Equal(embedded, src) {
			t.Fatalf("embedded %s 与源脚本 %s 不一致，请同步更新", pair[0], pair[1])
		}
	}
}

func TestPackageStoreValidationAndFiltering(t *testing.T) {
	// 1. 不存在或空目录 -> unavailable
	if _, ok := NewPackageStore(filepath.Join(t.TempDir(), "nonexistent")).LoadManifest(); ok {
		t.Fatal("不存在目录应返回 available=false")
	}

	// 2. 有效目录：过滤掉路径穿越、符号链接与缺失文件
	dir, _ := writeTestPackagesDir(t)
	m, ok := NewPackageStore(dir).LoadManifest()
	if !ok || m == nil {
		t.Fatal("有效目录应返回 available=true")
	}
	if len(m.Packages) != 4 {
		t.Fatalf("应仅保留 4 个合法包（剔除 traversal/symlink/missing），got %d: %+v", len(m.Packages), m.Packages)
	}
	if _, _, err := NewPackageStore(dir).Resolve("linux", "arm64", "rpm"); err == nil {
		t.Fatal("路径穿越条目不应可被解析")
	}
	if _, _, err := NewPackageStore(dir).Resolve("linux", "arm64", "deb"); err == nil {
		t.Fatal("符号链接条目不应可被解析")
	}
}

func TestAdminPackagesEndpoints(t *testing.T) {
	dir, files := writeTestPackagesDir(t)
	auditSpy := &spyAuditRecorder{}
	h := NewHandler(nil).SetAudits(auditSpy).SetPackageDir(dir)

	mux := newAdminMux(h, injectPerms(PermAgentsView, PermAgentsManage))

	// 1. 清单查询
	req := httptest.NewRequest(http.MethodGet, "/api/v1/traffic/agents/packages", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ListPackages status=%d body=%s", rec.Code, rec.Body.String())
	}
	var env struct {
		Code string           `json:"code"`
		Data PackagesResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Code != "SUCCESS" || !env.Data.Available || env.Data.Version != "2.4.0" || len(env.Data.Packages) != 4 {
		t.Fatalf("unexpected ListPackages response: %+v", env)
	}

	// 2. 离线下载 + SHA256 头 + 审计记录
	dlReq := httptest.NewRequest(http.MethodGet, "/api/v1/traffic/agents/packages/linux/amd64/rpm", nil)
	dlRec := httptest.NewRecorder()
	mux.ServeHTTP(dlRec, dlReq)
	if dlRec.Code != http.StatusOK {
		t.Fatalf("DownloadPackage status=%d body=%s", dlRec.Code, dlRec.Body.String())
	}
	wantBody := files["wdsp-agent-2.4.0-1.x86_64.rpm"]
	if !bytes.Equal(dlRec.Body.Bytes(), wantBody) {
		t.Fatalf("download body mismatch")
	}
	wantSum := sha256.Sum256(wantBody)
	if got := dlRec.Header().Get("X-WDSP-SHA256"); got != hex.EncodeToString(wantSum[:]) {
		t.Fatalf("X-WDSP-SHA256=%q want %q", got, hex.EncodeToString(wantSum[:]))
	}
	if dlRec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing nosniff header")
	}
	if len(auditSpy.records) != 1 || auditSpy.records[0].Action != "download" {
		t.Fatalf("expected download audit record, got %+v", auditSpy.records)
	}

	// 3. 非法参数 400 / 不存在 404
	badReq := httptest.NewRequest(http.MethodGet, "/api/v1/traffic/agents/packages/freebsd/amd64/rpm", nil)
	badRec := httptest.NewRecorder()
	mux.ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("invalid os should return 400, got %d", badRec.Code)
	}

	missReq := httptest.NewRequest(http.MethodGet, "/api/v1/traffic/agents/packages/windows/arm64/zip", nil)
	missRec := httptest.NewRecorder()
	mux.ServeHTTP(missRec, missReq)
	if missRec.Code != http.StatusNotFound {
		t.Fatalf("missing arch package should return 404, got %d", missRec.Code)
	}
}

func TestMachineBootstrapEndpointsAuthAndNonConsuming(t *testing.T) {
	dir, files := writeTestPackagesDir(t)
	tok := "wdt_" + strings.Repeat("a1", 32)
	tokHash := HashSecret(tok)
	checker := &fakeTokenChecker{active: map[string]bool{tokHash: true}}

	mh := NewMachineHandler(nil).SetPackageDir(dir).SetEnrollmentTokenChecker(checker)
	mux := http.NewServeMux()
	RegisterMachineRoutes(mux, mh)

	// 1. 无 Authorization -> 401
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/agents/bootstrap/manifest", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing auth must return 401, got %d", rec.Code)
	}

	// 2. Query 传令牌 -> 400（禁止进入访问日志）
	qReq := httptest.NewRequest(http.MethodGet, "/api/v1/agents/bootstrap/script/linux?token="+tok, nil)
	qReq.Header.Set("Authorization", "Bearer "+tok)
	qRec := httptest.NewRecorder()
	mux.ServeHTTP(qRec, qReq)
	if qRec.Code != http.StatusBadRequest {
		t.Fatalf("token in query must return 400, got %d", qRec.Code)
	}

	// 3. 格式非法或未登记令牌 -> 401
	badTokReq := httptest.NewRequest(http.MethodGet, "/api/v1/agents/bootstrap/script/linux", nil)
	badTokReq.Header.Set("Authorization", "Bearer wdt_nothex")
	badTokRec := httptest.NewRecorder()
	mux.ServeHTTP(badTokRec, badTokReq)
	if badTokRec.Code != http.StatusUnauthorized {
		t.Fatalf("bad token format must return 401, got %d", badTokRec.Code)
	}

	// 4. 有效 ACTIVE Token 连续拉取 manifest + linux/darwin/windows 脚本 + rpm/zip 包均成功（且不消耗 Token）
	doAuthGet := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		r := httptest.NewRecorder()
		mux.ServeHTTP(r, req)
		return r
	}

	if r := doAuthGet("/api/v1/agents/bootstrap/manifest"); r.Code != http.StatusOK {
		t.Fatalf("bootstrap manifest status=%d body=%s", r.Code, r.Body.String())
	}
	for _, tc := range []struct {
		osName  string
		keyword string
	}{
		{"linux", "wdsp-agent-install"},
		{"darwin", "wdsp-agent-install"},
		{"windows", "#Requires -Version 5.1"},
	} {
		r := doAuthGet("/api/v1/agents/bootstrap/script/" + tc.osName)
		if r.Code != http.StatusOK {
			t.Fatalf("bootstrap script %s status=%d", tc.osName, r.Code)
		}
		if !strings.Contains(r.Body.String(), tc.keyword) {
			t.Fatalf("script %s missing expected content %q", tc.osName, tc.keyword)
		}
		sum := sha256.Sum256(r.Body.Bytes())
		if r.Header().Get("X-WDSP-SHA256") != hex.EncodeToString(sum[:]) {
			t.Fatalf("script %s SHA256 header mismatch", tc.osName)
		}
	}

	pkgRec := doAuthGet("/api/v1/agents/bootstrap/packages/windows/amd64/zip")
	if pkgRec.Code != http.StatusOK || !bytes.Equal(pkgRec.Body.Bytes(), files["wdsp-agent-2.4.0-windows-amd64.zip"]) {
		t.Fatalf("bootstrap package windows/amd64/zip failed: status=%d", pkgRec.Code)
	}
	// 确认同一 Token 已多次成功拉取且未失效
	if checker.calls < 5 {
		t.Fatalf("expected non-consuming repeated checks, calls=%d", checker.calls)
	}

	// 5. 模拟 enroll 消费 Token 后，立刻返回 401
	delete(checker.active, tokHash)
	if r := doAuthGet("/api/v1/agents/bootstrap/packages/linux/amd64/rpm"); r.Code != http.StatusUnauthorized {
		t.Fatalf("used/revoked token must return 401, got %d", r.Code)
	}
}
