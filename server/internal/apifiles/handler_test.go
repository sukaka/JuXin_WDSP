// handler_test.go 文件资产 HTTP 入口测试：权限矩阵 / 参数校验 /
// 列表过滤分页 / stats 聚合（内存仓储驱动真实 Handler 与路由）。
package apifiles

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apidata"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// injectPrincipal 模拟认证链：注入持有给定权限点集合的主体。
func injectPrincipal(perms ...string) func(http.Handler) http.Handler {
	set := map[string]bool{}
	for _, p := range perms {
		set[p] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: uuid.New(), Username: "w8file-tester", PermsSet: set}
			ctx := authz.WithPrincipal(r.Context(), p)
			ctx = context.WithValue(ctx, response.RequestIDKey, "w8file-rid")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// noPrincipal 模拟未注入主体的认证链（权限中间件应 401）。
func noPrincipal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

// newTestMux 装配文件资产路由（内存仓储）。
func newTestMux(store *MemStore, authzFn func(http.Handler) http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterRoutes(mux, authzFn, NewHandler(store))
	return mux
}

// do 发请求。
func do(t *testing.T, mux http.Handler, url string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// seedAssets 造数：覆盖方向/敏感/身份/IP/端点维度。
func seedAssets(store *MemStore) {
	now := time.Now().UTC()
	store.addAsset(FileAsset{
		ID: uuid.New(), EndpointKey: "POST /api/v1/files/upload", Direction: DirectionUpload,
		FileName: "report.pdf", Extension: "pdf", MIME: "application/pdf", SizeBytes: 100,
		IdentityFingerprint: "auth:u1", ClientIPMasked: "203.0.113.0",
		SensitiveTypes: []string{}, FirstSeen: now.Add(-time.Hour), LastSeen: now, TransferCount: 2,
	})
	store.addAsset(FileAsset{
		ID: uuid.New(), EndpointKey: "POST /api/v1/files/upload", Direction: DirectionUpload,
		FileName: "id_backup.pem", Extension: "pem", MIME: "application/x-pem-file", SizeBytes: 1700,
		IdentityFingerprint: "auth:u1", ClientIPMasked: "203.0.113.0",
		SensitiveTypes: []string{"credential_file"}, FirstSeen: now.Add(-time.Hour), LastSeen: now, TransferCount: 1,
	})
	store.addAsset(FileAsset{
		ID: uuid.New(), EndpointKey: "GET /api/v1/orders/export", Direction: DirectionDownload,
		FileName: "orders.csv", Extension: "csv", MIME: "text/csv", SizeBytes: 5000,
		IdentityFingerprint: "auth:u2", ClientIPMasked: "198.51.100.0",
		SensitiveTypes: []string{"data_export"}, FirstSeen: now.Add(-2 * time.Hour), LastSeen: now, TransferCount: 7,
	})
	// 窗口外资产（8 天前）：默认 7 天窗口不计
	store.addAsset(FileAsset{
		ID: uuid.New(), EndpointKey: "GET /api/v1/old", Direction: DirectionDownload,
		FileName: "old.zip", Extension: "zip", MIME: "application/zip", SizeBytes: 9,
		IdentityFingerprint: "auth:u9", ClientIPMasked: "192.0.2.0",
		SensitiveTypes: []string{}, FirstSeen: now.AddDate(0, 0, -9), LastSeen: now.AddDate(0, 0, -8), TransferCount: 3,
	})
}

// 权限矩阵：未登录 401 / 无权限 403 / api_data.read 200（两个端点同口径）。
func TestFileAssetsPermissionMatrix(t *testing.T) {
	store := NewMemStore()
	for _, url := range []string{
		"/api/v1/api-security/file-assets",
		"/api/v1/api-security/file-assets/stats",
	} {
		if rr := do(t, newTestMux(store, noPrincipal), url); rr.Code != http.StatusUnauthorized {
			t.Fatalf("%s anon: status=%d, want 401", url, rr.Code)
		}
		if rr := do(t, newTestMux(store, injectPrincipal("other.read")), url); rr.Code != http.StatusForbidden {
			t.Fatalf("%s noperm: status=%d, want 403", url, rr.Code)
		}
		if rr := do(t, newTestMux(store, injectPrincipal(apidata.PermDataRead)), url); rr.Code != http.StatusOK {
			t.Fatalf("%s authorized: status=%d body=%s", url, rr.Code, rr.Body.String())
		}
	}
}

// 参数校验：非法枚举/超长/非布尔 400。
func TestFileAssetsValidation(t *testing.T) {
	mux := newTestMux(NewMemStore(), injectPrincipal(apidata.PermDataRead))
	for _, url := range []string{
		"/api/v1/api-security/file-assets?direction=SIDEWAYS",
		"/api/v1/api-security/file-assets?extension=" + strings.Repeat("a", 17),
		"/api/v1/api-security/file-assets?mime=" + strings.Repeat("a", 129),
		"/api/v1/api-security/file-assets?endpoint_key=" + strings.Repeat("a", 561),
		"/api/v1/api-security/file-assets?identity_fingerprint=" + strings.Repeat("a", 129),
		"/api/v1/api-security/file-assets?sensitive_only=maybe",
	} {
		if rr := do(t, mux, url); rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: status=%d, want 400", url, rr.Code)
		}
	}
}

// 列表：窗口过滤 + direction/sensitive_only/endpoint_key 过滤 + 分页。
func TestFileAssetsList(t *testing.T) {
	store := NewMemStore()
	seedAssets(store)
	mux := newTestMux(store, injectPrincipal(apidata.PermDataRead))

	type listBody struct {
		Data struct {
			Total int64 `json:"total"`
			Items []struct {
				FileName       string   `json:"filename"`
				Direction      string   `json:"direction"`
				SensitiveTypes []string `json:"sensitive_types"`
			} `json:"items"`
		} `json:"data"`
	}
	decode := func(rr *httptest.ResponseRecorder) listBody {
		var b listBody
		if err := json.Unmarshal(rr.Body.Bytes(), &b); err != nil {
			t.Fatalf("decode: %v (body=%s)", err, rr.Body.String())
		}
		return b
	}

	// 默认窗口：窗口外 old.zip 不出现
	rr := do(t, mux, "/api/v1/api-security/file-assets")
	if rr.Code != http.StatusOK {
		t.Fatalf("list: status=%d body=%s", rr.Code, rr.Body.String())
	}
	b := decode(rr)
	if b.Data.Total != 3 {
		t.Fatalf("default window total = %d, want 3 (%+v)", b.Data.Total, b.Data.Items)
	}
	// direction 过滤
	b = decode(do(t, mux, "/api/v1/api-security/file-assets?direction=DOWNLOAD"))
	if b.Data.Total != 1 || b.Data.Items[0].FileName != "orders.csv" {
		t.Fatalf("direction filter = %+v", b.Data)
	}
	// sensitive_only 过滤
	b = decode(do(t, mux, "/api/v1/api-security/file-assets?sensitive_only=true"))
	if b.Data.Total != 2 {
		t.Fatalf("sensitive_only total = %d, want 2 (%+v)", b.Data.Total, b.Data.Items)
	}
	for _, it := range b.Data.Items {
		if len(it.SensitiveTypes) == 0 {
			t.Fatalf("sensitive_only item without types: %+v", it)
		}
	}
	// endpoint 精确过滤 + extension 过滤
	b = decode(do(t, mux, "/api/v1/api-security/file-assets?endpoint_key=POST%20/api/v1/files/upload&extension=pem"))
	if b.Data.Total != 1 || b.Data.Items[0].FileName != "id_backup.pem" {
		t.Fatalf("endpoint+extension filter = %+v", b.Data)
	}
	// 分页
	b = decode(do(t, mux, "/api/v1/api-security/file-assets?page_size=2&page=2"))
	if b.Data.Total != 3 || len(b.Data.Items) != 1 {
		t.Fatalf("pagination = %+v", b.Data)
	}
	// 放宽窗口：old.zip 出现
	b = decode(do(t, mux, "/api/v1/api-security/file-assets?days=30"))
	if b.Data.Total != 4 {
		t.Fatalf("30d window total = %d, want 4", b.Data.Total)
	}
}

func TestFileAssetsIdentityFingerprintFilter(t *testing.T) {
	store := NewMemStore()
	seedAssets(store)
	mux := newTestMux(store, injectPrincipal(apidata.PermDataRead))
	list := func(url string) (int64, []FileAsset) {
		t.Helper()
		rr := do(t, mux, url)
		if rr.Code != http.StatusOK {
			t.Fatalf("identity filter: status=%d body=%s", rr.Code, rr.Body.String())
		}
		var body struct {
			Data struct {
				Total int64       `json:"total"`
				Items []FileAsset `json:"items"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode identity filter: %v", err)
		}
		return body.Data.Total, body.Data.Items
	}

	total, items := list("/api/v1/api-security/file-assets?identity_fingerprint=%20auth%3Au1%20")
	if total != 2 || len(items) != 2 {
		t.Fatalf("trimmed exact identity filter: total=%d items=%d, want 2", total, len(items))
	}
	for _, item := range items {
		if item.IdentityFingerprint != "auth:u1" {
			t.Fatalf("identity filter returned a different identity")
		}
	}
	total, items = list("/api/v1/api-security/file-assets?identity_fingerprint=auth%3Au")
	if total != 0 || len(items) != 0 {
		t.Fatalf("identity prefix must not match: total=%d items=%d", total, len(items))
	}
	total, items = list("/api/v1/api-security/file-assets?identity_fingerprint=%20%20")
	if total != 3 || len(items) != 3 {
		t.Fatalf("blank identity must not filter: total=%d items=%d, want 3", total, len(items))
	}
	total, items = list("/api/v1/api-security/file-assets?identity_fingerprint=" + strings.Repeat("a", 128))
	if total != 0 || len(items) != 0 {
		t.Fatalf("128-character identity should be accepted: total=%d items=%d", total, len(items))
	}
	total, items = list("/api/v1/api-security/file-assets?identity_fingerprint=auth%3Au1&sensitive_only=true")
	if total != 1 || len(items) != 1 || items[0].FileName != "id_backup.pem" {
		t.Fatalf("identity plus other filters: total=%d items=%d", total, len(items))
	}
	total, items = list("/api/v1/api-security/file-assets?identity_fingerprint=auth%3Au1&page_size=1&page=2")
	if total != 2 || len(items) != 1 {
		t.Fatalf("identity filter pagination: total=%d items=%d, want 2 and 1", total, len(items))
	}
}

func TestMemStoreIdentityFingerprintExactMatch(t *testing.T) {
	store := NewMemStore()
	now := time.Now().UTC()
	for _, identity := range []string{"auth:u1", "auth:u10", ""} {
		store.addAsset(FileAsset{
			ID: uuid.New(), Direction: DirectionDownload, IdentityFingerprint: identity,
			LastSeen: now, SensitiveTypes: []string{},
		})
	}
	for _, tc := range []struct {
		name      string
		filter    string
		wantTotal int64
	}{
		{name: "empty disables filter", wantTotal: 3},
		{name: "exact match", filter: "auth:u1", wantTotal: 1},
		{name: "prefix does not match", filter: "auth:u", wantTotal: 0},
		{name: "case sensitive", filter: "AUTH:U1", wantTotal: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			items, total, err := store.ListAssets(context.Background(), AssetFilter{
				Days: 7, IdentityFingerprint: tc.filter, Page: 1, PageSize: 20,
			})
			if err != nil {
				t.Fatalf("list assets: %v", err)
			}
			if total != tc.wantTotal || int64(len(items)) != tc.wantTotal {
				t.Fatalf("identity filter: total=%d items=%d, want %d", total, len(items), tc.wantTotal)
			}
			if tc.filter == "auth:u1" && items[0].IdentityFingerprint != tc.filter {
				t.Fatalf("identity filter returned a different identity")
			}
		})
	}
}

// stats：§106 汇总与四类 TOP 聚合。
func TestFileAssetsStats(t *testing.T) {
	store := NewMemStore()
	seedAssets(store)
	mux := newTestMux(store, injectPrincipal(apidata.PermDataRead))

	rr := do(t, mux, "/api/v1/api-security/file-assets/stats?days=7")
	if rr.Code != http.StatusOK {
		t.Fatalf("stats: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Data struct {
			Days    int `json:"days"`
			Summary struct {
				UploadAssets       int64 `json:"upload_assets"`
				DownloadAssets     int64 `json:"download_assets"`
				UploadTransfers    int64 `json:"upload_transfers"`
				DownloadTransfers  int64 `json:"download_transfers"`
				SensitiveFileCount int64 `json:"sensitive_file_count"`
			} `json:"summary"`
			TopFiles []struct {
				FileName  string `json:"filename"`
				Direction string `json:"direction"`
				Transfers int64  `json:"transfers"`
			} `json:"top_files"`
			TopIPs []struct {
				ClientIPMasked string `json:"client_ip_masked"`
				Transfers      int64  `json:"transfers"`
			} `json:"top_ips"`
			TopAccounts []struct {
				IdentityFingerprint string `json:"identity_fingerprint"`
				Transfers           int64  `json:"transfers"`
				Files               int64  `json:"files"`
			} `json:"top_accounts"`
			TopAPIs []struct {
				EndpointKey string `json:"endpoint_key"`
				Transfers   int64  `json:"transfers"`
			} `json:"top_apis"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rr.Body.String())
	}
	s := body.Data.Summary
	if s.UploadAssets != 2 || s.DownloadAssets != 1 || s.UploadTransfers != 3 || s.DownloadTransfers != 7 {
		t.Fatalf("summary = %+v", s)
	}
	if s.SensitiveFileCount != 2 {
		t.Fatalf("sensitive_file_count = %d, want 2", s.SensitiveFileCount)
	}
	// File TOP：orders.csv 7 次居首
	if len(body.Data.TopFiles) == 0 || body.Data.TopFiles[0].FileName != "orders.csv" || body.Data.TopFiles[0].Transfers != 7 {
		t.Fatalf("top_files = %+v", body.Data.TopFiles)
	}
	// IP TOP：198.51.100.0 以 7 次居首
	if len(body.Data.TopIPs) == 0 || body.Data.TopIPs[0].ClientIPMasked != "198.51.100.0" || body.Data.TopIPs[0].Transfers != 7 {
		t.Fatalf("top_ips = %+v", body.Data.TopIPs)
	}
	// Account TOP：auth:u1 共 3 次传输 2 个文件
	if len(body.Data.TopAccounts) == 0 {
		t.Fatalf("top_accounts empty")
	}
	var u1 *struct {
		IdentityFingerprint string `json:"identity_fingerprint"`
		Transfers           int64  `json:"transfers"`
		Files               int64  `json:"files"`
	}
	for i := range body.Data.TopAccounts {
		if body.Data.TopAccounts[i].IdentityFingerprint == "auth:u1" {
			u1 = &body.Data.TopAccounts[i]
		}
	}
	if u1 == nil || u1.Transfers != 3 || u1.Files != 2 {
		t.Fatalf("top_accounts = %+v", body.Data.TopAccounts)
	}
	// API TOP：上传端点 3 次传输
	if len(body.Data.TopAPIs) == 0 {
		t.Fatalf("top_apis empty")
	}
	var found bool
	for _, a := range body.Data.TopAPIs {
		if a.EndpointKey == "POST /api/v1/files/upload" && a.Transfers == 3 {
			found = true
		}
	}
	if !found {
		t.Fatalf("top_apis = %+v", body.Data.TopAPIs)
	}
}
