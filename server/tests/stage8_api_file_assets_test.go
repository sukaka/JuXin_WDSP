// stage8_api_file_assets_test.go API 文件资产（W8-FILE / P1-04）集成测试。
// 覆盖：迁移 000061 表结构/CHECK/唯一索引/阈值种子；
// 采集链路（JSONL → Collector → FileObsStore UPSERT）幂等与归一纪律
// （IP 掩码/敏感词表/endpoint_id 解析/缺失容忍）；
// apifiles SQL Store 列表过滤与 §106 统计聚合；批量下载风险判定
// （触发/未触发/findings dedup 幂等）；HTTP 接线与权限点 api_data.read。
package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apiassets"
	"github.com/jiuzhang-waf/server/internal/apifiles"
	"github.com/jiuzhang-waf/server/internal/apiruntime"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/settings"
)

// faWriteJSONL 写采集输入日志（一行一事件）。
func faWriteJSONL(t *testing.T, path string, recs []apiruntime.Record) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create log: %v", err)
	}
	defer f.Close()
	for _, rec := range recs {
		raw, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if _, err := f.Write(append(raw, '\n')); err != nil {
			t.Fatalf("write log: %v", err)
		}
	}
}

// faCollectOnce 跑一次真实采集（FileObsStore 接线）。
func faCollectOnce(t *testing.T, env *testEnv, logPath string) {
	t.Helper()
	c := apiruntime.NewCollector(apiruntime.NewStore(env.db), "fa-test", logPath, "", "node")
	c.SetFileObsRecorder(apiruntime.NewFileObsStore(env.db))
	if _, err := c.CollectOnce(context.Background()); err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
}

// TestStage8FileAssetsMigration 迁移 000061 落位：表结构 / CHECK / 唯一索引 / 设置种子。
func TestStage8FileAssetsMigration(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()

	if n := s8Count(t, env, `SELECT count(*) FROM information_schema.tables WHERE table_name='api_file_assets'`); n != 1 {
		t.Fatalf("api_file_assets missing")
	}
	for _, col := range []string{"id", "endpoint_id", "endpoint_key", "direction", "filename",
		"extension", "mime", "size_bytes", "sha256", "identity_fingerprint", "client_ip_masked",
		"sensitive_types", "first_seen", "last_seen", "transfer_count", "created_at", "updated_at"} {
		if n := s8Count(t, env, `SELECT count(*) FROM information_schema.columns
			WHERE table_name='api_file_assets' AND column_name=$1`, col); n != 1 {
			t.Fatalf("api_file_assets column %s missing", col)
		}
	}
	// 阈值设置种子（默认 50）
	if n := s8Count(t, env, `SELECT count(*) FROM system_settings
		WHERE setting_group='api_data' AND setting_key='file_bulk_download_threshold' AND setting_value='50'::jsonb`); n != 1 {
		t.Fatalf("file_bulk_download_threshold seed missing")
	}
	// CHECK：非法 direction 拒绝
	if _, err := env.db.Exec(ctx, `INSERT INTO api_file_assets (endpoint_key, direction, filename)
		VALUES ('GET /a', 'SIDEWAYS', 'x.pdf')`); err == nil {
		t.Fatalf("bad direction unexpectedly accepted")
	}
	// 唯一索引：同去重键重复拒绝；不同身份放行
	if _, err := env.db.Exec(ctx, `INSERT INTO api_file_assets
		(endpoint_key, direction, filename, identity_fingerprint)
		VALUES ('GET /a', 'DOWNLOAD', 'x.pdf', 'auth:u1')`); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if _, err := env.db.Exec(ctx, `INSERT INTO api_file_assets
		(endpoint_key, direction, filename, identity_fingerprint)
		VALUES ('GET /a', 'DOWNLOAD', 'x.pdf', 'auth:u1')`); err == nil {
		t.Fatalf("duplicate dedup key should fail")
	}
	if _, err := env.db.Exec(ctx, `INSERT INTO api_file_assets
		(endpoint_key, direction, filename, identity_fingerprint)
		VALUES ('GET /a', 'DOWNLOAD', 'x.pdf', 'auth:u2')`); err != nil {
		t.Fatalf("different identity should pass: %v", err)
	}
}

// TestStage8FileAssetsCollectUpsert 采集 UPSERT：元数据归一（IP 掩码/敏感词表/大小写）、
// endpoint_id 解析、重复采集幂等（去重键单行，transfer_count 累计）、缺失容忍。
func TestStage8FileAssetsCollectUpsert(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	rid := s5Rand()
	endpointKey := "POST /api/v1/files/upload-" + rid

	// 端点先发现（验证 endpoint_id 解析）
	ep, err := apiassets.NewStore(env.db).UpsertDiscovery(ctx, apiassets.DiscoveryInput{
		Method: "POST", PathTemplate: "/api/v1/files/upload-" + rid, Confidence: 0.9, IsAPI: true,
	})
	if err != nil {
		t.Fatalf("UpsertDiscovery: %v", err)
	}

	logPath := filepath.Join(t.TempDir(), "api-events.log")
	now := time.Now().UTC()
	rec := apiruntime.Record{
		RequestID: "fa-" + rid, EndpointKey: endpointKey, Method: "POST",
		PathTemplate: "/api/v1/files/upload-" + rid, IsAPI: true, APIConfidence: 0.9,
		FinalAction: "ALLOW", RiskLevel: "NONE", OccurredAt: now,
		IdentityFingerprint: "auth:u1", ClientIP: "203.0.113.87",
		FileObservations: []apiruntime.FileObservation{
			{Direction: "upload", FileName: "Id_Backup.PEM", Extension: "PEM", MIME: "Application/X-PEM-File", Size: 1700},
			{Direction: "UPLOAD", FileName: "notes.txt", Extension: "txt", MIME: "text/plain", Size: 12},
			{Direction: "SIDEWAYS", FileName: "bad.bin", Size: 1}, // 非法方向：跳过
			{Direction: "UPLOAD", FileName: "", Size: 1},          // 空文件名：跳过
		},
	}
	faWriteJSONL(t, logPath, []apiruntime.Record{rec})
	faCollectOnce(t, env, logPath)

	// 两条有效观测落库（非法方向与空文件名跳过）
	if n := s8Count(t, env, `SELECT count(*) FROM api_file_assets WHERE endpoint_key=$1`, endpointKey); n != 2 {
		t.Fatalf("rows = %d, want 2", n)
	}
	// 归一断言：扩展名小写推导敏感词表、IP /24 掩码、endpoint_id 解析
	var ext, ipMasked string
	var sensitiveRaw []byte
	var endpointID *uuid.UUID
	var size int64
	var transferCount int
	err = env.db.QueryRow(ctx, `SELECT extension, client_ip_masked, sensitive_types, endpoint_id, size_bytes, transfer_count
		FROM api_file_assets WHERE endpoint_key=$1 AND filename='Id_Backup.PEM'`, endpointKey).
		Scan(&ext, &ipMasked, &sensitiveRaw, &endpointID, &size, &transferCount)
	if err != nil {
		t.Fatalf("query asset: %v", err)
	}
	if ext != "pem" || ipMasked != "203.0.113.0" || size != 1700 || transferCount != 1 {
		t.Fatalf("normalized row ext=%s ip=%s size=%d count=%d", ext, ipMasked, size, transferCount)
	}
	var sensitive []string
	if err := json.Unmarshal(sensitiveRaw, &sensitive); err != nil || len(sensitive) != 1 || sensitive[0] != "credential_file" {
		t.Fatalf("sensitive_types = %s (err=%v)", sensitiveRaw, err)
	}
	if endpointID == nil || *endpointID != ep.ID {
		t.Fatalf("endpoint_id = %v, want %v", endpointID, ep.ID)
	}
	// 词表外扩展名 → 空敏感类型
	if n := s8Count(t, env, `SELECT count(*) FROM api_file_assets
		WHERE endpoint_key=$1 AND filename='notes.txt' AND sensitive_types='[]'::jsonb`, endpointKey); n != 1 {
		t.Fatalf("notes.txt sensitive_types should be []")
	}

	// 幂等：同事件再采集一次（模拟断点回退重放：删除 checkpoint 强制全量重读）
	// → 去重键命中不新增行，transfer_count 累计 +1（近似口径，见迁移注释）
	if err := os.Remove(logPath + ".checkpoint"); err != nil {
		t.Fatalf("remove checkpoint: %v", err)
	}
	faCollectOnce(t, env, logPath)
	if n := s8Count(t, env, `SELECT count(*) FROM api_file_assets WHERE endpoint_key=$1`, endpointKey); n != 2 {
		t.Fatalf("rows after replay = %d, want 2 (dedup)", n)
	}
	if n := s8Count(t, env, `SELECT transfer_count FROM api_file_assets
		WHERE endpoint_key=$1 AND filename='Id_Backup.PEM'`, endpointKey); n != 2 {
		t.Fatalf("transfer_count after replay = %d, want 2", n)
	}

	// 缺失容忍：无 file_observations 键的旧版事件正常采集零产出
	logPath2 := filepath.Join(t.TempDir(), "api-events2.log")
	faWriteJSONL(t, logPath2, []apiruntime.Record{{
		RequestID: "fa-legacy-" + rid, EndpointKey: endpointKey, Method: "POST",
		PathTemplate: "/api/v1/files/upload-" + rid, IsAPI: true, FinalAction: "ALLOW",
		RiskLevel: "NONE", OccurredAt: now,
	}})
	faCollectOnce(t, env, logPath2)
	if n := s8Count(t, env, `SELECT count(*) FROM api_file_assets WHERE endpoint_key=$1`, endpointKey); n != 2 {
		t.Fatalf("legacy record must not change rows, got %d", n)
	}
}

// faSeedAsset 直插资产行（统计/风险测试造数）。
func faSeedAsset(t *testing.T, env *testEnv, endpointKey, direction, filename, ext, identity, ip string, sensitive []string, lastSeen time.Time, count int) {
	t.Helper()
	raw, _ := json.Marshal(sensitive)
	_, err := env.db.Exec(context.Background(), `
INSERT INTO api_file_assets (endpoint_key, direction, filename, extension, mime, size_bytes,
	identity_fingerprint, client_ip_masked, sensitive_types, first_seen, last_seen, transfer_count)
VALUES ($1,$2,$3,$4,'application/octet-stream',100,$5,$6,$7::jsonb,$8,$8,$9)`,
		endpointKey, direction, filename, ext, identity, ip, string(raw), lastSeen, count)
	if err != nil {
		t.Fatalf("seed asset: %v", err)
	}
}

// TestStage8FileAssetsStatsSQL SQL Store 列表过滤与 §106 统计聚合。
func TestStage8FileAssetsStatsSQL(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	rid := s5Rand()
	epUp := "POST /api/v1/up-" + rid
	epDl := "GET /api/v1/dl-" + rid
	now := time.Now().UTC()

	faSeedAsset(t, env, epUp, "UPLOAD", "a.pdf", "pdf", "auth:u1", "203.0.113.0", []string{}, now, 2)
	faSeedAsset(t, env, epUp, "UPLOAD", "b.pem", "pem", "auth:u1", "203.0.113.0", []string{"credential_file"}, now, 1)
	faSeedAsset(t, env, epDl, "DOWNLOAD", "c.csv", "csv", "auth:u2", "198.51.100.0", []string{"data_export"}, now, 7)
	faSeedAsset(t, env, epDl, "DOWNLOAD", "old.zip", "zip", "auth:u9", "192.0.2.0", []string{}, now.AddDate(0, 0, -8), 3)

	store := apifiles.NewStore(env.db)

	// 列表：方向过滤
	assets, total, err := store.ListAssets(ctx, apifiles.AssetFilter{
		Days: 7, Direction: "DOWNLOAD", EndpointKey: epDl, Page: 1, PageSize: 20,
	})
	if err != nil {
		t.Fatalf("ListAssets: %v", err)
	}
	if total != 1 || len(assets) != 1 || assets[0].FileName != "c.csv" {
		t.Fatalf("list = total %d %+v", total, assets)
	}
	// 列表：sensitive_only + 窗口放宽（30 天含 old.zip）
	_, total, err = store.ListAssets(ctx, apifiles.AssetFilter{Days: 30, SensitiveOnly: true, EndpointKey: epUp, Page: 1, PageSize: 20})
	if err != nil {
		t.Fatalf("ListAssets sensitive: %v", err)
	}
	if total != 1 {
		t.Fatalf("sensitive list total = %d, want 1", total)
	}

	// 统计：7 天窗口（old.zip 不计）
	stats, err := store.Stats(ctx, 7)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.Summary.UploadAssets != 2 || stats.Summary.DownloadAssets != 1 ||
		stats.Summary.UploadTransfers != 3 || stats.Summary.DownloadTransfers != 7 ||
		stats.Summary.SensitiveFileCount != 2 {
		t.Fatalf("summary = %+v", stats.Summary)
	}
	// 注意：setupStage8Env 每测试重建独立库，TOP 断言可按精确值校验
	var fileOK, ipOK, accOK, apiOK bool
	for _, f := range stats.TopFiles {
		if f.FileName == "c.csv" && f.Direction == "DOWNLOAD" && f.Transfers == 7 && f.Identities == 1 {
			fileOK = true
		}
	}
	for _, ip := range stats.TopIPs {
		if ip.ClientIPMasked == "198.51.100.0" && ip.Transfers == 7 && ip.Files == 1 {
			ipOK = true
		}
	}
	for _, a := range stats.TopAccounts {
		if a.IdentityFingerprint == "auth:u1" && a.Transfers == 3 && a.Files == 2 {
			accOK = true
		}
	}
	for _, a := range stats.TopAPIs {
		if a.EndpointKey == epUp && a.Transfers == 3 && a.Files == 2 {
			apiOK = true
		}
	}
	if !fileOK || !ipOK || !accOK || !apiOK {
		t.Fatalf("tops missing: file=%v ip=%v acc=%v api=%v (%+v)", fileOK, ipOK, accOK, apiOK, stats)
	}
}

// TestStage8FileAssetsRiskSweep 批量下载风险判定：触发/未触发/findings dedup 幂等。
func TestStage8FileAssetsRiskSweep(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	rid := s5Rand()
	epDl := "GET /api/v1/dl-" + rid
	now := time.Now().UTC()
	greedy := "auth:greedy-" + rid

	// 超阈值身份：3 个不同文件（阈值经设置改为 2）
	for _, name := range []string{"f1.csv", "f2.csv", "f3.csv"} {
		faSeedAsset(t, env, epDl, "DOWNLOAD", name, "csv", greedy, "203.0.113.0", []string{"data_export"}, now, 1)
	}
	// 未超阈值身份（1 个文件）与匿名（10 个文件，豁免）
	faSeedAsset(t, env, epDl, "DOWNLOAD", "g1.csv", "csv", "auth:calm-"+rid, "198.51.100.0", []string{}, now, 1)
	for i := 0; i < 10; i++ {
		faSeedAsset(t, env, epDl, "DOWNLOAD", "anon"+string(rune('a'+i))+".csv", "csv", "", "192.0.2.0", []string{}, now, 1)
	}
	// 窗口外身份（2h 前，不计）
	for _, name := range []string{"h1.csv", "h2.csv", "h3.csv"} {
		faSeedAsset(t, env, epDl, "DOWNLOAD", name, "csv", "auth:old-"+rid, "10.0.0.0", []string{}, now.Add(-2*time.Hour), 1)
	}

	settingsSvc := settings.NewService(env.db)
	if _, err := env.db.Exec(ctx, `UPDATE system_settings SET setting_value='2'::jsonb
		WHERE setting_group='api_data' AND setting_key='file_bulk_download_threshold'`); err != nil {
		t.Fatalf("set threshold: %v", err)
	}

	sweep := apifiles.NewRiskSweeper(apifiles.NewStore(env.db), apiruntime.NewStore(env.db), settingsSvc)
	res, err := sweep.SweepOnce(ctx)
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if res.Threshold != 2 || res.Candidates != 1 || res.Findings != 1 {
		t.Fatalf("result = %+v", res)
	}
	// finding 落库：类型/主体/等级断言
	var findingType, severity, subjectType, subjectID string
	var count int
	err = env.db.QueryRow(ctx, `SELECT finding_type, severity, subject_type, subject_id, count
		FROM api_runtime_findings WHERE finding_type='FILE_BULK_DOWNLOAD' AND subject_id=$1`, greedy).
		Scan(&findingType, &severity, &subjectType, &subjectID, &count)
	if err != nil {
		t.Fatalf("query finding: %v", err)
	}
	if severity != "HIGH" || subjectType != "IDENTITY" || count != 1 {
		t.Fatalf("finding = %s/%s %s %s count=%d", findingType, severity, subjectType, subjectID, count)
	}
	// 未触发身份无 finding
	if n := s8Count(t, env, `SELECT count(*) FROM api_runtime_findings
		WHERE finding_type='FILE_BULK_DOWNLOAD' AND subject_id IN ($1, $2)`,
		"auth:calm-"+rid, "auth:old-"+rid); n != 0 {
		t.Fatalf("non-triggered identities must have no findings, got %d", n)
	}
	// 幂等：再次 Sweep → dedup 命中 count+1，不产生重复行
	if _, err := sweep.SweepOnce(ctx); err != nil {
		t.Fatalf("second SweepOnce: %v", err)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_runtime_findings
		WHERE finding_type='FILE_BULK_DOWNLOAD' AND subject_id=$1`, greedy); n != 1 {
		t.Fatalf("findings after re-sweep = %d, want 1 (dedup)", n)
	}
	if n := s8Count(t, env, `SELECT count FROM api_runtime_findings
		WHERE finding_type='FILE_BULK_DOWNLOAD' AND subject_id=$1`, greedy); n != 2 {
		t.Fatalf("finding count after re-sweep = %d, want 2", n)
	}
}

// faInjectNoPerm 注入无 api_data.read 权限的主体（403 断言用）。
func faInjectNoPerm(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := &authz.Principal{UserID: uuid.New(), Username: "w8file-noperm", PermsSet: map[string]bool{}}
		next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
	})
}

// TestStage8FileAssetsHTTP HTTP 接线：权限矩阵 / 参数校验 / 列表与统计出参。
func TestStage8FileAssetsHTTP(t *testing.T) {
	env := setupStage8Env(t)
	rid := s5Rand()
	epUp := "POST /api/v1/up-" + rid
	faSeedAsset(t, env, epUp, "UPLOAD", "keys.pem", "pem", "auth:u1", "203.0.113.0",
		[]string{"credential_file"}, time.Now().UTC(), 1)

	store := apifiles.NewStore(env.db)
	newMux := func(authzFn func(http.Handler) http.Handler) *http.ServeMux {
		mux := http.NewServeMux()
		apifiles.RegisterRoutes(mux, authzFn, apifiles.NewHandler(store))
		return mux
	}

	if rr := apidataDo(t, newMux(xbInjectAnon), http.MethodGet, "/api/v1/api-security/file-assets", nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("anon: status=%d, want 401", rr.Code)
	}
	if rr := apidataDo(t, newMux(faInjectNoPerm), http.MethodGet, "/api/v1/api-security/file-assets", nil); rr.Code != http.StatusForbidden {
		t.Fatalf("noperm: status=%d, want 403", rr.Code)
	}
	rr := apidataDo(t, newMux(apidataInjectPrincipal), http.MethodGet,
		"/api/v1/api-security/file-assets?endpoint_key="+url.QueryEscape(epUp)+"&sensitive_only=true", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("authorized: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var listBody struct {
		Data struct {
			Total int64 `json:"total"`
			Items []struct {
				FileName       string   `json:"filename"`
				SensitiveTypes []string `json:"sensitive_types"`
			} `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &listBody); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rr.Body.String())
	}
	if listBody.Data.Total != 1 || listBody.Data.Items[0].FileName != "keys.pem" ||
		len(listBody.Data.Items[0].SensitiveTypes) != 1 {
		t.Fatalf("list = %+v", listBody.Data)
	}
	// stats 出参
	rr = apidataDo(t, newMux(apidataInjectPrincipal), http.MethodGet, "/api/v1/api-security/file-assets/stats?days=7", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("stats: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var statsBody struct {
		Data struct {
			Summary struct {
				SensitiveFileCount int64 `json:"sensitive_file_count"`
			} `json:"summary"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &statsBody); err != nil {
		t.Fatalf("decode stats: %v (body=%s)", err, rr.Body.String())
	}
	if statsBody.Data.Summary.SensitiveFileCount < 1 {
		t.Fatalf("stats summary = %+v", statsBody.Data.Summary)
	}
	// 参数校验 400
	for _, url := range []string{
		"/api/v1/api-security/file-assets?direction=X",
		"/api/v1/api-security/file-assets?sensitive_only=maybe",
	} {
		if rr := apidataDo(t, newMux(apidataInjectPrincipal), http.MethodGet, url, nil); rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: status=%d, want 400", url, rr.Code)
		}
	}
}
