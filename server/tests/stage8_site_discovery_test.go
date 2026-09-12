// 站点资产被动发现（server 侧）集成测试。
//
// 覆盖：迁移 000077 表与权限种子生效；采集器经 site-discovery.jsonl → 真实 PG
// upsert 入库（幂等键 domain+ip+port，seen_count 累加，人工处置字段不被命中覆盖）；
// GET 列表过滤与分页；confirm/ignore/restore 状态机（含非法流转 409、不存在 404）；
// 审计落库（module=site_discovery）；权限矩阵（SECURITY_ADMIN 放行，SYSTEM_ADMIN 403——
// 角色集合与 applications.read/update 一致，见迁移 000077）。
//
// 运行方式与 TestStage8NodeInterfaces 一致（无 PG/Valkey 凭据时 t.Skip）：
//
//	POSTGRES_PASSWORD=... VALKEY_PASSWORD=... go test ./tests -run TestStage8SiteDiscovery -count=1
package tests

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/jiuzhang-waf/server/internal/sitediscovery"
)

// s8SiteLine 造一条站点发现 JSONL 行（字段与网关 mirrorcap 输出契约一致）。
func s8SiteLine(node, domain, ip string, port int, proto, mode string, hits, clients int) string {
	return `{"type":"site_discovery","node":"` + node + `","domain":"` + domain + `","ip":"` + ip +
		`","port":` + strconv.Itoa(port) + `,"protocol":"` + proto + `","source_mode":"` + mode +
		`","hits":` + strconv.Itoa(hits) + `,"client_count":` + strconv.Itoa(clients) +
		`,"window_start":"2026-08-21T04:00:00Z","window_end":"2026-08-21T04:00:30Z"}` + "\n"
}

func TestStage8SiteDiscovery(t *testing.T) {
	env := setupStage8Env(t)
	cookies, csrf := env.s5Login(t, "s8sdc", "SECURITY_ADMIN")
	kw := "s8sd" + s5Rand()
	node := "gw-" + kw

	// ---------- 采集链路：site-discovery.jsonl → collector → 真实 PG ----------
	logPath := filepath.Join(t.TempDir(), "site-discovery.jsonl")
	content := s8SiteLine(node, kw+".example.com", "10.66.0.5", 443, "HTTPS", "MIRROR", 10, 3) +
		s8SiteLine(node, "", "10.66.0.9", 80, "HTTP", "ROUTED", 4, 2) +
		`{"type":"heartbeat","node":"` + node + `"}` + "\n" + // 非本类型行：跳过
		`{"type":"site_discovery","ip":"bad-ip","port":443,"protocol":"HTTPS"}` + "\n" // 坏行：错误文件
	if err := os.WriteFile(logPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	collector := sitediscovery.NewCollector(sitediscovery.NewStore(env.db), "it-site-01", logPath, "", node)
	n, err := collector.CollectOnce(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if n != 4 {
		t.Fatalf("processed = %d, want 4", n)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM site_asset_discoveries WHERE gateway_node = $1`, node); n != 2 {
		t.Fatalf("collected rows = %d, want 2", n)
	}
	if _, err := os.Stat(logPath + ".errors"); err != nil {
		t.Fatalf("error file missing: %v", err)
	}

	// 追加命中：seen_count 累加（10→25）、client_count 覆盖为最近窗口
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(s8SiteLine(node, kw+".example.com", "10.66.0.5", 443, "HTTPS", "MIRROR", 15, 8)); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := collector.CollectOnce(context.Background()); err != nil {
		t.Fatalf("collect round2: %v", err)
	}
	if n := s8Count(t, env,
		`SELECT count(*) FROM site_asset_discoveries WHERE gateway_node = $1 AND seen_count = 25 AND client_count = 8`, node); n != 1 {
		t.Fatal("seen_count 累加/client_count 覆盖未生效")
	}

	// ---------- GET 列表：过滤 + 分页 ----------
	result := s5OK(t, env.get(t, "/api/v1/site-discoveries?keyword="+kw, cookies), "list discoveries")
	items, _ := result.Data["items"].([]interface{})
	if len(items) != 1 {
		t.Fatalf("keyword items = %v", items)
	}
	first := items[0].(map[string]interface{})
	if first["domain"] != kw+".example.com" || first["status"] != "NEW" ||
		first["protocol"] != "HTTPS" || first["source_mode"] != "MIRROR" {
		t.Fatalf("item = %+v", first)
	}
	id := first["id"].(string)
	result = s5OK(t, env.get(t, "/api/v1/site-discoveries?source_mode=ROUTED", cookies), "list by source_mode")
	items, _ = result.Data["items"].([]interface{})
	if len(items) != 1 || items[0].(map[string]interface{})["ip"] != "10.66.0.9" {
		t.Fatalf("source_mode items = %v", items)
	}
	// 非法过滤值 400
	s5Expect(t, env.get(t, "/api/v1/site-discoveries?status=BOGUS", cookies), http.StatusBadRequest, "bad status filter")
	s5Expect(t, env.get(t, "/api/v1/site-discoveries?protocol=FTP", cookies), http.StatusBadRequest, "bad protocol filter")

	// ---------- 状态机：confirm → ignore → restore，审计落库 ----------
	result = s5OK(t, env.post(t, "/api/v1/site-discoveries/"+id+"/confirm", "", cookies, csrf), "confirm")
	if result.Data["status"] != "CONFIRMED" || result.Data["confirmed_by"] == "" {
		t.Fatalf("confirm resp = %+v", result.Data)
	}
	// 命中不覆盖人工处置：再 upsert 同键，status/confirmed_by 保持
	if _, err := f2Write(logPath, s8SiteLine(node, kw+".example.com", "10.66.0.5", 443, "HTTPS", "MIRROR", 5, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := collector.CollectOnce(context.Background()); err != nil {
		t.Fatalf("collect round3: %v", err)
	}
	if n := s8Count(t, env,
		`SELECT count(*) FROM site_asset_discoveries WHERE id = $1 AND status = 'CONFIRMED' AND confirmed_by <> '' AND seen_count = 30`, id); n != 1 {
		t.Fatal("命中覆盖了人工处置字段或 seen_count 未累加")
	}

	result = s5OK(t, env.post(t, "/api/v1/site-discoveries/"+id+"/ignore", "", cookies, csrf), "ignore")
	if result.Data["status"] != "IGNORED" {
		t.Fatalf("ignore resp = %+v", result.Data)
	}
	// IGNORED 上 confirm → 409
	s5Expect(t, env.post(t, "/api/v1/site-discoveries/"+id+"/confirm", "", cookies, csrf),
		http.StatusConflict, "confirm on IGNORED")
	result = s5OK(t, env.post(t, "/api/v1/site-discoveries/"+id+"/restore", "", cookies, csrf), "restore")
	if result.Data["status"] != "NEW" || result.Data["confirmed_by"] != "" {
		t.Fatalf("restore resp = %+v", result.Data)
	}
	// 不存在 → 404
	s5Expect(t, env.post(t, "/api/v1/site-discoveries/00000000-0000-0000-0000-000000000000/confirm", "", cookies, csrf),
		http.StatusNotFound, "confirm missing")
	// 审计：confirm/ignore/restore 各一条，module=site_discovery
	if n := s8Count(t, env,
		`SELECT count(*) FROM operation_audits WHERE module = 'site_discovery' AND object_id = $1
		 AND action IN ('confirm','ignore','restore')`, id); n != 3 {
		t.Fatalf("audit rows = %d, want 3", n)
	}

	// ---------- 权限矩阵：SYSTEM_ADMIN 读/写均 403（与 applications.read 角色集合一致） ----------
	sysCookies, sysCSRF := env.s5Login(t, "s8sds", "SYSTEM_ADMIN")
	s5Expect(t, env.get(t, "/api/v1/site-discoveries", sysCookies), http.StatusForbidden, "SYSTEM_ADMIN list")
	s5Expect(t, env.post(t, "/api/v1/site-discoveries/"+id+"/confirm", "", sysCookies, sysCSRF),
		http.StatusForbidden, "SYSTEM_ADMIN confirm")
}

// f2Write 追加一行到日志文件（采集器增量读取用）。
func f2Write(path, line string) (int, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return f.WriteString(line)
}
