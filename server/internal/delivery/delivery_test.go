package delivery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------- 整体结果判定 ----------

func item(result string, critical bool) ItemResult {
	return ItemResult{Key: "k", Name: "n", Result: result, Critical: critical}
}

func TestOverall(t *testing.T) {
	cases := []struct {
		name  string
		items []ItemResult
		want  string
	}{
		{"全PASS", []ItemResult{item(ResultPass, true), item(ResultPass, false)}, OverallPass},
		{"空结果", nil, OverallPass},
		{"关键FAIL→FAIL", []ItemResult{item(ResultPass, false), item(ResultFail, true)}, OverallFail},
		{"关键FAIL优先于WARNING", []ItemResult{item(ResultWarning, false), item(ResultFail, true)}, OverallFail},
		{"非关键FAIL→WARNING", []ItemResult{item(ResultPass, true), item(ResultFail, false)}, OverallWarning},
		{"WARNING→WARNING", []ItemResult{item(ResultPass, true), item(item2(ResultWarning)), item(ResultPass, false)}, OverallWarning},
		{"NOT_APPLICABLE不影响", []ItemResult{item(ResultPass, true), item(ResultNA, true)}, OverallPass},
		{"仅NA→PASS", []ItemResult{item(ResultNA, true)}, OverallPass},
	}
	for _, c := range cases {
		if got := Overall(c.items); got != c.want {
			t.Errorf("%s: Overall = %s, want %s", c.name, got, c.want)
		}
	}
}

func item2(result string) (string, bool) { return result, true }

func TestCounts(t *testing.T) {
	items := []ItemResult{
		item(ResultPass, true), item(ResultPass, false),
		item(ResultWarning, false), item(ResultFail, true),
		item(ResultFail, false), item(ResultNA, false),
	}
	pass, warning, fail := Counts(items)
	if pass != 2 || warning != 1 || fail != 2 {
		t.Errorf("Counts = (%d,%d,%d), want (2,1,2)", pass, warning, fail)
	}
}

// ---------- 检查项注册完整性 ----------

func TestRegistryCompleteness(t *testing.T) {
	checks := Registry()
	if len(checks) < 20 {
		t.Fatalf("检查项数 = %d, want >= 20", len(checks))
	}
	keys := map[string]bool{}
	for _, c := range checks {
		if c.Key == "" {
			t.Error("存在空 key 的检查项")
		}
		if keys[c.Key] {
			t.Errorf("检查项 key 重复: %s", c.Key)
		}
		keys[c.Key] = true
		if c.Name == "" {
			t.Errorf("检查项 %s 缺少名称", c.Key)
		}
		if c.Category == "" {
			t.Errorf("检查项 %s 缺少类别", c.Key)
		}
		if c.Run == nil {
			t.Errorf("检查项 %s 缺少执行函数", c.Key)
		}
	}
	// 必须具备关键项（关键 FAIL → 整体 FAIL 的判定才有意义）
	criticalCount := 0
	for _, c := range checks {
		if c.Critical {
			criticalCount++
		}
	}
	if criticalCount == 0 {
		t.Error("注册表中无关键检查项")
	}
	// 规范要求的关键检查必须存在
	for _, key := range []string{
		"components_up", "https_config", "three_role_accounts", "password_policy",
		"caddy_admin_socket", "postgres_bind", "valkey_bind", "config_version_exists",
		"waf_detection", "backup_available", "audit_chain", "vulnerability_scan",
	} {
		if !keys[key] {
			t.Errorf("缺少必备检查项: %s", key)
		}
	}
}

// findCheck 与 Registry 定义一致（结果构造携带正确的 key/name/category/critical）。
func TestFindCheckConsistency(t *testing.T) {
	for _, c := range Registry() {
		got := findCheck(c.Key)
		if got.Key != c.Key || got.Name != c.Name || got.Category != c.Category || got.Critical != c.Critical {
			t.Errorf("findCheck(%s) 元数据不一致", c.Key)
		}
	}
	if got := findCheck("nonexistent"); got.Key != "nonexistent" || got.Name != "" {
		t.Error("未知 key 应返回零值定义")
	}
}

// ---------- 绑定地址判定（纯函数） ----------

func TestCheckBindAddress(t *testing.T) {
	c := Check{Key: "bind_test", Name: "n", Category: CategorySecurity, Critical: true}
	cases := []struct {
		host string
		want string
	}{
		{"127.0.0.1", ResultPass},
		{"localhost", ResultPass}, // 主机名解析失败按内部主机名处理
		{"postgres", ResultPass},  // docker 内部服务名
		{"valkey", ResultPass},
		{"10.0.0.5", ResultPass}, // 私网
		{"192.168.1.10", ResultPass},
		{"172.16.0.2", ResultPass},
		{"8.8.8.8", ResultFail}, // 公网
		{"1.2.3.4", ResultFail},
		{"0.0.0.0", ResultFail}, // 绑定全网卡（非公网IP语义，按公网暴露处理？）
	}
	for _, c2 := range cases {
		got := checkBindAddress(c, "Test", c2.host)
		if got.Result != c2.want {
			t.Errorf("host=%s result=%s(%s), want %s", c2.host, got.Result, got.Message, c2.want)
		}
	}
}

// ---------- CSV 导出 ----------

func TestExportCSV(t *testing.T) {
	items := []ItemResult{
		{Key: "a", Name: "名称,含逗号", Category: CategorySecurity, Critical: true, Result: ResultPass, Message: "ok"},
		{Key: "b", Name: "n", Category: CategoryQuality, Critical: false, Result: ResultWarning, Message: "含\"引号\""},
	}
	csv := exportCSV(items)
	if !strings.HasPrefix(csv, "item_key,item_name,category,critical,result,message\n") {
		t.Error("CSV 缺少表头")
	}
	if !strings.Contains(csv, `"名称,含逗号"`) {
		t.Error("逗号字段应加引号")
	}
	if !strings.Contains(csv, `"含""引号"""`) {
		t.Error("引号应转义")
	}
	if lines := strings.Split(strings.TrimRight(csv, "\n"), "\n"); len(lines) != 3 {
		t.Errorf("CSV 行数 = %d, want 3", len(lines))
	}
}

// 单项结果 message 截断（适配 VARCHAR(500)）。
func TestItemMessageTruncation(t *testing.T) {
	c := Check{Key: "k", Name: "n"}
	long := strings.Repeat("x", 600)
	if got := c.fail(long, nil); len(got.Message) != 500 {
		t.Errorf("message 长度 = %d, want 500", len(got.Message))
	}
}

// ---------- 漏洞扫描检查项（§十六） ----------

// setupVulnScanRepo 构造最小可用仓库结构：可执行扫描脚本 + 合法 SBOM + 高危登记表。
func setupVulnScanRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, s := range []string{"generate-sbom.sh", "license-audit.sh"} {
		p := filepath.Join(root, "scripts", s)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "docs", "SBOM.spdx.json"), []byte(`{"spdxVersion":"SPDX-2.3"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	reg := filepath.Join(root, "docs", "VULN_KNOWN_HIGH.md")
	if err := os.WriteFile(reg, []byte("# 登记表\n\n当前无未修复的高危漏洞发现。\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestCheckVulnerabilityScan(t *testing.T) {
	t.Run("PASS：能力齐备且无未修复发现", func(t *testing.T) {
		got := checkVulnerabilityScan(&RunContext{RepoRoot: setupVulnScanRepo(t)})
		if got.Result != ResultPass {
			t.Errorf("result=%s(%s), want PASS", got.Result, got.Message)
		}
		if !got.Critical {
			t.Error("漏洞扫描应为关键检查项")
		}
	})

	t.Run("PASS：已修复条目不计数", func(t *testing.T) {
		root := setupVulnScanRepo(t)
		reg := filepath.Join(root, "docs", "VULN_KNOWN_HIGH.md")
		content := "# 登记表\n\n- [x] CVE-2024-0001 某组件 已修复\n"
		if err := os.WriteFile(reg, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		got := checkVulnerabilityScan(&RunContext{RepoRoot: root})
		if got.Result != ResultPass {
			t.Errorf("result=%s(%s), want PASS", got.Result, got.Message)
		}
	})

	t.Run("FAIL：扫描脚本缺失", func(t *testing.T) {
		root := setupVulnScanRepo(t)
		if err := os.Remove(filepath.Join(root, "scripts", "license-audit.sh")); err != nil {
			t.Fatal(err)
		}
		got := checkVulnerabilityScan(&RunContext{RepoRoot: root})
		if got.Result != ResultFail {
			t.Errorf("result=%s(%s), want FAIL", got.Result, got.Message)
		}
	})

	t.Run("FAIL：扫描脚本不可执行", func(t *testing.T) {
		root := setupVulnScanRepo(t)
		if err := os.Chmod(filepath.Join(root, "scripts", "generate-sbom.sh"), 0o644); err != nil {
			t.Fatal(err)
		}
		got := checkVulnerabilityScan(&RunContext{RepoRoot: root})
		if got.Result != ResultFail {
			t.Errorf("result=%s(%s), want FAIL", got.Result, got.Message)
		}
	})

	t.Run("FAIL：SBOM 非法", func(t *testing.T) {
		root := setupVulnScanRepo(t)
		if err := os.WriteFile(filepath.Join(root, "docs", "SBOM.spdx.json"), []byte("not-json"), 0o644); err != nil {
			t.Fatal(err)
		}
		got := checkVulnerabilityScan(&RunContext{RepoRoot: root})
		if got.Result != ResultFail {
			t.Errorf("result=%s(%s), want FAIL", got.Result, got.Message)
		}
	})

	t.Run("FAIL：存在未修复高危发现", func(t *testing.T) {
		root := setupVulnScanRepo(t)
		reg := filepath.Join(root, "docs", "VULN_KNOWN_HIGH.md")
		content := "# 登记表\n\n- [ ] CVE-2025-1111 组件A v1 未修复\n- [ ] CVE-2025-2222 组件B v2 未修复\n- [x] CVE-2024-0001 组件C 已修复\n"
		if err := os.WriteFile(reg, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		got := checkVulnerabilityScan(&RunContext{RepoRoot: root})
		if got.Result != ResultFail {
			t.Errorf("result=%s(%s), want FAIL", got.Result, got.Message)
		}
		if n, ok := got.Details["unresolved_findings"].(int); !ok || n != 2 {
			t.Errorf("unresolved_findings=%v, want 2", got.Details["unresolved_findings"])
		}
	})

	t.Run("WARNING：登记表缺失", func(t *testing.T) {
		root := setupVulnScanRepo(t)
		if err := os.Remove(filepath.Join(root, "docs", "VULN_KNOWN_HIGH.md")); err != nil {
			t.Fatal(err)
		}
		got := checkVulnerabilityScan(&RunContext{RepoRoot: root})
		if got.Result != ResultWarning {
			t.Errorf("result=%s(%s), want WARNING", got.Result, got.Message)
		}
	})

	t.Run("WARNING：登记表过期（>90天未更新）", func(t *testing.T) {
		root := setupVulnScanRepo(t)
		reg := filepath.Join(root, "docs", "VULN_KNOWN_HIGH.md")
		stale := time.Now().Add(-120 * 24 * time.Hour)
		if err := os.Chtimes(reg, stale, stale); err != nil {
			t.Fatal(err)
		}
		got := checkVulnerabilityScan(&RunContext{RepoRoot: root})
		if got.Result != ResultWarning {
			t.Errorf("result=%s(%s), want WARNING", got.Result, got.Message)
		}
	})

	t.Run("真实仓库自检PASS", func(t *testing.T) {
		root, err := filepath.Abs(filepath.Join("..", "..", ".."))
		if err != nil {
			t.Fatal(err)
		}
		got := checkVulnerabilityScan(&RunContext{RepoRoot: root})
		if got.Result != ResultPass {
			t.Errorf("真实仓库 result=%s(%s), want PASS", got.Result, got.Message)
		}
	})
}

func TestCheckNoDefaultPasswordAllThreeAdminEnvs(t *testing.T) {
	t.Run("全未设置→PASS", func(t *testing.T) {
		got := checkNoDefaultPassword(&RunContext{EnvGet: func(string) string { return "" }})
		if got.Result != ResultPass {
			t.Fatalf("result=%s(%s), want PASS", got.Result, got.Message)
		}
	})
	for _, key := range []string{
		"INITIAL_ADMIN_PASSWORD",
		"INITIAL_OPER_ADMIN_PASSWORD",
		"INITIAL_AUDIT_ADMIN_PASSWORD",
	} {
		t.Run("残留"+key+"→WARNING", func(t *testing.T) {
			got := checkNoDefaultPassword(&RunContext{EnvGet: func(k string) string {
				if k == key {
					return "Temp@2026!Secret"
				}
				return ""
			}})
			if got.Result != ResultWarning {
				t.Fatalf("key=%s result=%s(%s), want WARNING", key, got.Result, got.Message)
			}
			if !strings.Contains(got.Message, key) {
				t.Errorf("message %q missing %s", got.Message, key)
			}
		})
	}
}
