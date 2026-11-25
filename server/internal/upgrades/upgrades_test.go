package upgrades

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// ---------- 版本号解析与比较 ----------

func TestCurrentVersion(t *testing.T) {
	if CurrentVersion != "1.13.1" {
		t.Fatalf("CurrentVersion = %q, want 1.13.1", CurrentVersion)
	}
}

func TestParseVersion(t *testing.T) {
	cases := []struct {
		in      string
		want    Version
		wantErr bool
	}{
		{"2.0.0", Version{2, 0, 0}, false},
		{"v2.1.3", Version{2, 1, 3}, false},
		{"10.20.30", Version{10, 20, 30}, false},
		{"2.0.0-rc.1", Version{2, 0, 0}, false},
		{"2.0", Version{}, true},
		{"2", Version{}, true},
		{"", Version{}, true},
		{"v2.0.0.1", Version{}, true},
		{"2.0.x", Version{}, true},
		{"a.b.c", Version{}, true},
	}
	for _, c := range cases {
		got, err := ParseVersion(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseVersion(%q) 应报错", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseVersion(%q) 意外报错: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseVersion(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}
}

func TestVersionCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2.0.0", "2.0.0", 0},
		{"2.0.0", "2.0.1", -1},
		{"2.1.0", "2.0.9", 1},
		{"3.0.0", "2.9.9", 1},
		{"1.9.9", "2.0.0", -1},
	}
	for _, c := range cases {
		a, err := ParseVersion(c.a)
		if err != nil {
			t.Fatalf("ParseVersion(%q): %v", c.a, err)
		}
		b, err := ParseVersion(c.b)
		if err != nil {
			t.Fatalf("ParseVersion(%q): %v", c.b, err)
		}
		if got := a.Compare(b); got != c.want {
			t.Errorf("%s.Compare(%s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// ---------- 状态机 ----------

func TestCanTransition(t *testing.T) {
	legal := [][2]string{
		{StatusPending, StatusPrecheck},
		{StatusPrecheck, StatusBackup},
		{StatusPrecheck, StatusFailed},
		{StatusBackup, StatusApplying},
		{StatusBackup, StatusFailed},
		{StatusApplying, StatusMigrating},
		{StatusApplying, StatusRollingBack},
		{StatusMigrating, StatusVerifying},
		{StatusMigrating, StatusRollingBack},
		{StatusVerifying, StatusSuccess},
		{StatusVerifying, StatusRollingBack},
		{StatusRollingBack, StatusRolledBack},
		{StatusRollingBack, StatusFailed},
		{StatusSuccess, StatusRollingBack},
		{StatusFailed, StatusRollingBack},
	}
	for _, tr := range legal {
		if !CanTransition(tr[0], tr[1]) {
			t.Errorf("CanTransition(%s,%s) 应为合法", tr[0], tr[1])
		}
	}
	illegal := [][2]string{
		{StatusPending, StatusSuccess},
		{StatusPending, StatusBackup},
		{StatusPrecheck, StatusApplying},
		{StatusBackup, StatusSuccess},
		{StatusSuccess, StatusFailed},
		{StatusSuccess, StatusPrecheck},
		{StatusRolledBack, StatusRollingBack},
		{StatusRolledBack, StatusPending},
		{StatusFailed, StatusSuccess},
		{"", StatusPending},
		{StatusPending, ""},
	}
	for _, tr := range illegal {
		if CanTransition(tr[0], tr[1]) {
			t.Errorf("CanTransition(%s,%s) 应为非法", tr[0], tr[1])
		}
	}
}

func TestTerminalStatus(t *testing.T) {
	for _, s := range []string{StatusSuccess, StatusFailed, StatusRolledBack} {
		if !TerminalStatus(s) {
			t.Errorf("TerminalStatus(%s) 应为 true", s)
		}
	}
	for _, s := range []string{StatusPending, StatusPrecheck, StatusBackup, StatusApplying, StatusMigrating, StatusVerifying, StatusRollingBack} {
		if TerminalStatus(s) {
			t.Errorf("TerminalStatus(%s) 应为 false", s)
		}
	}
}

// ---------- 预检规则（纯函数） ----------

func baseFacts() Facts {
	backupAt := time.Now().UTC().Add(-time.Hour)
	return Facts{
		CurrentVersion:     "2.0.0",
		PackageVersionFrom: "2.0.0",
		PackageVersionTo:   "2.1.0",
		DiskFreeBytes:      8 << 30,
		PostgresReachable:  true,
		ValkeyReachable:    true,
		MaxMigration:       11,
		MasterKey:          true,
		LastFullBackupAt:   &backupAt,
		Now:                time.Now().UTC(),

		PackageFileExpectedName: "jiuzhang-offline-2.1.0.tar.gz",
		PackageFileExpectedHash: strings.Repeat("b", 64),
		PackageFileExpectedSize: 1024,
		PackageFileExists:       true,
		PackageFileActualHash:   strings.Repeat("b", 64),
		PackageFileActualSize:   1024,
		PackageArtifactVerified: true,
	}
}

func itemByName(items []CheckItem, name string) CheckItem {
	for _, it := range items {
		if it.Name == name {
			return it
		}
	}
	return CheckItem{Name: name, Result: "MISSING"}
}

func TestEvaluateAllPass(t *testing.T) {
	items := Evaluate(baseFacts())
	if len(items) != 11 {
		t.Fatalf("预检项数 = %d, want 11", len(items))
	}
	for _, it := range items {
		if it.Result != CheckPass {
			t.Errorf("项 %s = %s(%s), want PASS", it.Name, it.Result, it.Message)
		}
	}
	if HasFail(items) {
		t.Error("全部通过时 HasFail 应为 false")
	}
}

func TestEvaluateVersionMismatch(t *testing.T) {
	f := baseFacts()
	f.CurrentVersion = "2.0.1"
	items := Evaluate(f)
	if got := itemByName(items, "version_match"); got.Result != CheckFail {
		t.Errorf("版本不匹配 = %s, want FAIL", got.Result)
	}
	if !HasFail(items) {
		t.Error("HasFail 应为 true")
	}
}

func TestEvaluateVersionToNotHigher(t *testing.T) {
	f := baseFacts()
	f.PackageVersionTo = "2.0.0"
	items := Evaluate(f)
	if got := itemByName(items, "version_match"); got.Result != CheckFail {
		t.Errorf("目标版本不高于当前 = %s, want FAIL", got.Result)
	}
}

func TestEvaluateDiskThresholds(t *testing.T) {
	f := baseFacts()
	f.DiskFreeBytes = 1 << 30 // < 2GiB → FAIL
	if got := itemByName(Evaluate(f), "disk_space"); got.Result != CheckFail {
		t.Errorf("1GiB 剩余 = %s, want FAIL", got.Result)
	}
	f.DiskFreeBytes = 3 << 30 // 2~4GiB → WARNING
	if got := itemByName(Evaluate(f), "disk_space"); got.Result != CheckWarning {
		t.Errorf("3GiB 剩余 = %s, want WARNING", got.Result)
	}
	f.DiskFreeBytes = -1 // 采集失败 → FAIL
	if got := itemByName(Evaluate(f), "disk_space"); got.Result != CheckFail {
		t.Errorf("采集失败 = %s, want FAIL", got.Result)
	}
}

func TestEvaluateUnreachableDeps(t *testing.T) {
	f := baseFacts()
	f.PostgresReachable = false
	f.ValkeyReachable = false
	items := Evaluate(f)
	if got := itemByName(items, "postgres_reachable"); got.Result != CheckFail {
		t.Errorf("PG 不可达 = %s, want FAIL", got.Result)
	}
	if got := itemByName(items, "valkey_reachable"); got.Result != CheckFail {
		t.Errorf("Valkey 不可达 = %s, want FAIL", got.Result)
	}
}

func TestEvaluateActiveTasks(t *testing.T) {
	f := baseFacts()
	f.ActiveTasks = []string{"1 个备份任务进行中"}
	items := Evaluate(f)
	got := itemByName(items, "no_active_tasks")
	if got.Result != CheckFail {
		t.Errorf("存在进行中任务 = %s, want FAIL", got.Result)
	}
	if !strings.Contains(got.Message, "备份任务") {
		t.Errorf("消息应包含任务描述: %s", got.Message)
	}
}

func TestEvaluateMigrationCompat(t *testing.T) {
	f := baseFacts()
	f.TargetSchema = 12
	if got := itemByName(Evaluate(f), "migration_compat"); got.Result != CheckPass {
		t.Errorf("目标迁移号12 = %s, want PASS", got.Result)
	}
	f.TargetSchema = 23 // 目标镜像可携带跨多个版本的迁移
	if got := itemByName(Evaluate(f), "migration_compat"); got.Result != CheckPass {
		t.Errorf("目标迁移号23 = %s, want PASS", got.Result)
	}
	f.TargetSchema = 0
	f.MaxMigration = -1 // 目录读取失败 → FAIL
	if got := itemByName(Evaluate(f), "migration_compat"); got.Result != CheckFail {
		t.Errorf("迁移目录不可读 = %s, want FAIL", got.Result)
	}
}

func TestEvaluateMasterKey(t *testing.T) {
	f := baseFacts()
	f.MasterKey = false
	if got := itemByName(Evaluate(f), "master_key"); got.Result != CheckFail {
		t.Errorf("主密钥未配置 = %s, want FAIL", got.Result)
	}
}

func TestEvaluateRecentBackup(t *testing.T) {
	f := baseFacts()
	f.LastFullBackupAt = nil
	if got := itemByName(Evaluate(f), "recent_backup"); got.Result != CheckWarning {
		t.Errorf("无备份 = %s, want WARNING", got.Result)
	}
	stale := time.Now().UTC().Add(-48 * time.Hour)
	f.LastFullBackupAt = &stale
	if got := itemByName(Evaluate(f), "recent_backup"); got.Result != CheckWarning {
		t.Errorf("备份过期 = %s, want WARNING", got.Result)
	}
}

func TestEvaluateCriticalAlerts(t *testing.T) {
	f := baseFacts()
	f.CriticalOpenAlerts = 2
	if got := itemByName(Evaluate(f), "no_critical_alerts"); got.Result != CheckFail {
		t.Errorf("存在严重告警 = %s, want FAIL", got.Result)
	}
}

func TestEvaluatePackageFile(t *testing.T) {
	// 文件缺失 → FAIL
	f := baseFacts()
	f.PackageFileExists = false
	f.PackageFileActualHash = ""
	f.PackageFileActualSize = 0
	if got := itemByName(Evaluate(f), "package_file"); got.Result != CheckFail {
		t.Errorf("文件缺失 = %s, want FAIL", got.Result)
	}
	// 大小不一致 → FAIL
	f = baseFacts()
	f.PackageFileActualSize = 2048
	if got := itemByName(Evaluate(f), "package_file"); got.Result != CheckFail {
		t.Errorf("大小不一致 = %s, want FAIL", got.Result)
	}
	// 哈希不一致 → FAIL
	f = baseFacts()
	f.PackageFileActualHash = strings.Repeat("c", 64)
	if got := itemByName(Evaluate(f), "package_file"); got.Result != CheckFail {
		t.Errorf("哈希不一致 = %s, want FAIL", got.Result)
	}
	// 一致 → PASS
	if got := itemByName(Evaluate(baseFacts()), "package_file"); got.Result != CheckPass {
		t.Errorf("完整性一致 = %s, want PASS", got.Result)
	}
}

func TestHashFileStreaming(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pkg.tar.gz")
	content := []byte("upgrade package content")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	hash, size, err := hashFileStreaming(path)
	if err != nil {
		t.Fatalf("hashFileStreaming 意外失败: %v", err)
	}
	want := sha256.Sum256(content)
	if hash != hex.EncodeToString(want[:]) {
		t.Errorf("hash = %s, want %x", hash, want)
	}
	if size != int64(len(content)) {
		t.Errorf("size = %d, want %d", size, len(content))
	}
	if _, _, err := hashFileStreaming(filepath.Join(dir, "missing")); err == nil {
		t.Error("缺失文件应报错")
	}
}

// ---------- 登记校验 ----------

func TestBuildPackageRegistered(t *testing.T) {
	req := &registerPackageRequest{
		FileName:    "jiuzhang-offline-2.1.0.tar.gz",
		VersionFrom: "2.0.0",
		VersionTo:   "2.1.0",
		FileHash:    strings.Repeat("a", 64),
		FileSize:    1024,
		Manifest:    []byte(`{"target_schema_version":12}`),
	}
	pkg, err := buildPackage(req, uuid.New())
	if err != nil {
		t.Fatalf("buildPackage 意外失败: %v", err)
	}
	if pkg.Status != PackageRegistered {
		t.Errorf("状态 = %s, want REGISTERED", pkg.Status)
	}
}

func TestBuildPackageRejected(t *testing.T) {
	cases := []struct {
		name string
		req  registerPackageRequest
	}{
		{"空文件名", registerPackageRequest{FileName: "", VersionFrom: "2.0.0", VersionTo: "2.1.0", FileHash: strings.Repeat("a", 64), FileSize: 1}},
		{"路径穿越", registerPackageRequest{FileName: "../evil.tar.gz", VersionFrom: "2.0.0", VersionTo: "2.1.0", FileHash: strings.Repeat("a", 64), FileSize: 1}},
		{"上级目录名", registerPackageRequest{FileName: "..", VersionFrom: "2.0.0", VersionTo: "2.1.0", FileHash: strings.Repeat("a", 64), FileSize: 1}},
		{"点前缀文件名", registerPackageRequest{FileName: ".hidden.tar.gz", VersionFrom: "2.0.0", VersionTo: "2.1.0", FileHash: strings.Repeat("a", 64), FileSize: 1}},
		{"签名后缀文件名", registerPackageRequest{FileName: "a.tar.gz.sig", VersionFrom: "2.0.0", VersionTo: "2.1.0", FileHash: strings.Repeat("a", 64), FileSize: 1}},
		{"起始版本非法", registerPackageRequest{FileName: "a.tar.gz", VersionFrom: "2.0", VersionTo: "2.1.0", FileHash: strings.Repeat("a", 64), FileSize: 1}},
		{"目标版本不回退", registerPackageRequest{FileName: "a.tar.gz", VersionFrom: "2.1.0", VersionTo: "2.0.0", FileHash: strings.Repeat("a", 64), FileSize: 1}},
		{"哈希非法", registerPackageRequest{FileName: "a.tar.gz", VersionFrom: "2.0.0", VersionTo: "2.1.0", FileHash: "xyz", FileSize: 1}},
		{"大小为零", registerPackageRequest{FileName: "a.tar.gz", VersionFrom: "2.0.0", VersionTo: "2.1.0", FileHash: strings.Repeat("a", 64), FileSize: 0}},
		{"manifest非法", registerPackageRequest{FileName: "a.tar.gz", VersionFrom: "2.0.0", VersionTo: "2.1.0", FileHash: strings.Repeat("a", 64), FileSize: 1, Manifest: []byte(`{`)}},
	}
	for _, c := range cases {
		pkg, err := buildPackage(&c.req, uuid.New())
		if err == nil {
			t.Errorf("%s: 应返回校验错误", c.name)
		}
		if pkg.Status != PackageRejected {
			t.Errorf("%s: 状态 = %s, want REJECTED", c.name, pkg.Status)
		}
	}
}

// ---------- 迁移文件校验 ----------

func TestCheckMigrationFiles(t *testing.T) {
	// 仓库内迁移目录（每个 up 必须有 down）
	if err := checkMigrationFiles("../../migrations"); err != nil {
		t.Errorf("仓库迁移目录校验失败: %v", err)
	}
	if got := MaxMigrationVersion("../../migrations"); got <= 0 {
		t.Errorf("MaxMigrationVersion = %d, want > 0", got)
	}
	if err := checkMigrationFiles(t.TempDir()); err == nil {
		t.Error("空目录应报错")
	}
	if got := MaxMigrationVersion(t.TempDir()); got != 0 {
		t.Errorf("空目录 MaxMigrationVersion = %d, want 0", got)
	}
	if got := MaxMigrationVersion("/nonexistent-dir-xyz"); got != -1 {
		t.Errorf("不存在目录 MaxMigrationVersion = %d, want -1", got)
	}
}

// ---------- manifest 目标迁移号 ----------

func TestManifestTargetSchema(t *testing.T) {
	if got := ManifestTargetSchema([]byte(`{"target_schema_version":12}`)); got != 12 {
		t.Errorf("= %d, want 12", got)
	}
	if got := ManifestTargetSchema([]byte(`{}`)); got != 0 {
		t.Errorf("= %d, want 0", got)
	}
	if got := ManifestTargetSchema([]byte(`{invalid`)); got != 0 {
		t.Errorf("非法 JSON = %d, want 0", got)
	}
	if got := ManifestTargetSchema(nil); got != 0 {
		t.Errorf("nil = %d, want 0", got)
	}
}

func TestValidHash(t *testing.T) {
	if !ValidHash(strings.Repeat("0", 64)) {
		t.Error("64 位小写 hex 应合法")
	}
	if ValidHash(strings.Repeat("A", 64)) {
		t.Error("大写 hex 应非法")
	}
	if ValidHash(strings.Repeat("0", 63)) {
		t.Error("63 位应非法")
	}
}
