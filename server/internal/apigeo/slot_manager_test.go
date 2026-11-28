// slot_manager_test.go GeoIP 槽位安装、gzip/tar.gz 提取、验真、备份裁剪、回滚与安全负例测试。
package apigeo

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func gzipBytes(t *testing.T, raw []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(raw); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

type tarTestEntry struct {
	name     string
	body     []byte
	typeflag byte
	linkname string
}

func tarGzBytes(t *testing.T, entries []tarTestEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		tf := e.typeflag
		if tf == 0 {
			tf = tar.TypeReg
		}
		hdr := &tar.Header{
			Name:     e.name,
			Mode:     0o644,
			Size:     int64(len(e.body)),
			Typeflag: tf,
			Linkname: e.linkname,
		}
		if tf == tar.TypeSymlink || tf == tar.TypeLink {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header %s: %v", e.name, err)
		}
		if hdr.Size > 0 {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatalf("tar write %s: %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func sha256Hex(raw []byte) string {
	s := sha256.Sum256(raw)
	return hex.EncodeToString(s[:])
}

func TestSlotManagerInstallUnchangedBackupAndRollback(t *testing.T) {
	dir := t.TempDir()
	eng := NewReloadableEngine(dir)
	mgr := NewSlotManager(dir, eng, dir)
	tick := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	mgr.now = func() time.Time {
		tick = tick.Add(2 * time.Second)
		return tick
	}

	v1 := buildSyntheticXDBv4(3, []struct {
		start, end string
		region     string
	}{
		{"1.1.1.0", "1.1.1.255", "澳大利亚|悉尼|悉尼|APNIC|AU"},
	})
	v2 := buildSyntheticXDBv4(3, []struct {
		start, end string
		region     string
	}{
		{"1.1.1.0", "1.1.1.255", "美国|加州|圣何塞|Cloudflare|US"},
	})

	// 1. 首次安装 v1（携带原始 SHA-256）
	res1, err := mgr.InstallSlotFromReader(SlotIP2RegionV4, "ip2region_v4.xdb", bytes.NewReader(v1), sha256Hex(v1), SourceTypeOffline)
	if err != nil {
		t.Fatalf("install v1: %v", err)
	}
	if res1.Unchanged || res1.NewSHA256 != sha256Hex(v1) || res1.Revision == "" {
		t.Fatalf("unexpected res1: %+v", res1)
	}
	if code, err := eng.LookupCountry(netip.MustParseAddr("1.1.1.1")); err != nil || code != "AU" {
		t.Fatalf("after v1 lookup = (%q, %v), want AU", code, err)
	}

	// 2. 重复安装相同内容 → Unchanged 短路且不产生冗余备份
	resDup, err := mgr.InstallSlotFromReader(SlotIP2RegionV4, "ip2region_v4.xdb", bytes.NewReader(v1), "", SourceTypeOffline)
	if err != nil {
		t.Fatalf("install dup: %v", err)
	}
	if !resDup.Unchanged {
		t.Fatalf("expected Unchanged=true on identical upload, got %+v", resDup)
	}

	// 3. 以 .xdb.gz 压缩格式安装 v2 → 自动备份 v1 并热加载 v2
	v2Gz := gzipBytes(t, v2)
	res2, err := mgr.InstallSlotFromReader(SlotIP2RegionV4, "ip2region_v4.xdb.gz", bytes.NewReader(v2Gz), sha256Hex(v2Gz), SourceTypeOffline)
	if err != nil {
		t.Fatalf("install v2 gz: %v", err)
	}
	if res2.Unchanged || res2.PreviousSHA256 != sha256Hex(v1) || res2.NewSHA256 != sha256Hex(v2) {
		t.Fatalf("unexpected res2: %+v", res2)
	}
	if code, err := eng.LookupCountry(netip.MustParseAddr("1.1.1.1")); err != nil || code != "US" {
		t.Fatalf("after v2 lookup = (%q, %v), want US", code, err)
	}

	// 4. InspectSlots 应可见 v1 备份
	slots, rev, err := mgr.InspectSlots()
	if err != nil {
		t.Fatalf("InspectSlots: %v", err)
	}
	if rev == nil || rev.Revision != res2.Revision {
		t.Fatalf("unexpected revision: %+v", rev)
	}
	var v4State SlotDiskState
	for _, s := range slots {
		if s.Slot == SlotIP2RegionV4 {
			v4State = s
		}
	}
	if v4State.ActiveOrigin != "runtime" || len(v4State.Backups) != 1 || v4State.Backups[0].SHA256 != sha256Hex(v1) {
		t.Fatalf("unexpected v4 disk state: %+v", v4State)
	}

	// 5. 回滚至 v1 备份 → 立即热切换回 AU，同时 v2 也被保留为可回滚备份
	rbRes, err := mgr.RollbackSlot(SlotIP2RegionV4, v4State.Backups[0].BackupID)
	if err != nil {
		t.Fatalf("RollbackSlot: %v", err)
	}
	if rbRes.NewSHA256 != sha256Hex(v1) || rbRes.PreviousSHA256 != sha256Hex(v2) {
		t.Fatalf("unexpected rollback result: %+v", rbRes)
	}
	if code, err := eng.LookupCountry(netip.MustParseAddr("1.1.1.1")); err != nil || code != "AU" {
		t.Fatalf("after rollback lookup = (%q, %v), want AU", code, err)
	}
}

func TestSlotManagerMaxMindTarGzAndLegacyArchive(t *testing.T) {
	rawMMDB, err := os.ReadFile(realMMDBPath)
	if err != nil {
		t.Skipf("real mmdb not present: %v", err)
	}
	dir := t.TempDir()
	// 预先放置高优先级旧文件名 dbip-city-lite-2026-10.mmdb，验证激活 city.mmdb 时会被归档而不抢占
	legacyPath := filepath.Join(dir, "dbip-city-lite-2026-10.mmdb")
	if err := os.WriteFile(legacyPath, rawMMDB, 0o640); err != nil {
		t.Fatalf("write legacy mmdb: %v", err)
	}

	eng := NewReloadableEngine(dir)
	mgr := NewSlotManager(dir, eng, dir)

	archive := tarGzBytes(t, []tarTestEntry{
		{name: "GeoLite2-City_20261128/README.txt", body: []byte("MaxMind GeoLite2")},
		{name: "GeoLite2-City_20261128/GeoLite2-City.mmdb", body: rawMMDB},
	})
	res, err := mgr.InstallSlotFromReader(SlotDBIPCity, "GeoLite2-City_20261128.tar.gz", bytes.NewReader(archive), sha256Hex(rawMMDB), SourceTypeOffline)
	if err != nil {
		t.Fatalf("install MaxMind tar.gz: %v", err)
	}
	if res.Filename != "city.mmdb" || res.NewSHA256 != sha256Hex(rawMMDB) {
		t.Fatalf("unexpected tar.gz install res: %+v", res)
	}
	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Fatalf("legacy file %s should have been archived and removed", legacyPath)
	}
	if !eng.Enabled() {
		t.Fatal("engine should be enabled after tar.gz install")
	}
}

func TestSlotManagerBackupPruningLimit(t *testing.T) {
	dir := t.TempDir()
	eng := NewReloadableEngine(dir)
	mgr := NewSlotManager(dir, eng, dir)
	tick := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	mgr.now = func() time.Time {
		tick = tick.Add(5 * time.Second)
		return tick
	}

	regions := []string{
		"中国|北京市|北京市|电信|CN",
		"中国|上海市|上海市|联通|CN",
		"中国|广东省|深圳市|移动|CN",
		"中国|浙江省|杭州市|电信|CN",
		"中国|四川省|成都市|电信|CN",
	}
	for _, r := range regions {
		b := buildSyntheticXDBv4(3, []struct {
			start, end string
			region     string
		}{{"114.114.114.0", "114.114.114.255", r}})
		if _, err := mgr.InstallSlotFromReader(SlotIP2RegionV4, "ip2region_v4.xdb", bytes.NewReader(b), "", SourceTypeOffline); err != nil {
			t.Fatalf("install %s: %v", r, err)
		}
	}

	slots, _, err := mgr.InspectSlots()
	if err != nil {
		t.Fatalf("InspectSlots: %v", err)
	}
	for _, s := range slots {
		if s.Slot == SlotIP2RegionV4 {
			if len(s.Backups) != maxBackupsPerSlot {
				t.Fatalf("backups count = %d, want capped at %d", len(s.Backups), maxBackupsPerSlot)
			}
		}
	}
}

func TestSlotManagerSecurityAndValidationMatrix(t *testing.T) {
	dir := t.TempDir()
	eng := NewReloadableEngine(dir)
	mgr := NewSlotManager(dir, eng, dir)

	v4XDB := buildSyntheticXDBv4(3, []struct {
		start, end string
		region     string
	}{{"1.1.1.0", "1.1.1.255", "美国|加州|洛杉矶|ISP|US"}})
	v6XDB := buildSyntheticXDBv6("2001:4860:4860::", "2001:4860:4860::ffff", "美国|加州|山景城|Google|US")

	// 先装一份合法 v4，验证后续全部非法上传绝不破坏既有库
	if _, err := mgr.InstallSlotFromReader(SlotIP2RegionV4, "ip2region_v4.xdb", bytes.NewReader(v4XDB), "", SourceTypeOffline); err != nil {
		t.Fatalf("seed v4: %v", err)
	}

	t.Run("invalid slot", func(t *testing.T) {
		_, err := mgr.InstallSlotFromReader("../etc", "x.xdb", bytes.NewReader(v4XDB), "", SourceTypeOffline)
		if !errors.Is(err, ErrInvalidSlot) {
			t.Fatalf("err = %v, want ErrInvalidSlot", err)
		}
	})

	t.Run("corrupt xdb rejected and existing intact", func(t *testing.T) {
		_, err := mgr.InstallSlotFromReader(SlotIP2RegionV4, "bad.xdb", bytes.NewReader([]byte("corrupt-data")), "", SourceTypeOffline)
		if !errors.Is(err, ErrGeoFileInvalid) {
			t.Fatalf("err = %v, want ErrGeoFileInvalid", err)
		}
		if code, err := eng.LookupCountry(netip.MustParseAddr("1.1.1.1")); err != nil || code != "US" {
			t.Fatalf("existing active DB damaged: (%q, %v)", code, err)
		}
	})

	t.Run("ip version mismatch v4 into v6 slot", func(t *testing.T) {
		_, err := mgr.InstallSlotFromReader(SlotIP2RegionV6, "ip2region_v4.xdb", bytes.NewReader(v4XDB), "", SourceTypeOffline)
		if !errors.Is(err, ErrGeoFileInvalid) {
			t.Fatalf("err = %v, want ErrGeoFileInvalid", err)
		}
	})

	t.Run("valid v6 xdb accepted in v6 slot", func(t *testing.T) {
		if _, err := mgr.InstallSlotFromReader(SlotIP2RegionV6, "ip2region_v6.xdb", bytes.NewReader(v6XDB), "", SourceTypeOffline); err != nil {
			t.Fatalf("valid v6 xdb rejected: %v", err)
		}
	})

	t.Run("sha256 mismatch rejected", func(t *testing.T) {
		wrongSHA := "0000000000000000000000000000000000000000000000000000000000000000"
		_, err := mgr.InstallSlotFromReader(SlotIP2RegionV4, "ip2region_v4.xdb", bytes.NewReader(v4XDB), wrongSHA, SourceTypeOffline)
		if !errors.Is(err, ErrSHA256Mismatch) {
			t.Fatalf("err = %v, want ErrSHA256Mismatch", err)
		}
	})

	t.Run("tar.gz path traversal rejected", func(t *testing.T) {
		evilTar := tarGzBytes(t, []tarTestEntry{
			{name: "../../evil.mmdb", body: []byte("evil")},
		})
		_, err := mgr.InstallSlotFromReader(SlotCountry, "evil.tar.gz", bytes.NewReader(evilTar), "", SourceTypeOffline)
		if !errors.Is(err, ErrGeoFileInvalid) {
			t.Fatalf("err = %v, want ErrGeoFileInvalid", err)
		}
	})

	t.Run("tar.gz symlink rejected", func(t *testing.T) {
		evilTar := tarGzBytes(t, []tarTestEntry{
			{name: "dir/country.mmdb", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"},
		})
		_, err := mgr.InstallSlotFromReader(SlotCountry, "sym.tar.gz", bytes.NewReader(evilTar), "", SourceTypeOffline)
		if !errors.Is(err, ErrGeoFileInvalid) {
			t.Fatalf("err = %v, want ErrGeoFileInvalid", err)
		}
	})

	t.Run("tar.gz multiple db files rejected", func(t *testing.T) {
		dupTar := tarGzBytes(t, []tarTestEntry{
			{name: "a/1.mmdb", body: []byte("abc")},
			{name: "b/2.mmdb", body: []byte("def")},
		})
		_, err := mgr.InstallSlotFromReader(SlotCountry, "dup.tar.gz", bytes.NewReader(dupTar), "", SourceTypeOffline)
		if !errors.Is(err, ErrGeoFileInvalid) {
			t.Fatalf("err = %v, want ErrGeoFileInvalid", err)
		}
	})

	t.Run("tar.gz missing target ext rejected", func(t *testing.T) {
		noMatch := tarGzBytes(t, []tarTestEntry{
			{name: "dir/README.txt", body: []byte("hello")},
		})
		_, err := mgr.InstallSlotFromReader(SlotCountry, "empty.tar.gz", bytes.NewReader(noMatch), "", SourceTypeOffline)
		if !errors.Is(err, ErrGeoFileInvalid) {
			t.Fatalf("err = %v, want ErrGeoFileInvalid", err)
		}
	})

	t.Run("rollback path traversal and not found", func(t *testing.T) {
		if _, err := mgr.RollbackSlot(SlotIP2RegionV4, "../../etc/passwd"); !errors.Is(err, ErrInvalidBackupID) {
			t.Fatalf("err = %v, want ErrInvalidBackupID", err)
		}
		if _, err := mgr.RollbackSlot(SlotIP2RegionV4, "1700000000-abcdef012345.xdb"); !errors.Is(err, ErrBackupNotFound) {
			t.Fatalf("err = %v, want ErrBackupNotFound", err)
		}
	})

	t.Run("gzip bomb exceeding slot max bytes rejected", func(t *testing.T) {
		// 使用最小槽位上限做定向解压超限验证：直接测 extractFromPlainGzip
		origSpec := slotSpecs[SlotCountry]
		tinySpec := origSpec
		tinySpec.MaxBytes = 1024
		rawPath := filepath.Join(dir, "bomb.gz")
		bomb := gzipBytes(t, bytes.Repeat([]byte("A"), 4096))
		if err := os.WriteFile(rawPath, bomb, 0o600); err != nil {
			t.Fatalf("write bomb: %v", err)
		}
		_, _, err := extractFromPlainGzip(rawPath, tinySpec, filepath.Join(dir, "bomb.out"))
		if !errors.Is(err, ErrGeoFileTooLarge) {
			t.Fatalf("err = %v, want ErrGeoFileTooLarge", err)
		}
	})
}
