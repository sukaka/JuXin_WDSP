// mmdb_test.go 只读 mmdb 解析器测试：真实库文件（仓库归档的 country.mmdb，
// 缺失时跳过）+ 损坏输入矩阵（必须报错而非 panic）。
package apigeo

import (
	"net/netip"
	"os"
	"testing"
)

// realMMDBPath 仓库内归档的 GeoIP 数据文件（web 大屏静态资产，CC0 数据集；
// 服务端测试只读引用，不复制不修改）。
const realMMDBPath = "../../../web/public/assets/geo/country.mmdb"

// openRealMMDB 打开真实库；文件缺失（裁剪后的部署环境）跳过测试。
func openRealMMDB(t *testing.T) *MMDB {
	t.Helper()
	if _, err := os.Stat(realMMDBPath); err != nil {
		t.Skipf("real mmdb not present: %v", err)
	}
	db, err := OpenMMDB(realMMDBPath)
	if err != nil {
		t.Fatalf("OpenMMDB: %v", err)
	}
	return db
}

// TestMMDBRealLookup 真实库已知 IP 断言（锚定值与 mmdb-lib 前端链路一致：
// 8.8.8.8=US / 1.1.1.1=AU / 114.114.114.114=CN；内网段库未收录返回空）。
func TestMMDBRealLookup(t *testing.T) {
	db := openRealMMDB(t)
	cases := []struct {
		ip      string
		country string
	}{
		{"8.8.8.8", "US"},
		{"1.1.1.1", "AU"},
		{"114.114.114.114", "CN"},
		{"223.5.5.5", "CN"},
		{"10.0.0.1", ""}, // 该段在库中无记录（whois 无归属统计）
		// 注意：geo-whois 源自 whois 统计，个别私网段带父级国家码（如 192.168.x→AU），
		// 内网豁免由判定层 isInternalAddr 在查库前完成（见 resolver_test.go），本层不做假设。
	}
	for _, c := range cases {
		addr, err := netip.ParseAddr(c.ip)
		if err != nil {
			t.Fatalf("parse %s: %v", c.ip, err)
		}
		got, err := db.LookupCountry(addr)
		if err != nil {
			t.Fatalf("lookup %s: %v", c.ip, err)
		}
		if got != c.country {
			t.Fatalf("lookup %s = %q, want %q", c.ip, got, c.country)
		}
	}
}

// TestMMDBRealLookupIPv6 真实库 IPv6 与 4-in-6 归一断言。
func TestMMDBRealLookupIPv6(t *testing.T) {
	db := openRealMMDB(t)
	// Cloudflare DNS v6（IPv6 树遍历）
	addr, _ := netip.ParseAddr("2606:4700:4700::1111")
	if got, err := db.LookupCountry(addr); err != nil || got != "US" {
		t.Fatalf("lookup v6 = %q, %v; want US", got, err)
	}
	// 4-in-6 归一（Unmap 后走 IPv4 路径）
	mapped, _ := netip.ParseAddr("::ffff:8.8.8.8")
	if got, err := db.LookupCountry(mapped); err != nil || got != "US" {
		t.Fatalf("lookup 4in6 = %q, %v; want US", got, err)
	}
}

// TestMMDBCorrupt 损坏输入矩阵：全部必须返回错误而非 panic。
func TestMMDBCorrupt(t *testing.T) {
	if _, err := ParseMMDB(nil); err == nil {
		t.Fatal("nil buffer should fail")
	}
	if _, err := ParseMMDB([]byte("not an mmdb file at all")); err == nil {
		t.Fatal("garbage should fail")
	}
	// 有标记但元数据不可解码
	fake := append([]byte{0x01, 0x02, 0x03}, metadataMarker...)
	fake = append(fake, make([]byte, 128)...)
	if _, err := ParseMMDB(fake); err == nil {
		t.Fatal("undecodable metadata should fail")
	}
	if _, err := OpenMMDB("/nonexistent/path/country.mmdb"); err == nil {
		t.Fatal("missing file should fail")
	}
}

// TestExtractMMDBLocationDualSchema 验证同时兼容 sapics 扁平结构与官方 DB-IP/MaxMind 嵌套结构。
func TestExtractMMDBLocationDualSchema(t *testing.T) {
	t.Run("official DB-IP nested schema", func(t *testing.T) {
		rec := map[string]any{
			"country": map[string]any{
				"iso_code": "nl",
				"names": map[string]any{
					"en":    "Netherlands",
					"zh-CN": "荷兰",
				},
			},
			"subdivisions": []any{
				map[string]any{
					"iso_code": "NH",
					"names": map[string]any{
						"en":    "North Holland",
						"zh-CN": "北荷兰省",
					},
				},
			},
			"city": map[string]any{
				"names": map[string]any{
					"en":    "Amsterdam",
					"zh-CN": "阿姆斯特丹",
				},
			},
			"location": map[string]any{
				"latitude":  52.3676,
				"longitude": 4.9041,
			},
		}
		loc := extractMMDBLocation(rec)
		if loc == nil {
			t.Fatal("expected non-nil location")
		}
		if loc.CountryCode != "NL" || loc.Country != "荷兰" || loc.Province != "北荷兰省" || loc.City != "阿姆斯特丹" {
			t.Fatalf("unexpected nested loc: %+v", loc)
		}
		if !loc.HasCoord || loc.Latitude != 52.3676 || loc.Longitude != 4.9041 {
			t.Fatalf("unexpected coords: %+v", loc)
		}
	})

	t.Run("official DB-IP registered_country fallback and en names", func(t *testing.T) {
		rec := map[string]any{
			"registered_country": map[string]any{
				"iso_code": "US",
				"names":    map[string]any{"en": "United States"},
			},
			"city": map[string]any{
				"names": map[string]any{"en": "Mountain View"},
			},
			"location": map[string]any{
				"latitude":  float32(37.4056),
				"longitude": float32(-122.0775),
			},
		}
		loc := extractMMDBLocation(rec)
		if loc == nil || loc.CountryCode != "US" || loc.Country != "United States" || loc.City != "Mountain View" || !loc.HasCoord {
			t.Fatalf("unexpected fallback loc: %+v", loc)
		}
	})

	t.Run("sapics flat schema", func(t *testing.T) {
		rec := map[string]any{
			"country_code": "JP",
			"state1":       "Tokyo",
			"city":         "Tokyo",
			"latitude":     35.6762,
			"longitude":    139.6503,
		}
		loc := extractMMDBLocation(rec)
		if loc == nil || loc.CountryCode != "JP" || loc.Province != "Tokyo" || loc.City != "Tokyo" || !loc.HasCoord {
			t.Fatalf("unexpected flat loc: %+v", loc)
		}
	})

	t.Run("zero coord ignored", func(t *testing.T) {
		rec := map[string]any{
			"country_code": "US",
			"latitude":     0.0,
			"longitude":    0.0,
		}
		loc := extractMMDBLocation(rec)
		if loc == nil || loc.CountryCode != "US" || loc.HasCoord {
			t.Fatalf("expected HasCoord=false for (0,0), got %+v", loc)
		}
	})
}

// TestMMDBRealCityIPv6Lookup 真实仓库 city-ipv6.mmdb 城市与坐标查询断言。
func TestMMDBRealCityIPv6Lookup(t *testing.T) {
	const cityV6Path = "../../../web/public/assets/geo/city-ipv6.mmdb"
	if _, err := os.Stat(cityV6Path); err != nil {
		t.Skipf("real city-ipv6.mmdb not present: %v", err)
	}
	db, err := OpenMMDB(cityV6Path)
	if err != nil {
		t.Fatalf("OpenMMDB city-ipv6: %v", err)
	}
	addr := netip.MustParseAddr("2606:4700:4700::1111")
	loc, err := db.LookupLocation(addr)
	if err != nil {
		t.Fatalf("LookupLocation v6: %v", err)
	}
	if loc == nil || loc.CountryCode == "" {
		t.Fatalf("expected non-empty IPv6 city location, got %+v", loc)
	}
}

// TestMMDBPointerLoopProtected 循环指针必须触发深度保护返回错误而非栈溢出。
func TestMMDBPointerLoopProtected(t *testing.T) {
	// 构造 2 字节循环指针：控制字节 001_00_000 (0x20) + 偏移 0 → 指回自身 baseOffset+0
	d := decoder{
		buf:        []byte{0x20, 0x00},
		baseOffset: 0,
	}
	if _, _, err := d.decode(0); err == nil {
		t.Fatal("expected pointer loop to return error")
	}
}
