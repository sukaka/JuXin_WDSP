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
