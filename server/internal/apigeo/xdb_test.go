// xdb_test.go ip2region XDB 只读解析器单元测试：
// 覆盖合成 v2/v3（IPv4/IPv6）二进制样本、损坏边界矩阵、以及仓库内置真实 ip2region_v4.xdb 样本。
package apigeo

import (
	"encoding/binary"
	"net/netip"
	"os"
	"testing"
)

const realXDBv4Path = "../../assets/geoip/ip2region_v4.xdb"

// buildSyntheticXDBv4 构造合法的最小 ip2region XDB v2/v3 IPv4 字节流（用于纯单测）。
func buildSyntheticXDBv4(version uint16, entries []struct {
	start, end string
	region     string
}) []byte {
	buf := make([]byte, xdbMinFileSize)
	binary.LittleEndian.PutUint16(buf[0:2], version)
	binary.LittleEndian.PutUint16(buf[2:4], xdbIndexPolicyVector)
	if version >= 3 {
		binary.LittleEndian.PutUint16(buf[16:18], 4)
		binary.LittleEndian.PutUint16(buf[18:20], 4)
	}

	// 写入数据区
	type recMeta struct {
		sip, eip uint32
		b0, b1   byte
		dataPtr  uint32
		dataLen  uint16
	}
	var metas []recMeta
	for _, e := range entries {
		s := netip.MustParseAddr(e.start).As4()
		t := netip.MustParseAddr(e.end).As4()
		ptr := uint32(len(buf))
		buf = append(buf, []byte(e.region)...)
		metas = append(metas, recMeta{
			sip:     binary.BigEndian.Uint32(s[:]),
			eip:     binary.BigEndian.Uint32(t[:]),
			b0:      s[0],
			b1:      s[1],
			dataPtr: ptr,
			dataLen: uint16(len(e.region)),
		})
	}

	// 写入索引区（假定测试样本按 ip 升序且同一 (b0,b1) 连续）
	startIdx := uint32(len(buf))
	type vecRange struct{ s, e uint32 }
	vecs := map[uint16]vecRange{}
	for _, m := range metas {
		segOff := uint32(len(buf))
		var seg [xdbSegSizeV4]byte
		binary.LittleEndian.PutUint32(seg[0:4], m.sip)
		binary.LittleEndian.PutUint32(seg[4:8], m.eip)
		binary.LittleEndian.PutUint16(seg[8:10], m.dataLen)
		binary.LittleEndian.PutUint32(seg[10:14], m.dataPtr)
		buf = append(buf, seg[:]...)

		key := uint16(m.b0)<<8 | uint16(m.b1)
		if vr, ok := vecs[key]; !ok {
			vecs[key] = vecRange{s: segOff, e: segOff}
		} else {
			vr.e = segOff
			vecs[key] = vr
		}
	}
	endIdx := uint32(len(buf) - xdbSegSizeV4)
	binary.LittleEndian.PutUint32(buf[8:12], startIdx)
	binary.LittleEndian.PutUint32(buf[12:16], endIdx)

	for key, vr := range vecs {
		vOff := xdbHeaderSize + int(key)*xdbVectorEntrySize
		binary.LittleEndian.PutUint32(buf[vOff:vOff+4], vr.s)
		binary.LittleEndian.PutUint32(buf[vOff+4:vOff+8], vr.e)
	}
	return buf
}

// buildSyntheticXDBv6 构造合法的最小 ip2region XDB v3 IPv6 字节流。
func buildSyntheticXDBv6(start, end, region string) []byte {
	buf := make([]byte, xdbMinFileSize)
	binary.LittleEndian.PutUint16(buf[0:2], 3)
	binary.LittleEndian.PutUint16(buf[2:4], xdbIndexPolicyVector)
	binary.LittleEndian.PutUint16(buf[16:18], 6)
	binary.LittleEndian.PutUint16(buf[18:20], 4)

	dataPtr := uint32(len(buf))
	buf = append(buf, []byte(region)...)

	s := netip.MustParseAddr(start).As16()
	e := netip.MustParseAddr(end).As16()
	segOff := uint32(len(buf))
	var seg [xdbSegSizeV6]byte
	copy(seg[0:16], s[:])
	copy(seg[16:32], e[:])
	binary.LittleEndian.PutUint16(seg[32:34], uint16(len(region)))
	binary.LittleEndian.PutUint32(seg[34:38], dataPtr)
	buf = append(buf, seg[:]...)

	binary.LittleEndian.PutUint32(buf[8:12], segOff)
	binary.LittleEndian.PutUint32(buf[12:16], segOff)
	vOff := xdbHeaderSize + (int(s[0])*xdbVectorCols+int(s[1]))*xdbVectorEntrySize
	binary.LittleEndian.PutUint32(buf[vOff:vOff+4], segOff)
	binary.LittleEndian.PutUint32(buf[vOff+4:vOff+8], segOff)
	return buf
}

func TestXDBSyntheticV3AndV2(t *testing.T) {
	t.Run("v3 IPv4", func(t *testing.T) {
		buf := buildSyntheticXDBv4(3, []struct{ start, end, region string }{
			{"202.96.128.0", "202.96.128.255", "中国|广东省|广州市|电信|CN"},
			{"202.96.129.0", "202.96.129.255", "中国|香港特别行政区|0|0|CN"},
		})
		db, err := ParseXDB(buf)
		if err != nil {
			t.Fatalf("ParseXDB v3: %v", err)
		}
		rec, err := db.Lookup(netip.MustParseAddr("202.96.128.86"))
		if err != nil || rec == nil {
			t.Fatalf("lookup failed: rec=%+v err=%v", rec, err)
		}
		if rec.CountryCode != "CN" || rec.Province != "广东省" || rec.City != "广州市" || rec.ISP != "电信" {
			t.Fatalf("unexpected v3 rec: %+v", rec)
		}
		hk, err := db.Lookup(netip.MustParseAddr("202.96.129.10"))
		if err != nil || hk == nil || hk.CountryCode != "HK" {
			t.Fatalf("expected HK refinement, got %+v err=%v", hk, err)
		}
		// 4-in-6 自动归一
		mapped, err := db.Lookup(netip.MustParseAddr("::ffff:202.96.128.86"))
		if err != nil || mapped == nil || mapped.City != "广州市" {
			t.Fatalf("expected 4in6 hit, got %+v err=%v", mapped, err)
		}
		// IPv6 在 IPv4 库中返回 (nil, nil)
		if v6, err := db.Lookup(netip.MustParseAddr("240e::1")); err != nil || v6 != nil {
			t.Fatalf("expected nil for v6 in v4 xdb, got %+v err=%v", v6, err)
		}
	})

	t.Run("v2 IPv4", func(t *testing.T) {
		buf := buildSyntheticXDBv4(2, []struct{ start, end, region string }{
			{"114.114.114.0", "114.114.114.255", "中国|0|江苏省|南京市|电信"},
		})
		db, err := ParseXDB(buf)
		if err != nil {
			t.Fatalf("ParseXDB v2: %v", err)
		}
		rec, err := db.Lookup(netip.MustParseAddr("114.114.114.114"))
		if err != nil || rec == nil {
			t.Fatalf("v2 lookup failed: rec=%+v err=%v", rec, err)
		}
		if rec.CountryCode != "CN" || rec.Province != "江苏省" || rec.City != "南京市" || rec.ISP != "电信" {
			t.Fatalf("unexpected v2 rec: %+v", rec)
		}
	})

	t.Run("v3 IPv6", func(t *testing.T) {
		buf := buildSyntheticXDBv6("240e:0000::", "240e:00ff:ffff:ffff:ffff:ffff:ffff:ffff", "中国|上海市|上海市|电信|CN")
		db, err := ParseXDB(buf)
		if err != nil {
			t.Fatalf("ParseXDB v6: %v", err)
		}
		if db.IPVersion() != 6 {
			t.Fatalf("IPVersion = %d, want 6", db.IPVersion())
		}
		rec, err := db.Lookup(netip.MustParseAddr("240e:12::1"))
		if err != nil || rec == nil || rec.CountryCode != "CN" || rec.Province != "上海市" || rec.ISP != "电信" {
			t.Fatalf("unexpected v6 rec: %+v err=%v", rec, err)
		}
	})
}

func TestXDBCorruptInputs(t *testing.T) {
	if _, err := ParseXDB(nil); err == nil {
		t.Fatal("nil buffer should fail")
	}
	if _, err := ParseXDB(make([]byte, 1024)); err == nil {
		t.Fatal("too small buffer should fail")
	}
	badVer := make([]byte, xdbMinFileSize+32)
	binary.LittleEndian.PutUint16(badVer[0:2], 99)
	if _, err := ParseXDB(badVer); err == nil {
		t.Fatal("unsupported version should fail")
	}
	badRange := make([]byte, xdbMinFileSize+32)
	binary.LittleEndian.PutUint16(badRange[0:2], 3)
	binary.LittleEndian.PutUint16(badRange[2:4], xdbIndexPolicyVector)
	binary.LittleEndian.PutUint32(badRange[8:12], 100)
	binary.LittleEndian.PutUint32(badRange[12:16], 200)
	if _, err := ParseXDB(badRange); err == nil {
		t.Fatal("invalid index range should fail")
	}
	if _, err := OpenXDB("/nonexistent/ip2region_v4.xdb"); err == nil {
		t.Fatal("missing file should fail")
	}
}

func TestXDBRealDatabaseLookup(t *testing.T) {
	if _, err := os.Stat(realXDBv4Path); err != nil {
		t.Skipf("real ip2region_v4.xdb not present: %v", err)
	}
	db, err := OpenXDB(realXDBv4Path)
	if err != nil {
		t.Fatalf("OpenXDB real: %v", err)
	}
	cases := []struct {
		ip          string
		countryCode string
		wantProv    string
		wantISP     string
	}{
		{"202.96.128.86", "CN", "广东省", "电信"},
		{"223.5.5.5", "CN", "浙江省", "阿里"},
		{"119.29.29.29", "CN", "北京市", "腾讯"},
		{"168.95.1.1", "TW", "台湾省", "中华电信"},
		{"202.45.84.58", "HK", "香港特别行政区", ""},
		{"202.175.3.3", "MO", "澳门特别行政区", "澳门电讯"},
		{"8.8.8.8", "US", "California", "Google LLC"},
		{"45.148.10.75", "NL", "South Holland", ""},
	}
	for _, tc := range cases {
		rec, err := db.Lookup(netip.MustParseAddr(tc.ip))
		if err != nil {
			t.Fatalf("lookup %s error: %v", tc.ip, err)
		}
		if rec == nil {
			t.Fatalf("lookup %s returned nil", tc.ip)
		}
		if rec.CountryCode != tc.countryCode {
			t.Fatalf("lookup %s country_code=%q, want %q (raw=%q)", tc.ip, rec.CountryCode, tc.countryCode, rec.Raw)
		}
		if tc.wantProv != "" && rec.Province != tc.wantProv {
			t.Fatalf("lookup %s province=%q, want %q (raw=%q)", tc.ip, rec.Province, tc.wantProv, rec.Raw)
		}
		if tc.wantISP != "" && rec.ISP != tc.wantISP {
			t.Fatalf("lookup %s isp=%q, want %q (raw=%q)", tc.ip, rec.ISP, tc.wantISP, rec.Raw)
		}
	}
}
