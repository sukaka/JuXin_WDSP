// engine_test.go 统一 GeoIP 引擎（ip2region + DB-IP/MMDB 融合）、自动目录发现与 HTTP 批量接口测试。
package apigeo

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMergeGeoInfoHybrid(t *testing.T) {
	t.Run("CN prefers ip2region Chinese province/city/ISP and CN coord table", func(t *testing.T) {
		xdbRec := &XDBRecord{CountryCode: "CN", Country: "中国", Province: "江苏省", City: "南京市", ISP: "电信"}
		// 模拟 DB-IP 将 114.114.114.114 误标为济南的场景：国内以 ip2region 与中国省市坐标为准
		cityLoc := &MMDBLocation{CountryCode: "CN", Country: "China", Province: "Shandong", City: "Jinan", Latitude: 36.65, Longitude: 117.12, HasCoord: true}
		got := mergeGeoInfo("114.114.114.114", xdbRec, cityLoc, nil)
		if got.CountryCode != "CN" || got.Country != "中国" || got.Province != "江苏省" || got.City != "南京市" || got.ISP != "电信" {
			t.Fatalf("unexpected CN merged geo: %+v", got)
		}
		if got.Label != "中国 江苏省 南京市" {
			t.Fatalf("unexpected CN label: %q", got.Label)
		}
		if got.Longitude == nil || got.Latitude == nil || *got.Longitude != 118.8 || *got.Latitude != 32.06 {
			t.Fatalf("expected Nanjing coord (118.8, 32.06), got (%v, %v)", got.Longitude, got.Latitude)
		}
		if got.Source != "ip2region" {
			t.Fatalf("expected source=ip2region, got %q", got.Source)
		}
	})

	t.Run("overseas merges DB-IP city/coord with ip2region ISP", func(t *testing.T) {
		xdbRec := &XDBRecord{CountryCode: "US", Country: "United States", Province: "California", City: "", ISP: "Google LLC"}
		cityLoc := &MMDBLocation{CountryCode: "US", Country: "United States", Province: "California", City: "Mountain View", Latitude: 37.4056, Longitude: -122.0775, HasCoord: true}
		got := mergeGeoInfo("8.8.8.8", xdbRec, cityLoc, nil)
		if got.CountryCode != "US" || got.Country != "美国" || got.Province != "California" || got.City != "Mountain View" || got.ISP != "Google LLC" {
			t.Fatalf("unexpected overseas merged geo: %+v", got)
		}
		if got.Label != "美国 California Mountain View" {
			t.Fatalf("unexpected overseas label: %q", got.Label)
		}
		if got.Longitude == nil || *got.Longitude != -122.0775 || got.Latitude == nil || *got.Latitude != 37.4056 {
			t.Fatalf("unexpected overseas coord: %v, %v", got.Longitude, got.Latitude)
		}
		if got.Source != "hybrid" {
			t.Fatalf("expected source=hybrid, got %q", got.Source)
		}
	})

	t.Run("municipality and HK/TW deduplicate label", func(t *testing.T) {
		bj := mergeGeoInfo("119.29.29.29", &XDBRecord{CountryCode: "CN", Country: "中国", Province: "北京市", City: "北京市", ISP: "腾讯"}, nil, nil)
		if bj.Label != "中国 北京市" {
			t.Fatalf("expected deduplicated Beijing label, got %q", bj.Label)
		}
		hk := mergeGeoInfo("202.45.84.58", &XDBRecord{CountryCode: "HK", Country: "中国", Province: "香港特别行政区"}, nil, nil)
		if hk.Label != "中国香港" || hk.Longitude == nil {
			t.Fatalf("unexpected HK geo: %+v", hk)
		}
	})
}

func TestEngineRealAssetsEndToEnd(t *testing.T) {
	if _, err := os.Stat(realXDBv4Path); err != nil {
		t.Skipf("real xdb not present: %v", err)
	}
	engine := OpenEngine("../../assets/geoip", "../../../web/public/assets/geo")
	if !engine.Enabled() {
		t.Fatal("expected engine enabled with real assets")
	}
	sources := strings.Join(engine.Sources(), ",")
	if !strings.Contains(sources, "ip2region_v4") {
		t.Fatalf("expected ip2region_v4 in sources, got %q", sources)
	}

	// 内网地址
	priv := engine.LookupGeo("192.168.1.10")
	if priv.Scope != IPScopeInternal || priv.Label != "内网地址" {
		t.Fatalf("unexpected private geo: %+v", priv)
	}
	// 非法输入
	inv := engine.LookupGeo("not-an-ip")
	if inv.Scope != IPScopeInvalid {
		t.Fatalf("unexpected invalid geo: %+v", inv)
	}
	// 国内电信
	gz := engine.LookupGeo("202.96.128.86")
	if gz.Scope != IPScopePublic || gz.CountryCode != "CN" || gz.Province != "广东省" || gz.City != "广州市" || gz.ISP != "电信" || gz.Longitude == nil {
		t.Fatalf("unexpected Guangzhou geo: %+v", gz)
	}
	// 海外 IPv4
	nl := engine.LookupGeo("45.148.10.75")
	if nl.CountryCode != "NL" || nl.Country != "荷兰" {
		t.Fatalf("unexpected NL geo: %+v", nl)
	}
	// CountryLookup 兼容（1.1.1.1=AU；240e::1=CN）
	if code, err := engine.LookupCountry(netip.MustParseAddr("1.1.1.1")); err != nil || code != "AU" {
		t.Fatalf("LookupCountry 1.1.1.1 = %q, %v; want AU", code, err)
	}
	if code, err := engine.LookupCountry(netip.MustParseAddr("240e::1")); err != nil || code != "CN" {
		t.Fatalf("LookupCountry 240e::1 = %q, %v; want CN", code, err)
	}
	// IPv6 城市库融合（city-ipv6.mmdb）
	v6Geo := engine.LookupGeo("240e::1")
	if v6Geo.CountryCode != "CN" || v6Geo.Country != "中国" || v6Geo.Longitude == nil || v6Geo.Latitude == nil {
		t.Fatalf("unexpected v6 CN geo: %+v", v6Geo)
	}
	v6Overseas := engine.LookupGeo("2001:4860:4860::8888")
	if v6Overseas.CountryCode == "" || v6Overseas.Country == "" || v6Overseas.Longitude == nil || v6Overseas.Latitude == nil {
		t.Fatalf("unexpected v6 overseas geo: %+v", v6Overseas)
	}
}

func TestOpenEnginePriorityAndGlobOrder(t *testing.T) {
	dirHigh := t.TempDir()
	dirLow := t.TempDir()

	highBuf := buildSyntheticXDBv4(3, []struct{ start, end, region string }{
		{"202.96.128.0", "202.96.128.255", "中国|上海市|上海市|联通|CN"},
	})
	lowBuf := buildSyntheticXDBv4(3, []struct{ start, end, region string }{
		{"202.96.128.0", "202.96.128.255", "中国|广东省|广州市|电信|CN"},
	})
	if err := os.WriteFile(filepath.Join(dirHigh, "ip2region_v4.xdb"), highBuf, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirLow, "ip2region_v4.xdb"), lowBuf, 0o600); err != nil {
		t.Fatal(err)
	}

	eng := OpenEngine(dirHigh, dirLow)
	got := eng.LookupGeo("202.96.128.86")
	if got.Province != "上海市" || got.ISP != "联通" {
		t.Fatalf("expected high-priority dir override, got %+v", got)
	}

	// 验证 findFirstMatch 按月倒序选取最新文件
	if err := os.WriteFile(filepath.Join(dirHigh, "dbip-city-lite-2026-10.mmdb"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirHigh, "dbip-city-lite-2026-11.mmdb"), []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	picked := findFirstMatch([]string{dirHigh}, []string{"dbip-city-lite*.mmdb"})
	if filepath.Base(picked) != "dbip-city-lite-2026-11.mmdb" {
		t.Fatalf("expected newest monthly dbip file, got %q", picked)
	}
}

func TestLookupHandlerHTTP(t *testing.T) {
	xdb, err := ParseXDB(buildSyntheticXDBv4(3, []struct{ start, end, region string }{
		{"202.96.128.0", "202.96.128.255", "中国|广东省|广州市|电信|CN"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine(EngineOptions{XDBv4: xdb})
	h := NewLookupHandler(eng)
	mux := http.NewServeMux()
	passAuth := func(next http.Handler) http.Handler { return next }
	RegisterLookupRoutes(mux, passAuth, h)

	t.Run("GET single ip", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/geoip/lookup?ip=202.96.128.86", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		var body struct {
			Data lookupOneResponse `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if !body.Data.GeoEnabled || body.Data.Geo == nil || body.Data.Geo.ISP != "电信" || body.Data.Geo.City != "广州市" {
			t.Fatalf("unexpected response: %+v", body.Data)
		}
	})

	t.Run("GET missing ip returns 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/geoip/lookup", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
	})

	t.Run("POST batch deduplicates and resolves internal/public", func(t *testing.T) {
		payload := `{"ips":["202.96.128.86","202.96.128.86","10.0.0.1"]}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/geoip/lookup", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		var body struct {
			Data lookupBatchResponse `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if len(body.Data.Items) != 2 {
			t.Fatalf("expected 2 deduplicated items, got %d", len(body.Data.Items))
		}
		if body.Data.Items["202.96.128.86"].Label != "中国 广东省 广州市" {
			t.Fatalf("unexpected public item: %+v", body.Data.Items["202.96.128.86"])
		}
		if body.Data.Items["10.0.0.1"].Label != "内网地址" {
			t.Fatalf("unexpected private item: %+v", body.Data.Items["10.0.0.1"])
		}
	})

	t.Run("POST batch rejects >200 IPs", func(t *testing.T) {
		ips := make([]string, 201)
		for i := range ips {
			ips[i] = "1.1.1.1"
		}
		raw, _ := json.Marshal(lookupBatchRequest{IPs: ips})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/geoip/lookup", bytes.NewReader(raw))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for >200 IPs, got %d", rec.Code)
		}
	})

	t.Run("nil engine degrades cleanly", func(t *testing.T) {
		nilHandler := NewLookupHandler(nil)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/geoip/lookup?ip=10.0.0.1", nil)
		rec := httptest.NewRecorder()
		nilHandler.LookupOne(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d", rec.Code)
		}
		var body struct {
			Data lookupOneResponse `json:"data"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if body.Data.GeoEnabled || body.Data.Geo.Label != "内网地址" {
			t.Fatalf("unexpected nil-engine response: %+v", body.Data)
		}
	})
}
