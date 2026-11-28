// reloadable_test.go ReloadableEngine 零重启热加载、动态 IsLookupEnabled、目录监听与并发安全测试。
package apigeo

import (
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

type plainCountryStub struct{ code string }

func (p plainCountryStub) LookupCountry(netip.Addr) (string, error) { return p.code, nil }

func TestIsLookupEnabled(t *testing.T) {
	if IsLookupEnabled(nil) {
		t.Fatal("nil should be disabled")
	}
	var typedNilEngine *Engine
	if IsLookupEnabled(typedNilEngine) {
		t.Fatal("typed-nil *Engine should be disabled")
	}
	var typedNilReloadable *ReloadableEngine
	if IsLookupEnabled(typedNilReloadable) {
		t.Fatal("typed-nil *ReloadableEngine should be disabled")
	}
	if IsLookupEnabled(NewEngine(EngineOptions{})) {
		t.Fatal("empty *Engine should be disabled")
	}
	if !IsLookupEnabled(plainCountryStub{code: "US"}) {
		t.Fatal("non-nil plain CountryLookup stub should be enabled")
	}
	emptyDir := t.TempDir()
	re := NewReloadableEngine(emptyDir)
	if IsLookupEnabled(re) {
		t.Fatal("ReloadableEngine without database files should be disabled")
	}
	xdbBytes := buildSyntheticXDBv4(3, []struct {
		start, end string
		region     string
	}{
		{"1.1.1.0", "1.1.1.255", "美国|加利福尼亚|旧金山|Cloudflare|US"},
	})
	if err := os.WriteFile(filepath.Join(emptyDir, "ip2region_v4.xdb"), xdbBytes, 0o640); err != nil {
		t.Fatalf("write xdb: %v", err)
	}
	re.Reload()
	if !IsLookupEnabled(re) {
		t.Fatal("ReloadableEngine after Reload with valid xdb should be enabled")
	}
}

func TestReloadableEngineZeroRestartActivationAndConsumers(t *testing.T) {
	dir := t.TempDir()
	re := NewReloadableEngine(dir)

	// 启动无库：动态降级
	if re.Enabled() {
		t.Fatal("expected disabled initially")
	}
	resolver := NewGeoResolver(re, []string{"CN"})
	if resolver.Enabled() {
		t.Fatal("GeoResolver should dynamically reflect disabled ReloadableEngine")
	}
	if scope, code, err := resolver.Classify("1.1.1.1"); err != nil || scope != ScopeUnknown || code != "" {
		t.Fatalf("disabled classify = (%s, %q, %v), want (UNKNOWN, '', nil)", scope, code, err)
	}

	// 写入有效 v4 XDB 并触发 CheckAndReload（无需重启进程）
	xdbBytes := buildSyntheticXDBv4(3, []struct {
		start, end string
		region     string
	}{
		{"1.1.1.0", "1.1.1.255", "美国|加利福尼亚|洛杉矶|Cloudflare|US"},
		{"114.114.114.0", "114.114.114.255", "中国|江苏省|南京市|电信|CN"},
	})
	if err := os.WriteFile(filepath.Join(dir, "ip2region_v4.xdb"), xdbBytes, 0o640); err != nil {
		t.Fatalf("write xdb: %v", err)
	}
	if !re.CheckAndReload() {
		t.Fatal("CheckAndReload should detect new file and reload")
	}
	if re.CheckAndReload() {
		t.Fatal("second CheckAndReload with no changes should return false")
	}
	if !re.Enabled() || !resolver.Enabled() {
		t.Fatal("ReloadableEngine and GeoResolver should dynamically activate after hot reload")
	}
	scope, code, err := resolver.Classify("1.1.1.1")
	if err != nil || scope != ScopeForeign || code != "US" {
		t.Fatalf("classify 1.1.1.1 = (%s, %q, %v), want (FOREIGN, US, nil)", scope, code, err)
	}
	geo := re.LookupGeo("114.114.114.114")
	if geo.CountryCode != "CN" || geo.City != "南京市" {
		t.Fatalf("LookupGeo 114.114.114.114 = %+v, want CN 南京市", geo)
	}

	// 写入新版 XDB + .revision.json（模拟 HA 备节点 hasyncd 落盘），验证再次热切换
	xdbV2 := buildSyntheticXDBv4(3, []struct {
		start, end string
		region     string
	}{
		{"1.1.1.0", "1.1.1.255", "日本|东京都|东京|Cloudflare|JP"},
	})
	if err := os.WriteFile(filepath.Join(dir, "ip2region_v4.xdb"), xdbV2, 0o640); err != nil {
		t.Fatalf("write xdb v2: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, revisionFileName), []byte(`{"revision":"rev-2"}`), 0o640); err != nil {
		t.Fatalf("write revision: %v", err)
	}
	if !re.CheckAndReload() {
		t.Fatal("CheckAndReload should detect revision update")
	}
	scope, code, err = resolver.Classify("1.1.1.1")
	if err != nil || scope != ScopeForeign || code != "JP" {
		t.Fatalf("classify after v2 reload = (%s, %q, %v), want (FOREIGN, JP, nil)", scope, code, err)
	}
}

func TestReloadableEngineConcurrentLookupAndReload(t *testing.T) {
	dir := t.TempDir()
	xdbBytes := buildSyntheticXDBv4(3, []struct {
		start, end string
		region     string
	}{
		{"114.114.114.0", "114.114.114.255", "中国|江苏省|南京市|电信|CN"},
	})
	if err := os.WriteFile(filepath.Join(dir, "ip2region_v4.xdb"), xdbBytes, 0o640); err != nil {
		t.Fatalf("write xdb: %v", err)
	}
	re := NewReloadableEngine(dir)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip := netip.MustParseAddr("114.114.114.114")
			for {
				select {
				case <-stop:
					return
				default:
					code, err := re.LookupCountry(ip)
					if err != nil || code != "CN" {
						t.Errorf("concurrent LookupCountry = (%q, %v)", code, err)
						return
					}
					g := re.LookupGeo("114.114.114.114")
					if g == nil || g.CountryCode != "CN" {
						t.Errorf("concurrent LookupGeo = %+v", g)
						return
					}
				}
			}
		}()
	}

	for i := 0; i < 10; i++ {
		re.Reload()
	}
	close(stop)
	wg.Wait()
}
