package securityevents

import (
	"net/netip"
	"testing"

	"github.com/jiuzhang-waf/server/internal/apigeo"
)

type countingGeoLookup struct {
	calls map[string]int
}

func (c *countingGeoLookup) LookupCountry(netip.Addr) (string, error) { return "CN", nil }
func (c *countingGeoLookup) Enabled() bool                            { return true }
func (c *countingGeoLookup) Sources() []string                        { return []string{"test"} }
func (c *countingGeoLookup) LookupGeo(ip string) *apigeo.GeoInfo {
	c.calls[ip]++
	if ip == "10.0.0.1" {
		return &apigeo.GeoInfo{IP: ip, Scope: apigeo.IPScopeInternal, Label: "内网地址", Source: "internal"}
	}
	return &apigeo.GeoInfo{
		IP: ip, Scope: apigeo.IPScopePublic, CountryCode: "CN",
		Country: "中国", Province: "广东省", City: "广州市", ISP: "电信",
		Label: "中国 广东省 广州市", Source: "ip2region",
	}
}

func TestHandlerAttachGeoEnrichmentAndDedup(t *testing.T) {
	stub := &countingGeoLookup{calls: map[string]int{}}
	h := NewHandler(nil, nil, nil)
	h.SetGeoLookup(stub)

	list := []Event{
		{ClientIP: "202.96.128.86"},
		{ClientIP: "202.96.128.86"},
		{ClientIP: "10.0.0.1"},
		{ClientIP: ""},
	}
	h.attachGeoSlice(list)

	if stub.calls["202.96.128.86"] != 1 {
		t.Fatalf("expected deduplicated 1 lookup, got %d", stub.calls["202.96.128.86"])
	}
	if list[0].ClientIPGeo == nil || list[0].ClientIPGeo.Label != "中国 广东省 广州市" || list[0].ClientIPGeo.ISP != "电信" {
		t.Fatalf("unexpected geo on list[0]: %+v", list[0].ClientIPGeo)
	}
	if list[1].ClientIPGeo != list[0].ClientIPGeo {
		t.Fatal("expected cached pointer reuse for identical IP")
	}
	if list[2].ClientIPGeo == nil || list[2].ClientIPGeo.Label != "内网地址" {
		t.Fatalf("unexpected geo on private ip: %+v", list[2].ClientIPGeo)
	}
	if list[3].ClientIPGeo != nil {
		t.Fatalf("expected nil geo for empty ip, got %+v", list[3].ClientIPGeo)
	}

	single := &Event{ClientIP: "202.96.128.86"}
	h.attachGeo(single)
	if single.ClientIPGeo == nil || single.ClientIPGeo.ISP != "电信" {
		t.Fatalf("unexpected single geo: %+v", single.ClientIPGeo)
	}

	// nil geoLookup 安全空转
	nilH := NewHandler(nil, nil, nil)
	evt := &Event{ClientIP: "202.96.128.86"}
	nilH.attachGeo(evt)
	if evt.ClientIPGeo != nil {
		t.Fatalf("expected nil when geoLookup unset")
	}
}
