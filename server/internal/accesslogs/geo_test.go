package accesslogs

import (
	"net/netip"
	"testing"

	"github.com/jiuzhang-waf/server/internal/apigeo"
)

type stubGeoLookup struct {
	calls map[string]int
}

func (s *stubGeoLookup) LookupCountry(netip.Addr) (string, error) { return "NL", nil }
func (s *stubGeoLookup) Enabled() bool                            { return true }
func (s *stubGeoLookup) Sources() []string                        { return []string{"test"} }
func (s *stubGeoLookup) LookupGeo(ip string) *apigeo.GeoInfo {
	s.calls[ip]++
	return &apigeo.GeoInfo{
		IP: ip, Scope: apigeo.IPScopePublic, CountryCode: "NL",
		Country: "荷兰", Province: "South Holland", ISP: "Example ISP",
		Label: "荷兰 South Holland", Source: "hybrid",
	}
}

func TestHandlerAttachGeo(t *testing.T) {
	stub := &stubGeoLookup{calls: map[string]int{}}
	h := NewHandler(nil, nil)
	h.SetGeoLookup(stub)

	logs := []AccessLog{
		{ClientIP: "45.148.10.75"},
		{ClientIP: "45.148.10.75"},
		{ClientIP: ""},
	}
	h.attachGeoSlice(logs)
	if stub.calls["45.148.10.75"] != 1 {
		t.Fatalf("expected 1 deduplicated lookup, got %d", stub.calls["45.148.10.75"])
	}
	if logs[0].ClientIPGeo == nil || logs[0].ClientIPGeo.Label != "荷兰 South Holland" || logs[0].ClientIPGeo.ISP != "Example ISP" {
		t.Fatalf("unexpected log geo: %+v", logs[0].ClientIPGeo)
	}
	if logs[2].ClientIPGeo != nil {
		t.Fatal("expected nil geo for empty ip")
	}

	entry := &AccessLog{ClientIP: "45.148.10.75"}
	h.attachGeo(entry)
	if entry.ClientIPGeo == nil || entry.ClientIPGeo.CountryCode != "NL" {
		t.Fatalf("unexpected single entry geo: %+v", entry.ClientIPGeo)
	}
}
