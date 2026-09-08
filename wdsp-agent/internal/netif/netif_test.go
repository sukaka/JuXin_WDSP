package netif

import "testing"

func TestDiscover(t *testing.T) {
	ifaces, err := Discover()
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range ifaces {
		if i.Name == "lo" || i.Name == "lo0" {
			t.Fatalf("loopback 应被排除: %+v", i)
		}
		if i.Name == "" || i.MTU <= 0 {
			t.Fatalf("字段缺失: %+v", i)
		}
	}
	t.Logf("发现 %d 个接口: %+v", len(ifaces), ifaces)
}
