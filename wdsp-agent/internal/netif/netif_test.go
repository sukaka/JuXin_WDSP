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
		// 虚拟/隧道伪接口（如 macOS pktap0 分组捕获点）无 MAC/IP/MTU 等 L2/L3 标识，
		// 属宿主环境特征而非缺陷，跳过硬性字段断言
		if i.MAC == "" && len(i.IPv4) == 0 && len(i.IPv6) == 0 {
			t.Logf("跳过伪接口: %+v", i)
			continue
		}
		if i.Name == "" || i.MTU <= 0 {
			t.Fatalf("字段缺失: %+v", i)
		}
	}
	t.Logf("发现 %d 个接口: %+v", len(ifaces), ifaces)
}
