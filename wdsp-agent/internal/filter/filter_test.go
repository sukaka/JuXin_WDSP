package filter

import "testing"

func TestMatchDirection(t *testing.T) {
	ports := []uint16{80, 443, 8080}
	cases := []struct {
		name        string
		dir         string
		src, dst    uint16
		wantOK      bool
		wantIngress bool
	}{
		{"both-dst-hit", Both, 51234, 80, true, true},
		{"both-src-hit", Both, 80, 51234, true, false},
		{"both-miss", Both, 12345, 22, false, false},
		{"ingress-dst-hit", Ingress, 51234, 443, true, true},
		{"ingress-src-hit-reject", Ingress, 443, 51234, false, false},
		{"ingress-miss", Ingress, 1234, 9090, false, false},
		{"egress-src-hit", Egress, 8080, 40000, true, false},
		{"egress-dst-hit-reject", Egress, 40000, 8080, false, false},
		{"both-endpoints-hit-prefer-ingress", Both, 80, 443, true, true},
		{"invalid-dir-falls-back-both", "sideways", 51234, 80, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := New(ports, tc.dir)
			ok, ingress := f.Match(tc.src, tc.dst)
			if ok != tc.wantOK || ingress != tc.wantIngress {
				t.Fatalf("Match(%d,%d) dir=%s = (%v,%v), want (%v,%v)",
					tc.src, tc.dst, tc.dir, ok, ingress, tc.wantOK, tc.wantIngress)
			}
		})
	}
}

func TestSetPortsHotUpdate(t *testing.T) {
	f := New([]uint16{80}, Both)
	if ok, _ := f.Match(1234, 8080); ok {
		t.Fatal("8080 不应命中初始集合")
	}
	f.SetPorts([]uint16{8080})
	ok, ingress := f.Match(1234, 8080)
	if !ok || !ingress {
		t.Fatal("热更新后 8080 应命中 ingress")
	}
	if ok, _ := f.Match(1234, 80); ok {
		t.Fatal("热更新后 80 不应再命中")
	}
}

func TestSetDirectionHotUpdate(t *testing.T) {
	f := New([]uint16{80}, Both)
	f.SetDirection(Egress)
	if f.Direction() != Egress {
		t.Fatalf("Direction=%s", f.Direction())
	}
	if ok, _ := f.Match(1234, 80); ok {
		t.Fatal("egress 模式下 dst 命中应被拒")
	}
}
