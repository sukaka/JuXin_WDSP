// grpc_test.go gRPC 流量识别测试（W14-GW / P2-05）：
// Content-Type + 路径形态双重确认正反、服务/方法名全保留、畸形头降级。
package classifier

import (
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// 识别正反：application/grpc(+proto) + /package.Service/Method 形态命中。
func TestClassifyGRPC(t *testing.T) {
	cases := []struct {
		name    string
		ct      string
		path    string
		want    bool
		service string
		method  string
	}{
		{"proto content type", "application/grpc", "/pkg.Svc/Call", true, "pkg.Svc", "Call"},
		{"proto suffix", "application/grpc+proto", "/grpc.health.v1.Health/Check", true, "grpc.health.v1.Health", "Check"},
		{"with charset", "application/grpc; charset=utf-8", "/a.B/C", true, "a.B", "C"},
		{"uppercase media", "Application/GRPC", "/a.B/C", true, "a.B", "C"},
		{"service without package", "application/grpc", "/Greeter/SayHello", true, "Greeter", "SayHello"},
		{"json content type", "application/json", "/pkg.Svc/Call", false, "", ""},
		{"grpc-web excluded", "application/grpc-web", "/pkg.Svc/Call", false, "", ""},
		{"grpc-web+proto excluded", "application/grpc-web+proto", "/pkg.Svc/Call", false, "", ""},
		{"empty content type", "", "/pkg.Svc/Call", false, "", ""},
		{"one segment", "application/grpc", "/pkg.Svc", false, "", ""},
		{"three segments", "application/grpc", "/pkg.Svc/Call/Extra", false, "", ""},
		{"empty method", "application/grpc", "/pkg.Svc/", false, "", ""},
		{"empty service", "application/grpc", "//Call", false, "", ""},
		{"no leading slash", "application/grpc", "pkg.Svc/Call", false, "", ""},
		{"bad chars space", "application/grpc", "/pkg.Svc/Call Now", false, "", ""},
		{"bad chars percent", "application/grpc", "/pkg.Svc/%2e%2e", false, "", ""},
		{"bad chars non-ascii", "application/grpc", "/pkg.Svc/方法", false, "", ""},
		{"malformed content type fallback", "application/grpc;;;", "/pkg.Svc/Call", true, "pkg.Svc", "Call"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &parser.Parsed{ContentType: tc.ct, RawPath: tc.path}
			got := ClassifyGRPC(p)
			if got.IsGRPC != tc.want {
				t.Fatalf("IsGRPC = %v, want %v", got.IsGRPC, tc.want)
			}
			if got.Service != tc.service || got.Method != tc.method {
				t.Fatalf("service/method = %q/%q, want %q/%q", got.Service, got.Method, tc.service, tc.method)
			}
		})
	}
	// nil Parsed 不判
	if got := ClassifyGRPC(nil); got.IsGRPC {
		t.Fatal("nil parsed must not classify")
	}
}
