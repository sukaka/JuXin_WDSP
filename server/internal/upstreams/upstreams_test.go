package upstreams

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
)

func TestC06SSRFBlocksMappedIPv6MetadataAndLoopback(t *testing.T) {
	blockedHosts := []string{
		"::ffff:169.254.169.254",
		"::ffff:127.0.0.1",
		"::ffff:10.0.0.1",
		"fd00:ec2::254",
		"169.254.170.2",
		"100.100.100.200",
		"127.0.0.1",
		"::1",
		"10.0.0.1",
	}
	for _, host := range blockedHosts {
		res := TestConnectivity(context.Background(), TestInput{
			Scheme: "http",
			Host:   host,
			Port:   80,
		})
		if res.ErrorCode != "SSRF_BLOCKED" {
			t.Errorf("TestConnectivity(%q, allowPrivate=false) error_code=%q, want SSRF_BLOCKED", host, res.ErrorCode)
		}
	}

	// 即使服务端开启 AllowPrivate，元数据与回环也必须始终拒绝
	alwaysDenied := []string{
		"::ffff:169.254.169.254",
		"::ffff:127.0.0.1",
		"fd00:ec2::254",
		"169.254.170.2",
		"100.100.100.200",
		"127.0.0.1",
		"::1",
	}
	for _, host := range alwaysDenied {
		res := TestConnectivity(context.Background(), TestInput{
			Scheme:       "http",
			Host:         host,
			Port:         80,
			AllowPrivate: true,
		})
		if res.ErrorCode != "SSRF_BLOCKED" {
			t.Errorf("TestConnectivity(%q, allowPrivate=true) error_code=%q, want SSRF_BLOCKED", host, res.ErrorCode)
		}
	}
}

func TestC06HandlerIgnoresClientAllowPrivate(t *testing.T) {
	h := NewTestHandler(nil) // 默认 allowPrivate = false
	for _, host := range []string{
		"10.0.0.1",
		"::ffff:10.0.0.1",
		"::ffff:127.0.0.1",
		"::ffff:169.254.169.254",
		"fd00:ec2::254",
		"169.254.170.2",
	} {
		body := `{"scheme":"http","host":"` + host + `","port":80,"allow_private":true}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/upstreams/test", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(authz.WithPrincipal(req.Context(), &authz.Principal{
			UserID:   uuid.New(),
			Username: "tester",
		}))
		rr := httptest.NewRecorder()
		h.Test(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("host %q status=%d body=%s", host, rr.Code, rr.Body.String())
		}
		var env struct {
			Data TestResult `json:"data"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
			t.Fatalf("decode response for %q: %v", host, err)
		}
		if env.Data.ErrorCode != "SSRF_BLOCKED" {
			t.Errorf("client allow_private=true bypassed SSRF for %q: %+v", host, env.Data)
		}
	}
}

func TestCheckExpectedStatus(t *testing.T) {
	cases := []struct {
		name     string
		actual   int
		expected string
		want     bool
	}{
		{"空期望默认200匹配", 200, "", true},
		{"空期望默认200不匹配", 204, "", false},
		{"单状态码匹配", 301, "200,301", true},
		{"通配2xx匹配", 204, "2xx", true},
		{"通配大写2XX匹配", 201, "2XX", true},
		{"通配不匹配", 404, "2xx", false},
		{"范围匹配下界", 200, "200-299", true},
		{"范围匹配中间", 204, "200-299", true},
		{"范围匹配上界", 299, "200-299", true},
		{"范围不匹配下界外", 199, "200-299", false},
		{"范围不匹配上界外", 300, "200-299", false},
		{"混合规则匹配", 301, "200-204, 301, 4xx", true},
		{"倒置范围拒绝", 250, "300-200", false},
		{"非法范围拒绝", 200, "200-abc", false},
		{"实际状态码0拒绝", 0, "200-299", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CheckExpectedStatus(tc.actual, tc.expected); got != tc.want {
				t.Errorf("CheckExpectedStatus(%d, %q) = %v, want %v", tc.actual, tc.expected, got, tc.want)
			}
		})
	}
}

func TestInvalidMethodRejected(t *testing.T) {
	for _, method := range []string{"POST", "DELETE", "PUT", "TRACE"} {
		res := TestConnectivity(context.Background(), TestInput{
			Scheme: "http",
			Host:   "93.184.216.34",
			Port:   80,
			Method: method,
		})
		if res.ErrorCode != "INVALID_METHOD" {
			t.Errorf("method %q error_code=%q, want INVALID_METHOD", method, res.ErrorCode)
		}
	}
}

func TestAllowedPrivateCIDRsPrecisionAndHardDeny(t *testing.T) {
	cidrs := ParseAllowedPrivateCIDRs("172.30.0.0/16, 100.64.0.0/10, fc00::/7")
	if len(cidrs) != 3 {
		t.Fatalf("parsed cidrs = %v, want 3", cidrs)
	}

	// 白名单内私网地址通过策略校验
	for _, ip := range []string{"172.30.128.202", "100.64.1.10", "fd12:3456::1"} {
		if err := checkUpstreamAddrPolicy(netip.MustParseAddr(ip), false, cidrs); err != nil {
			t.Errorf("expected %s to be allowed by CIDR whitelist, got err=%v", ip, err)
		}
	}

	// 非白名单私网地址仍被拦截
	for _, ip := range []string{"10.0.0.1", "172.31.0.1", "192.168.1.1"} {
		if err := checkUpstreamAddrPolicy(netip.MustParseAddr(ip), false, cidrs); err == nil {
			t.Errorf("expected non-whitelisted private ip %s to be denied", ip)
		}
	}

	// 即使强行传入全网/高危前缀，回环、链路本地与云元数据仍始终硬拒绝
	unsafePrefixes := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("fc00::/7"),
	}
	for _, ip := range []string{
		"127.0.0.1", "::1", "::ffff:127.0.0.1",
		"169.254.169.254", "::ffff:169.254.169.254",
		"169.254.170.2", "100.100.100.200", "fd00:ec2::254",
		"fe80::1", "0.0.0.0", "224.0.0.1",
	} {
		if err := checkUpstreamAddrPolicy(netip.MustParseAddr(ip), true, unsafePrefixes); err == nil {
			t.Errorf("expected hard-denied addr %s to stay blocked", ip)
		}
	}

	// ParseAllowedPrivateCIDRs 自动剔除非法、全网与高危重叠网段
	filtered := ParseAllowedPrivateCIDRs("0.0.0.0/0, 127.0.0.0/8, 169.254.169.254/32, 172.30.128.0/24, bad")
	if len(filtered) != 1 || filtered[0].String() != "172.30.128.0/24" {
		t.Fatalf("filtered cidrs = %v, want [172.30.128.0/24]", filtered)
	}
}

func TestHandlerDynamicPrivatePolicyAndClientIsolation(t *testing.T) {
	allowDyn := false
	cidrsDyn := []netip.Prefix{netip.MustParsePrefix("172.30.0.0/16")}

	h := NewTestHandler(nil).SetPolicyLookup(func(ctx context.Context) PrivatePolicy {
		return PrivatePolicy{
			AllowPrivate:        allowDyn,
			AllowedPrivateCIDRs: cidrsDyn,
		}
	})

	callTest := func(host string, clientAllowPrivate bool) TestResult {
		t.Helper()
		// 极短超时确保即使放行进入拨号也快速结束，无需依赖真实内网可达
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		body := `{"scheme":"https","host":"` + host + `","port":443,"allow_private":false}`
		if clientAllowPrivate {
			body = `{"scheme":"https","host":"` + host + `","port":443,"allow_private":true}`
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/upstreams/test", strings.NewReader(body)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(authz.WithPrincipal(req.Context(), &authz.Principal{
			UserID:   uuid.New(),
			Username: "tester",
		}))
		rr := httptest.NewRecorder()
		h.Test(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("host %q status=%d body=%s", host, rr.Code, rr.Body.String())
		}
		var env struct {
			Data TestResult `json:"data"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return env.Data
	}

	// 1. 命中动态白名单的 172.30.128.202 通过 SSRF/DNS 阶段（不再报 SSRF_BLOCKED）
	resAllowed := callTest("172.30.128.202", false)
	if resAllowed.ErrorCode == "SSRF_BLOCKED" || resAllowed.DNSResult != "ok" {
		t.Fatalf("whitelisted private host 172.30.128.202 should pass SSRF: %+v", resAllowed)
	}

	// 2. 不在白名单的 10.0.0.1 即使客户端传 allow_private=true 仍报 SSRF_BLOCKED
	resDenied := callTest("10.0.0.1", true)
	if resDenied.ErrorCode != "SSRF_BLOCKED" {
		t.Fatalf("non-whitelisted 10.0.0.1 should be SSRF_BLOCKED: %+v", resDenied)
	}

	// 3. 动态开启 allow_private=true 后，10.0.0.1 通过 SSRF 阶段，但 127.0.0.1 与 169.254.169.254 仍硬拦截
	allowDyn = true
	resAllowAll := callTest("10.0.0.1", false)
	if resAllowAll.ErrorCode == "SSRF_BLOCKED" || resAllowAll.DNSResult != "ok" {
		t.Fatalf("10.0.0.1 should pass SSRF when dynamic allow_private=true: %+v", resAllowAll)
	}
	for _, hardDenied := range []string{"127.0.0.1", "169.254.169.254", "100.100.100.200"} {
		res := callTest(hardDenied, true)
		if res.ErrorCode != "SSRF_BLOCKED" {
			t.Fatalf("hard-denied %s must stay SSRF_BLOCKED even when allow_private=true: %+v", hardDenied, res)
		}
	}
}
