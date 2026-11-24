package upstreams

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
