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
