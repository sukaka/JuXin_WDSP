package jiuzhang_guard

import (
	"crypto/hmac"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/l7rules"
)

const publishSmokeTestKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func newPublishSmokeTestGuard(t *testing.T, cfg Guard) *Guard {
	t.Helper()
	if cfg.AppID == "" {
		cfg.AppID = "app-1"
	}
	if cfg.AppCode == "" {
		cfg.AppCode = "shop"
	}
	if cfg.PublishSmoke == nil {
		cfg.PublishSmoke = &publishSmokeJSON{PublishID: "publish-1", KeyHex: publishSmokeTestKeyHex}
	}
	g := newTestGuard(t, cfg)
	if err := g.assemblePublishSmoke(); err != nil {
		t.Fatalf("assemble publish smoke: %v", err)
	}
	return g
}

func publishSmokeTestRequest(t *testing.T, g *Guard, timestamp int64) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "http://shop.example.com:80"+publishSmokePath, nil)
	r.RemoteAddr = "127.0.0.1:9000"
	r.Header.Set("X-Request-Id", "11111111-2222-3333-4444-555555555555")
	b := publishSmokeBinding{
		appID: g.AppID, appCode: g.AppCode, host: publishSmokeHost(r.Host),
		publishID: g.PublishSmoke.PublishID, nonce: "0123456789abcdef0123456789abcdef",
		timestamp: timestamp, probe: "REAL_IP",
	}
	r.Header.Set(publishSmokeMarkerHeader, b.probe)
	r.Header.Set(publishSmokeAppIDHeader, b.appID)
	r.Header.Set(publishSmokeAppCodeHeader, b.appCode)
	r.Header.Set(publishSmokePublishHeader, b.publishID)
	r.Header.Set(publishSmokeNonceHeader, b.nonce)
	r.Header.Set(publishSmokeTimeHeader, strconv.FormatInt(b.timestamp, 10))
	r.Header.Set(publishSmokeSigHeader, hex.EncodeToString(publishSmokeRequestSignature(g.publishSmokeKey, b)))
	return r
}

func servePublishSmokeTest(g *Guard, r *http.Request) (*httptest.ResponseRecorder, bool, error) {
	rec := httptest.NewRecorder()
	called := false
	err := g.ServeHTTP(rec, r, nextHandler{&called})
	return rec, called, err
}

func TestPublishSmokeIndependentOfBotPolicy(t *testing.T) {
	for _, tc := range []struct {
		name string
		bp   *botPolicyJSON
	}{
		{name: "nil policy"},
		{name: "off released", bp: &botPolicyJSON{Mode: botModeOff, RouteReservation: botRouteReservationJSON{State: botReservationReleased}}},
		{name: "off tombstone", bp: &botPolicyJSON{Mode: botModeOff, RouteReservation: botRouteReservationJSON{State: botReservationTombstone}}},
		{name: "observe enabled", bp: &botPolicyJSON{Mode: botModeObserve, RouteReservation: botRouteReservationJSON{State: botReservationEnabled}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newPublishSmokeTestGuard(t, Guard{})
			g.botPolicy = tc.bp
			rec, called, err := servePublishSmokeTest(g, publishSmokeTestRequest(t, g, time.Now().Unix()))
			if err != nil || called || rec.Code != http.StatusOK {
				t.Fatalf("authenticated endpoint: err=%v called=%v code=%d body=%s", err, called, rec.Code, rec.Body.String())
			}
			if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get(publishSmokeMarkerHeader) != "REAL_IP" {
				t.Fatalf("response headers = %v", rec.Header())
			}
			var body publishSmokeResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.AppID != g.AppID || body.AppCode != g.AppCode || body.Host != "shop.example.com:80" ||
				body.PublishID != "publish-1" || body.Nonce == "" || body.Timestamp == 0 {
				t.Fatalf("response binding = %+v", body)
			}
			sig, err := hex.DecodeString(body.Signature)
			if err != nil {
				t.Fatal(err)
			}
			b := publishSmokeBinding{
				appID: body.AppID, appCode: body.AppCode, host: body.Host, publishID: body.PublishID,
				nonce: body.Nonce, timestamp: body.Timestamp, probe: "REAL_IP",
			}
			if !hmac.Equal(sig, publishSmokeResponseSignature(g.publishSmokeKey, b)) {
				t.Fatal("response HMAC does not match request binding")
			}
		})
	}
}

func TestPublishSmokeRejectsInvalidBindingWithoutUpstream(t *testing.T) {
	t.Run("fixed header only", func(t *testing.T) {
		g := newPublishSmokeTestGuard(t, Guard{})
		r := httptest.NewRequest(http.MethodGet, "http://shop.example.com:80"+publishSmokePath, nil)
		r.RemoteAddr = "127.0.0.1:9000"
		r.Header.Set(publishSmokeMarkerHeader, "REAL_IP")
		rec, called, err := servePublishSmokeTest(g, r)
		if err != nil || called || rec.Code != http.StatusNotFound {
			t.Fatalf("fixed header must fail locally: err=%v called=%v code=%d", err, called, rec.Code)
		}
	})
	t.Run("bad signature", func(t *testing.T) {
		g := newPublishSmokeTestGuard(t, Guard{})
		r := publishSmokeTestRequest(t, g, time.Now().Unix())
		r.Header.Set(publishSmokeSigHeader, strings.Repeat("0", 64))
		rec, called, err := servePublishSmokeTest(g, r)
		if err != nil || called || rec.Code != http.StatusNotFound {
			t.Fatalf("bad signature must fail locally: err=%v called=%v code=%d", err, called, rec.Code)
		}
	})
	t.Run("expired", func(t *testing.T) {
		g := newPublishSmokeTestGuard(t, Guard{})
		r := publishSmokeTestRequest(t, g, time.Now().Add(-publishSmokeMaxAge-time.Second).Unix())
		rec, called, err := servePublishSmokeTest(g, r)
		if err != nil || called || rec.Code != http.StatusNotFound {
			t.Fatalf("expired probe must fail locally: err=%v called=%v code=%d", err, called, rec.Code)
		}
	})
	t.Run("wrong host", func(t *testing.T) {
		g := newPublishSmokeTestGuard(t, Guard{})
		r := publishSmokeTestRequest(t, g, time.Now().Unix())
		r.Host = "wrong.example.com:80"
		rec, called, err := servePublishSmokeTest(g, r)
		if err != nil || called || rec.Code != http.StatusNotFound {
			t.Fatalf("wrong Host must fail locally: err=%v called=%v code=%d", err, called, rec.Code)
		}
	})
	t.Run("cross site", func(t *testing.T) {
		source := newPublishSmokeTestGuard(t, Guard{})
		target := newPublishSmokeTestGuard(t, Guard{AppID: "app-2", AppCode: "other"})
		rec, called, err := servePublishSmokeTest(target, publishSmokeTestRequest(t, source, time.Now().Unix()))
		if err != nil || called || rec.Code != http.StatusNotFound {
			t.Fatalf("cross-site probe must fail locally: err=%v called=%v code=%d", err, called, rec.Code)
		}
	})
	t.Run("cross publish", func(t *testing.T) {
		source := newPublishSmokeTestGuard(t, Guard{})
		target := newPublishSmokeTestGuard(t, Guard{PublishSmoke: &publishSmokeJSON{PublishID: "publish-2", KeyHex: publishSmokeTestKeyHex}})
		rec, called, err := servePublishSmokeTest(target, publishSmokeTestRequest(t, source, time.Now().Unix()))
		if err != nil || called || rec.Code != http.StatusNotFound {
			t.Fatalf("cross-publish probe must fail locally: err=%v called=%v code=%d", err, called, rec.Code)
		}
	})
	t.Run("wrong method", func(t *testing.T) {
		g := newPublishSmokeTestGuard(t, Guard{})
		r := publishSmokeTestRequest(t, g, time.Now().Unix())
		r.Method = http.MethodPost
		rec, called, err := servePublishSmokeTest(g, r)
		if err != nil || called || rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodGet {
			t.Fatalf("wrong method must fail locally: err=%v called=%v code=%d headers=%v", err, called, rec.Code, rec.Header())
		}
	})
	t.Run("authentication not configured", func(t *testing.T) {
		g := newTestGuard(t, Guard{AppID: "app-1", AppCode: "shop"})
		r := httptest.NewRequest(http.MethodGet, "http://shop.example.com:80"+publishSmokePath, nil)
		r.RemoteAddr = "127.0.0.1:9000"
		rec, called, err := servePublishSmokeTest(g, r)
		if err != nil || called || rec.Code != http.StatusNotFound {
			t.Fatalf("unconfigured endpoint must fail locally: err=%v called=%v code=%d", err, called, rec.Code)
		}
	})
}

func TestPublishSmokeExactPathDoesNotAffectAdjacentOrLegacyBotRoute(t *testing.T) {
	g := newPublishSmokeTestGuard(t, Guard{})
	adjacent := publishSmokeTestRequest(t, g, time.Now().Unix())
	adjacent.URL.Path = publishSmokePath + "-business"
	_, called, err := servePublishSmokeTest(g, adjacent)
	if err != nil || !called {
		t.Fatalf("adjacent business path must continue downstream: err=%v called=%v", err, called)
	}

	legacy := newPublishSmokeTestGuard(t, Guard{})
	legacy.botPolicy = &botPolicyJSON{Mode: botModeOff, RouteReservation: botRouteReservationJSON{State: botReservationReleased}}
	r := httptest.NewRequest(http.MethodGet, "http://shop.example.com:80/_wdsp/bot/v1/publish-smoke", nil)
	r.RemoteAddr = "127.0.0.1:9000"
	_, called, err = servePublishSmokeTest(legacy, r)
	if err != nil || !called {
		t.Fatalf("legacy Bot path must retain RELEASED behavior: err=%v called=%v", err, called)
	}
}

func TestPublishSmokeRealIPBlacklistRunsBeforeEndpoint(t *testing.T) {
	const deniedIP = "198.51.100.77"
	g := newPublishSmokeTestGuard(t, Guard{
		TrustedProxies: []proxyJSON{{Name: "local", CIDR: "127.0.0.1/32", HeaderType: "X_FORWARDED_FOR", Priority: 1}},
		GlobalDeny:     []ruleJSON{{ID: "deny-smoke", Address: deniedIP, Priority: 1}},
	})
	r := publishSmokeTestRequest(t, g, time.Now().Unix())
	r.Header.Set("X-Forwarded-For", deniedIP)
	_, called, err := servePublishSmokeTest(g, r)
	var handlerErr caddyhttp.HandlerError
	if !errors.As(err, &handlerErr) || handlerErr.StatusCode != http.StatusForbidden || called {
		t.Fatalf("REAL_IP/blacklist must reject before authenticated response: err=%v called=%v", err, called)
	}
}

func TestPublishSmokeCCRunsBeforeEndpoint(t *testing.T) {
	g := newPublishSmokeTestGuard(t, Guard{RateLimits: []policyJSON{{
		ID: "cc-smoke", Dimension: "CLIENT_IP", Algorithm: "SLIDING_WINDOW", URIMatchType: "ALL",
		RequestsLimit: 1, WindowSeconds: 60, Action: "REJECT", Priority: 1,
	}}})
	first, called, err := servePublishSmokeTest(g, publishSmokeTestRequest(t, g, time.Now().Unix()))
	if err != nil || called || first.Code != http.StatusOK {
		t.Fatalf("first request must pass CC and authenticate: err=%v called=%v code=%d", err, called, first.Code)
	}
	second, called, err := servePublishSmokeTest(g, publishSmokeTestRequest(t, g, time.Now().Unix()))
	if err != nil || called || second.Code != http.StatusTooManyRequests {
		t.Fatalf("second request must be limited before endpoint: err=%v called=%v code=%d", err, called, second.Code)
	}
}

func TestPublishSmokeConfigValidation(t *testing.T) {
	for _, sec := range []*publishSmokeJSON{
		{PublishID: "", KeyHex: publishSmokeTestKeyHex},
		{PublishID: "publish-1", KeyHex: "not-hex"},
		{PublishID: "publish-1", KeyHex: "00"},
		{PublishID: " publish-1", KeyHex: publishSmokeTestKeyHex},
	} {
		if err := validatePublishSmokeConfig(sec); err == nil {
			t.Fatalf("invalid publish smoke config accepted: publish_id=%q key_length=%d", sec.PublishID, len(sec.KeyHex))
		}
	}
	if err := validatePublishSmokeConfig(nil); err != nil {
		t.Fatalf("nil config must remain valid: %v", err)
	}
}

func TestPublishSmokeBypassesL7HostRedirectOnlyWhenAuthenticated(t *testing.T) {
	g := newPublishSmokeTestGuard(t, Guard{
		L7Rules: &l7rules.Config{Rules: []l7rules.RuleJSON{{
			ID: "apex-redirect", Name: "裸域跳www", Priority: 1, Enabled: true,
			Conditions: []l7rules.ConditionJSON{{Type: "host", Op: "eq", Value: "shop.example.com"}},
			Action:     "redirect",
			ActionConfig: l7rules.ActionConfigJSON{
				RedirectURL: "https://www.shop.example.com", RedirectStatus: 301, PreservePathQuery: true,
			},
		}}},
	})
	// 1. 携带有效当次发布 HMAC 的冒烟探针跳过 L7 重定向，完成本地验签应答
	rec, called, err := servePublishSmokeTest(g, publishSmokeTestRequest(t, g, time.Now().Unix()))
	if err != nil || called || rec.Code != http.StatusOK {
		t.Fatalf("authenticated publish smoke must pass L7 host redirect: err=%v called=%v code=%d loc=%s",
			err, called, rec.Code, rec.Header().Get("Location"))
	}
	// 2. 未鉴权请求访问同一路径仍被 L7 正常重定向（零绕过）
	unauth := httptest.NewRequest(http.MethodGet, "http://shop.example.com:80"+publishSmokePath+"?id=1", nil)
	unauth.RemoteAddr = "127.0.0.1:9000"
	rec2, called2, err2 := servePublishSmokeTest(g, unauth)
	if err2 != nil || called2 || rec2.Code != http.StatusMovedPermanently ||
		rec2.Header().Get("Location") != "https://www.shop.example.com"+publishSmokePath+"?id=1" {
		t.Fatalf("unauthenticated request must still hit L7 redirect: err=%v called=%v code=%d loc=%s",
			err2, called2, rec2.Code, rec2.Header().Get("Location"))
	}
}
