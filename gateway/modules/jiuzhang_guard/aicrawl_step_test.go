package jiuzhang_guard

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jiuzhang-waf/gateway/dynamic_security/capability"
	"github.com/jiuzhang-waf/gateway/dynamic_security/httpsig"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/aicrawl"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/l7rules"
)

func genAICrawlEd25519Key(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	return priv, pemStr
}

func signAICrawlReq(t *testing.T, r *http.Request, priv ed25519.PrivateKey, kid, agent string) {
	t.Helper()
	now := time.Now().UTC()
	r.Header.Set("Signature-Agent", `"`+agent+`"`)
	sigInput := fmt.Sprintf(`sig1=("@authority" "signature-agent");created=%d;expires=%d;keyid="%s";nonce="aicrawl-n1";tag="web-bot-auth"`,
		now.Unix()-5, now.Unix()+120, kid)
	r.Header.Set("Signature-Input", sigInput)
	r.Header.Set("Signature", "sig1=:AA==:")
	p, err := httpsig.ParseWebBotAuth(r, httpsig.Budgets{})
	if err != nil {
		t.Fatalf("ParseWebBotAuth: %v", err)
	}
	base, err := httpsig.BuildWebBotAuthSignatureBase(r, p)
	if err != nil {
		t.Fatalf("BuildWebBotAuthSignatureBase: %v", err)
	}
	sig := ed25519.Sign(priv, base)
	r.Header.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(sig)+":")
}

func TestAICrawlValidateAndProvisionFailClosed(t *testing.T) {
	// Unknown field fails Validate.
	g := &Guard{
		EventsLog:     t.TempDir() + "/events.log",
		AICrawlPolicy: json.RawMessage(`{"schema_version":1,"mode":"OBSERVE","bogus":1}`),
	}
	if err := g.Validate(); err == nil {
		t.Fatal("expected unknown field in ai_crawl_policy to fail Validate")
	}

	// PROTECT + labyrinth_enabled without key fails Validate.
	g2 := &Guard{
		EventsLog:     t.TempDir() + "/events.log",
		AICrawlPolicy: json.RawMessage(`{"schema_version":1,"mode":"PROTECT","labyrinth_enabled":true}`),
	}
	if err := g2.Validate(); err == nil {
		t.Fatal("expected PROTECT + labyrinth_enabled without key to fail Validate")
	}
}

func TestAICrawlStep_ProtectActionsAndWhitelistNonBypass(t *testing.T) {
	keyHex := strings.Repeat("5a", 32)
	pol := aicrawl.Policy{
		SchemaVersion:           1,
		ApplicationID:           "app-aicrawl-1",
		Mode:                    aicrawl.ModeProtect,
		Version:                 2,
		DefaultAIAction:         aicrawl.ActionHTTP402,
		ContentSignal:           "ai-train=no, search=yes, ai-input=no",
		VerifyWebBotAuth:        true,
		LabyrinthEnabled:        true,
		LabyrinthInjectLinks:    true,
		LabyrinthMaxDepth:       3,
		LabyrinthMaxConcurrency: 16,
		LabyrinthDelayMS:        0,
		LabyrinthKeyHex:         keyHex,
		HTTP402: aicrawl.HTTP402Config{
			Message:       "Pay to crawl",
			PriceHint:     "$0.01/1k",
			ContactURL:    "https://pay.example.com",
			ReceiptHeader: "X-AI-Receipt",
		},
		Rules: []aicrawl.Rule{
			{ID: "r-block", Name: "Block Bytespider", UAPatterns: []string{"Bytespider"}, Action: aicrawl.ActionBlock, Priority: 10},
			{ID: "r-tarpit", Name: "Tarpit CCBot", UAPatterns: []string{"CCBot"}, Action: aicrawl.ActionTarpit, Priority: 20},
			{ID: "r-rl", Name: "RateLimit Perplexity", UAPatterns: []string{"PerplexityBot"}, Action: aicrawl.ActionRateLimit, RateLimitRPM: 2, Priority: 30},
		},
	}

	g := newTestGuard(t, Guard{
		AppID:              "app-aicrawl-1",
		AppCode:            "docs",
		ProtectedAddresses: []string{"198.51.100.10/32"},
		GlobalAllow:        []ruleJSON{{ID: "allow-ip", Address: "198.51.100.20/32", Priority: 1}},
		GlobalURLAllow:     []urlAllowRuleJSON{{ID: "allow-url", MatchType: "PREFIX", URIPattern: "/public", Priority: 1}},
		L7Rules: &l7rules.Config{
			Rules: []l7rules.RuleJSON{{
				ID:       "l7-allow",
				Name:     "L7 Allow",
				Enabled:  true,
				Priority: 1,
				Action:   "allow",
				Conditions: []l7rules.ConditionJSON{{
					Type:  "uri",
					Op:    "prefix",
					Value: "/l7open",
				}},
			}},
		},
		AICrawlPolicy: mustJSON(t, pol),
	})
	if err := g.assembleAICrawl(); err != nil {
		t.Fatalf("assembleAICrawl: %v", err)
	}

	// 1. White-list / ProtectedAddress / URL allow / L7 allow MUST NOT bypass HTTP_402.
	bypassCases := []struct {
		name string
		ip   string
		path string
	}{
		{"protected_address", "198.51.100.10:1234", "/article"},
		{"ip_allowlist", "198.51.100.20:1234", "/article"},
		{"url_allowlist", "203.0.113.5:1234", "/public/article"},
		{"l7_allow", "203.0.113.6:1234", "/l7open/article"},
	}
	for _, tc := range bypassCases {
		t.Run("non_bypass_"+tc.name, func(t *testing.T) {
			called := false
			r := httptest.NewRequest(http.MethodGet, "https://example.com"+tc.path, nil)
			r.RemoteAddr = tc.ip
			r.Header.Set("User-Agent", "GPTBot/1.2")
			r.Header.Set("Accept", "application/json")
			rec := httptest.NewRecorder()
			if err := g.ServeHTTP(rec, r, nextHandler{&called}); err != nil {
				t.Fatalf("ServeHTTP err: %v", err)
			}
			if called {
				t.Fatalf("%s bypassed AI crawl HTTP_402!", tc.name)
			}
			if rec.Code != http.StatusPaymentRequired {
				t.Fatalf("%s status = %d, want 402", tc.name, rec.Code)
			}
			if rec.Header().Get(aicrawl.ContentSignalHeader) != pol.ContentSignal {
				t.Fatalf("Content-Signal missing: %q", rec.Header().Get(aicrawl.ContentSignalHeader))
			}
		})
	}

	// 2. BLOCK rule -> 403.
	{
		called := false
		r := httptest.NewRequest(http.MethodGet, "https://example.com/blog", nil)
		r.RemoteAddr = "203.0.113.7:1234"
		r.Header.Set("User-Agent", "Bytespider/1.0")
		rec := httptest.NewRecorder()
		if err := g.ServeHTTP(rec, r, nextHandler{&called}); err != nil {
			t.Fatal(err)
		}
		if called || rec.Code != http.StatusForbidden {
			t.Fatalf("Bytespider expected 403 without next, got code=%d called=%v", rec.Code, called)
		}
	}

	// 3. TARPIT rule -> depth-0 decoy page + follow signed link into /_wdsp/labyrinth/v1/ (NEVER proxied) -> AI_CRAWL_TRAP_HIT.
	{
		called := false
		r := httptest.NewRequest(http.MethodGet, "https://example.com/blog", nil)
		r.RemoteAddr = "203.0.113.8:1234"
		r.Header.Set("User-Agent", "CCBot/2.0")
		rec := httptest.NewRecorder()
		if err := g.ServeHTTP(rec, r, nextHandler{&called}); err != nil {
			t.Fatal(err)
		}
		if called || rec.Code != http.StatusOK {
			t.Fatalf("CCBot TARPIT expected local 200 decoy, got code=%d called=%v", rec.Code, called)
		}
		re := regexp.MustCompile(`href="(/_wdsp/labyrinth/v1/p/[^"]+)"`)
		m := re.FindStringSubmatch(rec.Body.String())
		if m == nil {
			t.Fatalf("TARPIT decoy missing signed labyrinth link: %s", rec.Body.String())
		}

		// Follow signed link into reserved namespace.
		trapCalled := false
		rTrap := httptest.NewRequest(http.MethodGet, "https://example.com"+m[1], nil)
		rTrap.RemoteAddr = "198.51.100.20:5555" // even allowlisted IP cannot proxy labyrinth!
		recTrap := httptest.NewRecorder()
		if err := g.ServeHTTP(recTrap, rTrap, nextHandler{&trapCalled}); err != nil {
			t.Fatal(err)
		}
		if trapCalled || recTrap.Code != http.StatusOK {
			t.Fatalf("labyrinth hit expected local 200 without next, got code=%d called=%v", recTrap.Code, trapCalled)
		}

		// Invalid labyrinth path returns local 404 (never proxied) and still emits AI_CRAWL_TRAP_HIT.
		badCalled := false
		rBad := httptest.NewRequest(http.MethodGet, "https://example.com/_wdsp/labyrinth/v1/bogus", nil)
		rBad.RemoteAddr = "203.0.113.8:5555"
		recBad := httptest.NewRecorder()
		if err := g.ServeHTTP(recBad, rBad, nextHandler{&badCalled}); err != nil {
			t.Fatal(err)
		}
		if badCalled || recBad.Code != http.StatusNotFound {
			t.Fatalf("bad labyrinth path expected local 404, got code=%d called=%v", recBad.Code, badCalled)
		}
	}

	// 4. RATE_LIMIT rule -> first 2 pass, 3rd returns 429.
	for i := 1; i <= 3; i++ {
		called := false
		r := httptest.NewRequest(http.MethodGet, "https://example.com/news", nil)
		r.RemoteAddr = "203.0.113.9:1234"
		r.Header.Set("User-Agent", "PerplexityBot/1.0")
		rec := httptest.NewRecorder()
		if err := g.ServeHTTP(rec, r, nextHandler{&called}); err != nil {
			t.Fatal(err)
		}
		if i <= 2 && (!called || rec.Code != http.StatusOK) {
			t.Fatalf("req %d expected pass, got code=%d called=%v", i, rec.Code, called)
		}
		if i == 3 && (called || rec.Code != http.StatusTooManyRequests) {
			t.Fatalf("req 3 expected 429 without next, got code=%d called=%v", rec.Code, called)
		}
	}

	// 5. Normal browser passes through with Content-Signal header and NO injected trap link.
	{
		htmlNext := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body><p>Welcome human</p></body></html>"))
			return nil
		})
		r := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
		r.RemoteAddr = "203.0.113.10:1234"
		r.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36")
		rec := httptest.NewRecorder()
		if err := g.ServeHTTP(rec, r, htmlNext); err != nil {
			t.Fatal(err)
		}
		if rec.Code != http.StatusOK || rec.Header().Get(aicrawl.ContentSignalHeader) != pol.ContentSignal {
			t.Fatalf("human browser response mismatch: code=%d header=%q", rec.Code, rec.Header().Get(aicrawl.ContentSignalHeader))
		}
		if strings.Contains(rec.Body.String(), aicrawl.LabyrinthReservedNamespace) {
			t.Fatalf("human browser must not receive trap link: %s", rec.Body.String())
		}
	}

	// Verify AI_CRAWL_TRAP_HIT and AI_CRAWL_ACTION events were emitted.
	evs := g.readEvents(t)
	trapHits, actionHits := 0, 0
	for _, e := range evs {
		if e.EventType == events.AICrawlTrapHit {
			trapHits++
		}
		if e.EventType == events.AICrawlAction {
			actionHits++
		}
	}
	if trapHits < 2 {
		t.Fatalf("expected >=2 AI_CRAWL_TRAP_HIT events, got %d", trapHits)
	}
	if actionHits < 4 {
		t.Fatalf("expected >=4 AI_CRAWL_ACTION events, got %d", actionHits)
	}
}

func TestAICrawlStep_ObserveModeAndTrapLinkInjection(t *testing.T) {
	pol := aicrawl.Policy{
		SchemaVersion:        1,
		ApplicationID:        "app-obs",
		Mode:                 aicrawl.ModeObserve,
		Version:              1,
		DefaultAIAction:      aicrawl.ActionBlock,
		ContentSignal:        "ai-train=no",
		VerifyWebBotAuth:     true,
		LabyrinthEnabled:     true,
		LabyrinthInjectLinks: true,
		LabyrinthMaxDepth:    2,
		LabyrinthDelayMS:     0,
		// OBSERVE mode allows empty labyrinth_key_hex (ephemeral key auto-generated).
	}
	g := newTestGuard(t, Guard{
		AppID:         "app-obs",
		AICrawlPolicy: mustJSON(t, pol),
	})
	if err := g.assembleAICrawl(); err != nil {
		t.Fatalf("assembleAICrawl: %v", err)
	}

	htmlNext := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body><h1>Article</h1></body></html>"))
		return nil
	})
	r := httptest.NewRequest(http.MethodGet, "https://example.com/post", nil)
	r.RemoteAddr = "203.0.113.20:1234"
	r.Header.Set("User-Agent", "GPTBot/1.2")
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, r, htmlNext); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("OBSERVE mode must not block, got status %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `aria-hidden="true"`) || !strings.Contains(body, `display:none`) || !strings.Contains(body, aicrawl.LabyrinthReservedNamespace) {
		t.Fatalf("expected invisible trap link injected for unverified bot HTML GET, got: %s", body)
	}

	evs := g.readEvents(t)
	foundObs := false
	for _, e := range evs {
		if e.EventType == events.AICrawlObserved && e.AICrawl != nil && e.AICrawl.Action == aicrawl.ActionBlock {
			foundObs = true
		}
	}
	if !foundObs {
		t.Fatalf("expected AI_CRAWL_OBSERVED event, got %+v", evs)
	}
}

func TestAICrawlStep_VerifiedExemptBotChallengeOnlyStillRunsJWTProtect(t *testing.T) {
	priv, pubPEM := genAICrawlEd25519Key(t)
	g, _ := newBotStepGuard(t, Guard{
		AppID:        "app-exempt",
		AppCode:      "shop",
		IdentitySalt: "salt-for-jwt-protect-tests-0123456789",
	})

	// Seed behavior so Bot JS challenge would fire for curl/8.1 on /shop.
	seedBotBehavior(t, g, "203.0.113.30:4000", "https://example.com/shop", 3)

	// Enable Bot PROTECT on /shop.
	botPol := &botPolicyJSON{
		SchemaVersion: 1,
		ApplicationID: "app-exempt",
		Mode:          botModeProtect,
		Version:       1,
		Selectors:     []botSelectorJSON{{PathPrefix: "/shop"}},
		SignalRules: botSignalRulesJSON{
			MinIndependentGroups: 2,
			RequireBehaviorGroup: true,
			Rules: []botSignalRuleJSON{
				{ID: "r_ua", Group: "client_claim", Metric: "ua_class_match", Params: map[string]string{"class": "BOT"}, WindowSeconds: 60, Weight: 1, Threshold: 0},
				{ID: "r_uri", Group: "request_behavior", Metric: "uri_concentration", WindowSeconds: 60, Weight: 1, Threshold: 0.5},
			},
		},
		Challenge: botChallengeJSON{
			Type:                "JS",
			NonceTTLSeconds:     90,
			ClearanceTTLSeconds: 900,
			Difficulty:          10,
			MaxAttempts:         3,
			KeyRef:              "k-bot-1",
		},
		RouteReservation: botRouteReservationJSON{State: botReservationEnabled, Namespace: botReservedNamespace},
		SigningKeys:      map[string]string{"k-bot-1": strings.Repeat("aa", 32)},
	}
	assembleBotStep(t, g, botPol)

	// Enable AI Crawl PROTECT with verified search crawler exempt_bot_challenge=true.
	aiPol := aicrawl.Policy{
		SchemaVersion:    1,
		ApplicationID:    "app-exempt",
		Mode:             aicrawl.ModeProtect,
		Version:          1,
		DefaultAIAction:  aicrawl.ActionAllow,
		VerifyWebBotAuth: true,
		Rules: []aicrawl.Rule{
			{
				ID:                 "r-verified-exempt",
				Name:               "Verified Search Exempt Bot",
				AgentID:            "trusted-bot",
				RequireVerifiedSig: true,
				Action:             aicrawl.ActionAllow,
				ExemptBotChallenge: true,
				Priority:           1,
			},
		},
		Directories: []aicrawl.DirectorySpec{
			{
				ID:             "dir-trusted",
				Slug:           "trusted-bot",
				Name:           "Trusted Bot",
				Category:       aicrawl.CategorySearchEngine,
				SignatureAgent: "https://trusted.bot.example",
				Keys:           []aicrawl.KeySpec{{Kid: "tb-1", Alg: httpsig.AlgEd25519, PublicKeyPEM: pubPEM}},
			},
		},
	}
	g.AICrawlPolicy = mustJSON(t, aiPol)
	if err := g.assembleAICrawl(); err != nil {
		t.Fatalf("assembleAICrawl: %v", err)
	}

	// 1. Unverified request hits Bot JS challenge (403).
	calledUnv := false
	recUnv := httptest.NewRecorder()
	if err := g.ServeHTTP(recUnv, botStepReq("203.0.113.30:4001", "https://example.com/shop", botBrowserHeaders()), nextHandler{&calledUnv}); err != nil {
		t.Fatal(err)
	}
	if calledUnv || recUnv.Code != http.StatusForbidden {
		t.Fatalf("unverified bot must hit Bot JS challenge 403, got code=%d called=%v", recUnv.Code, calledUnv)
	}

	// 2. Verified Web Bot Auth with exempt_bot_challenge=true skips Bot JS challenge and reaches next!
	calledVer := false
	rVer := botStepReq("203.0.113.30:4002", "https://example.com/shop", botBrowserHeaders())
	signAICrawlReq(t, rVer, priv, "tb-1", "https://trusted.bot.example")
	recVer := httptest.NewRecorder()
	if err := g.ServeHTTP(recVer, rVer, nextHandler{&calledVer}); err != nil {
		t.Fatal(err)
	}
	if !calledVer || recVer.Code != http.StatusOK {
		t.Fatalf("verified exempt bot must skip Bot JS challenge and reach next, got code=%d called=%v", recVer.Code, calledVer)
	}

	// 3. Now attach JWT PROTECT on /shop/private: verified exempt bot skips Bot JS challenge
	//    but MUST STILL be enforced (401) by JWT PROTECT!
	jwtEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	xBuf, yBuf := make([]byte, 32), make([]byte, 32)
	jwtEC.PublicKey.X.FillBytes(xBuf)
	jwtEC.PublicKey.Y.FillBytes(yBuf)
	g.JWTTrust = json.RawMessage(fmt.Sprintf(`{
		"schema_version": 1,
		"application_id": "app-exempt",
		"mode": "PROTECT",
		"version": 1,
		"selectors": [{"methods":["GET"],"path_prefix":"/shop/private","token_required":true}],
		"issuers": [{
			"issuer_config_id": "iss-1",
			"issuer": "https://idp.example",
			"audiences": ["shop"],
			"algorithms": ["ES256"],
			"clock_skew_seconds": 30,
			"key_source_type": "STATIC_JWKS",
			"jwks": {"keys":[{"kty":"EC","crv":"P-256","kid":"k1","use":"sig","alg":"ES256","x":%q,"y":%q}]}
		}]
	}`, base64.RawURLEncoding.EncodeToString(xBuf), base64.RawURLEncoding.EncodeToString(yBuf)))
	if err := g.assembleJWTTrust(); err != nil {
		t.Fatalf("assembleJWTTrust: %v", err)
	}
	calledJWT := false
	rJWT := botStepReq("203.0.113.30:4003", "https://example.com/shop/private", botBrowserHeaders())
	signAICrawlReq(t, rJWT, priv, "tb-1", "https://trusted.bot.example")
	recJWT := httptest.NewRecorder()
	if err := g.ServeHTTP(recJWT, rJWT, nextHandler{&calledJWT}); err != nil {
		t.Fatal(err)
	}
	if calledJWT || recJWT.Code != http.StatusUnauthorized {
		t.Fatalf("verified exempt bot must STILL hit JWT PROTECT 401, got code=%d called=%v", recJWT.Code, calledJWT)
	}
}

func TestAICrawlStep_LabyrinthReservedNamespaceNeverProxiedEvenWhenOff(t *testing.T) {
	g := newTestGuard(t, Guard{
		AppID:     "app-off",
		EventsLog: t.TempDir() + "/events.log",
	})
	called := false
	r := httptest.NewRequest(http.MethodGet, "https://example.com/_wdsp/labyrinth/v1/p/0/0123456789abcdef/deadbeef", nil)
	r.RemoteAddr = "203.0.113.50:1234"
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, r, nextHandler{&called}); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("/_wdsp/labyrinth/v1/ MUST NEVER be reverse-proxied")
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 tombstone", rec.Code)
	}
}

func TestCapabilityManifest_Phase9ADetectorsAndActions(t *testing.T) {
	m := buildCapabilityManifest(capabilityInputs{NodeID: "gw-phase9a", GRPCUnary: true}, time.Now())
	if msg := m.Validate(); msg != "" {
		t.Fatalf("manifest invalid: %s", msg)
	}
	req := capability.Manifest{
		ContractVersion: capability.ContractVersion,
		Detectors: []capability.DetectorCap{
			{Name: "jwt.binding", Version: "jwtbind/1"},
			{Name: "aicrawl", Version: "aicrawl/1"},
		},
		Actions: []string{"tarpit", "http_402"},
	}
	if missing := capability.CheckRequirements(req, m); len(missing) != 0 {
		t.Fatalf("Phase 9A capabilities missing from manifest: %+v", missing)
	}
}

func TestAICrawlStep_ProvisionAndCleanupLifecycle(t *testing.T) {
	t.Setenv(capDisabledEnv, "1")
	pol := aicrawl.Policy{
		SchemaVersion:   1,
		ApplicationID:   "app-lifecycle",
		Mode:            aicrawl.ModeProtect,
		Version:         1,
		DefaultAIAction: aicrawl.ActionHTTP402,
		ContentSignal:   "ai-train=no",
		LabyrinthEnabled: true,
		LabyrinthKeyHex: strings.Repeat("7c", 32),
		Directories: []aicrawl.DirectorySpec{
			{
				ID:           "dir-remote-offline",
				Slug:         "remote-bot",
				Category:     aicrawl.CategoryAIAgent,
				DirectoryURL: "https://crawler-dir.example.invalid/.well-known/http-message-signatures-directory",
			},
		},
	}
	g := &Guard{
		AppID:          "app-lifecycle",
		AppCode:        "life",
		CounterBackend: "memory",
		EventsLog:      t.TempDir() + "/events.log",
		AICrawlPolicy:  mustJSON(t, pol),
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if err := g.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}
	if g.aiCrawl == nil || g.aiCrawlCancel == nil {
		t.Fatalf("expected aiCrawl and aiCrawlCancel initialized by Provision")
	}

	called := false
	r := httptest.NewRequest(http.MethodGet, "https://example.com/doc", nil)
	r.RemoteAddr = "203.0.113.88:1234"
	r.Header.Set("User-Agent", "GPTBot/1.2")
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, r, nextHandler{&called}); err != nil {
		t.Fatal(err)
	}
	if called || rec.Code != http.StatusPaymentRequired {
		t.Fatalf("provisioned guard expected 402, got code=%d called=%v", rec.Code, called)
	}
	// Cleanup cancels background directory refresh and waits cleanly (idempotent).
	if err := g.Cleanup(); err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}
	if err := g.Cleanup(); err != nil {
		t.Fatalf("second Cleanup failed: %v", err)
	}
}
