package jiuzhang_guard

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/apievents"
	"go.uber.org/zap"
)

type authzCrossModuleContract struct {
	AppID            string                       `json:"app_id"`
	GuardConfig      json.RawMessage              `json:"guard_config"`
	CandidateHandoff authzCandidatePublishHandoff `json:"candidate_handoff"`
	ObjectID         string                       `json:"object_id"`
	AdminPath        string                       `json:"admin_path"`
	EventsLog        string                       `json:"events_log"`
	APIEventsLog     string                       `json:"api_events_log"`
}

type authzCandidatePublishHandoff struct {
	ApplicationID        string                   `json:"application_id"`
	ObjectID             string                   `json:"object_id"`
	CandidateID          string                   `json:"candidate_id"`
	CandidateStatus      string                   `json:"candidate_status"`
	ConfirmedRelation    detectors.ObjectRelation `json:"confirmed_relation"`
	PublishCallbackCount int                      `json:"publish_callback_count"`
	PublishRequestID     string                   `json:"publish_request_id"`
	PublishUserID        string                   `json:"publish_user_id"`
}

// authzPipeListener lets the test run a real net/http.Server without binding
// an OS socket, which is unavailable in the isolated test environment.
type authzPipeListener struct {
	conns     chan net.Conn
	done      chan struct{}
	closeOnce sync.Once
}

type authzPipeAddr struct{}

func (authzPipeAddr) Network() string { return "authz-pipe" }
func (authzPipeAddr) String() string  { return "authz-pipe" }

func newAuthzPipeListener() *authzPipeListener {
	return &authzPipeListener{conns: make(chan net.Conn), done: make(chan struct{})}
}

func (l *authzPipeListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *authzPipeListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return nil
}

func (l *authzPipeListener) Addr() net.Addr { return authzPipeAddr{} }

func (l *authzPipeListener) dial(ctx context.Context) (net.Conn, error) {
	clientConn, serverConn := net.Pipe()
	select {
	case l.conns <- serverConn:
		return clientConn, nil
	case <-l.done:
		_ = clientConn.Close()
		_ = serverConn.Close()
		return nil, net.ErrClosed
	case <-ctx.Done():
		_ = clientConn.Close()
		_ = serverConn.Close()
		return nil, ctx.Err()
	}
}

func TestConsumeAuthzCrossModuleContract(t *testing.T) {
	in := os.Getenv("AUTHZ_CONTRACT_INPUT")
	if in == "" {
		t.Skip("AUTHZ_CONTRACT_INPUT is required")
	}
	data, err := os.ReadFile(in)
	if err != nil {
		t.Fatal(err)
	}
	var contract authzCrossModuleContract
	if err := json.Unmarshal(data, &contract); err != nil {
		t.Fatalf("decode contract: %v", err)
	}
	handoff := contract.CandidateHandoff
	if handoff.ApplicationID != contract.AppID || handoff.ObjectID != contract.ObjectID ||
		handoff.CandidateID == "" || handoff.CandidateStatus != "CONFIRMED" ||
		handoff.ConfirmedRelation.ApplicationID != contract.AppID ||
		handoff.ConfirmedRelation.Status != "CONFIRMED" || handoff.ConfirmedRelation.Relation != "OWNER" ||
		handoff.ConfirmedRelation.PrincipalID != "user-owner" || handoff.PublishCallbackCount != 1 ||
		handoff.PublishRequestID != "test-rid" || handoff.PublishUserID == "" {
		t.Fatalf("published contract lost candidate confirmation: %+v", handoff)
	}
	var g Guard
	if err := json.Unmarshal(contract.GuardConfig, &g); err != nil {
		t.Fatalf("decode guard config: %v", err)
	}
	g.AppID = contract.AppID
	resetSharedEngineForTest()
	t.Cleanup(resetSharedEngineForTest)
	if err := g.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	t.Cleanup(func() { _ = g.Cleanup() })
	if g.apiAuthzPreviousValid == nil || len(g.apiAuthzPreviousValid.ObjectRefHMACKey) != 32 {
		t.Fatal("Provision did not decode PreviousValid HMAC key")
	}

	originCalls := 0
	next := nextFunc(func(w http.ResponseWriter, _ *http.Request) error {
		originCalls++
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "origin-ok")
		return nil
	})
	key := g.APIAuthzObjectHMACKey
	if handoff.ConfirmedRelation.ObjectRef != detectors.ObjectRefHMAC(key, handoff.ObjectID) {
		t.Fatalf("published candidate object ref does not match Guard runtime HMAC: got=%q", handoff.ConfirmedRelation.ObjectRef)
	}
	var loadedRelation bool
	for _, relation := range g.APIAuthzRelations {
		if relation.ApplicationID == handoff.ConfirmedRelation.ApplicationID &&
			relation.PrincipalID == handoff.ConfirmedRelation.PrincipalID &&
			relation.ObjectRef == handoff.ConfirmedRelation.ObjectRef &&
			relation.Relation == handoff.ConfirmedRelation.Relation && relation.Status == "CONFIRMED" {
			loadedRelation = true
			break
		}
	}
	if !loadedRelation {
		t.Fatalf("Guard snapshot did not load confirmed candidate relation: %+v", g.APIAuthzRelations)
	}
	// Run a real HTTP server over a net.Conn boundary so the contract is
	// exercised at the same client/server boundary used by a local gateway
	// deployment. The JWT verification result is injected at the request-context
	// boundary used by the upstream trust module.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal := r.Header.Get("X-Test-Principal")
		jwt := jwtverify.VerificationResult{
			Status:              jwtverify.StatusVerified,
			VerifiedPrincipalID: principal,
			PolicyVersion:       "current-policy",
		}
		if principal == "user-support" {
			jwt.VerifiedRoles = []string{"support"}
		}
		*r = *r.WithContext(context.WithValue(r.Context(), jwtResultKey{}, jwt))
		if err := g.serveNext(w, r, next); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	var listener net.Listener
	var dialContext func(context.Context) (net.Conn, error)
	if os.Getenv("AUTHZ_GATEWAY_REAL_HTTP") == "1" {
		osListener, listenErr := net.Listen("tcp", "127.0.0.1:0")
		if listenErr != nil {
			t.Fatalf("listen real gateway HTTP endpoint: %v", listenErr)
		}
		listener = osListener
		dialContext = func(ctx context.Context) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "tcp", osListener.Addr().String())
		}
	} else {
		pipeListener := newAuthzPipeListener()
		listener = pipeListener
		dialContext = pipeListener.dial
	}
	server := &http.Server{Handler: handler}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		_ = listener.Close()
		select {
		case err := <-serveErr:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("gateway HTTP server: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("gateway HTTP server did not stop")
		}
	})
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialContext(ctx)
	}}
	client := &http.Client{Transport: transport}
	t.Cleanup(transport.CloseIdleConnections)

	doRequest := func(path, requestID, principal string) {
		req, err := http.NewRequest(http.MethodGet, "http://gateway.test"+path, nil)
		if err != nil {
			t.Fatalf("build %s request: %v", principal, err)
		}
		req.Header.Set("X-Request-Id", requestID)
		req.Header.Set("X-Test-Principal", principal)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s request: %v", principal, err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read %s response: %v", principal, err)
		}
		if resp.StatusCode != http.StatusOK || string(body) != "origin-ok" {
			t.Fatalf("%s request must reach origin: status=%d body=%q", principal, resp.StatusCode, body)
		}
	}
	doRequest("/v1/orders/"+contract.ObjectID, "cross-module-owner", "user-owner")
	doRequest("/v1/orders/"+contract.ObjectID, "cross-module-bola", "user-other")
	doRequest(contract.AdminPath, "cross-module-bfla", "user-support")
	if originCalls != 3 {
		t.Fatalf("owner, BOLA OBSERVE, and BFLA requests must all reach origin: calls=%d", originCalls)
	}

	recs := readAPIRecords(t, contract.APIEventsLog)
	if len(recs) != 3 {
		t.Fatalf("want owner, BOLA, and BFLA API events, got %d", len(recs))
	}
	owner, bola, bfla := recs[0].AuthzDecision, recs[1].AuthzDecision, recs[2].AuthzDecision
	if owner == nil || len(owner.Checks) < 2 {
		t.Fatalf("unexpected owner authorization decision: %+v", owner)
	}
	var foundOwner bool
	for _, check := range owner.Checks {
		if check.Type == "BOLA" && check.Decision == detectors.AuthorizationAllow && check.RelationState == "EFFECTIVE_OWNER" {
			foundOwner = true
		}
	}
	if !foundOwner {
		t.Fatalf("owner ALLOW check missing: %+v", owner.Checks)
	}
	if bola == nil || bola.Decision != detectors.AuthorizationObserveViolation || len(bola.Checks) < 2 {
		t.Fatalf("unexpected fallback BOLA decision: %+v", bola)
	}
	var foundBOLA bool
	for _, check := range bola.Checks {
		if check.Type == "BOLA" && check.ReasonCode == "AUTHZ-BOLA-001" {
			foundBOLA = true
			if check.ObjectRef != detectors.ObjectRefHMAC(key, contract.ObjectID) {
				t.Fatalf("BOLA ref mismatch: %+v", check)
			}
			encoded, _ := json.Marshal(check)
			if strings.Contains(string(encoded), contract.ObjectID) {
				t.Fatal("BOLA event retained raw object id")
			}
		}
	}
	if !foundBOLA {
		t.Fatalf("BOLA fallback check missing: %+v", bola.Checks)
	}
	if bfla == nil || len(bfla.Checks) < 2 {
		t.Fatalf("unexpected BFLA decision: %+v", bfla)
	}
	var foundBFLA bool
	for _, check := range bfla.Checks {
		if check.Type == "BFLA" && check.Decision == detectors.AuthorizationAllow && check.RoleSource == "VERIFIED" {
			foundBFLA = true
		}
	}
	if !foundBFLA {
		t.Fatalf("BFLA fallback allow check missing: %+v", bfla.Checks)
	}
}

// TestTransientPublishRetryLoadsSameSnapshotIntoGuardAndDecides exercises the
// real JSON hand-off boundary used by the publisher: a transient /load failure
// is retried with the byte-identical snapshot, then the received payload is
// provisioned by Guard and used by the API decision path.  The server module's
// Provider is intentionally outside this Go module; its publisher retry and
// node bookkeeping are covered by server/internal/gatewayconfig tests, while
// this test proves the shared HTTP/JSON contract through a live Guard.
func TestTransientPublishRetryLoadsSameSnapshotIntoGuardAndDecides(t *testing.T) {
	currentKey := []byte("01234567890123456789012345678901")
	previousKey := []byte("12345678901234567890123456789012")
	rawObjectID := "order-retry-contract-1"
	previousRef := detectors.ObjectRefHMAC(previousKey, rawObjectID)
	expired := time.Now().UTC().Add(-time.Minute)
	model := detectors.ObjectModel{
		ApplicationID: "app-retry", EndpointKey: "GET /v1/orders/{orderId}",
		PathTemplate: "/v1/orders/{orderId}", ObjectType: "ORDER",
		Identifiers:      []detectors.ObjectIdentifier{{Location: "path", Name: "orderId", Primary: true}},
		RequiredRelation: "OWNER", OwnerExclusive: true, Publishable: true,
		UniqueEndpointTemplate: true, ModelVersion: "retry-model",
	}
	input := &Guard{
		AppID:                     "app-retry",
		EventsLog:                 filepath.Join(t.TempDir(), "events.log"),
		GatewayNode:               "retry-contract",
		CounterBackend:            "memory",
		APIDynamicProtection:      true,
		APIProtectionMode:         "OBSERVE",
		APIPolicyVersion:          "retry-policy",
		APIAuthzModels:            []detectors.ObjectModel{model},
		APIAuthzObjectHMACKeyHex:  hex.EncodeToString(currentKey),
		APIAuthzSnapshotExpiresAt: &expired,
		APIAuthzPreviousValid: &authzSnapshotJSON{
			Models: []detectors.ObjectModel{model},
			Relations: []detectors.ObjectRelation{{
				ApplicationID: "app-retry", PrincipalID: "user-owner", ObjectType: "ORDER",
				ObjectRef: previousRef, Relation: "OWNER", Status: "CONFIRMED",
			}},
			ObjectHMACKeyHex: hex.EncodeToString(previousKey),
			PolicyVersion:    "retry-previous-policy",
		},
	}
	snapshot, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}

	attempts := 0
	var loaded []byte
	listener := newAuthzPipeListener()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/load" {
			http.NotFound(w, r)
			return
		}
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			http.Error(w, readErr.Error(), http.StatusBadRequest)
			return
		}
		attempts++
		if attempts == 1 {
			http.Error(w, `{"error":"temporary node outage"}`, http.StatusInternalServerError)
			return
		}
		loaded = append(loaded[:0], body...)
		w.WriteHeader(http.StatusOK)
	})}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(listener) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = listener.Close()
		select {
		case err := <-serveErr:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("retry HTTP server: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("retry HTTP server did not stop")
		}
	})
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return listener.dial(ctx)
	}}
	client := &http.Client{Transport: transport}
	t.Cleanup(transport.CloseIdleConnections)

	post := func() error {
		req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://gateway.test/load", bytes.NewReader(snapshot))
		if reqErr != nil {
			return reqErr
		}
		req.Header.Set("Content-Type", "application/json")
		resp, postErr := client.Do(req)
		if postErr != nil {
			return postErr
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("load status %s", resp.Status)
		}
		return nil
	}
	if err := post(); err == nil {
		t.Fatal("first publish attempt must fail")
	}
	if err := post(); err != nil {
		t.Fatalf("retry publish: %v", err)
	}
	if attempts != 2 || !bytes.Equal(loaded, snapshot) {
		t.Fatalf("retry must load identical snapshot: attempts=%d identical=%v", attempts, bytes.Equal(loaded, snapshot))
	}

	var g Guard
	if err := json.Unmarshal(loaded, &g); err != nil {
		t.Fatalf("decode retried snapshot: %v", err)
	}
	resetSharedEngineForTest()
	t.Cleanup(resetSharedEngineForTest)
	if err := g.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatalf("provision retried snapshot: %v", err)
	}
	t.Cleanup(func() { _ = g.Cleanup() })
	if g.apiAuthzPreviousValid == nil || !bytes.Equal(g.apiAuthzPreviousValid.ObjectRefHMACKey, previousKey) {
		t.Fatalf("retried snapshot PreviousValid was not provisioned: %+v", g.apiAuthzPreviousValid)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/orders/"+rawObjectID, nil)
	req.Header.Set("X-Request-Id", "retry-contract-bola")
	verified := jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "user-other", PolicyVersion: "retry-policy"}
	*req = *req.WithContext(context.WithValue(req.Context(), jwtResultKey{}, verified))
	res := httptest.NewRecorder()
	if err := g.serveNext(res, req, nextFunc(func(w http.ResponseWriter, _ *http.Request) error {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "origin-ok")
		return nil
	})); err != nil {
		t.Fatalf("serve retried snapshot request: %v", err)
	}
	if res.Code != http.StatusOK || res.Body.String() != "origin-ok" {
		t.Fatalf("OBSERVE request must reach origin: status=%d body=%q", res.Code, res.Body.String())
	}
	recs := readAPIRecords(t, filepath.Join(filepath.Dir(g.EventsLog), "api-runtime-events.log"))
	if len(recs) != 1 || recs[0].AuthzDecision == nil || recs[0].AuthzDecision.Decision != detectors.AuthorizationObserveViolation {
		t.Fatalf("retried snapshot did not produce BOLA OBSERVE event: %+v", recs)
	}
	foundBOLA := false
	for _, check := range recs[0].AuthzDecision.Checks {
		if check.Type == "BOLA" && check.ReasonCode == "AUTHZ-BOLA-001" {
			foundBOLA = true
			break
		}
	}
	if !foundBOLA {
		t.Fatalf("retried snapshot BOLA check missing: %+v", recs[0].AuthzDecision.Checks)
	}
}

var _ caddyhttp.Handler = nextFunc(nil)
var _ = zap.NewNop
var _ = apievents.Record{}
