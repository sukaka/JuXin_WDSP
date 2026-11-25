package protectionpolicies

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
)

func validTestPolicy() *Policy {
	return &Policy{
		Code:                     "custom-policy",
		Name:                     "自定义策略",
		ProtectionMode:           ModeObserve,
		ParanoiaLevel:            1,
		InboundAnomalyThreshold:  5,
		OutboundAnomalyThreshold: 4,
		RequestBodyLimit:         13107200,
		BlockingStatusCode:       403,
	}
}

func TestValidatePolicyThresholdBounds(t *testing.T) {
	if err := ValidatePolicy(validTestPolicy()); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}

	for _, tc := range []struct {
		name     string
		inbound  int
		outbound int
		wantErr  bool
	}{
		{name: "min boundary 1", inbound: 1, outbound: 1, wantErr: false},
		{name: "max boundary 100", inbound: 100, outbound: 100, wantErr: false},
		{name: "inbound below min", inbound: 0, outbound: 4, wantErr: true},
		{name: "inbound above max", inbound: 101, outbound: 4, wantErr: true},
		{name: "outbound below min", inbound: 5, outbound: 0, wantErr: true},
		{name: "outbound above max", inbound: 5, outbound: 101, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := validTestPolicy()
			p.InboundAnomalyThreshold = tc.inbound
			p.OutboundAnomalyThreshold = tc.outbound
			err := ValidatePolicy(p)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for inbound=%d outbound=%d", tc.inbound, tc.outbound)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error for inbound=%d outbound=%d: %v", tc.inbound, tc.outbound, err)
			}
		})
	}
}

func TestEmptyApplicationIDsSerializesAsArray(t *testing.T) {
	emptyIDs := []uuid.UUID{}
	item := policyItem(validTestPolicy(), 0)
	item["application_ids"] = emptyIDs
	item["domains"] = []BoundDomain{}

	raw, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"application_ids":[]`) {
		t.Fatalf("expected application_ids:[], got %s", string(raw))
	}
	if !strings.Contains(string(raw), `"domains":[]`) {
		t.Fatalf("expected domains:[], got %s", string(raw))
	}

	appsRaw, err := json.Marshal(map[string]interface{}{"application_ids": emptyIDs, "count": len(emptyIDs)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(appsRaw), `"application_ids":[]`) {
		t.Fatalf("expected application_ids:[] in list response, got %s", string(appsRaw))
	}
}

func TestHandlerCreateRejectsOutOfRangeThresholds(t *testing.T) {
	h := NewHandler(nil, nil)
	for _, body := range []string{
		`{"code":"p1","name":"P1","inbound_anomaly_threshold":101}`,
		`{"code":"p2","name":"P2","outbound_anomaly_threshold":101}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/protection-policies", strings.NewReader(body))
		req = req.WithContext(authz.WithPrincipal(req.Context(), &authz.Principal{UserID: uuid.New(), Username: "admin"}))
		rr := httptest.NewRecorder()
		h.Create(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for %s, got %d (%s)", body, rr.Code, rr.Body.String())
		}
	}
}
