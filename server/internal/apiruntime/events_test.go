package apiruntime

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	dsevents "github.com/jiuzhang-waf/gateway/dynamic_security/events"
)

func TestSavePrimaryRejectsUnencodableDetails(t *testing.T) {
	db := &fakeBatchTx{}
	store := &Store{db: db}
	ev := &PrimaryEvent{
		PrimaryEvent: dsevents.PrimaryEvent{
			RequestID:  "req-details-json",
			OccurredAt: time.Now().UTC(),
			Details:    []dsctx.DetectorMatch{{Confidence: math.NaN()}},
		},
	}

	err := store.SavePrimary(context.Background(), ev)
	if err == nil || !strings.Contains(err.Error(), "marshal event details") {
		t.Fatalf("SavePrimary error = %v, want explicit details marshal error", err)
	}
	if len(db.ops) != 0 {
		t.Fatalf("database must not be called after details marshal failure, ops = %v", db.ops)
	}
}

func TestSavePrimaryRejectsUnsanitizedAuthorizationBeforeInsert(t *testing.T) {
	db := &fakeBatchTx{}
	store := &Store{db: db}
	ev := &PrimaryEvent{
		PrimaryEvent: dsevents.PrimaryEvent{
			RequestID:  "req-authz-raw",
			OccurredAt: time.Now().UTC(),
			AuthzDecision: &dsevents.AuthorizationDecisionGroup{
				DecisionID: uuid.NewString(),
				Decision:   dsevents.AuthorizationObserveViolation,
				Checks: []dsevents.AuthorizationCheck{{
					Type:      "BOLA",
					Decision:  dsevents.AuthorizationObserveViolation,
					ObjectRef: "order-123",
				}},
			},
		},
	}

	err := store.SavePrimary(context.Background(), ev)
	if err == nil || !strings.Contains(err.Error(), "redacted HMAC reference") {
		t.Fatalf("SavePrimary error = %v, want raw object reference rejection", err)
	}
	if len(db.ops) != 0 {
		t.Fatalf("database must not be called for an unsanitized authorization decision, ops = %v", db.ops)
	}
}

func TestSavePrimaryRejectsRawAuthorizationRoleBeforeInsert(t *testing.T) {
	db := &fakeBatchTx{}
	store := &Store{db: db}
	ev := &PrimaryEvent{
		PrimaryEvent: dsevents.PrimaryEvent{
			RequestID:  "req-authz-role",
			OccurredAt: time.Now().UTC(),
			AuthzDecision: &dsevents.AuthorizationDecisionGroup{
				DecisionID: uuid.NewString(),
				Decision:   dsevents.AuthorizationAllow,
				Checks: []dsevents.AuthorizationCheck{{
					Type:     "BFLA",
					Decision: dsevents.AuthorizationAllow,
					Role:     "admin",
				}},
			},
		},
	}

	err := store.SavePrimary(context.Background(), ev)
	if err == nil || !strings.Contains(err.Error(), "raw role claims") {
		t.Fatalf("SavePrimary error = %v, want raw role rejection", err)
	}
	if len(db.ops) != 0 {
		t.Fatalf("database must not be called for a raw role claim, ops = %v", db.ops)
	}
}

func TestSavePrimaryPersistsRedactedAuthorizationDecision(t *testing.T) {
	db := &fakeBatchTx{}
	store := &Store{db: db}
	ev := &PrimaryEvent{
		PrimaryEvent: dsevents.PrimaryEvent{
			RequestID:  "req-authz-redacted",
			OccurredAt: time.Now().UTC(),
			AuthzDecision: &dsevents.AuthorizationDecisionGroup{
				DecisionID: uuid.NewString(),
				Decision:   dsevents.AuthorizationAllow,
				Checks: []dsevents.AuthorizationCheck{{
					Type:      "BOLA",
					Decision:  dsevents.AuthorizationAllow,
					ObjectRef: "objref:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				}},
			},
		},
	}

	if err := store.SavePrimary(context.Background(), ev); err != nil {
		t.Fatalf("SavePrimary: %v", err)
	}
	if got := db.countOp("exec:INSERT"); got != 2 {
		t.Fatalf("want primary and authorization INSERTs, got %d (%v)", got, db.ops)
	}
}
