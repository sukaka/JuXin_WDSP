package apiruntime

import (
	"context"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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

// captureArgsTx 记录 Exec 的 SQL 与参数（DBTX 契约由嵌入 pgx.Tx 满足；
// SavePrimary 路径只调用 Exec）。
type captureArgsTx struct {
	pgx.Tx
	sqls []string
	args [][]any
}

func (c *captureArgsTx) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	c.sqls = append(c.sqls, sql)
	c.args = append(c.args, args)
	return pgconn.CommandTag{}, nil
}

// NG-AZ-03 D1：服务端事件边界接收决策词表第四值 VERIFIED_VIOLATION
// （词表外取值仍拒收不降级——server 侧字面常量校验，不依赖网关 events 包编译期常量）。
func TestSavePrimaryAcceptsVerifiedViolationDecision(t *testing.T) {
	db := &fakeBatchTx{}
	store := &Store{db: db}
	ev := &PrimaryEvent{
		PrimaryEvent: dsevents.PrimaryEvent{
			RequestID:  "req-authz-verified-violation",
			OccurredAt: time.Now().UTC(),
			AuthzDecision: &dsevents.AuthorizationDecisionGroup{
				DecisionID: uuid.NewString(),
				Decision:   dsevents.AuthorizationDecision("VERIFIED_VIOLATION"),
				Checks: []dsevents.AuthorizationCheck{{
					Type:      "BOLA",
					Decision:  dsevents.AuthorizationDecision("VERIFIED_VIOLATION"),
					ObjectRef: "objref:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				}},
			},
		},
	}
	if err := store.SavePrimary(context.Background(), ev); err != nil {
		t.Fatalf("VERIFIED_VIOLATION 决策应通过服务端边界校验: %v", err)
	}
	if got := db.countOp("exec:INSERT"); got != 2 {
		t.Fatalf("want primary and authorization INSERTs, got %d (%v)", got, db.ops)
	}

	// 词表外取值仍拒收（不降级猜义）
	ev2 := &PrimaryEvent{
		PrimaryEvent: dsevents.PrimaryEvent{
			RequestID:  "req-authz-bogus",
			OccurredAt: time.Now().UTC(),
			AuthzDecision: &dsevents.AuthorizationDecisionGroup{
				DecisionID: uuid.NewString(),
				Decision:   dsevents.AuthorizationDecision("MAYBE_VIOLATION"),
			},
		},
	}
	db2 := &fakeBatchTx{}
	if err := (&Store{db: db2}).SavePrimary(context.Background(), ev2); err == nil || !strings.Contains(err.Error(), "invalid value") {
		t.Fatalf("词表外决策值应拒收: %v", err)
	}
	if len(db2.ops) != 0 {
		t.Fatalf("非法决策值不得触库: %v", db2.ops)
	}
}

// NG-AZ-03 D5：VERIFIED_VIOLATION 实断证据随主事件 final_decision.authz_enforcement
// 内嵌上报——决策行 evidence 原样带出该子对象；无证据时落 '{}' 与历史一致。
func TestSavePrimaryCarriesAuthzEnforcementEvidence(t *testing.T) {
	newDecisionEvent := func(requestID string, finalDecision json.RawMessage) *PrimaryEvent {
		return &PrimaryEvent{
			PrimaryEvent: dsevents.PrimaryEvent{
				RequestID:  requestID,
				OccurredAt: time.Now().UTC(),
				AuthzDecision: &dsevents.AuthorizationDecisionGroup{
					DecisionID:    uuid.NewString(),
					Decision:      dsevents.AuthorizationDecision("VERIFIED_VIOLATION"),
					PolicyVersion: "authz-pv1",
					Checks: []dsevents.AuthorizationCheck{{
						Type:      "BOLA",
						Decision:  dsevents.AuthorizationDecision("VERIFIED_VIOLATION"),
						ObjectRef: "objref:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
					}},
				},
			},
			FinalDecision: finalDecision,
		}
	}

	// 含 authz_enforcement：决策行 evidence 原样带出
	db := &captureArgsTx{}
	evidencePayload := `{"decision":"VERIFIED_VIOLATION","reason_code":"AUTHZ-BOLA-001","enforced":true,"endpoint_key":"GET /v1/orders/{id}","eligibility":{"trusted_identity":true,"model_applicable":true,"relation_valid":true,"no_conflict":true,"tenant_consistent":true,"evidence_fresh":true,"other_owner":true,"owner_exclusive":true},"enforcement_owner":"zhang.lei@example.com","evidence_source":"AUTHORITY_SYNC","recorded_at":"2026-10-05T08:00:00Z"}`
	ev := newDecisionEvent("req-authz-evidence", json.RawMessage(`{"completion_status":"COMPLETED","security_action":"BLOCK","authz_enforcement":`+evidencePayload+`}`))
	if err := (&Store{db: db}).SavePrimary(context.Background(), ev); err != nil {
		t.Fatalf("SavePrimary: %v", err)
	}
	// 定位决策 INSERT（fake RowsAffected=0 会先触发 final_decision 条件补全 UPDATE——
	// 按 SQL 文本定位而非位置假设）
	decisionArgs := findDecisionInsertArgs(t, db)
	// 决策 INSERT 参数序：decision_id, application_id, endpoint_key, policy_version, decision, checks, evidence, occurred_at
	rawEvidence, ok := decisionArgs[6].([]byte)
	if !ok {
		t.Fatalf("evidence 参数应为 []byte: %T", decisionArgs[6])
	}
	var evidence map[string]json.RawMessage
	if err := json.Unmarshal(rawEvidence, &evidence); err != nil {
		t.Fatalf("evidence 应为合法 JSON 对象: %v (%s)", err, rawEvidence)
	}
	got, present := evidence["authz_enforcement"]
	if !present {
		t.Fatalf("evidence 应内嵌 authz_enforcement 键: %s", rawEvidence)
	}
	if string(got) != evidencePayload {
		t.Fatalf("authz_enforcement 应原样带出（只读透传不解释）:\n got %s\nwant %s", got, evidencePayload)
	}

	// 无 authz_enforcement（OBSERVE 形态/旧版网关）：evidence 落 '{}' 与历史一致
	db2 := &captureArgsTx{}
	if err := (&Store{db: db2}).SavePrimary(context.Background(), newDecisionEvent("req-authz-no-evidence", nil)); err != nil {
		t.Fatalf("SavePrimary: %v", err)
	}
	if raw, ok := findDecisionInsertArgs(t, db2)[6].([]byte); !ok || string(raw) != "{}" {
		t.Fatalf("无证据时 evidence 应落 '{}': %v", findDecisionInsertArgs(t, db2)[6])
	}
}

// findDecisionInsertArgs 定位 api_authorization_decisions INSERT 的参数集。
func findDecisionInsertArgs(t *testing.T, db *captureArgsTx) []any {
	t.Helper()
	for i, sql := range db.sqls {
		if strings.Contains(sql, "INSERT INTO api_authorization_decisions") {
			return db.args[i]
		}
	}
	t.Fatalf("未找到决策 INSERT: %v", db.sqls)
	return nil
}

func TestSavePrimaryGeneratesUUIDv7(t *testing.T) {
	for _, tc := range []struct {
		name      string
		initialID string
		wantV7    bool
	}{
		{name: "empty_id_generates_v7", initialID: "", wantV7: true},
		{name: "invalid_id_regenerates_v7", initialID: "not-a-uuid", wantV7: true},
		{name: "explicit_v4_preserved", initialID: uuid.New().String(), wantV7: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := &captureArgsTx{}
			ev := &PrimaryEvent{
				PrimaryEvent: dsevents.PrimaryEvent{
					ID:         tc.initialID,
					RequestID:  "req-uuidv7-" + tc.name,
					OccurredAt: time.Now().UTC(),
				},
			}
			if err := (&Store{db: db}).SavePrimary(context.Background(), ev); err != nil {
				t.Fatalf("SavePrimary: %v", err)
			}
			parsed, err := uuid.Parse(ev.ID)
			if err != nil {
				t.Fatalf("invalid ev.ID %q: %v", ev.ID, err)
			}
			if parsed.Variant() != uuid.RFC4122 {
				t.Fatalf("variant = %v, want RFC4122", parsed.Variant())
			}
			if tc.wantV7 && parsed.Version() != 7 {
				t.Fatalf("version = %d, want 7", parsed.Version())
			}
			if !tc.wantV7 && ev.ID != tc.initialID {
				t.Fatalf("explicit ID overwritten: got %s, want %s", ev.ID, tc.initialID)
			}
		})
	}
}
