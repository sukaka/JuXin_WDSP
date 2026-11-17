package apiruntime

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestSavePrimaryPersistsApplicationID(t *testing.T) {
	db := &captureArgsTx{}
	ev := ctxFieldEvent("req-app-id")
	ev.ApplicationID = "11111111-1111-1111-1111-111111111111"
	if err := (&Store{db: db}).SavePrimary(context.Background(), ev); err != nil {
		t.Fatalf("SavePrimary: %v", err)
	}
	if len(db.args) != 1 || len(db.args[0]) != 25 {
		t.Fatalf("primary insert args = %+v", db.args)
	}
	applicationID, ok := db.args[0][23].(uuid.UUID)
	if !ok || applicationID.String() != ev.ApplicationID {
		t.Fatalf("application_id argument = %#v", db.args[0][23])
	}
	if !strings.Contains(db.sqls[0], "application_id") {
		t.Fatalf("primary insert does not persist application_id: %s", db.sqls[0])
	}
}

func TestSavePrimaryKeepsUnknownApplicationNull(t *testing.T) {
	db := &captureArgsTx{}
	if err := (&Store{db: db}).SavePrimary(context.Background(), ctxFieldEvent("req-app-unknown")); err != nil {
		t.Fatalf("SavePrimary legacy event: %v", err)
	}
	if len(db.args) != 1 || db.args[0][23] != nil {
		t.Fatalf("unknown application must remain NULL: %+v", db.args)
	}
}

func TestSavePrimaryRejectsInvalidApplicationIDBeforeInsert(t *testing.T) {
	db := &fakeBatchTx{}
	ev := ctxFieldEvent("req-app-invalid")
	ev.ApplicationID = "orders-prod"
	err := (&Store{db: db}).SavePrimary(context.Background(), ev)
	if err == nil || !strings.Contains(err.Error(), "application_id: invalid UUID") {
		t.Fatalf("invalid application_id error = %v", err)
	}
	if len(db.ops) != 0 {
		t.Fatalf("invalid application_id must not touch database: %+v", db.ops)
	}
}
