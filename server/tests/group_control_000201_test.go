package tests

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/events"
	"github.com/jiuzhang-waf/server/internal/apiruntime"
	"github.com/jiuzhang-waf/server/internal/apisecurity"
)

func TestGroupControlMigration000201Static(t *testing.T) {
	up := readMigration(t, "000201_api_runtime_event_application.up.sql")
	down := readMigration(t, "000201_api_runtime_event_application.down.sql")
	for _, fragment := range []string{
		"ADD COLUMN IF NOT EXISTS application_id UUID",
		"CREATE INDEX IF NOT EXISTS idx_api_runtime_events_app_device_time",
		"历史事件不回填",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("000201 up missing %q", fragment)
		}
	}
	for _, fragment := range []string{"DROP INDEX IF EXISTS idx_api_runtime_events_app_device_time", "DROP COLUMN IF EXISTS application_id"} {
		if !strings.Contains(down, fragment) {
			t.Errorf("000201 down missing %q", fragment)
		}
	}
}

func TestGroupControlSharedDevicesIntegration000201(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	up, err := os.ReadFile("../migrations/000201_api_runtime_event_application.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := env.db.Exec(ctx, string(up)); err != nil {
			t.Fatalf("replay up #%d: %v", i+1, err)
		}
	}
	if got := s8Count(t, env, `SELECT count(*) FROM information_schema.columns
		WHERE table_name='api_runtime_events' AND column_name='application_id' AND is_nullable='YES'`); got != 1 {
		t.Fatalf("nullable application_id columns=%d", got)
	}
	down, err := os.ReadFile("../migrations/000201_api_runtime_event_application.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.db.Exec(ctx, string(down)); err != nil {
		t.Fatalf("down: %v", err)
	}
	if got := s8Count(t, env, `SELECT count(*) FROM information_schema.columns
		WHERE table_name='api_runtime_events' AND column_name='application_id'`); got != 0 {
		t.Fatalf("application_id remains after down: %d", got)
	}
	if _, err := env.db.Exec(ctx, string(up)); err != nil {
		t.Fatalf("re-up: %v", err)
	}

	applicationA := uuid.NewString()
	applicationB := uuid.NewString()
	deviceA := strings.Repeat("a", 32)
	runtimeStore := apiruntime.NewStore(env.db)
	now := time.Now().UTC()
	save := func(requestID, applicationID, device, principal string, signal bool) {
		t.Helper()
		details := []dsctx.DetectorMatch{}
		if signal {
			details = append(details, dsctx.DetectorMatch{RuleID: "behavior.shared_device_accounts", Category: "OBSERVE", Severity: "MEDIUM"})
		}
		event := &apiruntime.PrimaryEvent{
			PrimaryEvent: events.PrimaryEvent{
				RequestID: requestID, ApplicationID: applicationID, EndpointKey: "GET /v1/shared-" + requestID,
				OccurredAt: now, DeviceFingerprint: device, Details: details,
			},
			JWTVerification: &events.JWTVerification{Status: "VERIFIED", VerifiedPrincipalID: principal},
		}
		if err := runtimeStore.SavePrimary(ctx, event); err != nil {
			t.Fatalf("SavePrimary %s: %v", requestID, err)
		}
	}
	for i, principal := range []string{strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 32)} {
		save("gc-a-"+s5Rand()+string(rune('a'+i)), applicationA, deviceA, principal, i == 2)
	}
	for i, principal := range []string{strings.Repeat("1", 32), strings.Repeat("2", 32)} {
		save("gc-b-"+s5Rand()+string(rune('a'+i)), applicationB, deviceA, principal, false)
	}
	save("gc-legacy-"+s5Rand(), "", deviceA, strings.Repeat("4", 32), false)

	securityStore := apisecurity.NewStore(env.db)
	filter := apisecurity.SharedDeviceFilter{Start: now.Add(-time.Minute), End: now.Add(time.Minute), MinAccounts: 3, Page: 1, PageSize: 20}
	items, total, err := securityStore.ListSharedDevices(ctx, filter)
	if err != nil {
		t.Fatalf("ListSharedDevices: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].ApplicationID.String() != applicationA ||
		items[0].DistinctAccounts != 3 || items[0].EventCount != 3 || items[0].SignalCount != 1 || items[0].EndpointCount != 3 {
		t.Fatalf("aggregate total=%d items=%+v", total, items)
	}
	accounts, accountTotal, err := securityStore.ListSharedDeviceAccounts(ctx, filter)
	if err != nil {
		t.Fatalf("ListSharedDeviceAccounts: %v", err)
	}
	if accountTotal != 3 || len(accounts) != 3 {
		t.Fatalf("account aggregate total=%d items=%+v", accountTotal, accounts)
	}
	for _, account := range accounts {
		wantSignals := int64(0)
		if account.PrincipalRef == strings.Repeat("3", 32) {
			wantSignals = 1
		}
		if account.EventCount != 1 || account.SignalCount != wantSignals || account.EndpointCount != 1 {
			t.Fatalf("account aggregate=%+v", account)
		}
	}
	trend, err := securityStore.SharedDeviceTrend(ctx, apisecurity.SharedDeviceTrendFilter{
		SharedDeviceFilter: filter, Bucket: "hour",
	})
	if err != nil || len(trend) != 1 || trend[0].GroupCount != 1 || trend[0].SignalCount != 1 || trend[0].EventCount != 3 {
		t.Fatalf("trend aggregate=%+v err=%v", trend, err)
	}
	filter.ApplicationID = applicationB
	items, total, err = securityStore.ListSharedDevices(ctx, filter)
	if err != nil || total != 0 || len(items) != 0 {
		t.Fatalf("two-account application must remain below threshold: total=%d items=%+v err=%v", total, items, err)
	}
}
