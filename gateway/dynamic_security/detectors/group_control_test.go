package detectors

import (
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
)

func groupControlContext(key string, store IPSpreadStore) *dsctx.RequestContext {
	ctx := dsctx.New(key, dsctx.DefaultParseLimits())
	ctx.DeviceFingerprint = "passive-device-hash"
	now := time.Now
	if memory, ok := store.(memoryIPSpreadStore); ok {
		now = memory.t.now
	}
	ctx.BindDetectorStoreOverrides(&StoreOverrides{
		IPSpread: store, BehaviorWindow: NewMemoryWindowStore(64, now),
	})
	return ctx
}

func groupControlJWT(principal string) *jwtverify.VerificationResult {
	return &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: principal}
}

func TestSharedDeviceAccountsThresholdWithoutRepeat(t *testing.T) {
	ctx := groupControlContext("group-threshold", NewMemoryIPSpreadStore(64, nil))
	for _, principal := range []string{"principal-hash-a", "principal-hash-b"} {
		CheckSharedDeviceAccounts(ctx, groupControlJWT(principal), "app-group")
	}
	if len(ctx.CopyMatches()) != 0 {
		t.Fatal("two accounts must remain below threshold")
	}
	CheckSharedDeviceAccounts(ctx, groupControlJWT("principal-hash-c"), "app-group")
	matches := ctx.CopyMatches()
	if len(matches) != 1 || matches[0].RuleID != "behavior.shared_device_accounts" || matches[0].Category != "OBSERVE" {
		t.Fatalf("matches=%+v", matches)
	}
	if matches[0].Confidence != 0.55 || matches[0].Evidence["distinct_accounts"] != "3" || matches[0].Evidence["identity_assurance"] != "JWT_VERIFIED" {
		t.Fatalf("evidence=%+v", matches[0])
	}
	for _, value := range matches[0].Evidence {
		if strings.Contains(value, "principal-hash-") {
			t.Fatalf("raw principal leaked: %+v", matches[0].Evidence)
		}
	}
	for _, principal := range []string{"principal-hash-c", "principal-hash-d"} {
		CheckSharedDeviceAccounts(ctx, groupControlJWT(principal), "app-group")
	}
	if len(ctx.CopyMatches()) != 1 {
		t.Fatalf("repeated or subsequent accounts must not produce duplicate threshold alerts: %+v", ctx.CopyMatches())
	}
}

func TestSharedDeviceAccountsWindowReset(t *testing.T) {
	now := time.Date(2026, 11, 15, 4, 0, 0, 0, time.UTC)
	store := NewMemoryIPSpreadStore(64, func() time.Time { return now })
	ctx := groupControlContext("group-window", store)
	for _, principal := range []string{"principal-hash-a", "principal-hash-b", "principal-hash-c"} {
		CheckSharedDeviceAccounts(ctx, groupControlJWT(principal), "app-group")
	}
	if len(ctx.CopyMatches()) != 1 {
		t.Fatal("first threshold signal missing")
	}
	now = now.Add(2 * time.Minute)
	for _, principal := range []string{"principal-hash-a", "principal-hash-b", "principal-hash-c"} {
		CheckSharedDeviceAccounts(ctx, groupControlJWT(principal), "app-group")
	}
	if len(ctx.CopyMatches()) != 2 {
		t.Fatalf("new window should produce one fresh observation: %+v", ctx.CopyMatches())
	}
}

func TestSharedDeviceAccountsPreconditions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		jwt    *jwtverify.VerificationResult
		appID  string
		device string
	}{
		{"missing verification", nil, "app-group", "device-hash"},
		{"untrusted token", &jwtverify.VerificationResult{Status: jwtverify.StatusInvalid, VerifiedPrincipalID: "not-trusted"}, "app-group", "device-hash"},
		{"missing principal", groupControlJWT(" "), "app-group", "device-hash"},
		{"missing device", groupControlJWT("principal-hash"), "app-group", ""},
		{"missing application", groupControlJWT("principal-hash"), "", "device-hash"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := groupControlContext("group-precondition", nil)
			ctx.DeviceFingerprint = tc.device
			CheckSharedDeviceAccounts(ctx, tc.jwt, tc.appID)
			if len(ctx.CopyMatches()) != 0 {
				t.Fatalf("insufficient evidence produced matches: %+v", ctx.CopyMatches())
			}
		})
	}
}

func TestSharedDeviceAccountsApplicationIsolation(t *testing.T) {
	store := NewMemoryIPSpreadStore(64, nil)
	for _, appID := range []string{"app-a", "app-b"} {
		ctx := groupControlContext("group-"+appID, store)
		for _, principal := range []string{"principal-hash-a", "principal-hash-b"} {
			CheckSharedDeviceAccounts(ctx, groupControlJWT(principal), appID)
		}
		if len(ctx.CopyMatches()) != 0 {
			t.Fatalf("application %s mixed accounts with another application", appID)
		}
	}
}

func TestSharedDeviceAccountsConcurrentSingleThresholdObservation(t *testing.T) {
	ctx := groupControlContext("group-concurrent", NewMemoryIPSpreadStore(64, nil))
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			CheckSharedDeviceAccounts(ctx, groupControlJWT("principal-hash-"+strconv.Itoa(i)), "app-group")
		}(i)
	}
	wg.Wait()
	if len(ctx.CopyMatches()) != 1 {
		t.Fatalf("concurrent threshold observations=%d", len(ctx.CopyMatches()))
	}
}

func TestSharedDeviceAccountsCustomLimit(t *testing.T) {
	ctx := groupControlContext("group-custom-limit", NewMemoryIPSpreadStore(64, nil))
	CheckSharedDeviceAccountsWithLimit(ctx, groupControlJWT("principal-hash-a"), "app-group", 2)
	if len(ctx.CopyMatches()) != 0 {
		t.Fatal("first account must remain below custom threshold")
	}
	CheckSharedDeviceAccountsWithLimit(ctx, groupControlJWT("principal-hash-b"), "app-group", 2)
	matches := ctx.CopyMatches()
	if len(matches) != 1 || matches[0].Evidence["distinct_accounts"] != "2" || matches[0].Category != "OBSERVE" {
		t.Fatalf("custom threshold matches=%+v", matches)
	}
}

func TestSharedDeviceAccountsInvalidLimitUsesDefault(t *testing.T) {
	ctx := groupControlContext("group-invalid-limit", NewMemoryIPSpreadStore(64, nil))
	for _, principal := range []string{"principal-hash-a", "principal-hash-b"} {
		CheckSharedDeviceAccountsWithLimit(ctx, groupControlJWT(principal), "app-group", 1)
	}
	if len(ctx.CopyMatches()) != 0 {
		t.Fatal("invalid threshold must not become one-account alerting")
	}
	CheckSharedDeviceAccountsWithLimit(ctx, groupControlJWT("principal-hash-c"), "app-group", 1)
	if len(ctx.CopyMatches()) != 1 {
		t.Fatalf("invalid threshold should fall back to default 3: %+v", ctx.CopyMatches())
	}
}
