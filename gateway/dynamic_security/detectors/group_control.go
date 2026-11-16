package detectors

import (
	"strconv"
	"strings"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
)

const DefaultSharedDeviceAccountLimit = 3

// CheckSharedDeviceAccounts observes distinct verified principals sharing a passive
// device fingerprint in the existing bounded one-minute distinct-value window.
// It is an OBSERVE signal, not proof of coordinated abuse or a blocking decision.
func CheckSharedDeviceAccounts(ctx *dsctx.RequestContext, jwt *jwtverify.VerificationResult, applicationID string) {
	CheckSharedDeviceAccountsWithLimit(ctx, jwt, applicationID, DefaultSharedDeviceAccountLimit)
}

func CheckSharedDeviceAccountsWithLimit(ctx *dsctx.RequestContext, jwt *jwtverify.VerificationResult, applicationID string, limit int) {
	if limit < 2 || limit > 1000 {
		limit = DefaultSharedDeviceAccountLimit
	}
	if ctx == nil || jwt == nil || jwt.Status != jwtverify.StatusVerified {
		return
	}
	principal := strings.TrimSpace(jwt.VerifiedPrincipalID)
	if principal == "" || applicationID == "" || ctx.DeviceFingerprint == "" {
		return
	}
	key := "group-control\x00" + applicationID + "\x00" + ctx.DeviceFingerprint
	distinct := ipSpreadAdd(ctx, key, principal)
	if distinct < limit {
		return
	}
	observations, _ := behaviorCounts(ctx, key+"\x00observation")
	if observations != 1 {
		return
	}
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector: "behavior", RuleID: "behavior.shared_device_accounts",
		Category: "OBSERVE", Severity: "MEDIUM",
		Message: "multiple verified principals used the same passive device fingerprint",
		Evidence: map[string]string{
			"distinct_accounts":  strconv.Itoa(distinct),
			"window":             "1m",
			"identity_assurance": "JWT_VERIFIED",
			"device_fingerprint": ctx.DeviceFingerprint,
		},
		ScoreDelta: 10, Confidence: 0.55,
	})
}
