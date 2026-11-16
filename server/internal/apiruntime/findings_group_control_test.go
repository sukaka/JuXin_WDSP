package apiruntime

import (
	"context"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func TestRecordFindingsSharedDeviceEvidence(t *testing.T) {
	saver := &fakeFindingSaver{}
	collector := NewCollector(nil, "test-group-control", "", "", "")
	collector.SetFindingSaver(saver)
	device := strings.Repeat("a", 32)
	collector.recordFindings(context.Background(), &Record{
		RequestID: "req-group-control-evidence", EndpointKey: "GET /v1/team",
		FinalAction: "ALLOW", DeviceFingerprint: device,
		Details: []dsctx.DetectorMatch{{
			Detector: "behavior", RuleID: "behavior.shared_device_accounts",
			Category: "OBSERVE", Severity: "MEDIUM", Message: "shared passive fingerprint",
			Evidence: map[string]string{
				"distinct_accounts": "3", "window": "1m", "identity_assurance": "JWT_VERIFIED",
				"device_fingerprint": device, "raw_account": "must-not-persist",
			},
		}},
	})
	if len(saver.batches) != 1 || len(saver.batches[0]) != 1 {
		t.Fatalf("finding batches=%+v", saver.batches)
	}
	finding := saver.batches[0][0]
	if finding.FindingType != "SHARED_DEVICE_ACCOUNTS" || finding.DeviceFingerprint != device {
		t.Fatalf("finding mapping/snapshot=%+v", finding)
	}
	for key, want := range map[string]string{
		"distinct_accounts": "3", "window": "1m", "identity_assurance": "JWT_VERIFIED", "device_fingerprint": device,
	} {
		if finding.Evidence[key] != want {
			t.Fatalf("evidence[%s]=%v want %q", key, finding.Evidence[key], want)
		}
	}
	if _, exists := finding.Evidence["raw_account"]; exists {
		t.Fatalf("raw account value persisted: %+v", finding.Evidence)
	}
}
