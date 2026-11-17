package accesscontrolevents

import "testing"

func TestParseRiskPolicyEventChallenge(t *testing.T) {
	for _, tc := range []struct {
		actionTaken string
		wantAction  string
	}{
		{actionTaken: "would_challenge", wantAction: ActionObserve},
		{actionTaken: "challenged", wantAction: ActionChallenge},
	} {
		t.Run(tc.actionTaken, func(t *testing.T) {
			evt, err := ParseEventLine(validLine(t, map[string]interface{}{
				"event_type": "RISK_POLICY_CHALLENGE",
				"action":     tc.actionTaken,
				"risk": map[string]interface{}{
					"identity_key":   "ik-risk-challenge",
					"score":          60,
					"risk_level":     "HIGH",
					"threshold":      55,
					"signals":        []interface{}{},
					"mode":           "PROTECT",
					"policy_version": 4,
					"action_taken":   tc.actionTaken,
					"reason":         "identity_risk_policy",
				},
			}), "default-node")
			if err != nil {
				t.Fatalf("valid challenge event rejected: %v", err)
			}
			if evt.EventType != EventTypeRiskPolicyChallenge || evt.Action != tc.wantAction {
				t.Fatalf("event/action=%s/%s, want RISK_POLICY_CHALLENGE/%s", evt.EventType, evt.Action, tc.wantAction)
			}
			if isRejected(evt) {
				t.Fatal("risk challenge must not count as REJECT")
			}
			if evt.Details["action_taken"] != tc.actionTaken || evt.Details["threshold"] != 55 {
				t.Fatalf("challenge details=%+v", evt.Details)
			}
		})
	}
}
