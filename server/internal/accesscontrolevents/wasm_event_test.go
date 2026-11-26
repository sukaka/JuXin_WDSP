package accesscontrolevents

import (
	"strings"
	"testing"
)

func wasmPluginDetailFixture() map[string]interface{} {
	return map[string]interface{}{
		"plugin_id":      "9d1a2c3d-0000-4000-8000-000000000001",
		"plugin_name":    "header-signature-check",
		"plugin_version": 3,
		"abi_version":    "wdsp_v1",
		"mode":           "PROTECT",
		"sha256":         strings.Repeat("a", 64),
		"rule_id":        "wasm.custom_sig_missing",
		"reason":         "missing custom hmac header",
		"score_delta":    80,
		"latency_ms":     2,
		"fail_policy":    "FAIL_OPEN",
		"action_taken":   "BLOCK",
		"error":          "execution timeout",
	}
}

func TestParseWasmPluginEventsAllTypes(t *testing.T) {
	for _, evType := range WasmPluginEventTypes {
		t.Run(evType, func(t *testing.T) {
			d := wasmPluginDetailFixture()
			// Undeclared sensitive fields MUST be dropped at decode time.
			d["wasm_binary"] = "AGFzbQEAAAA="
			d["wasm_base64"] = "AGFzbQEAAAA="
			d["authorization"] = "Bearer top-secret"
			d["cookie"] = "session=secret"
			d["body"] = "raw-request-body"

			evt, err := ParseEventLine(validLine(t, map[string]interface{}{
				"event_type":  evType,
				"action":      "REJECT",
				"wasm_plugin": d,
				"final_decision": map[string]interface{}{
					"schema_version": 1,
					"action":         "BLOCK",
				},
			}), "default-node")
			if err != nil {
				t.Fatalf("valid %s line rejected: %v", evType, err)
			}
			wp, ok := evt.Details["wasm_plugin"].(map[string]interface{})
			if !ok {
				t.Fatalf("details.wasm_plugin missing: %+v", evt.Details)
			}
			if wp["plugin_id"] != "9d1a2c3d-0000-4000-8000-000000000001" ||
				wp["plugin_name"] != "header-signature-check" ||
				wp["plugin_version"] != 3 ||
				wp["abi_version"] != "wdsp_v1" ||
				wp["mode"] != "PROTECT" ||
				wp["sha256"] != strings.Repeat("a", 64) ||
				wp["rule_id"] != "wasm.custom_sig_missing" ||
				wp["reason"] != "missing custom hmac header" ||
				wp["score_delta"] != 80 ||
				wp["latency_ms"] != int64(2) ||
				wp["fail_policy"] != "FAIL_OPEN" ||
				wp["action_taken"] != "BLOCK" ||
				wp["error"] != "execution timeout" {
				t.Errorf("details.wasm_plugin mismatch: %+v", wp)
			}
			for _, forbidden := range []string{"wasm_binary", "wasm_base64", "authorization", "cookie", "body"} {
				if _, leaked := wp[forbidden]; leaked {
					t.Errorf("undeclared sensitive field %q must be dropped: %+v", forbidden, wp)
				}
			}
			if _, ok := evt.Details["final_decision"]; !ok {
				t.Error("final_decision must be preserved alongside details.wasm_plugin")
			}
			label := formatACEventType(evType)
			if label == evType {
				t.Errorf("missing Chinese export label for %s", evType)
			}
			csvOut := renderExportCSV([]Event{*evt})
			if !strings.Contains(csvOut, label) {
				t.Errorf("exported CSV missing Chinese label %q: %s", label, csvOut)
			}
		})
	}
}

func TestParseWasmPluginEventMissingDetailRejected(t *testing.T) {
	for _, evType := range WasmPluginEventTypes {
		if _, err := ParseEventLine(validLine(t, map[string]interface{}{
			"event_type": evType,
			"action":     "REJECT",
		}), "default-node"); err == nil {
			t.Fatalf("%s event missing wasm_plugin object must fail parse", evType)
		}
	}
}
