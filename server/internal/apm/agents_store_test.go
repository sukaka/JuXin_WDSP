// agents_store_test.go Agent 仓储解码回归测试。
package apm

import "testing"

func TestDecodeNodeInfo_NormalizesLegacyScalarValues(t *testing.T) {
	got, err := decodeNodeInfo([]byte(`{
        "hostname": "agent-1",
        "port": 4317,
        "enabled": true,
        "labels": {"zone": "cn-east-1"},
        "tags": ["apm", "java"],
        "empty": null
    }`))
	if err != nil {
		t.Fatalf("decodeNodeInfo returned error: %v", err)
	}
	want := NodeInfo{
		"hostname": "agent-1",
		"port":     "4317",
		"enabled":  "true",
		"labels":   `{"zone":"cn-east-1"}`,
		"tags":     `["apm","java"]`,
		"empty":    "",
	}
	for key, wantValue := range want {
		if got[key] != wantValue {
			t.Errorf("node_info[%q] = %q, want %q", key, got[key], wantValue)
		}
	}
}

func TestDecodeNodeInfo_EmptyValues(t *testing.T) {
	for _, input := range []string{"", "null"} {
		got, err := decodeNodeInfo([]byte(input))
		if err != nil {
			t.Fatalf("decodeNodeInfo(%q) returned error: %v", input, err)
		}
		if got == nil || len(got) != 0 {
			t.Errorf("decodeNodeInfo(%q) = %#v, want empty map", input, got)
		}
	}
}

func TestDecodeNodeInfo_RejectsNonObject(t *testing.T) {
	if _, err := decodeNodeInfo([]byte(`"unexpected"`)); err == nil {
		t.Fatal("decodeNodeInfo accepted a non-object value")
	}
}
