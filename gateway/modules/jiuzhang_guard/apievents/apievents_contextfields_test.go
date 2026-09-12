package apievents

import (
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// §7 字段：携带时键存在且形态完整；超长条数/字段被 sanitize 封顶。
func TestEmit_WithContextIdentifierFields(t *testing.T) {
	ids := make([]dsctx.ObjectIdentifier, 0, dsctx.MaxObjectIdentifiers+2)
	for i := 0; i < dsctx.MaxObjectIdentifiers+2; i++ {
		ids = append(ids, dsctx.ObjectIdentifier{
			Source: "path", Param: "id",
			ValueHash: strings.Repeat("a", 32),
		})
	}
	ids[0].Param = "id\x1b injected" // 控制字符须被剥离
	line := emitAndRead(t, Record{
		EndpointKey:       "GET /v1/users/{id}",
		FinalAction:       "ALLOW",
		DeviceFingerprint: strings.Repeat("b", 32),
		ObjectIdentifiers: ids,
	})
	if !strings.Contains(line, `"device_fingerprint"`) || !strings.Contains(line, `"object_identifiers"`) {
		t.Fatalf("§7 keys missing: %s", line)
	}
	if strings.Contains(line, "\x1b") {
		t.Fatalf("control char must be stripped: %s", line)
	}
	if got := strings.Count(line, `"value_hash"`); got != dsctx.MaxObjectIdentifiers {
		t.Fatalf("object identifiers must cap at %d, got %d", dsctx.MaxObjectIdentifiers, got)
	}
}

// 无 §7 字段：键省略（omitempty），事件较旧版零变化。
func TestEmit_WithoutContextIdentifierFields(t *testing.T) {
	line := emitAndRead(t, Record{EndpointKey: "GET /v1/ping", FinalAction: "ALLOW"})
	if strings.Contains(line, "device_fingerprint") || strings.Contains(line, "object_identifiers") {
		t.Fatalf("§7 keys must be omitted when empty: %s", line)
	}
}
