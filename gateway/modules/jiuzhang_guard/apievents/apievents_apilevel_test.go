package apievents

import (
	"strings"
	"testing"
)

// §8.2 四级识别标签：携带时 api_level 键存在且值原样；超长被 sanitize 封顶。
func TestEmit_WithAPILevel(t *testing.T) {
	line := emitAndRead(t, Record{
		EndpointKey: "GET /v1/users/{id}",
		FinalAction: "ALLOW",
		APILevel:    "CONFIRMED_API",
	})
	if !strings.Contains(line, `"api_level":"CONFIRMED_API"`) {
		t.Fatalf("api_level missing: %s", line)
	}

	long := emitAndRead(t, Record{
		EndpointKey: "GET /v1/users/{id}",
		FinalAction: "ALLOW",
		APILevel:    strings.Repeat("L", maxProtoLen+8),
	})
	if !strings.Contains(long, `"api_level":"`+strings.Repeat("L", maxProtoLen)+`"`) {
		t.Fatalf("api_level must be capped at %d chars: %s", maxProtoLen, long)
	}
}

// 无四级标签（管线未写 api.classification，如 fail-open 旁路）：键省略，事件零变化。
func TestEmit_WithoutAPILevel(t *testing.T) {
	line := emitAndRead(t, Record{EndpointKey: "GET /v1/ping", FinalAction: "ALLOW"})
	if strings.Contains(line, "api_level") {
		t.Fatalf("api_level must be omitted when empty: %s", line)
	}
}
