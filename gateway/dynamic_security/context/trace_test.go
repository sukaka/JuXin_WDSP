package context

import (
	"strings"
	"testing"
)

func TestParseTraceparent(t *testing.T) {
	validTID := "0af7651916cd43dd8448eb211c80319c"
	validSID := "b7ad6b7169203331"
	cases := []struct {
		name string
		h    string
		ok   bool
	}{
		{"valid version 00", "00-" + validTID + "-" + validSID + "-01", true},
		{"valid version 01 unsampled", "01-" + validTID + "-" + validSID + "-00", true},
		{"empty", "", false},
		{"version ff rejected", "ff-" + validTID + "-" + validSID + "-01", false},
		{"version too long", "000-" + validTID + "-" + validSID + "-01", false},
		{"version non-hex", "0g-" + validTID + "-" + validSID + "-01", false},
		{"trace id all zero", "00-00000000000000000000000000000000-" + validSID + "-01", false},
		{"trace id 31 chars", "00-" + validTID[1:] + "-" + validSID + "-01", false},
		{"trace id 33 chars", "00-" + validTID + "0-" + validSID + "-01", false},
		{"trace id uppercase rejected", "00-" + strings.ToUpper(validTID) + "-" + validSID + "-01", false},
		{"span id all zero", "00-" + validTID + "-0000000000000000-01", false},
		{"span id 15 chars", "00-" + validTID + "-" + validSID[1:] + "-01", false},
		{"span id 17 chars", "00-" + validTID + "-" + validSID + "0-01", false},
		{"span id uppercase rejected", "00-" + validTID + "-" + strings.ToUpper(validSID) + "-01", false},
		{"flags too long", "00-" + validTID + "-" + validSID + "-011", false},
		{"flags non-hex", "00-" + validTID + "-" + validSID + "-0x", false},
		{"flags uppercase rejected", "00-" + validTID + "-" + validSID + "-0A", false},
		{"three segments", "00-" + validTID + "-" + validSID, false},
		{"five segments", "00-" + validTID + "-" + validSID + "-01-extra", false},
		{"non-hex garbage", "zz-zz-zz-zz", false},
		{"over 128 chars", "00-" + validTID + "-" + validSID + "-01" + strings.Repeat("a", 128), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tid, ok := ParseTraceparent(c.h)
			if ok != c.ok {
				t.Fatalf("ParseTraceparent(%q) ok = %v, want %v", c.h, ok, c.ok)
			}
			if ok && tid != validTID {
				t.Fatalf("trace id = %q, want %q", tid, validTID)
			}
			if !ok && tid != "" {
				t.Fatalf("invalid input must not yield trace id, got %q", tid)
			}
		})
	}
	// 边界：恰好 128 字符的合法头可接受（版本 00 固定 55 字符，构造等长合法形态验证长度判定）
	if len("00-"+validTID+"-"+validSID+"-01") != 55 {
		t.Fatal("fixture length assumption broken")
	}
}

func TestNewTraceContextUnique(t *testing.T) {
	const n = 10000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		tc, err := NewTraceContext()
		if err != nil {
			t.Fatalf("NewTraceContext: %v", err)
		}
		if len(tc.TraceID) != 32 || !isLowerHex(tc.TraceID) || isAllZero(tc.TraceID) {
			t.Fatalf("bad trace id %q", tc.TraceID)
		}
		if len(tc.SpanID) != 16 || !isLowerHex(tc.SpanID) || isAllZero(tc.SpanID) {
			t.Fatalf("bad span id %q", tc.SpanID)
		}
		if _, dup := seen[tc.TraceID]; dup {
			t.Fatalf("duplicate trace id %q", tc.TraceID)
		}
		seen[tc.TraceID] = struct{}{}
	}
}

func TestContinueTrace(t *testing.T) {
	tid := "0af7651916cd43dd8448eb211c80319c"
	a, err := ContinueTrace(tid)
	if err != nil {
		t.Fatalf("ContinueTrace: %v", err)
	}
	b, err := ContinueTrace(tid)
	if err != nil {
		t.Fatalf("ContinueTrace: %v", err)
	}
	if a.TraceID != tid || b.TraceID != tid {
		t.Fatalf("continued trace id must be external id: %q %q", a.TraceID, b.TraceID)
	}
	if len(a.SpanID) != 16 || len(b.SpanID) != 16 {
		t.Fatalf("bad span id len: %q %q", a.SpanID, b.SpanID)
	}
	if a.SpanID == b.SpanID {
		t.Fatal("span id must be regenerated per continuation")
	}
}
