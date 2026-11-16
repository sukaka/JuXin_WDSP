package pipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func TestDownloadContentFingerprintOnlyWhenComplete(t *testing.T) {
	payload := []byte("complete download content")
	sum := sha256.Sum256(payload)
	for _, tc := range []struct {
		name      string
		body      []byte
		streamed  bool
		truncated bool
		want      string
	}{
		{name: "complete", body: payload, want: hex.EncodeToString(sum[:])},
		{name: "streamed", body: nil, streamed: true},
		{name: "truncated", body: []byte("partial"), truncated: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := dsctx.New("fingerprint-"+tc.name, dsctx.DefaultParseLimits())
			_, err := ProcessResponse(ctx, ResponseInput{
				Status: 200, ContentType: "application/pdf",
				ContentDisposition: `attachment; filename="report.pdf"`,
				Body:               tc.body, BodySize: int64(len(tc.body)), Streamed: tc.streamed, Truncated: tc.truncated,
			}, ResponseConfig{Mode: "OBSERVE"})
			if err != nil {
				t.Fatal(err)
			}
			obs := ctx.GetResponse().FileObservation
			if obs == nil || obs.ContentSHA256 != tc.want {
				t.Fatalf("unexpected download fingerprint: %+v", obs)
			}
		})
	}
}
