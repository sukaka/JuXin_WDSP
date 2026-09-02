package identitybehavior

import (
	"net/url"
	"testing"
)

func TestIdentifierKeyIsStableAndHashed(t *testing.T) {
	query := url.Values{"Account_ID": {"alice"}, "object_id": {"42"}}
	got := identifierKey(query, []string{"account_id"})
	if got == "" || got == "alice" || got != identifierKey(query, []string{"ACCOUNT_ID"}) {
		t.Fatalf("identifier key is not normalized/hashed: %q", got)
	}
	if identifierKey(url.Values{"account_id": {""}}, []string{"account_id"}) != "" {
		t.Fatal("empty identifier must be ignored")
	}
}

func TestEnumerationExcludedPaginationAndBatch(t *testing.T) {
	if !enumerationExcluded("/v1/users", url.Values{"account": {"alice"}, "page": {"2"}}) {
		t.Fatal("pagination requests must be excluded")
	}
	if !enumerationExcluded("/v1/users/batch", url.Values{"account": {"alice"}}) {
		t.Fatal("batch endpoints must be excluded")
	}
	if enumerationExcluded("/v1/users", url.Values{"account": {"alice"}}) {
		t.Fatal("ordinary identifier requests must remain eligible")
	}
}

func TestEnumerationSignalRequiresIdentityConfidence(t *testing.T) {
	threshold := int64(2)
	cfg, err := Compile(&Params{Enabled: true, AccountEnumThreshold: &threshold}, nil)
	if err != nil {
		t.Fatal(err)
	}
	snap := &Snapshot{}
	snap.Windows[Window5m].AccountEnumCount = 2
	if got := EvaluateRecon(cfg, snap, ""); len(got) != 0 {
		t.Fatalf("anonymous identity emitted enumeration signal: %#v", got)
	}
	snap.IdentityConfidence = 40
	snap.Windows[Window5m].RequestCount = 3
	snap.Windows[Window5m].Status401Count = 1
	got := EvaluateRecon(cfg, snap, "")
	if len(got) != 1 || got[0].Signal != SignalAccountEnumeration {
		t.Fatalf("expected account enumeration signal, got %#v", got)
	}
	if got[0].Metadata["request_count"] != int64(3) || got[0].Metadata["status_401_count"] != int64(1) {
		t.Fatalf("enumeration evidence missing response context: %#v", got[0].Metadata)
	}
	if fields, ok := got[0].Metadata["identifier_fields"].([]string); !ok || len(fields) == 0 {
		t.Fatalf("enumeration evidence missing identifier fields: %#v", got[0].Metadata)
	}
}
