package learning

import (
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func TestCandidateConfirmFreezeAndDeviationDoesNotWiden(t *testing.T) {
	s := NewStore()
	ep := "POST /v1/orders/{id}"
	cand, err := s.CreateCandidate(ep, map[string]string{"id": "number", "name": "string"})
	if err != nil {
		t.Fatal(err)
	}
	if cand.Status != StatusCandidate {
		t.Fatal(cand.Status)
	}
	formal, err := s.Confirm(cand.ID)
	if err != nil {
		t.Fatal(err)
	}
	if formal.Status != StatusFormal || formal.FrozenAt == nil {
		t.Fatalf("%+v", formal)
	}
	// immutability
	if err := s.MutateFormal(ep, map[string]string{"id": "number", "extra": "string"}); err != ErrFormalImmutable {
		t.Fatalf("mutate: %v", err)
	}
	schema := s.FormalSchema(ep)
	if _, ok := schema["extra"]; ok {
		t.Fatal("formal must not gain extra")
	}
	// deviation against frozen model does not call MutateFormal
	ctx := dsctx.New("e1", dsctx.DefaultParseLimits())
	observed := map[string]string{"id": "number", "extra": "string"}
	detectors.CheckSchemaDeviation(ctx, observed, schema)
	if ctx.MatchCount() < 1 {
		t.Fatal("expected deviation match")
	}
	// formal still without extra
	schema2 := s.FormalSchema(ep)
	if _, ok := schema2["extra"]; ok {
		t.Fatal("deviation must not widen formal")
	}
	if len(schema2) != 2 {
		t.Fatal(schema2)
	}
}

func TestConfirmOnlyCandidate(t *testing.T) {
	s := NewStore()
	v, _ := s.CreateCandidate("GET /x", map[string]string{"a": "string"})
	if _, err := s.Confirm(v.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Confirm(v.ID); err != ErrNotCandidate {
		t.Fatalf("got %v", err)
	}
}
