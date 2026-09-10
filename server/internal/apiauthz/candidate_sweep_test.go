package apiauthz

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestObjectReferenceIsDomainSeparatedAndOpaque(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	a := objectReference(key, "customer-123")
	b := objectReference(key, "customer-124")
	if !strings.HasPrefix(a, "objref:") || a == b || strings.Contains(a, "customer-123") {
		t.Fatalf("opaque refs invalid: a=%q b=%q", a, b)
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(a, "objref:")); err != nil {
		t.Fatalf("object ref payload is not hex: %v", err)
	}
}

func TestDecodeObjectHMACKeyRequires32ByteHex(t *testing.T) {
	if _, err := decodeObjectHMACKey("abcd"); err == nil {
		t.Fatal("short key accepted")
	}
	if _, err := decodeObjectHMACKey(strings.Repeat("01", 32)); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
}

func TestCandidateIdentityEligibility(t *testing.T) {
	for _, identityType := range []string{"BOT", "SERVICE", "APPLICATION", "AGENT", "MACHINE"} {
		if candidateIdentityEligible("VERIFIED", "fp:principal", identityType) {
			t.Fatalf("%s identity must not learn authorization relation", identityType)
		}
	}
	if candidateIdentityEligible("INVALID", "fp:principal", "HUMAN") ||
		candidateIdentityEligible("VERIFIED", "", "HUMAN") {
		t.Fatal("unverified or empty principal accepted")
	}
	if !candidateIdentityEligible("VERIFIED", "fp:principal", "HUMAN") {
		t.Fatal("verified human principal rejected")
	}
}

func TestCandidateSweepSelectClaimsEventsSafely(t *testing.T) {
	query := strings.Join(strings.Fields(candidateSweepSelectQuery), " ")
	for _, clause := range []string{"FOR UPDATE OF e SKIP LOCKED", "LEFT JOIN api_authz_candidate_event_receipts r ON r.event_id=e.id", "WHERE r.event_id IS NULL"} {
		if !strings.Contains(query, clause) {
			t.Fatalf("candidate sweep query missing %q: %s", clause, query)
		}
	}
}

func TestFrozenFanoutCandidatesCannotPolluteConfirmedRelations(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	applicationID := uuid.New()
	const objectRef = "objref:fanout-object"

	for i := 0; i < candidateFreezeLimit+1; i++ {
		principalID := fmt.Sprintf("principal-%d", i)
		candidate := store.addRelationCandidate(RelationCandidate{
			ApplicationID: applicationID,
			ObjectType:    "ORDER",
			ObjectRef:     objectRef,
			PrincipalID:   &principalID,
			Source:        CandidateSourceObserved,
			Status:        CandidateStatusFrozen,
			ConfidenceInputs: map[string]any{
				"freeze_reason": "principal_fanout",
			},
		})

		if _, err := store.ConfirmRelationCandidate(ctx, candidate.ID, ConfirmCandidateInput{
			Relation:    RelationOwner,
			Reason:      "AZ-11 regression",
			ConfirmedBy: "security-admin",
		}); err != ErrCandidateNotConfirmable {
			t.Fatalf("frozen candidate confirmation error = %v, want %v", err, ErrCandidateNotConfirmable)
		}
	}

	candidates, total, err := store.ListRelationCandidates(ctx, CandidateFilter{
		ApplicationID: &applicationID,
		Status:        CandidateStatusFrozen,
	})
	if err != nil {
		t.Fatalf("list frozen candidates: %v", err)
	}
	if total != int64(candidateFreezeLimit+1) || len(candidates) != candidateFreezeLimit+1 {
		t.Fatalf("frozen candidates = len:%d total:%d, want %d", len(candidates), total, candidateFreezeLimit+1)
	}

	confirmed, total, err := store.ListObjectRelations(ctx, RelationFilter{
		ApplicationID: &applicationID,
		Status:        RelationStatusConfirmed,
	})
	if err != nil {
		t.Fatalf("list confirmed relations: %v", err)
	}
	if total != 0 || len(confirmed) != 0 {
		t.Fatalf("confirmed relations after frozen fanout confirmations = len:%d total:%d, want zero", len(confirmed), total)
	}
}
