package apiauthz

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/encryption"
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

type objectKeyWinnerSettingsKV struct {
	winner  string
	found   bool
	readErr error
}

func (f *objectKeyWinnerSettingsKV) GetString(context.Context, string, string, string) string {
	return ""
}

func (f *objectKeyWinnerSettingsKV) UpsertString(context.Context, string, string, string, string, uuid.UUID) error {
	return nil
}

func (f *objectKeyWinnerSettingsKV) GetStringWithSource(context.Context, string, string) (string, bool, error) {
	if f.readErr != nil {
		return "", false, f.readErr
	}
	return f.winner, f.found || f.winner != "", nil
}

func (f *objectKeyWinnerSettingsKV) CreateStringIfAbsent(context.Context, string, string, string, string, uuid.UUID) (bool, error) {
	return false, nil
}

func TestLoadOrCreateObjectHMACKeyUsesDatabaseWinnerAfterAtomicCreateRace(t *testing.T) {
	master := make([]byte, 32)
	enc, err := encryption.NewWithKey(master)
	if err != nil {
		t.Fatal(err)
	}
	winnerKey := strings.Repeat("cd", 32)
	winnerCipher, err := enc.Encrypt(winnerKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := LoadOrCreateObjectHMACKey(context.Background(), &objectKeyWinnerSettingsKV{winner: winnerCipher}, enc)
	if err != nil {
		t.Fatal(err)
	}
	if got != winnerKey {
		t.Fatal("losing initializer must use the database winner")
	}
}

func TestLoadOrCreateObjectHMACKeyDoesNotTreatReadFailureAsMissing(t *testing.T) {
	master := make([]byte, 32)
	enc, err := encryption.NewWithKey(master)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateObjectHMACKey(context.Background(), &objectKeyWinnerSettingsKV{readErr: errors.New("settings unavailable")}, enc); err == nil {
		t.Fatal("settings read failure must be returned")
	}
}

func TestLoadOrCreateObjectHMACKeyDoesNotTreatEmptyStoredValueAsMissing(t *testing.T) {
	master := make([]byte, 32)
	enc, err := encryption.NewWithKey(master)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateObjectHMACKey(context.Background(), &objectKeyWinnerSettingsKV{found: true}, enc); err == nil {
		t.Fatal("empty stored object HMAC key must be rejected")
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
