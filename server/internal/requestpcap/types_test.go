package requestpcap

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestValidateArtifactManifestAndKeyBoundaries(t *testing.T) {
	artifact := validTestArtifact(t)
	if err := ValidateArtifact(artifact); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "WrappedDEK") || strings.Contains(string(encoded), string(artifact.WrappedDEK)) {
		t.Fatalf("wrapped key leaked through JSON: %s", encoded)
	}

	mismatch := validTestArtifact(t)
	mismatch.PlaintextSHA256 = strings.Repeat("f", 64)
	if err := ValidateArtifact(mismatch); err == nil {
		t.Fatal("manifest hash mismatch was accepted")
	}
	unknown := validTestArtifact(t)
	var fields map[string]interface{}
	if err := json.Unmarshal(unknown.Manifest, &fields); err != nil {
		t.Fatal(err)
	}
	fields["raw_pcap"] = "not-allowed"
	unknown.Manifest, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateArtifact(unknown); err == nil {
		t.Fatal("unexpected raw payload key was accepted in manifest")
	}
	invalidKey := validTestArtifact(t)
	invalidKey.WrappedDEK = nil
	if err := ValidateArtifact(invalidKey); err == nil {
		t.Fatal("missing wrapped key was accepted")
	}
}

func TestValidateRequestLinkRequiresDirectEvidence(t *testing.T) {
	first, last := int64(1), int64(1)
	link := RequestLink{
		ArtifactID: uuid.New(), RequestID: "req-1", MatchStatus: "MATCHED",
		MatchBasis: "CONNECTION_EPOCH", Coverage: "CONNECTION", CandidateCount: 1,
		FirstPacketNo: &first, LastPacketNo: &last,
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	if err := ValidateRequestLink(link); err != nil {
		t.Fatal(err)
	}
	link.MatchBasis = "TIME_WINDOW"
	if err := ValidateRequestLink(link); err == nil {
		t.Fatal("time-only correlation was accepted as a matched request")
	}
	link.MatchBasis = "CONNECTION_EPOCH"
	link.CandidateCount = 2
	if err := ValidateRequestLink(link); err == nil {
		t.Fatal("multiple candidates were accepted as matched")
	}
	link.MatchStatus = "AMBIGUOUS"
	link.Coverage = "UNKNOWN"
	if err := ValidateRequestLink(link); err != nil {
		t.Fatalf("valid ambiguous evidence rejected: %v", err)
	}
}

func validTestArtifact(t *testing.T) Artifact {
	t.Helper()
	id := uuid.New()
	start := time.Now().UTC().Add(-time.Second)
	end := time.Now().UTC()
	artifact := Artifact{
		ID: id, NodeID: "gw-test", CapturePoint: "GATEWAY_INGRESS", State: "HOT", StorageTier: "HOT",
		CaptureStartedAt: start, CaptureEndedAt: end, PacketCount: 1, DroppedCount: 0,
		PlaintextSizeBytes: 64, CiphertextSizeBytes: 128,
		PlaintextSHA256: strings.Repeat("a", 64), CiphertextSHA256: strings.Repeat("b", 64),
		ChunkSizeBytes: 1024, ChunkCount: 1, WrappedDEK: []byte("wrapped-test-only"), KeyID: "key-test-1",
		PolicyVersion: "policy-1", ExpiresAt: end.Add(time.Hour),
	}
	manifest := map[string]interface{}{
		"format": "wdsp-encrypted-pcap", "format_version": 1,
		"segment": map[string]interface{}{
			"artifact_id": id.String(), "node_id": artifact.NodeID, "capture_point": artifact.CapturePoint,
			"started_at": start, "packet_count": 1, "dropped_count": 0, "truncated": false,
			"policy_version": artifact.PolicyVersion,
		},
		"ended_at": end, "size_plain": 64, "size_encrypted": 128,
		"sha256_plain": artifact.PlaintextSHA256, "sha256_encrypted": artifact.CiphertextSHA256,
		"encryption": map[string]interface{}{"algorithm": "AES-256-GCM", "chunk_size": 1024, "chunk_count": 1},
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	artifact.Manifest = encoded
	return artifact
}
