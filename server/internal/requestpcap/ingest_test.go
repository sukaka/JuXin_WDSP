package requestpcap

import (
	"bytes"
	"testing"
)

func TestArtifactFromManifestPreservesSealedEvidence(t *testing.T) {
	original := validTestArtifact(t)
	artifact, err := ArtifactFromManifest(original.Manifest, original.WrappedDEK, original.KeyID, original.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if artifact.ID != original.ID || artifact.NodeID != original.NodeID {
		t.Fatalf("manifest identity changed: %+v", artifact)
	}
	if artifact.State != "HOT" || artifact.StorageTier != "HOT" || artifact.PacketCount != original.PacketCount ||
		artifact.ChunkCount != original.ChunkCount || artifact.PlaintextSHA256 != original.PlaintextSHA256 {
		t.Fatalf("manifest facts changed: %+v", artifact)
	}
	if !bytes.Equal(artifact.WrappedDEK, original.WrappedDEK) || !bytes.Equal(artifact.Manifest, original.Manifest) {
		t.Fatal("key envelope or manifest was not preserved")
	}
	if _, err := ArtifactFromManifest([]byte(`{"format":"wdsp-encrypted-pcap","raw_body":"not-allowed"}`), original.WrappedDEK, original.KeyID, original.ExpiresAt); err == nil {
		t.Fatal("manifest with raw payload was accepted")
	}
}
