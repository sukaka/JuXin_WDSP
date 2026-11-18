//go:build linux

package pcapevidence

import (
	"os"
	"testing"
	"time"
)

func TestSpoolOnlyRetainsSealedMetadataWithoutDeliveryError(t *testing.T) {
	directory := t.TempDir()
	id := testArtifactID(t)
	path := directory + "/" + id.String() + ".wpcap"
	writer, err := NewSegmentWriter(path, Segment{ArtifactID: id, NodeID: "gw-spool", StartedAt: time.Now().UTC()}, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(testPCAP(t, 1)); err != nil {
		t.Fatal(err)
	}
	manifest, err := writer.Commit()
	if err != nil {
		t.Fatal(err)
	}
	capture := &Capture{config: CaptureConfig{SpoolOnly: true}}
	if err := capture.deliverSegment(SealedSegment{Manifest: manifest, Path: path, KeyID: "key", WrappedKey: []byte("wrapped")}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".json"); err != nil {
		t.Fatalf("spool metadata was not retained: %v", err)
	}
	if capture.Stats().DeliveryErrors != 0 {
		t.Fatal("normal local spool was counted as a delivery failure")
	}
}
