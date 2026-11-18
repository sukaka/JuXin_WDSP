//go:build linux

package pcapevidence

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCaptureQueueIsBounded(t *testing.T) {
	capture := &Capture{
		config:  CaptureConfig{QueuePackets: 1, QueueBytes: 64},
		packets: make(chan capturedPacket, 1),
	}
	first := capturedPacket{data: make([]byte, 32)}
	if !capture.enqueue(first) {
		t.Fatal("first packet did not enter bounded queue")
	}
	if capture.enqueue(capturedPacket{data: make([]byte, 32)}) {
		t.Fatal("packet count limit was bypassed")
	}
	capture.dequeue(<-capture.packets)
	if !capture.enqueue(capturedPacket{data: make([]byte, 32)}) {
		t.Fatal("released queue capacity was not reusable")
	}
	capture.dequeue(<-capture.packets)
	// 用独立Capture验证字节水位，不受包数通道容量影响。
	capture = &Capture{config: CaptureConfig{QueuePackets: 2, QueueBytes: 32}, packets: make(chan capturedPacket, 2)}
	if !capture.enqueue(first) || capture.enqueue(first) {
		t.Fatal("byte-based queue limit was not enforced")
	}
}

func TestCaptureDeliveryFailureRetainsEvidenceAndSidecar(t *testing.T) {
	directory := t.TempDir()
	id := testArtifactID(t)
	path := filepath.Join(directory, id.String()+".wpcap")
	key := make([]byte, 32)
	writer, err := NewSegmentWriter(path, Segment{ArtifactID: id, NodeID: "gw-test", StartedAt: time.Now().UTC()}, key)
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
	capture := &Capture{config: CaptureConfig{OnSegment: func(context.Context, SealedSegment) error {
		return errors.New("injected metadata delivery failure")
	}}}
	sealed := SealedSegment{Manifest: manifest, Path: path, KeyID: "key-test", WrappedKey: []byte("wrapped-test")}
	if err := capture.deliverSegment(sealed); err == nil {
		t.Fatal("delivery failure was hidden")
	}
	sidecar, err := os.ReadFile(path + ".json")
	if err != nil {
		t.Fatalf("delivery failure did not retain sidecar: %v", err)
	}
	var record struct {
		Manifest   Manifest `json:"manifest"`
		KeyID      string   `json:"key_id"`
		WrappedKey []byte   `json:"wrapped_key"`
	}
	if err := json.Unmarshal(sidecar, &record); err != nil {
		t.Fatal(err)
	}
	if record.Manifest.Segment.ArtifactID != id || record.KeyID != "key-test" {
		t.Fatalf("sidecar evidence identity mismatch: %+v", record)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("sealed evidence is missing after delivery failure: %v", err)
	}
}
