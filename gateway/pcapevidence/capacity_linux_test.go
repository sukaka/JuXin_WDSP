//go:build linux

package pcapevidence

import (
	"errors"
	"testing"
	"time"
)

func TestCaptureStopsBeforeCreatingEvidenceAtLowDiskWatermark(t *testing.T) {
	capture := &Capture{config: CaptureConfig{HotDir: t.TempDir()}, capacityCheck: func() error {
		return errors.New("injected low disk watermark")
	}}
	segment, err := capture.startSegment(time.Now())
	if err == nil || segment != nil {
		t.Fatal("capture created a segment below the disk watermark")
	}
	if capture.Stats().CapacityStops != 1 {
		t.Fatal("disk capacity stop was not counted")
	}
}
