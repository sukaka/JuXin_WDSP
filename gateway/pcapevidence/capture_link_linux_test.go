//go:build linux

package pcapevidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRequestCorrelationContinuesAcrossSegments(t *testing.T) {
	first, second := testArtifactID(t), testArtifactID(t)
	capture := &Capture{pendingRequests: make(map[ArtifactID][]RequestEvidence),
		connectionRequests: make(map[string]map[string]RequestEvidence), orphanRequests: make(map[string][]RequestEvidence)}
	evidence := RequestEvidence{RequestID: "req-cross-segment", TraceID: "0123456789abcdef0123456789abcdef", ConnectionID: "connection-1",
		CapturePoint: "GATEWAY_EGRESS", Method: "GET", Path: "/v1/evidence"}
	capture.addRequestEvidence(evidence)
	capture.beginRequestLinkSegment(first)
	capture.activePacketRanges[evidence.ConnectionID] = packetRange{first: 1, last: 2}
	capture.attachPendingLocked(evidence.ConnectionID, capture.activePacketRanges[evidence.ConnectionID])
	links := capture.takeRequestLinks(first)
	if len(links) != 1 || links[0].FirstPacketNo != 1 || links[0].LastPacketNo != 2 {
		t.Fatalf("first segment link incorrect: %+v", links)
	}
	capture.beginRequestLinkSegment(second)
	capture.activePacketRanges[evidence.ConnectionID] = packetRange{first: 1, last: 1}
	capture.attachPendingLocked(evidence.ConnectionID, capture.activePacketRanges[evidence.ConnectionID])
	links = capture.takeRequestLinks(second)
	if len(links) != 1 || links[0].RequestID != evidence.RequestID || links[0].LastPacketNo != 1 {
		t.Fatalf("continuation segment link incorrect: %+v", links)
	}
	capture.forgetConnectionLocked(evidence.ConnectionID)
	if capture.trackedRequestCount != 0 || capture.countUnattachedRequests() != 0 {
		t.Fatal("connection state was not released")
	}
}

func TestLateRequestEvidenceUsesOriginalArtifactAndSupplementalSpool(t *testing.T) {
	artifactID := testArtifactID(t)
	capture := &Capture{config: CaptureConfig{HotDir: t.TempDir()}, pendingRequests: make(map[ArtifactID][]RequestEvidence),
		connectionRequests: make(map[string]map[string]RequestEvidence), orphanRequests: make(map[string][]RequestEvidence),
		lastPacketRanges: make(map[string]trackedPacketRange), evidenceArtifacts: make(map[ArtifactID]storedEvidenceMetadata), deferredArtifacts: make(map[ArtifactID]bool)}
	evidence := RequestEvidence{RequestID: "req-late", ConnectionID: "connection-late", CapturePoint: "GATEWAY_EGRESS", Method: "GET", Path: "/v1/late"}
	capture.rememberEvidenceMetadata(Manifest{Segment: Segment{ArtifactID: artifactID, NodeID: "gw-late"}}, "key-id", []byte("wrapped"))
	capture.lastPacketRanges[evidence.ConnectionID] = trackedPacketRange{artifactID: artifactID, first: 4, last: 8, observedAt: time.Now()}
	capture.addRequestEvidence(evidence)
	if !capture.deferredArtifacts[artifactID] || len(capture.pendingRequests[artifactID]) != 1 {
		t.Fatal("late evidence did not reference the original artifact")
	}
	if err := capture.flushDeferredEvidence(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(capture.config.HotDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("supplemental sidecar missing: %+v err=%v", entries, err)
	}
	payload, err := os.ReadFile(filepath.Join(capture.config.HotDir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Manifest Manifest          `json:"manifest"`
		Requests []RequestEvidence `json:"requests"`
	}
	if err := json.Unmarshal(payload, &record); err != nil {
		t.Fatal(err)
	}
	if record.Manifest.Segment.ArtifactID != artifactID || len(record.Requests) != 1 || record.Requests[0].FirstPacketNo != 4 || record.Requests[0].LastPacketNo != 8 {
		t.Fatalf("supplemental evidence points to the wrong artifact: %+v", record)
	}
}

func TestLateEvidenceDuringSealJoinsOriginalSegment(t *testing.T) {
	artifactID := testArtifactID(t)
	capture := &Capture{pendingRequests: make(map[ArtifactID][]RequestEvidence),
		connectionRequests: make(map[string]map[string]RequestEvidence), orphanRequests: make(map[string][]RequestEvidence),
		lastPacketRanges: make(map[string]trackedPacketRange), evidenceArtifacts: make(map[ArtifactID]storedEvidenceMetadata), deferredArtifacts: make(map[ArtifactID]bool)}
	evidence := RequestEvidence{RequestID: "req-during-seal", ConnectionID: "connection-seal", CapturePoint: "GATEWAY_EGRESS", Method: "GET", Path: "/v1/seal"}
	capture.lastPacketRanges[evidence.ConnectionID] = trackedPacketRange{artifactID: artifactID, first: 3, last: 7, observedAt: time.Now()}
	capture.addRequestEvidence(evidence)
	if capture.countUnattachedRequests() != 1 {
		t.Fatal("unsealed evidence was incorrectly treated as already linked")
	}
	links := capture.takeRequestLinks(artifactID)
	if len(links) != 1 || links[0].FirstPacketNo != 3 || links[0].LastPacketNo != 7 {
		t.Fatalf("late request was not included in the sealed segment: %+v", links)
	}
	if capture.countUnattachedRequests() != 0 {
		t.Fatal("sealed segment left a late request unattached")
	}
}
