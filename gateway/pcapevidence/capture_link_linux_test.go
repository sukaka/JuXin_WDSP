//go:build linux

package pcapevidence

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

func TestRememberEvidenceMetadataNilSafeAndRaceFree(t *testing.T) {
	// Zero-value Capture simulates non-GATEWAY_EGRESS mode where evidenceArtifacts was previously nil.
	capture := &Capture{}
	firstID := testArtifactID(t)
	capture.rememberEvidenceMetadata(Manifest{Segment: Segment{ArtifactID: firstID, NodeID: "gw-mirror"}}, "key-1", []byte("w1"))

	capture.linkMu.Lock()
	if _, ok := capture.evidenceArtifacts[firstID]; !ok {
		capture.linkMu.Unlock()
		t.Fatal("rememberEvidenceMetadata did not store artifact metadata")
	}
	capture.linkMu.Unlock()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			id := testArtifactID(t)
			capture.rememberEvidenceMetadata(Manifest{
				Segment: Segment{ArtifactID: id, NodeID: "gw-race"},
				EndedAt: time.Now().UTC(),
			}, "key-id", []byte("wrapped"))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			capture.addRequestEvidence(RequestEvidence{
				RequestID:    fmt.Sprintf("req-race-%d", i),
				ConnectionID: fmt.Sprintf("conn-%d", i%8),
				CapturePoint: "GATEWAY_EGRESS",
				Method:       "GET",
				Path:         "/race",
			})
		}
	}()
	wg.Wait()
}

func TestFlushDeferredEvidenceUsesRestrictedWriterIdentity(t *testing.T) {
	artifactID := testArtifactID(t)
	hotDir := t.TempDir()
	capture := &Capture{
		config:             CaptureConfig{HotDir: hotDir, FilesystemUID: 1000, FilesystemGID: 1000},
		pendingRequests:    make(map[ArtifactID][]RequestEvidence),
		connectionRequests: make(map[string]map[string]RequestEvidence),
		orphanRequests:     make(map[string][]RequestEvidence),
		lastPacketRanges:   make(map[string]trackedPacketRange),
		evidenceArtifacts:  make(map[ArtifactID]storedEvidenceMetadata),
		deferredArtifacts:  make(map[ArtifactID]bool),
	}
	capture.rememberEvidenceMetadata(Manifest{Segment: Segment{ArtifactID: artifactID, NodeID: "gw-deferred"}}, "key-id", []byte("wrapped"))
	capture.lastPacketRanges["conn-1"] = trackedPacketRange{artifactID: artifactID, first: 1, last: 2, observedAt: time.Now().UTC()}
	capture.addRequestEvidence(RequestEvidence{RequestID: "req-1", ConnectionID: "conn-1", CapturePoint: "GATEWAY_EGRESS", Method: "GET", Path: "/v1/deferred"})

	origRestrict := restrictEvidenceWriterFn
	t.Cleanup(func() { restrictEvidenceWriterFn = origRestrict })

	// Failure in restrictEvidenceWriter must prevent writing deferred sidecars as root.
	restrictEvidenceWriterFn = func(uid, gid int) (func() error, error) {
		return nil, errors.New("injected fsuid failure")
	}
	if err := capture.flushDeferredEvidence(); err == nil {
		t.Fatal("expected error when restrictEvidenceWriter fails")
	}
	if entries, err := os.ReadDir(hotDir); err != nil || len(entries) != 0 {
		t.Fatalf("sidecar should not be written when identity restriction fails: entries=%d err=%v", len(entries), err)
	}

	// Success path must restrict to configured uid/gid and invoke restore afterward.
	var gotUID, gotGID int
	restored := false
	restrictEvidenceWriterFn = func(uid, gid int) (func() error, error) {
		gotUID, gotGID = uid, gid
		return func() error {
			restored = true
			return nil
		}, nil
	}
	if err := capture.flushDeferredEvidence(); err != nil {
		t.Fatalf("flushDeferredEvidence failed: %v", err)
	}
	if gotUID != 1000 || gotGID != 1000 || !restored {
		t.Fatalf("expected restrict(1000,1000) + restore, got uid=%d gid=%d restored=%t", gotUID, gotGID, restored)
	}
	if entries, err := os.ReadDir(hotDir); err != nil || len(entries) != 1 {
		t.Fatalf("expected 1 deferred sidecar after flush, got %d err=%v", len(entries), err)
	}
}

func buildTestTCPPacket(t *testing.T, srcPort, dstPort uint16) []byte {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IPv4(10, 0, 0, 1),
		DstIP:    net.IPv4(10, 0, 0, 2),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     1,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestActivePacketRangesAndConnectionRequestsAreBounded(t *testing.T) {
	linker, err := NewRequestLinker("gw-cap", "GATEWAY_EGRESS", nil)
	if err != nil {
		t.Fatal(err)
	}
	capture := &Capture{
		linker:             linker,
		pendingRequests:    make(map[ArtifactID][]RequestEvidence),
		connectionRequests: make(map[string]map[string]RequestEvidence),
		orphanRequests:     make(map[string][]RequestEvidence),
		lastPacketRanges:   make(map[string]trackedPacketRange),
		evidenceArtifacts:  make(map[ArtifactID]storedEvidenceMetadata),
		deferredArtifacts:  make(map[ArtifactID]bool),
	}
	capture.beginRequestLinkSegment(testArtifactID(t))

	const extra = 32
	for i := 0; i < maxTrackedPacketRanges+extra; i++ {
		pkt := buildTestTCPPacket(t, uint16(10000+i), 8080)
		capture.trackPacketConnection(pkt)
	}
	if got := len(capture.activePacketRanges); got != maxTrackedPacketRanges {
		t.Fatalf("activePacketRanges len=%d want cap %d", got, maxTrackedPacketRanges)
	}
	if dropped := capture.Stats().LinkDropped; dropped < extra {
		t.Fatalf("expected at least %d dropped active packet ranges, got %d", extra, dropped)
	}

	for i := 0; i < maxTrackedConnectionRequests+extra; i++ {
		capture.addRequestEvidence(RequestEvidence{
			RequestID:    fmt.Sprintf("req-%d", i),
			ConnectionID: fmt.Sprintf("conn-%d", i),
			CapturePoint: "GATEWAY_EGRESS",
			Method:       "GET",
			Path:         "/bounded",
		})
	}
	if got := len(capture.connectionRequests); got != maxTrackedConnectionRequests {
		t.Fatalf("connectionRequests leaked empty maps: len=%d want %d", got, maxTrackedConnectionRequests)
	}
	if capture.trackedRequestCount != maxTrackedConnectionRequests {
		t.Fatalf("trackedRequestCount=%d want %d", capture.trackedRequestCount, maxTrackedConnectionRequests)
	}
}
