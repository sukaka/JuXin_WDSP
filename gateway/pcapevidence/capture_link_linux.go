//go:build linux

package pcapevidence

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type packetRange struct {
	first uint64
	last  uint64
}

type trackedPacketRange struct {
	artifactID ArtifactID
	first      uint64
	last       uint64
	observedAt time.Time
}

type storedEvidenceMetadata struct {
	manifest   Manifest
	keyID      string
	wrappedKey []byte
}

const (
	maxTrackedConnectionRequests = 4096
	maxTrackedRequestsPerSegment = 256
	maxTrackedPacketRanges       = 4096
	maxStoredEvidenceMetadata    = 4096
)

func (c *Capture) trackPacketConnection(data []byte) {
	if c.linker == nil {
		return
	}
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	network := packet.NetworkLayer()
	if network == nil {
		return
	}
	tcp := tcpLayer.(*layers.TCP)
	flow := network.NetworkFlow()
	meta := FlowMeta{
		SrcIP: flow.Src().String(), SrcPort: uint16(tcp.SrcPort),
		DstIP: flow.Dst().String(), DstPort: uint16(tcp.DstPort),
	}
	connectionID := c.linker.ConnectionID(meta)
	c.linkMu.Lock()
	defer c.linkMu.Unlock()
	if tcp.SYN && !tcp.ACK {
		c.forgetConnectionLocked(connectionID)
	}
	if c.activeLink.IsZero() || c.linkClosing {
		return
	}
	c.activePacketSeq++
	if c.activePacketRanges == nil {
		c.activePacketRanges = make(map[string]packetRange)
	}
	bounds, tracked := c.activePacketRanges[connectionID]
	if !tracked {
		if len(c.activePacketRanges) >= maxTrackedPacketRanges {
			c.counters.linkDropped.Add(1)
			return
		}
		bounds.first = c.activePacketSeq
	}
	bounds.last = c.activePacketSeq
	c.activePacketRanges[connectionID] = bounds
	c.rememberPacketRangeLocked(connectionID, trackedPacketRange{artifactID: c.activeLink, first: bounds.first, last: bounds.last, observedAt: time.Now().UTC()})
	c.attachPendingLocked(connectionID, bounds)
}

func (c *Capture) assembleRequest(data []byte, capturedAt time.Time) {
	if c.assembler == nil {
		return
	}
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	tcp := tcpLayer.(*layers.TCP)
	// PCAP仍保留双方向包；请求ID解析只处理命中保护端口的目标方向，避免把响应当请求。
	if !c.portAllowed(uint16(tcp.DstPort)) {
		return
	}
	network := packet.NetworkLayer()
	if network == nil {
		return
	}
	c.assembler.AssembleWithTimestamp(network.NetworkFlow(), tcp, capturedAt)
}

func (c *Capture) addRequestEvidence(evidence RequestEvidence) {
	c.linkMu.Lock()
	defer c.linkMu.Unlock()
	requests := c.connectionRequests[evidence.ConnectionID]
	known, exists := requests[evidence.RequestID]
	if exists {
		evidence = known
	} else {
		if c.trackedRequestCount >= maxTrackedConnectionRequests ||
			(requests == nil && len(c.connectionRequests) >= maxTrackedConnectionRequests) {
			c.counters.linkDropped.Add(1)
			return
		}
		if requests == nil {
			if c.connectionRequests == nil {
				c.connectionRequests = make(map[string]map[string]RequestEvidence)
			}
			requests = make(map[string]RequestEvidence)
			c.connectionRequests[evidence.ConnectionID] = requests
		}
		requests[evidence.RequestID] = evidence
		c.trackedRequestCount++
	}
	bounds, hasBounds := c.activePacketRanges[evidence.ConnectionID]
	if !c.activeLink.IsZero() && hasBounds && !c.linkClosing {
		c.appendRequestLocked(c.activeLink, evidence, bounds)
		return
	}
	if last, ok := c.lastPacketRanges[evidence.ConnectionID]; ok {
		if _, exists := c.evidenceArtifacts[last.artifactID]; exists {
			if c.appendRequestLocked(last.artifactID, evidence, packetRange{first: last.first, last: last.last}) {
				if c.deferredArtifacts == nil {
					c.deferredArtifacts = make(map[ArtifactID]bool)
				}
				c.deferredArtifacts[last.artifactID] = true
			}
			return
		}
	}
	if !exists {
		if c.orphanRequests == nil {
			c.orphanRequests = make(map[string][]RequestEvidence)
		}
		c.orphanRequests[evidence.ConnectionID] = append(c.orphanRequests[evidence.ConnectionID], evidence)
	}
}

func (c *Capture) appendRequestLocked(id ArtifactID, evidence RequestEvidence, bounds packetRange) bool {
	if id.IsZero() {
		return false
	}
	if c.pendingRequests == nil {
		c.pendingRequests = make(map[ArtifactID][]RequestEvidence)
	}
	links := c.pendingRequests[id]
	for _, existing := range links {
		if existing.RequestID == evidence.RequestID && existing.ConnectionID == evidence.ConnectionID {
			return true
		}
	}
	if len(links) >= maxTrackedRequestsPerSegment {
		c.counters.linkDropped.Add(1)
		return false
	}
	evidence.FirstPacketNo = bounds.first
	evidence.LastPacketNo = bounds.last
	c.pendingRequests[id] = append(links, evidence)
	return true
}

func (c *Capture) attachPendingLocked(connectionID string, bounds packetRange) {
	if c.activeLink.IsZero() {
		return
	}
	for _, evidence := range c.connectionRequests[connectionID] {
		c.appendRequestLocked(c.activeLink, evidence, bounds)
	}
	orphans := c.orphanRequests[connectionID]
	remaining := orphans[:0]
	for _, evidence := range orphans {
		if !c.appendRequestLocked(c.activeLink, evidence, bounds) {
			remaining = append(remaining, evidence)
		}
	}
	if len(remaining) == 0 {
		delete(c.orphanRequests, connectionID)
	} else {
		c.orphanRequests[connectionID] = remaining
	}
}

func (c *Capture) rememberPacketRangeLocked(connectionID string, value trackedPacketRange) {
	if c.lastPacketRanges == nil {
		c.lastPacketRanges = make(map[string]trackedPacketRange)
	}
	if _, exists := c.lastPacketRanges[connectionID]; !exists && len(c.lastPacketRanges) >= maxTrackedPacketRanges {
		var oldestID string
		var oldest time.Time
		for id, current := range c.lastPacketRanges {
			if oldestID == "" || current.observedAt.Before(oldest) {
				oldestID, oldest = id, current.observedAt
			}
		}
		delete(c.lastPacketRanges, oldestID)
	}
	c.lastPacketRanges[connectionID] = value
}

func (c *Capture) rememberEvidenceMetadata(manifest Manifest, keyID string, wrappedKey []byte) {
	c.linkMu.Lock()
	defer c.linkMu.Unlock()
	if c.evidenceArtifacts == nil {
		c.evidenceArtifacts = make(map[ArtifactID]storedEvidenceMetadata)
	}
	if _, exists := c.evidenceArtifacts[manifest.Segment.ArtifactID]; !exists && len(c.evidenceArtifacts) >= maxStoredEvidenceMetadata {
		var oldestID ArtifactID
		var oldest time.Time
		for id, current := range c.evidenceArtifacts {
			if oldestID.IsZero() || current.manifest.EndedAt.Before(oldest) {
				oldestID, oldest = id, current.manifest.EndedAt
			}
		}
		delete(c.evidenceArtifacts, oldestID)
		delete(c.deferredArtifacts, oldestID)
		if dropped := len(c.pendingRequests[oldestID]); dropped > 0 {
			c.counters.linkDropped.Add(uint64(dropped))
		}
		delete(c.pendingRequests, oldestID)
	}
	c.evidenceArtifacts[manifest.Segment.ArtifactID] = storedEvidenceMetadata{manifest: manifest, keyID: keyID, wrappedKey: append([]byte(nil), wrappedKey...)}
}

func (c *Capture) flushDeferredEvidence() (flushErr error) {
	c.linkMu.Lock()
	if len(c.deferredArtifacts) == 0 {
		c.linkMu.Unlock()
		return nil
	}
	c.linkMu.Unlock()

	restore, err := restrictEvidenceWriterFn(c.config.FilesystemUID, c.config.FilesystemGID)
	if err != nil {
		return err
	}
	defer func() {
		if err := restore(); err != nil {
			flushErr = errors.Join(flushErr, err)
		}
	}()

	c.linkMu.Lock()
	defer c.linkMu.Unlock()
	for id := range c.deferredArtifacts {
		metadata, exists := c.evidenceArtifacts[id]
		requests := append([]RequestEvidence(nil), c.pendingRequests[id]...)
		if !exists || len(requests) == 0 {
			delete(c.deferredArtifacts, id)
			continue
		}
		supplementID, err := NewArtifactID()
		if err != nil {
			return err
		}
		path := filepath.Join(c.config.HotDir, id.String()+"."+supplementID.String()+".wpcap.json")
		payload, err := json.Marshal(struct {
			Manifest   Manifest          `json:"manifest"`
			KeyID      string            `json:"key_id"`
			WrappedKey []byte            `json:"wrapped_key"`
			Requests   []RequestEvidence `json:"requests"`
		}{Manifest: metadata.manifest, KeyID: metadata.keyID, WrappedKey: metadata.wrappedKey, Requests: requests})
		if err != nil {
			return err
		}
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		writeErr := writeAll(file, payload)
		if writeErr == nil {
			writeErr = file.Sync()
		}
		if closeErr := file.Close(); writeErr == nil {
			writeErr = closeErr
		}
		if writeErr != nil {
			_ = os.Remove(path)
			return fmt.Errorf("deliver supplemental evidence: %w", writeErr)
		}
		delete(c.pendingRequests, id)
		delete(c.deferredArtifacts, id)
	}
	return nil
}

func (c *Capture) forgetConnectionLocked(connectionID string) {
	requests := c.connectionRequests[connectionID]
	c.trackedRequestCount -= len(requests)
	delete(c.connectionRequests, connectionID)
	c.counters.linkDropped.Add(uint64(len(c.orphanRequests[connectionID])))
	delete(c.orphanRequests, connectionID)
	delete(c.lastPacketRanges, connectionID)
}

func (c *Capture) pruneIdleConnectionsLocked(now time.Time) {
	for connectionID, last := range c.lastPacketRanges {
		if now.Sub(last.observedAt) >= 10*time.Minute {
			c.forgetConnectionLocked(connectionID)
		}
	}
}

func (c *Capture) countUnattachedRequests() int {
	c.linkMu.Lock()
	defer c.linkMu.Unlock()
	count := 0
	for _, requests := range c.orphanRequests {
		count += len(requests)
	}
	return count
}

func (c *Capture) beginRequestLinkSegment(id ArtifactID) {
	c.linkMu.Lock()
	c.pruneIdleConnectionsLocked(time.Now().UTC())
	c.activeLink = id
	c.linkClosing = false
	c.activePacketSeq = 0
	c.activePacketRanges = make(map[string]packetRange)
	c.linkMu.Unlock()
}

func (c *Capture) closeRequestLinkSegment(id ArtifactID) {
	c.linkMu.Lock()
	if c.activeLink == id {
		c.linkClosing = true
	}
	c.linkMu.Unlock()
}

func (c *Capture) takeRequestLinks(id ArtifactID) []RequestEvidence {
	c.linkMu.Lock()
	defer c.linkMu.Unlock()
	for connectionID, orphans := range c.orphanRequests {
		last, exists := c.lastPacketRanges[connectionID]
		if !exists || last.artifactID != id {
			continue
		}
		remaining := orphans[:0]
		for _, evidence := range orphans {
			if !c.appendRequestLocked(id, evidence, packetRange{first: last.first, last: last.last}) {
				remaining = append(remaining, evidence)
			}
		}
		if len(remaining) == 0 {
			delete(c.orphanRequests, connectionID)
		} else {
			c.orphanRequests[connectionID] = remaining
		}
	}
	links := append([]RequestEvidence(nil), c.pendingRequests[id]...)
	delete(c.pendingRequests, id)
	if c.activeLink == id {
		c.activeLink = ArtifactID{}
		c.linkClosing = false
		c.activePacketSeq = 0
		c.activePacketRanges = nil
	}
	return links
}

func (c *Capture) discardRequestLinkSegment(id ArtifactID) {
	c.linkMu.Lock()
	delete(c.pendingRequests, id)
	if c.activeLink == id {
		c.activeLink = ArtifactID{}
		c.linkClosing = false
		c.activePacketSeq = 0
		c.activePacketRanges = nil
	}
	c.linkMu.Unlock()
}
