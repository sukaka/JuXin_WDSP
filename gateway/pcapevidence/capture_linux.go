//go:build linux

package pcapevidence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/tcpassembly"
)

type capturedPacket struct {
	data []byte
	info gopacket.CaptureInfo
}

type activeCaptureSegment struct {
	writer         *SegmentWriter
	pcap           *pcapgo.Writer
	timer          *time.Timer
	startedAt      time.Time
	packetCount    uint64
	queueDropStart uint64
	keyID          string
	wrappedKey     []byte
}

// Capture 是独立抓包与分片进程内核；业务转发不调用或等待它。
type Capture struct {
	config              CaptureConfig
	handle              packetSource
	assembler           RequestAssembler
	linker              *RequestLinker
	packets             chan capturedPacket
	stop                chan struct{}
	closeOnce           sync.Once
	queueMu             sync.Mutex
	queueBytes          int64
	counters            captureCounters
	linkMu              sync.Mutex
	activeLink          ArtifactID
	linkClosing         bool
	activePacketSeq     uint64
	activePacketRanges  map[string]packetRange
	pendingRequests     map[ArtifactID][]RequestEvidence
	connectionRequests  map[string]map[string]RequestEvidence
	orphanRequests      map[string][]RequestEvidence
	trackedRequestCount int
	lastPacketRanges    map[string]trackedPacketRange
	evidenceArtifacts   map[ArtifactID]storedEvidenceMetadata
	deferredArtifacts   map[ArtifactID]bool
	capacityCheck       func() error
	requestSync         sync.RWMutex
}

func NewCapture(config CaptureConfig) (*Capture, error) {
	config, err := validateCaptureConfig(config)
	if err != nil {
		return nil, err
	}
	handle, err := newPollPacketSource(config.Iface, config.Promiscuous)
	if err != nil {
		return nil, fmt.Errorf("open capture interface: %w", err)
	}
	stat, err := os.Stat(config.HotDir)
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("capture hot directory is unavailable: %w", err)
	}
	if !stat.IsDir() {
		handle.Close()
		return nil, fmt.Errorf("capture hot directory is not a directory")
	}
	capture := &Capture{
		config:            config,
		handle:            handle,
		packets:           make(chan capturedPacket, config.QueuePackets),
		stop:              make(chan struct{}),
		evidenceArtifacts: make(map[ArtifactID]storedEvidenceMetadata),
		deferredArtifacts: make(map[ArtifactID]bool),
	}
	if config.CapturePoint == "GATEWAY_EGRESS" {
		linker, err := NewRequestLinker(config.NodeID, config.CapturePoint, capture.addRequestEvidence)
		if err != nil {
			handle.Close()
			return nil, err
		}
		if config.RequestAssemblerFactory == nil {
			handle.Close()
			return nil, fmt.Errorf("trusted request correlation requires an HTTP request assembler")
		}
		capture.linker = linker
		capture.assembler = config.RequestAssemblerFactory(linker)
		if capture.assembler == nil {
			handle.Close()
			return nil, fmt.Errorf("HTTP request assembler is unavailable")
		}
		capture.pendingRequests = make(map[ArtifactID][]RequestEvidence)
		capture.connectionRequests = make(map[string]map[string]RequestEvidence)
		capture.orphanRequests = make(map[string][]RequestEvidence)
		capture.lastPacketRanges = make(map[string]trackedPacketRange)
	}
	return capture, nil
}

func (c *Capture) Stats() CaptureStats { return c.counters.snapshot() }

func (c *Capture) Run() error {
	writerDone := make(chan error, 1)
	writerReady := make(chan error, 1)
	go func() { writerDone <- c.writePackets(writerReady) }()
	if err := <-writerReady; err != nil {
		return err
	}
	var readErr error
	writerFinished := false
readLoop:
	for {
		select {
		case <-c.stop:
			break readLoop
		case err := <-writerDone:
			readErr = err
			writerFinished = true
			break readLoop
		default:
		}
		data, info, err := c.handle.ReadPacketData()
		if errors.Is(err, errCaptureReadTimeout) {
			continue
		}
		if err != nil {
			select {
			case <-c.stop:
			default:
				readErr = fmt.Errorf("read capture packet: %w", err)
			}
			break readLoop
		}
		c.counters.seen.Add(1)
		if !c.portMatches(data) {
			c.counters.filtered.Add(1)
			continue
		}
		if info.Timestamp.IsZero() {
			info.Timestamp = time.Now().UTC()
		}
		packet := capturedPacket{data: append([]byte(nil), data...), info: info}
		if !c.enqueue(packet) {
			c.counters.queueDropped.Add(1)
			continue
		}
		c.requestSync.RLock()
		c.trackPacketConnection(packet.data)
		c.assembleRequest(packet.data, info.Timestamp)
		c.requestSync.RUnlock()
	}
	if c.assembler != nil {
		c.requestSync.RLock()
		c.assembler.FlushWithOptions(tcpassembly.FlushOptions{T: time.Now(), CloseAll: true})
		c.requestSync.RUnlock()
	}
	close(c.packets)
	var writerErr error
	if !writerFinished {
		writerErr = <-writerDone
	}
	deferredErr := c.flushDeferredEvidence()
	c.counters.linkDropped.Add(uint64(c.countUnattachedRequests()))
	return errors.Join(readErr, writerErr, deferredErr)
}

func (c *Capture) portMatches(data []byte) bool {
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	if layer := packet.Layer(layers.LayerTypeTCP); layer != nil {
		tcp := layer.(*layers.TCP)
		return c.portAllowed(uint16(tcp.SrcPort)) || c.portAllowed(uint16(tcp.DstPort))
	}
	if layer := packet.Layer(layers.LayerTypeUDP); layer != nil {
		udp := layer.(*layers.UDP)
		return c.portAllowed(uint16(udp.SrcPort)) || c.portAllowed(uint16(udp.DstPort))
	}
	return false
}

func (c *Capture) portAllowed(port uint16) bool {
	for _, allowed := range c.config.Ports {
		if port == allowed {
			return true
		}
	}
	return false
}

func (c *Capture) enqueue(packet capturedPacket) bool {
	size := int64(len(packet.data))
	c.queueMu.Lock()
	if c.queueBytes+size > c.config.QueueBytes {
		c.queueMu.Unlock()
		return false
	}
	c.queueBytes += size
	c.queueMu.Unlock()
	select {
	case c.packets <- packet:
		return true
	default:
		c.queueMu.Lock()
		c.queueBytes -= size
		c.queueMu.Unlock()
		return false
	}
}

func (c *Capture) dequeue(packet capturedPacket) {
	c.queueMu.Lock()
	c.queueBytes -= int64(len(packet.data))
	c.queueMu.Unlock()
}

func (c *Capture) writePackets(ready chan<- error) (runErr error) {
	restore, err := restrictEvidenceWriterFn(c.config.FilesystemUID, c.config.FilesystemGID)
	if err != nil {
		ready <- err
		return err
	}
	defer func() {
		if err := restore(); err != nil {
			runErr = errors.Join(runErr, err)
		}
	}()
	active, err := c.startSegment(time.Now().UTC())
	if err != nil {
		ready <- err
		return err
	}
	ready <- nil
	for {
		var rotate <-chan time.Time
		if active != nil {
			rotate = active.timer.C
		}
		select {
		case packet, ok := <-c.packets:
			if !ok {
				if active != nil {
					return c.finishSegment(active)
				}
				return nil
			}
			c.dequeue(packet)
			if active != nil && active.writer.plainBytes+int64(len(packet.data))+16 > c.config.SegmentMaxBytes {
				if err := c.finishSegment(active); err != nil {
					return err
				}
				active = nil
			}
			if active == nil {
				active, err = c.startSegment(packet.info.Timestamp)
				if err != nil {
					return err
				}
			}
			if err := active.pcap.WritePacket(packet.info, packet.data); err != nil {
				_ = active.writer.Abort()
				return fmt.Errorf("write PCAP packet: %w", err)
			}
			active.packetCount++
			c.counters.written.Add(1)
		case <-rotate:
			if active != nil {
				if err := c.finishSegment(active); err != nil {
					return err
				}
				active, err = c.startSegment(time.Now().UTC())
				if err != nil {
					return err
				}
			}
		}
	}
}

func (c *Capture) startSegment(capturedAt time.Time) (*activeCaptureSegment, error) {
	capacityCheck := c.capacityCheck
	if capacityCheck == nil {
		capacityCheck = c.checkDiskCapacity
	}
	if err := capacityCheck(); err != nil {
		c.counters.capacityStops.Add(1)
		return nil, err
	}
	artifactID, err := NewArtifactID()
	if err != nil {
		return nil, err
	}
	dek, err := c.config.DEKProvider.NewDEK(context.Background())
	if err != nil {
		return nil, fmt.Errorf("obtain evidence DEK: %w", err)
	}
	if len(dek.KeyID) == 0 || len(dek.WrappedKey) == 0 {
		clear(dek.Key)
		return nil, fmt.Errorf("evidence DEK metadata is incomplete")
	}
	if capturedAt.IsZero() {
		capturedAt = time.Now().UTC()
	}
	segment := Segment{
		ArtifactID: artifactID, NodeID: c.config.NodeID, CapturePoint: c.config.CapturePoint,
		StartedAt: capturedAt, PolicyVersion: c.config.PolicyVersion,
	}
	path := filepath.Join(c.config.HotDir, artifactID.String()+".wpcap")
	writer, err := NewSegmentWriter(path, segment, dek.Key)
	clear(dek.Key)
	if err != nil {
		return nil, err
	}
	active := &activeCaptureSegment{
		writer: writer, pcap: pcapgo.NewWriter(writer), timer: time.NewTimer(c.config.SegmentMaxSeconds),
		startedAt: capturedAt, queueDropStart: c.counters.queueDropped.Load(),
		keyID: dek.KeyID, wrappedKey: append([]byte(nil), dek.WrappedKey...),
	}
	if err := active.pcap.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		_ = writer.Abort()
		return nil, err
	}
	active.writer.segment.PacketCount = 0
	c.beginRequestLinkSegment(artifactID)
	return active, nil
}

func (c *Capture) finishSegment(active *activeCaptureSegment) error {
	if active == nil {
		return nil
	}
	active.timer.Stop()
	artifactID := active.writer.segment.ArtifactID
	if active.packetCount == 0 {
		c.discardRequestLinkSegment(artifactID)
		return active.writer.Abort()
	}
	c.closeRequestLinkSegment(artifactID)
	active.writer.segment.PacketCount = active.packetCount
	active.writer.segment.DroppedCount = c.counters.queueDropped.Load() - active.queueDropStart
	_, kernelDelta, err := c.handle.Stats()
	if err != nil {
		active.writer.segment.Truncated = true
	} else {
		active.writer.segment.DroppedCount += uint64(kernelDelta)
		c.counters.kernelDropped.Add(uint64(kernelDelta))
	}
	if active.writer.segment.DroppedCount > 0 {
		active.writer.segment.Truncated = true
	}
	manifest, err := active.writer.Commit()
	if err != nil {
		c.discardRequestLinkSegment(artifactID)
		_ = active.writer.Abort()
		return err
	}
	sealed := SealedSegment{
		Manifest: manifest, Path: filepath.Join(c.config.HotDir, manifest.Segment.ArtifactID.String()+".wpcap"),
	}
	c.requestSync.Lock()
	sealed.Requests = c.takeRequestLinks(artifactID)
	c.requestSync.Unlock()
	sealed.KeyID = active.keyID
	sealed.WrappedKey = append([]byte(nil), active.wrappedKey...)
	c.rememberEvidenceMetadata(manifest, sealed.KeyID, sealed.WrappedKey)
	if err := c.deliverSegment(sealed); err != nil {
		c.counters.deliveryErrors.Add(1)
	}
	if err := c.flushDeferredEvidence(); err != nil {
		c.counters.deliveryErrors.Add(1)
	}
	return nil
}

func (c *Capture) deliverSegment(sealed SealedSegment) error {
	payload, err := json.Marshal(struct {
		Manifest   Manifest          `json:"manifest"`
		KeyID      string            `json:"key_id"`
		WrappedKey []byte            `json:"wrapped_key"`
		Requests   []RequestEvidence `json:"requests,omitempty"`
	}{Manifest: sealed.Manifest, KeyID: sealed.KeyID, WrappedKey: sealed.WrappedKey, Requests: sealed.Requests})
	if err != nil {
		return err
	}
	sidecar := sealed.Path + ".json"
	file, err := os.OpenFile(sidecar, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(sidecar)
		}
	}()
	if err := writeAll(file, payload); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	ok = true
	if c.config.SpoolOnly {
		return nil
	}
	if c.config.OnSegment == nil {
		return fmt.Errorf("evidence delivery callback is not configured; sidecar retained")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.config.OnSegment(ctx, sealed); err != nil {
		return fmt.Errorf("deliver evidence metadata: %w", err)
	}
	if err := os.Remove(sidecar); err != nil {
		return fmt.Errorf("remove delivered evidence sidecar: %w", err)
	}
	return nil
}

func (c *Capture) Close() error {
	c.closeOnce.Do(func() {
		close(c.stop)
		c.handle.Close()
	})
	return nil
}
