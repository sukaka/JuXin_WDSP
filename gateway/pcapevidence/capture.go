package pcapevidence

import (
	"context"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
)

type RequestAssembler interface {
	AssembleWithTimestamp(gopacket.Flow, *layers.TCP, time.Time)
	FlushWithOptions(tcpassembly.FlushOptions) (int, int)
}

// DEK 是单次分片密钥及其受控封装。Key只在创建加密器时短暂使用，不进入清单或日志。
type DEK struct {
	Key        []byte
	KeyID      string
	WrappedKey []byte
}

type DEKProvider interface {
	NewDEK(context.Context) (DEK, error)
}

type DEKProviderFunc func(context.Context) (DEK, error)

func (f DEKProviderFunc) NewDEK(ctx context.Context) (DEK, error) { return f(ctx) }

type CaptureConfig struct {
	Iface                   string
	Promiscuous             bool
	Ports                   []uint16
	NodeID                  string
	CapturePoint            string
	PolicyVersion           string
	HotDir                  string
	QueuePackets            int
	QueueBytes              int64
	SegmentMaxBytes         int64
	SegmentMaxSeconds       time.Duration
	MinFreePercent          int
	FilesystemUID           int
	FilesystemGID           int
	DEKProvider             DEKProvider
	RequestAssemblerFactory func(*RequestLinker) RequestAssembler
	SpoolOnly               bool
	OnSegment               func(context.Context, SealedSegment) error
}

// SealedSegment 仅供节点内交付；Path不得通过管理API暴露。
type SealedSegment struct {
	Manifest   Manifest
	KeyID      string
	WrappedKey []byte
	Path       string
	Requests   []RequestEvidence
}

type CaptureStats struct {
	PacketsSeen     uint64
	PacketsWritten  uint64
	PacketsFiltered uint64
	QueueDropped    uint64
	KernelDropped   uint64
	DeliveryErrors  uint64
	LinkDropped     uint64
	CapacityStops   uint64
}

type captureCounters struct {
	seen           atomic.Uint64
	written        atomic.Uint64
	filtered       atomic.Uint64
	queueDropped   atomic.Uint64
	kernelDropped  atomic.Uint64
	deliveryErrors atomic.Uint64
	linkDropped    atomic.Uint64
	capacityStops  atomic.Uint64
}

func (c *captureCounters) snapshot() CaptureStats {
	return CaptureStats{
		PacketsSeen: c.seen.Load(), PacketsWritten: c.written.Load(), PacketsFiltered: c.filtered.Load(),
		QueueDropped: c.queueDropped.Load(), KernelDropped: c.kernelDropped.Load(), DeliveryErrors: c.deliveryErrors.Load(),
		LinkDropped: c.linkDropped.Load(), CapacityStops: c.capacityStops.Load(),
	}
}

func validateCaptureConfig(config CaptureConfig) (CaptureConfig, error) {
	if config.Iface == "" || config.NodeID == "" || config.HotDir == "" || !filepath.IsAbs(config.HotDir) {
		return config, fmt.Errorf("capture interface, node and absolute hot directory are required")
	}
	if config.DEKProvider == nil {
		return config, fmt.Errorf("capture DEK provider is required")
	}
	if config.CapturePoint == "" {
		config.CapturePoint = "MIRROR"
	}
	if config.QueuePackets <= 0 {
		config.QueuePackets = 1024
	}
	if config.QueueBytes <= 0 {
		config.QueueBytes = 64 << 20
	}
	if config.SegmentMaxBytes <= 0 {
		config.SegmentMaxBytes = 256 << 20
	}
	if config.SegmentMaxSeconds <= 0 {
		config.SegmentMaxSeconds = time.Minute
	}
	if config.MinFreePercent == 0 {
		config.MinFreePercent = 10
	}
	if config.MinFreePercent < 0 || config.MinFreePercent > 95 {
		return config, fmt.Errorf("capture free-space watermark must be between 1 and 95 percent")
	}
	ports := make(map[uint16]struct{}, len(config.Ports))
	for _, port := range config.Ports {
		if port == 0 {
			return config, fmt.Errorf("capture port cannot be zero")
		}
		ports[port] = struct{}{}
	}
	if len(ports) == 0 {
		return config, fmt.Errorf("at least one explicit protected capture port is required")
	}
	return config, nil
}
