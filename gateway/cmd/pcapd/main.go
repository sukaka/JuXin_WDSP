package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jiuzhang-waf/gateway/pcapcapture"
	"github.com/jiuzhang-waf/gateway/pcapevidence"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "pcapd error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	iface := flag.String("iface", os.Getenv("REQUEST_PCAP_IFACE"), "受控抓包网卡，必须显式指定")
	ports := flag.String("ports", os.Getenv("REQUEST_PCAP_PORTS"), "受控监听端口，逗号分隔，必须显式指定")
	node := flag.String("node", os.Getenv("GATEWAY_NODE_NAME"), "网关节点ID")
	hotDir := flag.String("hot-dir", envOrDefault("REQUEST_PCAP_HOT_DIR", "/var/lib/jiuzhang/pcap-hot"), "SSD加密证据热目录")
	grantPath := flag.String("grant", envOrDefault("REQUEST_PCAP_GRANT", "/etc/jiuzhang/pcap-public.json"), "管理面签名的节点公钥授权")
	trustPath := flag.String("trust", envOrDefault("REQUEST_PCAP_TRUST", "/etc/jiuzhang/pcap-release.pub"), "安装时固定的发布验签公钥")
	policyVersion := flag.String("policy-version", os.Getenv("REQUEST_PCAP_POLICY_VERSION"), "已审核的抓包策略版本")
	promiscuous := flag.Bool("promiscuous", false, "是否启用混杂模式；默认关闭")
	segmentSeconds := flag.Int("segment-seconds", 60, "分片封口周期（秒）")
	minFreePercent := flag.Int("min-free-percent", 10, "热盘最小剩余空间百分比")
	flag.Parse()
	allowedPorts, err := parsePorts(*ports)
	if err != nil {
		return err
	}
	if *segmentSeconds < 1 || *segmentSeconds > 3600 {
		return fmt.Errorf("segment-seconds must be between 1 and 3600")
	}
	provider, err := pcapevidence.NewSignedPublicKeyProvider(*trustPath, *grantPath, *node)
	if err != nil {
		return fmt.Errorf("validate evidence public key: %w", err)
	}
	capture, err := pcapcapture.NewCapture(pcapcapture.CaptureConfig{
		Iface: *iface, Ports: allowedPorts, Promiscuous: *promiscuous, NodeID: *node, CapturePoint: "GATEWAY_EGRESS",
		PolicyVersion: *policyVersion, HotDir: *hotDir, DEKProvider: provider, SpoolOnly: true,
		QueuePackets: 4096, QueueBytes: 128 << 20, SegmentMaxBytes: 256 << 20,
		SegmentMaxSeconds: time.Duration(*segmentSeconds) * time.Second, MinFreePercent: *minFreePercent,
	})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		if err := capture.Close(); err != nil {
			log.Printf("pcapd close failed: %v", err)
		}
	}()
	log.Printf("pcapd started node=%s iface=%s ports=%v promiscuous=%t", *node, *iface, allowedPorts, *promiscuous)
	if err := capture.Run(); err != nil {
		return err
	}
	stats := capture.Stats()
	log.Printf("pcapd stopped packets=%d written=%d queue_dropped=%d kernel_dropped=%d link_dropped=%d delivery_errors=%d capacity_stops=%d",
		stats.PacketsSeen, stats.PacketsWritten, stats.QueueDropped, stats.KernelDropped, stats.LinkDropped, stats.DeliveryErrors, stats.CapacityStops)
	return nil
}

func parsePorts(value string) ([]uint16, error) {
	parts := strings.Split(value, ",")
	if len(parts) == 0 || len(parts) > 128 {
		return nil, fmt.Errorf("capture ports must contain 1 to 128 explicit ports")
	}
	result := make([]uint16, 0, len(parts))
	seen := make(map[uint16]bool)
	for _, part := range parts {
		port, err := strconv.ParseUint(strings.TrimSpace(part), 10, 16)
		if err != nil || port == 0 || seen[uint16(port)] {
			return nil, fmt.Errorf("invalid or duplicate capture port %q", part)
		}
		seen[uint16(port)] = true
		result = append(result, uint16(port))
	}
	return result, nil
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
