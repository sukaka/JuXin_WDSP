package main

import (
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/jiuzhang-waf/gateway/mirrorcap"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/netif"
)

const (
	netifSysfsDir        = "/sys/class/net"
	netifSnapshotName    = "node-interfaces.jsonl"
	netifCollectInterval = 60 * time.Second
)

// startNetifReporter 常驻采集物理网口清单并原子写入 node-interfaces.jsonl（与事件日志同目录）。
// 解决纯镜像部署场景下 Caddy 尚未加载任何内联站点（未实例化 jiuzhang_guard）导致
// 「系统运维 → 网口管理」无网口可选、无法标记镜像口的鸡生蛋死锁问题。
func startNetifReporter(base mirrorcap.Config, cfgPath string, stop <-chan struct{}) {
	if _, err := os.Stat(netifSysfsDir); err != nil {
		log.Printf("[mirrorcap] netif reporter skipped (sysfs unavailable: %v)", err)
		return
	}
	var prober netif.Prober
	if ep := netif.NewEthtoolProber(); ep != nil {
		prober = ep
	}
	outPath := filepath.Join(filepath.Dir(base.EventsLog), netifSnapshotName)

	collect := func() {
		node := resolveReporterNode(base.NodeName, cfgPath)
		inv, err := netif.Collect(netifSysfsDir, prober)
		if err != nil {
			log.Printf("[mirrorcap] netif collect warn: %v", err)
			return
		}
		if err := netif.WriteSnapshot(outPath, node, inv.Interfaces, time.Now().UTC()); err != nil {
			log.Printf("[mirrorcap] netif write snapshot %s warn: %v", outPath, err)
		}
	}

	collect()
	go func() {
		t := time.NewTicker(netifCollectInterval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				collect()
			}
		}
	}()
}

// resolveReporterNode 优先采用发布下发文件里的节点名，回退 env GATEWAY_NODE_NAME。
func resolveReporterNode(fallback, cfgPath string) string {
	if fc, err := mirrorcap.LoadFileConfig(cfgPath); err == nil && fc.Node != "" {
		return fc.Node
	}
	if fallback != "" {
		return fallback
	}
	return "mirror-unknown"
}
