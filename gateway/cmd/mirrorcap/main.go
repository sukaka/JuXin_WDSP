// mirrorcap 九章镜像（旁路）部署模式旁路采集器（阶段C 技术验证 PoC → 产品化文件配置模式）。
//
// 设计依据：docs/NETWORK_MODES_DESIGN.md §4.2。
// 只检测出事件、绝不阻断：抓包为只读路径，不向网络回注任何报文。
//
// 配置来源与优先级（文件存在即文件优先；无文件时 env 兜底）：
//
//   - 发布链路下发文件 mirrorcap.DefaultFileConfigPath（容器内
//     /var/run/caddy/sidecars/mirrorcap.json），轮询周期 15s，支持在线启停切换：
//     {"enabled":bool,"node":"...","interfaces":["eth2",...],"ports":[80,8080],"events_log":"...",
//     "discovery":{"enabled":bool,"interfaces":[{"name":"eth2","mode":"MIRROR"}],
//     "flush_interval_sec":30,"log":"..."}}
//     enabled 与 discovery.enabled 相互独立（检测 / 站点资产被动发现各自启停）；
//     双功能全禁或文件被删除 → 停止抓包进入空转（进程不退出）；
//
//   - 文件不存在且从未生效过 → 环境变量模式（PoC/lab 路径，详见 mirrorcap.Config）：
//
//     MIRROR_IFACE        监听接口（env 模式下必填，空则空转等待下发文件）
//     MIRROR_PORTS        目标 TCP 端口，逗号分隔（默认 80,8080）
//     MIRROR_EVENTS_LOG   事件输出路径（默认 /var/log/caddy/api-runtime-events.log）
//     MIRROR_BODY_MAX     Body 捕获上限字节（默认 65536）
//     GATEWAY_NODE_NAME   网关节点名（写入事件 gateway_node_id）
//     MIRROR_IDENTITY_SALT 身份/来源指纹 HMAC 盐（可空，空走固定域分隔）
//     MIRROR_RULES_DIR    Coraza/CRS 规则目录（默认 /etc/caddy/rules）
//     SITE_DISCOVERY_ENABLED        站点资产被动发现开关（true/false）
//     SITE_DISCOVERY_IFACES         发现接口列表（"eth2:MIRROR,eth0:ROUTED"，mode 缺省 MIRROR）
//     SITE_DISCOVERY_FLUSH_INTERVAL 发现聚合落盘周期秒（默认 30）
//     SITE_DISCOVERY_LOG            发现输出路径（默认 /var/log/caddy/site-discovery.jsonl）
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/jiuzhang-waf/gateway/mirrorcap"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/apievents"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "mirrorcap error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	base, envErr := mirrorcap.FromEnv()
	if envErr != nil {
		// 文件配置模式下允许 env 不完整（典型：MIRROR_IFACE 未设置，等待发布链路
		// 下发文件）：以内置默认基线进入轮询空转，不启动即退出。显式日志，不静默。
		log.Printf("[mirrorcap] env 配置不可用: %v；进入配置文件轮询（%s），等待发布链路下发", envErr, mirrorcap.DefaultFileConfigPath)
		base = mirrorcap.Defaults()
	}
	stats := &mirrorcap.Stats{}

	sup := mirrorcap.NewSupervisor(base, envErr, mirrorcap.DefaultFileConfigPath, mirrorcap.DefaultPollInterval, stats,
		apievents.NewLogger,
		func(cfg mirrorcap.Config, events *apievents.Logger, st *mirrorcap.Stats) (mirrorcap.RequestHandler, error) {
			return mirrorcap.NewDetector(cfg, events, st)
		},
		func(cfg mirrorcap.Config, consumer mirrorcap.IfaceConsumer, st *mirrorcap.Stats) (mirrorcap.Runner, error) {
			return mirrorcap.NewCapture(cfg, consumer, st)
		})

	// 周期状态日志（抓包/丢包/重组/事件计数；内核统计聚合各接口句柄）
	stopStats := make(chan struct{})
	go stats.Logger(base.StatsInterval, sup.StatsFunc(), stopStats)

	// 优雅退出：SIGTERM/SIGINT → 停止轮询 → 关闭全部抓包句柄与事件文件 → 落盘最终统计
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	log.Printf("[mirrorcap] start config_file=%s poll=%s stats_interval=%s",
		mirrorcap.DefaultFileConfigPath, mirrorcap.DefaultPollInterval, base.StatsInterval)

	go sup.Run()
	sig := <-sigCh
	log.Printf("[mirrorcap] signal %s received, shutting down", sig)
	sup.Close()

	close(stopStats)
	// 最终统计落一行（退出可观测）
	log.Printf("[mirrorcap] final stats packets=%d dropped=%d requests=%d events=%d event_errors=%d",
		stats.PacketsCaptured.Load(), stats.PacketsDropped.Load(),
		stats.RequestsParsed.Load(), stats.EventsEmitted.Load(), stats.EventErrors.Load())
	return nil
}
