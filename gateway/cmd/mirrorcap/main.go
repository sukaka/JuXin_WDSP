// mirrorcap 九章镜像（旁路）部署模式旁路采集器（阶段C 技术验证 PoC → 产品化文件配置模式）。
//
// 设计依据：docs/NETWORK_MODES_DESIGN.md §4.2。
// 只检测出事件、绝不阻断：抓包为只读路径，不向网络回注任何报文。
//
// 配置来源与优先级（文件存在即文件优先；无文件时 env 兜底）：
//
//   - 发布链路下发文件 MIRROR_CONFIG_FILE（默认 /var/run/caddy/sidecars/mirrorcap.json），
//     轮询周期 15s，支持在线启停切换：
//     {"enabled":bool,"node":"...","interfaces":["eth2",...],"ports":[80,8080],"domains":[...],
//     "events_log":"...","audit_log":"...","discovery":{"enabled":bool,
//     "interfaces":[{"name":"eth2","mode":"MIRROR"}],"flush_interval_sec":30,"log":"..."}}
//     enabled 与 discovery.enabled 相互独立（检测 / 站点资产被动发现各自启停）；
//     双功能全禁或文件被删除 → 停止抓包进入空转（进程不退出）；
//
//   - 文件不存在且从未生效过 → 环境变量模式（PoC/lab 路径，详见 mirrorcap.Config）：
//
//     MIRROR_IFACE        监听接口（env 模式下必填，空则空转等待下发文件）
//     MIRROR_PORTS        目标 TCP 端口，逗号分隔（默认 80,8080）
//     MIRROR_EVENTS_LOG   事件输出路径（默认 /var/log/caddy/api-runtime-events.log）
//     MIRROR_AUDIT_LOG    Coraza 审计日志路径（默认 /var/log/caddy/coraza-audit.log；off/none 关闭）
//     MIRROR_BODY_MAX     Body 捕获上限字节（默认 65536）
//     GATEWAY_NODE_NAME   网关节点名（写入事件 gateway_node_id 与网口快照 node_name）
//     MIRROR_IDENTITY_SALT 身份/来源指纹 HMAC 盐（可空，空走固定域分隔）
//     MIRROR_RULES_DIR    Coraza/CRS 规则目录（默认 /etc/caddy/rules）
//     MIRROR_CONFIG_FILE  边车配置文件路径（默认 /var/run/caddy/sidecars/mirrorcap.json）
//     MIRROR_DROP_PRIVS   设为 1 时容器内由 root 降权至 1000:1000 并仅保留 ambient CAP_NET_RAW/CAP_NET_ADMIN
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
	"path/filepath"
	"syscall"

	"github.com/jiuzhang-waf/gateway/mirrorcap"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/apievents"
)

func main() {
	for _, arg := range os.Args[1:] {
		if arg == "--healthcheck" {
			if err := runHealthcheck(); err != nil {
				fmt.Fprintf(os.Stderr, "mirrorcap healthcheck failed: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}
	if err := maybeDropPrivileges(); err != nil {
		fmt.Fprintf(os.Stderr, "mirrorcap privilege drop error: %v\n", err)
		os.Exit(1)
	}
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "mirrorcap error: %v\n", err)
		os.Exit(1)
	}
}

// runHealthcheck 校验基础日志目录与规则目录可访问（容器 HEALTHCHECK / 升级就绪探针）。
func runHealthcheck() error {
	base, err := mirrorcap.ParseEnv()
	if err != nil {
		base = mirrorcap.Defaults()
	}
	logDir := filepath.Dir(base.EventsLog)
	if st, err := os.Stat(logDir); err != nil || !st.IsDir() {
		return fmt.Errorf("events log dir %s unavailable: %v", logDir, err)
	}
	if st, err := os.Stat(base.RulesDir); err != nil || !st.IsDir() {
		return fmt.Errorf("rules dir %s unavailable: %v", base.RulesDir, err)
	}
	return nil
}

func run() error {
	cfgPath := mirrorcap.FileConfigPath()
	// 先解析全部环境变量保留运维基线（MIRROR_RULES_DIR/MIRROR_IDENTITY_SALT/MIRROR_AUDIT_LOG 等），
	// 仅在语法非法时回退内置默认；随后再调用 Validate() 判断 env 模式是否可直接抓包。
	base, parseErr := mirrorcap.ParseEnv()
	var envErr error
	if parseErr != nil {
		log.Printf("[mirrorcap] env 配置格式非法: %v；回退默认基线并等待发布链路下发（%s）", parseErr, cfgPath)
		base = mirrorcap.Defaults()
		envErr = parseErr
	} else if verr := base.Validate(); verr != nil {
		log.Printf("[mirrorcap] env 模式未指定抓包口: %v；保留运维环境变量基线并进入配置文件轮询（%s）", verr, cfgPath)
		envErr = verr
	}
	stats := &mirrorcap.Stats{}

	sup := mirrorcap.NewSupervisor(base, envErr, cfgPath, mirrorcap.DefaultPollInterval, stats,
		apievents.NewLogger,
		func(cfg mirrorcap.Config, events *apievents.Logger, st *mirrorcap.Stats) (mirrorcap.RequestHandler, error) {
			return mirrorcap.NewDetector(cfg, events, st)
		},
		func(cfg mirrorcap.Config, consumer mirrorcap.IfaceConsumer, st *mirrorcap.Stats) (mirrorcap.Runner, error) {
			return mirrorcap.NewCapture(cfg, consumer, st)
		})

	stopBg := make(chan struct{})
	// 周期状态日志（抓包/丢包/重组/事件计数；内核统计聚合各接口句柄）
	go stats.Logger(base.StatsInterval, sup.StatsFunc(), stopBg)
	// 常驻物理网口清单采集（解决纯镜像场景未发布反代站点时网口管理为空的问题）
	startNetifReporter(base, cfgPath, stopBg)

	// 优雅退出：SIGTERM/SIGINT → 停止轮询与后台任务 → 关闭全部抓包句柄与事件文件 → 落盘最终统计
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	log.Printf("[mirrorcap] start config_file=%s poll=%s stats_interval=%s rules_dir=%s events_log=%s",
		cfgPath, mirrorcap.DefaultPollInterval, base.StatsInterval, base.RulesDir, base.EventsLog)

	go sup.Run()
	sig := <-sigCh
	log.Printf("[mirrorcap] signal %s received, shutting down", sig)
	sup.Close()

	close(stopBg)
	// 最终统计落一行（退出可观测）
	log.Printf("[mirrorcap] final stats packets=%d dropped=%d requests=%d events=%d event_errors=%d",
		stats.PacketsCaptured.Load(), stats.PacketsDropped.Load(),
		stats.RequestsParsed.Load(), stats.EventsEmitted.Load(), stats.EventErrors.Load())
	return nil
}
