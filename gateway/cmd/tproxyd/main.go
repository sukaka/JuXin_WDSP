// tproxyd 九章透明串接（透明代理）部署模式前置牵引进程（阶段D 技术验证 PoC → 产品化文件配置模式）。
//
// 设计依据：docs/NETWORK_MODES_DESIGN.md §4.3。
// 只牵引透传、不做检测：检测由下游 Caddy（coraza_waf）完成。
//
// 配置来源与优先级（文件存在即文件优先；无文件时 env 兜底）：
//
//   - 发布链路下发文件 tproxyd.DefaultFileConfigPath（容器内
//     /var/run/caddy/sidecars/tproxyd.json），轮询周期 15s，支持在线启停切换：
//     {"enabled":bool,"listen":"127.0.0.1:15000","target":"127.0.0.1:8080","ports":[80],
//     "protect_hosts":["www.test.com"],"target_tls":"127.0.0.1:8443"}
//     enabled=false 或文件被删除 → 关闭监听进入空转（进程不退出）；
//
//   - 文件不存在且从未生效过 → 环境变量模式（PoC/lab 路径，详见 tproxyd.Config）：
//
//     TPROXY_LISTEN          监听地址（默认 127.0.0.1:15000；桥上 REDIRECT 目标）
//     TPROXY_TARGET          下游 Caddy HTTP 地址（默认 127.0.0.1:8080）
//     TPROXY_TARGET_TLS      下游 Caddy TLS 地址（默认 127.0.0.1:8443；SNI 分流用）
//     TPROXY_PROTECT_HOSTS   SNI 防护域名清单（逗号分隔；空 = 关闭分流，全量送 Target）
//     TPROXY_SNIFF_TIMEOUT   SNI 嗅探读超时秒（默认 3，超时关连接）
//     TPROXY_MAX_CONNS       并发连接上限（默认 1024，超出立即关闭新连接）
//     TPROXY_STATS_INTERVAL  统计日志周期秒（默认 60）
//     TPROXY_DIAL_TIMEOUT    连接下游超时秒（默认 10）
//     TPROXY_SHUTDOWN_GRACE  优雅退出宽限秒（默认 5，超时强制断开在途连接）
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/jiuzhang-waf/gateway/tproxyd"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "tproxyd error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	base, envErr := tproxyd.FromEnv()
	if envErr != nil {
		// 文件配置模式下允许 env 不完整：以内置默认基线进入轮询空转，
		// 等待发布链路下发文件，不启动即退出。显式日志，不静默。
		log.Printf("[tproxyd] env 配置不可用: %v；进入配置文件轮询（%s），等待发布链路下发", envErr, tproxyd.DefaultFileConfigPath)
		base = tproxyd.Defaults()
	}
	stats := &tproxyd.Stats{}

	sup := tproxyd.NewSupervisor(base, envErr, tproxyd.DefaultFileConfigPath, tproxyd.DefaultPollInterval, stats,
		func(cfg tproxyd.Config, st *tproxyd.Stats) (tproxyd.ServerRunner, error) {
			return tproxyd.NewServer(cfg, st)
		})

	// 周期状态日志（连接/背压/字节/错误计数）
	stopStats := make(chan struct{})
	go stats.Logger(base.StatsInterval, stopStats)

	// 优雅退出：SIGTERM/SIGINT → 停止轮询 → 关监听宽限等待在途连接 → 落盘最终统计
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	log.Printf("[tproxyd] start config_file=%s poll=%s stats_interval=%s",
		tproxyd.DefaultFileConfigPath, tproxyd.DefaultPollInterval, base.StatsInterval)

	go sup.Run()
	sig := <-sigCh
	log.Printf("[tproxyd] signal %s received, shutting down", sig)
	sup.Close()

	close(stopStats)
	// 最终统计落一行（退出可观测）
	log.Printf("[tproxyd] final stats accepted=%d rejected=%d bytes(c2t=%d t2c=%d) errors(origdst=%d dial=%d header=%d) sni(protected=%d passthrough=%d sniff_err=%d sniff_timeout=%d)",
		stats.ConnAccepted.Load(), stats.ConnRejected.Load(),
		stats.BytesToTarget.Load(), stats.BytesToClient.Load(),
		stats.OrigDstErrors.Load(), stats.DialErrors.Load(), stats.HeaderErrors.Load(),
		stats.ConnsProtected.Load(), stats.ConnsPassthrough.Load(), stats.SniffErrors.Load(), stats.SniffTimeouts.Load())
	return nil
}
