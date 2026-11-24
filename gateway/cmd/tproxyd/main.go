// tproxyd 九章透明串接（透明代理）部署模式前置牵引进程（产品化文件配置模式）。
//
// 设计依据：docs/NETWORK_MODES_DESIGN.md §4.3。
// 只牵引透传、不做检测：检测由下游 Caddy（coraza_waf）完成。
//
// 配置来源与优先级（文件存在即文件优先；无文件时 env 兜底）：
//
//   - 发布链路下发文件（--config / TPROXY_CONFIG_FILE，默认
//     /var/run/caddy/sidecars/tproxyd.json），轮询周期 15s，支持在线启停切换：
//     {"enabled":bool,"listen":"0.0.0.0:15000","target":"127.0.0.1:15080","ports":[80,443],
//     "protect_hosts":["www.test.com","*.example.com"],"target_tls":"127.0.0.1:15443"}
//     enabled=false 或文件被删除 → 关闭监听进入空转（进程不退出）；
//
//   - 文件不存在且从未生效过 → 环境变量模式（PoC/lab 路径，详见 tproxyd.Config）：
//
//     TPROXY_CONFIG_FILE     下发配置文件路径（默认 /var/run/caddy/sidecars/tproxyd.json）
//     TPROXY_HEALTH_ADDR     健康检查 HTTP 监听地址（默认 127.0.0.1:15001）
//     TPROXY_LISTEN          监听地址（默认 0.0.0.0:15000；桥上 REDIRECT 目标）
//     TPROXY_TARGET          下游 Caddy HTTP 地址（默认 127.0.0.1:15080）
//     TPROXY_TARGET_TLS      下游 Caddy TLS 地址（默认 127.0.0.1:15443；SNI 分流用）
//     TPROXY_PROTECT_HOSTS   SNI 防护域名清单（逗号分隔，支持 *.example.com；空 = 关闭分流）
//     TPROXY_SNIFF_TIMEOUT   SNI 嗅探读超时秒（默认 3，超时关连接）
//     TPROXY_MAX_CONNS       并发连接上限（默认 1024，超出立即关闭新连接）
//     TPROXY_STATS_INTERVAL  统计日志周期秒（默认 60）
//     TPROXY_DIAL_TIMEOUT    连接下游超时秒（默认 10）
//     TPROXY_SHUTDOWN_GRACE  优雅退出宽限秒（默认 5，超时强制断开在途连接）
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jiuzhang-waf/gateway/tproxyd"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "tproxyd error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("tproxyd", flag.ContinueOnError)
	configPath := fs.String("config", tproxyd.FileConfigPath(), "下发配置文件路径（默认取 TPROXY_CONFIG_FILE 或 "+tproxyd.DefaultFileConfigPath+"）")
	healthAddr := fs.String("health-addr", tproxyd.HealthAddrFromEnv(), "健康检查 HTTP 监听地址（默认取 TPROXY_HEALTH_ADDR 或 "+tproxyd.DefaultHealthAddr+"）")
	healthcheck := fs.Bool("healthcheck", false, "探测 http://<health-addr>/healthz 并在健康时返回退出码 0")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *healthcheck {
		return tproxyd.ProbeHealth(context.Background(), *healthAddr)
	}

	base, envErr := tproxyd.FromEnv()
	if envErr != nil {
		// 文件配置模式下允许 env 不完整：以内置默认基线进入轮询空转，
		// 等待发布链路下发文件，不启动即退出。显式日志，不静默。
		log.Printf("[tproxyd] env 配置不可用: %v；进入配置文件轮询（%s），等待发布链路下发", envErr, *configPath)
		base = tproxyd.Defaults()
	}
	stats := &tproxyd.Stats{}

	sup := tproxyd.NewSupervisor(base, envErr, *configPath, tproxyd.DefaultPollInterval, stats,
		func(cfg tproxyd.Config, st *tproxyd.Stats) (tproxyd.ServerRunner, error) {
			return tproxyd.NewServer(cfg, st)
		})

	healthSrv, actualHealthAddr, err := sup.StartHealthServer(*healthAddr)
	if err != nil {
		return err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = healthSrv.Shutdown(ctx)
	}()

	// 周期状态日志（连接/背压/字节/错误计数）
	stopStats := make(chan struct{})
	go stats.Logger(base.StatsInterval, stopStats)

	// 优雅退出：SIGTERM/SIGINT → 停止轮询 → 关监听宽限等待在途连接 → 落盘最终统计
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	log.Printf("[tproxyd] start config_file=%s health_addr=%s poll=%s stats_interval=%s",
		*configPath, actualHealthAddr, tproxyd.DefaultPollInterval, base.StatsInterval)

	go sup.Run()
	sig := <-sigCh
	log.Printf("[tproxyd] signal %s received, shutting down", sig)
	sup.Close()

	close(stopStats)
	// 最终统计落一行（退出可观测，包含全部计数器）
	log.Printf("[tproxyd] final stats %s", stats.Summary())
	return nil
}
