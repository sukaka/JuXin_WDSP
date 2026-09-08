// havipd 九章主备高可用宿主机侧 VIP 执行组件（页面配置主备组与 VIP 漂移）。
//
// 设计依据：docs/HA_ACTIVE_STANDBY_DESIGN.md §8；包语义详见 gateway/havipd/doc.go。
//
// 运行模式（daemon 唯一形态——VIP 状态须持续采集，无 --once）：
// 轮询 ha-vip.json（默认 15s）驱动 keepalived 生命周期；状态轮询（默认 1s）
// 采集 MASTER/BACKUP/FAULT 并回写 ha-vip-status.json；SIGTERM/SIGINT 优雅退出
// （先停本组件管理的 keepalived，VIP 随之释放）。
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jiuzhang-waf/gateway/havipd"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "havipd error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		node       = flag.String("node", os.Getenv("GATEWAY_NODE_NAME"), "本机节点名（定位 members[] 中自身优先级；缺省取 GATEWAY_NODE_NAME 环境变量）")
		configPath = flag.String("config", havipd.DefaultConfigPath, "期望配置文件路径（ha-vip.json）")
		statusPath = flag.String("status", havipd.DefaultStatusPath, "状态回写路径（ha-vip-status.json）")
		workDir    = flag.String("workdir", filepath.Join(filepath.Dir(havipd.DefaultConfigPath), "keepalived"), "keepalived 配置/pidfile 工作目录")
		cfgInt     = flag.Int("config-interval", int(havipd.DefaultPollInterval/time.Second), "配置轮询周期（秒）")
		stateInt   = flag.Int("state-interval", int(havipd.DefaultStateInterval/time.Second), "状态采集周期（秒）")
		timeout    = flag.Int("timeout", int(havipd.DefaultCmdTimeout/time.Second), "单个外部命令超时（秒）")
	)
	flag.Parse()

	if *node == "" {
		return fmt.Errorf("必须指定本机节点名（--node 或 GATEWAY_NODE_NAME 环境变量）")
	}

	sv := havipd.NewSupervisor(*node, *configPath, *statusPath, *workDir,
		havipd.ExecRunner{Timeout: time.Duration(*timeout) * time.Second}, nil)
	sv.ConfigInterval = time.Duration(*cfgInt) * time.Second
	sv.StateInterval = time.Duration(*stateInt) * time.Second

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		s := <-sig
		log.Printf("[havipd] signal %v received, shutting down（停止 keepalived 并释放 VIP）", s)
		sv.Close()
	}()

	log.Printf("[havipd] start node=%s config=%s status=%s workdir=%s", *node, *configPath, *statusPath, *workDir)
	sv.Run()
	return nil
}
