// netmgrd 九章多模式部署宿主机侧网络执行组件（页面配置网桥与路由牵引）。
//
// 设计依据：docs/NETWORK_MODES_DESIGN.md；包语义详见 gateway/netmgrd/doc.go。
//
// 运行模式：
//
//	默认（daemon）：轮询 network.json（默认 15s），配置变化时幂等执行并回写
//	  network-status.json；失败不 crash-loop（last-good + 周期重试）；
//	  SIGTERM/SIGINT 优雅退出（不拆除任何网络状态）。
//	--once：加载配置 → 执行一次 → 写 status 并打印到 stdout → 退出
//	  （lab/运维验证路径）；退出码 0=全项成功 1=存在失败/配置不可用。
//	--dry-run：只打印将执行的变更命令不执行（只读查询真实执行以产出准确
//	  计划），不写 status；退出码同 --once（计划层面的失败如安全红线照报）。
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jiuzhang-waf/gateway/netmgrd"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "netmgrd error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath    = flag.String("config", netmgrd.DefaultConfigPath, "期望配置文件路径（network.json）")
		statusPath    = flag.String("status", netmgrd.DefaultStatusPath, "状态回写路径（network-status.json）")
		tproxydConfig = flag.String("tproxyd-config", "", "透明牵引侧车配置文件路径（缺省与 --config 同目录 tproxyd.json）")
		tproxydHealth = flag.String("tproxyd-health", netmgrd.DefaultTproxydHealthURL, "tproxyd 健康检查端点 URL")
		caddySocket   = flag.String("caddy-socket", netmgrd.DefaultCaddyAdminSocket, "Caddy Admin Unix Socket 路径（透明 fail-open 探活用）")
		interval      = flag.Int("interval", int(netmgrd.DefaultPollInterval/time.Second), "轮询周期（秒，daemon 模式）")
		timeout       = flag.Int("timeout", int(netmgrd.DefaultCmdTimeout/time.Second), "单个 ip/sysctl 动作超时（秒）")
		once          = flag.Bool("once", false, "执行一次后退出（lab/运维验证）")
		dryRun        = flag.Bool("dry-run", false, "只打印将执行的变更命令，不执行、不写 status")
		nodeName      = flag.String("node", os.Getenv("NODE_NAME"), "诊断请求认领节点名（缺省空=认领全部节点；也可用 NODE_NAME 环境变量）")
		healthcheck   = flag.Bool("healthcheck", false, "通过本地 Unix Socket 只读检查 daemon 就绪状态，不执行网络变更")
	)
	flag.Parse()
	if *healthcheck {
		return netmgrd.ProbeHealth(context.Background(), netmgrd.DefaultHealthSocket)
	}

	runner := netmgrd.ExecRunner{Timeout: time.Duration(*timeout) * time.Second}

	// --dry-run：单次计划输出（隐含 --once 语义，不写 status）
	if *dryRun {
		cfg, err := netmgrd.LoadConfig(*configPath)
		if err != nil {
			return fmt.Errorf("加载配置: %w", err)
		}
		dry := &netmgrd.DryRunner{Real: runner, Out: os.Stdout}
		st := netmgrd.Apply(context.Background(), cfg, dry, time.Now())
		fmt.Println("(dry-run) 以上变更命令未执行；未写 status")
		fmt.Printf("(dry-run) 计划结果: ok=%v message=%s\n", st.OK, st.Message)
		if !st.OK {
			return fmt.Errorf("计划存在失败项（安全红线/校验拒绝），详见上方输出")
		}
		return nil
	}

	// --once：执行一次，写 status 并打印，退出码反映执行结果
	if *once {
		cfg, err := netmgrd.LoadConfig(*configPath)
		if err != nil {
			// 配置不可用也写 status（--once 为显式运维验证，消费方需要看到本次结论）
			st := netmgrd.Status{
				AppliedAt: time.Now().UTC().Format(time.RFC3339),
				OK:        false,
				Bridges:   make([]netmgrd.BridgeStatus, 0),
				IPForward: netmgrd.StateSkipped,
				Routes:    make([]netmgrd.RouteStatus, 0),
				Message:   "配置不可用: " + err.Error(),
			}
			if werr := netmgrd.WriteStatusAtomic(*statusPath, st); werr != nil {
				log.Printf("[netmgrd] 状态回写失败: %v", werr)
			}
			printStatus(st)
			return fmt.Errorf("加载配置: %w", err)
		}
		st := netmgrd.Apply(context.Background(), cfg, runner, time.Now())
		if err := netmgrd.WriteStatusAtomic(*statusPath, st); err != nil {
			return fmt.Errorf("状态回写失败: %w", err)
		}
		printStatus(st)
		if !st.OK {
			return fmt.Errorf("执行存在失败项: %s", st.Message)
		}
		return nil
	}

	// daemon：轮询执行，直到收到退出信号
	if *interval <= 0 {
		return fmt.Errorf("--interval 必须为正整数秒: %d", *interval)
	}
	sup := netmgrd.NewSupervisor(*configPath, *statusPath,
		time.Duration(*interval)*time.Second, runner)
	sup.Diag.NodeName = *nodeName
	if *tproxydConfig != "" {
		sup.Transparent.TproxydConfigPath = *tproxydConfig
	} else {
		sup.Transparent.TproxydConfigPath = filepath.Join(filepath.Dir(*configPath), "tproxyd.json")
	}
	sup.Transparent.TproxydHealthURL = *tproxydHealth
	sup.Transparent.CaddySocket = *caddySocket
	healthServer, err := sup.StartHealthServer(netmgrd.DefaultHealthSocket)
	if err != nil {
		return err
	}
	defer healthServer.Close()

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	log.Printf("[netmgrd] start config=%s status=%s tproxyd_cfg=%s tproxyd_health=%s caddy_sock=%s poll=%ds cmd_timeout=%ds node=%q diag_dir=%s",
		*configPath, *statusPath, sup.Transparent.TproxydConfigPath, sup.Transparent.TproxydHealthURL, sup.Transparent.CaddySocket,
		*interval, *timeout, *nodeName, sup.Diag.Dir)

	done := make(chan struct{})
	go func() { sup.Run(); close(done) }()
	sig := <-sigCh
	log.Printf("[netmgrd] signal %s received, shutting down（冲刷透明牵引规则，不拆除网桥与路由）", sig)
	sup.Close()
	<-done
	return nil
}

// printStatus 单行 JSON 打印执行状态（运维/lab 可直接管道解析）。
func printStatus(st netmgrd.Status) {
	data, err := json.Marshal(st)
	if err != nil {
		log.Printf("[netmgrd] 状态序列化失败: %v", err)
		return
	}
	fmt.Println(string(data))
}
