// tapharness P1-03 G3 取证工具（仅测试用途，不构成产品功能）：
//
//	tapharness adapter —— 运行 tapsrc 适配器（出向连接本机回环 Envoy Admin
//	                     的 POST /tap 管理流），把产出的 v2 记录以 JSONL
//	                     追加写入证据文件（记录已脱敏，脱敏在构造出口完成），
//	                     并周期写计数快照。
//
// 红线：harness 不接收/输出任何未脱敏数据；records.jsonl 只含已脱敏记录。
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
	"github.com/jiuzhang-waf/wdsp-agent/internal/events"
	"github.com/jiuzhang-waf/wdsp-agent/internal/tapsrc"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "adapter" {
		fmt.Fprintln(os.Stderr, "usage: tapharness adapter ...")
		os.Exit(2)
	}
	if err := runAdapter(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

func runAdapter(args []string) error {
	fs := flag.NewFlagSet("adapter", flag.ContinueOnError)
	admin := fs.String("admin", "127.0.0.1:9901", "Envoy Admin 回环地址")
	instance := fs.String("instance", "envoy-e2e", "受控采集实例标识")
	configID := fs.String("config-id", "wdsp_tap", "tap filter admin_config config_id")
	observed := fs.String("observed", "UNKNOWN", "观测协议部署断言（1.0/1.1/2/3；混合 listener 必须 UNKNOWN）")
	tlsTerminated := fs.Bool("tls-terminated", false, "部署断言：全部 tapped listener 为可信 TLS 终止点")
	body := fs.Bool("body", false, "正文采集总开关（默认仅元数据；gRPC 正文恒不采集）")
	maxBody := fs.Int("max-body", 4096, "正文捕获上限字节")
	level := fs.String("level", config.LevelL1, "采集等级 L1|L2")
	outPath := fs.String("out", "/evidence/records.jsonl", "记录输出（JSONL，已脱敏）")
	statsPath := fs.String("stats", "/evidence/adapter-stats.json", "计数快照输出")
	if err := fs.Parse(args); err != nil {
		return err
	}

	out, err := os.OpenFile(*outPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	var mu = make(chan struct{}, 1)
	mu <- struct{}{}
	enc := json.NewEncoder(out)

	src, err := tapsrc.New("harness", tapsrc.Config{
		AdminAddr:           *admin,
		SourceInstance:      *instance,
		ConfigID:            *configID,
		ObservedHTTPVersion: *observed,
		TLSTerminated:       *tlsTerminated,
		BodyEnabled:         *body,
		MaxBodyBytes:        *maxBody,
	}, func(rec events.HTTPRecordV2) {
		<-mu
		defer func() { mu <- struct{}{} }()
		if err := enc.Encode(rec); err != nil {
			log.Printf("记录写入失败: %v", err)
		}
	}, nil)
	if err != nil {
		return err
	}
	src.UpdatePolicy(*level, config.DefaultMaxBodySize, config.DefaultMasking())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := make(chan os.Signal, 2)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	go func() { <-stop; cancel() }()
	go src.Run(ctx)

	log.Printf("adapter 就绪 admin=%s instance=%s config_id=%s observed=%s tls=%v body=%v", *admin, *instance, *configID, *observed, *tlsTerminated, *body)
	// 计数快照跨进程重启累计（守护拉起场景：读取既有快照作为基线再累加，
	// 让 e2e 能断言累计的 disconnect/reconnect；harness 专用语义）
	base := map[string]uint64{}
	if data, err := os.ReadFile(*statsPath); err == nil {
		_ = json.Unmarshal(data, &base)
	}
	writeStats := func() {
		snap := map[string]uint64{
			"received":         src.Stats.Received.Load(),
			"emitted":          src.Stats.Emitted.Load(),
			"disconnects":      src.Stats.Disconnects.Load(),
			"reconnects":       src.Stats.Reconnects.Load(),
			"admin_rejects":    src.Stats.AdminRejects.Load(),
			"parse_errors":     src.Stats.ParseErrors.Load(),
			"oversize_drops":   src.Stats.OversizeDrops.Load(),
			"non_http_ignored": src.Stats.NonHTTPIgnored.Load(),
			"header_clamped":   src.Stats.HeaderClamped.Load(),
			"masked_fields":    src.MaskedFieldCount(),
		}
		for k := range snap {
			snap[k] += base[k]
		}
		data, _ := json.Marshal(snap)
		if err := os.WriteFile(*statsPath, data, 0o644); err != nil {
			log.Printf("计数快照写入失败: %v", err)
		}
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			writeStats()
			sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
			src.Shutdown(sctx)
			scancel()
			return nil
		case <-tick.C:
			writeStats()
		}
	}
}
