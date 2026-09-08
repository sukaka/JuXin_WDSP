// mirrorharness P1-03 G2 取证工具（仅测试用途，不构成产品功能）：
//
//	mirrorharness adapter  —— 运行 mirrorsrc 接收器，把产出的 v2 记录以
//	                         JSONL 追加写入证据文件（记录已脱敏，脱敏在构造出口完成），
//	                         并周期写计数快照；
//	mirrorharness origin   —— 业务源站：计数各路径请求与上传字节，支持可配状态码
//	                         （X-Origin-Status 头）、大响应、慢响应，证明镜像链路与
//	                         业务互不影响；
//	mirrorharness probe    —— 经 Unix Socket 直连适配器发一条请求并打印状态码
//	                         （伪造写入方/直连防御取证用，容器内无 curl 时替代）。
//
// 红线：harness 不接收/输出任何未脱敏数据；records.jsonl 只含已脱敏记录。
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
	"github.com/jiuzhang-waf/wdsp-agent/internal/events"
	"github.com/jiuzhang-waf/wdsp-agent/internal/mirrorsrc"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: mirrorharness adapter|origin|probe ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[2-1] {
	case "adapter":
		err = runAdapter(os.Args[2:])
	case "origin":
		err = runOrigin(os.Args[2:])
	case "probe":
		err = runProbe(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "unknown subcommand:", os.Args[1])
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

// ── adapter ───────────────────────────────────────────────

func runAdapter(args []string) error {
	fs := newFlagSet("adapter", args)
	socket := fs.String("socket", "/run/wdsp/mirror.sock", "unix socket 路径")
	listen := fs.String("listen", "", "回环 TCP 监听（与 -socket 互斥）")
	instance := fs.String("instance", "nginx-e2e", "受控采集实例标识")
	token := fs.String("token", "", "实例标识令牌（必填）")
	tlsTerminated := fs.Bool("tls-terminated", false, "部署断言：仅接可信 TLS 终止点后镜像")
	body := fs.Bool("body", false, "正文采集总开关（默认仅元数据）")
	maxBody := fs.Int("max-body", 64<<10, "正文捕获上限字节")
	mode := fs.Int("mode", 0o600, "socket 权限（八进制）")
	group := fs.String("group", "", "socket 属组")
	level := fs.String("level", config.LevelL2, "采集等级 L1|L2")
	outPath := fs.String("out", "/evidence/records.jsonl", "记录输出（JSONL，已脱敏）")
	statsPath := fs.String("stats", "/evidence/adapter-stats.json", "计数快照输出")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *token == "" {
		return fmt.Errorf("-token 必填")
	}

	out, err := os.OpenFile(*outPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	enc := json.NewEncoder(out)

	socketPath := *socket
	if *listen != "" {
		socketPath = "" // listen 与 socket 互斥
	}
	r, err := mirrorsrc.New("harness", mirrorsrc.Config{
		SocketPath:     socketPath,
		ListenAddr:     *listen,
		SocketMode:     os.FileMode(*mode),
		SocketGroup:    *group,
		SourceInstance: *instance,
		InstanceToken:  *token,
		TLSTerminated:  *tlsTerminated,
		BodyEnabled:    *body,
		MaxBodyBytes:   *maxBody,
	}, func(rec events.HTTPRecordV2) {
		if err := enc.Encode(rec); err != nil {
			log.Printf("记录写入失败: %v", err)
		}
	}, nil)
	if err != nil {
		return err
	}
	r.UpdatePolicy(*level, config.DefaultMaxBodySize, config.DefaultMasking())
	if err := r.Start(); err != nil {
		return err
	}
	log.Printf("adapter 就绪 instance=%s tls_terminated=%v body=%v", *instance, *tlsTerminated, *body)

	stop := make(chan os.Signal, 2)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	writeStats := func() {
		snap := map[string]uint64{
			"received":       r.Stats.Received.Load(),
			"emitted":        r.Stats.Emitted.Load(),
			"forbidden":      r.Stats.Forbidden.Load(),
			"conns_rejected": r.Stats.ConnsRejected.Load(),
			"header_clamped": r.Stats.HeaderClamped.Load(),
			"masked_fields":  r.MaskedFieldCount(),
		}
		data, _ := json.Marshal(snap)
		if err := os.WriteFile(*statsPath, data, 0o644); err != nil {
			log.Printf("计数快照写入失败: %v", err)
		}
	}
	for {
		select {
		case <-stop:
			writeStats()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			r.Shutdown(ctx)
			cancel()
			return nil
		case <-tick.C:
			writeStats()
		}
	}
}

// ── origin ────────────────────────────────────────────────

type originStats struct {
	Requests    int64            `json:"requests"`
	UploadBytes int64            `json:"upload_bytes"`
	ByPath      map[string]int64 `json:"by_path"`
}

func runOrigin(args []string) error {
	fs := newFlagSet("origin", args)
	listen := fs.String("listen", "127.0.0.1:18081", "回环监听")
	statsPath := fs.String("stats", "/evidence/origin-stats.json", "计数快照输出")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var mu sync.Mutex
	st := &originStats{ByPath: make(map[string]int64)}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body) // 读尽正文（上传字节计数）
		mu.Lock()
		st.ByPath[r.URL.Path]++
		st.Requests++
		st.UploadBytes += n
		mu.Unlock()
		if d := r.Header.Get("X-Origin-Delay-Ms"); d != "" {
			if ms, err := strconv.Atoi(d); err == nil && ms > 0 && ms <= 5000 {
				time.Sleep(time.Duration(ms) * time.Millisecond)
			}
		}
		code := http.StatusOK
		if s := r.Header.Get("X-Origin-Status"); s != "" {
			if c, err := strconv.Atoi(s); err == nil && c >= 100 && c <= 599 {
				code = c
			}
		}
		if r.URL.Path == "/big" {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(code)
			io.Copy(w, io.LimitReader(&zeroReader{}, 2<<20)) // 2MB 大响应
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		fmt.Fprintf(w, `{"ok":true,"path":%q,"method":%q}`, r.URL.Path, r.Method)
	})

	srv := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       120 * time.Second, // 容忍慢上传取证场景
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	if ta, ok := ln.Addr().(*net.TCPAddr); !ok || !ta.IP.IsLoopback() {
		ln.Close()
		return fmt.Errorf("origin 仅允许回环监听: %s", *listen)
	}
	stop := make(chan os.Signal, 2)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				writeOriginStats(*statsPath, &mu, st)
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				srv.Shutdown(ctx)
				cancel()
				return
			case <-tick.C:
				writeOriginStats(*statsPath, &mu, st)
			}
		}
	}()
	log.Printf("origin 就绪 %s", ln.Addr())
	return srv.Serve(ln)
}

type zeroReader struct{}

func (z *zeroReader) Read(p []byte) (int, error) { return len(p), nil }

func writeOriginStats(path string, mu *sync.Mutex, st *originStats) {
	mu.Lock()
	data, _ := json.Marshal(st)
	mu.Unlock()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		log.Printf("origin 计数快照写入失败: %v", err)
	}
}

// ── probe ─────────────────────────────────────────────────

func runProbe(args []string) error {
	fs := newFlagSet("probe", args)
	socket := fs.String("socket", "/run/wdsp/mirror.sock", "unix socket 路径")
	token := fs.String("token", "", "实例标识令牌（空=不带标识头，测伪造拒绝）")
	tokenCount := fs.Int("token-count", 1, "标识头重复次数（>1 测多值拒绝）")
	path := fs.String("path", "/probe", "请求路径")
	extra := fs.String("header", "", "额外头 k=v")
	if err := fs.Parse(args); err != nil {
		return err
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", *socket)
		},
	}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", "http://unix"+*path, nil)
	if err != nil {
		return err
	}
	for i := 0; i < *tokenCount; i++ {
		req.Header.Add(mirrorsrc.HeaderInstance, *token)
	}
	if *extra != "" {
		k, v, _ := strings.Cut(*extra, "=")
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	fmt.Println(resp.StatusCode)
	return nil
}

// newFlagSet 子命令 flag 集。
func newFlagSet(name string, _ []string) *flag.FlagSet {
	return flag.NewFlagSet(name, flag.ContinueOnError)
}
