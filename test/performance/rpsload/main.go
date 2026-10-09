// rpsload：S8 批次 B 档 3 恒定 RPS 开环负载发生器（测试基建，非生产代码）。
//
// 设计冻结（报告 §1.2/§1.3 承接）：
//   - 开环：按绝对时刻表派发（每 tick batch 个，tick 间隔=batch/rps 秒，
//     睡眠偏差后续 tick 补偿；macOS/Rosetta sleep 粒度 ~1ms 下仍可达标），
//     不依响应反馈调速；在途超过 -max-conc 时该次派发记 dropped（背压如实
//     计数，不降目标凑数）；
//   - 长连接复用（MaxIdleConns/PerHost 随并发上限）：恒定 2000 RPS 新建连接
//     会耗尽 ephemeral 端口，吞吐档必须复用连接（与档 0/1/2 的 curl 短连口径
//     不同，报告分别注明）；
//   - 逐请求记录 seq/start/duration_ms/status/err 落 CSV，统计由 python3
//     最近秩口径计算（与既有 stage8 脚本 p95 同口径）；
//   - 全部目标为 stage5 测试域（*.local / RFC5737），不对外发流。
package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type result struct {
	seq      int64
	startUnix int64
	durMs    float64
	status   int
	err      string
}

func main() {
	var (
		rps      = flag.Float64("rps", 2000, "恒定派发速率（开环）")
		dur      = flag.Duration("dur", 300*time.Second, "持续时间")
		url      = flag.String("url", "", "目标 URL（必填）")
		host     = flag.String("host", "", "Host 头")
		method   = flag.String("method", "GET", "HTTP 方法")
		body     = flag.String("body", "", "请求体字符串（小体量臂用）")
		ctype    = flag.String("content-type", "", "Content-Type")
		maxConc  = flag.Int("max-conc", 512, "在途上限（超出记 dropped）")
		batch    = flag.Int("batch", 4, "每 tick 派发数（tick 间隔=batch/rps 秒，规避 macOS sleep 粒度）")
		timeout  = flag.Duration("timeout", 5*time.Second, "单请求超时")
		warmup   = flag.Duration("warmup", 5*time.Second, "预热窗口（不计入结果）")
		out      = flag.String("out", "", "CSV 输出路径（必填）")
	)
	flag.Parse()
	if *url == "" || *out == "" || *rps <= 0 {
		fmt.Fprintln(os.Stderr, "usage: rpsload -url <u> -out <f> [-rps N] [-dur D] [-host H] [-method M] [-body S] [-max-conc N]")
		os.Exit(2)
	}

	tr := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		MaxIdleConns:          *maxConc,
		MaxIdleConnsPerHost:   *maxConc,
		MaxConnsPerHost:       *maxConc,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: *timeout,
	}
	client := &http.Client{Transport: tr, Timeout: *timeout}

	f, err := os.Create(*out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "create out:", err)
		os.Exit(1)
	}
	defer f.Close()
	var wmu sync.Mutex
	fmt.Fprintln(f, "seq,start_unix_ms,duration_ms,status,error")

	sem := make(chan struct{}, *maxConc)
	var wg sync.WaitGroup
	var dispatched, completed, dropped, errors atomic.Int64

	// 绝对时刻表 + 批量 tick：macOS/Rosetta 上 time.Sleep 粒度 ~1ms，
	// 0.5ms 相对睡眠实测只有 ~1450 循环/s（S8 档 3 首轮教训）。改为每 tick
	// 派发 batch 个、按 startTick+k*tickInterval 的绝对时刻睡眠，单次睡眠
	// 偏差由后续 tick 自动补偿，平均速率贴近目标。
	tickInterval := time.Duration(float64(*batch) / float64(*rps) * float64(time.Second))
	deadline := time.Now().Add(*dur)
	warmEnd := time.Now().Add(*warmup)
	t0 := time.Now()

	var seq int64
	for k := int64(0); ; k++ {
		next := t0.Add(time.Duration(k+1) * tickInterval)
		if !time.Now().Before(deadline) {
			break
		}
		for b := 0; b < *batch; b++ {
			seq++
			select {
			case sem <- struct{}{}:
			default:
				dropped.Add(1)
				// 背压：跳过本次派发但不停止节拍
				continue
			}
			dispatched.Add(1)
			wg.Add(1)
			go func(n int64) {
				defer wg.Done()
				defer func() { <-sem }()
				start := time.Now()
				var rd io.Reader
				if *body != "" {
					rd = strings.NewReader(*body)
				}
				req, err := http.NewRequest(*method, *url, rd)
				if err != nil {
					errors.Add(1)
					return
				}
				if *host != "" {
					req.Host = *host
				}
				if *ctype != "" {
					req.Header.Set("Content-Type", *ctype)
				}
				resp, err := client.Do(req)
				durMs := float64(time.Since(start).Nanoseconds()) / 1e6
				if time.Now().Before(warmEnd) {
					if resp != nil {
						io.Copy(io.Discard, resp.Body)
						resp.Body.Close()
					}
					completed.Add(1)
					return // 预热窗口不计入
				}
				st := 0
				estr := ""
				if err != nil {
					errors.Add(1)
					estr = "client_error"
				} else {
					st = resp.StatusCode
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
				completed.Add(1)
				wmu.Lock()
				fmt.Fprintf(f, "%d,%d,%.3f,%d,%s\n", n, start.UnixMilli(), durMs, st, estr)
				wmu.Unlock()
			}(seq)
		}
		if d := time.Until(next); d > 0 {
			time.Sleep(d)
		}
	}
	wg.Wait()
	fmt.Printf("dispatched=%d completed=%d dropped=%d client_errors=%d wall=%s\n",
		dispatched.Load(), completed.Load(), dropped.Load(), errors.Load(), dur.String())
}
