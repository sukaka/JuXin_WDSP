// l7bench：聚信压测工具（JuXin L7 Bench）核心引擎，遵循 RFC 3511 / RFC 9411（NetSecOPEN）行业测试口径。
//
// 核心能力：
//   1. 四大标准模式：tps（长连事务）、cps（1 req/conn 完整建连与挥手）、cc（海量并发连接保持）、emix（NetSecOPEN 多尺寸混合吞吐）；
//   2. 多源 IP 轮询绑定（--local-ips 支持单 IP / 区间 / CIDR），突破单 IP 65535 临时端口上限；
//   3. 严格三段式计量：Ramp-Up（爬坡）-> Steady State（仅此窗口计入最终成绩）-> Ramp-Down（优雅收尾）；
//   4. 逐请求 httptrace 精细拆解 TCP 建连 / TLS 握手 / TTFB / TTLB 延迟（O(1) 内存无锁直方图）；
//   5. 显式锁定 HTTP/1.1 vs HTTP/2、TLS 1.2 vs 1.3、密码套件、Full Handshake vs Session Resumption。
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type benchConfig struct {
	Mode           string        `json:"mode"`
	TargetBaseURL  string        `json:"target_base_url"`
	Path           string        `json:"path"`
	HostHeader     string        `json:"host_header"`
	Method         string        `json:"method"`
	Rate           float64       `json:"rate"`
	MaxInFlight    int           `json:"max_in_flight"`
	Conns          int           `json:"conns"`
	CCInterval     time.Duration `json:"cc_interval"`
	RampUp         time.Duration `json:"ramp_up"`
	Steady         time.Duration `json:"steady"`
	RampDown       time.Duration `json:"ramp_down"`
	Timeout        time.Duration `json:"timeout"`
	Batch          int           `json:"batch"`
	LocalIPSpec    string        `json:"local_ips"`
	LocalIPCount   int           `json:"local_ip_count"`
	EMIXPreset     string        `json:"emix_preset"`
	EMIXSpec       string        `json:"emix_spec"`
	TLSVersion     string        `json:"tls_version"`
	TLSCipher      string        `json:"tls_cipher"`
	TLSResume      bool          `json:"tls_resume"`
	HTTP2          bool          `json:"http2"`
	Insecure       bool          `json:"insecure_skip_tls_verify"`
	ExpectedStatus int           `json:"expected_status"`
}

type steadyCounters struct {
	dispatched          atomic.Uint64
	completed           atomic.Uint64
	droppedBackpressure atomic.Uint64
	status2xx           atomic.Uint64
	status3xx           atomic.Uint64
	status401_403       atomic.Uint64
	status429           atomic.Uint64
	status4xxOther      atomic.Uint64
	status5xx           atomic.Uint64
	errTCPReset         atomic.Uint64
	errTimeout          atomic.Uint64
	errTLS              atomic.Uint64
	errOtherTransport   atomic.Uint64
	unexpectedHTTP      atomic.Uint64
	goodputBodyBytes    atomic.Uint64
	wireEstBytes        atomic.Uint64
	connReused          atomic.Uint64
	connNew             atomic.Uint64

	// CC mode specific
	activeConnsCurrent atomic.Int64
	activeConnsPeak    atomic.Int64
	steadyConnsMin     atomic.Int64
	steadyConnsSamples atomic.Uint64
	steadyConnsSum     atomic.Uint64
	ccReconnects       atomic.Uint64

	tcpHist  *LatencyHist
	tlsHist  *LatencyHist
	ttfbHist *LatencyHist
	ttlbHist *LatencyHist
}

func newSteadyCounters() *steadyCounters {
	c := &steadyCounters{
		tcpHist:  newLatencyHist(),
		tlsHist:  newLatencyHist(),
		ttfbHist: newLatencyHist(),
		ttlbHist: newLatencyHist(),
	}
	c.steadyConnsMin.Store(math.MaxInt64)
	return c
}

type benchReport struct {
	Methodology   string         `json:"methodology"`
	GeneratedUTC  string         `json:"generated_at_utc"`
	Config        benchConfig    `json:"config"`
	SteadyWindow  steadyWindow   `json:"steady_window"`
	Summary       reportSummary  `json:"summary"`
	Latency       latencyBreakdown `json:"latency"`
	StatusCodes   statusSummary  `json:"status_codes"`
	Errors        errorSummary   `json:"errors"`
	ConcurrentCC  *ccSummary     `json:"concurrent_connections,omitempty"`
}

type steadyWindow struct {
	StartUTC        string  `json:"start_utc"`
	EndUTC          string  `json:"end_utc"`
	DurationSeconds float64 `json:"duration_seconds"`
}

type reportSummary struct {
	Dispatched         uint64  `json:"dispatched"`
	Completed          uint64  `json:"completed"`
	BackpressureDrops  uint64  `json:"backpressure_drops"`
	BackpressureDropPct float64 `json:"backpressure_drop_pct"`
	AchievedRPS        float64 `json:"achieved_rps"`
	AchievedCPS        float64 `json:"achieved_cps"`
	GoodputGbps        float64 `json:"goodput_gbps"`
	ThroughputEstGbps  float64 `json:"throughput_est_gbps"`
	GoodputMbps        float64 `json:"goodput_mbps"`
	ErrorRatePct       float64 `json:"error_rate_pct"`
	ZeroLossPass       bool    `json:"zero_loss_pass"`
	ConnNewCount       uint64  `json:"conn_new_count"`
	ConnReusedCount    uint64  `json:"conn_reused_count"`
}

type latencyBreakdown struct {
	TCPConnect   LatencySummary `json:"tcp_connect"`
	TLSHandshake LatencySummary `json:"tls_handshake"`
	TTFB         LatencySummary `json:"ttfb"`
	TTLB         LatencySummary `json:"ttlb"`
}

type statusSummary struct {
	S2xx      uint64 `json:"s2xx"`
	S3xx      uint64 `json:"s3xx"`
	S401_403  uint64 `json:"s401_403"`
	S429      uint64 `json:"s429"`
	S4xxOther uint64 `json:"s4xx_other"`
	S5xx      uint64 `json:"s5xx"`
}

type errorSummary struct {
	TCPReset        uint64 `json:"tcp_reset"`
	Timeout         uint64 `json:"timeout"`
	TLSError        uint64 `json:"tls_error"`
	OtherTransport  uint64 `json:"other_transport"`
	UnexpectedHTTP  uint64 `json:"unexpected_http"`
	TotalFailures   uint64 `json:"total_failures"`
}

type ccSummary struct {
	TargetConns     int     `json:"target_conns"`
	PeakActiveConns int64   `json:"peak_active_conns"`
	SteadyMinConns  int64   `json:"steady_min_conns"`
	SteadyAvgConns  float64 `json:"steady_avg_conns"`
	Reconnects      uint64  `json:"reconnects"`
}

func makeHTTPClient(localIP net.IP, tlsCfg *tls.Config, cfg benchConfig, singleConn bool) *http.Client {
	dialer := &net.Dialer{
		Timeout:   cfg.Timeout,
		KeepAlive: 30 * time.Second,
	}
	if localIP != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: localIP, Port: 0}
	}

	maxIdle := cfg.MaxInFlight
	if singleConn {
		maxIdle = 1
	}
	tr := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSClientConfig:       tlsCfg,
		DisableKeepAlives:     cfg.Mode == "cps",
		MaxIdleConns:          maxIdle,
		MaxIdleConnsPerHost:   maxIdle,
		MaxConnsPerHost:       maxIdle,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: cfg.Timeout,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    true,
	}
	if cfg.HTTP2 {
		tr.ForceAttemptHTTP2 = true
	} else {
		tr.ForceAttemptHTTP2 = false
		tr.TLSNextProto = make(map[string]func(authority string, c *tls.Conn) http.RoundTripper)
	}
	return &http.Client{
		Transport: tr,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func classifyTransportErr(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	if errors.Is(err, syscall.ECONNRESET) || strings.Contains(strings.ToLower(err.Error()), "connection reset") {
		return "tcp_reset"
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "tls:") || strings.Contains(msg, "x509:") || strings.Contains(msg, "handshake") {
		return "tls"
	}
	return "other"
}

func executeOneRequest(
	client *http.Client,
	reqURL string,
	hostHeader string,
	method string,
	closeHeader bool,
	expectedStatus int,
	recordSteady bool,
	stats *steadyCounters,
) (reused bool, ok bool) {
	var (
		connStart, tlsStart time.Time
		tcpDur, tlsDur      time.Duration
		ttfbDur             time.Duration
		gotFirstByte        bool
		gotConnReused       bool
	)

	reqStart := time.Now()
	trace := &httptrace.ClientTrace{
		ConnectStart: func(_, _ string) {
			connStart = time.Now()
		},
		ConnectDone: func(_, _ string, err error) {
			if err == nil && !connStart.IsZero() {
				tcpDur = time.Since(connStart)
			}
		},
		TLSHandshakeStart: func() {
			tlsStart = time.Now()
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err == nil && !tlsStart.IsZero() {
				tlsDur = time.Since(tlsStart)
			}
		},
		GotConn: func(info httptrace.GotConnInfo) {
			gotConnReused = info.Reused
		},
		GotFirstResponseByte: func() {
			gotFirstByte = true
			ttfbDur = time.Since(reqStart)
		},
	}

	req, err := http.NewRequest(method, reqURL, nil)
	if err != nil {
		if recordSteady {
			stats.errOtherTransport.Add(1)
			stats.completed.Add(1)
		}
		return false, false
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	if hostHeader != "" {
		req.Host = hostHeader
	}
	if closeHeader {
		req.Close = true
		req.Header.Set("Connection", "close")
	}

	resp, err := client.Do(req)
	if err != nil {
		if recordSteady {
			switch classifyTransportErr(err) {
			case "tcp_reset":
				stats.errTCPReset.Add(1)
			case "timeout":
				stats.errTimeout.Add(1)
			case "tls":
				stats.errTLS.Add(1)
			default:
				stats.errOtherTransport.Add(1)
			}
			stats.completed.Add(1)
		}
		return gotConnReused, false
	}

	bodyN, copyErr := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	ttlbDur := time.Since(reqStart)
	if copyErr != nil {
		if recordSteady {
			switch classifyTransportErr(copyErr) {
			case "tcp_reset":
				stats.errTCPReset.Add(1)
			case "timeout":
				stats.errTimeout.Add(1)
			default:
				stats.errOtherTransport.Add(1)
			}
			stats.completed.Add(1)
		}
		return gotConnReused, false
	}

	if recordSteady {
		stats.completed.Add(1)
		if gotConnReused {
			stats.connReused.Add(1)
		} else {
			stats.connNew.Add(1)
		}
		if tcpDur > 0 {
			stats.tcpHist.Record(tcpDur)
		}
		if tlsDur > 0 {
			stats.tlsHist.Record(tlsDur)
		}
		if gotFirstByte {
			stats.ttfbHist.Record(ttfbDur)
		}
		stats.ttlbHist.Record(ttlbDur)

		stats.goodputBodyBytes.Add(uint64(bodyN))
		// 估算含 HTTP 响应头与 TCP/IP 帧开销的线速吞吐（header ~200B + framing ~3%）
		wireEst := uint64(float64(bodyN+200) * 1.03)
		stats.wireEstBytes.Add(wireEst)

		st := resp.StatusCode
		switch {
		case st >= 200 && st < 300:
			stats.status2xx.Add(1)
		case st >= 300 && st < 400:
			stats.status3xx.Add(1)
		case st == 401 || st == 403:
			stats.status401_403.Add(1)
		case st == 429:
			stats.status429.Add(1)
		case st >= 400 && st < 500:
			stats.status4xxOther.Add(1)
		case st >= 500:
			stats.status5xx.Add(1)
		}

		if expectedStatus > 0 && st != expectedStatus {
			stats.unexpectedHTTP.Add(1)
			return gotConnReused, false
		}
		if expectedStatus == 0 && st >= 500 {
			stats.unexpectedHTTP.Add(1)
			return gotConnReused, false
		}
	}
	return gotConnReused, resp.StatusCode == expectedStatus || (expectedStatus == 0 && resp.StatusCode < 500)
}

func runOpenLoop(cfg benchConfig, pool *ipPool, tlsCfg *tls.Config, emix *emixProfile) benchReport {
	stats := newSteadyCounters()
	baseURL := strings.TrimRight(cfg.TargetBaseURL, "/")

	// 每个源 IP 一个独立 Client（无本地 IP 时建 1 个），避免高并发下共享 Transport 锁竞争
	clientCount := pool.Len()
	if clientCount == 0 {
		clientCount = 1
	}
	clients := make([]*http.Client, clientCount)
	for i := 0; i < clientCount; i++ {
		var lip net.IP
		if pool.Len() > 0 {
			lip = pool.ips[i]
		}
		clients[i] = makeHTTPClient(lip, tlsCfg, cfg, false)
	}
	defer func() {
		for _, c := range clients {
			c.CloseIdleConnections()
		}
	}()

	sem := make(chan struct{}, cfg.MaxInFlight)
	var wg sync.WaitGroup

	t0 := time.Now()
	steadyStart := t0.Add(cfg.RampUp)
	steadyEnd := steadyStart.Add(cfg.Steady)
	hardEnd := steadyEnd.Add(cfg.RampDown)

	batch := cfg.Batch
	if batch < 1 {
		batch = 1
	}
	tickInterval := time.Duration(float64(batch) / cfg.Rate * float64(time.Second))
	if tickInterval < time.Microsecond {
		tickInterval = time.Microsecond
	}

	var seq uint64
	for k := int64(0); ; k++ {
		now := time.Now()
		if !now.Before(hardEnd) {
			break
		}
		inSteady := !now.Before(steadyStart) && now.Before(steadyEnd)
		for b := 0; b < batch; b++ {
			seq++
			select {
			case sem <- struct{}{}:
			default:
				if inSteady {
					stats.droppedBackpressure.Add(1)
				}
				continue
			}
			if inSteady {
				stats.dispatched.Add(1)
			}
			reqSeq := seq
			record := inSteady
			client := clients[reqSeq%uint64(len(clients))]

			path := cfg.Path
			if cfg.Mode == "emix" && emix != nil {
				path = emix.Pick(reqSeq)
			}
			fullURL := baseURL + path

			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				executeOneRequest(
					client,
					fullURL,
					cfg.HostHeader,
					cfg.Method,
					cfg.Mode == "cps",
					cfg.ExpectedStatus,
					record,
					stats,
				)
			}()
		}
		next := t0.Add(time.Duration(k+1) * tickInterval)
		if d := time.Until(next); d > 0 {
			time.Sleep(d)
		}
	}
	wg.Wait()

	return buildReport(cfg, stats, steadyStart, steadyEnd, false)
}

func runConcurrentConnections(cfg benchConfig, pool *ipPool, tlsCfg *tls.Config) benchReport {
	stats := newSteadyCounters()
	baseURL := strings.TrimRight(cfg.TargetBaseURL, "/")
	fullURL := baseURL + cfg.Path

	t0 := time.Now()
	steadyStart := t0.Add(cfg.RampUp)
	steadyEnd := steadyStart.Add(cfg.Steady)
	hardEnd := steadyEnd.Add(cfg.RampDown)

	// 后台在 Steady 窗口每秒采样当前活跃并发连接数
	stopSampler := make(chan struct{})
	var samplerWg sync.WaitGroup
	samplerWg.Add(1)
	go func() {
		defer samplerWg.Done()
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopSampler:
				return
			case now := <-ticker.C:
				cur := stats.activeConnsCurrent.Load()
				for {
					pk := stats.activeConnsPeak.Load()
					if cur <= pk || stats.activeConnsPeak.CompareAndSwap(pk, cur) {
						break
					}
				}
				if !now.Before(steadyStart) && now.Before(steadyEnd) {
					stats.steadyConnsSamples.Add(1)
					stats.steadyConnsSum.Add(uint64(maxInt64(0, cur)))
					for {
						mn := stats.steadyConnsMin.Load()
						if cur >= mn || stats.steadyConnsMin.CompareAndSwap(mn, cur) {
							break
						}
					}
				}
			}
		}
	}()

	var wg sync.WaitGroup
	perConnDelay := time.Duration(0)
	if cfg.Conns > 1 && cfg.RampUp > 0 {
		perConnDelay = cfg.RampUp / time.Duration(cfg.Conns)
	}

	for i := 0; i < cfg.Conns; i++ {
		if perConnDelay > 0 && i > 0 {
			time.Sleep(perConnDelay)
		}
		if !time.Now().Before(steadyEnd) {
			break
		}
		lip := pool.Next()
		workerID := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := makeHTTPClient(lip, tlsCfg, cfg, true)
			defer client.CloseIdleConnections()

			// 建连首请求（爬坡期不计入稳态事务）
			_, ok := executeOneRequest(client, fullURL, cfg.HostHeader, cfg.Method, false, cfg.ExpectedStatus, false, stats)
			if !ok {
				// 允许一次爬坡重连
				_, ok = executeOneRequest(client, fullURL, cfg.HostHeader, cfg.Method, false, cfg.ExpectedStatus, false, stats)
			}
			if !ok {
				return
			}
			stats.activeConnsCurrent.Add(1)
			defer stats.activeConnsCurrent.Add(-1)

			// 错峰初始等待，避免所有连接同步心跳
			if cfg.CCInterval > 0 {
				jitter := time.Duration(workerID%1000) * (cfg.CCInterval / 1000)
				if jitter > 0 {
					sleepUntilOrStop(time.Now().Add(jitter), steadyEnd)
				}
			}

			for {
				now := time.Now()
				if !now.Before(steadyEnd) {
					break
				}
				inSteady := !now.Before(steadyStart)
				if inSteady {
					stats.dispatched.Add(1)
				}
				reused, reqOK := executeOneRequest(client, fullURL, cfg.HostHeader, cfg.Method, false, cfg.ExpectedStatus, inSteady, stats)
				if inSteady && !reused {
					stats.ccReconnects.Add(1)
				}
				if !reqOK && inSteady {
					// 失败后保持循环尝试，错误已如实入账
				}
				if cfg.CCInterval > 0 {
					sleepUntilOrStop(time.Now().Add(cfg.CCInterval), steadyEnd)
				}
			}
			// Ramp-down 阶段错峰优雅关闭
			if cfg.RampDown > 0 {
				grace := time.Duration(workerID%100) * (cfg.RampDown / 100)
				sleepUntilOrStop(time.Now().Add(grace), hardEnd)
			}
		}()
	}

	wg.Wait()
	close(stopSampler)
	samplerWg.Wait()

	return buildReport(cfg, stats, steadyStart, steadyEnd, true)
}

func sleepUntilOrStop(target, stop time.Time) {
	if stop.Before(target) {
		target = stop
	}
	if d := time.Until(target); d > 0 {
		time.Sleep(d)
	}
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func buildReport(cfg benchConfig, s *steadyCounters, steadyStart, steadyEnd time.Time, includeCC bool) benchReport {
	durSec := steadyEnd.Sub(steadyStart).Seconds()
	if durSec <= 0 {
		durSec = 1
	}

	dispatched := s.dispatched.Load()
	completed := s.completed.Load()
	drops := s.droppedBackpressure.Load()
	totalAttempts := dispatched + drops

	totalFail := s.errTCPReset.Load() + s.errTimeout.Load() + s.errTLS.Load() + s.errOtherTransport.Load() + s.unexpectedHTTP.Load()
	errRatePct := 0.0
	if completed > 0 {
		errRatePct = round3(float64(totalFail) / float64(completed) * 100.0)
	}
	dropPct := 0.0
	if totalAttempts > 0 {
		dropPct = round3(float64(drops) / float64(totalAttempts) * 100.0)
	}

	goodputB := s.goodputBodyBytes.Load()
	wireB := s.wireEstBytes.Load()
	goodputGbps := round3(float64(goodputB) * 8.0 / durSec / 1e9)
	wireGbps := round3(float64(wireB) * 8.0 / durSec / 1e9)
	goodputMbps := round3(float64(goodputB) * 8.0 / durSec / 1e6)

	connNew := s.connNew.Load()
	achievedRPS := round3(float64(completed) / durSec)
	achievedCPS := round3(float64(connNew) / durSec)

	var cc *ccSummary
	if includeCC {
		minC := s.steadyConnsMin.Load()
		if minC == math.MaxInt64 {
			minC = 0
		}
		avgC := 0.0
		if smp := s.steadyConnsSamples.Load(); smp > 0 {
			avgC = round3(float64(s.steadyConnsSum.Load()) / float64(smp))
		}
		cc = &ccSummary{
			TargetConns:     cfg.Conns,
			PeakActiveConns: s.activeConnsPeak.Load(),
			SteadyMinConns:  minC,
			SteadyAvgConns:  avgC,
			Reconnects:      s.ccReconnects.Load(),
		}
	}

	return benchReport{
		Methodology:  "聚信压测工具 (JuXin Bench) — RFC 3511 / RFC 9411 (NetSecOPEN) L7 Benchmark (Steady-State Isolated)",
		GeneratedUTC: time.Now().UTC().Format(time.RFC3339),
		Config:       cfg,
		SteadyWindow: steadyWindow{
			StartUTC:        steadyStart.UTC().Format(time.RFC3339),
			EndUTC:          steadyEnd.UTC().Format(time.RFC3339),
			DurationSeconds: round3(durSec),
		},
		Summary: reportSummary{
			Dispatched:          dispatched,
			Completed:           completed,
			BackpressureDrops:   drops,
			BackpressureDropPct: dropPct,
			AchievedRPS:         achievedRPS,
			AchievedCPS:         achievedCPS,
			GoodputGbps:         goodputGbps,
			ThroughputEstGbps:   wireGbps,
			GoodputMbps:         goodputMbps,
			ErrorRatePct:        errRatePct,
			ZeroLossPass:        totalFail == 0 && completed > 0,
			ConnNewCount:        connNew,
			ConnReusedCount:     s.connReused.Load(),
		},
		Latency: latencyBreakdown{
			TCPConnect:   s.tcpHist.Summary(),
			TLSHandshake: s.tlsHist.Summary(),
			TTFB:         s.ttfbHist.Summary(),
			TTLB:         s.ttlbHist.Summary(),
		},
		StatusCodes: statusSummary{
			S2xx:      s.status2xx.Load(),
			S3xx:      s.status3xx.Load(),
			S401_403:  s.status401_403.Load(),
			S429:      s.status429.Load(),
			S4xxOther: s.status4xxOther.Load(),
			S5xx:      s.status5xx.Load(),
		},
		Errors: errorSummary{
			TCPReset:       s.errTCPReset.Load(),
			Timeout:        s.errTimeout.Load(),
			TLSError:       s.errTLS.Load(),
			OtherTransport: s.errOtherTransport.Load(),
			UnexpectedHTTP: s.unexpectedHTTP.Load(),
			TotalFailures:  totalFail,
		},
		ConcurrentCC: cc,
	}
}

func main() {
	var (
		mode           = flag.String("mode", "tps", "测试模式：tps | cps | cc | emix")
		targetURL      = flag.String("url", "", "目标基础 URL，如 https://10.10.1.10 或 http://10.10.1.10（必填）")
		path           = flag.String("path", "/static/256b.txt", "请求路径（emix 模式下自动按权重替换）")
		hostHeader     = flag.String("host", "", "Host 请求头与 TLS SNI（如 bench.wdsp.local）")
		method         = flag.String("method", "GET", "HTTP 方法")
		rate           = flag.Float64("rate", 1000, "开环恒定速率：tps/emix 下为 RPS，cps 下为新建连接/s")
		maxInFlight    = flag.Int("max-inflight", 2048, "最大在途请求数（超出记背压丢弃）")
		conns          = flag.Int("conns", 1000, "cc 模式下的目标并发连接数")
		ccInterval     = flag.Duration("cc-interval", 5*time.Second, "cc 模式每连接稳态心跳间隔")
		rampUp         = flag.Duration("ramp-up", 15*time.Second, "爬坡预热时长（不计入稳态成绩）")
		steady         = flag.Duration("steady", 60*time.Second, "稳态计量时长（仅此窗口计分）")
		rampDown       = flag.Duration("ramp-down", 5*time.Second, "降坡收尾时长（不计入稳态成绩）")
		timeout        = flag.Duration("timeout", 5*time.Second, "单请求超时")
		batch          = flag.Int("batch", 4, "每 tick 派发数")
		localIPs       = flag.String("local-ips", "", "多源 IP 池，如 10.10.1.101-10.10.1.132 或 10.10.1.64/27")
		emixPreset     = flag.String("emix-preset", "netsecopen", "emix 预设：netsecopen | enterprise_web | api_mixed")
		emixSpec       = flag.String("emix-spec", "", "自定义 emix 权重，如 /static/1k.bin:50,/static/64k.bin:50")
		tlsVersion     = flag.String("tls-version", "auto", "TLS 版本锁定：auto | 1.2 | 1.3")
		tlsCipher      = flag.String("tls-cipher", "", "TLS 1.2 密码套件锁定（如 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256）")
		tlsResume      = flag.Bool("tls-resume", false, "是否开启 TLS Session Resumption（默认 false 即完整握手）")
		http2          = flag.Bool("http2", false, "是否启用 HTTP/2（默认 false 测 HTTP/1.1）")
		insecure       = flag.Bool("insecure", true, "跳过自签测试证书校验")
		expectedStatus = flag.Int("expected-status", 200, "期望 HTTP 状态码（0 表示 <500 均视为成功）")
		outJSON        = flag.String("out-json", "", "输出结构化 JSON 报告路径")
	)
	flag.Parse()

	if strings.TrimSpace(*targetURL) == "" {
		fmt.Fprintln(os.Stderr, "错误: 必须指定 -url（例如 -url https://10.10.1.10 -host bench.wdsp.local）")
		flag.Usage()
		os.Exit(2)
	}
	parsedURL, err := url.Parse(*targetURL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		fmt.Fprintf(os.Stderr, "错误: 非法 -url %q\n", *targetURL)
		os.Exit(2)
	}
	if !strings.HasPrefix(*path, "/") {
		*path = "/" + *path
	}
	sni := *hostHeader
	if sni == "" {
		sni = parsedURL.Hostname()
	}

	ips, err := parseLocalIPs(*localIPs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: 解析 -local-ips 失败: %v\n", err)
		os.Exit(2)
	}
	pool := newIPPool(ips)

	tlsCfg, err := buildTLSConfig(*tlsVersion, *tlsCipher, sni, *insecure, *tlsResume)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: TLS 配置非法: %v\n", err)
		os.Exit(2)
	}

	var emix *emixProfile
	if *mode == "emix" {
		emix, err = buildEMIXProfile(*emixPreset, *emixSpec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "错误: EMIX 配置非法: %v\n", err)
			os.Exit(2)
		}
	}

	cfg := benchConfig{
		Mode:           strings.ToLower(strings.TrimSpace(*mode)),
		TargetBaseURL:  *targetURL,
		Path:           *path,
		HostHeader:     *hostHeader,
		Method:         strings.ToUpper(*method),
		Rate:           *rate,
		MaxInFlight:    *maxInFlight,
		Conns:          *conns,
		CCInterval:     *ccInterval,
		RampUp:         *rampUp,
		Steady:         *steady,
		RampDown:       *rampDown,
		Timeout:        *timeout,
		Batch:          *batch,
		LocalIPSpec:    *localIPs,
		LocalIPCount:   pool.Len(),
		EMIXPreset:     *emixPreset,
		EMIXSpec:       *emixSpec,
		TLSVersion:     *tlsVersion,
		TLSCipher:      *tlsCipher,
		TLSResume:      *tlsResume,
		HTTP2:          *http2,
		Insecure:       *insecure,
		ExpectedStatus: *expectedStatus,
	}

	var report benchReport
	switch cfg.Mode {
	case "tps", "cps", "emix":
		if cfg.Rate <= 0 {
			fmt.Fprintln(os.Stderr, "错误: -rate 必须大于 0")
			os.Exit(2)
		}
		report = runOpenLoop(cfg, pool, tlsCfg, emix)
	case "cc":
		if cfg.Conns <= 0 {
			fmt.Fprintln(os.Stderr, "错误: -conns 必须大于 0")
			os.Exit(2)
		}
		report = runConcurrentConnections(cfg, pool, tlsCfg)
	default:
		fmt.Fprintf(os.Stderr, "错误: 不支持的模式 %q（支持 tps | cps | cc | emix）\n", cfg.Mode)
		os.Exit(2)
	}

	payload, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "序列化报告失败: %v\n", err)
		os.Exit(1)
	}
	if *outJSON != "" {
		if err := os.WriteFile(*outJSON, payload, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "写入报告失败: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Println(string(payload))
}
