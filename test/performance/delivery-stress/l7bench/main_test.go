package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestParseLocalIPs(t *testing.T) {
	ips, err := parseLocalIPs("10.10.1.101-10.10.1.104,10.10.1.200")
	if err != nil {
		t.Fatalf("parse range+single: %v", err)
	}
	if len(ips) != 5 {
		t.Fatalf("expected 5 IPs, got %d", len(ips))
	}
	if ips[0].String() != "10.10.1.101" || ips[4].String() != "10.10.1.200" {
		t.Fatalf("unexpected endpoints: %v", ips)
	}

	cidrIPs, err := parseLocalIPs("10.10.2.0/29")
	if err != nil {
		t.Fatalf("parse CIDR: %v", err)
	}
	// /29 has 8 addresses -> skip network & broadcast -> 6 usable host IPs
	if len(cidrIPs) != 6 {
		t.Fatalf("expected 6 usable IPs for /29, got %d", len(cidrIPs))
	}

	if _, err := parseLocalIPs("10.10.1.10-10.10.1.5"); err == nil {
		t.Fatalf("expected error for reversed IP range")
	}
	if _, err := parseLocalIPs("not-an-ip"); err == nil {
		t.Fatalf("expected error for invalid IP")
	}
}

func TestLatencyHistConcurrencyAndQuantiles(t *testing.T) {
	h := newLatencyHist()
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 1; i <= 100; i++ {
				h.Record(time.Duration(i) * time.Millisecond)
			}
		}()
	}
	wg.Wait()
	s := h.Summary()
	if s.Count != 400 {
		t.Fatalf("expected 400 samples, got %d", s.Count)
	}
	if s.P50Ms < 49.0 || s.P50Ms > 51.5 {
		t.Fatalf("unexpected p50: %v", s.P50Ms)
	}
	if s.P99Ms < 98.0 || s.P99Ms > 100.5 {
		t.Fatalf("unexpected p99: %v", s.P99Ms)
	}
	if s.MinMs != 1.0 || s.MaxMs != 100.0 {
		t.Fatalf("unexpected min/max: %v / %v", s.MinMs, s.MaxMs)
	}
}

func TestEMIXProfileDeterministicWeights(t *testing.T) {
	p, err := buildEMIXProfile("netsecopen", "")
	if err != nil {
		t.Fatalf("buildEMIXProfile: %v", err)
	}
	counts := make(map[string]int)
	for i := uint64(0); i < 1000; i++ {
		counts[p.Pick(i)]++
	}
	if counts["/static/1k.bin"] != 200 || counts["/static/1m.bin"] != 20 {
		t.Fatalf("unexpected distribution: %+v", counts)
	}

	custom, err := buildEMIXProfile("", "/a:3,/b:1")
	if err != nil {
		t.Fatalf("custom emix: %v", err)
	}
	if len(custom.Entries) != 2 || custom.totalWeight != 4 {
		t.Fatalf("unexpected custom emix: %+v", custom)
	}
}

func newTestServer(useTLS bool) *httptest.Server {
	mux := http.NewServeMux()
	sizes := map[string]int{
		"/static/256b.txt": 256,
		"/static/1k.bin":   1024,
		"/static/4k.bin":   4096,
		"/static/16k.bin":  16384,
		"/static/64k.bin":  65536,
		"/static/256k.bin": 262144,
		"/static/1m.bin":   1048576,
	}
	for p, sz := range sizes {
		body := bytes.Repeat([]byte("A"), sz)
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
		})
	}
	if useTLS {
		srv := httptest.NewUnstartedServer(mux)
		srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
		srv.StartTLS()
		return srv
	}
	return httptest.NewServer(mux)
}

func TestFourModesEndToEnd(t *testing.T) {
	httpSrv := newTestServer(false)
	defer httpSrv.Close()

	tlsSrv := newTestServer(true)
	defer tlsSrv.Close()

	pool := newIPPool(nil)

	// 1. TPS mode (Keep-Alive reuse, 3-phase steady state)
	tpsCfg := benchConfig{
		Mode: "tps", TargetBaseURL: httpSrv.URL, Path: "/static/256b.txt", Method: "GET",
		Rate: 100, MaxInFlight: 64, Batch: 2,
		RampUp: 100 * time.Millisecond, Steady: 400 * time.Millisecond, RampDown: 100 * time.Millisecond,
		Timeout: 2 * time.Second, ExpectedStatus: 200,
	}
	tlsAuto, _ := buildTLSConfig("auto", "", "", true, false)
	tpsRep := runOpenLoop(tpsCfg, pool, tlsAuto, nil)
	if !tpsRep.Summary.ZeroLossPass || tpsRep.Summary.Completed == 0 {
		t.Fatalf("tps failed: %+v", tpsRep.Summary)
	}
	if tpsRep.Summary.ConnReusedCount == 0 {
		t.Fatalf("expected connection reuse in tps mode, got %+v", tpsRep.Summary)
	}

	// 2. CPS mode over HTTPS TLS 1.2 Full Handshake (no reuse, TLS handshake measured)
	tls12, err := buildTLSConfig("1.2", "", "", true, false)
	if err != nil {
		t.Fatalf("buildTLSConfig 1.2: %v", err)
	}
	cpsCfg := benchConfig{
		Mode: "cps", TargetBaseURL: tlsSrv.URL, Path: "/static/256b.txt", Method: "GET",
		Rate: 40, MaxInFlight: 32, Batch: 1,
		RampUp: 100 * time.Millisecond, Steady: 400 * time.Millisecond, RampDown: 100 * time.Millisecond,
		Timeout: 3 * time.Second, ExpectedStatus: 200, TLSVersion: "1.2", TLSResume: false,
	}
	cpsRep := runOpenLoop(cpsCfg, pool, tls12, nil)
	if !cpsRep.Summary.ZeroLossPass || cpsRep.Summary.ConnNewCount == 0 || cpsRep.Summary.ConnReusedCount != 0 {
		t.Fatalf("cps failed: summary=%+v errors=%+v", cpsRep.Summary, cpsRep.Errors)
	}
	if cpsRep.Latency.TLSHandshake.Count == 0 || cpsRep.Latency.TCPConnect.Count == 0 {
		t.Fatalf("expected non-zero TCP and TLS handshake samples: %+v", cpsRep.Latency)
	}

	// 3. EMIX mode (NetSecOPEN multi-size)
	emix, _ := buildEMIXProfile("netsecopen", "")
	emixCfg := tpsCfg
	emixCfg.Mode = "emix"
	emixRep := runOpenLoop(emixCfg, pool, tlsAuto, emix)
	if !emixRep.Summary.ZeroLossPass || emixRep.Summary.GoodputMbps <= 0 {
		t.Fatalf("emix failed: %+v", emixRep.Summary)
	}

	// 4. CC mode (concurrent connections held across steady state)
	ccCfg := benchConfig{
		Mode: "cc", TargetBaseURL: httpSrv.URL, Path: "/static/256b.txt", Method: "GET",
		Conns: 12, CCInterval: 100 * time.Millisecond,
		RampUp: 150 * time.Millisecond, Steady: 450 * time.Millisecond, RampDown: 100 * time.Millisecond,
		Timeout: 2 * time.Second, ExpectedStatus: 200,
	}
	ccRep := runConcurrentConnections(ccCfg, pool, tlsAuto)
	if !ccRep.Summary.ZeroLossPass || ccRep.ConcurrentCC == nil || ccRep.ConcurrentCC.PeakActiveConns < 10 {
		t.Fatalf("cc failed: summary=%+v cc=%+v", ccRep.Summary, ccRep.ConcurrentCC)
	}
}
