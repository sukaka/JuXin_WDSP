// httpchain-origin —— NG-HTTP-01 记录型测试源站。
//
// 用途：登记「源站实际收到」的请求边界（方法/原始路径/头名序/声明长度 vs 实际体长/
// 体摘要/每连接请求计数），供 HTTP 解析链一致性测试比对网关安全判断与源站实况。
// 纪律：不记录真实凭据；请求体只留 sha256 摘要与长度（≤64KB 参与摘要）；
// 仅用于隔离测试环境，不得打进生产运行包。
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Record 单请求登记项（脱敏：仅头名序与允许清单头值）。
type Record struct {
	Seq            uint64            `json:"seq"`
	Conn           uint64            `json:"conn"`
	ConnSeq        int               `json:"conn_seq"`
	Method         string            `json:"method"`
	RawURI         string            `json:"raw_uri"`
	Host           string            `json:"host"`
	Proto          string            `json:"proto"`
	HeaderNames    []string          `json:"header_names"`
	AllowedHeaders map[string]string `json:"allowed_headers,omitempty"`
	DeclaredCL     int64             `json:"declared_cl"`
	TransferEnc    string            `json:"transfer_encoding,omitempty"`
	BodyLen        int               `json:"body_len"`
	BodySHA256     string            `json:"body_sha256"`
	TrailerPresent bool              `json:"trailer_present"`
	At             string            `json:"at"`
}

var headerValueAllowlist = map[string]bool{
	"content-length": true, "content-type": true, "connection": true,
	"transfer-encoding": true, "te": true,
	// 测试链自定义标记头（合成值，非凭据）
	"x-real-ip": true, "x-forwarded-for": true, "x-chain-case": true,
}

type recorder struct {
	mu      sync.Mutex
	seq     uint64
	records []Record
}

func (r *recorder) add(rec Record) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	rec.Seq = r.seq
	r.records = append(r.records, rec)
	return r.seq
}

func (r *recorder) since(from uint64) []Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []Record{}
	for _, rec := range r.records {
		if rec.Seq > from {
			out = append(out, rec)
		}
	}
	return out
}

func (r *recorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = nil
}

// connTracker 按连接分配 ID 并维护每连接请求计数（连接复用/走私判别用）。
type connTracker struct {
	mu   sync.Mutex
	next uint64
	ids  map[net.Conn]uint64
	seen map[net.Conn]int
}

func newConnTracker() *connTracker {
	return &connTracker{ids: map[net.Conn]uint64{}, seen: map[net.Conn]int{}}
}

func (t *connTracker) register(c net.Conn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.next++
	t.ids[c] = t.next
}

func (t *connTracker) note(c net.Conn) (id uint64, n int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.seen[c]++
	return t.ids[c], t.seen[c]
}

func main() {
	addr := os.Getenv("CHAIN_ORIGIN_ADDR")
	if addr == "" {
		addr = "127.0.0.1:18099"
	}
	rec := &recorder{}
	tracker := newConnTracker()

	mux := http.NewServeMux()
	mux.HandleFunc("/__chain/records", func(w http.ResponseWriter, r *http.Request) {
		from, _ := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
		w.Header().Set("Content-Type", "application/x-ndjson")
		for _, item := range rec.since(from) {
			b, _ := json.Marshal(item)
			fmt.Fprintln(w, string(b))
		}
	})
	mux.HandleFunc("/__chain/reset", func(w http.ResponseWriter, r *http.Request) {
		rec.reset()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		connID, connSeq := tracker.note(r.Context().Value(connKey{}).(net.Conn))
		body, _ := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		sum := sha256.Sum256(body)
		names := make([]string, 0, len(r.Header))
		allowed := map[string]string{}
		for name := range r.Header {
			names = append(names, name)
			if headerValueAllowlist[strings.ToLower(name)] {
				allowed[strings.ToLower(name)] = r.Header.Get(name)
			}
		}
		trailer := len(r.Trailer) > 0
		rec.add(Record{
			Conn:           connID,
			ConnSeq:        connSeq,
			Method:         r.Method,
			RawURI:         r.RequestURI,
			Host:           r.Host,
			Proto:          r.Proto,
			HeaderNames:    names,
			AllowedHeaders: allowed,
			DeclaredCL:     r.ContentLength,
			TransferEnc:    r.Header.Get("Transfer-Encoding"),
			BodyLen:        len(body),
			BodySHA256:     hex.EncodeToString(sum[:]),
			TrailerPresent: trailer,
			At:             time.Now().UTC().Format(time.RFC3339Nano),
		})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Chain-Origin", "httpchain-recorder")
		// /_wdsp/bot/v1/ 保留命名空间按网关墓碑三重判据同形返回（404 + no-store +
		// 精确正文 "404 not found"）：从未启用 Bot 的应用该命名空间会落到上游
		// （网关 bot_step 设计如此，首次 OFF=RELEASED 不抢占业务路径），发布冒烟
		// 探针据该三重判据认定「完整防护链执行」——与网关 bot_step 墓碑逐字节同形。
		if strings.HasPrefix(r.URL.Path, "/_wdsp/bot/v1/") {
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("404 not found"))
			return
		}
		fmt.Fprintf(w, `{"ack":true,"conn":%d,"conn_seq":%d}`, connID, connSeq)
	})

	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			tracker.register(c)
			return context.WithValue(ctx, connKey{}, c)
		},
	}
	log.Printf("httpchain-origin listening on %s", addr)
	log.Fatal(srv.ListenAndServe())
}

type connKey struct{}
