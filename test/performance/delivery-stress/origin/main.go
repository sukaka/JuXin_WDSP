// bench-origin：聚信压测工具万兆/云主机压测专用高性能测试源站（零外部依赖，支持静态交叉编译）。
//
// 特性：
//   1. 全套 NetSecOPEN / EMIX 标准静态载荷常驻内存（1B/256B/1K/4K/16K/64K/256K/1M），零磁盘 IO，轻松跑满万兆；
//   2. 所有 POST/PUT/PATCH/上传路由完整 drain 请求体后再回 200，杜绝大包上传早期 RST；
//   3. 支持自签 RSA-2048 或 ECDSA-P256 证书，支持 /v1/* API 路由与 /security-echo 安全回放路由。
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"
)

type apiResponse struct {
	OK        bool   `json:"ok"`
	Path      string `json:"path"`
	Method    string `json:"method"`
	BytesRead int64  `json:"bytes_read"`
	Origin    string `json:"origin"`
}

func makePayload(size int, fill byte) []byte {
	return bytes.Repeat([]byte{fill}, size)
}

func generateSelfSignedCert(keyType string) (tls.Certificate, error) {
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "bench.wdsp.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"bench.wdsp.local", "bench-origin.local", "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	switch strings.ToLower(strings.TrimSpace(keyType)) {
	case "ecdsa", "p256", "ecdsa-p256":
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return tls.Certificate{}, err
		}
		der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
		if err != nil {
			return tls.Certificate{}, err
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
	case "", "rsa", "rsa-2048":
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return tls.Certificate{}, err
		}
		der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
		if err != nil {
			return tls.Certificate{}, err
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
	default:
		return tls.Certificate{}, fmt.Errorf("unsupported key type %q (want rsa or ecdsa)", keyType)
	}
}

func drainBody(r *http.Request, maxBytes int64) (int64, error) {
	if r.Body == nil {
		return 0, nil
	}
	defer r.Body.Close()
	return io.Copy(io.Discard, io.LimitReader(r.Body, maxBytes))
}

func newOriginMux(maxBodyBytes int64, originLabel string) *http.ServeMux {
	payloads := map[string][]byte{
		"/static/1b.txt":    makePayload(1, '0'),
		"/static/256b.txt":  makePayload(256, 'A'),
		"/static/1k.bin":    makePayload(1024, '1'),
		"/static/4k.bin":    makePayload(4*1024, 'B'),
		"/static/16k.bin":   makePayload(16*1024, 'C'),
		"/static/64k.bin":   makePayload(64*1024, 'D'),
		"/static/256k.bin":  makePayload(256*1024, 'E'),
		"/static/1m.bin":    makePayload(1024*1024, 'M'),
	}
	okRoot := []byte(`{"status":"ok","service":"wdsp-bench-origin"}`)

	mux := http.NewServeMux()

	serveStatic := func(body []byte, contentType string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
				_, _ = drainBody(r, maxBodyBytes)
			}
			w.Header().Set("Content-Type", contentType)
			w.Header().Set("X-Wdsp-Bench-Origin", originLabel)
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
		}
	}

	mux.HandleFunc("/healthz", serveStatic([]byte("ok\n"), "text/plain; charset=utf-8"))
	for route, data := range payloads {
		ct := "application/octet-stream"
		if strings.HasSuffix(route, ".txt") {
			ct = "text/plain; charset=utf-8"
		}
		mux.HandleFunc(route, serveStatic(data, ct))
	}

	// /v1/* 命中 WDSP API 分类器，完整消费请求体后回 200 JSON
	mux.HandleFunc("/v1/", func(w http.ResponseWriter, r *http.Request) {
		n, err := drainBody(r, maxBodyBytes)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Wdsp-Bench-Origin", originLabel)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"ok":false,"error":"read_body_failed"}`))
			return
		}
		resp := apiResponse{
			OK:        true,
			Path:      r.URL.Path,
			Method:    r.Method,
			BytesRead: n,
			Origin:    originLabel,
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	})

	// 默认路径：完整 drain body 后回 200，保证安全语料回放与常规 Web 路由无意外 404 RST
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		n := int64(0)
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			n, _ = drainBody(r, maxBodyBytes)
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Wdsp-Bench-Origin", originLabel)
		if r.URL.Path == "/" || strings.HasPrefix(r.URL.Path, "/ping") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(okRoot)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"ok":true,"path":%q,"bytes_read":%d,"origin":%q}`, r.URL.Path, n, originLabel)
	})

	return mux
}

func main() {
	var (
		listenAddr  = flag.String("listen", ":18090", "HTTP 监听地址")
		tlsAddr     = flag.String("tls-listen", "", "可选 HTTPS 监听地址（例如 :18443）")
		tlsKeyType  = flag.String("tls-key-type", "rsa", "自签证书类型：rsa (RSA-2048) 或 ecdsa (ECDSA-P256)")
		maxBodyMB   = flag.Int64("max-body-mb", 8, "单请求最大完整消费请求体大小（MiB）")
		originLabel = flag.String("label", "wdsp-bench-origin", "X-Wdsp-Bench-Origin 响应标识")
	)
	flag.Parse()

	mux := newOriginMux((*maxBodyMB)*1024*1024, *originLabel)

	srv := &http.Server{
		Addr:              *listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	if *tlsAddr != "" {
		cert, err := generateSelfSignedCert(*tlsKeyType)
		if err != nil {
			log.Fatalf("generate self-signed cert: %v", err)
		}
		tlsSrv := &http.Server{
			Addr:              *tlsAddr,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			},
		}
		go func() {
			log.Printf("[bench-origin] HTTPS (%s) listening on %s", *tlsKeyType, *tlsAddr)
			if err := tlsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("https serve: %v", err)
			}
		}()
	}

	log.Printf("[bench-origin] HTTP listening on %s (EMIX routes: 1b/256b/1k/4k/16k/64k/256k/1m, /v1/*)", *listenAddr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("http serve: %v", err)
	}
}
