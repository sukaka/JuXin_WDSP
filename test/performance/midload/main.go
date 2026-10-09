// midload：S8 批次 B 档 2 机器身份臂采样器（测试基建，非生产代码）。
// 复用 test/waf/mid-e2e 的 sf.go/sign.go（S7 冻结参照实现原样拷贝，不改语义）：
// 每请求独立签名（随机 nonce——重放 Store 真实写路径），客户端视角计时落 CSV。
package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func nowUnix() int64 { return time.Now().Unix() }

func randomNonce() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FATAL: "+format+"\n", args...)
	os.Exit(2)
}

func mustURL(path, rawQuery string) *url.URL {
	if !strings.HasPrefix(path, "/") {
		fatal("path 须 / 开头")
	}
	return &url.URL{Path: path, RawQuery: rawQuery}
}

func main() {
	var (
		gw     = flag.String("gw", "http://127.0.0.1:18080", "网关基址")
		host   = flag.String("host", "", "Host 头（必填）")
		path   = flag.String("path", "/mid/ping", "路径")
		dir    = flag.String("dir", "", "密钥目录（mid-e2e keygen 产物，必填）")
		kid    = flag.String("kid", "", "签名 kid（必填）")
		n      = flag.Int("n", 300, "采样数")
		warmup = flag.Int("warmup", 10, "预热数（丢弃）")
		out    = flag.String("out", "", "CSV 输出（必填）")
		unsigned = flag.Bool("unsigned", false, "不携带签名头（同宿主模块在/验签缺席对照臂）")
	)
	flag.Parse()
	if *host == "" || *out == "" || (!*unsigned && (*dir == "" || *kid == "")) {
		fatal("usage: midload -host H -dir D -kid K -out F [-n N]")
	}
	var key *midKey
	if !*unsigned {
		var err error
		key, err = loadKey(*dir, *kid)
		if err != nil {
			fatal("加载密钥: %v", err)
		}
	}
	f, err := os.Create(*out)
	if err != nil {
		fatal("create out: %v", err)
	}
	defer f.Close()
	fmt.Fprintln(f, "seq,duration_ms,status")

	client := &http.Client{Timeout: 5 * time.Second}
	total := *warmup + *n
	ok := 0
	for i := 0; i < total; i++ {
		req := &http.Request{
			Method: http.MethodGet,
			Host:   *host,
			Header: http.Header{},
			URL:    mustURL(*path, ""),
		}
		req.Header.Set("User-Agent", "jiuzhang-midload/1.0 (S8 perf arm I1)")
		if err := signRequest(req, nil, key, *dir, signOptions{unsigned: *unsigned}); err != nil {
			fatal("签名: %v", err)
		}
		// http.Request 缺 URL.Scheme/Host 时 client 无法发——经 RequestURI 组装：
		realURL := *gw + req.URL.RequestURI()
		hreq, err := http.NewRequest(req.Method, realURL, nil)
		if err != nil {
			fatal("构造请求: %v", err)
		}
		hreq.Host = *host
		hreq.Header = req.Header
		start := time.Now()
		resp, err := client.Do(hreq)
		durMs := float64(time.Since(start).Nanoseconds()) / 1e6
		if err != nil {
			if i >= *warmup {
				fmt.Fprintf(f, "%d,%.3f,0\n", i, durMs)
			}
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if i >= *warmup {
			fmt.Fprintf(f, "%d,%.3f,%d\n", i, durMs, resp.StatusCode)
			if resp.StatusCode == 200 {
				ok++
			}
		}
	}
	fmt.Printf("midload n=%d ok200=%d kid=%s\n", *n, ok, *kid)
}
