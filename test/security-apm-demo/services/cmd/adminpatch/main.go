// adminpatch P1-01 A4 一次性工具：经 Caddy Admin Unix Socket 为已发布配置中的
// 全部 jiuzhang_guard 处理器显式开启 trace_inject_upstream（APM ADR D6 网关侧能力）。
//
// 背景：发布侧管理面取值接线（server GuardConfig.TraceInjectUpstream）当前恒 false
// 不下发（gatewayconfig/guard.go 字段注释），而网关联动演示需要网关向上游注入
// traceparent，使演示业务 Span 与网关 access_logs.trace_id 同一 trace 续接。
// 本工具只改运行态配置（不落产品代码、不改发布侧行为）：GET /config/ → 递归为
// handler==jiuzhang_guard 的处理器补 trace_inject_upstream=true → POST /load 原子加载
// → 回读校验。每次重新发布后发布内容会覆盖本补丁，须由 run.sh 在每次发布后再执行。
//
// 保密纪律：活跃配置可能含下发秘密材料（identity_salt 等），本工具不回显、不落盘
// 配置内容，标准输出仅打印补丁计数等聚合数字。
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

const defaultSocket = "/run/caddy-admin/admin.sock"

func main() {
	socket := os.Getenv("ADMIN_SOCKET")
	if socket == "" {
		socket = defaultSocket
	}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socket)
			},
		},
		Timeout: 20 * time.Second,
	}

	cfg, err := getConfig(client)
	if err != nil {
		fatal("读取活跃配置失败: %v", err)
	}
	patched := 0
	walk(cfg, &patchApplier{n: &patched})
	if patched == 0 {
		fatal("活跃配置中未找到 jiuzhang_guard 处理器（尚未发布？）")
	}
	body, err := json.Marshal(cfg)
	if err != nil {
		fatal("序列化配置失败: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://caddy/load", bytes.NewReader(body))
	if err != nil {
		fatal("构造 /load 请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fatal("POST /load 失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		fatal("POST /load 返回 %d（配置未生效）", resp.StatusCode)
	}

	// 回读校验：全部 guard 处理器必须带 trace_inject_upstream=true
	after, err := getConfig(client)
	if err != nil {
		fatal("回读校验失败: %v", err)
	}
	enabled := 0
	walk(after, &verifyApplier{n: &enabled})
	if enabled != patched {
		fatal("回读校验不一致：补丁 %d 处，回读确认 %d 处", patched, enabled)
	}
	fmt.Printf("{\"patched_handlers\":%d,\"verified\":true}\n", patched)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	os.Exit(1)
}

func getConfig(client *http.Client) (map[string]any, error) {
	resp, err := client.Get("http://caddy/config/")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /config/ 返回 %d", resp.StatusCode)
	}
	var cfg map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("解析配置 JSON: %w", err)
	}
	return cfg, nil
}

// walker 递归遍历 Caddy JSON 配置的访问者接口。
type walker interface {
	visitMap(m map[string]any)
}

type patchApplier struct{ n *int }

func (p *patchApplier) visitMap(m map[string]any) {
	if m["handler"] == "jiuzhang_guard" {
		m["trace_inject_upstream"] = true
		*p.n++
	}
}

type verifyApplier struct{ n *int }

func (v *verifyApplier) visitMap(m map[string]any) {
	if m["handler"] == "jiuzhang_guard" && m["trace_inject_upstream"] == true {
		*v.n++
	}
}

func walk(v any, w walker) {
	switch t := v.(type) {
	case map[string]any:
		w.visitMap(t)
		for _, child := range t {
			walk(child, w)
		}
	case []any:
		for _, child := range t {
			walk(child, w)
		}
	}
}
