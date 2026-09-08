// nodepatch HA lab 节点身份补丁工具（deployment/ha-lab 专用，不进生产交付物）。
//
// 经 Caddy Admin Unix Socket 读取节点当前生效配置，为其中全部 jiuzhang_guard
// 处理器写入每节点唯一 gateway_node 与 api_node_heartbeat_seconds（心跳周期），
// 再经 /load 原子回写。幂等：重复执行结果相同。
//
// 背景（docs/HA_TWO_NODE_DESIGN.md §5 的 lab 落地手段）：
// 发布扇出把同一份构建产物推送全部登记节点——gateway_node 取管理面
// GATEWAY_NODE_NAME（单一值），api_node_heartbeat_seconds 暂无发布通道注入；
// 而双节点视图/心跳要求每节点唯一节点名。故 ha-lab 在每次发布成功后经本工具
// 对两节点分别打身份补丁；节点重启经 caddy run --resume 恢复 autosave（补丁态）
// 不丢身份。生产形态的按节点注入属发布通道后续工程（见设计文档 §8 边界声明）。
//
// 仅标准库，零第三方依赖。用法：
//
//	nodepatch -sock /sock/a/admin.sock -node gw-a -heartbeat 30
//	nodepatch -sock /sock/b/admin.sock -source-sock /sock/a/admin.sock -node gw-b
//
// -source-sock（首次纳管引导）：从源节点读取当前生效配置（通常是主节点发布态），
// 改写节点身份后 /load 到目标节点——用于新节点首次接收入口配置（节点注册握手
// 协议未交付前的 lab 引导动作；此后由发布扇出持续对齐）。此后每次发布后的身份
// 补丁不再需要 -source-sock（就地读改写）。
//
// 退出码：0 成功；1 参数/连接/协议错误；2 配置中未发现 jiuzhang_guard 处理器
// （通常表示尚未完成首次发布/引导，身份补丁无对象）。
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	sock := flag.String("sock", "", "节点 Caddy Admin Unix Socket 路径（容器内）")
	sourceSock := flag.String("source-sock", "", "可选：从该 socket 读取源配置（首次纳管引导）；缺省就地读取目标节点当前配置")
	node := flag.String("node", "", "该节点的唯一 gateway_node 名（如 gw-a）")
	heartbeat := flag.Int("heartbeat", 30, "api_node_heartbeat_seconds（合法范围 30-300，0=不写该键）")
	timeout := flag.Duration("timeout", 10*time.Second, "单次 Admin API 调用超时")
	flag.Parse()

	if *sock == "" || *node == "" {
		fmt.Fprintln(os.Stderr, "nodepatch: -sock 与 -node 均必填")
		os.Exit(1)
	}
	if *heartbeat != 0 && (*heartbeat < 30 || *heartbeat > 300) {
		fmt.Fprintln(os.Stderr, "nodepatch: -heartbeat 合法范围为 30-300（网关侧校验口径）")
		os.Exit(1)
	}

	client := unixClient(*sock, *timeout)

	// 1. 读配置：默认读目标节点当前生效配置（/config/ 返回活跃 JSON）；
	//    -source-sock 时读源节点配置（首次纳管引导：目标节点尚在引导配置，
	//    没有 guard 处理器可读改写）
	readSock := *sock
	if *sourceSock != "" {
		readSock = *sourceSock
	}
	cfg, err := getConfig(unixClient(readSock, *timeout))
	if err != nil {
		fmt.Fprintf(os.Stderr, "nodepatch: 读取配置失败（%s）: %v\n", readSock, err)
		os.Exit(1)
	}

	// 2. 为全部 jiuzhang_guard 处理器写入节点身份
	patched := patchGuardHandlers(cfg, *node, *heartbeat)
	if patched == 0 {
		fmt.Fprintln(os.Stderr, "nodepatch: 配置中未发现 jiuzhang_guard 处理器（尚未发布？）")
		os.Exit(2)
	}

	// 3. 原子回写（/load 全量替换；admin.listen 未改动，通道不中断）
	if err := loadConfig(client, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "nodepatch: 回写节点配置失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("nodepatch: node=%s 已补丁 %d 个 jiuzhang_guard 处理器（gateway_node=%s heartbeat=%ds）\n",
		*node, patched, *node, *heartbeat)
}

// unixClient 构造经 Unix Socket 拨号的 HTTP 客户端（Admin API 无鉴权，仅走 socket）。
func unixClient(sock string, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
	}
}

// getConfig GET /config/ 读取节点当前活跃配置（任意 JSON 结构原样保留）。
func getConfig(c *http.Client) (map[string]interface{}, error) {
	resp, err := c.Get("http://unix/config/")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /config/ 状态码 %d: %s", resp.StatusCode, truncate(body))
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, fmt.Errorf("解析配置 JSON: %w", err)
	}
	return cfg, nil
}

// loadConfig POST /load 原子回写配置。
func loadConfig(c *http.Client, cfg map[string]interface{}) error {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	resp, err := c.Post("http://unix/load", "application/json", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST /load 状态码 %d: %s", resp.StatusCode, truncate(body))
	}
	return nil
}

// patchGuardHandlers 递归遍历配置树，为每个 handler=="jiuzhang_guard" 的处理器
// 写入节点身份字段，返回补丁处理器个数。其余字段一律原样保留。
func patchGuardHandlers(v interface{}, node string, heartbeat int) int {
	switch t := v.(type) {
	case map[string]interface{}:
		n := 0
		if t["handler"] == "jiuzhang_guard" {
			t["gateway_node"] = node
			if heartbeat > 0 {
				t["api_node_heartbeat_seconds"] = float64(heartbeat)
			}
			n = 1
		}
		for _, child := range t {
			n += patchGuardHandlers(child, node, heartbeat)
		}
		return n
	case []interface{}:
		n := 0
		for _, child := range t {
			n += patchGuardHandlers(child, node, heartbeat)
		}
		return n
	default:
		return 0
	}
}

// truncate 截断错误响应体（防超大输出）。
func truncate(b []byte) string {
	const max = 512
	if len(b) > max {
		return string(b[:max]) + "..."
	}
	return string(b)
}
