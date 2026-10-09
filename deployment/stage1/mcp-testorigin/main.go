// mcp-testorigin MCP 测试源站（NG-MCP G1 批次 C 联调源站，设计
// docs/nextgen/NG-MCP-g1-toolcall.md §4「测试源站形态（冻结）」承载）。
//
// 方案选择理由（登记）：Go stdlib 手工实现最小 Streamable HTTP MCP server
// （零第三方依赖）——四件套中的流式工具需要「首条正常、次条敏感」的刻意 SSE
// 线格式（官方 SDK server 抽象掉确切帧序列，无法确定性产出「第二条 result 敏感」
// 的病理形态；grpc-testorigin 手工构造描述符同思想——测试源站按冻结协议文本
// 手工实现 wire 形态，协议保真由客户端侧官方 SDK（test/waf/mcp-e2e，
// modelcontextprotocol/go-sdk v1.8.0）保证，对测纪律「禁 curl 冒充 MCP 调用」
// 不受源站实现方式影响）。
//
// 四件套工具（设计 §4 冻结）：
//   - echo（正常工具）：参数回显 + origin_mark 到达实证（响应头
//     X-Wdsp-Origin-Mark 与 structuredContent.origin_mark 双通道——与
//     testorigin/grpc-testorigin 受控源站标记契约同源）；
//   - sensitive_read（敏感返回工具）：结果含合成秘密值（00000000000000000X——
//     合成数据非真实秘密，命中值级规则 id_card 锚定正则）；
//   - stream_read（流式工具）：SSE 多消息结果——首条 notifications/progress
//     （正常）次条 result（敏感），M04「首条实收/次条不外发」断言锚点；
//   - admin_delete（高风险工具）：管理面登记 risk_level=HIGH+approval_required
//     的对测目标；带调用计数器（「未授权调用确实没有到达测试工具」的计数器
//     断言锚点，§11.4 原文）——/_counts 只读端点供断言侧取数。
//
// 协议面（2025-11-25 冻结基准的最小子集）：单端点 POST /mcp、JSON-RPC 2.0、
// initialize（protocolVersion 回显协商——多版本协商强制不在 G1）/
// notifications/*（202）/ping/tools\list/tools\call；响应可为 application/json
// 或 text/event-stream；Mcp-Session-Id 会话头签发与宽容接收；GET /mcp 405
// （反向请求面不在 G1 覆盖，观测即可）。批处理按冻结版协议已移除拒收 -32600。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// syntheticIDCard 合成秘密值（合成数据非真实秘密；命中值级规则 id_card
// 锚定正则 ^\d{17}[\dXx]$——全串恰 18 字符才命中（锚定语义））。
const syntheticIDCard = "00000000000000000X"

// originMark 受控源站标记（与 testorigin/grpc-testorigin 同契约键）。
const originMark = "mcp-test-origin"

var counters = map[string]*atomic.Int64{
	"echo":           {},
	"sensitive_read": {},
	"stream_read":    {},
	"admin_delete":   {},
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type callParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

func writeRPCResult(w http.ResponseWriter, id json.RawMessage, result any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0", "id": id, "result": result,
	})
}

func writeRPCError(w http.ResponseWriter, id json.RawMessage, code int, msg string) {
	if id == nil {
		id = json.RawMessage("null")
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": msg},
	})
}

func toolResult(text string, structured map[string]any) map[string]any {
	out := map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": false,
	}
	if structured != nil {
		out["structuredContent"] = structured
	}
	return out
}

// toolDefs 四件套工具定义（inputSchema 与管理面目录在册 schema 对齐——
// 目录为审批面真源，源站 schema 仅供客户端 tools/list 展示）。
func toolDefs() []map[string]any {
	obj := func(props map[string]any, required []string) map[string]any {
		return map[string]any{
			"type": "object", "properties": props,
			"required": required, "additionalProperties": false,
		}
	}
	return []map[string]any{
		{"name": "echo", "description": "参数回显（正常工具）",
			"inputSchema": obj(map[string]any{"text": map[string]any{"type": "string"}}, []string{"text"})},
		{"name": "sensitive_read", "description": "读取记录（结果含合成秘密值）",
			"inputSchema": obj(map[string]any{}, []string{})},
		{"name": "stream_read", "description": "流式读取（SSE 多消息：首条正常次条敏感）",
			"inputSchema": obj(map[string]any{}, []string{})},
		{"name": "admin_delete", "description": "删除记录（高风险，带调用计数器）",
			"inputSchema": obj(map[string]any{"target": map[string]any{"type": "string"}}, []string{"target"})},
	}
}

func handleCall(w http.ResponseWriter, req rpcRequest) {
	var p callParams
	if err := json.Unmarshal(req.Params, &p); err != nil || p.Name == "" {
		writeRPCError(w, req.ID, -32602, "invalid tools/call params")
		return
	}
	switch p.Name {
	case "echo":
		counters["echo"].Add(1)
		text, _ := p.Arguments["text"].(string)
		writeRPCResult(w, req.ID, toolResult("echo:"+text, map[string]any{
			"origin_mark": originMark,
			"echo":        p.Arguments,
		}))
	case "sensitive_read":
		counters["sensitive_read"].Add(1)
		writeRPCResult(w, req.ID, toolResult("record read ok", map[string]any{
			"record_id": "REC-2026-0001",
			"id_card":   syntheticIDCard, // 合成秘密值（M04 非流式敏感结果锚点）
		}))
	case "stream_read":
		counters["stream_read"].Add(1)
		// SSE 多消息结果：首条 progress（正常）次条 result（敏感）——
		// M04「首条实收/次条不外发+断连」断言线格式（确定性产出是手工源站的存在理由）
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		fmt.Fprintf(w, "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":\"s5-stream\",\"progress\":1,\"total\":2,\"message\":\"phase-1 normal\"}}\n\n")
		if flusher != nil {
			flusher.Flush()
		}
		time.Sleep(100 * time.Millisecond) // 首条先达（断言「首条实收」时间序锚点）
		id := req.ID
		if id == nil {
			id = json.RawMessage("null")
		}
		fmt.Fprintf(w, "data: {\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"phase-2 done\"}],\"structuredContent\":{\"record_id\":\"REC-2026-0002\",\"id_card\":\"%s\"}}}\n\n", string(id), syntheticIDCard)
		if flusher != nil {
			flusher.Flush()
		}
	case "admin_delete":
		counters["admin_delete"].Add(1)
		writeRPCResult(w, req.ID, toolResult("deleted", map[string]any{"deleted": true}))
	default:
		writeRPCError(w, req.ID, -32602, "unknown tool: "+p.Name)
	}
}

func mcpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// GET（SSE 通道开启）：反向请求面不在 G1 覆盖（设计 §1.2/§3）——405 如实
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("X-Wdsp-Origin-Mark", originMark)
	var req rpcRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeRPCError(w, nil, -32700, "parse error")
		return
	}
	if req.JSONRPC != "2.0" {
		writeRPCError(w, req.ID, -32600, "invalid request")
		return
	}
	switch {
	case req.Method == "initialize":
		var initParams struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &initParams)
		pv := initParams.ProtocolVersion
		if pv == "" {
			pv = "2025-11-25" // 冻结基准缺省（多版本协商强制不在 G1——回显协商）
		}
		w.Header().Set("Mcp-Session-Id", fmt.Sprintf("s5-%d", time.Now().UnixNano()))
		writeRPCResult(w, req.ID, map[string]any{
			"protocolVersion": pv,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "mcp-testorigin", "version": "1.0.0"},
		})
	case strings.HasPrefix(req.Method, "notifications/"):
		w.WriteHeader(http.StatusAccepted)
	case req.Method == "ping":
		writeRPCResult(w, req.ID, map[string]any{})
	case req.Method == "tools/list":
		writeRPCResult(w, req.ID, map[string]any{"tools": toolDefs()})
	case req.Method == "tools/call":
		handleCall(w, req)
	default:
		writeRPCError(w, req.ID, -32601, "method not found")
	}
}

func main() {
	listen := flag.String("listen", ":18572", "HTTP 监听地址（内网测试源站）")
	flag.Parse()
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", mcpHandler)
	// 调用计数器（「未授权调用确实没有到达测试工具」的断言锚点，设计 §11.4/§4）
	mux.HandleFunc("/_counts", func(w http.ResponseWriter, r *http.Request) {
		out := map[string]int64{}
		var total int64
		for name, c := range counters {
			v := c.Load()
			out[name] = v
			total += v
		}
		out["total"] = total
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("/_reset", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		for _, c := range counters {
			c.Store(0)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})
	log.Printf("mcp-testorigin listening on %s (tools: echo/sensitive_read/stream_read/admin_delete)", *listen)
	log.Fatal(http.ListenAndServe(*listen, mux))
}
