// capability_report.go 节点能力清单自报（NG-COV-04 guard 侧；契约 NG-BASE-02 §2.1
// CapabilityManifest，类型与校验在 dynamic_security/capability）。
//
// 语义与纪律：
//   - 与 coverage 开关解耦：能力清单是发布门的自报事实，不绑
//     COVERAGE_OBSERVATIONS_ENABLED；默认开启，`CAPABILITY_REPORT_DISABLED=1`
//     显式关闭（排障用；关闭后发布门禁按「清单缺失」fail-closed——有需求时不放行）；
//   - 进程级单例（与 coverage_out 同形态）：Provision 首用懒启动（sync.Once），
//     60s janitor 刷新 generated_at 原子重写（tmp+rename）；
//   - 输出 `<sidecarDir>/capability.json`：sidecarDir 取 GATEWAY_SIDECAR_DIR
//     （默认 /var/run/caddy/sidecars，目录不存在创建；api 容器经共享卷读取）；
//   - 写失败只记日志不 panic（自报失败不改变请求处理；门禁侧按清单缺失拒绝）；
//   - 清单内容逐键有据（写死为进程常量的自报表，不报未实现能力）：
//     protocols.http="1.1"——caddy 现有 h1/h2，v1 先按 1.1 报（h2 伪头/优先级
//     语义审计未做，h2 层级评估留后续批次）；
//     protocols.graphql="parse"——parser/parse_graphql.go 基础识别，无 AST 成本核算
//     （cost_v1 未实现不得报）；
//     protocols.grpc="frame"——parser/parse_grpc.go 帧结构校验；有描述符下发
//     （GRPCDescriptors 编译注册非空）时报 "unary_g1"（detectors/grpc_desc.go
//     字段级深检生效），无描述符时不得报 unary_g1；stream_g2 未实现；
//     protocols.mcp="observe"——detectors/mcp.go 观察线索（acl_v1 执行层未实现）；
//     actions 按决策枚举实报（block/temp_block/rate_limit/risk_challenge/mask_response/observe/allow；
//     risk_challenge 复用 Bot 挑战执行层；grpc_error 无协议适配执行层不得报）；
//     limits.max_grpc_frame_bytes 取当前生效值（api_grpc_max_frame_bytes 下发值
//     ≤0 时按 dsctx.DefaultGRPCMaxFrameBytes 4MiB 兜底——与 pipeline 兜底链一致）；
//   - product_version 为信息性字段（契约：不作为能力判定依据）：进程内无产品
//     版本 ldflags 注入点，报产品线标识常量；build_digest：xcaddy 构建的 caddy
//     自报 build 信息进程内不可得，按契约填空串（不得编造）。
package jiuzhang_guard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/jiuzhang-waf/gateway/dynamic_security/capability"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// 环境变量名与默认值（装配常量）。
const (
	capDisabledEnv       = "CAPABILITY_REPORT_DISABLED"
	capSidecarEnv        = "GATEWAY_SIDECAR_DIR"
	defaultCapSidecarDir = "/var/run/caddy/sidecars"
	capFileName          = "capability.json"
	capTick              = 60 * time.Second
	// capProductVersion 信息性产品线标识（非能力判定依据；产品版本随发布通道
	// wdsp-vX.Y.Z tag 管理，进程内无注入点，v1 报产品线常量）。
	capProductVersion = "jiuzhang-guard/wdsp"
)

// capabilityInputs 清单可变输入（Provision 每次刷新；grpc 层级翻转由 GRPCUnary 控制）。
type capabilityInputs struct {
	NodeID            string
	GRPCUnary         bool  // 有描述符注册表下发 → protocols.grpc=unary_g1 + detectors grpc.unary
	MaxGRPCFrameBytes int64 // ≤0 时按 dsctx.DefaultGRPCMaxFrameBytes 兜底
}

// capHandle 自报句柄（仅开启时构建）。
type capReportHandle struct {
	dir     string
	mu      sync.Mutex
	inputs  capabilityInputs
	stopJan chan struct{}
	janDone chan struct{}
}

var (
	capOnce   sync.Once
	capHandle *capReportHandle
)

// capabilityReportDisabled 关闭开关（真值集与 coverage_out 同口径）。
func capabilityReportDisabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(capDisabledEnv))) {
	case "1", "true", "on", "yes":
		return true
	}
	return false
}

// capabilitySidecarDir sidecar 目录（环境变量缺省回退默认；与 server 侧
// gatewayconfig.DefaultSidecarDir 同路径契约）。
func capabilitySidecarDir() string {
	if v := strings.TrimSpace(os.Getenv(capSidecarEnv)); v != "" {
		return v
	}
	return defaultCapSidecarDir
}

// buildCapabilityManifest 由输入构造清单（纯函数；now 注入便于测试）。
func buildCapabilityManifest(in capabilityInputs, now time.Time) capability.Manifest {
	grpcLevel := "frame"
	detectors := []capability.DetectorCap{
		{Name: "pipeline", Version: "pipeline/1"},  // dynamic_security/pipeline 统一引擎
		{Name: "authzdecide", Version: "az/4"},     // detectors/authzdecide.go 授权决策（ANY_OF=OWNER/SHARED_WITH；含 az/3 实断资格及 az/2 水位/租约/冲突集消费）
		{Name: "flowguard", Version: "flow/1"},     // detectors/flowguard 强流程（NG-FLOW-02：Valkey Lua 原子预留+fencing、OBSERVE/PROTECT 定义级实断；D12 能力门——含 PROTECT 定义的快照要求 flow/1）
		{Name: "graphql.parser", Version: "gql/1"}, // parser/parse_graphql.go 基础识别
		{Name: "grpc.frame", Version: "grpc/1"},    // parser/parse_grpc.go + detectors/grpc.go 帧校验
		{Name: "mcp.observe", Version: "mcp/1"},    // detectors/mcp.go 观察线索
		{Name: "mcp.toolcall", Version: "mcp/2"},      // detectors/mcpguard G1 完成态（NG-MCP D13：目录消费+转发前检查链+结果检查+协议化执行；mcp/1=观察线索——恒报进程能力不绑配置态，S5 偏差 2 教训承接）
		{Name: "mcp.pinning", Version: "mcppin/1"},    // Phase 9C-1：MCP 工具钉扎防 Rug Pull + 响应间接提示词净化 + Streamable HTTP 会话绑定 + OAuth 2.1 元数据
		{Name: "a2aguard", Version: "a2a/1"},          // Phase 9C-1：A2A 协议安全网关（Agent Card/AgBOM 发现 + RFC 8693 委派链作用域衰减 + 循环熔断 + Lethal Trifecta）
		{Name: "machineid", Version: "mid/1"},         // detectors/machineid G1 完成态（NG-ID D11：登记册消费+十步验证链+重放原子存储+轮换撤销水位+协议化执行——恒报进程能力不绑配置态）
		{Name: "jwt.binding", Version: "jwtbind/1"}, // Phase 9A-1：OAuth 2.0 DPoP (RFC 9449) + mTLS (RFC 8705) 令牌持有证明绑定
		{Name: "aicrawl", Version: "aicrawl/1"},     // Phase 9A-2：Web Bot Auth (RFC 9421) + AI 爬虫治理 + 离线 AI Labyrinth
		{Name: "clientside", Version: "clientside/1"}, // Phase 9B：客户端供应链安全（Magecart 防护 / PCI DSS 4.0 6.4.3 & 11.6.1）
		{Name: "semantic", Version: "semantic/1"},     // Phase 9C-2：本地离线 ONNX/SLM 语义防火墙（Unix Socket 客户端 + 熔断/并发护栏）
		{Name: "wasmplugin", Version: "wasm/1"},       // Phase 9D-1：Wasm（wazero 纯 Go 解释器）热插拔自定义检测插件沙箱
	}
	if in.GRPCUnary {
		grpcLevel = "unary_g1"
		detectors = append(detectors, capability.DetectorCap{Name: "grpc.unary", Version: "grpc/2"}) // detectors/grpcguard G1 完成态（NG-GRPC D10：重组+解压+结构校验+协议化执行；grpc/1=帧校验+描述符观测）
	}
	maxFrame := in.MaxGRPCFrameBytes
	if maxFrame <= 0 {
		maxFrame = dsctx.DefaultGRPCMaxFrameBytes
	}
	return capability.Manifest{
		ContractVersion: capability.ContractVersion,
		NodeID:          in.NodeID,
		ProductVersion:  capProductVersion,
		BuildDigest:     "", // xcaddy 构建的 caddy 自报 build 信息进程内不可得；契约允许空串，不编造
		Protocols: map[string]string{
			"http":    "1.1",
			"graphql": "parse",
			"grpc":    grpcLevel,
			"mcp":     "pin_v2", // Phase 9C-1：mcpguard 工具钉扎/间接提示词防护/会话绑定在 binary 即成立（涵盖 observe/acl_v1/pin_v2）
			"tls_mux": "v1",     // caddy.listeners.jiuzhang_tls_mux 与 http.reverse_proxy.transport.jiuzhang_tls 在 binary 即成立
			"tlcp":    "1.1",    // gotlcp TLCP 1.1（SM2/SM3/SM4）双证自识别与加密回源能力
		},
		Detectors:   detectors,
		Actions:     []string{"block", "temp_block", "rate_limit", "risk_challenge", "mask_response", "observe", "allow", "tarpit", "http_402"},
		Limits:      map[string]int64{"max_grpc_frame_bytes": maxFrame},
		GeneratedAt: now.UTC().Format(time.RFC3339),
	}
}

// provisionCapabilityReport 能力自报装配（Provision 调用）：默认开启——
// 首用懒启动 janitor 并立即写一份清单，随后每次 Provision 刷新可变输入
// （多应用共享进程级单例；节点级能力与单应用 Cleanup 解耦，避免互相踩踏）。
func (g *Guard) provisionCapabilityReport() {
	if capabilityReportDisabled() {
		return
	}
	capOnce.Do(func() {
		h := &capReportHandle{
			dir:     capabilitySidecarDir(),
			stopJan: make(chan struct{}),
			janDone: make(chan struct{}),
		}
		capHandle = h
		go h.janitor(capTick)
	})
	if capHandle == nil {
		return
	}
	nodeID := strings.TrimSpace(g.GatewayNode)
	if nodeID == "" {
		nodeID = coverageNodeName()
	}
	capHandle.update(capabilityInputs{
		NodeID: nodeID,
		// GRPCUnary 恒 true：detectors/protocols 为进程能力清单（grpcguard
		// （G1 完成态：重组+解压+结构校验+协议化执行）在 binary 即能力成立，
		// 与 flowguard=flow/1、authzdecide=az/4 恒报同纪律——若绑定「当前配置
		// 有描述符」则首次引入描述符的发布被能力门死锁（需求 unary_g1+grpc/2，
		// 自报 frame/空——fail-closed 永拒；批次 C 联调实证）
		GRPCUnary:         true,
		MaxGRPCFrameBytes: int64(g.APIGRPCMaxFrameBytes),
	})
}

// update 刷新清单输入并立即重写一次（Provision 调用；启动/配置变更即时生效，
// 不等下个 tick）。
func (h *capReportHandle) update(in capabilityInputs) {
	h.mu.Lock()
	h.inputs = in
	h.mu.Unlock()
	h.writeOnce()
}

// writeOnce 按当前输入生成清单并原子写（tmp+rename；写失败只记日志不 panic）。
func (h *capReportHandle) writeOnce() {
	h.mu.Lock()
	in := h.inputs
	h.mu.Unlock()
	m := buildCapabilityManifest(in, time.Now())
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil { // 结构全字段可序列化，理论不可达；失败仅记日志
		caddy.Log().Error("capability manifest marshal failed")
		return
	}
	if err := os.MkdirAll(h.dir, 0o770); err != nil {
		caddy.Log().Error("capability sidecar dir create failed")
		return
	}
	// 容器入口启用 umask 077 以保护 admin.sock，会导致 MkdirAll 产出的 sidecars 目录变为 0700；
	// 显式 chmod 0770 让同组 1000 的 netmgrd（cap_drop ALL、无 CAP_DAC_OVERRIDE）可读写 sidecars，
	// capability.json 自身仍受 umask 077 约束保持 0600，不向同组暴露。
	if err := os.Chmod(h.dir, 0o770); err != nil {
		caddy.Log().Warn("capability sidecar dir chmod failed")
	}
	tmp := filepath.Join(h.dir, capFileName+".tmp")
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		caddy.Log().Error("capability manifest write failed")
		return
	}
	if err := os.Rename(tmp, filepath.Join(h.dir, capFileName)); err != nil {
		caddy.Log().Error("capability manifest rename failed")
	}
}

// janitor 周期刷新 generated_at 重写（清单内容不变也刷新——staleness 判定以
// generated_at 为准，停刷新即声明节点自报不可用）。
func (h *capReportHandle) janitor(tick time.Duration) {
	defer close(h.janDone)
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			h.writeOnce()
		case <-h.stopJan:
			return
		}
	}
}

// resetCapabilityReportForTest 重置自报单例（仅测试使用：停止 janitor、重建 Once）。
func resetCapabilityReportForTest() {
	if capHandle != nil {
		close(capHandle.stopJan)
		<-capHandle.janDone
		capHandle = nil
	}
	capOnce = sync.Once{}
}
