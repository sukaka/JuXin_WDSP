// apigrpcguard.go gRPC G1 深检装配置装配（NG-GRPC 批次 B2，设计 §1.3/D3/D5）：
// api_grpc_bindings 发布段解析归一 + per-app 绑定注册表 + content_hash 覆盖读数。
//
// 装配纪律：
//   - 无描述符且无绑定 = nil（grpcguard 全链零行为，NG-T-C01）；
//   - 绑定行字段缺失/词表外 fail-safe：mode 缺省/词表外归一 OBSERVE + Warn（与
//     api_admission 同纪律不拒载——不误断优于误断）；application_id/service/
//     descriptor_name 空缺行跳过 + Warn；
//   - 绑定引用未知描述符集：行保留但无注册表（运行期 SKIPPED(no_descriptor)
//     不误断）——跳过行会把应用错误回退到「空绑定=全局」语义，方向相反；
//   - 服务名精确匹配（大小写敏感——proto 全限定名语义；server B1 词表偏差
//     登记备查，消费侧不做归一化放宽，词表放宽留集成批裁决）；
//   - 绑定集专用注册表逐集独立编译（grpcdesc 复用；编译失败 Warn + 无注册表，
//     运行期 no_descriptor——与全局注册表 Warn 跳过降级同一纪律）。
package jiuzhang_guard

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors/grpcguard"
	"github.com/jiuzhang-waf/gateway/dynamic_security/grpcdesc"
	"go.uber.org/zap"
)

// grpcBindingJSON gRPC 描述符 per-app 绑定（api_grpc_bindings 数组项；
// 与 server guardconfig.GuardGRPCBinding 跨轨线契约——json tag 不得改名）。
type grpcBindingJSON struct {
	ApplicationID  string `json:"application_id"`  // 应用 ID（UUID）
	Service        string `json:"service"`         // pkg.Service 全名（绑定粒度）
	DescriptorName string `json:"descriptor_name"` // 引用的描述符集名
	Mode           string `json:"mode"`            // OBSERVE（缺省）| PROTECT（字段结构违规协议化执行）
}

// buildGRPCGuardConfig grpcguard 装配置装配（Provision 调用；nil = 零行为 NG-T-C01）。
func (g *Guard) buildGRPCGuardConfig() *grpcguard.Config {
	if g.apiGRPCRegistry == nil && len(g.APIGRPCBindings) == 0 {
		return nil
	}
	cfg := &grpcguard.Config{
		GlobalRegistry:   g.apiGRPCRegistry,
		SetRegistries:    map[string]*grpcdesc.Registry{},
		SetHashes:        map[string]string{},
		Bindings:         map[string]map[string]grpcguard.Binding{},
		AllowCompression: g.APIGRPCAllowCompression,
	}
	// 描述符集名 → 原始字节索引（绑定集专用注册表编译与 content_hash 读数共用）
	setContents := map[string][]byte{}
	for _, d := range g.APIGRPCDescriptors {
		raw, err := base64.StdEncoding.DecodeString(d.ContentBase64)
		if err != nil || len(raw) == 0 {
			continue // 非法集由 buildAPIGRPCRegistry 路径已 Warn；此处静默跳过不重复告警
		}
		setContents[d.Name] = raw
		sum := sha256.Sum256(raw)
		cfg.SetHashes[d.Name] = hex.EncodeToString(sum[:])[:8] // content_hash 前 8（覆盖读数）
	}
	for i, b := range g.APIGRPCBindings {
		appID := strings.TrimSpace(b.ApplicationID)
		service := strings.TrimSpace(b.Service)
		setName := strings.TrimSpace(b.DescriptorName)
		if appID == "" || service == "" || setName == "" {
			g.logger.Warn("api_grpc_bindings 行字段空缺跳过", zap.Int("index", i))
			continue
		}
		mode := strings.ToUpper(strings.TrimSpace(b.Mode))
		if mode == "" {
			mode = grpcguard.ModeObserve
		}
		if mode != grpcguard.ModeObserve && mode != grpcguard.ModeProtect {
			g.logger.Warn("api_grpc_bindings mode 词表外归一 OBSERVE（fail-safe）",
				zap.Int("index", i), zap.String("mode", b.Mode))
			mode = grpcguard.ModeObserve
		}
		// 绑定集专用注册表（逐名一次编译；未知集名行保留但无注册表——运行期
		// no_descriptor 不误断，不回落全局语义）
		if _, built := cfg.SetRegistries[setName]; !built {
			if raw, ok := setContents[setName]; ok {
				reg := grpcdesc.NewRegistry()
				if err := reg.AddSet(setName, base64.StdEncoding.EncodeToString(raw)); err != nil {
					g.logger.Warn("api_grpc_bindings 引用集编译失败（运行期 no_descriptor 不误断）",
						zap.String("descriptor_name", setName), zap.Error(err))
				} else {
					cfg.SetRegistries[setName] = reg
				}
			} else {
				g.logger.Warn("api_grpc_bindings 引用未知描述符集（运行期 no_descriptor 不误断）",
					zap.String("descriptor_name", setName))
			}
		}
		if cfg.Bindings[appID] == nil {
			cfg.Bindings[appID] = map[string]grpcguard.Binding{}
		}
		cfg.Bindings[appID][service] = grpcguard.Binding{DescriptorName: setName, Mode: mode}
	}
	return cfg
}

// grpcCompressionAllowLegacy 现状 grpc 检测器压缩许可（三态归一为二态：
// nil 未下发 = false 维持现状二态——与 *bool 变更前行为完全一致）。
func (g *Guard) grpcCompressionAllowLegacy() bool {
	return g.APIGRPCAllowCompression != nil && *g.APIGRPCAllowCompression
}

// boolPtr 布尔指针辅助（配置段三态构造）。
func boolPtr(b bool) *bool { return &b }
