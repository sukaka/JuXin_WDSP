// grpc.go gRPC 流量识别（W14-GW / P2-05 首批，任务书 P2-05 gRPC 深度解析 v1 子集）。
//
// 双重确认（保守精确，与 LLM 识别同一纪律）：
//   - Content-Type 主类型 application/grpc 或 application/grpc+<suffix>（+proto/+json；
//     Caddy 已终结 HTTP/2 传输，grpc-web 的 HTTP/1.1 兼容封装 v1 不覆盖）；
//   - :path 为 /package.Service/Method 形态（Caddy 透传的 r.URL.Path：恰好两段、
//     段字符集限定标识符形 [A-Za-z0-9._-]，防空段/路径穿越/乱码误标）。
//
// 识别只做打标（protocol=GRPC 进事件与端点发现），不参与 API 分类打分：
// gRPC 二进制体在 JSON 信号驱动的 API 分类下天然低分，识别与帧校验不挂 api.IsAPI
// 分类门槛（分类漏判不应关掉帧校验，与扫描/LLM 识别同一纪律）。
package classifier

import (
	"mime"
	"strings"

	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// GRPCResult gRPC 流量识别结果。
type GRPCResult struct {
	IsGRPC  bool
	Service string // 服务段（package.Service 全保留，不归一化）
	Method  string // 方法段（全保留，不归一化）
}

// ClassifyGRPC 识别 gRPC 流量（Content-Type + 路径形态双重确认）。
func ClassifyGRPC(p *parser.Parsed) GRPCResult {
	if p == nil {
		return GRPCResult{}
	}
	mt, _, err := mime.ParseMediaType(p.ContentType)
	if err != nil {
		// 头部畸形降级为 ';' 前缀小写（与 parser.splitMediaType 同一纪律）
		mt = strings.ToLower(strings.TrimSpace(strings.SplitN(p.ContentType, ";", 2)[0]))
	}
	if !parser.IsGRPCMediaType(strings.ToLower(mt)) {
		return GRPCResult{}
	}
	svc, method, ok := splitGRPCPath(p.RawPath)
	if !ok {
		return GRPCResult{}
	}
	return GRPCResult{IsGRPC: true, Service: svc, Method: method}
}

// splitGRPCPath 校验并拆分 /package.Service/Method 形态路径（恰好两段）；
// 段字符集限定标识符形，段全保留（服务/方法名不归一化）。
func splitGRPCPath(rawPath string) (string, string, bool) {
	if !strings.HasPrefix(rawPath, "/") {
		return "", "", false
	}
	rest := strings.TrimPrefix(rawPath, "/")
	svc, method, found := strings.Cut(rest, "/")
	if !found || svc == "" || method == "" || strings.Contains(method, "/") {
		return "", "", false
	}
	if !isGRPCSegment(svc) || !isGRPCSegment(method) {
		return "", "", false
	}
	return svc, method, true
}

// isGRPCSegment 段字符集判定：标识符形（字母/数字/._-），防乱码与路径穿越误标。
func isGRPCSegment(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '.' || c == '_' || c == '-' {
			continue
		}
		return false
	}
	return true
}
