// overrides.go Phase 4 定向采集规则（capture overrides）类型与校验
// （契约 docs/agents/WDSP_AGENT_PHASE4_CONTRACT.md §2）：
//   - match 匹配条件（§2.2）：dst_ip（单个 IP 或 CIDR，v4/v6）/ dst_port（1-65535）/
//     host（精确匹配大小写不敏感，≤255）/ uri_prefix（以 / 开头，≤512 字节），
//     全部可选、多字段 AND、四字段全空非法（管理端 400）；未知字段 fail-closed；
//   - 规则只升不降：Agent 侧生效等级 = max(基础等级, 命中规则等级)（§2.4，Agent 实现，
//     服务端只负责校验与下发）；
//   - ttl_minutes 1-1440 默认 30（§2.3）。
package agents

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
)

// 定向采集规则校验边界（契约 §2.2/§2.3 冻结值）。
const (
	// OverrideTTLDefaultMinutes ttl_minutes 缺省值（契约 §2.3：默认 30）。
	OverrideTTLDefaultMinutes = 30
	// OverrideTTLMinMinutes / OverrideTTLMaxMinutes ttl_minutes 合法区间 1-1440。
	OverrideTTLMinMinutes = 1
	OverrideTTLMaxMinutes = 1440
	// overrideHostMaxLen host 上限 255 字符。
	overrideHostMaxLen = 255
	// overrideURIPrefixMaxLen uri_prefix 上限 512 字节。
	overrideURIPrefixMaxLen = 512
	// overrideNoteMaxLen 备注上限（管理端输入卫生；契约未冻结，取 512）。
	overrideNoteMaxLen = 512
)

// ErrCaptureOverrideNotFound 定向采集规则不存在（或不属于该 Agent——删除 404，防越权探测）。
var ErrCaptureOverrideNotFound = errors.New("agent capture override not found")

// CaptureOverrideMatch 匹配条件（§2.2；指针/空串表示缺省，序列化回库时省略缺省键）。
type CaptureOverrideMatch struct {
	DstIP     string `json:"dst_ip,omitempty"`
	DstPort   *int   `json:"dst_port,omitempty"`
	Host      string `json:"host,omitempty"`
	URIPrefix string `json:"uri_prefix,omitempty"`
}

// validate 匹配条件校验（fail-closed）：
// 至少一个字段非空；dst_ip 为合法 IP 或 CIDR；dst_port ∈ [1,65535]；
// host 非空 ≤255；uri_prefix 以 / 开头且 ≤512 字节。
func (m *CaptureOverrideMatch) validate() error {
	m.DstIP = strings.TrimSpace(m.DstIP)
	m.Host = strings.TrimSpace(m.Host)
	m.URIPrefix = strings.TrimSpace(m.URIPrefix)
	if m.DstIP == "" && m.DstPort == nil && m.Host == "" && m.URIPrefix == "" {
		return errors.New("match 至少需要一个匹配字段（dst_ip/dst_port/host/uri_prefix）")
	}
	if m.DstIP != "" {
		if _, err := netip.ParseAddr(m.DstIP); err != nil {
			if _, perr := netip.ParsePrefix(m.DstIP); perr != nil {
				return errors.New("match.dst_ip 须为合法 IP 或 CIDR（v4/v6）")
			}
		}
	}
	if m.DstPort != nil && (*m.DstPort < 1 || *m.DstPort > 65535) {
		return errors.New("match.dst_port 须在 1~65535")
	}
	if len(m.Host) > overrideHostMaxLen {
		return fmt.Errorf("match.host 超过 %d 字符", overrideHostMaxLen)
	}
	if m.URIPrefix != "" {
		if !strings.HasPrefix(m.URIPrefix, "/") {
			return errors.New("match.uri_prefix 须以 / 开头")
		}
		if len(m.URIPrefix) > overrideURIPrefixMaxLen {
			return fmt.Errorf("match.uri_prefix 超过 %d 字节", overrideURIPrefixMaxLen)
		}
	}
	return nil
}

// CaptureOverride 定向采集规则行（契约 §2.1；match 以 JSONB 原样存取）。
type CaptureOverride struct {
	ID           uuid.UUID       `json:"id"`
	AgentID      uuid.UUID       `json:"agent_id"`
	Match        json.RawMessage `json:"match"`
	CaptureLevel string          `json:"capture_level"`
	Note         string          `json:"note"`
	CreatedBy    string          `json:"created_by"`
	CreatedAt    time.Time       `json:"created_at"`
	ExpiresAt    time.Time       `json:"expires_at"`
}

// CaptureOverrideItem 管理端列表项（含派生 active——未过期；契约 §2.3）。
type CaptureOverrideItem struct {
	CaptureOverride
	Active bool `json:"active"`
}

// captureOverrideConfig 机器端 config 下发项（§2.4：{id, match, capture_level, expires_at}）。
type captureOverrideConfig struct {
	ID           uuid.UUID       `json:"id"`
	Match        json.RawMessage `json:"match"`
	CaptureLevel string          `json:"capture_level"`
	ExpiresAt    time.Time       `json:"expires_at"`
}

// CaptureOverrideInput 创建输入（仓储层；match 为校验后归一 JSON）。
type CaptureOverrideInput struct {
	AgentID      uuid.UUID
	Match        json.RawMessage
	CaptureLevel string
	Note         string
	CreatedBy    string
	ExpiresAt    time.Time
	Now          time.Time
}
