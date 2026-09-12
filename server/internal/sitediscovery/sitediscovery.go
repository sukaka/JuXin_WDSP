// Package sitediscovery 站点资产被动发现（docs/NETWORK_MODES_DESIGN.md 配套能力）：
// 网关 mirrorcap 按窗口聚合嗅探到的站点流量写 site-discovery.jsonl，
// 采集器断点续传 upsert 进 site_asset_discoveries（幂等键 domain+ip+port），
// 管理面提供列表查询与确认/忽略/恢复处置。
//
// 数据契约（跨端字段名一致，网关侧由 mirrorcap 实现）：
//
//	{"type":"site_discovery","node":"gw-1","domain":"example.com","ip":"10.0.0.5",
//	 "port":443,"protocol":"HTTPS","source_mode":"MIRROR","hits":123,"client_count":17,
//	 "window_start":"...","window_end":"..."}
//
// type 恒为 "site_discovery"；domain 可空串（未识别域名）；protocol ∈ HTTP/HTTPS；
// source_mode ∈ MIRROR/ROUTED/TRANSPARENT。
package sitediscovery

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
)

// 处置状态词表（site_asset_discoveries.status，CHECK 约束见迁移 000077）。
const (
	StatusNew       = "NEW"
	StatusConfirmed = "CONFIRMED"
	StatusIgnored   = "IGNORED"
)

// 协议与来源模式词表（网关上报契约）。
const (
	ProtocolHTTP  = "HTTP"
	ProtocolHTTPS = "HTTPS"

	SourceModeMirror      = "MIRROR"
	SourceModeRouted      = "ROUTED"
	SourceModeTransparent = "TRANSPARENT"
)

// RecordType 网关 JSONL 行的 type 恒定值（非本类型行跳过，不写错误文件）。
const RecordType = "site_discovery"

var (
	// ErrNotFound 发现条目不存在。
	ErrNotFound = errors.New("site discovery not found")
	// ErrInvalidTransition 当前状态不允许该处置流转。
	ErrInvalidTransition = errors.New("invalid site discovery status transition")
	// ErrInvalidInput 发现输入非法（采集器据此前移断点并写错误文件，不重试）。
	ErrInvalidInput = errors.New("invalid site discovery input")
)

// Discovery 是一条站点发现结果（列名对齐迁移 000077）。
type Discovery struct {
	ID          uuid.UUID  `json:"id"`
	Domain      string     `json:"domain"`
	IP          string     `json:"ip"`
	Port        int        `json:"port"`
	Protocol    string     `json:"protocol"`
	SourceMode  string     `json:"source_mode"`
	GatewayNode string     `json:"gateway_node"`
	SeenCount   int64      `json:"seen_count"`
	ClientCount int64      `json:"client_count"`
	FirstSeen   time.Time  `json:"first_seen"`
	LastSeen    time.Time  `json:"last_seen"`
	Status      string     `json:"status"`
	ConfirmedBy string     `json:"confirmed_by"`
	ConfirmedAt *time.Time `json:"confirmed_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// DiscoveryInput 发现/命中输入（采集器从网关 JSONL 解析后传入）。
type DiscoveryInput struct {
	Node        string
	Domain      string
	IP          string
	Port        int
	Protocol    string
	SourceMode  string
	Hits        int64
	ClientCount int64
	WindowStart time.Time
	WindowEnd   time.Time
}

// ListFilter 列表过滤条件（status/protocol/source_mode/keyword + 分页）。
type ListFilter struct {
	Status     string
	Protocol   string
	SourceMode string
	Keyword    string // domain 或 ip 模糊匹配
	Page       int
	PageSize   int
}

// Repository 站点发现仓储（SQL 与内存实现共用，便于诚实单测）。
type Repository interface {
	Upsert(ctx context.Context, in DiscoveryInput) (*Discovery, error)
	List(ctx context.Context, f ListFilter) ([]Discovery, int64, error)
	GetByID(ctx context.Context, id uuid.UUID) (*Discovery, error)
	Confirm(ctx context.Context, id uuid.UUID, operator string) (*Discovery, error)
	Ignore(ctx context.Context, id uuid.UUID, operator string) (*Discovery, error)
	Restore(ctx context.Context, id uuid.UUID, operator string) (*Discovery, error)
}

// normalizeInput 归一化与校验发现输入（SQL/内存仓储共用同一语义）：
// domain trim+小写；ip 必须可解析；port ∈ [1,65535]；protocol ∈ HTTP/HTTPS（大写归一）；
// source_mode 词表内取值（空串容忍为未知）；window 缺零值回落 now（网关字段缺失时容错）。
// 非法输入返回包装 ErrInvalidInput 的错误。
func normalizeInput(in DiscoveryInput) (DiscoveryInput, error) {
	in.Domain = strings.ToLower(strings.TrimSpace(in.Domain))
	in.IP = strings.TrimSpace(in.IP)
	in.Node = strings.TrimSpace(in.Node)
	in.Protocol = strings.ToUpper(strings.TrimSpace(in.Protocol))
	in.SourceMode = strings.ToUpper(strings.TrimSpace(in.SourceMode))
	if _, err := netip.ParseAddr(in.IP); err != nil {
		return in, fmt.Errorf("%w: ip %q 非法", ErrInvalidInput, in.IP)
	}
	if in.Port < 1 || in.Port > 65535 {
		return in, fmt.Errorf("%w: port %d 越界", ErrInvalidInput, in.Port)
	}
	if in.Protocol != ProtocolHTTP && in.Protocol != ProtocolHTTPS {
		return in, fmt.Errorf("%w: protocol %q 非法（允许 HTTP/HTTPS）", ErrInvalidInput, in.Protocol)
	}
	switch in.SourceMode {
	case "", SourceModeMirror, SourceModeRouted, SourceModeTransparent:
	default:
		return in, fmt.Errorf("%w: source_mode %q 非法", ErrInvalidInput, in.SourceMode)
	}
	if in.Hits < 0 || in.ClientCount < 0 {
		return in, fmt.Errorf("%w: hits/client_count 不能为负", ErrInvalidInput)
	}
	now := time.Now().UTC()
	if in.WindowStart.IsZero() {
		in.WindowStart = now
	}
	if in.WindowEnd.IsZero() {
		in.WindowEnd = now
	}
	return in, nil
}

// validStatus 校验处置状态取值（List 过滤用；空串 = 不过滤）。
func validStatus(s string) bool {
	switch s {
	case StatusNew, StatusConfirmed, StatusIgnored:
		return true
	}
	return false
}
