// Package l7rules 提供 L7 访问控制规则：存储、校验、评估（规则测试器）与 HTTP 处理。
// 表结构见 server/migrations/000032_l7_access_rules.up.sql；
// 下发网关的 JSON 契约（guardconfig l7_rules 段）见契约一，由 guardconfig 组装。
//
// 评估语义（与网关 jiuzhang_guard l7rules 引擎一致）：
// 请求阶段与响应阶段分别按 (priority 升序, created_at 升序) 稳定排序，首个 enabled 且条件全中
// （多条件 AND）的规则生效（首中即停）；含响应头/响应体条件的规则在响应回程评估。
package l7rules

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// 条件类型（契约一）
const (
	CondTypeURI            = "uri"             // 访问 URI（路径部分，不含 query）
	CondTypeMethod         = "method"          // 请求方法（values 数组，等价 op=in）
	CondTypeHeader         = "header"          // 请求头（name + op + value；名称大小写不敏感）
	CondTypeCookie         = "cookie"          // Cookie（name + op + value）
	CondTypeQuery          = "query"           // Query 参数（name + op + value）
	CondTypeClientIP       = "client_ip"       // 来源 IP（values 数组：单 IP 或 CIDR，等价 op=in）
	CondTypeRequestBody    = "request_body"    // 请求体（op + value；网关有界读取并还原）
	CondTypeResponseHeader = "response_header" // 响应头（name + op + value；名称大小写不敏感）
	CondTypeResponseBody   = "response_body"   // 响应体（op + value；完整且不超过 1 MiB 时检查）
)

// 运算符（契约一）。exists/not_exists 不需要 value；
// in 仅由 method/client_ip 以 values 数组表达（命名条件不支持 op=in，可用 regex 替代）。
const (
	OpEq        = "eq"
	OpNe        = "ne"
	OpPrefix    = "prefix"
	OpContains  = "contains"
	OpRegex     = "regex"
	OpExists    = "exists"
	OpNotExists = "not_exists"
	OpIn        = "in"
)

// 动作（契约一）
const (
	ActionBlock      = "block"       // 阻止（可配状态码+文案，默认 403）
	ActionAllow      = "allow"       // 放行并跳过 CC 等后续 guard 检查（仍过 Coraza——安全底线）
	ActionRedirect   = "redirect"    // 重定向（301/302，URL 强制 http(s) 校验）
	ActionCustomPage = "custom_page" // 返回自定义页面（状态码+内容，≤64KB）
)

// 命中事件类型（写 access_control_events；常量定义在 accesscontrolevents 包，此处不重复）。

// 上限（服务侧校验）
const (
	MaxRules          = 500       // 规则总数上限
	MaxConditions     = 10        // 单规则条件数上限
	MaxValues         = 64        // method/client_ip values 数组长度上限
	MaxNameRunes      = 200       // 规则名长度（字符）
	MaxCondNameLen    = 128       // 条件名称长度（字节）
	MaxCondValueLen   = 512       // 条件值长度（字节）
	MaxRegexLen       = 512       // 正则长度（字节）
	MaxMessageRunes   = 1024      // 阻止文案长度（字符）
	MaxRedirectURLLen = 2048      // 重定向 URL 长度（字节）
	MaxContentTypeLen = 128       // Content-Type 长度（字节）
	MaxBodyBytes      = 64 * 1024 // 自定义页面内容上限（64KB，字节）
)

// 错误
var (
	ErrNotFound     = errors.New("l7 access rule not found")
	ErrInvalidInput = errors.New("invalid l7 access rule input")
	ErrTooManyRules = errors.New("too many l7 access rules")
)

// Condition 是一条匹配条件。method/client_ip 用 Values（数组，等价 op=in）；
// header/cookie/query/response_header 用 Name+Op+Value；uri/request_body/response_body 无 Name。
type Condition struct {
	Type   string   `json:"type"`
	Name   string   `json:"name,omitempty"`
	Op     string   `json:"op,omitempty"`
	Value  string   `json:"value,omitempty"`
	Values []string `json:"values,omitempty"`
}

// ActionConfig 是动作配置。六键全量存储/下发（与契约一一致），按动作取对应字段：
// block→status+message；allow→无；redirect→redirect_url+redirect_status；
// custom_page→status+content_type+body。
type ActionConfig struct {
	Status         int    `json:"status"`
	Message        string `json:"message"`
	RedirectURL    string `json:"redirect_url"`
	RedirectStatus int    `json:"redirect_status"`
	ContentType    string `json:"content_type"`
	Body           string `json:"body"`
}

// Rule 是一条 L7 访问控制规则。
type Rule struct {
	ID           uuid.UUID    `json:"id"`
	Name         string       `json:"name"`
	Priority     int          `json:"priority"` // 数值小者优先
	Enabled      bool         `json:"enabled"`
	Conditions   []Condition  `json:"conditions"`
	Action       string       `json:"action"`
	ActionConfig ActionConfig `json:"action_config"`
	HitCount24h  int64        `json:"hit_count_24h"` // 近 24h 命中数（事件聚合填充，非表字段）
	CreatedBy    *uuid.UUID   `json:"created_by"`
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedBy    *uuid.UUID   `json:"updated_by"`
	UpdatedAt    time.Time    `json:"updated_at"`
}

// RuleInput 是新建/编辑规则的输入（校验后入库；校验会原地规范化并填默认值）。
type RuleInput struct {
	Name         string
	Priority     int
	Enabled      bool
	Conditions   []Condition
	Action       string
	ActionConfig ActionConfig
}

// ListFilter 是规则列表筛选。
type ListFilter struct {
	Keyword  string // 匹配名称（模糊）
	Enabled  *bool  // nil 表示不过滤
	Page     int
	PageSize int
}
