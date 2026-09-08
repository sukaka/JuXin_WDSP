// Package aitools AI Tool 注册中心：统一契约、权限校验、超时控制、审计与脱敏。
// 阶段7只允许 READ_ONLY 与 DRAFT_ONLY 两类 Tool。
package aitools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// 风险等级。
const (
	RiskReadOnly  = "READ_ONLY"
	RiskDraftOnly = "DRAFT_ONLY"
)

// 错误。
var (
	ErrToolNotFound   = errors.New("tool not found")
	ErrToolDisabled   = errors.New("tool disabled")
	ErrPermission     = errors.New("permission denied for tool")
	ErrInvalidInput   = errors.New("invalid tool input")
	ErrTimeout        = errors.New("tool timeout")
	ErrTooManyResults = errors.New("too many results")
)

// Principal 调用者身份（权限校验用）。
type Principal struct {
	UserID      uuid.UUID
	Username    string
	Permissions map[string]bool
}

// HasPermission 权限点检查。
func (p *Principal) HasPermission(perm string) bool {
	if p == nil || perm == "" {
		return false
	}
	return p.Permissions[perm]
}

// principalContextKey 将调用方 Principal 注入 Tool.Run 上下文（供草稿 created_by 等使用）。
type principalContextKey struct{}

// WithPrincipal 注入调用方身份。
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	if p == nil {
		return ctx
	}
	return context.WithValue(ctx, principalContextKey{}, p)
}

// PrincipalFromContext 读取调用方身份（无则 nil）。
func PrincipalFromContext(ctx context.Context) *Principal {
	p, _ := ctx.Value(principalContextKey{}).(*Principal)
	return p
}

// CreatorID 从上下文取 created_by，无则 uuid.Nil。
func CreatorID(ctx context.Context) uuid.UUID {
	if p := PrincipalFromContext(ctx); p != nil {
		return p.UserID
	}
	return uuid.Nil
}

// Tool Tool 统一契约。
type Tool interface {
	// Code Tool 编码（如 security_event.search）。
	Code() string
	// Name 名称。
	Name() string
	// Description 功能说明。
	Description() string
	// Version 版本。
	Version() string
	// RiskLevel READ_ONLY / DRAFT_ONLY。
	RiskLevel() string
	// RequiredPermission 所需权限点（空表示仅需登录）。
	RequiredPermission() string
	// TimeoutSeconds 超时秒数。
	TimeoutSeconds() int
	// MaxResults 最大返回数量。
	MaxResults() int
	// InputSchema 输入 JSON Schema。
	InputSchema() map[string]interface{}
	// Run 执行（入参 JSON，出参 JSON 可序列化结构）。
	Run(ctx context.Context, input json.RawMessage) (interface{}, error)
}

// toolMeta Tool 元数据（注册表持久化与展示用）。
type toolMeta struct {
	code        string
	name        string
	description string
	version     string
	risk        string
	permission  string
	timeout     int
	maxResults  int
	schema      map[string]interface{}
}

// baseTool 内嵌元数据的基座。
type baseTool struct{ meta toolMeta }

func (b *baseTool) Code() string                        { return b.meta.code }
func (b *baseTool) Name() string                        { return b.meta.name }
func (b *baseTool) Description() string                 { return b.meta.description }
func (b *baseTool) Version() string                     { return b.meta.version }
func (b *baseTool) RiskLevel() string                   { return b.meta.risk }
func (b *baseTool) RequiredPermission() string          { return b.meta.permission }
func (b *baseTool) TimeoutSeconds() int                 { return b.meta.timeout }
func (b *baseTool) MaxResults() int                     { return b.meta.maxResults }
func (b *baseTool) InputSchema() map[string]interface{} { return b.meta.schema }

// EnabledChecker Tool 启停检查（DB 管理面状态；返回 false 禁止执行）。
type EnabledChecker func(ctx context.Context, code string) bool

// Registry Tool 注册中心。
type Registry struct {
	tools map[string]Tool
	// enabledChecker 可选启停检查（启动时装配，之后只读，无需加锁）
	enabledChecker EnabledChecker
}

// NewRegistry 创建注册中心。
func NewRegistry() *Registry {
	return &Registry{tools: map[string]Tool{}}
}

// SetEnabledChecker 设置 Tool 启停检查（启动时调用一次；nil 表示全部启用）。
func (r *Registry) SetEnabledChecker(c EnabledChecker) {
	r.enabledChecker = c
}

// Register 注册 Tool。
func (r *Registry) Register(t Tool) {
	r.tools[t.Code()] = t
}

// Get 获取 Tool。
func (r *Registry) Get(code string) (Tool, bool) {
	t, ok := r.tools[code]
	return t, ok
}

// List 列出全部 Tool 元数据。
func (r *Registry) List() []map[string]interface{} {
	out := []map[string]interface{}{}
	for _, t := range r.tools {
		out = append(out, map[string]interface{}{
			"code": t.Code(), "name": t.Name(), "description": t.Description(),
			"version": t.Version(), "risk_level": t.RiskLevel(),
			"required_permission": t.RequiredPermission(),
			"timeout_seconds":     t.TimeoutSeconds(), "max_results": t.MaxResults(),
			"input_schema": t.InputSchema(),
		})
	}
	return out
}

// AuditRecord Tool 调用审计记录。
type AuditRecord struct {
	TaskID       uuid.UUID
	AgentRunID   *uuid.UUID
	ToolCode     string
	ToolVersion  string
	RiskLevel    string
	InputSummary string
	Status       string // SUCCESS / FAILED / TIMEOUT / DENIED
	DurationMs   int
	ErrorCode    string
}

// Auditor 审计接口（由 aiaudit 实现）。
type Auditor interface {
	RecordToolCall(ctx context.Context, rec AuditRecord) (reference string, err error)
}

// Execute 统一执行：权限校验 → 超时控制 → 审计。
func (r *Registry) Execute(ctx context.Context, p *Principal, taskID uuid.UUID, agentRunID *uuid.UUID, code string, input json.RawMessage, auditor Auditor) (interface{}, string, error) {
	t, ok := r.tools[code]
	if !ok {
		return nil, "", ErrToolNotFound
	}
	// 管理面启停校验（DB 中禁用则拒绝执行）
	if r.enabledChecker != nil && !r.enabledChecker(ctx, code) {
		return nil, "", ErrToolDisabled
	}
	start := time.Now()
	rec := AuditRecord{
		TaskID: taskID, AgentRunID: agentRunID, ToolCode: code, ToolVersion: t.Version(), RiskLevel: t.RiskLevel(),
		InputSummary: summarizeInput(input),
	}
	finish := func(status, errCode string) (string, error) {
		rec.Status = status
		rec.ErrorCode = errCode
		rec.DurationMs = int(time.Since(start).Milliseconds())
		ref := ""
		if auditor != nil {
			ref, _ = auditor.RecordToolCall(ctx, rec)
		}
		return ref, nil
	}
	// 权限校验（每次执行前重新检查当前用户真实权限）
	if req := t.RequiredPermission(); req != "" && !p.HasPermission(req) {
		_, _ = finish("DENIED", "PERMISSION_DENIED")
		return nil, "", fmt.Errorf("%w: %s requires %s", ErrPermission, code, req)
	}
	timeout := time.Duration(t.TimeoutSeconds()) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	callCtx, cancel := context.WithTimeout(WithPrincipal(ctx, p), timeout)
	defer cancel()
	result, err := t.Run(callCtx, input)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			_, _ = finish("TIMEOUT", "TIMEOUT")
			return nil, "", ErrTimeout
		}
		_, _ = finish("FAILED", "RUN_ERROR")
		return nil, "", err
	}
	ref, _ := finish("SUCCESS", "")
	_ = ref
	return result, ref, nil
}

// summarizeInput 入参摘要（截断脱敏）。
func summarizeInput(input json.RawMessage) string {
	s := string(input)
	if len(s) > 400 {
		s = s[:400] + "..."
	}
	return s
}

// Decode 解码入参。
func Decode[T any](input json.RawMessage, out *T) error {
	if len(input) == 0 {
		return nil
	}
	if err := json.Unmarshal(input, out); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	return nil
}

// StrField 取字符串字段并限制长度。
func StrField(m map[string]interface{}, key string, maxLen int) string {
	v, _ := m[key].(string)
	if maxLen > 0 && len(v) > maxLen {
		v = v[:maxLen]
	}
	return v
}

// IntField 取整数字段。
func IntField(m map[string]interface{}, key string, def int) int {
	if f, ok := m[key].(float64); ok {
		return int(f)
	}
	return def
}

// BoolField 取布尔字段。
func BoolField(m map[string]interface{}, key string) bool {
	b, _ := m[key].(bool)
	return b
}

var _ = fmt.Sprint
