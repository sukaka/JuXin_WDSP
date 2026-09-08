// gateway.go 模型网关：按任务路由模型、主备故障切换、健康检查与密钥解密。
package aimodel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// TaskComplexity 任务复杂度（模型路由依据）。
type TaskComplexity string

const (
	ComplexitySimple   TaskComplexity = "simple"   // 分类/简单问答 → 低成本模型
	ComplexityStandard TaskComplexity = "standard" // 单事件分析 → 标准模型
	ComplexityHigh     TaskComplexity = "high"     // 攻击链/复杂根因 → 高能力模型
)

// KeyResolver 密钥解析接口（由 encryption 服务实现）。
type KeyResolver interface {
	DecryptSecret(ctx context.Context, reference string) (string, error)
}

// Gateway 模型网关。
type Gateway struct {
	mu       sync.RWMutex
	client   *OpenAIClient
	resolver KeyResolver
	// 模型路由表：复杂度 → 按优先级排序的模型（与供应商连接信息）
	routes map[TaskComplexity][]routedModel
	// 熔断状态：模型 → 连续失败次数与熔断截止时间
	circuit map[uuid.UUID]*circuitState
}

type routedModel struct {
	model    *Model
	provider *Provider
}

type circuitState struct {
	failures  int
	openUntil time.Time
}

// 熔断参数。
const (
	circuitThreshold = 3
	circuitCooldown  = 60 * time.Second
)

// NewGateway 创建模型网关。
func NewGateway(resolver KeyResolver) *Gateway {
	return &Gateway{
		client:   NewOpenAIClient(),
		resolver: resolver,
		routes:   map[TaskComplexity][]routedModel{},
		circuit:  map[uuid.UUID]*circuitState{},
	}
}

// SetRoutes 设置路由表（启动时从数据库加载）。
func (g *Gateway) SetRoutes(routes map[TaskComplexity][]struct {
	Model    *Model
	Provider *Provider
},
) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.routes = map[TaskComplexity][]routedModel{}
	for c, list := range routes {
		for _, item := range list {
			g.routes[c] = append(g.routes[c], routedModel{model: item.Model, provider: item.Provider})
		}
		sort.Slice(g.routes[c], func(i, j int) bool {
			return g.routes[c][i].model.Priority < g.routes[c][j].model.Priority
		})
	}
}

// circuitOpen 熔断是否开启。
func (g *Gateway) circuitOpen(modelID uuid.UUID) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	cs := g.circuit[modelID]
	return cs != nil && time.Now().Before(cs.openUntil)
}

// recordResult 记录模型调用结果（熔断计数）。
func (g *Gateway) recordResult(modelID uuid.UUID, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	cs := g.circuit[modelID]
	if cs == nil {
		cs = &circuitState{}
		g.circuit[modelID] = cs
	}
	if err == nil {
		cs.failures = 0
		cs.openUntil = time.Time{}
		return
	}
	cs.failures++
	if cs.failures >= circuitThreshold {
		cs.openUntil = time.Now().Add(circuitCooldown)
		cs.failures = 0
	}
}

// apiKey 解析密钥（密钥本体绝不记录日志）。
// KeyReference 已配置但解密失败时返回错误并记 Warn：配置故障必须暴露，
// 不得按空密钥继续呼叫（随后 401 静默切备用模型会掩盖配置故障，见审查 LOW-S11）。
func (g *Gateway) apiKey(ctx context.Context, p *Provider) (string, error) {
	if p.KeyReference == "" {
		return "", nil
	}
	if g.resolver == nil {
		return "", fmt.Errorf("ai provider %q 已配置密钥引用但加密服务未装配", p.Name)
	}
	key, err := g.resolver.DecryptSecret(ctx, p.KeyReference)
	if err != nil {
		slog.Warn("ai provider key decrypt failed", "provider", p.Name, "reference", p.KeyReference, "error", err)
		return "", fmt.Errorf("ai provider %q 密钥解密失败: %w", p.Name, err)
	}
	return key, nil
}

// Chat 路由式对话（按复杂度选模型，主备切换）。
func (g *Gateway) Chat(ctx context.Context, complexity TaskComplexity, req ChatRequest) (*ChatResult, error) {
	return g.chatWith(ctx, complexity, req, nil)
}

// ChatStream 路由式流式对话。
func (g *Gateway) ChatStream(ctx context.Context, complexity TaskComplexity, req ChatRequest, cb StreamCallback) (*ChatResult, error) {
	return g.chatWith(ctx, complexity, req, cb)
}

// chatWith 统一调用：遍历路由候选（跳过熔断），失败切换下一个。
func (g *Gateway) chatWith(ctx context.Context, complexity TaskComplexity, req ChatRequest, cb StreamCallback) (*ChatResult, error) {
	g.mu.RLock()
	candidates := append([]routedModel{}, g.routes[complexity]...)
	g.mu.RUnlock()
	if len(candidates) == 0 {
		// 复杂度无路由时回退标准模型
		g.mu.RLock()
		candidates = append([]routedModel{}, g.routes[ComplexityStandard]...)
		g.mu.RUnlock()
	}
	if len(candidates) == 0 {
		return nil, ErrNoModel
	}
	var lastErr error
	for _, c := range candidates {
		if g.circuitOpen(c.model.ID) {
			continue
		}
		timeout := time.Duration(c.model.TimeoutSeconds) * time.Second
		if timeout <= 0 {
			timeout = 60 * time.Second
		}
		callCtx, cancel := context.WithTimeout(ctx, timeout)
		key, keyErr := g.apiKey(ctx, c.provider)
		if keyErr != nil {
			// 密钥配置故障：该候选直接判失败，不发起 HTTP 呼叫（空密钥 401 会掩盖故障）；
			// 不计熔断——非模型调用失败，避免配置错误把健康模型熔断
			cancel()
			lastErr = keyErr
			continue
		}
		var res *ChatResult
		var err error
		if cb != nil && c.model.SupportsStreaming {
			res, err = g.client.ChatStream(callCtx, c.provider.BaseURL, key, c.model.Code, req, cb)
		} else {
			res, err = g.client.Chat(callCtx, c.provider.BaseURL, key, c.model.Code, req)
		}
		cancel()
		g.recordResult(c.model.ID, err)
		if err == nil {
			return res, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrModelDown
}

// HealthCheckAll 全部模型健康检查。
func (g *Gateway) HealthCheckAll(ctx context.Context) map[uuid.UUID]error {
	g.mu.RLock()
	seen := map[uuid.UUID]routedModel{}
	for _, list := range g.routes {
		for _, c := range list {
			seen[c.model.ID] = c
		}
	}
	g.mu.RUnlock()
	out := map[uuid.UUID]error{}
	for id, c := range seen {
		key, err := g.apiKey(ctx, c.provider)
		if err != nil {
			out[id] = err // 密钥配置故障如实上报（健康检查面板暴露）
			continue
		}
		out[id] = g.client.HealthCheck(ctx, c.provider.BaseURL, key, c.model.Code)
	}
	return out
}

// HealthCheckModel 单模型健康检查（管理面"测试模型"用；密钥仅服务端内部解析，不外传）。
func (g *Gateway) HealthCheckModel(ctx context.Context, m *Model, p *Provider) error {
	key, err := g.apiKey(ctx, p)
	if err != nil {
		return err
	}
	return g.client.HealthCheck(ctx, p.BaseURL, key, m.Code)
}

// ModelCount 已注册模型数。
func (g *Gateway) ModelCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n := 0
	seen := map[uuid.UUID]bool{}
	for _, list := range g.routes {
		for _, c := range list {
			if !seen[c.model.ID] {
				seen[c.model.ID] = true
				n++
			}
		}
	}
	return n
}

var _ = errors.Is
