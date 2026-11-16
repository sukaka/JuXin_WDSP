package jiuzhang_guard

import (
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/identitybehavior"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/riskengine"
	"go.uber.org/zap"
)

type riskPolicyOverrideJSON struct {
	ApplicationID            string         `json:"application_id"`
	Policy                   riskPolicyJSON `json:"policy"`
	SharedDeviceAccountLimit int            `json:"shared_device_account_limit,omitempty"`
}

func (g *Guard) sharedDeviceAccountLimit() int {
	if limit, ok := g.sharedDeviceAccountLimits[g.AppID]; ok {
		return limit
	}
	return detectors.DefaultSharedDeviceAccountLimit
}

func (g *Guard) buildRiskEngine(policy *riskPolicyJSON, eng *sharedEngine) *riskengine.Engine {
	cfg, err := riskengine.Compile(policy, g.logger)
	if err != nil {
		g.logger.Error("risk_policy: 配置编译失败，功能关闭（fail-open）", zap.Error(err))
		return nil
	}
	if cfg == nil {
		return nil
	}
	mem := riskengine.NewMemoryStore(cfg.Window(), g.MaxCounterKeys, g.logger)
	var store riskengine.Store = mem
	valkeyStore := g.BehaviorStore == "valkey" && eng != nil && eng.valkey != nil
	if valkeyStore {
		store = riskengine.NewValkeyStore(eng.valkey, cfg.Window(), mem, g.logger)
	}
	g.logger.Info("identity risk policy enabled",
		zap.String("mode", cfg.Mode),
		zap.Int("version", cfg.Version),
		zap.Int("block_threshold", cfg.BlockThreshold),
		zap.Int("rate_limit_threshold", cfg.RateLimitThreshold),
		zap.Int("rate_limit_rps", cfg.RateLimitRPS),
		zap.Int("signal_window_seconds", cfg.SignalWindowSeconds),
		zap.Int("score_overrides", len(cfg.Scores)),
		zap.Bool("valkey_store", valkeyStore))
	return riskengine.NewEngine(cfg, store, g.logger)
}

func (g *Guard) riskEngineForApp() *riskengine.Engine {
	if eng, ok := g.riskOverrides[g.AppID]; ok {
		return eng
	}
	return g.risk
}

func (g *Guard) riskIdentityKey(identityKey string) string {
	if _, ok := g.riskOverrides[g.AppID]; ok {
		return g.AppID + "\x00" + identityKey
	}
	return identityKey
}

func (g *Guard) addRiskIdentitySignals(identityKey string, signals []identitybehavior.Signal) {
	eng := g.riskEngineForApp()
	if eng == nil {
		return
	}
	eng.AddIdentitySignals(g.riskIdentityKey(identityKey), signals)
}
