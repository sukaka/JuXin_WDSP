// 身份与行为防护（WDSP AI 自动化渗透防护增强 阶段1）的 Guard 装配桥接。
//
// 纪律：
//   - 配置缺省 = 零行为变化：identity_behavior 段不下发或 enabled=false 时不装配引擎，
//     请求链路无 wrapper、无事件文件、无计数；
//   - 装配失败 fail-open：配置编译/事件日志打开失败记 zap Error 并关闭本功能（g.ibh 置 nil），
//     不影响 guard 其他功能加载；
//   - 运行期失败 fail-open：存储 Valkey 故障回退内存（identitybehavior 实现内节流 Warn），
//     End panic recover + zap Error，事件写失败仅告警——请求永不因本功能失败而失败；
//   - 本阶段全部信号仅 OBSERVE，不拦截任何请求。
package jiuzhang_guard

import (
	"path/filepath"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/identitybehavior"
	"go.uber.org/zap"
)

// identityBehaviorJSON 发布通道下发原文（identity_behavior 段；json tag 为跨分片契约，
// 不得改动）。定义为 identitybehavior.Params 的别名，发布契约与引擎编译入参同源。
type identityBehaviorJSON = identitybehavior.Params

// provisionIdentityBehavior 装配身份与行为防护：编译配置 → 选定 Store（behavior_store=valkey
// 且共享引擎 Valkey 连接可用 → Valkey 实现，否则进程内存实现）→ 打开身份事件日志 → 建引擎。
// 需在共享引擎就绪后调用；任何一步失败 fail-open（记 Error + g.ibh 保持 nil）。
func (g *Guard) provisionIdentityBehavior(eng *sharedEngine) {
	p := g.IdentityBehavior
	if p == nil || !p.Enabled {
		return
	}
	cfg, err := identitybehavior.Compile(p, g.logger)
	if err != nil {
		g.logger.Error("identity_behavior: 配置编译失败，功能关闭（fail-open）", zap.Error(err))
		return
	}
	if cfg == nil {
		return
	}
	// 内存实现为 Valkey 故障的运行期回退与缺省路径；identity 键上限复用 max_counter_keys
	// （identitybehavior 默认 5 万，与计数器同一容量纪律）
	mem := identitybehavior.NewMemoryStore(g.MaxCounterKeys, g.logger)
	var store identitybehavior.Store = mem
	valkeyStore := g.BehaviorStore == "valkey" && eng != nil && eng.valkey != nil
	if valkeyStore {
		store = identitybehavior.NewValkeyStore(eng.valkey, mem, g.logger)
	}
	logPath := g.IdentityEventsLog
	if logPath == "" {
		logPath = filepath.Join(filepath.Dir(g.EventsLog), "identity-events.log")
	}
	ev, err := identitybehavior.NewEventLogger(logPath, g.GatewayNode, g.logger)
	if err != nil {
		g.logger.Error("identity_behavior: 事件日志打开失败，功能关闭（fail-open）",
			zap.String("path", logPath), zap.Error(err))
		_ = store.Close()
		return
	}
	g.ibh = identitybehavior.NewEngine(cfg, store, ev, identitybehavior.Options{
		AppID:       g.AppID,
		AppCode:     g.AppCode,
		GatewayNode: g.GatewayNode,
		Salt:        g.IdentitySalt,
		Logger:      g.logger,
	})
	g.logger.Info("identity behavior protection enabled",
		zap.String("mode", cfg.Mode),
		zap.String("events_log", logPath),
		zap.String("policy_version", cfg.PolicyVersion),
		zap.Bool("valkey_store", valkeyStore),
		zap.Int("sensitive_paths", len(cfg.SensitivePaths)),
		zap.Int("whitelist_ips", len(p.WhitelistIPs)),
		zap.Int("whitelist_uas", len(p.WhitelistUAs)))
}
