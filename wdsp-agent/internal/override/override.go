// Package override 定向采集规则集（Phase 4 契约 §2.2/§2.4）。
//
//   - 规则来自 config 响应 overrides 数组（缺省=空），经 config 热更整表替换，
//     不重启抓包；规则数钳 100（超出 Warn 截断）；
//   - 求值两点：dst_ip/dst_port 在 flow 首包（EvalFlow）；host/uri_prefix 在
//     请求行嗅探成功时（EvalRequest）。多字段 AND、多规则命中取最高等级；
//   - 过期（now > expires_at）规则即时忽略并惰性清理（Prune 由上层周期驱动）；
//   - 红线：任何规则解析失败跳过该规则不阻断采集；热路径 O(规则数) 小常数。
package override

import (
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
)

// MaxRules 规则数硬上限（契约红线：超出 Warn 截断）。
const MaxRules = 100

// maxURIPrefixBytes uri_prefix 长度上限（契约 §2.2）。
const maxURIPrefixBytes = 512

// rule 编译后的单条规则。
type rule struct {
	ip      netip.Prefix // hasIP 时有效（单 IP 归一化为 /32、/128）
	hasIP   bool
	port    uint16
	hasPort bool
	host    string // 已转小写（大小写不敏感精确匹配）
	uri     string
	level   int // 0-3（config.LevelRank）
	expires time.Time
}

// matchFlow 五元组阶段匹配：仅评估 dst_ip/dst_port 字段；含 host/uri 的
// 规则在本阶段无法确认（AND 语义），留待请求行阶段。
func (r *rule) matchFlow(addr netip.Addr, dstPort uint16) bool {
	if r.host != "" || r.uri != "" {
		return false
	}
	return r.matchTuple(addr, dstPort)
}

// matchRequest 请求行阶段匹配：全部已设字段 AND。
func (r *rule) matchRequest(addr netip.Addr, dstPort uint16, host, uri string) bool {
	if !r.matchTuple(addr, dstPort) {
		return false
	}
	if r.host != "" && r.host != strings.ToLower(host) {
		return false
	}
	if r.uri != "" && !strings.HasPrefix(uri, r.uri) {
		return false
	}
	return true
}

func (r *rule) matchTuple(addr netip.Addr, dstPort uint16) bool {
	if r.hasIP && !r.ip.Contains(addr) {
		return false
	}
	if r.hasPort && r.port != dstPort {
		return false
	}
	return true
}

// Set 规则集（并发安全：热路径读锁 + 小切片，热更写锁整表替换）。
type Set struct {
	log *slog.Logger

	mu    sync.RWMutex
	rules []rule
	dirty atomic.Bool // 求值时遇到过期规则，提示 Prune 惰性清理
}

// NewSet 创建空规则集。
func NewSet(log *slog.Logger) *Set {
	if log == nil {
		log = slog.Default()
	}
	return &Set{log: log}
}

// Replace 整表替换（config 热更）。解析失败的规则跳过（Warn），四字段全空/
// 等级非法/时间非法同样跳过，绝不阻断采集；输入超 MaxRules 截断。
func (s *Set) Replace(ovs []config.Override) {
	if len(ovs) > MaxRules {
		s.log.Warn("定向采集规则超上限，截断", "count", len(ovs), "max", MaxRules)
		ovs = ovs[:MaxRules]
	}
	rules := make([]rule, 0, len(ovs))
	for i := range ovs {
		r, err := compile(&ovs[i])
		if err != nil {
			s.log.Warn("定向采集规则非法，跳过", "id", ovs[i].ID, "err", err)
			continue
		}
		rules = append(rules, r)
	}
	s.mu.Lock()
	s.rules = rules
	s.mu.Unlock()
	s.dirty.Store(false)
}

// compile 解析单条规则；任何字段非法返回错误（调用方跳过该规则）。
func compile(o *config.Override) (rule, error) {
	var r rule
	switch o.CaptureLevel {
	case config.LevelL0, config.LevelL1, config.LevelL2, config.LevelL3:
		r.level = config.LevelRank(o.CaptureLevel)
	default:
		return r, errInvalid("capture_level 非法: %q", o.CaptureLevel)
	}
	exp, err := time.Parse(time.RFC3339, o.ExpiresAt)
	if err != nil {
		return r, errInvalid("expires_at 非法: %q", o.ExpiresAt)
	}
	r.expires = exp

	m := o.Match
	if m.DstIP != "" {
		if p, err := netip.ParsePrefix(m.DstIP); err == nil {
			r.ip, r.hasIP = p.Masked(), true
		} else if a, err := netip.ParseAddr(m.DstIP); err == nil {
			r.ip, r.hasIP = netip.PrefixFrom(a, a.BitLen()), true
		} else {
			return r, errInvalid("dst_ip 非法: %q", m.DstIP)
		}
	}
	if m.DstPort != 0 {
		if m.DstPort < 1 || m.DstPort > 65535 {
			return r, errInvalid("dst_port 非法: %d", m.DstPort)
		}
		r.port, r.hasPort = uint16(m.DstPort), true
	}
	r.host = strings.ToLower(strings.TrimSpace(m.Host))
	if m.URIPrefix != "" {
		if !strings.HasPrefix(m.URIPrefix, "/") || len(m.URIPrefix) > maxURIPrefixBytes {
			return r, errInvalid("uri_prefix 非法（须以 / 开头且 ≤512 字节）")
		}
		r.uri = m.URIPrefix
	}
	if !r.hasIP && !r.hasPort && r.host == "" && r.uri == "" {
		return r, errInvalid("匹配条件全空（至少一个字段）")
	}
	return r, nil
}

// EvalFlow 首包五元组求值：返回命中规则的最高等级（0-3；无命中=0）。
// dstIP 解析失败按无命中处理（不阻断采集）。
func (s *Set) EvalFlow(dstIP string, dstPort uint16, now time.Time) int {
	addr, err := netip.ParseAddr(dstIP)
	if err != nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	max := 0
	for i := range s.rules {
		r := &s.rules[i]
		if s.expiredLocked(r, now) {
			continue
		}
		if r.level > max && r.matchFlow(addr, dstPort) {
			max = r.level
		}
	}
	return max
}

// EvalRequest 请求行嗅探成功后的完整求值（含 host/uri_prefix）。
// host 大小写不敏感精确匹配；uri 前缀匹配。返回命中规则的最高等级。
func (s *Set) EvalRequest(dstIP string, dstPort uint16, host, uri string, now time.Time) int {
	addr, err := netip.ParseAddr(dstIP)
	if err != nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	max := 0
	for i := range s.rules {
		r := &s.rules[i]
		if s.expiredLocked(r, now) {
			continue
		}
		if r.level > max && r.matchRequest(addr, dstPort, host, uri) {
			max = r.level
		}
	}
	return max
}

// expiredLocked 过期判定（now > expires_at）；遇到过期规则置惰性清理标记。
func (s *Set) expiredLocked(r *rule, now time.Time) bool {
	if now.After(r.expires) {
		s.dirty.Store(true)
		return true
	}
	return false
}

// Prune 惰性清理过期规则（上层周期驱动；无过期标记时零开销直接返回）。
func (s *Set) Prune(now time.Time) {
	if !s.dirty.Load() {
		return
	}
	s.mu.Lock()
	kept := s.rules[:0]
	for i := range s.rules {
		if !now.After(s.rules[i].expires) {
			kept = append(kept, s.rules[i])
		}
	}
	// 清空尾部，避免已过期规则被底层数组引用滞留
	for i := len(kept); i < len(s.rules); i++ {
		s.rules[i] = rule{}
	}
	s.rules = kept
	s.mu.Unlock()
	s.dirty.Store(false)
}

// Len 当前规则数（含未清理的过期规则；测试与观测用）。
func (s *Set) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.rules)
}

func errInvalid(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}
