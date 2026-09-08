// Package filter 采集端口/方向/协议过滤（契约 §3.3 policy.capture、§6 默认集）。
//
// 方向语义（与契约及任务约定一致）：
//   - 目的端口命中采集端口集合 → ingress（进入被保护服务的请求方向）
//   - 源端口命中采集端口集合   → egress（被保护服务发出的响应方向）
//   - direction=ingress 只放行 ingress；egress 只放行 egress；both 两者皆放行
package filter

import "sync/atomic"

// 方向枚举（契约 §3.3 direction）。
const (
	Ingress = "ingress"
	Egress  = "egress"
	Both    = "both"
)

// Filter 端口集合 + 方向过滤。内部用原子指针实现整表热替换（无锁读）。
type Filter struct {
	ports atomic.Pointer[map[uint16]struct{}]
	dir   atomic.Value // string
}

// New 创建过滤器；dir 非法值按 both 处理。
func New(ports []uint16, dir string) *Filter {
	f := &Filter{}
	f.SetPorts(ports)
	f.SetDirection(dir)
	return f
}

// SetPorts 热更新端口集合（整表原子替换，热路径无锁读）。
func (f *Filter) SetPorts(ports []uint16) {
	m := make(map[uint16]struct{}, len(ports))
	for _, p := range ports {
		m[p] = struct{}{}
	}
	f.ports.Store(&m)
}

// SetDirection 热更新方向。
func (f *Filter) SetDirection(dir string) {
	switch dir {
	case Ingress, Egress:
	default:
		dir = Both
	}
	f.dir.Store(dir)
}

// Direction 当前方向配置。
func (f *Filter) Direction() string {
	if v := f.dir.Load(); v != nil {
		return v.(string)
	}
	return Both
}

// Ports 当前端口集合快照。
func (f *Filter) Ports() []uint16 {
	m := f.ports.Load()
	out := make([]uint16, 0, len(*m))
	for p := range *m {
		out = append(out, p)
	}
	return out
}

// HasPort 端口是否在当前采集集合内（Phase 3 httpsensor server 端识别用；无锁读）。
func (f *Filter) HasPort(p uint16) bool {
	_, ok := (*f.ports.Load())[p]
	return ok
}

// Match 判定一个 TCP 包是否放行；ingress 标记其方向归属。
// dst 命中优先于 src 命中（同包两端都命中采集端口时按 ingress 计）。
func (f *Filter) Match(srcPort, dstPort uint16) (ok bool, ingress bool) {
	m := f.ports.Load()
	_, dstHit := (*m)[dstPort]
	_, srcHit := (*m)[srcPort]
	dir := f.Direction()
	if dstHit && dir != Egress {
		return true, true
	}
	if srcHit && dir != Ingress {
		return true, false
	}
	return false, false
}
