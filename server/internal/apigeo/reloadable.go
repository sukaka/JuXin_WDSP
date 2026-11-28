// reloadable.go 零重启可热重载 GeoIP 引擎（atomic.Pointer[Engine] + .revision.json 目录监听）。
//
// 并发模型：
//   - 所有读路径（LookupCountry / LookupGeo / Enabled / Sources）均为无锁原子指针加载；
//   - Reload / CheckAndReload 由互斥锁串行化，先在独立新 Engine 中完成全部文件读取与解析，
//     成功后一次性原子替换指针，旧 Engine 由 GC 自然回收，并发查询零中断；
//   - Watch 周期扫描 <dataDir>/geoip/.revision.json 与槽位文件 stat 指纹，发现变更即热重载，
//     同时服务本机管理面上传、HA 备节点 hasyncd 同步落盘及运维手工替换文件场景。
package apigeo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultWatchInterval 后台目录变更检测默认周期（与 mirrorcap 轮询口径一致）。
const DefaultWatchInterval = 15 * time.Second

// enabledChecker 可动态报告可用态的 GeoIP 查询器接口（*Engine / *ReloadableEngine 实现）。
type enabledChecker interface {
	Enabled() bool
}

// IsLookupEnabled 判断 CountryLookup 实例当前是否真正可用：
//   - nil 或 typed-nil 指针返回 false；
//   - 实现 Enabled() bool 的动态查询器（如 *Engine / *ReloadableEngine）实时返回其 Enabled()；
//   - 其他纯 CountryLookup 实现（如 *MMDB / *XDB / 单测桩）非 nil 即视为可用。
func IsLookupEnabled(lookup CountryLookup) bool {
	if lookup == nil {
		return false
	}
	v := reflect.ValueOf(lookup)
	switch v.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Map, reflect.Func, reflect.Slice:
		if v.IsNil() {
			return false
		}
	}
	if ec, ok := lookup.(enabledChecker); ok {
		return ec.Enabled()
	}
	return true
}

// ReloadableEngine 并发安全、支持零重启热重载的统一 GeoIP 引擎包装器。
type ReloadableEngine struct {
	dirs     []string
	watchDir string

	mu              sync.Mutex
	current         atomic.Pointer[Engine]
	loadedAtNano    atomic.Int64
	lastFingerprint string
	onReload        func(*Engine) // 测试钩子
}

// 编译期接口断言：同时满足 GeoLookup 与 CountryLookup。
var (
	_ GeoLookup     = (*ReloadableEngine)(nil)
	_ CountryLookup = (*ReloadableEngine)(nil)
)

// NewReloadableEngine 构造可热重载 GeoIP 引擎，默认监听首个非空候选目录（即 <dataDir>/geoip）。
func NewReloadableEngine(dirs ...string) *ReloadableEngine {
	watchDir := ""
	cleaned := make([]string, 0, len(dirs))
	for _, d := range dirs {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		c := filepath.Clean(d)
		if watchDir == "" {
			watchDir = c
		}
		cleaned = append(cleaned, c)
	}
	return NewReloadableEngineWithWatchDir(watchDir, cleaned...)
}

// NewReloadableEngineWithWatchDir 构造可热重载 GeoIP 引擎并显式指定监听目录。
func NewReloadableEngineWithWatchDir(watchDir string, dirs ...string) *ReloadableEngine {
	cleaned := make([]string, 0, len(dirs))
	for _, d := range dirs {
		d = strings.TrimSpace(d)
		if d != "" {
			cleaned = append(cleaned, filepath.Clean(d))
		}
	}
	r := &ReloadableEngine{
		dirs:     cleaned,
		watchDir: strings.TrimSpace(watchDir),
	}
	if r.watchDir != "" {
		r.watchDir = filepath.Clean(r.watchDir)
	}
	eng := OpenEngine(r.dirs...)
	r.current.Store(eng)
	r.loadedAtNano.Store(time.Now().UTC().UnixNano())
	r.lastFingerprint = r.watchFingerprint()
	return r
}

// Engine 返回当前生效的只读引擎快照（永不为 nil）。
func (r *ReloadableEngine) Engine() *Engine {
	if r == nil {
		return nil
	}
	return r.current.Load()
}

// LoadedAt 返回最近一次加载/热重载时间（UTC）。
func (r *ReloadableEngine) LoadedAt() time.Time {
	if r == nil {
		return time.Time{}
	}
	ns := r.loadedAtNano.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns).UTC()
}

// Dirs 返回候选搜索目录副本。
func (r *ReloadableEngine) Dirs() []string {
	if r == nil {
		return nil
	}
	out := make([]string, len(r.dirs))
	copy(out, r.dirs)
	return out
}

// Enabled 实时返回当前生效引擎是否加载了至少一个离线 GeoIP 库。
func (r *ReloadableEngine) Enabled() bool {
	return r != nil && r.current.Load().Enabled()
}

// Sources 实时返回当前生效的数据源名称列表副本。
func (r *ReloadableEngine) Sources() []string {
	if r == nil {
		return []string{}
	}
	return r.current.Load().Sources()
}

// LookupCountry 实现 CountryLookup 接口（无锁读当前原子快照）。
func (r *ReloadableEngine) LookupCountry(ip netip.Addr) (string, error) {
	if r == nil {
		return "", nil
	}
	return r.current.Load().LookupCountry(ip)
}

// LookupGeo 实现 GeoLookup 接口（无锁读当前原子快照）。
func (r *ReloadableEngine) LookupGeo(ipRaw string) *GeoInfo {
	if r == nil {
		var nilEng *Engine
		return nilEng.LookupGeo(ipRaw)
	}
	return r.current.Load().LookupGeo(ipRaw)
}

// Reload 强制重新扫描候选目录并原子切换内存引擎（并发调用由互斥锁串行化）。
func (r *ReloadableEngine) Reload() *Engine {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reloadLocked()
}

func (r *ReloadableEngine) reloadLocked() *Engine {
	fp := r.watchFingerprint()
	next := OpenEngine(r.dirs...)
	r.current.Store(next)
	r.loadedAtNano.Store(time.Now().UTC().UnixNano())
	r.lastFingerprint = fp
	if r.onReload != nil {
		r.onReload(next)
	}
	slog.Info("geoip engine reloaded", "enabled", next.Enabled(), "sources", next.Sources())
	return next
}

// CheckAndReload 检测监听目录指纹变化，若发生变化则触发原子热重载并返回 true。
func (r *ReloadableEngine) CheckAndReload() bool {
	if r == nil || r.watchDir == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	fp := r.watchFingerprint()
	if fp == r.lastFingerprint {
		return false
	}
	r.reloadLocked()
	return true
}

// Watch 启动后台目录变更监听协程（默认 15s 轮询，ctx 取消即退出）。
func (r *ReloadableEngine) Watch(ctx context.Context, interval time.Duration) {
	if r == nil || r.watchDir == "" {
		return
	}
	if interval <= 0 {
		interval = DefaultWatchInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.CheckAndReload()
		}
	}
}

// watchFingerprint 计算 watchDir 内 .revision.json 内容与顶层 .xdb/.mmdb 文件元数据的轻量摘要。
// 空闲周期仅做 stat 与极小 JSON 读取，不读入任何大库文件内容。
func (r *ReloadableEngine) watchFingerprint() string {
	if r.watchDir == "" {
		return ""
	}
	h := sha256.New()
	if f, err := os.Open(filepath.Join(r.watchDir, revisionFileName)); err == nil {
		_, _ = io.Copy(h, io.LimitReader(f, 64<<10))
		_ = f.Close()
	}
	_, _ = h.Write([]byte{'\n'})

	entries, err := os.ReadDir(r.watchDir)
	if err == nil {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			lower := strings.ToLower(e.Name())
			if !strings.HasSuffix(lower, ".xdb") && !strings.HasSuffix(lower, ".mmdb") {
				continue
			}
			names = append(names, e.Name())
		}
		sort.Strings(names)
		for _, name := range names {
			info, statErr := os.Stat(filepath.Join(r.watchDir, name))
			if statErr != nil || info.IsDir() {
				continue
			}
			_, _ = fmt.Fprintf(h, "%s:%d:%d\n", name, info.Size(), info.ModTime().UTC().UnixNano())
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}
