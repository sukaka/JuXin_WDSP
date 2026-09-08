// 发布链路下发的文件配置（多模式部署产品化，docs/NETWORK_MODES_DESIGN.md）。
//
// 服务端将本文件写入共享卷，容器内固定路径 DefaultFileConfigPath；
// 本组件以轮询（默认 15s，避免 fsnotify 依赖，容忍共享卷挂载语义差异）感知变化。
//
// 优先级约定（与 env 的关系，注释即契约）：
//   - 文件存在即文件优先：enabled/interfaces/ports/events_log/node/discovery 以文件为准，
//     文件未携带的运维项（body_max/rules_dir 等）沿用 env 基线；
//   - 文件不存在且从未生效过 → env 为默认值（PoC/lab 路径）；
//   - 文件曾生效后被删除 → 发布方收回配置，停止抓包进入空转（进程不退出）；
//   - 文件解析/校验失败 → 保留上一份生效配置（last-good），显式告警，不中途切换。
package mirrorcap

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	// DefaultFileConfigPath 发布链路写入共享卷的固定容器内路径。
	DefaultFileConfigPath = "/var/run/caddy/sidecars/mirrorcap.json"
	// DefaultPollInterval 配置文件轮询周期。
	DefaultPollInterval = 15 * time.Second
)

// FileConfig mirrorcap.json 下发契约：
// {"enabled":bool,"node":"...","interfaces":["eth2",...],"ports":[80,8080],"events_log":"...",
//
//	"discovery":{"enabled":bool,"interfaces":[{"name":"eth2","mode":"MIRROR"}],
//	             "flush_interval_sec":30,"log":"..."}}
type FileConfig struct {
	// Enabled 检测启停开关（false = 停止检测抓包；缺省零值同为 false，不擅自抓包）。
	Enabled bool `json:"enabled"`
	// Node 网关节点名（写入事件 gateway_node_id；空回退 env GATEWAY_NODE_NAME）。
	Node string `json:"node"`
	// Ifaces 检测镜像监听接口集合（每口一个抓包句柄；enabled=true 时必填）。
	Ifaces []string `json:"interfaces"`
	// Ports 目标 TCP 端口集合（仅重组目的端口命中集合的流；空回退 env MIRROR_PORTS）。
	Ports []uint16 `json:"ports"`
	// EventsLog 事件输出路径（空回退 env MIRROR_EVENTS_LOG）。
	EventsLog string `json:"events_log"`
	// Discovery 站点资产被动发现块（可选；缺省整块缺省 = 沿用 env 基线，块内
	// enabled=false = 文件显式关闭发现——文件优先）。发现与检测独立启停。
	Discovery *FileDiscovery `json:"discovery"`
}

// FileDiscovery 站点资产被动发现下发块（未知字段容忍契约与顶层一致）。
type FileDiscovery struct {
	// Enabled 发现开关（false = 停止发现抓包；与检测 enabled 相互独立）。
	Enabled bool `json:"enabled"`
	// Interfaces 发现监听接口集合（enabled=true 时必填——同顶层 enabled/interfaces 约束风格）。
	Interfaces []FileDiscoveryIface `json:"interfaces"`
	// FlushIntervalSec 聚合窗口落盘周期秒（<=0 回退默认 30s；负数报错）。
	FlushIntervalSec int `json:"flush_interval_sec"`
	// Log 发现记录输出路径（空回退 env SITE_DISCOVERY_LOG / 内置默认）。
	Log string `json:"log"`
}

// FileDiscoveryIface 发现接口及其流量来源模式。
type FileDiscoveryIface struct {
	// Name 接口名。
	Name string `json:"name"`
	// Mode 流量来源模式（MIRROR / ROUTED / TRANSPARENT；空缺省 MIRROR——旁路采集器原生模式；
	// 写入发现记录 source_mode 字段）。
	Mode string `json:"mode"`
}

// LoadFileConfig 读取并校验下发文件。文件不存在返回可用 errors.Is(err, os.ErrNotExist)
// 判别的错误；解析/校验失败返回明确错误（调用方保留上一份有效配置，不静默降级）。
func LoadFileConfig(path string) (FileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return FileConfig{}, err
	}
	var fc FileConfig
	// 未知字段容忍（前向兼容：发布端先行新增字段时旧进程仍可解析）。
	if err := json.Unmarshal(data, &fc); err != nil {
		return FileConfig{}, fmt.Errorf("解析 %s: %w", path, err)
	}
	if err := fc.normalize(); err != nil {
		return FileConfig{}, fmt.Errorf("校验 %s: %w", path, err)
	}
	return fc, nil
}

// normalize 去空白/去重保序并做合法性校验（端口上界 65535 由 uint16 类型在
// json 解码期保证，此处校验下界与 enabled 约束）。
func (fc *FileConfig) normalize() error {
	seenIf := map[string]struct{}{}
	ifaces := make([]string, 0, len(fc.Ifaces))
	for _, s := range fc.Ifaces {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seenIf[s]; ok {
			continue
		}
		seenIf[s] = struct{}{}
		ifaces = append(ifaces, s)
	}
	fc.Ifaces = ifaces

	seenPort := map[uint16]struct{}{}
	ports := make([]uint16, 0, len(fc.Ports))
	for _, p := range fc.Ports {
		if p == 0 {
			return fmt.Errorf("非法端口 0（需 1-65535）")
		}
		if _, ok := seenPort[p]; ok {
			continue
		}
		seenPort[p] = struct{}{}
		ports = append(ports, p)
	}
	fc.Ports = ports

	fc.Node = strings.TrimSpace(fc.Node)
	fc.EventsLog = strings.TrimSpace(fc.EventsLog)
	if fc.Enabled && len(fc.Ifaces) == 0 {
		return fmt.Errorf("enabled=true 但 interfaces 为空")
	}
	if err := fc.normalizeDiscovery(); err != nil {
		return err
	}
	return nil
}

// normalizeDiscovery 校验发现块：接口名去空白去重保序、mode 归一（缺省 MIRROR，
// 仅接受 MIRROR/ROUTED/TRANSPARENT）、flush_interval_sec 负数报错、enabled=true 时接口必填。
func (fc *FileConfig) normalizeDiscovery() error {
	d := fc.Discovery
	if d == nil {
		return nil
	}
	seen := map[string]struct{}{}
	ifaces := make([]FileDiscoveryIface, 0, len(d.Interfaces))
	for _, it := range d.Interfaces {
		name := strings.TrimSpace(it.Name)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		mode := strings.ToUpper(strings.TrimSpace(it.Mode))
		if mode == "" {
			mode = "MIRROR"
		}
		if mode != "MIRROR" && mode != "ROUTED" && mode != "TRANSPARENT" {
			return fmt.Errorf("discovery 接口 %s 非法 mode %q（需 MIRROR/ROUTED/TRANSPARENT）", name, it.Mode)
		}
		ifaces = append(ifaces, FileDiscoveryIface{Name: name, Mode: mode})
	}
	d.Interfaces = ifaces
	d.Log = strings.TrimSpace(d.Log)
	if d.FlushIntervalSec < 0 {
		return fmt.Errorf("discovery.flush_interval_sec 非法（需正整数秒）: %d", d.FlushIntervalSec)
	}
	if d.Enabled && len(d.Interfaces) == 0 {
		return fmt.Errorf("discovery.enabled=true 但 discovery.interfaces 为空")
	}
	return nil
}

// overlay 以文件配置覆盖 env 基线：文件字段非空即以文件为准（文件优先）；
// 文件未携带的字段沿用 env 基线（容忍发布端只下发差量字段）。
// discovery 块存在即整块的 enabled 以文件为准（bool 零值无法区分缺省与显式 false，
// 以块存在性表达下发方意图）。
func (fc FileConfig) overlay(base Config) Config {
	cfg := base
	if len(fc.Ports) > 0 {
		cfg.Ports = fc.Ports
	}
	if fc.EventsLog != "" {
		cfg.EventsLog = fc.EventsLog
	}
	if fc.Node != "" {
		cfg.NodeName = fc.Node
	}
	if fc.Discovery != nil {
		cfg.Discovery.Enabled = fc.Discovery.Enabled
		if len(fc.Discovery.Interfaces) > 0 {
			ifaces := make([]DiscoveryIface, 0, len(fc.Discovery.Interfaces))
			for _, it := range fc.Discovery.Interfaces {
				ifaces = append(ifaces, DiscoveryIface{Name: it.Name, Mode: it.Mode})
			}
			cfg.Discovery.Ifaces = ifaces
		}
		if fc.Discovery.FlushIntervalSec > 0 {
			cfg.Discovery.FlushInterval = time.Duration(fc.Discovery.FlushIntervalSec) * time.Second
		}
		if fc.Discovery.Log != "" {
			cfg.Discovery.Log = fc.Discovery.Log
		}
	}
	return cfg
}
