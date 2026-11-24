// 发布链路下发的文件配置（多模式部署产品化，docs/NETWORK_MODES_DESIGN.md）。
//
// 服务端将本文件写入共享卷，容器内固定路径 DefaultFileConfigPath；
// 本组件以轮询（默认 15s，避免 fsnotify 依赖，容忍共享卷挂载语义差异）感知变化。
//
// 优先级约定（与 env 的关系，注释即契约）：
//   - 文件存在即文件优先：enabled/listen/target 以文件为准，
//     文件未携带的运维项（max_conns/超时等）沿用 env 基线；
//   - 文件不存在且从未生效过 → env 为默认值（PoC/lab 路径）；
//   - 文件曾生效后被删除 → 发布方收回配置，关闭监听进入空转（进程不退出）；
//   - 文件解析/校验失败 → 保留上一份生效配置（last-good），显式告警，不中途切换。
package tproxyd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	// DefaultFileConfigPath 发布链路写入共享卷的固定容器内路径。
	DefaultFileConfigPath = "/var/run/caddy/sidecars/tproxyd.json"
	// DefaultPollInterval 配置文件轮询周期。
	DefaultPollInterval = 15 * time.Second
)

// FileConfig tproxyd.json 下发契约：
// {"enabled":bool,"listen":"0.0.0.0:15000","target":"127.0.0.1:15080","ports":[80],
//
//	"protect_hosts":["www.test.com","*.example.com"],"target_tls":"127.0.0.1:15443"}
//
// ports 为牵引端口集合（编排层据其安装 REDIRECT 牵引规则）；本进程数据面只消费
// listen/target，ports 在此仅校验并记入状态日志，不参与转发逻辑。
// protect_hosts 非空时启用 TLS SNI 嗅探分流（清单内域名送 target_tls 终结检测，
// 清单外默认 fail-closed 倒向 target_tls，仅 passthrough_allowlist 内域名按原始目的透传）。
// 两者均支持精确域名与 RFC 单级前导通配符（*.example.com）。
type FileConfig struct {
	// Enabled 启停开关（false = 关闭监听进入空转；缺省零值同为 false，不擅自监听）。
	Enabled bool `json:"enabled"`
	// Listen 监听地址（REDIRECT 牵引目标；空回退 env TPROXY_LISTEN）。
	Listen string `json:"listen"`
	// Target 下游 Caddy 地址（空回退 env TPROXY_TARGET）。
	Target string `json:"target"`
	// Ports 牵引端口集合（信息性字段，见类型注释）。
	Ports []uint16 `json:"ports"`
	// ProtectHosts SNI 防护域名清单（nil 回退 env TPROXY_PROTECT_HOSTS；空数组 [] 显式清空）。
	ProtectHosts []string `json:"protect_hosts"`
	// PassthroughAllowlist 显式允许端到端透传的 TLS SNI 域名白名单（空 = 禁止任意未列明 SNI 透传）。
	PassthroughAllowlist []string `json:"passthrough_allowlist,omitempty"`
	// TargetTLS 下游 Caddy TLS 监听器地址（空回退 env TPROXY_TARGET_TLS）。
	TargetTLS string `json:"target_tls"`
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
// json 解码期保证；listen/target 非空时须为合法 host:port）。
func (fc *FileConfig) normalize() error {
	fc.Listen = strings.TrimSpace(fc.Listen)
	fc.Target = strings.TrimSpace(fc.Target)
	fc.TargetTLS = strings.TrimSpace(fc.TargetTLS)
	if fc.Listen != "" {
		if err := checkAddr("listen", fc.Listen); err != nil {
			return err
		}
	}
	if fc.Target != "" {
		if err := checkAddr("target", fc.Target); err != nil {
			return err
		}
	}
	if fc.TargetTLS != "" {
		if err := checkAddr("target_tls", fc.TargetTLS); err != nil {
			return err
		}
	}
	if len(fc.ProtectHosts) > 0 {
		hosts, err := normalizeHosts(strings.Join(fc.ProtectHosts, ","))
		if err != nil {
			return err
		}
		fc.ProtectHosts = hosts
	}
	if len(fc.PassthroughAllowlist) > 0 {
		hosts, err := normalizeHosts(strings.Join(fc.PassthroughAllowlist, ","))
		if err != nil {
			return err
		}
		fc.PassthroughAllowlist = hosts
	}
	seen := map[uint16]struct{}{}
	ports := make([]uint16, 0, len(fc.Ports))
	for _, p := range fc.Ports {
		if p == 0 {
			return fmt.Errorf("非法端口 0（需 1-65535）")
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		ports = append(ports, p)
	}
	fc.Ports = ports
	return nil
}
