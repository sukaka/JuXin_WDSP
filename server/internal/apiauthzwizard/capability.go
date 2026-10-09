// capability.go 主节点能力检查（§1.2 BLOCKED_BY_NODE 判定输入）：
// 读 sidecar capability.json——发布门同一事实源（gatewayconfig.LoadNodeManifest），
// authzdecide 自报须 ≥ az/3；清单缺失/契约违规/陈旧均按能力不足处理
// （与发布门 fail-closed 同语义——readiness 是「切 PROTECT 后能否生效」的预评估）。
package apiauthzwizard

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// capabilityStaleAfter 清单陈旧阈值（与发布门 capabilityStaleAfter 同口径：3×60s tick）。
const capabilityStaleAfter = 3 * 60 * time.Second

// SidecarCapabilityChecker 构造 sidecar 清单能力检查器（dir 空串用网关默认目录）。
func SidecarCapabilityChecker(dir string) CapabilityChecker {
	if dir == "" {
		dir = gatewayconfig.DefaultSidecarDir
	}
	return func(ctx context.Context) (bool, string) {
		manifest, err := gatewayconfig.LoadNodeManifest(dir)
		if err != nil {
			return false, "能力清单不可用（" + err.Error() + "）"
		}
		if stale, age := gatewayconfig.ManifestStale(manifest, time.Now().UTC(), capabilityStaleAfter); stale {
			return false, fmt.Sprintf("能力清单过期（陈旧 %.0f 秒）", age.Seconds())
		}
		for _, d := range manifest.Detectors {
			if d.Name == "authzdecide" {
				if azVersionAtLeast(d.Version, 3) {
					return true, ""
				}
				return false, "authzdecide 自报 " + d.Version + "（含 PROTECT 快照要求 az/3）"
			}
		}
		return false, "能力清单无 authzdecide 自报"
	}
}

// azVersionAtLeast authzdecide 版本序数比较（"az/N" ≥ want；形态不符按不满足）。
func azVersionAtLeast(version string, want int) bool {
	parts := strings.SplitN(strings.TrimSpace(version), "/", 2)
	if len(parts) != 2 || parts[0] != "az" {
		return false
	}
	n, err := strconv.Atoi(parts[1])
	return err == nil && n >= want
}
