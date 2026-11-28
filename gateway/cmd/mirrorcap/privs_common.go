package main

import (
	"fmt"
	"os"
	"strings"
)

const (
	mirrorTargetUID = 1000
	mirrorTargetGID = 1000
	capSetPCap      = 8
	capNetAdmin     = 12
	capNetRaw       = 13
)

func shouldDropPrivileges() bool {
	v := strings.TrimSpace(os.Getenv("MIRROR_DROP_PRIVS"))
	return strings.EqualFold(v, "1") || strings.EqualFold(v, "true")
}

type healthcheckPrivOps interface {
	Geteuid() int
	ReadCapPrm() (uint64, error)
	SetNoNewPrivs() error
	ClearGroups() error
	DropAllBoundingCaps() error
	Setresgid(gid int) error
	Setresuid(uid int) error
	ClearCapabilities() error
}

// dropHealthcheckPrivilegesWith 在 MIRROR_DROP_PRIVS=1 且以 root 执行 --healthcheck 时
// 同步降权至 UID/GID 1000 并清零全部 Linux capability：
//   - 避免 cap_drop: [ALL]（无 CAP_DAC_OVERRIDE）的 root 健康检查探针无法访问
//     1000:1000 0750 的 gateway-rules 卷（/etc/caddy/rules/current）；
//   - 使 --healthcheck 使用与运行期主进程一致的 1000:1000 身份校验目录可达性，
//     且不要求持有 CAP_NET_RAW/CAP_NET_ADMIN。
func dropHealthcheckPrivilegesWith(ops healthcheckPrivOps) error {
	if !shouldDropPrivileges() || ops.Geteuid() != 0 {
		return nil
	}
	if err := ops.SetNoNewPrivs(); err != nil {
		return fmt.Errorf("healthcheck drop-privs PR_SET_NO_NEW_PRIVS: %w", err)
	}
	if err := ops.ClearGroups(); err != nil {
		return fmt.Errorf("healthcheck drop-privs Setgroups: %w", err)
	}
	perm, err := ops.ReadCapPrm()
	if err != nil {
		return fmt.Errorf("healthcheck drop-privs read CapPrm: %w", err)
	}
	if perm&(1<<uint(capSetPCap)) != 0 {
		if err := ops.DropAllBoundingCaps(); err != nil {
			return fmt.Errorf("healthcheck drop-privs drop bounding caps: %w", err)
		}
	}
	if err := ops.Setresgid(mirrorTargetGID); err != nil {
		return fmt.Errorf("healthcheck drop-privs Setresgid(%d): %w", mirrorTargetGID, err)
	}
	if err := ops.Setresuid(mirrorTargetUID); err != nil {
		return fmt.Errorf("healthcheck drop-privs Setresuid(%d): %w", mirrorTargetUID, err)
	}
	if err := ops.ClearCapabilities(); err != nil {
		return fmt.Errorf("healthcheck drop-privs clear caps: %w", err)
	}
	return nil
}
