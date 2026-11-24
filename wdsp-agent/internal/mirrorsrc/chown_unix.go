//go:build !windows

package mirrorsrc

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
)

func applySocketGroup(path, group string) error {
	g, err := user.LookupGroup(group)
	if err != nil {
		return fmt.Errorf("mirrorsrc: 属组 %q 不存在: %w", group, err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return fmt.Errorf("mirrorsrc: 属组 %q GID 非法: %w", group, err)
	}
	if err := os.Chown(path, -1, gid); err != nil {
		return fmt.Errorf("mirrorsrc: 设置 socket 属组失败: %w", err)
	}
	return nil
}
