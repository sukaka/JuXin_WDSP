//go:build windows

package mirrorsrc

import "fmt"

func applySocketGroup(_, group string) error {
	return fmt.Errorf("mirrorsrc: Windows 不支持 socket_group (%q)，请改用回环 TCP listen_addr（如 127.0.0.1:9080）", group)
}
