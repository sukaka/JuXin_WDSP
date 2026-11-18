//go:build linux

package pcapevidence

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func (c *Capture) checkDiskCapacity() error {
	var stat unix.Statfs_t
	if err := unix.Statfs(c.config.HotDir, &stat); err != nil {
		return fmt.Errorf("check PCAP hot storage capacity: %w", err)
	}
	if stat.Blocks == 0 || uint64(stat.Bavail)*100 < uint64(stat.Blocks)*uint64(c.config.MinFreePercent) {
		return fmt.Errorf("PCAP hot storage free space is below the configured watermark")
	}
	return nil
}
