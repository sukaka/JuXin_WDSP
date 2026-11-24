package netif

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Record node-interfaces.jsonl 单行（字段与 server 侧 gateway_node_interfaces 采集对应）。
type Record struct {
	NodeName    string    `json:"node_name"`
	IfName      string    `json:"ifname"`
	MAC         string    `json:"mac"`
	IPAddresses []string  `json:"ip_addresses"`
	PCIPath     string    `json:"pci_path,omitempty"`
	Driver      string    `json:"driver,omitempty"`
	MediaType   string    `json:"media_type"`
	LinkSpeed   int       `json:"link_speed"`
	OperState   string    `json:"operstate"`
	CollectedAt time.Time `json:"collected_at"`
}

// WriteSnapshot 全量快照原子重写：临时文件 + fsync + rename，
// 采集端（server 只读卷）不会读到半文件。清单是全量快照而非追加流，
// 空清单同样写空文件（区分「已采集但无物理口」与「采集器未运行」）。
func WriteSnapshot(path, nodeName string, ifs []Interface, now time.Time) (err error) {
	if path == "" {
		return fmt.Errorf("snapshot path required")
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("open tmp snapshot: %w", err)
	}
	tmp := f.Name()
	if err = f.Chmod(0o640); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("chmod tmp snapshot: %w", err)
	}
	// 失败路径清理临时文件（成功路径 f 已 Close 且 rename 走，Remove 落空无碍）
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()

	w := bufio.NewWriter(f)
	for _, ifi := range ifs {
		rec := Record{
			NodeName:    nodeName,
			IfName:      ifi.IfName,
			MAC:         ifi.MAC,
			IPAddresses: ifi.IPAddresses,
			PCIPath:     ifi.PCIPath,
			Driver:      ifi.Driver,
			MediaType:   ifi.MediaType,
			LinkSpeed:   ifi.LinkSpeed,
			OperState:   ifi.OperState,
			CollectedAt: now,
		}
		data, merr := json.Marshal(rec)
		if merr != nil {
			err = fmt.Errorf("marshal interface %s: %w", ifi.IfName, merr)
			return err
		}
		if _, werr := w.Write(append(data, '\n')); werr != nil {
			err = fmt.Errorf("write snapshot: %w", werr)
			return err
		}
	}
	if err = w.Flush(); err != nil {
		return fmt.Errorf("flush snapshot: %w", err)
	}
	if err = f.Sync(); err != nil {
		return fmt.Errorf("sync snapshot: %w", err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("close snapshot: %w", err)
	}
	if err = os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename snapshot: %w", err)
	}
	return nil
}
