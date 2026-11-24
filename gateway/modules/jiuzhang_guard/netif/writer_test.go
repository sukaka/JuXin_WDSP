package netif

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func readRecords(t *testing.T, path string) []Record {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []Record
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("bad json line %q: %v", sc.Text(), err)
		}
		out = append(out, r)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestWriteSnapshotAtomicRewrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node-interfaces.jsonl")
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)

	ifs := []Interface{
		{
			IfName: "eth0", MAC: "00:11:22:33:44:55",
			IPAddresses: []string{"192.168.10.2/24", "2408:8207::1/64"},
			PCIPath:     "0000:03:00.0", Driver: "ixgbe", MediaType: MediaFibre, LinkSpeed: 10000, OperState: "up",
		},
		{
			IfName: "eth1", MAC: "00:11:22:33:44:66",
			IPAddresses: []string{},
			MediaType:   MediaUnknown, LinkSpeed: 0, OperState: "down",
		},
	}
	if err := WriteSnapshot(path, "node-1", ifs, now); err != nil {
		t.Fatal(err)
	}
	recs := readRecords(t, path)
	if len(recs) != 2 {
		t.Fatalf("records: %+v", recs)
	}
	r := recs[0]
	if r.NodeName != "node-1" || r.IfName != "eth0" || r.MAC != "00:11:22:33:44:55" ||
		len(r.IPAddresses) != 2 || r.IPAddresses[0] != "192.168.10.2/24" || r.IPAddresses[1] != "2408:8207::1/64" ||
		r.PCIPath != "0000:03:00.0" || r.Driver != "ixgbe" || r.MediaType != MediaFibre ||
		r.LinkSpeed != 10000 || r.OperState != "up" || !r.CollectedAt.Equal(now) {
		t.Errorf("record fields: %+v", r)
	}
	if recs[1].IPAddresses == nil || len(recs[1].IPAddresses) != 0 {
		t.Errorf("eth1 empty ip_addresses should unmarshal as non-nil empty slice, got %#v", recs[1].IPAddresses)
	}

	// 临时文件不留存（原子 rename 成功）
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("tmp file should not exist: %v", err)
	}

	// 全量快照语义：重写后旧记录被整体替换而非追加
	if err := WriteSnapshot(path, "node-1", ifs[1:], now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	recs = readRecords(t, path)
	if len(recs) != 1 || recs[0].IfName != "eth1" {
		t.Fatalf("rewrite should replace, got %+v", recs)
	}

	// 空清单写空文件（区分「已采集无物理口」与「采集器未运行」）
	if err := WriteSnapshot(path, "node-1", nil, now); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != 0 {
		t.Errorf("empty snapshot should be 0 bytes, got %d", fi.Size())
	}
}

func TestWriteSnapshotErrorCleansTmp(t *testing.T) {
	// 目标目录不存在：返回错误且不残留临时文件
	path := filepath.Join(t.TempDir(), "nonexistent", "node-interfaces.jsonl")
	err := WriteSnapshot(path, "node-1", nil, time.Now().UTC())
	if err == nil {
		t.Fatal("expect error for missing parent dir")
	}
	if _, serr := os.Stat(path + ".tmp"); !os.IsNotExist(serr) {
		t.Errorf("tmp file should be cleaned: %v", serr)
	}
	if err := WriteSnapshot("", "node-1", nil, time.Now().UTC()); err == nil {
		t.Error("expect error for empty path")
	}
}
