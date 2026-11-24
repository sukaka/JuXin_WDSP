package nodeinterfaces

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// MemStore 是内存清单仓储（单元测试用），与 *Store 共用 reconcile 合并语义。
type MemStore struct {
	mu   sync.Mutex
	rows map[string]Interface // key: node_name + "\x00" + ifname
}

// NewMemStore 创建内存仓储。
func NewMemStore() *MemStore {
	return &MemStore{rows: map[string]Interface{}}
}

func memKey(nodeName, ifname string) string { return nodeName + "\x00" + ifname }

// ListGrouped 按节点分组返回清单（组内 sort_order 升序）。
func (m *MemStore) ListGrouped(_ context.Context, nodeName string) ([]NodeInterfaces, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	byNode := map[string][]Interface{}
	var nodes []string
	for _, row := range m.rows {
		if nodeName != "" && row.NodeName != nodeName {
			continue
		}
		if _, ok := byNode[row.NodeName]; !ok {
			nodes = append(nodes, row.NodeName)
		}
		row.IPAddresses = cloneIPAddresses(row.IPAddresses)
		byNode[row.NodeName] = append(byNode[row.NodeName], row)
	}
	sort.Strings(nodes)
	out := make([]NodeInterfaces, 0, len(nodes))
	for _, n := range nodes {
		list := byNode[n]
		sortInterfaces(list)
		out = append(out, NodeInterfaces{NodeName: n, Interfaces: list})
	}
	return out, nil
}

// ApplySnapshot 合并一次全量快照（语义同 SQL 仓储）。
func (m *MemStore) ApplySnapshot(_ context.Context, nodeName string, items []SnapshotItem, seenAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var existing []Interface
	for _, row := range m.rows {
		if row.NodeName == nodeName {
			existing = append(existing, row)
		}
	}
	sortInterfaces(existing)
	for _, row := range reconcile(nodeName, existing, items, seenAt) {
		m.rows[memKey(row.NodeName, row.Ifname)] = row
	}
	return nil
}

// ReplaceOrder 整体替换排序与角色（语义同 SQL 仓储）。
func (m *MemStore) ReplaceOrder(_ context.Context, nodeName string, items []OrderItem) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var missing []string
	for _, it := range items {
		row, ok := m.rows[memKey(nodeName, it.Ifname)]
		if !ok || row.NodeName != nodeName {
			missing = append(missing, it.Ifname)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: %s", ErrUnknownInterface, strings.Join(missing, ","))
	}
	for _, it := range items {
		row := m.rows[memKey(nodeName, it.Ifname)]
		row.SortOrder = it.SortOrder
		row.Role = it.Role
		m.rows[memKey(nodeName, it.Ifname)] = row
	}
	return nil
}
