package nodeinterfaces

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store 是 PostgreSQL 清单仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

const ifaceColumns = `id, node_name, ifname, mac, COALESCE(ip_addresses, '{}'::TEXT[]), pci_path, driver, media_type, link_speed, operstate,
       sort_order, role, present, first_seen_at, last_seen_at`

func scanInterface(row pgx.Row) (Interface, error) {
	var it Interface
	err := row.Scan(&it.ID, &it.NodeName, &it.Ifname, &it.MAC, &it.IPAddresses, &it.PCIPath, &it.Driver,
		&it.MediaType, &it.LinkSpeed, &it.Operstate, &it.SortOrder, &it.Role,
		&it.Present, &it.FirstSeenAt, &it.LastSeenAt)
	if it.IPAddresses == nil {
		it.IPAddresses = []string{}
	}
	return it, err
}

// ListGrouped 按节点分组返回清单（组内 sort_order 升序）；nodeName 非空时只返回该节点。
func (s *Store) ListGrouped(ctx context.Context, nodeName string) ([]NodeInterfaces, error) {
	rows, err := s.db.Query(ctx, `
SELECT `+ifaceColumns+`
FROM gateway_node_interfaces
WHERE ($1 = '' OR node_name = $1)
ORDER BY node_name, sort_order ASC, ifname ASC`, nodeName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NodeInterfaces
	for rows.Next() {
		it, err := scanInterface(rows)
		if err != nil {
			return nil, err
		}
		if n := len(out); n > 0 && out[n-1].NodeName == it.NodeName {
			out[n-1].Interfaces = append(out[n-1].Interfaces, it)
		} else {
			out = append(out, NodeInterfaces{NodeName: it.NodeName, Interfaces: []Interface{it}})
		}
	}
	return out, rows.Err()
}

// loadNodeLocked 读取节点当前全部记录（事务内，供 reconcile 合并）。
func loadNode(ctx context.Context, tx pgx.Tx, nodeName string) ([]Interface, error) {
	rows, err := tx.Query(ctx, `
SELECT `+ifaceColumns+`
FROM gateway_node_interfaces WHERE node_name = $1
ORDER BY sort_order ASC, ifname ASC`, nodeName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Interface
	for rows.Next() {
		it, err := scanInterface(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// ApplySnapshot 把某节点一次全量快照 UPSERT 入库（reconcile 语义见包注释）。
func (s *Store) ApplySnapshot(ctx context.Context, nodeName string, items []SnapshotItem, seenAt time.Time) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	existing, err := loadNode(ctx, tx, nodeName)
	if err != nil {
		return fmt.Errorf("load node interfaces: %w", err)
	}
	hasIP := make(map[string]bool, len(items))
	for _, it := range items {
		if it.IPAddresses != nil {
			hasIP[it.Ifname] = true
		}
	}
	merged := reconcile(nodeName, existing, items, seenAt)
	for _, row := range merged {
		// 冲突分支只刷新采集字段与 present/last_seen_at；
		// sort_order/role/first_seen_at 属用户设定与历史，绝不由采集覆盖。
		ipAddrs := cloneIPAddresses(row.IPAddresses)
		_, err := tx.Exec(ctx, `
INSERT INTO gateway_node_interfaces
(node_name, ifname, mac, ip_addresses, pci_path, driver, media_type, link_speed, operstate,
 sort_order, role, present, first_seen_at, last_seen_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
ON CONFLICT (node_name, ifname) DO UPDATE SET
  mac = EXCLUDED.mac,
  ip_addresses = CASE WHEN $15 THEN EXCLUDED.ip_addresses ELSE gateway_node_interfaces.ip_addresses END,
  pci_path = EXCLUDED.pci_path, driver = EXCLUDED.driver,
  media_type = CASE
    WHEN EXCLUDED.media_type NOT IN ('', 'UNKNOWN')
      OR gateway_node_interfaces.media_type IN ('', 'UNKNOWN')
    THEN EXCLUDED.media_type
    ELSE gateway_node_interfaces.media_type
  END,
  link_speed = EXCLUDED.link_speed,
  operstate = EXCLUDED.operstate, present = EXCLUDED.present,
  last_seen_at = EXCLUDED.last_seen_at`,
			row.NodeName, row.Ifname, row.MAC, ipAddrs, row.PCIPath, row.Driver, row.MediaType,
			row.LinkSpeed, row.Operstate, row.SortOrder, row.Role, row.Present,
			row.FirstSeenAt, row.LastSeenAt, hasIP[row.Ifname])
		if err != nil {
			return fmt.Errorf("upsert interface %s/%s: %w", row.NodeName, row.Ifname, err)
		}
	}
	return tx.Commit(ctx)
}

// ListMirrorInterfaces 返回节点 role=MIRROR 且 present 的接口名（sort_order 升序、同值按 ifname）；
// 发布通道写 mirrorcap 边车配置用（docs/NETWORK_MODES_DESIGN.md §4.2）。
func (s *Store) ListMirrorInterfaces(ctx context.Context, nodeName string) ([]string, error) {
	return s.ListInterfacesByRole(ctx, nodeName, RoleMirror)
}

// ListInterfacesByRole 返回节点指定 role 且 present 的接口名（sort_order 升序、同值按 ifname）；
// 发布通道边车配置按角色取接口用（MIRROR 口给镜像发现，TRAFFIC 口给路由/透明发现）。
func (s *Store) ListInterfacesByRole(ctx context.Context, nodeName, role string) ([]string, error) {
	rows, err := s.db.Query(ctx, `
SELECT ifname FROM gateway_node_interfaces
WHERE node_name = $1 AND role = $2 AND present
ORDER BY sort_order ASC, ifname ASC`, nodeName, role)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// ReplaceOrder 整体替换节点下指定接口的排序与角色（role 恒传，空串 = 清除角色）。
// 引用不存在的接口时返回 ErrUnknownInterface（包裹缺失接口名）。
func (s *Store) ReplaceOrder(ctx context.Context, nodeName string, items []OrderItem) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	existing, err := loadNode(ctx, tx, nodeName)
	if err != nil {
		return fmt.Errorf("load node interfaces: %w", err)
	}
	known := make(map[string]bool, len(existing))
	for _, e := range existing {
		known[e.Ifname] = true
	}
	var missing []string
	for _, it := range items {
		if !known[it.Ifname] {
			missing = append(missing, it.Ifname)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: %s", ErrUnknownInterface, strings.Join(missing, ","))
	}
	for _, it := range items {
		// role 恒传（空串 = 清除角色），整体替换
		tag, err := tx.Exec(ctx, `
UPDATE gateway_node_interfaces SET sort_order = $3, role = $4
WHERE node_name = $1 AND ifname = $2`, nodeName, it.Ifname, it.SortOrder, it.Role)
		if err != nil {
			return fmt.Errorf("update interface order %s/%s: %w", nodeName, it.Ifname, err)
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("%w: %s", ErrUnknownInterface, it.Ifname)
		}
	}
	return tx.Commit(ctx)
}

// sortInterfaces 组内排序（sort_order 升序，同值按 ifname 稳定次序）。
func sortInterfaces(list []Interface) {
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].SortOrder != list[j].SortOrder {
			return list[i].SortOrder < list[j].SortOrder
		}
		return list[i].Ifname < list[j].Ifname
	})
}
