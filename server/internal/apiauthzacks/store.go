// store.go 节点授权 ACK 视图 PostgreSQL 仓储（NG-AZ-02 D6）：联查 api_gateway_nodes
// 与 api_node_authz_acks（迁移 000173），并读出管理面向量水位
// （api_authz_manual_revocation_seq 单行 manual_seq + api_authority_watermarks 逐来源）。
// 全部只读——ACK 事实的唯一写入方是 apinodes.Store.RecordHeartbeat（心跳通道）。
package apiauthzacks

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/apiruntime"
)

// Store 节点授权 ACK 视图仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建。
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

// ListNodeAcks 全节点 ACK 联查（node_name 升序，节点基数小不分页；无 ACK 行的
// 节点 HasAck=false，ACK 列全空——派生侧如实 NEVER_ACKED）。
func (s *Store) ListNodeAcks(ctx context.Context) ([]AckRow, error) {
	rows, err := s.db.Query(ctx, `
SELECT n.node_name, n.status,
       a.last_ack_at, a.authz_policy_version, a.authz_watermark,
       a.authz_applied_at, a.authz_lease_seconds, a.clock_skew_seconds,
       (a.node_name IS NOT NULL)
FROM api_gateway_nodes n
LEFT JOIN api_node_authz_acks a ON a.node_name = n.node_name
ORDER BY n.node_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AckRow{}
	for rows.Next() {
		var r AckRow
		var watermarkJSON []byte
		var lease *int32
		var policyVersion *string // 无 ACK 行时 LEFT JOIN 为 NULL（NOT NULL DEFAULT '' 仅保证有行非空）
		if err := rows.Scan(&r.NodeName, &r.Status,
			&r.LastAckAt, &policyVersion, &watermarkJSON,
			&r.AuthzAppliedAt, &lease, &r.ClockSkewSeconds, &r.HasAck); err != nil {
			return nil, err
		}
		if policyVersion != nil {
			r.AuthzPolicyVersion = *policyVersion
		}
		if lease != nil {
			v := int64(*lease)
			r.AuthzLeaseSeconds = &v
		}
		if watermarkJSON != nil {
			var wm apiruntime.VectorWatermark
			if err := json.Unmarshal(watermarkJSON, &wm); err != nil {
				return nil, err
			}
			r.AuthzWatermark = &wm
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ManagementWatermark 管理面向量水位（§1.1）：manual_seq 取
// api_authz_manual_revocation_seq 单行（无行 = 0——从未有手工撤销，如实零水位）；
// sources 取 api_authority_watermarks 逐来源 revocation_watermark（NG-AZ-01 已保证
// 只增），键为来源 UUID 字符串。sources 保证非 nil（空 map = 尚无权威来源水位）。
func (s *Store) ManagementWatermark(ctx context.Context) (apiruntime.VectorWatermark, error) {
	out := apiruntime.VectorWatermark{Sources: map[string]int64{}}
	err := s.db.QueryRow(ctx,
		`SELECT seq FROM api_authz_manual_revocation_seq WHERE id = 1`).Scan(&out.ManualSeq)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return apiruntime.VectorWatermark{}, err
	}
	rows, err := s.db.Query(ctx,
		`SELECT source_id, revocation_watermark FROM api_authority_watermarks`)
	if err != nil {
		return apiruntime.VectorWatermark{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var sourceID uuid.UUID
		var wm int64
		if err := rows.Scan(&sourceID, &wm); err != nil {
			return apiruntime.VectorWatermark{}, err
		}
		out.Sources[sourceID.String()] = wm
	}
	return out, rows.Err()
}
