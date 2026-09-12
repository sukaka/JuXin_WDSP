// store.go api_grpc_descriptors 表读写（表由迁移 000076 建立）。
package apigrpcdesc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrDuplicateName 同名描述符集已存在（唯一索引冲突，409）。
var ErrDuplicateName = errors.New("grpc descriptor name already exists")

// ErrNotFound 描述符集不存在（删除目标缺失，404）。
var ErrNotFound = errors.New("grpc descriptor not found")

// MaxContentBytes 描述符集内容上限（1 MiB，与迁移 000076 检查约束一致；
// handler 侧 MaxBytesReader 同值拦截，超限 400）。
const MaxContentBytes = 1 << 20

// Descriptor 描述符集行（List 不携带 content 字节，避免列表页大字段传输）。
type Descriptor struct {
	ID          uuid.UUID        `json:"id"`
	Name        string           `json:"name"`
	SizeBytes   int              `json:"size_bytes"`
	ContentHash string           `json:"content_hash"`
	Services    []ServiceSummary `json:"services"`
	Status      string           `json:"status"`
	CreatedBy   string           `json:"created_by"`
	CreatedAt   time.Time        `json:"created_at"`
}

// Repository 描述符集仓储接口（pgx 实现见 Store；单测可注入内存 fake）。
type Repository interface {
	Create(ctx context.Context, name string, content []byte, createdBy string) (*Descriptor, error)
	List(ctx context.Context) ([]Descriptor, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

// Store api_grpc_descriptors pgx 实现。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建描述符集仓储。
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

var _ Repository = (*Store)(nil)

// Create 登记描述符集：sha256 内容哈希 + 服务摘要 + status=ENABLED 落库；
// 同名冲突返回 ErrDuplicateName（唯一索引兜底，非 TOCTOU 预查）。
func (s *Store) Create(ctx context.Context, name string, content []byte, createdBy string) (*Descriptor, error) {
	services, err := ParseFileDescriptorSet(content)
	if err != nil {
		return nil, err // ErrBadDescriptorSet 家族，handler 映射 400
	}
	sum := sha256.Sum256(content)
	svcJSON, err := json.Marshal(services)
	if err != nil {
		return nil, fmt.Errorf("marshal services summary: %w", err)
	}
	d := &Descriptor{
		Name:        name,
		SizeBytes:   len(content),
		ContentHash: hex.EncodeToString(sum[:]),
		Services:    services,
		Status:      "ENABLED",
		CreatedBy:   createdBy,
	}
	err = s.db.QueryRow(ctx, `
INSERT INTO api_grpc_descriptors (name, content, content_hash, services, created_by)
VALUES ($1, $2, $3, $4, NULLIF($5,''))
RETURNING id, created_at`,
		name, content, d.ContentHash, svcJSON, createdBy).Scan(&d.ID, &d.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
			return nil, ErrDuplicateName
		}
		return nil, fmt.Errorf("insert api_grpc_descriptors: %w", err)
	}
	return d, nil
}

// List 全量列出描述符集（不含 content 字节；按名称稳定排序；v1 量级小不分页，
// 单行 content 受 1MiB 约束，摘要与元数据体量可控）。
func (s *Store) List(ctx context.Context) ([]Descriptor, error) {
	rows, err := s.db.Query(ctx, `
SELECT id, name, octet_length(content), content_hash, services, status,
       COALESCE(created_by,''), created_at
FROM api_grpc_descriptors
ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list api_grpc_descriptors: %w", err)
	}
	defer rows.Close()
	out := []Descriptor{}
	for rows.Next() {
		var d Descriptor
		var svcRaw []byte
		if err := rows.Scan(&d.ID, &d.Name, &d.SizeBytes, &d.ContentHash, &svcRaw,
			&d.Status, &d.CreatedBy, &d.CreatedAt); err != nil {
			return nil, err
		}
		d.Services = []ServiceSummary{}
		if len(svcRaw) > 0 {
			if err := json.Unmarshal(svcRaw, &d.Services); err != nil {
				return nil, fmt.Errorf("decode services summary for %q: %w", d.Name, err)
			}
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Delete 按 id 删除（不存在返回 ErrNotFound，404）。
func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM api_grpc_descriptors WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete api_grpc_descriptors: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
