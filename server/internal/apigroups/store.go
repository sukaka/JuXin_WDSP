package apigroups

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository interface {
	Create(ctx context.Context, in CreateInput) (*Group, error)
	List(ctx context.Context, filter ListFilter) ([]Group, int64, error)
	Get(ctx context.Context, id uuid.UUID) (*Group, error)
	Update(ctx context.Context, id uuid.UUID, in UpdateInput) (*Group, error)
	Delete(ctx context.Context, id uuid.UUID) error
	ListEndpoints(ctx context.Context, groupID uuid.UUID, page, pageSize int) ([]Endpoint, int64, error)
	AddEndpoint(ctx context.Context, groupID, endpointID uuid.UUID) (*Member, error)
	RemoveEndpoint(ctx context.Context, groupID, endpointID uuid.UUID) error
}

type Store struct{ db *pgxpool.Pool }

func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

var _ Repository = (*Store)(nil)

const groupSelect = `
SELECT g.id, g.application_id, a.name, g.code, g.name, g.description, g.enabled,
       (SELECT count(*) FROM api_endpoint_group_members m WHERE m.group_id = g.id),
       g.created_at, g.updated_at
FROM api_endpoint_groups g
JOIN applications a ON a.id = g.application_id`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanGroup(row rowScanner) (*Group, error) {
	var g Group
	if err := row.Scan(&g.ID, &g.ApplicationID, &g.ApplicationName, &g.Code, &g.Name,
		&g.Description, &g.Enabled, &g.EndpointCount, &g.CreatedAt, &g.UpdatedAt); err != nil {
		return nil, err
	}
	return &g, nil
}

func (s *Store) Create(ctx context.Context, in CreateInput) (*Group, error) {
	if err := validateCreate(&in); err != nil {
		return nil, err
	}
	var id uuid.UUID
	err := s.db.QueryRow(ctx, `
INSERT INTO api_endpoint_groups (application_id, code, name, description, enabled)
SELECT a.id, $2, $3, $4, $5
FROM applications a
WHERE a.id = $1 AND a.deleted_at IS NULL
RETURNING id`, in.ApplicationID, in.Code, in.Name, in.Description, in.Enabled).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrApplicationNotFound
		}
		if mapped := mapGroupWriteError(err); mapped != nil {
			return nil, mapped
		}
		return nil, fmt.Errorf("insert api_endpoint_groups: %w", err)
	}
	return s.Get(ctx, id)
}

func (s *Store) List(ctx context.Context, filter ListFilter) ([]Group, int64, error) {
	filter.Page, filter.PageSize = normalizePage(filter.Page, filter.PageSize)
	where := ""
	args := []any{}
	if filter.ApplicationID != nil {
		where = ` WHERE g.application_id = $1`
		args = append(args, *filter.ApplicationID)
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM api_endpoint_groups g`+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count api_endpoint_groups: %w", err)
	}
	args = append(args, filter.PageSize, (filter.Page-1)*filter.PageSize)
	rows, err := s.db.Query(ctx, groupSelect+where+`
 ORDER BY g.created_at DESC, g.id DESC
 LIMIT $`+fmt.Sprint(len(args)-1)+` OFFSET $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list api_endpoint_groups: %w", err)
	}
	defer rows.Close()
	items := []Group{}
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan api_endpoint_groups: %w", err)
		}
		items = append(items, *g)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate api_endpoint_groups: %w", err)
	}
	return items, total, nil
}

func (s *Store) Get(ctx context.Context, id uuid.UUID) (*Group, error) {
	g, err := scanGroup(s.db.QueryRow(ctx, groupSelect+` WHERE g.id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get api_endpoint_groups: %w", err)
	}
	return g, nil
}

func (s *Store) Update(ctx context.Context, id uuid.UUID, in UpdateInput) (*Group, error) {
	if err := validateUpdate(&in); err != nil {
		return nil, err
	}
	tag, err := s.db.Exec(ctx, `
UPDATE api_endpoint_groups
SET code = $2, name = $3, description = $4, enabled = $5, updated_at = now()
WHERE id = $1`, id, in.Code, in.Name, in.Description, in.Enabled)
	if err != nil {
		if mapped := mapGroupWriteError(err); mapped != nil {
			return nil, mapped
		}
		return nil, fmt.Errorf("update api_endpoint_groups: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return s.Get(ctx, id)
}

func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM api_endpoint_groups WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete api_endpoint_groups: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ListEndpoints(ctx context.Context, groupID uuid.UUID, page, pageSize int) ([]Endpoint, int64, error) {
	page, pageSize = normalizePage(page, pageSize)
	var exists bool
	if err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM api_endpoint_groups WHERE id = $1)`, groupID).Scan(&exists); err != nil {
		return nil, 0, fmt.Errorf("check api_endpoint_groups: %w", err)
	}
	if !exists {
		return nil, 0, ErrNotFound
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM api_endpoint_group_members WHERE group_id = $1`, groupID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count api_endpoint_group_members: %w", err)
	}
	rows, err := s.db.Query(ctx, `
SELECT e.id, e.application_id, e.http_method, e.normalized_path, e.endpoint_key, e.asset_status, m.created_at
FROM api_endpoint_group_members m
JOIN api_endpoints e ON e.id = m.endpoint_id
WHERE m.group_id = $1
ORDER BY m.created_at DESC, e.id DESC
LIMIT $2 OFFSET $3`, groupID, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, fmt.Errorf("list api_endpoint_group_members: %w", err)
	}
	defer rows.Close()
	items := []Endpoint{}
	for rows.Next() {
		var e Endpoint
		if err := rows.Scan(&e.ID, &e.ApplicationID, &e.HTTPMethod, &e.NormalizedPath,
			&e.EndpointKey, &e.AssetStatus, &e.AddedAt); err != nil {
			return nil, 0, fmt.Errorf("scan api_endpoint_group_members: %w", err)
		}
		items = append(items, e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate api_endpoint_group_members: %w", err)
	}
	return items, total, nil
}

func (s *Store) AddEndpoint(ctx context.Context, groupID, endpointID uuid.UUID) (*Member, error) {
	if endpointID == uuid.Nil {
		return nil, invalidf("endpoint_id 必填")
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin add endpoint member: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var applicationID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT application_id FROM api_endpoint_groups WHERE id = $1 FOR UPDATE`, groupID).Scan(&applicationID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("lock api_endpoint_groups: %w", err)
	}
	var endpointApplicationID *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT application_id FROM api_endpoints WHERE id = $1 FOR UPDATE`, endpointID).Scan(&endpointApplicationID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrEndpointNotFound
		}
		return nil, fmt.Errorf("lock api_endpoints: %w", err)
	}
	if endpointApplicationID == nil || *endpointApplicationID != applicationID {
		return nil, ErrApplicationMismatch
	}
	member := &Member{GroupID: groupID, EndpointID: endpointID}
	if err := tx.QueryRow(ctx, `
INSERT INTO api_endpoint_group_members (group_id, endpoint_id)
VALUES ($1, $2)
RETURNING created_at`, groupID, endpointID).Scan(&member.CreatedAt); err != nil {
		if mapped := mapMemberWriteError(err); mapped != nil {
			return nil, mapped
		}
		return nil, fmt.Errorf("insert api_endpoint_group_members: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit add endpoint member: %w", err)
	}
	return member, nil
}

func (s *Store) RemoveEndpoint(ctx context.Context, groupID, endpointID uuid.UUID) error {
	tag, err := s.db.Exec(ctx, `
DELETE FROM api_endpoint_group_members
WHERE group_id = $1 AND endpoint_id = $2`, groupID, endpointID)
	if err != nil {
		return fmt.Errorf("delete api_endpoint_group_members: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrMemberNotFound
	}
	return nil
}

func mapGroupWriteError(err error) error {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return nil
	}
	switch pgErr.Code {
	case "23505":
		return ErrDuplicate
	case "23503":
		return ErrApplicationNotFound
	case "23514", "22001":
		return &ValidationError{message: "分组字段违反数据库约束"}
	}
	return nil
}

func mapMemberWriteError(err error) error {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return nil
	}
	switch pgErr.Code {
	case "23505":
		return ErrDuplicateMember
	case "23503":
		return ErrNotFound
	}
	return nil
}
