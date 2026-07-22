package apiassets

import (
	"context"

	"github.com/google/uuid"
)

// Repository 端点资产仓储（SQL 与内存实现共用，便于诚实单测）。
type Repository interface {
	UpsertDiscovery(ctx context.Context, method, pathTemplate string, confidence float64, isAPI bool) (*Endpoint, error)
	List(ctx context.Context, status string, page, pageSize int) ([]Endpoint, int64, error)
	Confirm(ctx context.Context, id uuid.UUID) (*Endpoint, error)
	GetByID(ctx context.Context, id uuid.UUID) (*Endpoint, error)
}

// 确保 *Store 实现 Repository。
var _ Repository = (*Store)(nil)
