package apiassets

import (
	"context"

	"github.com/google/uuid"
)

// Repository 端点资产仓储（SQL 与内存实现共用，便于诚实单测）。
type Repository interface {
	// 发现与查询
	UpsertDiscovery(ctx context.Context, method, pathTemplate string, confidence float64, isAPI bool) (*Endpoint, error)
	List(ctx context.Context, f ListFilter) ([]Endpoint, int64, error)
	Confirm(ctx context.Context, id uuid.UUID) (*Endpoint, error)
	GetByID(ctx context.Context, id uuid.UUID) (*Endpoint, error)
	// 合并 / 拆分 / 状态
	Merge(ctx context.Context, primaryID, otherID uuid.UUID, actor string) (*Endpoint, error)
	Split(ctx context.Context, id uuid.UUID, newPaths []string, actor string) ([]Endpoint, error)
	SetAssetStatus(ctx context.Context, id uuid.UUID, status, actor string) (*Endpoint, error)
	// 业务维度扩展（api_assets）
	GetAsset(ctx context.Context, endpointID uuid.UUID) (*Asset, error)
	UpsertAsset(ctx context.Context, endpointID uuid.UUID, purpose, exposure, owner string, tags []string) (*Asset, error)
	// 分类与学习状态
	SetClassificationLocked(ctx context.Context, id uuid.UUID, locked bool) error
	SetLearningStatus(ctx context.Context, id uuid.UUID, status string) error
	AutoClassify(ctx context.Context, id uuid.UUID) ([]ClassificationDimension, error)
	// 学习任务
	StartLearning(ctx context.Context, endpointID uuid.UUID, createdBy *uuid.UUID) (*LearningJob, error)
	StopLearning(ctx context.Context, endpointID uuid.UUID, actor string) (*LearningJob, error)
	LearningStatus(ctx context.Context, endpointID uuid.UUID) (*LearningJob, SampleStats, error)
	// 生命周期事件与学习样本
	ListLifecycleEvents(ctx context.Context, endpointID uuid.UUID, page, pageSize int) ([]LifecycleEvent, int64, error)
	ListLearningSamples(ctx context.Context, endpointID uuid.UUID, accepted *bool, page, pageSize int) ([]LearningSample, int64, error)
}

// 确保 *Store 实现 Repository。
var _ Repository = (*Store)(nil)
