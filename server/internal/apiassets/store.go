// Package apiassets API 接口资产管理（发现、列表、确认、合并/拆分、学习与分类）。
package apiassets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	// ErrNotFound 接口不存在。
	ErrNotFound = errors.New("api endpoint not found")
	// ErrEndpointConflict 接口键已存在（拆分目标路径与现有接口冲突）。
	ErrEndpointConflict = errors.New("api endpoint already exists")
	// ErrLearningRunning 接口已有运行中的学习任务。
	ErrLearningRunning = errors.New("learning job already running")
	// ErrLearningNotRunning 接口没有运行中的学习任务。
	ErrLearningNotRunning = errors.New("no running learning job")
	// ErrInvalidSampleTarget 学习样本目标超出允许范围。
	ErrInvalidSampleTarget = errors.New("invalid sample target")
	// ErrClassificationLocked 接口分类已锁定，禁止自动分类覆盖。
	ErrClassificationLocked = errors.New("classification locked")
	// ErrLicenseQuotaExceeded 授权 API 端点配额超限：新发现端点拒绝落库
	// （采集链路捕获后告警，不重试；既有端点命中不受影响）。
	ErrLicenseQuotaExceeded = errors.New("api endpoint license quota exceeded")
)

// 资产状态白名单（asset_status）。
var validAssetStatuses = map[string]bool{
	"DISCOVERED": true,
	"CONFIRMED":  true,
	"IGNORED":    true,
	"DEPRECATED": true,
	"ZOMBIE":     true,
}

// 学习状态白名单（learning_status）。
var validLearningStatuses = map[string]bool{
	"NOT_STARTED": true,
	"LEARNING":    true,
	"PAUSED":      true,
	"LEARNED":     true,
}

// 业务类型白名单（business_type；WDSP AI 自动化渗透防护增强 阶段4，设计 #12.1 原文枚举，
// 应用层校验——与 exposure 同纪律不落 CHECK 约束，扩枚举不迁移）。
var validBusinessTypes = map[string]bool{
	"LOGIN": true, "REGISTER": true, "PASSWORD_RESET": true, "SMS": true, "EMAIL": true,
	"ORDER": true, "PAYMENT": true, "EXPORT": true, "DOWNLOAD": true, "SEARCH": true,
	"QUERY_PERSONAL_DATA": true, "AI_INFERENCE": true, "OTHER": true,
}

// NormalizeBusinessType 业务类型归一（大写去空白；空值归 OTHER）。
func NormalizeBusinessType(v string) string {
	v = strings.ToUpper(strings.TrimSpace(v))
	if v == "" {
		return "OTHER"
	}
	return v
}

// 学习样本目标（sample_target）取值域：缺省 100，允许 [10, 100000]。
const (
	DefaultSampleTarget = 100
	MinSampleTarget     = 10
	MaxSampleTarget     = 100000
)

// Endpoint API 接口（列名对齐迁移 000018 / 000020）。
type Endpoint struct {
	ID                    uuid.UUID  `json:"id"`
	ApplicationID         *uuid.UUID `json:"application_id,omitempty"`
	ApplicationName       string     `json:"application_name,omitempty"`   // 列表 LEFT JOIN applications 带出
	ApplicationDomain     string     `json:"application_domain,omitempty"` // 主域名（application_domains 主记录）
	DomainID              *uuid.UUID `json:"domain_id,omitempty"`
	ApplicationBindingID  *uuid.UUID `json:"application_binding_id,omitempty"`
	Host                  string     `json:"host,omitempty"`
	HTTPMethod            string     `json:"http_method"`
	NormalizedPath        string     `json:"normalized_path"`
	RawPathExample        string     `json:"raw_path_example"`
	DirectoryPath         string     `json:"directory_path"`
	EndpointKey           string     `json:"endpoint_key"`
	APIConfidence         float64    `json:"api_confidence"`
	AssetStatus           string     `json:"asset_status"`
	ProtocolType          string     `json:"protocol_type"`
	LearningStatus        string     `json:"learning_status"`
	CurrentModelVersionID *uuid.UUID `json:"current_model_version_id,omitempty"`
	ClassificationLocked  bool       `json:"classification_locked"`
	IsAPI                 bool       `json:"is_api"`
	HitCount              int64      `json:"hit_count"`
	FirstSeenAt           time.Time  `json:"first_seen_at"`
	LastSeenAt            time.Time  `json:"last_seen_at"`
	ConfirmedAt           *time.Time `json:"confirmed_at,omitempty"`
	// 生命周期增强（迁移 000045）：资产价值评分（未评分为空）与僵尸态起点。
	AssetValue        string          `json:"asset_value,omitempty"`
	AssetValueExplain json.RawMessage `json:"asset_value_explain,omitempty"`
	ZombieSince       *time.Time      `json:"zombie_since,omitempty"`
	// BusinessType 业务类型（api_assets.business_type，列表经 LEFT JOIN 带出；
	// 无资产记录时归一为 OTHER；设计 #12.1，迁移 000105）。
	BusinessType string `json:"business_type,omitempty"`
	// Asset 业务维度扩展（来自 api_assets，详情接口附带，无记录时为空）。
	Asset *Asset `json:"asset,omitempty"`
}

// Asset api_assets 业务维度归属。
type Asset struct {
	EndpointID         uuid.UUID `json:"endpoint_id"`
	Purpose            string    `json:"purpose"`
	Exposure           string    `json:"exposure"`
	DataClassification string    `json:"data_classification"`
	Owner              string    `json:"owner"`
	Tags               []string  `json:"tags"`
	BusinessType       string    `json:"business_type"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// ClassificationDimension 接口分类维度（api_classification_dimensions）。
type ClassificationDimension struct {
	EndpointID uuid.UUID `json:"endpoint_id"`
	Dimension  string    `json:"dimension"`
	Value      string    `json:"value"`
	Source     string    `json:"source"`
	Confidence float64   `json:"confidence"`
}

// LearningJob 学习任务（api_learning_jobs）。
type LearningJob struct {
	ID             uuid.UUID  `json:"id"`
	EndpointID     uuid.UUID  `json:"endpoint_id"`
	Status         string     `json:"status"`
	SampleTarget   int        `json:"sample_target"`
	CollectedCount int        `json:"collected_count"`
	ValidCount     int        `json:"valid_count"`
	ExcludedCount  int        `json:"excluded_count"`
	LastError      string     `json:"last_error,omitempty"`
	StartedAt      time.Time  `json:"started_at"`
	StoppedAt      *time.Time `json:"stopped_at,omitempty"`
	CreatedBy      *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// SampleStats 学习样本统计（api_learning_samples 聚合）。
type SampleStats struct {
	Total    int64 `json:"total"`
	Accepted int64 `json:"accepted"`
	Excluded int64 `json:"excluded"`
}

// LifecycleEvent 生命周期事件（api_lifecycle_events）。
type LifecycleEvent struct {
	ID         uuid.UUID `json:"id"`
	EndpointID uuid.UUID `json:"endpoint_id"`
	FromStatus string    `json:"from_status"`
	ToStatus   string    `json:"to_status"`
	Reason     string    `json:"reason"`
	Actor      string    `json:"actor"`
	CreatedAt  time.Time `json:"created_at"`
}

// LearningSample 学习样本（api_learning_samples；仅存样本哈希，不含完整敏感值）。
type LearningSample struct {
	ID                  uuid.UUID `json:"id"`
	EndpointID          uuid.UUID `json:"endpoint_id"`
	RequestID           string    `json:"request_id"`
	SampleHash          string    `json:"sample_hash"`
	SourceFingerprint   string    `json:"source_fingerprint"`
	IdentityFingerprint string    `json:"identity_fingerprint"`
	ResponseStatus      *int      `json:"response_status,omitempty"`
	Accepted            bool      `json:"accepted"`
	ExcludeReason       string    `json:"exclude_reason"`
	CollectedAt         time.Time `json:"collected_at"`
}

// ListFilter 接口列表过滤条件。
type ListFilter struct {
	AssetStatus     string
	LearningStatus  string
	Keyword         string
	ApplicationID   *uuid.UUID
	Unassigned      bool   // true 时仅查未归属接口（application_id IS NULL）
	DirectoryPrefix string // 目录前缀（含子目录）：/test 命中 /test 与 /test/php
	BusinessType    string // 业务类型过滤（api_assets.business_type；无资产记录接口按 OTHER 计）
	Page            int
	PageSize        int
}

// endpointColumns 接口全列（扫描顺序固定）。
const endpointColumns = `id, application_id, domain_id, application_binding_id, host, http_method, normalized_path, raw_path_example,
	endpoint_key, api_confidence, asset_status, protocol_type, learning_status,
	current_model_version_id, classification_locked, is_api, hit_count,
	first_seen_at, last_seen_at, confirmed_at, directory_path,
	asset_value, asset_value_explain, zombie_since`

// learningJobColumns 学习任务全列（扫描顺序固定）。
const learningJobColumns = `id, endpoint_id, status, sample_target, collected_count, valid_count,
	excluded_count, last_error, started_at, stopped_at, created_by, created_at`

// rowScanner 抽象 pgx.Row / pgx.Rows 的 Scan。
type rowScanner interface {
	Scan(dest ...any) error
}

// scanEndpoint 扫描端点行（extra 追加列目标，供 UpsertDiscovery 顺带取 inserted 标记）。
func scanEndpoint(rs rowScanner, extra ...any) (*Endpoint, error) {
	var e Endpoint
	// 000045 新增列可空：经中间变量转换（NULL → 零值）
	var assetValue *string
	var assetValueExplain []byte
	dests := []any{&e.ID, &e.ApplicationID, &e.DomainID, &e.ApplicationBindingID, &e.Host, &e.HTTPMethod, &e.NormalizedPath,
		&e.RawPathExample, &e.EndpointKey, &e.APIConfidence, &e.AssetStatus, &e.ProtocolType,
		&e.LearningStatus, &e.CurrentModelVersionID, &e.ClassificationLocked, &e.IsAPI,
		&e.HitCount, &e.FirstSeenAt, &e.LastSeenAt, &e.ConfirmedAt, &e.DirectoryPath,
		&assetValue, &assetValueExplain, &e.ZombieSince}
	dests = append(dests, extra...)
	err := rs.Scan(dests...)
	if err != nil {
		return nil, err
	}
	if assetValue != nil {
		e.AssetValue = *assetValue
	}
	if assetValueExplain != nil {
		e.AssetValueExplain = json.RawMessage(assetValueExplain)
	}
	return &e, nil
}

// DirectoryOf 目录派生：normalized_path 去掉最后一段（/test/php/login → /test/php；/users/{id} → /users）。
// 与迁移 000020 的 regexp_replace(path, '/[^/]*$', ”) 语义一致。
// protocolOrDefault 协议类型缺省回落（发现链路：空串归 REST 历史缺省值；与 UpsertDiscovery
// COALESCE 口径一致）。§9 词表扩展后网关上报 13 值（REST_JSON/JSON_RPC/…），存量 REST 行
// 不迁移改写，protocol_type 为 VARCHAR(32) 无 CHECK 约束，新值直接落库。
func protocolOrDefault(v string) string {
	if v == "" {
		return "REST"
	}
	return v
}

func DirectoryOf(normalizedPath string) string {
	i := strings.LastIndex(normalizedPath, "/")
	if i <= 0 {
		return ""
	}
	return normalizedPath[:i]
}

func scanLearningJob(rs rowScanner) (*LearningJob, error) {
	var j LearningJob
	err := rs.Scan(&j.ID, &j.EndpointID, &j.Status, &j.SampleTarget, &j.CollectedCount,
		&j.ValidCount, &j.ExcludedCount, &j.LastError, &j.StartedAt, &j.StoppedAt,
		&j.CreatedBy, &j.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &j, nil
}

// Store 仓储。
// db 为查询句柄（默认连接池，逐语句 autocommit）；pool 保留给自管理事务的方法
// （Merge/Split/生命周期迁移等 Begin 路径，pgx.Tx 无 Begin 不可经 db 抽象）。
// W22 采集器批次事务窗口内经 WithDB 浅拷贝把采集链路方法切到事务句柄（pool=nil），
// 该浅拷贝只允许调用采集链路方法（UpsertDiscovery/RecordLearningSample/
// RecordTrafficBucket），调 Begin 路径会因 pool 为 nil 直接 panic（快速失败，不静默）。
type Store struct {
	db   DBTX
	pool *pgxpool.Pool
	// endpointQuota 授权 API 端点配额提供者（装配层闭包读取 license 内存状态，无 IO；
	// nil 或返回 0 = 不限制）。WithDB 浅拷贝透传该字段（批次事务窗口内配额语义一致）。
	endpointQuota func(ctx context.Context) int64
}

// NewStore 创建。
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db, pool: db} }

// SetEndpointQuotaProvider 注入授权端点配额（0=不限制；仅发现链路 UpsertDiscovery 强制）。
func (s *Store) SetEndpointQuotaProvider(fn func(ctx context.Context) int64) *Store {
	s.endpointQuota = fn
	return s
}

// WithDB 返回绑定到给定句柄的浅拷贝（采集器批次事务化：句柄为该批次的 pgx.Tx）。
// 浅拷贝上采集链路方法不再自开事务，提交权归外层批次事务；失败由批次整体回滚，
// 断点不前移，重放由各 upsert/幂等键兜底（语义与 autocommit 路径一致）。
// 配额提供者随浅拷贝透传，批次事务窗口内发现配额强制语义与 autocommit 路径一致。
func (s *Store) WithDB(db DBTX) *Store { return &Store{db: db, endpointQuota: s.endpointQuota} }

// DiscoveryInput 发现/命中接口输入（采集器从网关事件解析后传入）。
type DiscoveryInput struct {
	Method        string
	PathTemplate  string
	Confidence    float64
	IsAPI         bool
	ApplicationID *uuid.UUID // 可为 nil（未归属）
	DomainID      *uuid.UUID // 可为 nil
	// ApplicationBindingID 是已验证的应用绑定作用域。
	ApplicationBindingID *uuid.UUID
	// ScopeKey 保留兼容旧调用方；它只用于内存仓储的临时作用域隔离。
	ScopeKey string
	// Host 是发现记录的归一化主机作用域。
	Host string
	// ProtocolType 协议类型（§9 词表：REST_JSON/REST_XML/FORM_API/SOAP/GRAPHQL/JSON_RPC/
	// XML_RPC/WEBHOOK/FILE_UPLOAD/FILE_DOWNLOAD/WEBSOCKET_HANDSHAKE/SERVER_SENT_EVENTS/
	// UNKNOWN_HTTP_API，另含历史值 REST/GRPC；空串回落 REST）。
	// 仅首次发现写入，命中时不覆盖（允许后续人工修正）。
	ProtocolType string
}

// UpsertDiscovery 发现/命中接口（按应用、域名、绑定、Host、协议和 runtime endpoint_key 作用域幂等）。
// application_id / domain_id / directory_path 仅首次发现写入；命中时不覆盖（允许后续人工改属）。
// 首插（xmax = 0 判插入，命中走 DO UPDATE）同事务派生 api_endpoint_path_segments
// 段形——normalized_path 不可变，命中重放不重写段形（一致性方案见 segments.go）。
// WithDB 浅拷贝（pool==nil，采集器批次事务窗口）时不再自开事务：写入并入外层
// 批次事务，段形原子性由批次事务 + 采集端记录级 SAVEPOINT 保证。
func (s *Store) UpsertDiscovery(ctx context.Context, in DiscoveryInput) (*Endpoint, error) {
	if s.pool == nil {
		return s.upsertDiscovery(ctx, s.db, in)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	e, err := s.upsertDiscovery(ctx, tx, in)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return e, nil
}

// upsertDiscovery 在给定句柄上执行发现 upsert 与段形派生（事务边界由调用方负责）。
func (s *Store) upsertDiscovery(ctx context.Context, q DBTX, in DiscoveryInput) (*Endpoint, error) {
	method := strings.ToUpper(strings.TrimSpace(in.Method))
	pathTemplate := strings.TrimSpace(in.PathTemplate)
	if method == "" || pathTemplate == "" {
		return nil, fmt.Errorf("method and path_template required")
	}
	key := discoveryEndpointKey(method, pathTemplate, in.Host, in.ScopeKey, in.ApplicationID, in.DomainID, in.ProtocolType)
	host := normalizeDiscoveryHost(in.Host)
	protocol := protocolOrDefault(strings.ToUpper(strings.TrimSpace(in.ProtocolType)))
	var inserted bool
	e, err := scanEndpoint(q.QueryRow(ctx, `
INSERT INTO api_endpoints (application_id, domain_id, application_binding_id, host,
  http_method, normalized_path, raw_path_example, directory_path, endpoint_key,
  api_confidence, is_api, hit_count, asset_status, protocol_type)
VALUES ($1,$2,$3,$4,$5,$6,$6,$7,$8,$9,$10,1,'DISCOVERED',$11)
ON CONFLICT (application_id, domain_id, application_binding_id, host, endpoint_key, protocol_type) DO UPDATE SET
  hit_count = api_endpoints.hit_count + 1,
  last_seen_at = now(),
  api_confidence = GREATEST(api_endpoints.api_confidence, EXCLUDED.api_confidence),
  updated_at = now()
RETURNING `+endpointColumns+`, (xmax = 0) AS inserted`,
		in.ApplicationID, in.DomainID, in.ApplicationBindingID, host, method, pathTemplate,
		DirectoryOf(pathTemplate), key, in.Confidence, in.IsAPI, protocol,
	), &inserted)
	if err != nil {
		return nil, err
	}
	if inserted {
		// 授权端点配额强制（0=不限制）：插入后总数 > 配额 ⟺ 插入前已达上限，
		// 同一事务句柄删回本行并返回哨兵——autocommit 路径外层事务随错误回滚、
		// 批次事务路径显式删除生效，两路径语义一致（新端点不落库）；
		// 命中既有端点（inserted=false）不受配额影响，与「已有端点不受影响」口径一致。
		if s.endpointQuota != nil {
			if quota := s.endpointQuota(ctx); quota > 0 {
				var total int64
				if err := q.QueryRow(ctx, `SELECT count(*) FROM api_endpoints`).Scan(&total); err != nil {
					return nil, err
				}
				if total > quota {
					if _, err := q.Exec(ctx, `DELETE FROM api_endpoints WHERE id = $1`, e.ID); err != nil {
						return nil, err
					}
					return nil, ErrLicenseQuotaExceeded
				}
			}
		}
		if err := upsertPathSegments(ctx, q, e.ID, pathTemplate); err != nil {
			return nil, err
		}
	}
	return e, nil
}

// Count 端点总数（全表计数不受生命周期状态影响；授权配额强制与授权状态页配额用量展示共用口径）。
func (s *Store) Count(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRow(ctx, `SELECT count(*) FROM api_endpoints`).Scan(&n)
	return n, err
}

// List 分页列表（asset_status / learning_status / keyword / application_id / unassigned / directory 过滤）。
// 应用名经 LEFT JOIN applications 带出（未归属为空字符串）。
func (s *Store) List(ctx context.Context, f ListFilter) ([]Endpoint, int64, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 || f.PageSize > 100 {
		f.PageSize = 20
	}
	where := "1=1"
	args := []any{}
	add := func(cond string, v any) {
		args = append(args, v)
		where += fmt.Sprintf(" AND "+cond, len(args))
	}
	if f.AssetStatus != "" {
		add("e.asset_status = $%d", f.AssetStatus)
	}
	if f.LearningStatus != "" {
		add("e.learning_status = $%d", f.LearningStatus)
	}
	if f.Keyword != "" {
		add("e.normalized_path ILIKE $%d", "%"+f.Keyword+"%")
	}
	if f.ApplicationID != nil {
		add("e.application_id = $%d", *f.ApplicationID)
	}
	if f.Unassigned {
		where += " AND e.application_id IS NULL"
	}
	if f.DirectoryPrefix != "" {
		args = append(args, f.DirectoryPrefix, f.DirectoryPrefix+"/%")
		where += fmt.Sprintf(" AND (e.directory_path = $%d OR e.directory_path LIKE $%d)", len(args)-1, len(args))
	}
	if f.BusinessType != "" {
		add("COALESCE(ast.business_type,'OTHER') = $%d", f.BusinessType)
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM api_endpoints e
LEFT JOIN api_assets ast ON ast.endpoint_id = e.id WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	cols := "e." + strings.ReplaceAll(endpointColumns, ", ", ", e.")
	q := fmt.Sprintf(`
SELECT %s, COALESCE(a.name,''),
  COALESCE((SELECT d.hostname FROM application_domains d
    WHERE d.application_id = a.id ORDER BY d.is_primary DESC, d.created_at LIMIT 1), ''),
  COALESCE(ast.business_type,'OTHER')
FROM api_endpoints e
LEFT JOIN applications a ON a.id = e.application_id
LEFT JOIN api_assets ast ON ast.endpoint_id = e.id
WHERE %s ORDER BY e.last_seen_at DESC LIMIT $%d OFFSET $%d`,
		cols, where, len(args)-1, len(args))
	rows, err := s.db.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Endpoint{}
	for rows.Next() {
		e := Endpoint{}
		// 000045 新增列可空：经中间变量转换（NULL → 零值）
		var assetValue *string
		var assetValueExplain []byte
		if err := rows.Scan(&e.ID, &e.ApplicationID, &e.DomainID, &e.ApplicationBindingID, &e.Host, &e.HTTPMethod, &e.NormalizedPath,
			&e.RawPathExample, &e.EndpointKey, &e.APIConfidence, &e.AssetStatus, &e.ProtocolType,
			&e.LearningStatus, &e.CurrentModelVersionID, &e.ClassificationLocked, &e.IsAPI,
			&e.HitCount, &e.FirstSeenAt, &e.LastSeenAt, &e.ConfirmedAt, &e.DirectoryPath,
			&assetValue, &assetValueExplain, &e.ZombieSince,
			&e.ApplicationName, &e.ApplicationDomain, &e.BusinessType); err != nil {
			return nil, 0, err
		}
		if assetValue != nil {
			e.AssetValue = *assetValue
		}
		if assetValueExplain != nil {
			e.AssetValueExplain = json.RawMessage(assetValueExplain)
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// SiteSummaryItem 站点接口计数（站点列表角标）。
type SiteSummaryItem struct {
	ApplicationID     *uuid.UUID `json:"application_id,omitempty"`
	ApplicationName   string     `json:"application_name"`
	ApplicationDomain string     `json:"application_domain"` // 主域名，前端优先展示
	EndpointCount     int64      `json:"endpoint_count"`
}

// SiteSummary 各站点接口计数（含未归属桶）。
func (s *Store) SiteSummary(ctx context.Context) ([]SiteSummaryItem, int64, error) {
	rows, err := s.db.Query(ctx, `
SELECT a.id, a.name,
  COALESCE((SELECT d.hostname FROM application_domains d
    WHERE d.application_id = a.id ORDER BY d.is_primary DESC, d.created_at LIMIT 1), ''),
  count(e.id)
FROM applications a
LEFT JOIN api_endpoints e ON e.application_id = a.id
GROUP BY a.id, a.name ORDER BY a.name`)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []SiteSummaryItem{}
	for rows.Next() {
		var it SiteSummaryItem
		if err := rows.Scan(&it.ApplicationID, &it.ApplicationName, &it.ApplicationDomain, &it.EndpointCount); err != nil {
			return nil, 0, err
		}
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	var unassigned int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM api_endpoints WHERE application_id IS NULL`).Scan(&unassigned); err != nil {
		return nil, 0, err
	}
	return out, unassigned, nil
}

// DirectoryCount 目录接口计数（目录树节点，扁平返回由前端组装层级）。
type DirectoryCount struct {
	DirectoryPath string `json:"directory_path"`
	EndpointCount int64  `json:"endpoint_count"`
}

// DirectoryTree 按目录聚合接口计数（application_id 指定站点；unassigned=true 查未归属）。
func (s *Store) DirectoryTree(ctx context.Context, applicationID *uuid.UUID, unassigned bool) ([]DirectoryCount, error) {
	where := "1=1"
	args := []any{}
	if applicationID != nil {
		args = append(args, *applicationID)
		where = "application_id = $1"
	} else if unassigned {
		where = "application_id IS NULL"
	}
	rows, err := s.db.Query(ctx, `
SELECT directory_path, count(*) FROM api_endpoints
WHERE `+where+` GROUP BY directory_path ORDER BY directory_path`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DirectoryCount{}
	for rows.Next() {
		var dc DirectoryCount
		if err := rows.Scan(&dc.DirectoryPath, &dc.EndpointCount); err != nil {
			return nil, err
		}
		out = append(out, dc)
	}
	return out, rows.Err()
}

// ListKeyStatus 返回全部接口的 endpoint_key → asset_status 映射（发布通道下发网关，生命周期检测基线）。
func (s *Store) ListKeyStatus(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.Query(ctx, `SELECT endpoint_key, asset_status FROM api_endpoints`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var key, status string
		if err := rows.Scan(&key, &status); err != nil {
			return nil, err
		}
		out[key] = status
	}
	return out, rows.Err()
}

// Confirm 人工确认接口（asset_status=CONFIRMED）。
func (s *Store) Confirm(ctx context.Context, id uuid.UUID) (*Endpoint, error) {
	e, err := scanEndpoint(s.db.QueryRow(ctx, `
UPDATE api_endpoints SET asset_status='CONFIRMED', confirmed_at=now(), updated_at=now()
WHERE id=$1
RETURNING `+endpointColumns, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return e, err
}

// GetByID 查询。
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*Endpoint, error) {
	e, err := scanEndpoint(s.db.QueryRow(ctx, `SELECT `+endpointColumns+` FROM api_endpoints WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return e, err
}

// Merge 把 other 接口并入 primary：命中数累加、other 历史接口键归档进
// api_endpoint_aliases、删除 other、写生命周期 MERGED（事务）。
func (s *Store) Merge(ctx context.Context, primaryID, otherID uuid.UUID, actor string) (*Endpoint, error) {
	if primaryID == otherID {
		return nil, fmt.Errorf("不能将接口合并到自身")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 单语句按固定扫描顺序锁定两接口，避免并发合并相互死锁
	type mergeRow struct {
		key      string
		hits     int64
		lastSeen time.Time
	}
	locked := map[uuid.UUID]mergeRow{}
	rows, err := tx.Query(ctx, `
SELECT id, endpoint_key, hit_count, last_seen_at FROM api_endpoints
WHERE id IN ($1,$2) FOR UPDATE`, primaryID, otherID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id uuid.UUID
		var r mergeRow
		if err := rows.Scan(&id, &r.key, &r.hits, &r.lastSeen); err != nil {
			rows.Close()
			return nil, err
		}
		locked[id] = r
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(locked) != 2 {
		return nil, ErrNotFound
	}
	other := locked[otherID]

	// other 的历史接口键归档到 primary（重复归档幂等）
	if _, err = tx.Exec(ctx, `
INSERT INTO api_endpoint_aliases (endpoint_id, alias_key, created_reason)
VALUES ($1,$2,'merge')
ON CONFLICT (alias_key) DO NOTHING`, primaryID, other.key); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `
UPDATE api_endpoints SET hit_count = hit_count + $2,
  last_seen_at = GREATEST(last_seen_at, $3), updated_at = now()
WHERE id = $1`, primaryID, other.hits, other.lastSeen); err != nil {
		return nil, err
	}
	// 删除对方端点行：段形/扩展表随 ON DELETE CASCADE 清理（见 segments.go 一致性说明）
	if _, err = tx.Exec(ctx, `DELETE FROM api_endpoints WHERE id = $1`, otherID); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `
INSERT INTO api_lifecycle_events (endpoint_id, from_status, to_status, reason, actor)
VALUES ($1,'','MERGED',$2,$3)`,
		primaryID, fmt.Sprintf("合并接口 %s（%s）", otherID, other.key), actor); err != nil {
		return nil, err
	}
	merged, err := scanEndpoint(tx.QueryRow(ctx, `SELECT `+endpointColumns+` FROM api_endpoints WHERE id=$1`, primaryID))
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return merged, nil
}

// Split 按给定归一化路径从 id 接口拆分出新接口（继承 http_method/api_confidence
// 等身份属性，asset_status=DISCOVERED），原接口写生命周期 SPLIT（事务）。
func (s *Store) Split(ctx context.Context, id uuid.UUID, newPaths []string, actor string) ([]Endpoint, error) {
	if len(newPaths) == 0 {
		return nil, fmt.Errorf("拆分路径不能为空")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	src, err := scanEndpoint(tx.QueryRow(ctx, `SELECT `+endpointColumns+` FROM api_endpoints WHERE id=$1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	created := []Endpoint{}
	for _, p := range newPaths {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, fmt.Errorf("拆分路径不能为空")
		}
		key := discoveryEndpointKey(src.HTTPMethod, p, src.Host, "", src.ApplicationID, src.DomainID, src.ProtocolType)
		e, err := scanEndpoint(tx.QueryRow(ctx, `
INSERT INTO api_endpoints (application_id, domain_id, application_binding_id, host,
  http_method, normalized_path, raw_path_example, directory_path, endpoint_key,
  api_confidence, asset_status, protocol_type, is_api)
VALUES ($1,$2,$3,$4,$5,$6,$6,$7,$8,$9,'DISCOVERED',$10,$11)
ON CONFLICT (application_id, domain_id, application_binding_id, host, endpoint_key, protocol_type) DO NOTHING
RETURNING `+endpointColumns,
			src.ApplicationID, src.DomainID, src.ApplicationBindingID, normalizeDiscoveryHost(src.Host), src.HTTPMethod, p,
			DirectoryOf(p), key, src.APIConfidence, protocolOrDefault(strings.ToUpper(strings.TrimSpace(src.ProtocolType))), src.IsAPI))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ErrEndpointConflict, key)
		}
		if err != nil {
			return nil, err
		}
		// 新端点行同事务派生段形（与发现链路同口径，见 segments.go）
		if err := upsertPathSegments(ctx, tx, e.ID, p); err != nil {
			return nil, err
		}
		created = append(created, *e)
	}
	if _, err = tx.Exec(ctx, `
INSERT INTO api_lifecycle_events (endpoint_id, from_status, to_status, reason, actor)
VALUES ($1,'','SPLIT',$2,$3)`,
		id, fmt.Sprintf("拆分出 %d 个接口：%s", len(created), strings.Join(newPaths, ", ")), actor); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return created, nil
}

// SetAssetStatus 变更资产状态（忽略/恢复等），写生命周期事件（事务）。
func (s *Store) SetAssetStatus(ctx context.Context, id uuid.UUID, status, actor string) (*Endpoint, error) {
	status = strings.ToUpper(strings.TrimSpace(status))
	if !validAssetStatuses[status] {
		return nil, fmt.Errorf("无效的资产状态：%s", status)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var from string
	err = tx.QueryRow(ctx, `SELECT asset_status FROM api_endpoints WHERE id=$1 FOR UPDATE`, id).Scan(&from)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	e, err := scanEndpoint(tx.QueryRow(ctx, `
UPDATE api_endpoints SET asset_status=$2,
  zombie_since = CASE WHEN $3 = 'ZOMBIE' THEN zombie_since ELSE NULL END,
  updated_at=now()
WHERE id=$1
RETURNING `+endpointColumns, id, status, status))
	if err != nil {
		return nil, err
	}
	if from != status {
		if _, err = tx.Exec(ctx, `
INSERT INTO api_lifecycle_events (endpoint_id, from_status, to_status, reason, actor)
VALUES ($1,$2,$3,'资产状态变更',$4)`, id, from, status, actor); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return e, nil
}

// GetAsset 读取接口业务维度扩展；无记录返回 (nil, nil)。
func (s *Store) GetAsset(ctx context.Context, endpointID uuid.UUID) (*Asset, error) {
	var a Asset
	var tags []byte
	err := s.db.QueryRow(ctx, `
SELECT endpoint_id, purpose, exposure, data_classification, owner, tags, business_type, created_at, updated_at
FROM api_assets WHERE endpoint_id=$1`, endpointID).Scan(
		&a.EndpointID, &a.Purpose, &a.Exposure, &a.DataClassification, &a.Owner, &tags, &a.BusinessType, &a.CreatedAt, &a.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a.Tags = []string{}
	if err := json.Unmarshal(tags, &a.Tags); err != nil {
		return nil, fmt.Errorf("解析资产标签失败：%w", err)
	}
	return &a, nil
}

// UpsertAsset 按接口 upsert 业务维度扩展（purpose/exposure/owner/tags/business_type 全量替换；
// business_type 空值归一为 OTHER，枚举校验见 handler 层与 NormalizeBusinessType）。
func (s *Store) UpsertAsset(ctx context.Context, endpointID uuid.UUID, purpose, exposure, owner string, tags []string, businessType string) (*Asset, error) {
	exposure = strings.ToUpper(strings.TrimSpace(exposure))
	if exposure == "" {
		exposure = "INTERNAL"
	}
	businessType = NormalizeBusinessType(businessType)
	if !validBusinessTypes[businessType] {
		return nil, fmt.Errorf("无效的业务类型：%s", businessType)
	}
	if tags == nil {
		tags = []string{}
	}
	tagsJSON, err := json.Marshal(tags)
	if err != nil {
		return nil, fmt.Errorf("序列化资产标签失败：%w", err)
	}
	var a Asset
	var tagsRaw []byte
	err = s.db.QueryRow(ctx, `
INSERT INTO api_assets (endpoint_id, purpose, exposure, owner, tags, business_type)
VALUES ($1,$2,$3,$4,$5::jsonb,$6)
ON CONFLICT (endpoint_id) DO UPDATE SET
  purpose = EXCLUDED.purpose, exposure = EXCLUDED.exposure,
  owner = EXCLUDED.owner, tags = EXCLUDED.tags, business_type = EXCLUDED.business_type,
  updated_at = now()
RETURNING endpoint_id, purpose, exposure, data_classification, owner, tags, business_type, created_at, updated_at`,
		endpointID, purpose, exposure, owner, string(tagsJSON), businessType).Scan(
		&a.EndpointID, &a.Purpose, &a.Exposure, &a.DataClassification, &a.Owner, &tagsRaw, &a.BusinessType, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	a.Tags = []string{}
	if err := json.Unmarshal(tagsRaw, &a.Tags); err != nil {
		return nil, fmt.Errorf("解析资产标签失败：%w", err)
	}
	return &a, nil
}

// SetClassificationLocked 设置分类锁定标记。
func (s *Store) SetClassificationLocked(ctx context.Context, id uuid.UUID, locked bool) error {
	tag, err := s.db.Exec(ctx, `
UPDATE api_endpoints SET classification_locked=$2, updated_at=now() WHERE id=$1`, id, locked)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetLearningStatus 更新学习状态（NOT_STARTED/LEARNING/PAUSED/LEARNED）。
func (s *Store) SetLearningStatus(ctx context.Context, id uuid.UUID, status string) error {
	status = strings.ToUpper(strings.TrimSpace(status))
	if !validLearningStatuses[status] {
		return fmt.Errorf("无效的学习状态：%s", status)
	}
	tag, err := s.db.Exec(ctx, `
UPDATE api_endpoints SET learning_status=$2, updated_at=now() WHERE id=$1`, id, status)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// AutoClassify 按路径/方法启发式自动分类，写 api_classification_dimensions（source=AUTO）。
// 维度：PURPOSE/EXPOSURE/ACCESS/ACTION 恒产出，BUSINESS_DOMAIN 仅领域关键词置信达标时产出。
// 接口分类已锁定时返回 ErrClassificationLocked（事务）。
func (s *Store) AutoClassify(ctx context.Context, id uuid.UUID) ([]ClassificationDimension, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	e, err := scanEndpoint(tx.QueryRow(ctx, `SELECT `+endpointColumns+` FROM api_endpoints WHERE id=$1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if e.ClassificationLocked {
		return nil, ErrClassificationLocked
	}
	dims := classifyByPath(e.HTTPMethod, e.NormalizedPath)
	for i := range dims {
		dims[i].EndpointID = id
		if _, err = tx.Exec(ctx, `
INSERT INTO api_classification_dimensions (endpoint_id, dimension, value, source, confidence)
VALUES ($1,$2,$3,'AUTO',$4)
ON CONFLICT (endpoint_id, dimension) DO UPDATE SET
  value = EXCLUDED.value, source = 'AUTO', confidence = EXCLUDED.confidence, updated_at = now()`,
			id, dims[i].Dimension, dims[i].Value, dims[i].Confidence); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return dims, nil
}

// StartLearning 创建 RUNNING 学习任务并置接口 learning_status=LEARNING；
// 已有 RUNNING 任务时返回 ErrLearningRunning（事务）。
// sampleTarget 为样本目标：0 取缺省 DefaultSampleTarget；越界返回 ErrInvalidSampleTarget。
func (s *Store) StartLearning(ctx context.Context, endpointID uuid.UUID, sampleTarget int, createdBy *uuid.UUID) (*LearningJob, error) {
	if sampleTarget == 0 {
		sampleTarget = DefaultSampleTarget
	}
	if sampleTarget < MinSampleTarget || sampleTarget > MaxSampleTarget {
		return nil, ErrInvalidSampleTarget
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 学习启停互斥：锁定接口行防并发双开；不存在则返回 ErrNotFound
	var one int
	err = tx.QueryRow(ctx, `SELECT 1 FROM api_endpoints WHERE id=$1 FOR UPDATE`, endpointID).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var running bool
	if err = tx.QueryRow(ctx, `
SELECT EXISTS(SELECT 1 FROM api_learning_jobs WHERE endpoint_id=$1 AND status='RUNNING')`, endpointID).Scan(&running); err != nil {
		return nil, err
	}
	if running {
		return nil, ErrLearningRunning
	}
	job, err := scanLearningJob(tx.QueryRow(ctx, `
INSERT INTO api_learning_jobs (endpoint_id, status, sample_target, created_by)
VALUES ($1,'RUNNING',$2,$3)
RETURNING `+learningJobColumns, endpointID, sampleTarget, createdBy))
	if err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `
UPDATE api_endpoints SET learning_status='LEARNING', updated_at=now() WHERE id=$1`, endpointID); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return job, nil
}

// StopLearning 停止运行中的学习任务（置 STOPPED），接口 learning_status=PAUSED；
// 无 RUNNING 任务时返回 ErrLearningNotRunning（事务）。
func (s *Store) StopLearning(ctx context.Context, endpointID uuid.UUID, actor string) (*LearningJob, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 锁定接口行，与 StartLearning 互斥；不存在则返回 ErrNotFound
	var one int
	err = tx.QueryRow(ctx, `SELECT 1 FROM api_endpoints WHERE id=$1 FOR UPDATE`, endpointID).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	job, err := scanLearningJob(tx.QueryRow(ctx, `
UPDATE api_learning_jobs SET status='STOPPED', stopped_at=now()
WHERE endpoint_id=$1 AND status='RUNNING'
RETURNING `+learningJobColumns, endpointID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrLearningNotRunning
	}
	if err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `
UPDATE api_endpoints SET learning_status='PAUSED', updated_at=now() WHERE id=$1`, endpointID); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `
INSERT INTO api_lifecycle_events (endpoint_id, from_status, to_status, reason, actor)
VALUES ($1,'LEARNING','PAUSED','停止学习',$2)`, endpointID, actor); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return job, nil
}

// LearningStatus 返回最近一次学习任务与样本统计；从未学习时 job 为 nil。
func (s *Store) LearningStatus(ctx context.Context, endpointID uuid.UUID) (*LearningJob, SampleStats, error) {
	var stats SampleStats
	if err := s.db.QueryRow(ctx, `
SELECT count(*),
  count(*) FILTER (WHERE accepted),
  count(*) FILTER (WHERE NOT accepted)
FROM api_learning_samples WHERE api_endpoint_id=$1`, endpointID).Scan(
		&stats.Total, &stats.Accepted, &stats.Excluded); err != nil {
		return nil, stats, err
	}
	job, err := scanLearningJob(s.db.QueryRow(ctx, `
SELECT `+learningJobColumns+` FROM api_learning_jobs
WHERE endpoint_id=$1 ORDER BY started_at DESC, id DESC LIMIT 1`, endpointID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, stats, nil
	}
	if err != nil {
		return nil, stats, err
	}
	return job, stats, nil
}

// ListLifecycleEvents 接口生命周期事件分页列表（created_at DESC）。
func (s *Store) ListLifecycleEvents(ctx context.Context, endpointID uuid.UUID, page, pageSize int) ([]LifecycleEvent, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	var total int64
	if err := s.db.QueryRow(ctx,
		`SELECT count(*) FROM api_lifecycle_events WHERE endpoint_id=$1`, endpointID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(ctx, `
SELECT id, endpoint_id, from_status, to_status, reason, actor, created_at
FROM api_lifecycle_events WHERE endpoint_id=$1 ORDER BY created_at DESC, id LIMIT $2 OFFSET $3`,
		endpointID, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []LifecycleEvent{}
	for rows.Next() {
		var ev LifecycleEvent
		if err := rows.Scan(&ev.ID, &ev.EndpointID, &ev.FromStatus, &ev.ToStatus,
			&ev.Reason, &ev.Actor, &ev.CreatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, ev)
	}
	return out, total, rows.Err()
}

// ListLearningSamples 接口学习样本分页列表（accepted 可空过滤，collected_at DESC）。
func (s *Store) ListLearningSamples(ctx context.Context, endpointID uuid.UUID, accepted *bool, page, pageSize int) ([]LearningSample, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	where := "api_endpoint_id=$1"
	args := []any{endpointID}
	if accepted != nil {
		args = append(args, *accepted)
		where += fmt.Sprintf(" AND accepted=$%d", len(args))
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM api_learning_samples WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, fmt.Sprintf(`
SELECT id, api_endpoint_id, request_id, sample_hash, source_fingerprint, identity_fingerprint,
  response_status, accepted, exclude_reason, collected_at
FROM api_learning_samples WHERE %s ORDER BY collected_at DESC, id LIMIT $%d OFFSET $%d`,
		where, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []LearningSample{}
	for rows.Next() {
		var sm LearningSample
		if err := rows.Scan(&sm.ID, &sm.EndpointID, &sm.RequestID, &sm.SampleHash,
			&sm.SourceFingerprint, &sm.IdentityFingerprint, &sm.ResponseStatus,
			&sm.Accepted, &sm.ExcludeReason, &sm.CollectedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, sm)
	}
	return out, total, rows.Err()
}
