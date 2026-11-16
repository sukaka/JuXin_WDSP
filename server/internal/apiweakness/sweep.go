// sweep.go 弱点派生扫描（SweepOnce 供集成方挂到现有周期任务）。
//
// v1 派生规则（数据源 api_runtime_events / api_runtime_findings，全部端点级）：
//
//	UNAUTHENTICATED_SENSITIVE_API  端点近 24h 匿名（auth_type 为空）且命中 sensitive 检测器的事件达样本量
//	DEPRECATED_STILL_CALLED        近 24h 存在 lifecycle.deprecated_api_call 命中
//	SENSITIVE_IN_QUERY             近 24h 存在 sensitive.in_query 命中
//	SENSITIVE_RESPONSE_UNMASKED    近 24h 响应涉敏且未观察到成功脱敏的事件达样本量
//	SCHEMA_DRIFT_PERSISTENT        同端点 SCHEMA% 类 finding 首现 ≥3 天且近 24h 仍在出现
//
// 写入语义（Repository.UpsertDerived）：同端点同 weakness_code 已存在则
// trigger_count+1、刷新 last_seen 与证据；原 FIXED 状态自动回 REPRODUCED。
// 证据只存脱敏摘要（规则/计数/窗口/时间/端点），不落任何原始请求数据。
// 空表安全：各规则查询零命中即零产出，不产生错误。
package apiweakness

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 默认派生参数。
const (
	defaultSweepWindow    = 24 * time.Hour // 近窗口
	defaultMinSamples     = 3              // 未认证敏感接口与响应未脱敏样本量阈值
	defaultSchemaPersistD = 3              // Schema 漂移持续天数阈值
)

// SweepOptions 派生扫描参数（零值字段取默认）。
type SweepOptions struct {
	Window            time.Duration // 近窗口（默认 24h）
	MinSamples        int           // 未认证敏感接口与响应未脱敏样本量阈值（默认 3）
	SchemaPersistDays int           // SCHEMA_DRIFT_PERSISTENT 持续天数阈值（默认 3）
}

func (o SweepOptions) withDefaults() SweepOptions {
	out := o
	if out.Window <= 0 {
		out.Window = defaultSweepWindow
	}
	if out.MinSamples <= 0 {
		out.MinSamples = defaultMinSamples
	}
	if out.SchemaPersistDays <= 0 {
		out.SchemaPersistDays = defaultSchemaPersistD
	}
	return out
}

// EndpointSignal 一条端点级派生信号（仅计数摘要）。
type EndpointSignal struct {
	EndpointID  uuid.UUID
	EndpointKey string
	Hits        int
	FirstSeen   time.Time
	LastSeen    time.Time
}

// SignalSource 运行时信号读取（PG 实现见 pgSignalSource；单测注入 fake）。
type SignalSource interface {
	// 匿名且命中 sensitive 检测器的事件按端点聚合（达 minSamples 样本量）
	UnauthenticatedSensitive(ctx context.Context, since time.Time, minSamples int) ([]EndpointSignal, error)
	// lifecycle.deprecated_api_call 命中按端点聚合
	DeprecatedCalls(ctx context.Context, since time.Time) ([]EndpointSignal, error)
	// sensitive.in_query 命中按端点聚合
	SensitiveInQuery(ctx context.Context, since time.Time) ([]EndpointSignal, error)
	// credential.url_password 命中按端点聚合
	CredentialInURL(ctx context.Context, since time.Time) ([]EndpointSignal, error)
	// credential.cookie_sensitive 命中按端点聚合
	SensitiveCookie(ctx context.Context, since time.Time) ([]EndpointSignal, error)
	// server.version_disclosure / server.error_disclosure 命中按端点聚合
	ServerInfoDisclosure(ctx context.Context, since time.Time) ([]EndpointSignal, error)
	// resource.object_enumeration 命中按端点聚合（仅可信身份时间窗信号）
	ObjectEnumeration(ctx context.Context, since time.Time) ([]EndpointSignal, error)
	// 已声明流程基线的跳步/逆序/非法状态转换，以及强流程实际违规；UNKNOWN 不计入
	FlowSequence(ctx context.Context, since time.Time) ([]EndpointSignal, error)
	// 已声明流程基线的重复提交与超声明阈值批量执行
	FlowReplayBurst(ctx context.Context, since time.Time) ([]EndpointSignal, error)
	// 下载文件真实签名与声明类型不一致；无法检测/未知签名不计入
	FileContentTypeMismatch(ctx context.Context, since time.Time) ([]EndpointSignal, error)
	// 上传/下载文本中按 file 位置规则识别的敏感值；未检查/不支持格式不计入
	FileSensitiveContent(ctx context.Context, since time.Time) ([]EndpointSignal, error)
	// 响应涉敏且未观察到成功脱敏的事件按端点聚合（达 minSamples 样本量）
	SensitiveResponseUnmasked(ctx context.Context, since time.Time, minSamples int) ([]EndpointSignal, error)
	// SCHEMA% 类 finding：首现早于 persistBefore 且 activeSince 之后仍在出现
	SchemaDriftPersistent(ctx context.Context, persistBefore, activeSince time.Time) ([]EndpointSignal, error)
}

// SweepResult 一轮派生结果摘要。
type SweepResult struct {
	WindowStart time.Time      `json:"window_start"`
	Inserted    int            `json:"inserted"`   // 首次发现数
	Updated     int            `json:"updated"`    // 已存在计数 +1 数
	Reproduced  int            `json:"reproduced"` // FIXED 再触发回 REPRODUCED 数
	ByCode      map[string]int `json:"by_code"`    // 各弱点码命中端点数
}

// Sweeper 弱点派生器（周期执行 SweepOnce）。
type Sweeper struct {
	source SignalSource
	store  Repository
	opts   SweepOptions
	now    func() time.Time
}

// NewSweeper 创建派生器（默认参数；信号源与仓储共用 db）。
func NewSweeper(db *pgxpool.Pool) *Sweeper {
	return &Sweeper{
		source: &pgSignalSource{db: db},
		store:  NewStore(db),
		opts:   SweepOptions{}.withDefaults(),
		now:    func() time.Time { return time.Now().UTC() },
	}
}

// SweepOnce 执行一轮派生扫描：逐规则取信号 → upsert 弱点。
// 任一规则/写入失败即返回错误（不静默吞错），已写入部分不回滚（幂等，可下轮重扫）。
func (s *Sweeper) SweepOnce(ctx context.Context) (*SweepResult, error) {
	opts := s.opts.withDefaults()
	nowFn := s.now
	if nowFn == nil {
		nowFn = func() time.Time { return time.Now().UTC() }
	}
	now := nowFn()
	since := now.Add(-opts.Window)

	rules := []struct {
		code  string
		fetch func(context.Context) ([]EndpointSignal, error)
	}{
		{CodeUnauthenticatedSensitiveAPI, func(ctx context.Context) ([]EndpointSignal, error) {
			return s.source.UnauthenticatedSensitive(ctx, since, opts.MinSamples)
		}},
		{CodeDeprecatedStillCalled, func(ctx context.Context) ([]EndpointSignal, error) {
			return s.source.DeprecatedCalls(ctx, since)
		}},
		{CodeSensitiveInQuery, func(ctx context.Context) ([]EndpointSignal, error) {
			return s.source.SensitiveInQuery(ctx, since)
		}},
		{CodeCredentialInURL, func(ctx context.Context) ([]EndpointSignal, error) {
			return s.source.CredentialInURL(ctx, since)
		}},
		{CodeSensitiveCookie, func(ctx context.Context) ([]EndpointSignal, error) {
			return s.source.SensitiveCookie(ctx, since)
		}},
		{CodeServerInfoDisclosure, func(ctx context.Context) ([]EndpointSignal, error) {
			return s.source.ServerInfoDisclosure(ctx, since)
		}},
		{CodeObjectEnumerationRisk, func(ctx context.Context) ([]EndpointSignal, error) {
			return s.source.ObjectEnumeration(ctx, since)
		}},
		{CodeFlowSequenceDeviation, func(ctx context.Context) ([]EndpointSignal, error) {
			return s.source.FlowSequence(ctx, since)
		}},
		{CodeFlowReplayOrBurst, func(ctx context.Context) ([]EndpointSignal, error) {
			return s.source.FlowReplayBurst(ctx, since)
		}},
		{CodeFileContentTypeMismatch, func(ctx context.Context) ([]EndpointSignal, error) {
			return s.source.FileContentTypeMismatch(ctx, since)
		}},
		{CodeSensitiveFileContent, func(ctx context.Context) ([]EndpointSignal, error) {
			return s.source.FileSensitiveContent(ctx, since)
		}},
		{CodeSensitiveResponseUnmasked, func(ctx context.Context) ([]EndpointSignal, error) {
			return s.source.SensitiveResponseUnmasked(ctx, since, opts.MinSamples)
		}},
		{CodeSchemaDriftPersistent, func(ctx context.Context) ([]EndpointSignal, error) {
			return s.source.SchemaDriftPersistent(ctx, now.Add(-time.Duration(opts.SchemaPersistDays)*24*time.Hour), since)
		}},
	}

	res := &SweepResult{WindowStart: since, ByCode: map[string]int{}}
	for _, rule := range rules {
		name, category, severity, ok := WeaknessMeta(rule.code)
		if !ok {
			return nil, fmt.Errorf("weakness code %s 未注册元数据", rule.code)
		}
		signals, err := rule.fetch(ctx)
		if err != nil {
			return nil, fmt.Errorf("派生规则 %s 取数失败: %w", rule.code, err)
		}
		for _, sig := range signals {
			out, err := s.store.UpsertDerived(ctx, DerivedInput{
				EndpointID:   sig.EndpointID,
				WeaknessCode: rule.code,
				WeaknessName: name,
				Category:     category,
				Severity:     severity,
				Evidence:     derivedEvidence(rule.code, sig, opts.Window),
				Now:          now,
			})
			if err != nil {
				return res, fmt.Errorf("派生规则 %s 落库失败（端点 %s）: %w", rule.code, sig.EndpointID, err)
			}
			res.ByCode[rule.code]++
			switch {
			case out.Inserted:
				res.Inserted++
			case out.Reproduced:
				res.Reproduced++
			default:
				res.Updated++
			}
		}
	}
	return res, nil
}

// derivedEvidence 构造脱敏证据摘要：只含规则/计数/窗口/时间/端点，不含原始请求数据。
func derivedEvidence(code string, sig EndpointSignal, window time.Duration) json.RawMessage {
	raw, _ := json.Marshal(map[string]any{
		"rule":         code,
		"endpoint_key": sig.EndpointKey,
		"sample_count": sig.Hits,
		"window_hours": int(window.Hours()),
		"first_seen":   sig.FirstSeen.UTC().Format(time.RFC3339),
		"last_seen":    sig.LastSeen.UTC().Format(time.RFC3339),
	})
	return raw
}

// ---------- PostgreSQL 信号源 ----------

// pgSignalSource 从 api_runtime_events / api_runtime_findings 读取派生信号。
// 只使用 000016/000018/000029 已存在的列，与并行分片的 enrichment 列解耦。
type pgSignalSource struct {
	db *pgxpool.Pool
}

// scanSignals 扫描信号行集。
func scanSignals(rows pgx.Rows) ([]EndpointSignal, error) {
	defer rows.Close()
	out := []EndpointSignal{}
	for rows.Next() {
		var sig EndpointSignal
		if err := rows.Scan(&sig.EndpointID, &sig.EndpointKey, &sig.Hits, &sig.FirstSeen, &sig.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, sig)
	}
	return out, rows.Err()
}

// UnauthenticatedSensitive 匿名（auth_type 为空）且命中 sensitive 检测器的事件按端点聚合，达样本量阈值。
func (s *pgSignalSource) UnauthenticatedSensitive(ctx context.Context, since time.Time, minSamples int) ([]EndpointSignal, error) {
	rows, err := s.db.Query(ctx, `
SELECT ep.id, e.endpoint_key, count(*) AS hits, min(e.occurred_at), max(e.occurred_at)
FROM api_runtime_events e
JOIN api_endpoints ep ON ep.endpoint_key = e.endpoint_key
WHERE e.occurred_at >= $1
  AND e.auth_type = ''
  AND EXISTS (
    SELECT 1 FROM jsonb_array_elements(e.details_json) m
    WHERE m->>'detector' = 'sensitive'
  )
GROUP BY ep.id, e.endpoint_key
HAVING count(*) >= $2`, since, minSamples)
	if err != nil {
		return nil, err
	}
	return scanSignals(rows)
}

// DeprecatedCalls 已下线接口仍被调用（lifecycle.deprecated_api_call 命中）按端点聚合。
func (s *pgSignalSource) DeprecatedCalls(ctx context.Context, since time.Time) ([]EndpointSignal, error) {
	rows, err := s.db.Query(ctx, `
SELECT ep.id, e.endpoint_key, count(*) AS hits, min(e.occurred_at), max(e.occurred_at)
FROM api_runtime_events e
JOIN api_endpoints ep ON ep.endpoint_key = e.endpoint_key
WHERE e.occurred_at >= $1
  AND EXISTS (
    SELECT 1 FROM jsonb_array_elements(e.details_json) m
    WHERE m->>'rule_id' = 'lifecycle.deprecated_api_call'
  )
GROUP BY ep.id, e.endpoint_key`, since)
	if err != nil {
		return nil, err
	}
	return scanSignals(rows)
}

// SensitiveInQuery 敏感数据出现在查询串（sensitive.in_query 命中）按端点聚合。
func (s *pgSignalSource) SensitiveInQuery(ctx context.Context, since time.Time) ([]EndpointSignal, error) {
	rows, err := s.db.Query(ctx, `
SELECT ep.id, e.endpoint_key, count(*) AS hits, min(e.occurred_at), max(e.occurred_at)
FROM api_runtime_events e
JOIN api_endpoints ep ON ep.endpoint_key = e.endpoint_key
WHERE e.occurred_at >= $1
  AND EXISTS (
    SELECT 1 FROM jsonb_array_elements(e.details_json) m
    WHERE m->>'rule_id' = 'sensitive.in_query'
  )
GROUP BY ep.id, e.endpoint_key`, since)
	if err != nil {
		return nil, err
	}
	return scanSignals(rows)
}

// CredentialInURL URL 携带凭据（credential.url_password 命中）按端点聚合。
func (s *pgSignalSource) CredentialInURL(ctx context.Context, since time.Time) ([]EndpointSignal, error) {
	rows, err := s.db.Query(ctx, `
SELECT ep.id, e.endpoint_key, count(*) AS hits, min(e.occurred_at), max(e.occurred_at)
FROM api_runtime_events e
JOIN api_endpoints ep ON ep.endpoint_key = e.endpoint_key
WHERE e.occurred_at >= $1
  AND EXISTS (
    SELECT 1 FROM jsonb_array_elements(e.details_json) m
    WHERE m->>'rule_id' = 'credential.url_password'
  )
GROUP BY ep.id, e.endpoint_key`, since)
	if err != nil {
		return nil, err
	}
	return scanSignals(rows)
}

// SensitiveCookie 敏感 Cookie 名（credential.cookie_sensitive 命中）按端点聚合。
func (s *pgSignalSource) SensitiveCookie(ctx context.Context, since time.Time) ([]EndpointSignal, error) {
	rows, err := s.db.Query(ctx, `
SELECT ep.id, e.endpoint_key, count(*) AS hits, min(e.occurred_at), max(e.occurred_at)
FROM api_runtime_events e
JOIN api_endpoints ep ON ep.endpoint_key = e.endpoint_key
WHERE e.occurred_at >= $1
  AND EXISTS (
    SELECT 1 FROM jsonb_array_elements(e.details_json) m
    WHERE m->>'rule_id' = 'credential.cookie_sensitive'
  )
GROUP BY ep.id, e.endpoint_key`, since)
	if err != nil {
		return nil, err
	}
	return scanSignals(rows)
}

// ServerInfoDisclosure 服务器版本或错误信息泄露按端点聚合。
func (s *pgSignalSource) ServerInfoDisclosure(ctx context.Context, since time.Time) ([]EndpointSignal, error) {
	rows, err := s.db.Query(ctx, `
SELECT ep.id, e.endpoint_key, count(*) AS hits, min(e.occurred_at), max(e.occurred_at)
FROM api_runtime_events e
JOIN api_endpoints ep ON ep.endpoint_key = e.endpoint_key
WHERE e.occurred_at >= $1
  AND EXISTS (
    SELECT 1 FROM jsonb_array_elements(e.details_json) m
    WHERE m->>'rule_id' IN ('server.version_disclosure', 'server.error_disclosure')
  )
GROUP BY ep.id, e.endpoint_key`, since)
	if err != nil {
		return nil, err
	}
	return scanSignals(rows)
}

// ObjectEnumeration 可信身份时间窗对象枚举信号按端点聚合。
func (s *pgSignalSource) ObjectEnumeration(ctx context.Context, since time.Time) ([]EndpointSignal, error) {
	rows, err := s.db.Query(ctx, `
SELECT ep.id, e.endpoint_key, count(*) AS hits, min(e.occurred_at), max(e.occurred_at)
FROM api_runtime_events e
JOIN api_endpoints ep ON ep.endpoint_key = e.endpoint_key
WHERE e.occurred_at >= $1
  AND EXISTS (
    SELECT 1 FROM jsonb_array_elements(e.details_json) m
    WHERE m->>'rule_id' = 'resource.object_enumeration'
  )
GROUP BY ep.id, e.endpoint_key`, since)
	if err != nil {
		return nil, err
	}
	return scanSignals(rows)
}

// SchemaDriftPersistent 同端点 SCHEMA% 类 finding 跨 persistBefore 首现且 activeSince 后仍在出现。
// 只统计未闭环（NEW/CONFIRMED/IN_PROGRESS，000042 七态词表）的 finding；RESOLVED/FALSE_POSITIVE 不算持续存在。
func (s *pgSignalSource) SchemaDriftPersistent(ctx context.Context, persistBefore, activeSince time.Time) ([]EndpointSignal, error) {
	rows, err := s.db.Query(ctx, `
SELECT f.endpoint_id, COALESCE(ep.endpoint_key, ''), count(*) AS hits, min(f.first_seen_at), max(f.last_seen_at)
FROM api_runtime_findings f
LEFT JOIN api_endpoints ep ON ep.id = f.endpoint_id
WHERE f.endpoint_id IS NOT NULL
  AND f.finding_type LIKE 'SCHEMA%'
  AND f.status IN ('NEW', 'CONFIRMED', 'IN_PROGRESS')
GROUP BY f.endpoint_id, ep.endpoint_key
HAVING min(f.first_seen_at) <= $1 AND max(f.last_seen_at) >= $2`, persistBefore, activeSince)
	if err != nil {
		return nil, err
	}
	return scanSignals(rows)
}
