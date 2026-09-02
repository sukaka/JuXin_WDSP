// store.go client_identity 体系事件入库（采集器批量事务内逐记录调用）。
// 全部写方法接收 Querier（采集器 flush 批次传入同一个 pgx.Tx，整批一次 COMMIT；
// 失败整体回滚、断点不前移，下轮重放由 UPSERT 幂等兜底——request_count 类自增
// 在「提交成功但断点保存失败」的极小窗口内可能重复累计，指标口径可接受，
// 与既有采集器同一断点纪律）。
package identityevents

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Querier 采集批次事务/连接池共用的最小查询接口。
type Querier interface {
	Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row
}

// Store 是 client_identity 体系仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// UpsertObservation 身份观测入库：UPSERT client_identity（identity_key 冲突时
// 累计 request_count、刷新 last_seen_at、非空字段才覆盖、identity_type 仅在现值
// UNKNOWN 时更新）→ UPSERT identity_ip_history → 逐凭据 UPSERT identity_credential。
func (s *Store) UpsertObservation(ctx context.Context, q Querier, rec *Record) error {
	accountID, jwtSubject, apiKeyHash, oauthClientID := derivedIdentityFields(rec.Credentials)
	confidenceSource := []byte("[]")
	identityEvidence := sanitizeIdentityEvidence(rec.IdentityEvidence)
	if len(identityEvidence) > 0 {
		if raw, err := json.Marshal(identityEvidence); err == nil {
			confidenceSource = raw
		}
	}
	var identityID uuid.UUID
	err := q.QueryRow(ctx, `
INSERT INTO client_identity (identity_key, identity_type, identity_confidence, confidence_source,
  first_seen_at, last_seen_at, primary_ip, tls_fingerprint, browser_fingerprint, account_id,
  jwt_subject, api_key_hash, oauth_client_id, request_count)
VALUES ($1,$2,$3,$4,$5,$5,$6,$7,$8,$9,$10,$11,$12,1)
ON CONFLICT (identity_key) DO UPDATE SET
  last_seen_at = GREATEST(client_identity.last_seen_at, EXCLUDED.last_seen_at),
  first_seen_at = LEAST(client_identity.first_seen_at, EXCLUDED.first_seen_at),
  request_count = client_identity.request_count + 1,
  primary_ip = CASE WHEN EXCLUDED.primary_ip <> '' THEN EXCLUDED.primary_ip ELSE client_identity.primary_ip END,
  tls_fingerprint = CASE WHEN EXCLUDED.tls_fingerprint <> '' THEN EXCLUDED.tls_fingerprint ELSE client_identity.tls_fingerprint END,
  browser_fingerprint = CASE WHEN EXCLUDED.browser_fingerprint <> '' THEN EXCLUDED.browser_fingerprint ELSE client_identity.browser_fingerprint END,
  account_id = CASE WHEN EXCLUDED.account_id <> '' THEN EXCLUDED.account_id ELSE client_identity.account_id END,
  jwt_subject = CASE WHEN EXCLUDED.jwt_subject <> '' THEN EXCLUDED.jwt_subject ELSE client_identity.jwt_subject END,
  api_key_hash = CASE WHEN EXCLUDED.api_key_hash <> '' THEN EXCLUDED.api_key_hash ELSE client_identity.api_key_hash END,
  oauth_client_id = CASE WHEN EXCLUDED.oauth_client_id <> '' THEN EXCLUDED.oauth_client_id ELSE client_identity.oauth_client_id END,
  identity_type = CASE WHEN client_identity.identity_type = 'UNKNOWN' AND EXCLUDED.identity_type <> 'UNKNOWN'
                       THEN EXCLUDED.identity_type ELSE client_identity.identity_type END,
  identity_confidence = GREATEST(client_identity.identity_confidence, EXCLUDED.identity_confidence),
  confidence_source = CASE WHEN EXCLUDED.identity_confidence >= client_identity.identity_confidence
                            THEN EXCLUDED.confidence_source ELSE client_identity.confidence_source END,
  updated_at = now()
RETURNING id`,
		rec.IdentityKey, rec.IdentityType, rec.IdentityConfidence, confidenceSource, rec.OccurredAt, rec.ClientIP,
		rec.TLSFingerprint, rec.BrowserFingerprint, accountID, jwtSubject, apiKeyHash, oauthClientID,
	).Scan(&identityID)
	if err != nil {
		return fmt.Errorf("upsert client_identity: %w", err)
	}

	// IP 历史（无 IP 的观测跳过；同 identity+ip 累计请求数）
	if rec.ClientIP != "" {
		if _, err := q.Exec(ctx, `
INSERT INTO identity_ip_history (identity_id, ip, first_seen_at, last_seen_at, request_count)
VALUES ($1,$2,$3,$3,1)
ON CONFLICT (identity_id, ip) DO UPDATE SET
  last_seen_at = GREATEST(identity_ip_history.last_seen_at, EXCLUDED.last_seen_at),
  first_seen_at = LEAST(identity_ip_history.first_seen_at, EXCLUDED.first_seen_at),
  request_count = identity_ip_history.request_count + 1`,
			identityID, rec.ClientIP, rec.OccurredAt); err != nil {
			return fmt.Errorf("upsert identity_ip_history: %w", err)
		}
	}

	// 凭据指纹（未知类型/空哈希跳过，不落明文凭据）
	for _, c := range rec.Credentials {
		if !validCredentialTypes[c.Type] || c.Hash == "" {
			continue
		}
		if _, err := q.Exec(ctx, `
INSERT INTO identity_credential (identity_id, credential_type, credential_hash, first_seen_at, last_seen_at)
VALUES ($1,$2,$3,$4,$4)
ON CONFLICT (identity_id, credential_type, credential_hash) DO UPDATE SET
  last_seen_at = GREATEST(identity_credential.last_seen_at, EXCLUDED.last_seen_at)`,
			identityID, c.Type, c.Hash, rec.OccurredAt); err != nil {
			return fmt.Errorf("upsert identity_credential: %w", err)
		}
	}
	return nil
}

// ensureIdentity 确保身份存在（behavior_snapshot/recon_signal 先于观测到达时按
// identity_key 建 UNKNOWN 占位行；已存在则仅刷新 last_seen_at）。
func (s *Store) ensureIdentity(ctx context.Context, q Querier, identityKey string, occurredAt time.Time) (uuid.UUID, error) {
	var id uuid.UUID
	err := q.QueryRow(ctx, `
INSERT INTO client_identity (identity_key, identity_type, first_seen_at, last_seen_at)
VALUES ($1,'UNKNOWN',$2,$2)
ON CONFLICT (identity_key) DO UPDATE SET
  last_seen_at = GREATEST(client_identity.last_seen_at, EXCLUDED.last_seen_at),
  updated_at = now()
RETURNING id`, identityKey, occurredAt).Scan(&id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("ensure client_identity: %w", err)
	}
	return id, nil
}

// UpsertSnapshot 行为快照入库：确保身份存在后对每个窗口 UPSERT behavior_statistics
// （计数直接覆盖为观测值——网关按窗口对齐输出累计值，同窗口重复上报以最新快照为准）。
func (s *Store) UpsertSnapshot(ctx context.Context, q Querier, rec *Record) error {
	identityID, err := s.ensureIdentity(ctx, q, rec.IdentityKey, rec.OccurredAt)
	if err != nil {
		return err
	}
	for windowType, w := range rec.Windows {
		if !validWindowTypes[windowType] {
			// 未知窗口键跳过（容忍网关后续新增窗口；行级不视为坏行）
			continue
		}
		if _, err := q.Exec(ctx, `
INSERT INTO behavior_statistics (identity_id, window_type, window_start,
  request_count, unique_uri_count, new_uri_count,
  status_401_count, status_403_count, status_404_count, status_405_count, status_500_count,
  auth_fail_count, parameter_mutation_count, sensitive_path_hits, account_enum_count, object_enum_count)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
ON CONFLICT (identity_id, window_type, window_start) DO UPDATE SET
  request_count = EXCLUDED.request_count,
  unique_uri_count = EXCLUDED.unique_uri_count,
  new_uri_count = EXCLUDED.new_uri_count,
  status_401_count = EXCLUDED.status_401_count,
  status_403_count = EXCLUDED.status_403_count,
  status_404_count = EXCLUDED.status_404_count,
  status_405_count = EXCLUDED.status_405_count,
  status_500_count = EXCLUDED.status_500_count,
  auth_fail_count = EXCLUDED.auth_fail_count,
  parameter_mutation_count = EXCLUDED.parameter_mutation_count,
  sensitive_path_hits = EXCLUDED.sensitive_path_hits,
  account_enum_count = EXCLUDED.account_enum_count,
  object_enum_count = EXCLUDED.object_enum_count,
  updated_at = now()`,
			identityID, windowType, w.WindowStart,
			w.RequestCount, w.UniqueURICount, w.NewURICount,
			w.Status401Count, w.Status403Count, w.Status404Count, w.Status405Count, w.Status500Count,
			w.AuthFailCount, w.ParameterMutationCount, w.SensitivePathHits, w.AccountEnumCount, w.ObjectEnumCount); err != nil {
			return fmt.Errorf("upsert behavior_statistics: %w", err)
		}
	}

	// 以 1m 窗口计数估算累加身份与来源 IP 的请求量：快照按身份每 60s 节流一次，
	// 1m 窗口近似覆盖间隔期请求，是 request_count 的主要累加来源
	// （identity_observation 的 +1 仅标记首见；窗口边界存在少量重复/遗漏，属估算语义）。
	if w1m, ok := rec.Windows["1m"]; ok && w1m.RequestCount > 0 {
		if _, err := q.Exec(ctx, `
UPDATE client_identity SET request_count = request_count + $2, updated_at = now() WHERE id = $1`,
			identityID, w1m.RequestCount); err != nil {
			return fmt.Errorf("bump client_identity request_count: %w", err)
		}
		if rec.ClientIP != "" {
			if _, err := q.Exec(ctx, `
UPDATE identity_ip_history SET
  request_count = request_count + $3,
  last_seen_at = GREATEST(COALESCE(last_seen_at, $4), $4)
WHERE identity_id = $1 AND ip = $2`,
				identityID, rec.ClientIP, w1m.RequestCount, rec.OccurredAt); err != nil {
				return fmt.Errorf("bump identity_ip_history request_count: %w", err)
			}
		}
	}
	return nil
}

// RecordSignal 侦察信号入库：确保身份存在 → INSERT identity_behavior_events →
// 重算风险分（24h 内 risk_score_delta 求和，截断 [0,100]）与风险等级（Go 侧计算，
// 阈值口径见 RiskLevelForScore）。
func (s *Store) RecordSignal(ctx context.Context, q Querier, rec *Record) error {
	identityID, err := s.ensureIdentity(ctx, q, rec.IdentityKey, rec.OccurredAt)
	if err != nil {
		return err
	}
	metadata := []byte("{}")
	if cleanMetadata := sanitizeSignalMetadata(rec.Metadata); len(cleanMetadata) > 0 {
		if raw, merr := json.Marshal(cleanMetadata); merr == nil {
			metadata = raw
		}
	}
	identityEvidence := []byte("[]")
	if cleanEvidence := sanitizeIdentityEvidence(rec.IdentityEvidence); len(cleanEvidence) > 0 {
		if raw, merr := json.Marshal(cleanEvidence); merr == nil {
			identityEvidence = raw
		}
	}
	if _, err := q.Exec(ctx, `
INSERT INTO identity_behavior_events (identity_id, identity_key, occurred_at, event_kind,
  rule_code, rule_version, signal, risk_score_delta, mode, reason, metadata,
  request_id, client_ip, method, path, app_id, domain, gateway_node, identity_confidence, identity_evidence)
VALUES ($1,$2,$3,'RECON_SIGNAL',$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
		identityID, rec.IdentityKey, rec.OccurredAt,
		rec.RuleCode, rec.RuleVersion, rec.Signal, rec.RiskScoreDelta, rec.Mode, rec.Reason, metadata,
		rec.RequestID, rec.ClientIP, rec.Method, rec.Path, rec.AppID, rec.Domain, rec.GatewayNode,
		rec.IdentityConfidence, identityEvidence); err != nil {
		return fmt.Errorf("insert identity_behavior_events: %w", err)
	}

	// 24h 滚动窗口风险分重算（该身份全部信号增量求和）
	var total int
	if err := q.QueryRow(ctx, `
SELECT COALESCE(SUM(risk_score_delta), 0) FROM identity_behavior_events
WHERE identity_id = $1 AND occurred_at >= now() - INTERVAL '24 hours'`, identityID).Scan(&total); err != nil {
		return fmt.Errorf("sum risk score delta: %w", err)
	}
	score := clampRiskScore(total)
	if _, err := q.Exec(ctx, `
UPDATE client_identity SET risk_score = $2, risk_level = $3, updated_at = now() WHERE id = $1`,
		identityID, score, RiskLevelForScore(score)); err != nil {
		return fmt.Errorf("update identity risk: %w", err)
	}
	return nil
}

// InsertParseFailure 解析失败入队（event_parse_failures 通用表，与安全事件/访问日志
// 采集器共用；best-effort——队列写入失败仅由调用方记日志，不阻断采集）。
func (s *Store) InsertParseFailure(ctx context.Context, collectorID, rawLine, reason string) error {
	if len(rawLine) > 4096 {
		rawLine = rawLine[:4096]
	}
	_, err := s.db.Exec(ctx,
		`INSERT INTO event_parse_failures (collector_id, raw_line, error_reason) VALUES ($1, $2, $3)`,
		collectorID, rawLine, reason)
	return err
}
