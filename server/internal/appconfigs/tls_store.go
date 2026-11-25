// tls_store.go 应用级 TLS/国密协议自识别、TLS/HTTP 协议降级与加密会话分析配置仓储（PostgreSQL + 内存实现）。
package appconfigs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// TLSConfigRecord 应用 TLS/HTTP 协议策略完整记录（含乐观锁版本与审计时间）。
type TLSConfigRecord struct {
	Config    *gatewayconfig.AppTLSConfig `json:"config"`
	Version   int                         `json:"version"`
	UpdatedBy *uuid.UUID                  `json:"updated_by,omitempty"`
	CreatedAt time.Time                   `json:"created_at"`
	UpdatedAt time.Time                   `json:"updated_at"`
}

// DefaultTLSConfig 返回未显式配置时的默认站点协议策略。
func DefaultTLSConfig() *gatewayconfig.AppTLSConfig {
	return gatewayconfig.DefaultAppTLSConfig()
}

const tlsConfigColumns = `application_id, tls_protocol_mode, allowed_tls_versions,
  legacy_ssl_analysis_versions, http_versions, upstream_http_version,
  upstream_tls_min_version, session_analysis_enabled, updated_by, created_at, updated_at, version`

// GetTLSConfig 查询应用 TLS/HTTP 协议策略；无记录返回 (nil, nil)。
func (s *Store) GetTLSConfig(ctx context.Context, appID uuid.UUID) (*gatewayconfig.AppTLSConfig, error) {
	rec, err := s.GetTLSConfigRecord(ctx, appID)
	if err != nil || rec == nil {
		return nil, err
	}
	return rec.Config, nil
}

// GetTLSConfigRecord 查询应用 TLS/HTTP 协议策略完整记录；无记录返回 (nil, nil)。
func (s *Store) GetTLSConfigRecord(ctx context.Context, appID uuid.UUID) (*TLSConfigRecord, error) {
	row := s.db.QueryRow(ctx, `SELECT `+tlsConfigColumns+` FROM app_tls_configs WHERE application_id = $1`, appID)
	rec, err := scanTLSConfig(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return rec, nil
}

// UpsertTLSConfig 全量 upsert 站点 TLS/HTTP 协议策略（version 乐观锁，语义与 UpsertHeaderConfig 一致）。
func (s *Store) UpsertTLSConfig(ctx context.Context, appID uuid.UUID, cfg *gatewayconfig.AppTLSConfig, updatedBy uuid.UUID, expectVersion int) (int, error) {
	if err := gatewayconfig.NormalizeAndValidateAppTLSConfig(cfg); err != nil {
		return 0, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	allowedJSON, err := json.Marshal(cfg.AllowedTLSVersions)
	if err != nil {
		return 0, fmt.Errorf("marshal allowed_tls_versions: %w", err)
	}
	legacyJSON, err := json.Marshal(cfg.LegacySSLAnalysisVersions)
	if err != nil {
		return 0, fmt.Errorf("marshal legacy_ssl_analysis_versions: %w", err)
	}
	httpJSON, err := json.Marshal(cfg.HTTPVersions)
	if err != nil {
		return 0, fmt.Errorf("marshal http_versions: %w", err)
	}
	var ub *uuid.UUID
	if updatedBy != uuid.Nil {
		ub = &updatedBy
	}
	if expectVersion > 0 {
		res, err := s.db.Exec(ctx, `
UPDATE app_tls_configs SET tls_protocol_mode=$2, allowed_tls_versions=$3,
  legacy_ssl_analysis_versions=$4, http_versions=$5, upstream_http_version=$6,
  upstream_tls_min_version=$7, session_analysis_enabled=$8, updated_by=$9,
  updated_at=now(), version=version+1
WHERE application_id=$1 AND version=$10`,
			appID, cfg.TLSProtocolMode, allowedJSON, legacyJSON, httpJSON,
			cfg.UpstreamHTTPVersion, cfg.UpstreamTLSMinVersion, cfg.SessionAnalysisEnabled,
			ub, expectVersion)
		if err != nil {
			return 0, err
		}
		if res.RowsAffected() == 0 {
			return 0, ErrVersionConflict
		}
		return expectVersion + 1, nil
	}
	var newVersion int
	err = s.db.QueryRow(ctx, `
INSERT INTO app_tls_configs (application_id, tls_protocol_mode, allowed_tls_versions,
  legacy_ssl_analysis_versions, http_versions, upstream_http_version,
  upstream_tls_min_version, session_analysis_enabled, updated_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
RETURNING version`,
		appID, cfg.TLSProtocolMode, allowedJSON, legacyJSON, httpJSON,
		cfg.UpstreamHTTPVersion, cfg.UpstreamTLSMinVersion, cfg.SessionAnalysisEnabled, ub).Scan(&newVersion)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case "23503":
				return 0, ErrAppNotFound
			case "23505":
				return 0, ErrVersionConflict
			}
		}
		return 0, err
	}
	return newVersion, nil
}

func scanTLSConfig(row pgx.Row) (*TLSConfigRecord, error) {
	var (
		appID                                   uuid.UUID
		cfg                                     gatewayconfig.AppTLSConfig
		allowedRaw, legacyRaw, httpVersionsRaw []byte
		rec                                     TLSConfigRecord
	)
	err := row.Scan(
		&appID, &cfg.TLSProtocolMode, &allowedRaw, &legacyRaw, &httpVersionsRaw,
		&cfg.UpstreamHTTPVersion, &cfg.UpstreamTLSMinVersion, &cfg.SessionAnalysisEnabled,
		&rec.UpdatedBy, &rec.CreatedAt, &rec.UpdatedAt, &rec.Version,
	)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(allowedRaw, &cfg.AllowedTLSVersions)
	_ = json.Unmarshal(legacyRaw, &cfg.LegacySSLAnalysisVersions)
	_ = json.Unmarshal(httpVersionsRaw, &cfg.HTTPVersions)
	rec.Config = &cfg
	return &rec, nil
}

// ---------- MemStore 实现 ----------

// GetTLSConfig 查询应用 TLS/HTTP 协议策略（内存实现）。
func (m *MemStore) GetTLSConfig(ctx context.Context, appID uuid.UUID) (*gatewayconfig.AppTLSConfig, error) {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.tlsConfigs[appID]
	if !ok {
		return nil, nil
	}
	return gatewayconfig.CloneAppTLSConfig(rec.Config), nil
}

// GetTLSConfigRecord 查询应用 TLS/HTTP 协议策略完整记录（内存实现）。
func (m *MemStore) GetTLSConfigRecord(ctx context.Context, appID uuid.UUID) (*TLSConfigRecord, error) {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.tlsConfigs[appID]
	if !ok {
		return nil, nil
	}
	out := *rec
	out.Config = gatewayconfig.CloneAppTLSConfig(rec.Config)
	return &out, nil
}

// UpsertTLSConfig 全量 upsert 站点 TLS/HTTP 协议策略（内存实现，含乐观锁）。
func (m *MemStore) UpsertTLSConfig(ctx context.Context, appID uuid.UUID, cfg *gatewayconfig.AppTLSConfig, updatedBy uuid.UUID, expectVersion int) (int, error) {
	_ = ctx
	if err := gatewayconfig.NormalizeAndValidateAppTLSConfig(cfg); err != nil {
		return 0, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tlsConfigs == nil {
		m.tlsConfigs = map[uuid.UUID]*TLSConfigRecord{}
	}
	now := time.Now().UTC()
	var ub *uuid.UUID
	if updatedBy != uuid.Nil {
		ub = &updatedBy
	}
	if expectVersion > 0 {
		rec, ok := m.tlsConfigs[appID]
		if !ok || rec.Version != expectVersion {
			return 0, ErrVersionConflict
		}
		rec.Config = gatewayconfig.CloneAppTLSConfig(cfg)
		rec.UpdatedBy = ub
		rec.UpdatedAt = now
		rec.Version++
		return rec.Version, nil
	}
	if _, ok := m.tlsConfigs[appID]; ok {
		return 0, ErrVersionConflict
	}
	m.tlsConfigs[appID] = &TLSConfigRecord{
		Config:    gatewayconfig.CloneAppTLSConfig(cfg),
		Version:   1,
		UpdatedBy: ub,
		CreatedAt: now,
		UpdatedAt: now,
	}
	return 1, nil
}
