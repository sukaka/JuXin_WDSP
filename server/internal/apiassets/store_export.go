package apiassets

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const (
	exportAgentSourceLimit    = 100
	exportFindingLimit        = 50
	exportWeaknessLimit       = 50
	exportSensitiveFieldLimit = 500
)

// LoadExportExtras 读取单个端点详细导出的分类、来源与安全扩展数据。
// 所有集合均有上限；detail/evidence/source_detail 沿用各表既有脱敏 JSON，不含正文值。
func (s *Store) LoadExportExtras(ctx context.Context, endpointID uuid.UUID) (*ExportExtras, error) {
	out := &ExportExtras{}
	if err := s.loadExportClassificationDimensions(ctx, endpointID, out); err != nil {
		return nil, err
	}
	if err := s.loadExportAgentSources(ctx, endpointID, out); err != nil {
		return nil, err
	}
	if err := s.loadExportFindings(ctx, endpointID, out); err != nil {
		return nil, err
	}
	if err := s.loadExportWeaknesses(ctx, endpointID, out); err != nil {
		return nil, err
	}
	if err := s.loadExportSensitiveFields(ctx, endpointID, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) loadExportClassificationDimensions(ctx context.Context, endpointID uuid.UUID, out *ExportExtras) error {
	rows, err := s.db.Query(ctx, `
SELECT endpoint_id, dimension, value, source, confidence
FROM api_classification_dimensions
WHERE endpoint_id=$1
ORDER BY dimension, value`, endpointID)
	if err != nil {
		return fmt.Errorf("load export classification dimensions: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var d ClassificationDimension
		if err := rows.Scan(&d.EndpointID, &d.Dimension, &d.Value, &d.Source, &d.Confidence); err != nil {
			return err
		}
		out.ClassificationDimensions = append(out.ClassificationDimensions, d)
	}
	return rows.Err()
}

func (s *Store) loadExportAgentSources(ctx context.Context, endpointID uuid.UUID, out *ExportExtras) error {
	rows, err := s.db.Query(ctx, `
SELECT agent_id, endpoint_id, host, method, path_template,
       source_type, source_instance, source_epoch,
       application_binding_id, binding_version, association_state, last_error,
       classification_is_api, classification_confidence, classification_level,
       classification_signals, classified_at,
       first_seen_at, last_seen_at, count(*) OVER() AS total
FROM agent_http_asset_sources
WHERE endpoint_id=$1
ORDER BY last_seen_at DESC, id DESC
LIMIT $2`, endpointID, exportAgentSourceLimit)
	if err != nil {
		return fmt.Errorf("load export agent sources: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var item ExportAgentSource
		var classIsAPI *bool
		var classConfidence *float64
		var classLevel string
		var classSignals []byte
		var classifiedAt *time.Time
		if err := rows.Scan(&item.AgentID, &item.EndpointID, &item.Host, &item.Method, &item.PathTemplate,
			&item.SourceType, &item.SourceInstance, &item.SourceEpoch,
			&item.ApplicationBindingID, &item.BindingVersion, &item.AssociationState, &item.LastError,
			&classIsAPI, &classConfidence, &classLevel, &classSignals, &classifiedAt,
			&item.FirstSeenAt, &item.LastSeenAt, &out.AgentSourcesTotal); err != nil {
			return err
		}
		if classifiedAt != nil {
			classification := &ExportClassification{Level: classLevel, Signals: []string{}, ClassifiedAt: *classifiedAt}
			if classIsAPI != nil {
				classification.IsAPI = *classIsAPI
			}
			if classConfidence != nil {
				classification.Confidence = *classConfidence
			}
			if len(classSignals) > 0 {
				_ = json.Unmarshal(classSignals, &classification.Signals)
			}
			item.Classification = classification
		}
		out.AgentSources = append(out.AgentSources, item)
	}
	return rows.Err()
}

func (s *Store) loadExportFindings(ctx context.Context, endpointID uuid.UUID, out *ExportExtras) error {
	rows, err := s.db.Query(ctx, `
SELECT id, endpoint_id, request_id, finding_type, severity, status, title, detail,
       first_seen_at, last_seen_at, count(*) OVER() AS total
FROM api_runtime_findings
WHERE endpoint_id=$1
ORDER BY last_seen_at DESC
LIMIT $2`, endpointID, exportFindingLimit)
	if err != nil {
		return fmt.Errorf("load export findings: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var item ExportFinding
		if err := rows.Scan(&item.ID, &item.EndpointID, &item.RequestID, &item.FindingType,
			&item.Severity, &item.Status, &item.Title, &item.Detail,
			&item.FirstSeenAt, &item.LastSeenAt, &out.FindingsTotal); err != nil {
			return err
		}
		out.Findings = append(out.Findings, item)
	}
	return rows.Err()
}

func (s *Store) loadExportWeaknesses(ctx context.Context, endpointID uuid.UUID, out *ExportExtras) error {
	rows, err := s.db.Query(ctx, `
SELECT id, endpoint_id, weakness_code, weakness_name, category, severity, status,
       evidence_json, first_seen, last_seen, trigger_count, owner, count(*) OVER() AS total
FROM api_weaknesses
WHERE endpoint_id=$1
ORDER BY last_seen DESC
LIMIT $2`, endpointID, exportWeaknessLimit)
	if err != nil {
		return fmt.Errorf("load export weaknesses: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var item ExportWeakness
		if err := rows.Scan(&item.ID, &item.EndpointID, &item.Code, &item.Name, &item.Category,
			&item.Severity, &item.Status, &item.Evidence, &item.FirstSeen, &item.LastSeen,
			&item.TriggerCount, &item.Owner, &out.WeaknessesTotal); err != nil {
			return err
		}
		out.Weaknesses = append(out.Weaknesses, item)
	}
	return rows.Err()
}

func (s *Store) loadExportSensitiveFields(ctx context.Context, endpointID uuid.UUID, out *ExportExtras) error {
	rows, err := s.db.Query(ctx, `
SELECT id, endpoint_id, direction, structured_path, data_type, confidence, detection_source,
       first_seen, last_seen, occurrence_count, source_detail, count(*) OVER() AS total
FROM api_sensitive_fields
WHERE endpoint_id=$1
ORDER BY COALESCE(last_seen, updated_at) DESC
LIMIT $2`, endpointID, exportSensitiveFieldLimit)
	if err != nil {
		return fmt.Errorf("load export sensitive fields: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var item ExportSensitiveField
		if err := rows.Scan(&item.ID, &item.EndpointID, &item.Direction, &item.StructuredPath,
			&item.DataType, &item.Confidence, &item.DetectionSource,
			&item.FirstSeen, &item.LastSeen, &item.OccurrenceCount, &item.SourceDetail,
			&out.SensitiveFieldsTotal); err != nil {
			return err
		}
		out.SensitiveFields = append(out.SensitiveFields, item)
	}
	return rows.Err()
}

// LoadExportExtras 内存仓储测试实现：扩展数据默认空集合；单测可注入 fake provider 覆盖。
func (m *MemStore) LoadExportExtras(_ context.Context, _ uuid.UUID) (*ExportExtras, error) {
	return &ExportExtras{}, nil
}
