package apiassets

import (
	"context"
	"math"
	"time"

	"github.com/google/uuid"
)

type ApplicationValueDimension struct {
	Name         string  `json:"name"`
	AverageScore float64 `json:"average_score"`
	Max          int     `json:"max"`
}

type ApplicationAssetValue struct {
	ApplicationID     uuid.UUID                   `json:"application_id"`
	Level             string                      `json:"level"`
	AverageScore      float64                     `json:"average_score"`
	MaxScore          int                         `json:"max_score"`
	MaxTotal          int                         `json:"max_total"`
	EndpointCount     int64                       `json:"endpoint_count"`
	ScoredCount       int64                       `json:"scored_count"`
	UnscoredCount     int64                       `json:"unscored_count"`
	LevelDistribution map[string]int64            `json:"level_distribution"`
	Dimensions        []ApplicationValueDimension `json:"dimensions"`
	GeneratedAt       time.Time                   `json:"generated_at"`
}

func (s *Store) ApplicationAssetValue(ctx context.Context, applicationID uuid.UUID) (*ApplicationAssetValue, error) {
	var exists bool
	if err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM applications WHERE id=$1 AND deleted_at IS NULL)`, applicationID).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrNotFound
	}
	out := &ApplicationAssetValue{
		ApplicationID: applicationID, MaxTotal: assetValueMaxTotal,
		LevelDistribution: map[string]int64{}, Dimensions: []ApplicationValueDimension{}, GeneratedAt: time.Now().UTC(),
	}
	if err := s.db.QueryRow(ctx, `
SELECT count(*) FILTER (WHERE asset_status <> 'IGNORED'),
  count(*) FILTER (WHERE asset_status <> 'IGNORED' AND asset_value_explain IS NOT NULL),
  COALESCE(round(avg((asset_value_explain->>'total')::numeric)
    FILTER (WHERE asset_status <> 'IGNORED' AND asset_value_explain IS NOT NULL), 2), 0),
  COALESCE(max((asset_value_explain->>'total')::int)
    FILTER (WHERE asset_status <> 'IGNORED' AND asset_value_explain IS NOT NULL), 0)
FROM api_endpoints WHERE application_id=$1 AND is_api = TRUE`, applicationID).Scan(
		&out.EndpointCount, &out.ScoredCount, &out.AverageScore, &out.MaxScore); err != nil {
		return nil, err
	}
	out.UnscoredCount = out.EndpointCount - out.ScoredCount
	if out.ScoredCount > 0 {
		out.Level = assetValueLevel(int(math.Round(out.AverageScore)))
	}

	rows, err := s.db.Query(ctx, `
SELECT COALESCE(NULLIF(asset_value, ''), 'UNKNOWN'), count(*)
FROM api_endpoints
WHERE application_id=$1 AND is_api = TRUE AND asset_status <> 'IGNORED' AND asset_value_explain IS NOT NULL
GROUP BY COALESCE(NULLIF(asset_value, ''), 'UNKNOWN') ORDER BY 1`, applicationID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var level string
		var count int64
		if err := rows.Scan(&level, &count); err != nil {
			rows.Close()
			return nil, err
		}
		out.LevelDistribution[level] = count
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = s.db.Query(ctx, `
SELECT d.item->>'name',
  round(avg((d.item->>'score')::numeric), 2),
  max((d.item->>'max')::int)
FROM api_endpoints e
CROSS JOIN LATERAL jsonb_array_elements(e.asset_value_explain->'dimensions') AS d(item)
WHERE e.application_id=$1 AND e.is_api = TRUE AND e.asset_status <> 'IGNORED'
  AND e.asset_value_explain IS NOT NULL
  AND jsonb_typeof(e.asset_value_explain->'dimensions') = 'array'
GROUP BY d.item->>'name' ORDER BY d.item->>'name'`, applicationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var dimension ApplicationValueDimension
		if err := rows.Scan(&dimension.Name, &dimension.AverageScore, &dimension.Max); err != nil {
			return nil, err
		}
		out.Dimensions = append(out.Dimensions, dimension)
	}
	return out, rows.Err()
}
