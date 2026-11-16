package apidataflow

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/agents"
	"github.com/jiuzhang-waf/server/internal/apiassets"
)

type AssetProjector interface {
	Project(context.Context, agents.APIObservationEnvelope) error
}

type PostgresAssetProjector struct {
	db     *pgxpool.Pool
	assets *apiassets.Store
}

func NewPostgresAssetProjector(db *pgxpool.Pool, assets *apiassets.Store) *PostgresAssetProjector {
	return &PostgresAssetProjector{db: db, assets: assets}
}

func (p *PostgresAssetProjector) Project(ctx context.Context, record agents.APIObservationEnvelope) error {
	if record.ApplicationBindingID == nil || record.HTTP.Direction != "SERVER" {
		return nil
	}
	endpointKey := record.Service.Name + "|" + record.HTTP.Host + "|" + record.HTTP.Method + "|" + record.HTTP.PathTemplate + "|" + record.ApplicationBindingID.String()
	tx, err := p.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var inserted bool
	err = tx.QueryRow(ctx, `
INSERT INTO agent_api_observation_asset_events (agent_id,event_id,endpoint_key)
VALUES ($1,$2,$3)
ON CONFLICT (agent_id,event_id,endpoint_key) DO NOTHING
RETURNING true`, record.AgentID, record.EventID, endpointKey).Scan(&inserted)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			slog.Warn("skip API observation for deleted agent", "agent_id", record.AgentID, "event_id", record.EventID)
			return nil
		}
		return fmt.Errorf("insert observation asset receipt agent=%s: %w", record.AgentID, err)
	}
	protocol := "UNKNOWN_HTTP_API"
	contentType := strings.ToLower(record.HTTP.RequestContentType + " " + record.HTTP.ResponseContentType)
	switch {
	case strings.Contains(contentType, "json"):
		protocol = "REST_JSON"
	case strings.Contains(contentType, "xml"):
		protocol = "REST_XML"
	case strings.Contains(contentType, "x-www-form-urlencoded"):
		protocol = "FORM_API"
	}
	_, err = p.assets.WithDB(tx).UpsertDiscovery(ctx, apiassets.DiscoveryInput{
		Method: record.HTTP.Method, PathTemplate: record.HTTP.PathTemplate,
		Confidence: 0.99, IsAPI: true, ApplicationID: record.ApplicationID,
		ApplicationBindingID: record.ApplicationBindingID, Host: record.HTTP.Host, ProtocolType: protocol,
	})
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
