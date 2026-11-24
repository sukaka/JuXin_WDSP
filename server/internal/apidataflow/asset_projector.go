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
	"github.com/jiuzhang-waf/gateway/dynamic_security/classifier"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
	"github.com/jiuzhang-waf/server/internal/agents"
	"github.com/jiuzhang-waf/server/internal/apiassets"
)

type AssetProjector interface {
	Project(context.Context, agents.APIObservationEnvelope) error
}

type PostgresAssetProjector struct {
	db              *pgxpool.Pool
	assets          *apiassets.Store
	discoveryFilter func(ctx context.Context) apiassets.DiscoveryFilterConfig
}

func NewPostgresAssetProjector(db *pgxpool.Pool, assets *apiassets.Store) *PostgresAssetProjector {
	return &PostgresAssetProjector{db: db, assets: assets}
}

// SetDiscoveryFilter 注入 API 资产发现过滤配置提供者（nil 时使用内置默认规则）。
func (p *PostgresAssetProjector) SetDiscoveryFilter(fn func(ctx context.Context) apiassets.DiscoveryFilterConfig) *PostgresAssetProjector {
	p.discoveryFilter = fn
	return p
}

func (p *PostgresAssetProjector) currentDiscoveryFilter(ctx context.Context) apiassets.DiscoveryFilterConfig {
	if p.discoveryFilter != nil {
		return p.discoveryFilter(ctx)
	}
	return apiassets.DefaultDiscoveryFilterConfig()
}

func classifyObservationHTTP(record agents.APIObservationEnvelope) (classifier.Result, string) {
	reqCT := strings.TrimSpace(record.HTTP.RequestContentType)
	respCT := strings.TrimSpace(record.HTTP.ResponseContentType)
	parsed := &parser.Parsed{
		Method:      strings.ToUpper(strings.TrimSpace(record.HTTP.Method)),
		RawPath:     record.HTTP.PathTemplate,
		ContentType: reqCT,
		IsJSON:      strings.Contains(strings.ToLower(reqCT), "json"),
		Headers:     map[string]string{},
	}
	var respEv *classifier.ResponseEvidence
	if respCT != "" || record.HTTP.Status > 0 {
		respEv = &classifier.ResponseEvidence{
			Status:      record.HTTP.Status,
			ContentType: respCT,
		}
	}
	res := classifier.ClassifyWithResponse(parsed, respEv)

	// 协议类型按实际可见 Content-Type 判定
	protocol := classifier.ProtocolUnknownHTTPAPI
	combinedCT := strings.ToLower(reqCT + " " + respCT)
	switch {
	case strings.Contains(combinedCT, "grpc"):
		protocol = classifier.ProtocolGRPC
		res.IsAPI = true
		if res.Confidence < 0.95 {
			res.Confidence = 0.95
			res.Level = classifier.LevelConfirmedAPI
			res.Confidence100 = 95
		}
	case strings.Contains(combinedCT, "json"):
		protocol = classifier.ProtocolRESTJSON
	case strings.Contains(combinedCT, "xml"):
		protocol = classifier.ProtocolRESTXML
	case strings.Contains(combinedCT, "x-www-form-urlencoded"):
		protocol = classifier.ProtocolFormAPI
	case strings.Contains(combinedCT, "text/event-stream"):
		protocol = classifier.ProtocolSSE
	}

	// 进程内框架路由（如 Spring/Gin Controller）：若既不是静态路径也非静态/HTML 响应，
	// 且存在已提取结构化字段或写方法，则视为可信 API 端点。
	if !res.IsAPI &&
		!classifier.IsStaticAssetPath(parsed.Method, parsed.RawPath) &&
		!classifier.IsStaticResponseContentType(respCT) &&
		!classifier.IsHTMLResponseContentType(respCT) {
		isWrite := parsed.Method == "POST" || parsed.Method == "PUT" || parsed.Method == "PATCH" || parsed.Method == "DELETE"
		if len(record.Fields) > 0 || (record.Quality.RouteSource == "FRAMEWORK" && isWrite) {
			res.IsAPI = true
			if res.Confidence < 0.75 {
				res.Confidence = 0.75
				res.Level = classifier.LevelConfirmedAPI
				res.Confidence100 = 75
			}
		}
	}

	return res, protocol
}

func (p *PostgresAssetProjector) Project(ctx context.Context, record agents.APIObservationEnvelope) error {
	if record.ApplicationBindingID == nil || record.HTTP.Direction != "SERVER" {
		return nil
	}
	classification, protocol := classifyObservationHTTP(record)
	effectiveIsAPI := classification.IsAPI || classifier.IsStructuralProtocol(protocol)
	filterCfg := p.currentDiscoveryFilter(ctx)
	if filtered, _ := filterCfg.ShouldFilterDiscovery(record.HTTP.Method, record.HTTP.PathTemplate, effectiveIsAPI); filtered {
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
	_, err = p.assets.WithDB(tx).UpsertDiscovery(ctx, apiassets.DiscoveryInput{
		Method: record.HTTP.Method, PathTemplate: record.HTTP.PathTemplate,
		Confidence: classification.Confidence, IsAPI: effectiveIsAPI, ApplicationID: record.ApplicationID,
		ApplicationBindingID: record.ApplicationBindingID, Host: record.HTTP.Host, ProtocolType: protocol,
	})
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
