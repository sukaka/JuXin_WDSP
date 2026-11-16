package apidataflow

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jiuzhang-waf/server/internal/apm"
)

type ContributionStore interface {
	SaveContributions(context.Context, []Contribution) error
}

type CHContributionStore struct {
	resolve func(context.Context) apm.CHQuerier
	now     func() time.Time
}

func NewCHContributionStore(resolve func(context.Context) apm.CHQuerier) *CHContributionStore {
	return &CHContributionStore{resolve: resolve, now: time.Now}
}

func (s *CHContributionStore) executor(ctx context.Context) (chExecutor, error) {
	return (&CHObservationStore{resolve: s.resolve}).executor(ctx)
}

func (s *CHContributionStore) SaveContributions(ctx context.Context, records []Contribution) error {
	if len(records) == 0 {
		return nil
	}
	executor, err := s.executor(ctx)
	if err != nil {
		return err
	}
	args := make([]any, 0, len(records)*31)
	for _, record := range records {
		dataTypes, err := json.Marshal(record.DataTypes)
		if err != nil {
			return err
		}
		args = append(args,
			record.AgentID, record.EventID, record.EdgeID, record.OccurredAt.UTC(), s.now().UTC(), nullableUUID(record.ApplicationID),
			record.SourceNode, record.SourceType, record.TargetNode, record.TargetType, record.Protocol,
			record.Method, record.PathTemplate, record.Status, record.LatencyMS, record.Error, record.CountWeight, string(dataTypes),
			fieldEvidenceJSON(record.Fields), record.EvidenceType, record.Confidence, record.TraceID, record.SpanID,
			record.PeerAddress, record.ClientAddress, record.ClientAddressSource, record.ServerAddress,
			record.SourceZone, record.TargetZone, record.BoundaryType, record.BoundaryEvidence,
		)
	}
	query := insertValuesSQL("wdsp.data_flow_contributions", []string{
		"agent_id", "event_id", "edge_id", "occurred_at", "received_at", "application_id",
		"source_node", "source_type", "target_node", "target_type", "protocol", "method", "path_template", "status", "latency_ms",
		"error", "count_weight", "data_types_json", "field_evidence_json", "evidence_type", "confidence", "trace_id", "span_id",
		"peer_address", "client_address", "client_address_source", "server_address", "source_zone", "target_zone", "boundary_type", "boundary_evidence",
	}, len(records))
	return executor.Exec(ctx, query, args...)
}
