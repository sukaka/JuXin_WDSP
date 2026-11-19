package agents

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrWorkloadBinding = errors.New("workload binding is invalid")

type APIObservationReceiptStore interface {
	RecordAPIObservationReceipts(context.Context, uuid.UUID, []string, time.Time) ([]int, int, error)
}

type WorkloadBindingStore interface {
	ResolveWorkloadBinding(context.Context, uuid.UUID, uuid.UUID, int64, string, string) (*uuid.UUID, error)
}

func (s *Store) UpdateAPIObservationSchemas(ctx context.Context, agentID uuid.UUID, schemas []int16) error {
	result, err := s.db.Exec(ctx, `UPDATE agents SET api_observation_schemas=$2, updated_at=now() WHERE agent_id=$1`, agentID, schemas)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return ErrAgentNotFound
	}
	return nil
}

func (s *Store) RecordAPIObservationReceipts(ctx context.Context, agentID uuid.UUID, eventIDs []string, receivedAt time.Time) ([]int, int, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	accepted := make([]int, 0, len(eventIDs))
	duplicates := 0
	for i, eventID := range eventIDs {
		var id int64
		err := tx.QueryRow(ctx, `
INSERT INTO agent_api_observation_receipts (agent_id,event_id,received_at)
VALUES ($1,$2,$3)
ON CONFLICT (agent_id,event_id) DO NOTHING
RETURNING 1`, agentID, eventID, receivedAt.UTC()).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			duplicates++
			continue
		}
		if err != nil {
			return nil, 0, err
		}
		accepted = append(accepted, i)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, 0, err
	}
	return accepted, duplicates, nil
}

func (s *Store) DeleteAPIObservationReceipts(ctx context.Context, agentID uuid.UUID, eventIDs []string) error {
	if len(eventIDs) == 0 {
		return nil
	}
	_, err := s.db.Exec(ctx, `
DELETE FROM agent_api_observation_receipts
WHERE agent_id=$1 AND event_id = ANY($2)`, agentID, eventIDs)
	return err
}

func (s *Store) ResolveWorkloadBinding(ctx context.Context, agentID, bindingID uuid.UUID, version int64, serviceName, environment string) (*uuid.UUID, error) {
	var applicationID *uuid.UUID
	var err error
	if serviceName == "" {
		err = s.db.QueryRow(ctx, `
SELECT application_id FROM agent_workload_bindings
WHERE traffic_agent_id=$1 AND id=$2 AND binding_version=$3
  AND status='ACTIVE'`,
			agentID, bindingID, version).Scan(&applicationID)
	} else {
		err = s.db.QueryRow(ctx, `
SELECT application_id FROM agent_workload_bindings
WHERE traffic_agent_id=$1 AND id=$2 AND binding_version=$3
  AND service_name=$4 AND environment=$5 AND status='ACTIVE'`,
			agentID, bindingID, version, serviceName, environment).Scan(&applicationID)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrWorkloadBinding
	}
	if err != nil {
		return nil, err
	}
	return applicationID, nil
}
