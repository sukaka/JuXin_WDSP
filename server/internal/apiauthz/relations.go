// relations.go implements the trusted object-relation control plane introduced by
// AUTHZ-01. Observation candidates are deliberately kept outside Repository so
// older callers can continue to provide the legacy authorization repository.
package apiauthz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrCandidateNotConfirmable = errors.New("authorization relation candidate is not confirmable")
	ErrRelationConflict        = errors.New("authorization object relation conflict")
)

type CandidateFilter struct {
	ApplicationID *uuid.UUID
	Status        string
	Page          int
	PageSize      int
}

type RelationFilter struct {
	ApplicationID *uuid.UUID
	ObjectType    string
	Status        string
	Page          int
	PageSize      int
}

type DecisionFilter struct {
	ApplicationID   *uuid.UUID
	Decision        string
	IncludeEvidence bool
	Page            int
	PageSize        int
}

type AuthorizationDecision struct {
	ID            uuid.UUID      `json:"id"`
	DecisionID    uuid.UUID      `json:"decision_id"`
	ApplicationID *uuid.UUID     `json:"application_id,omitempty"`
	EndpointKey   string         `json:"endpoint_key"`
	PolicyVersion string         `json:"policy_version"`
	Decision      string         `json:"decision"`
	Checks        []any          `json:"checks"`
	Evidence      map[string]any `json:"evidence,omitempty"`
	OccurredAt    time.Time      `json:"occurred_at"`
}

type AuthorizationCoverage struct {
	ApplicationID         *uuid.UUID `json:"application_id,omitempty"`
	PendingCandidates     int64      `json:"pending_candidates"`
	ConfirmedRelations    int64      `json:"confirmed_relations"`
	Decisions             int64      `json:"decisions"`
	UnknownDecisions      int64      `json:"unknown_decisions"`
	ObserveViolations     int64      `json:"observe_violations"`
	VerifiedIdentityRate  float64    `json:"verified_identity_rate"`
	ModelCoverageRate     float64    `json:"model_coverage_rate"`
	ConfirmedRelationRate float64    `json:"confirmed_relation_rate"`
	UnknownRate           float64    `json:"unknown_rate"`
}

type ConfirmCandidateInput struct {
	Relation    string
	Reason      string
	ConfirmedBy string
	ValidUntil  *time.Time
}

type ReauthorizeRelationInput struct {
	Reason      string
	ConfirmedBy string
	ValidFrom   time.Time
	ValidUntil  *time.Time
}

const maxReauthorizeReasonRunes = 512

type RelationRepository interface {
	ListRelationCandidates(context.Context, CandidateFilter) ([]RelationCandidate, int64, error)
	ConfirmRelationCandidate(context.Context, uuid.UUID, ConfirmCandidateInput) (*ObjectRelation, error)
	RejectRelationCandidate(context.Context, uuid.UUID, string, string) (*RelationCandidate, error)
	ListObjectRelations(context.Context, RelationFilter) ([]ObjectRelation, int64, error)
	CreateObjectRelation(context.Context, *ObjectRelation) error
	RevokeObjectRelation(context.Context, uuid.UUID) (*ObjectRelation, error)
	ReauthorizeObjectRelation(context.Context, uuid.UUID, ReauthorizeRelationInput) (*ObjectRelation, error)
	ExpireObjectRelations(context.Context, time.Time) ([]ObjectRelation, error)
	ListAuthorizationDecisions(context.Context, DecisionFilter) ([]AuthorizationDecision, int64, error)
	GetAuthorizationDecision(context.Context, uuid.UUID, *uuid.UUID, bool) (*AuthorizationDecision, error)
	GetAuthorizationCoverage(context.Context, *uuid.UUID) (*AuthorizationCoverage, error)
}

func validateReauthorizeInput(in ReauthorizeRelationInput) error {
	if in.ValidFrom.IsZero() {
		return errors.New("valid_from 必填")
	}
	if strings.TrimSpace(in.Reason) == "" {
		return errors.New("reason 必填")
	}
	if utf8.RuneCountInString(strings.TrimSpace(in.Reason)) > maxReauthorizeReasonRunes {
		return errors.New("reason 不能超过 512 个字符")
	}
	if in.ValidUntil != nil && !in.ValidUntil.After(in.ValidFrom) {
		return errors.New("valid_until 必须晚于 valid_from")
	}
	return nil
}

var (
	_ RelationRepository = (*Store)(nil)
	_ RelationRepository = (*MemStore)(nil)
)

const candidateCols = `id, application_id, endpoint_id, object_type, object_ref,
	principal_id, tenant_id, legacy_identity_fingerprint, source, status,
	source_count, observation_count, confidence_inputs, evidence_ref, reject_reason,
	first_seen, last_seen, created_at, updated_at`

func scanCandidate(row pgx.Row) (*RelationCandidate, error) {
	var c RelationCandidate
	var confidence []byte
	err := row.Scan(&c.ID, &c.ApplicationID, &c.EndpointID, &c.ObjectType, &c.ObjectRef,
		&c.PrincipalID, &c.TenantID, &c.LegacyIdentityFingerprint, &c.Source, &c.Status,
		&c.SourceCount, &c.ObservationCount, &confidence, &c.EvidenceRef, &c.RejectReason,
		&c.FirstSeen, &c.LastSeen, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, err
	}
	c.ConfidenceInputs = map[string]any{}
	if len(confidence) > 0 {
		if err := json.Unmarshal(confidence, &c.ConfidenceInputs); err != nil {
			return nil, err
		}
	}
	return &c, nil
}

const relationCols = `id, application_id, object_type, object_ref, principal_id,
	tenant_id, relation, source, status, valid_from, valid_until, evidence_ref,
	confirmed_by, confirmed_at, reason, created_at, updated_at`

const decisionCols = `id, decision_id, application_id, endpoint_key, policy_version,
	decision, checks, evidence, occurred_at`

func scanDecision(row pgx.Row, includeEvidence bool) (*AuthorizationDecision, error) {
	var d AuthorizationDecision
	var checks, evidence []byte
	if err := row.Scan(&d.ID, &d.DecisionID, &d.ApplicationID, &d.EndpointKey, &d.PolicyVersion,
		&d.Decision, &checks, &evidence, &d.OccurredAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(checks, &d.Checks); err != nil {
		return nil, err
	}
	if includeEvidence {
		d.Evidence = map[string]any{}
		if err := json.Unmarshal(evidence, &d.Evidence); err != nil {
			return nil, err
		}
	}
	return &d, nil
}

func scanRelation(row pgx.Row) (*ObjectRelation, error) {
	var r ObjectRelation
	err := row.Scan(&r.ID, &r.ApplicationID, &r.ObjectType, &r.ObjectRef, &r.PrincipalID,
		&r.TenantID, &r.Relation, &r.Source, &r.Status, &r.ValidFrom, &r.ValidUntil,
		&r.EvidenceRef, &r.ConfirmedBy, &r.ConfirmedAt, &r.Reason, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Store) ListRelationCandidates(ctx context.Context, f CandidateFilter) ([]RelationCandidate, int64, error) {
	f.Page, f.PageSize = normPage(f.Page, f.PageSize)
	where, args := []string{}, []any{}
	if f.ApplicationID != nil {
		args = append(args, *f.ApplicationID)
		where = append(where, fmt.Sprintf("application_id = $%d", len(args)))
	}
	if f.Status != "" {
		args = append(args, f.Status)
		where = append(where, fmt.Sprintf("status = $%d", len(args)))
	}
	cond := buildCond(where, args)
	var total int64
	if err := s.db.QueryRow(ctx, "SELECT count(*) FROM api_object_relation_candidates"+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, `SELECT `+candidateCols+` FROM api_object_relation_candidates`+cond+
		fmt.Sprintf(" ORDER BY last_seen DESC, id LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []RelationCandidate{}
	for rows.Next() {
		c, err := scanCandidate(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *c)
	}
	return out, total, rows.Err()
}

func (s *Store) ConfirmRelationCandidate(ctx context.Context, id uuid.UUID, in ConfirmCandidateInput) (*ObjectRelation, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck -- commit decides the transaction outcome
	c, err := scanCandidate(tx.QueryRow(ctx, `SELECT `+candidateCols+` FROM api_object_relation_candidates WHERE id=$1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if c.Status != CandidateStatusPending || c.PrincipalID == nil || c.LegacyIdentityFingerprint != nil {
		return nil, ErrCandidateNotConfirmable
	}
	relation := strings.ToUpper(strings.TrimSpace(in.Relation))
	if relation != RelationOwner {
		return nil, errors.New("候选确认仅允许 OWNER 关系")
	}
	now := time.Now().UTC()
	rel := &ObjectRelation{
		ApplicationID: c.ApplicationID, ObjectType: c.ObjectType, ObjectRef: c.ObjectRef,
		PrincipalID: *c.PrincipalID, TenantID: c.TenantID, Relation: relation,
		Source: RelationSourceCreateBinding, Status: RelationStatusConfirmed, ValidFrom: now,
		ValidUntil: in.ValidUntil, EvidenceRef: c.EvidenceRef, ConfirmedBy: in.ConfirmedBy,
		ConfirmedAt: now, Reason: strings.TrimSpace(in.Reason),
	}
	if err := validateObjectRelation(rel); err != nil {
		return nil, err
	}
	err = tx.QueryRow(ctx, `INSERT INTO api_object_relations
		(application_id, object_type, object_ref, principal_id, tenant_id, relation, source,
		 status, valid_from, valid_until, evidence_ref, confirmed_by, confirmed_at, reason)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		RETURNING id, created_at, updated_at`, rel.ApplicationID, rel.ObjectType, rel.ObjectRef,
		rel.PrincipalID, rel.TenantID, rel.Relation, rel.Source, rel.Status, rel.ValidFrom,
		rel.ValidUntil, rel.EvidenceRef, rel.ConfirmedBy, rel.ConfirmedAt, rel.Reason).
		Scan(&rel.ID, &rel.CreatedAt, &rel.UpdatedAt)
	if isUniqueViolation(err) {
		return nil, ErrRelationConflict
	}
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE api_object_relation_candidates SET status='CONFIRMED',
		reviewed_by=$2, reviewed_at=$3, updated_at=$3 WHERE id=$1`, id, in.ConfirmedBy, now); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return rel, nil
}

func (s *Store) RejectRelationCandidate(ctx context.Context, id uuid.UUID, reason, reviewedBy string) (*RelationCandidate, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return nil, errors.New("reason 必填")
	}
	c, err := scanCandidate(s.db.QueryRow(ctx, `UPDATE api_object_relation_candidates
		SET status='REJECTED', reject_reason=$2, reviewed_by=$3, reviewed_at=now(), updated_at=now()
		WHERE id=$1 AND status='PENDING' RETURNING `+candidateCols, id, reason, reviewedBy))
	if errors.Is(err, pgx.ErrNoRows) {
		var exists bool
		if qerr := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM api_object_relation_candidates WHERE id=$1)`, id).Scan(&exists); qerr != nil {
			return nil, qerr
		}
		if !exists {
			return nil, ErrNotFound
		}
		return nil, ErrCandidateNotConfirmable
	}
	return c, err
}

func (s *Store) ListObjectRelations(ctx context.Context, f RelationFilter) ([]ObjectRelation, int64, error) {
	f.Page, f.PageSize = normPage(f.Page, f.PageSize)
	where, args := []string{}, []any{}
	if f.ApplicationID != nil {
		args = append(args, *f.ApplicationID)
		where = append(where, fmt.Sprintf("application_id = $%d", len(args)))
	}
	if f.ObjectType != "" {
		args = append(args, f.ObjectType)
		where = append(where, fmt.Sprintf("object_type = $%d", len(args)))
	}
	if f.Status != "" {
		args = append(args, f.Status)
		where = append(where, fmt.Sprintf("status = $%d", len(args)))
	}
	cond := buildCond(where, args)
	var total int64
	if err := s.db.QueryRow(ctx, "SELECT count(*) FROM api_object_relations"+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, `SELECT `+relationCols+` FROM api_object_relations`+cond+
		fmt.Sprintf(" ORDER BY created_at DESC, id LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []ObjectRelation{}
	for rows.Next() {
		r, err := scanRelation(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *r)
	}
	return out, total, rows.Err()
}

func (s *Store) CreateObjectRelation(ctx context.Context, r *ObjectRelation) error {
	if r.ValidFrom.IsZero() {
		r.ValidFrom = time.Now().UTC()
	}
	if err := validateObjectRelation(r); err != nil {
		return err
	}
	r.Status = RelationStatusConfirmed
	r.ConfirmedAt = time.Now().UTC()
	err := s.db.QueryRow(ctx, `INSERT INTO api_object_relations
		(application_id, object_type, object_ref, principal_id, tenant_id, relation, source,
		 status, valid_from, valid_until, evidence_ref, confirmed_by, confirmed_at, reason)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		RETURNING id, created_at, updated_at`, r.ApplicationID, r.ObjectType, r.ObjectRef,
		r.PrincipalID, r.TenantID, r.Relation, r.Source, r.Status, r.ValidFrom, r.ValidUntil,
		r.EvidenceRef, r.ConfirmedBy, r.ConfirmedAt, r.Reason).Scan(&r.ID, &r.CreatedAt, &r.UpdatedAt)
	if isUniqueViolation(err) {
		return ErrRelationConflict
	}
	if isForeignKeyViolation(err) {
		return ErrNotFound
	}
	return err
}

// RevokeObjectRelation changes only an active relation. Historical rows are
// retained so the compiler and audit views can distinguish revocation from
// expiry and repeated requests cannot resurrect a relation.
// NG-AZ-02 D1：撤销事实与手工水位推进（manual_seq+1）同一事务原子提交。
func (s *Store) RevokeObjectRelation(ctx context.Context, id uuid.UUID) (*ObjectRelation, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck -- commit decides the transaction outcome
	r, err := scanRelation(tx.QueryRow(ctx, `UPDATE api_object_relations
		SET status='REVOKED', updated_at=now()
		WHERE id=$1 AND status='CONFIRMED'
		RETURNING `+relationCols, id))
	if errors.Is(err, pgx.ErrNoRows) {
		var exists bool
		if qerr := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM api_object_relations WHERE id=$1)`, id).Scan(&exists); qerr != nil {
			return nil, qerr
		}
		if !exists {
			return nil, ErrNotFound
		}
		return nil, ErrRelationConflict
	}
	if err != nil {
		return nil, err
	}
	if err := bumpManualRevocationSeq(ctx, tx); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

// bumpManualRevocationSeq 手工撤销水位推进（NG-AZ-02 D1；调用方保证在撤销事实的
// 同一事务内调用——水位与事实原子提交；单行 upsert 只增）。
func bumpManualRevocationSeq(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `
INSERT INTO api_authz_manual_revocation_seq (id, seq) VALUES (1, 1)
ON CONFLICT (id) DO UPDATE SET seq = api_authz_manual_revocation_seq.seq + 1`)
	if err != nil {
		return fmt.Errorf("bump manual revocation seq: %w", err)
	}
	return nil
}

// ReauthorizeObjectRelation is the explicit audited state transition for a
// historical relation. Ordinary create/confirm paths intentionally remain
// conflict-only for retained REVOKED/EXPIRED rows.
func (s *Store) ReauthorizeObjectRelation(ctx context.Context, id uuid.UUID, in ReauthorizeRelationInput) (*ObjectRelation, error) {
	if err := validateReauthorizeInput(in); err != nil {
		return nil, err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck -- commit decides the transaction outcome
	var previousStatus string
	if err := tx.QueryRow(ctx, `SELECT status FROM api_object_relations WHERE id=$1 FOR UPDATE`, id).Scan(&previousStatus); errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	if previousStatus != "REVOKED" && previousStatus != "EXPIRED" {
		return nil, ErrRelationConflict
	}
	r, err := scanRelation(tx.QueryRow(ctx, `UPDATE api_object_relations
		SET status='CONFIRMED', valid_from=$2, valid_until=$3, confirmed_by=$4,
			confirmed_at=now(), reason=$5, updated_at=now()
		WHERE id=$1
		RETURNING `+relationCols, id, in.ValidFrom.UTC(), in.ValidUntil, strings.TrimSpace(in.ConfirmedBy), strings.TrimSpace(in.Reason)))
	if err != nil {
		return nil, err
	}
	r.PreviousStatus = previousStatus
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

// ExpireObjectRelations atomically marks due confirmed relations expired and
// returns the changed rows. The caller owns the publication and audit hooks.
// NG-AZ-02 D1：到期废止与手工水位推进同一事务（有行变更才推进——空扫不抬水位）。
func (s *Store) ExpireObjectRelations(ctx context.Context, now time.Time) ([]ObjectRelation, error) {
	now = now.UTC()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck -- commit decides the transaction outcome
	rows, err := tx.Query(ctx, `UPDATE api_object_relations
		SET status='EXPIRED', updated_at=$1
		WHERE status='CONFIRMED' AND valid_until IS NOT NULL AND valid_until <= $1
		RETURNING `+relationCols, now)
	if err != nil {
		return nil, err
	}
	out := []ObjectRelation{}
	for rows.Next() {
		r, err := scanRelation(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, *r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	if len(out) > 0 {
		if err := bumpManualRevocationSeq(ctx, tx); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) ListAuthorizationDecisions(ctx context.Context, f DecisionFilter) ([]AuthorizationDecision, int64, error) {
	f.Page, f.PageSize = normPage(f.Page, f.PageSize)
	where, args := []string{}, []any{}
	if f.ApplicationID != nil {
		args = append(args, *f.ApplicationID)
		where = append(where, fmt.Sprintf("application_id = $%d", len(args)))
	}
	if f.Decision != "" {
		args = append(args, f.Decision)
		where = append(where, fmt.Sprintf("decision = $%d", len(args)))
	}
	cond := buildCond(where, args)
	var total int64
	if err := s.db.QueryRow(ctx, "SELECT count(*) FROM api_authorization_decisions"+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, `SELECT `+decisionCols+` FROM api_authorization_decisions`+cond+
		fmt.Sprintf(" ORDER BY occurred_at DESC, id LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []AuthorizationDecision{}
	for rows.Next() {
		d, err := scanDecision(rows, f.IncludeEvidence)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *d)
	}
	return out, total, rows.Err()
}

// GetAuthorizationDecision reads one decision. applicationID is an optional
// tenant boundary: a mismatched application is intentionally indistinguishable
// from a missing decision (404 at the HTTP layer).
func (s *Store) GetAuthorizationDecision(ctx context.Context, id uuid.UUID, applicationID *uuid.UUID, includeEvidence bool) (*AuthorizationDecision, error) {
	where := []string{"id = $1"}
	args := []any{id}
	if applicationID != nil {
		args = append(args, *applicationID)
		where = append(where, fmt.Sprintf("application_id = $%d", len(args)))
	}
	d, err := scanDecision(s.db.QueryRow(ctx, "SELECT "+decisionCols+" FROM api_authorization_decisions WHERE "+strings.Join(where, " AND "), args...), includeEvidence)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return d, nil
}

func (s *Store) GetAuthorizationCoverage(ctx context.Context, appID *uuid.UUID) (*AuthorizationCoverage, error) {
	result := &AuthorizationCoverage{ApplicationID: appID}
	var appArg any
	if appID != nil {
		appArg = *appID
	}
	err := s.db.QueryRow(ctx, `WITH
		runtime AS (
			SELECT e.jwt_verification
			FROM api_runtime_events e
			JOIN api_endpoints ep ON ep.endpoint_key=e.endpoint_key
			WHERE ($1::uuid IS NULL OR ep.application_id=$1)
		),
		models AS (
			SELECT DISTINCT ep.id,
				bool_or(m.publishable AND m.required_relation IN ('OWNER','ANY_OF') AND m.owner_exclusive) AS covered
			FROM api_endpoints ep
			LEFT JOIN api_object_models m ON m.endpoint_id=ep.id
			WHERE ep.status='CONFIRMED' AND ($1::uuid IS NULL OR ep.application_id=$1)
			GROUP BY ep.id
		),
		candidate_objects AS (
			SELECT DISTINCT application_id, object_type, object_ref
			FROM api_object_relation_candidates
			WHERE ($1::uuid IS NULL OR application_id=$1)
		),
		active_relation_objects AS (
			SELECT DISTINCT application_id, object_type, object_ref
			FROM api_object_relations
			WHERE status='CONFIRMED' AND valid_from<=now() AND (valid_until IS NULL OR valid_until>now())
				AND ($1::uuid IS NULL OR application_id=$1)
		)
	SELECT
		(SELECT count(*) FROM api_object_relation_candidates WHERE status='PENDING' AND ($1::uuid IS NULL OR application_id=$1)),
		(SELECT count(*) FROM api_object_relations WHERE status='CONFIRMED' AND valid_from<=now() AND (valid_until IS NULL OR valid_until>now()) AND ($1::uuid IS NULL OR application_id=$1)),
		(SELECT count(*) FROM api_authorization_decisions WHERE ($1::uuid IS NULL OR application_id=$1)),
		(SELECT count(*) FROM api_authorization_decisions WHERE decision='UNKNOWN' AND ($1::uuid IS NULL OR application_id=$1)),
		(SELECT count(*) FROM api_authorization_decisions WHERE decision='OBSERVE_VIOLATION' AND ($1::uuid IS NULL OR application_id=$1)),
		COALESCE((SELECT count(*) FILTER (WHERE jwt_verification->>'status'='VERIFIED' AND COALESCE(jwt_verification->>'verified_principal_id','')<>'')::float8 / NULLIF(count(*),0) FROM runtime),0),
		COALESCE((SELECT count(*) FILTER (WHERE covered)::float8 / NULLIF(count(*),0) FROM models),0),
		COALESCE((SELECT count(*)::float8 / NULLIF((SELECT count(*) FROM candidate_objects),0) FROM active_relation_objects),0),
		COALESCE((SELECT count(*) FILTER (WHERE decision='UNKNOWN')::float8 / NULLIF(count(*),0) FROM api_authorization_decisions WHERE ($1::uuid IS NULL OR application_id=$1)),0)`, appArg).Scan(
		&result.PendingCandidates, &result.ConfirmedRelations, &result.Decisions,
		&result.UnknownDecisions, &result.ObserveViolations, &result.VerifiedIdentityRate,
		&result.ModelCoverageRate, &result.ConfirmedRelationRate, &result.UnknownRate)
	if err != nil {
		return nil, err
	}
	if result.ConfirmedRelationRate > 1 {
		result.ConfirmedRelationRate = 1
	}
	return result, nil
}
