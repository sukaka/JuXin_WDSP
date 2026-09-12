package apiauthz

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

func cloneCandidate(in *RelationCandidate) *RelationCandidate {
	out := *in
	if in.EndpointID != nil {
		v := *in.EndpointID
		out.EndpointID = &v
	}
	if in.PrincipalID != nil {
		v := *in.PrincipalID
		out.PrincipalID = &v
	}
	if in.TenantID != nil {
		v := *in.TenantID
		out.TenantID = &v
	}
	if in.LegacyIdentityFingerprint != nil {
		v := *in.LegacyIdentityFingerprint
		out.LegacyIdentityFingerprint = &v
	}
	if in.EvidenceRef != nil {
		v := *in.EvidenceRef
		out.EvidenceRef = &v
	}
	if in.RejectReason != nil {
		v := *in.RejectReason
		out.RejectReason = &v
	}
	out.ConfidenceInputs = map[string]any{}
	for k, v := range in.ConfidenceInputs {
		out.ConfidenceInputs[k] = v
	}
	return &out
}

func cloneRelation(in *ObjectRelation) *ObjectRelation {
	out := *in
	if in.TenantID != nil {
		v := *in.TenantID
		out.TenantID = &v
	}
	if in.ValidUntil != nil {
		v := *in.ValidUntil
		out.ValidUntil = &v
	}
	if in.EvidenceRef != nil {
		v := *in.EvidenceRef
		out.EvidenceRef = &v
	}
	return &out
}

func cloneDecision(in *AuthorizationDecision, includeEvidence bool) *AuthorizationDecision {
	out := *in
	out.Checks = append([]any(nil), in.Checks...)
	if includeEvidence && in.Evidence != nil {
		out.Evidence = make(map[string]any, len(in.Evidence))
		for k, v := range in.Evidence {
			out.Evidence[k] = v
		}
	} else {
		out.Evidence = nil
	}
	return &out
}

// addRelationCandidate seeds observations in handler and collector tests.
func (m *MemStore) addRelationCandidate(in RelationCandidate) *RelationCandidate {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	if in.ID == uuid.Nil {
		in.ID = uuid.New()
	}
	if in.Source == "" {
		in.Source = CandidateSourceObserved
	}
	if in.Status == "" {
		in.Status = CandidateStatusPending
	}
	if in.SourceCount == 0 {
		in.SourceCount = 1
	}
	if in.ObservationCount == 0 {
		in.ObservationCount = 1
	}
	if in.FirstSeen.IsZero() {
		in.FirstSeen = now
	}
	if in.LastSeen.IsZero() {
		in.LastSeen = now
	}
	if in.CreatedAt.IsZero() {
		in.CreatedAt = now
	}
	in.UpdatedAt = now
	if in.ConfidenceInputs == nil {
		in.ConfidenceInputs = map[string]any{}
	}
	c := cloneCandidate(&in)
	m.relationCandidates[c.ID] = c
	return cloneCandidate(c)
}

func (m *MemStore) ListRelationCandidates(_ context.Context, f CandidateFilter) ([]RelationCandidate, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	items := []RelationCandidate{}
	for _, c := range m.relationCandidates {
		if f.ApplicationID != nil && c.ApplicationID != *f.ApplicationID {
			continue
		}
		if f.Status != "" && c.Status != f.Status {
			continue
		}
		items = append(items, *cloneCandidate(c))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].LastSeen.After(items[j].LastSeen) })
	total := int64(len(items))
	return paginate(items, f.Page, f.PageSize), total, nil
}

func relationUniqueKey(r *ObjectRelation) string {
	return r.ApplicationID.String() + "|" + r.ObjectType + "|" + r.ObjectRef + "|" + r.PrincipalID + "|" + r.Relation
}

func (m *MemStore) relationKeyExists(key string) bool {
	for _, r := range m.relations {
		if relationUniqueKey(r) == key {
			return true
		}
	}
	return false
}

func (m *MemStore) ConfirmRelationCandidate(_ context.Context, id uuid.UUID, in ConfirmCandidateInput) (*ObjectRelation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.relationCandidates[id]
	if !ok {
		return nil, ErrNotFound
	}
	if c.Status != CandidateStatusPending || c.PrincipalID == nil || c.LegacyIdentityFingerprint != nil {
		return nil, ErrCandidateNotConfirmable
	}
	now := time.Now().UTC()
	r := &ObjectRelation{
		ID: uuid.New(), ApplicationID: c.ApplicationID, ObjectType: c.ObjectType, ObjectRef: c.ObjectRef,
		PrincipalID: *c.PrincipalID, TenantID: c.TenantID, Relation: strings.ToUpper(strings.TrimSpace(in.Relation)),
		Source: RelationSourceCreateBinding, Status: RelationStatusConfirmed, ValidFrom: now,
		ValidUntil: in.ValidUntil, EvidenceRef: c.EvidenceRef, ConfirmedBy: in.ConfirmedBy,
		ConfirmedAt: now, Reason: strings.TrimSpace(in.Reason), CreatedAt: now, UpdatedAt: now,
	}
	if err := validateObjectRelation(r); err != nil {
		return nil, err
	}
	if m.relationKeyExists(relationUniqueKey(r)) {
		return nil, ErrRelationConflict
	}
	m.relations[r.ID] = cloneRelation(r)
	c.Status = CandidateStatusConfirmed
	c.UpdatedAt = now
	return cloneRelation(r), nil
}

func (m *MemStore) RejectRelationCandidate(_ context.Context, id uuid.UUID, reason, _ string) (*RelationCandidate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.relationCandidates[id]
	if !ok {
		return nil, ErrNotFound
	}
	if c.Status != CandidateStatusPending {
		return nil, ErrCandidateNotConfirmable
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return nil, errors.New("reason 必填")
	}
	c.Status = CandidateStatusRejected
	c.RejectReason = &reason
	c.UpdatedAt = time.Now().UTC()
	return cloneCandidate(c), nil
}

func (m *MemStore) ListObjectRelations(_ context.Context, f RelationFilter) ([]ObjectRelation, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	items := []ObjectRelation{}
	for _, r := range m.relations {
		if f.ApplicationID != nil && r.ApplicationID != *f.ApplicationID {
			continue
		}
		if f.ObjectType != "" && r.ObjectType != f.ObjectType {
			continue
		}
		if f.Status != "" && r.Status != f.Status {
			continue
		}
		items = append(items, *cloneRelation(r))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.After(items[j].CreatedAt) })
	total := int64(len(items))
	return paginate(items, f.Page, f.PageSize), total, nil
}

func (m *MemStore) CreateObjectRelation(_ context.Context, r *ObjectRelation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r.ValidFrom.IsZero() {
		r.ValidFrom = time.Now().UTC()
	}
	if err := validateObjectRelation(r); err != nil {
		return err
	}
	if m.relationKeyExists(relationUniqueKey(r)) {
		return ErrRelationConflict
	}
	now := time.Now().UTC()
	r.ID = uuid.New()
	r.Status = RelationStatusConfirmed
	r.ConfirmedAt = now
	r.CreatedAt = now
	r.UpdatedAt = now
	m.relations[r.ID] = cloneRelation(r)
	return nil
}

func (m *MemStore) RevokeObjectRelation(_ context.Context, id uuid.UUID) (*ObjectRelation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.relations[id]
	if !ok {
		return nil, ErrNotFound
	}
	if r.Status != RelationStatusConfirmed {
		return nil, ErrRelationConflict
	}
	r.Status = RelationStatusRevoked
	r.UpdatedAt = time.Now().UTC()
	return cloneRelation(r), nil
}

func (m *MemStore) ReauthorizeObjectRelation(_ context.Context, id uuid.UUID, in ReauthorizeRelationInput) (*ObjectRelation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := validateReauthorizeInput(in); err != nil {
		return nil, err
	}
	r, ok := m.relations[id]
	if !ok {
		return nil, ErrNotFound
	}
	if r.Status != RelationStatusRevoked && r.Status != RelationStatusExpired {
		return nil, ErrRelationConflict
	}
	r.PreviousStatus = r.Status
	now := time.Now().UTC()
	r.Status = RelationStatusConfirmed
	r.ValidFrom = in.ValidFrom.UTC()
	if in.ValidUntil == nil {
		r.ValidUntil = nil
	} else {
		until := in.ValidUntil.UTC()
		r.ValidUntil = &until
	}
	r.ConfirmedBy = strings.TrimSpace(in.ConfirmedBy)
	r.ConfirmedAt = now
	r.Reason = strings.TrimSpace(in.Reason)
	r.UpdatedAt = now
	return cloneRelation(r), nil
}

func (m *MemStore) ExpireObjectRelations(_ context.Context, now time.Time) ([]ObjectRelation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now = now.UTC()
	out := []ObjectRelation{}
	for _, r := range m.relations {
		if r.Status == RelationStatusConfirmed && r.ValidUntil != nil && !now.Before(r.ValidUntil.UTC()) {
			r.Status = RelationStatusExpired
			r.UpdatedAt = now
			out = append(out, *cloneRelation(r))
		}
	}
	return out, nil
}

func (m *MemStore) ListAuthorizationDecisions(_ context.Context, f DecisionFilter) ([]AuthorizationDecision, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f.Page, f.PageSize = normPage(f.Page, f.PageSize)
	items := make([]AuthorizationDecision, 0, len(m.decisions))
	for _, d := range m.decisions {
		if f.ApplicationID != nil && (d.ApplicationID == nil || *d.ApplicationID != *f.ApplicationID) {
			continue
		}
		if f.Decision != "" && d.Decision != f.Decision {
			continue
		}
		items = append(items, *cloneDecision(d, f.IncludeEvidence))
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].OccurredAt.Equal(items[j].OccurredAt) {
			return items[i].ID.String() < items[j].ID.String()
		}
		return items[i].OccurredAt.After(items[j].OccurredAt)
	})
	total := int64(len(items))
	return paginate(items, f.Page, f.PageSize), total, nil
}

// addAuthorizationDecision seeds a decision fixture for handler tests.
func (m *MemStore) addAuthorizationDecision(in AuthorizationDecision) *AuthorizationDecision {
	m.mu.Lock()
	defer m.mu.Unlock()
	if in.ID == uuid.Nil {
		in.ID = uuid.New()
	}
	if in.DecisionID == uuid.Nil {
		in.DecisionID = uuid.New()
	}
	if in.OccurredAt.IsZero() {
		in.OccurredAt = time.Now().UTC()
	}
	d := cloneDecision(&in, true)
	m.decisions[d.ID] = d
	return cloneDecision(d, true)
}

func (m *MemStore) GetAuthorizationDecision(_ context.Context, id uuid.UUID, applicationID *uuid.UUID, includeEvidence bool) (*AuthorizationDecision, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.decisions[id]
	if !ok || (applicationID != nil && (d.ApplicationID == nil || *d.ApplicationID != *applicationID)) {
		return nil, ErrNotFound
	}
	return cloneDecision(d, includeEvidence), nil
}

func (m *MemStore) GetAuthorizationCoverage(_ context.Context, appID *uuid.UUID) (*AuthorizationCoverage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := &AuthorizationCoverage{ApplicationID: appID}
	now := time.Now().UTC()
	candidateObjects := map[string]struct{}{}
	activeRelationObjects := map[string]struct{}{}
	for _, c := range m.relationCandidates {
		if appID != nil && c.ApplicationID != *appID {
			continue
		}
		if c.Status == CandidateStatusPending {
			out.PendingCandidates++
		}
		candidateObjects[c.ApplicationID.String()+"|"+c.ObjectType+"|"+c.ObjectRef] = struct{}{}
	}
	for _, r := range m.relations {
		active := r.Status == RelationStatusConfirmed &&
			!r.ValidFrom.After(now) && (r.ValidUntil == nil || r.ValidUntil.After(now))
		if appID != nil && r.ApplicationID != *appID {
			continue
		}
		if active {
			out.ConfirmedRelations++
			activeRelationObjects[r.ApplicationID.String()+"|"+r.ObjectType+"|"+r.ObjectRef] = struct{}{}
		}
	}
	for _, d := range m.decisions {
		if appID != nil && (d.ApplicationID == nil || *d.ApplicationID != *appID) {
			continue
		}
		out.Decisions++
		switch d.Decision {
		case "UNKNOWN":
			out.UnknownDecisions++
		case "OBSERVE_VIOLATION":
			out.ObserveViolations++
		}
	}
	if len(candidateObjects) > 0 {
		out.ConfirmedRelationRate = float64(len(activeRelationObjects)) / float64(len(candidateObjects))
		if out.ConfirmedRelationRate > 1 {
			out.ConfirmedRelationRate = 1
		}
	}
	if out.Decisions > 0 {
		out.UnknownRate = float64(out.UnknownDecisions) / float64(out.Decisions)
	}
	return out, nil
}
