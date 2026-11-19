package apiauthz

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	objectKeySettingsGroup = "api_authz"
	objectKeySettingsKey   = "object_hmac_key"
)

type SettingsKV interface {
	GetStringWithSource(context.Context, string, string) (string, bool, error)
	CreateStringIfAbsent(context.Context, string, string, string, string, uuid.UUID) (bool, error)
}

type Encryptor interface {
	Encrypt(string) (string, error)
	Decrypt(string) (string, error)
}

const (
	objectRefDomain       = "jiuzhang-wdsp-authz-objref-v1\x00"
	candidateBatchSize    = 2000
	candidateFreezeLimit  = 8
	candidateFreezeWindow = 10 * time.Minute
)

// candidateSweepSelectQuery claims runtime events for the duration of the
// sweep transaction. The lock is deliberately scoped to e: the receipt join
// remains a read-only eligibility check while concurrent sweepers skip events
// already being processed by another worker.
const candidateSweepSelectQuery = `
SELECT e.id, ep.id, ep.application_id, ep.normalized_path, e.raw_path, e.occurred_at,
       COALESCE(e.jwt_verification->>'status',''),
       COALESCE(e.jwt_verification->>'verified_principal_id',''),
       NULLIF(e.jwt_verification->>'verified_tenant_id',''),
       COALESCE(e.jwt_verification->>'verified_identity_type','')
FROM api_runtime_events e
JOIN api_endpoints ep ON ep.endpoint_key=e.endpoint_key
LEFT JOIN api_authz_candidate_event_receipts r ON r.event_id=e.id
WHERE r.event_id IS NULL AND ep.application_id IS NOT NULL
  AND e.raw_path IS NOT NULL AND e.raw_path<>''
ORDER BY e.occurred_at, e.id
LIMIT $1
FOR UPDATE OF e SKIP LOCKED`

type CandidateSweepResult struct {
	EventsScanned      int  `json:"events_scanned"`
	CandidatesUpserted int  `json:"candidates_upserted"`
	SkippedUntrusted   int  `json:"skipped_untrusted"`
	SkippedNoMatch     int  `json:"skipped_no_match"`
	Frozen             int  `json:"frozen"`
	HasMore            bool `json:"has_more"`
}

func decodeObjectHMACKey(raw string) ([]byte, error) {
	key, err := hex.DecodeString(strings.TrimSpace(raw))
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("api authz object HMAC key must be 32-byte hex")
	}
	return key, nil
}

// LoadOrCreateObjectHMACKey returns a 32-byte hex key. The stored value is
// encrypted by the installation master key and marked sensitive by settings.
func LoadOrCreateObjectHMACKey(ctx context.Context, kv SettingsKV, enc Encryptor) (string, error) {
	if kv == nil || enc == nil {
		return "", fmt.Errorf("api authz object HMAC key dependencies are not configured")
	}
	load := func() (string, bool, error) {
		cipherText, found, err := kv.GetStringWithSource(ctx, objectKeySettingsGroup, objectKeySettingsKey)
		if err != nil {
			return "", false, fmt.Errorf("read api authz object HMAC key: %w", err)
		}
		if !found {
			return "", false, nil
		}
		cipherText = strings.TrimSpace(cipherText)
		if cipherText == "" {
			return "", false, fmt.Errorf("api authz object HMAC key setting is empty")
		}
		plain, err := enc.Decrypt(cipherText)
		if err != nil {
			return "", false, fmt.Errorf("decrypt api authz object HMAC key: %w", err)
		}
		key, err := decodeObjectHMACKey(plain)
		if err != nil {
			return "", false, err
		}
		return hex.EncodeToString(key), true, nil
	}
	if key, found, err := load(); err != nil || found {
		return key, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("generate api authz object HMAC key: %w", err)
	}
	plain := hex.EncodeToString(key)
	cipherText, err := enc.Encrypt(plain)
	if err != nil {
		return "", fmt.Errorf("encrypt api authz object HMAC key: %w", err)
	}
	created, err := kv.CreateStringIfAbsent(ctx, objectKeySettingsGroup, objectKeySettingsKey, cipherText,
		"API 对象授权引用 HMAC 密钥（密文存储）", uuid.Nil)
	if err != nil {
		return "", fmt.Errorf("store api authz object HMAC key: %w", err)
	}
	if created {
		return plain, nil
	}
	// Another initializer won the insert. Reload its encrypted value so all
	// callers use the same key, even when they generated different candidates.
	winner, found, err := load()
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("api authz object HMAC key missing after concurrent create")
	}
	return winner, nil
}

func objectReference(key []byte, objectID string) string {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(objectRefDomain))
	_, _ = h.Write([]byte(objectID))
	return "objref:" + hex.EncodeToString(h.Sum(nil))
}

func candidateIdentityEligible(status, principalID, identityType string) bool {
	if strings.ToUpper(strings.TrimSpace(status)) != "VERIFIED" || strings.TrimSpace(principalID) == "" {
		return false
	}
	switch strings.ToUpper(strings.TrimSpace(identityType)) {
	case "BOT", "SERVICE", "APPLICATION", "AGENT", "MACHINE", "TEST_BOT", "HIGH_PRIVILEGE":
		return false
	default:
		return true
	}
}

// SweepRelationCandidatesOnce consumes each runtime event exactly once. Only a
// VERIFIED principal may produce a candidate; the raw object identifier is
// converted to a dedicated-key HMAC before any authorization table write.
func (s *Store) SweepRelationCandidatesOnce(ctx context.Context, keyHex string) (*CandidateSweepResult, error) {
	key, err := decodeObjectHMACKey(keyHex)
	if err != nil {
		return nil, err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("authz candidate transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	rows, err := tx.Query(ctx, candidateSweepSelectQuery, candidateBatchSize)
	if err != nil {
		return nil, fmt.Errorf("authz candidate query: %w", err)
	}
	defer rows.Close()
	type eventRow struct {
		id, endpointID, appID uuid.UUID
		template, rawPath     string
		occurred              time.Time
		status, principal     string
		tenant                *string
		identityType          string
	}
	events := []eventRow{}
	for rows.Next() {
		var e eventRow
		if err := rows.Scan(&e.id, &e.endpointID, &e.appID, &e.template, &e.rawPath, &e.occurred,
			&e.status, &e.principal, &e.tenant, &e.identityType); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	res := &CandidateSweepResult{HasMore: len(events) == candidateBatchSize}
	if len(events) == 0 {
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return res, nil
	}
	for _, e := range events {
		res.EventsScanned++
		if !candidateIdentityEligible(e.status, e.principal, e.identityType) {
			res.SkippedUntrusted++
		} else {
			refs := extractObjectRefs(e.template, e.rawPath)
			if len(refs) == 0 {
				res.SkippedNoMatch++
			}
			for _, ref := range refs {
				objRef := objectReference(key, ref.ObjectID)
				confidence, _ := json.Marshal(map[string]any{"identity_assurance": "VERIFIED", "source": "OBSERVED_ACCESS"})
				if _, err := tx.Exec(ctx, `INSERT INTO api_object_relation_candidates
 (application_id,endpoint_id,object_type,object_ref,principal_id,tenant_id,source,status,
  source_count,observation_count,first_seen,last_seen,confidence_inputs,evidence_ref)
 VALUES ($1,$2,$3,$4,$5,$6,'OBSERVED_ACCESS','PENDING',1,1,$7,$7,$8::jsonb,$9)
 ON CONFLICT (application_id,object_type,object_ref,principal_id) WHERE principal_id IS NOT NULL
 DO UPDATE SET observation_count=api_object_relation_candidates.observation_count+1,
  first_seen=LEAST(api_object_relation_candidates.first_seen,EXCLUDED.first_seen),
  last_seen=GREATEST(api_object_relation_candidates.last_seen,EXCLUDED.last_seen),
  evidence_ref=EXCLUDED.evidence_ref,updated_at=now()`, e.appID, e.endpointID, ref.ObjectType,
					objRef, e.principal, e.tenant, e.occurred, confidence, e.id.String()); err != nil {
					return nil, fmt.Errorf("authz candidate upsert: %w", err)
				}
				res.CandidatesUpserted++
				var principals int
				if err := tx.QueryRow(ctx, `SELECT count(DISTINCT principal_id)
 FROM api_object_relation_candidates WHERE application_id=$1 AND object_type=$2 AND object_ref=$3
 AND principal_id IS NOT NULL AND last_seen >= $4`, e.appID, ref.ObjectType, objRef,
					e.occurred.Add(-candidateFreezeWindow)).Scan(&principals); err != nil {
					return nil, err
				}
				if principals > candidateFreezeLimit {
					ct, err := tx.Exec(ctx, `UPDATE api_object_relation_candidates SET status='FROZEN',updated_at=now(),
 confidence_inputs=confidence_inputs || '{"freeze_reason":"principal_fanout"}'::jsonb
 WHERE application_id=$1 AND object_type=$2 AND object_ref=$3 AND status='PENDING'`, e.appID, ref.ObjectType, objRef)
					if err != nil {
						return nil, err
					}
					res.Frozen += int(ct.RowsAffected())
				}
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO api_authz_candidate_event_receipts(event_id) VALUES ($1) ON CONFLICT DO NOTHING`, e.id); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return res, nil
}

// MigrateLegacyOwnershipOnce turns clear legacy ownership into unconfirmable,
// HMAC-addressed evidence. It is safe to retry and never creates a trusted relation.
func (s *Store) MigrateLegacyOwnershipOnce(ctx context.Context, keyHex string) (int64, error) {
	key, err := decodeObjectHMACKey(keyHex)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var status string
	if err := tx.QueryRow(ctx, `SELECT status FROM api_authz_migration_state WHERE migration_key='legacy_object_ownership_v1' FOR UPDATE`).Scan(&status); err != nil {
		return 0, err
	}
	if status == "COMPLETED" {
		return 0, nil
	}
	rows, err := tx.Query(ctx, `SELECT o.endpoint_id,ep.application_id,o.identity_fingerprint,o.object_type,o.object_id,
 o.first_seen,o.last_seen,o.access_count FROM api_object_ownership o JOIN api_endpoints ep ON ep.id=o.endpoint_id
 WHERE ep.application_id IS NOT NULL`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	type legacy struct {
		endpointID, appID uuid.UUID
		fp, typ, id       string
		first, last       time.Time
		count             int64
	}
	items := []legacy{}
	for rows.Next() {
		var v legacy
		if err := rows.Scan(&v.endpointID, &v.appID, &v.fp, &v.typ, &v.id, &v.first, &v.last, &v.count); err != nil {
			return 0, err
		}
		items = append(items, v)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `UPDATE api_authz_migration_state SET status='RUNNING',last_error='',updated_at=now() WHERE migration_key='legacy_object_ownership_v1'`); err != nil {
		return 0, err
	}
	var migrated int64
	for _, v := range items {
		ct, err := tx.Exec(ctx, `INSERT INTO api_object_relation_candidates
 (application_id,endpoint_id,object_type,object_ref,legacy_identity_fingerprint,source,status,
 source_count,observation_count,first_seen,last_seen,confidence_inputs,evidence_ref)
 VALUES ($1,$2,$3,$4,$5,'OBSERVED_ACCESS','FROZEN',1,$6,$7,$8,
 '{"identity_assurance":"LEGACY_UNVERIFIED","confirmable":false}'::jsonb,'legacy_object_ownership_v1')
 ON CONFLICT (application_id,object_type,object_ref,legacy_identity_fingerprint)
 WHERE legacy_identity_fingerprint IS NOT NULL DO NOTHING`, v.appID, v.endpointID, v.typ, objectReference(key, v.id), v.fp, v.count, v.first, v.last)
		if err != nil {
			return 0, err
		}
		migrated += ct.RowsAffected()
	}
	if _, err := tx.Exec(ctx, `UPDATE api_authz_migration_state SET status='COMPLETED',rows_migrated=$1,last_error='',updated_at=now() WHERE migration_key='legacy_object_ownership_v1'`, migrated); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return migrated, nil
}
