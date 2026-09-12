// learning_automation.go 学习自动化闭环（P0-1）的持久化方法：
// 样本落库（幂等 + 计数回填 + 来源占比上限）、达阈值任务扫描、任务完成（COMPLETED + LEARNED）。
package apiassets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// LearningJobProgress 学习任务 + 学习质量进度（000038 新列 + 成功率原料即时聚合）。
// 多条件达标判定（样本量/来源与身份多样性/学习时长/成功率）见 learningjobs/conditions.go。
type LearningJobProgress struct {
	LearningJob
	UniqueIPs         int        `json:"unique_ips"`
	UniqueIdentities  int        `json:"unique_identities"`
	FirstSampleAt     *time.Time `json:"first_sample_at,omitempty"`
	StatusSampleCount int        `json:"status_sample_count"` // 带响应状态码的 accepted 样本数（成功率分母；状态缺失不计入）
	SuccessCount      int        `json:"success_count"`       // 其中 2xx/3xx 样本数（成功率分子）
}

// LearningStartAt 学习时长判定起点：首次落样时间（真实流量起点），无落样回退任务启动时间。
func (p *LearningJobProgress) LearningStartAt() time.Time {
	if p.FirstSampleAt != nil {
		return *p.FirstSampleAt
	}
	return p.StartedAt
}

// ExcludeReasonSourceRatioCap 单一来源占比超上限的排除原因（任务书 §26 最小子集）。
const ExcludeReasonSourceRatioCap = "source_ratio_cap"

// ThresholdReached 学习任务是否已达样本阈值（sample_target>0 且有效样本数达标）。
// sample_target=0 的历史任务恒为 false，不参与阈值判定（不空转）。
func (j *LearningJob) ThresholdReached() bool {
	return j.SampleTarget > 0 && j.ValidCount >= j.SampleTarget
}

// SourceAcceptedCap 单一来源 accepted 样本上限：max(10, sample_target/2)。
func SourceAcceptedCap(sampleTarget int) int {
	return max(10, sampleTarget/2)
}

// LearningSampleHash 样本内容哈希：sha256(endpoint_key + '|' + request_id)。
// 与 (api_endpoint_id, request_id) 唯一索引同旨，供样本身份反查。
func LearningSampleHash(endpointKey, requestID string) string {
	sum := sha256.Sum256([]byte(endpointKey + "|" + requestID))
	return hex.EncodeToString(sum[:])
}

// LearningSampleInput 学习样本落库输入（采集器按网关事件构造；判定结果已含在 Accepted/ExcludeReason）。
type LearningSampleInput struct {
	EndpointKey         string
	RequestID           string
	SourceFingerprint   string
	IdentityFingerprint string
	ResponseStatus      int // 0 = 网关侧未采集到状态码（跳过状态码过滤规则）
	Accepted            bool
	ExcludeReason       string
}

// RecordLearningSample 按 endpoint_key 找到 RUNNING 学习任务并落一条样本。
// 返回 recorded=false 表示无 RUNNING 任务（正常跳过，非错误）。
// 幂等：(api_endpoint_id, request_id) 唯一索引 + ON CONFLICT DO NOTHING，
// 采集器重读不重复计数；计数（collected/valid/excluded）同事务只对实际插入的行 +1。
// 来源占比上限：同一 source_fingerprint 的 accepted 样本达 SourceAcceptedCap 后，
// 该来源后续样本改判 exclude（source_ratio_cap）。
// WithDB 浅拷贝（pool==nil，采集器批次事务窗口）时不再自开事务：落样与计数
// 并入外层批次事务（FOR UPDATE 任务行锁持有至批次提交，见 W22 设计说明）。
func (s *Store) RecordLearningSample(ctx context.Context, in LearningSampleInput) (bool, error) {
	if s.pool == nil {
		return s.recordLearningSample(ctx, s.db, in)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	recorded, err := s.recordLearningSample(ctx, tx, in)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return recorded, nil
}

// recordLearningSample 在给定句柄上执行落样与计数回填（事务边界由调用方负责）。
func (s *Store) recordLearningSample(ctx context.Context, q DBTX, in LearningSampleInput) (bool, error) {
	if in.EndpointKey == "" || in.RequestID == "" {
		// 无端点键无法归属任务；无 request_id 无法幂等去重——不落库（采集端已前置跳过）。
		return false, nil
	}
	accepted := in.Accepted
	excludeReason := strings.TrimSpace(in.ExcludeReason)
	if !accepted && excludeReason == "" {
		excludeReason = "unspecified"
	}

	// 点查 RUNNING 任务并锁任务行（FOR UPDATE 串行化并发计数更新）。
	var endpointID, jobID uuid.UUID
	var sampleTarget int
	err := q.QueryRow(ctx, `
SELECT e.id, j.id, j.sample_target
FROM api_endpoints e
JOIN api_learning_jobs j ON j.endpoint_id = e.id AND j.status = 'RUNNING'
WHERE e.endpoint_key = $1
FOR UPDATE OF j`, in.EndpointKey).Scan(&endpointID, &jobID, &sampleTarget)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	// 来源占比上限（任务书 §26 最小子集）：仅对拟 accepted 且带来源指纹的样本判定。
	if accepted && in.SourceFingerprint != "" {
		var fromSource int
		if err = q.QueryRow(ctx, `
SELECT count(*) FROM api_learning_samples
WHERE api_endpoint_id=$1 AND source_fingerprint=$2 AND accepted`,
			endpointID, in.SourceFingerprint).Scan(&fromSource); err != nil {
			return false, err
		}
		if fromSource >= SourceAcceptedCap(sampleTarget) {
			accepted = false
			excludeReason = ExcludeReasonSourceRatioCap
		}
	}

	// 幂等落样：重复 request_id 由部分唯一索引（request_id<>''）拦下，DO NOTHING。
	var sampleID uuid.UUID
	err = q.QueryRow(ctx, `
INSERT INTO api_learning_samples
  (api_endpoint_id, request_id, sample_hash, source_fingerprint, identity_fingerprint,
   response_status, accepted, exclude_reason)
VALUES ($1,$2,$3,$4,$5,NULLIF($6,0),$7,$8)
ON CONFLICT (api_endpoint_id, request_id) WHERE request_id <> '' DO NOTHING
RETURNING id`,
		endpointID, in.RequestID, LearningSampleHash(in.EndpointKey, in.RequestID),
		in.SourceFingerprint, in.IdentityFingerprint, in.ResponseStatus,
		accepted, excludeReason).Scan(&sampleID)
	if errors.Is(err, pgx.ErrNoRows) {
		// 重复样本：已落过库，不重复计数。
		return true, nil
	}
	if err != nil {
		return false, err
	}

	// 只对实际插入的行回填计数；同时重算学习质量维度（000038）：
	// unique_ips/unique_identities 按 accepted 样本的去重非空指纹整体重算
	// （选「重算」而非「增量 +1」：口径随过滤规则演进时可自愈，且无需判重先查）；
	// first_sample_at 记录首次落样时间（含被排除样本——反映真实流量起点）。
	validInc, excludedInc := 0, 0
	if accepted {
		validInc = 1
	} else {
		excludedInc = 1
	}
	if _, err = q.Exec(ctx, `
UPDATE api_learning_jobs j
SET collected_count = collected_count + 1,
    valid_count = valid_count + $2,
    excluded_count = excluded_count + $3,
    unique_ips = (SELECT count(DISTINCT source_fingerprint) FROM api_learning_samples
                  WHERE api_endpoint_id = j.endpoint_id AND accepted AND source_fingerprint <> ''),
    unique_identities = (SELECT count(DISTINCT identity_fingerprint) FROM api_learning_samples
                  WHERE api_endpoint_id = j.endpoint_id AND accepted AND identity_fingerprint <> ''),
    first_sample_at = COALESCE(first_sample_at, now())
WHERE j.id = $1`, jobID, validInc, excludedInc); err != nil {
		return false, err
	}
	return true, nil
}

// ListRunningLearningJobs 列出带样本目标的 RUNNING 学习任务（多条件判定 janitor 扫描源；
// sample_target>0 由 SQL 过滤）。除任务全列外附带 000038 学习质量维度
// （unique_ips/unique_identities/first_sample_at）与成功率原料（accepted 样本中
// 带状态码数 / 2xx/3xx 数，LATERAL 即时聚合，不落冗余列）。
func (s *Store) ListRunningLearningJobs(ctx context.Context) ([]LearningJobProgress, error) {
	rows, err := s.db.Query(ctx, `
SELECT `+learningJobColumns+`,
       j.unique_ips, j.unique_identities, j.first_sample_at,
       COALESCE(a.status_sample_count, 0), COALESCE(a.success_count, 0)
FROM api_learning_jobs j
LEFT JOIN LATERAL (
    SELECT count(*) FILTER (WHERE s.response_status IS NOT NULL) AS status_sample_count,
           count(*) FILTER (WHERE s.response_status BETWEEN 200 AND 399) AS success_count
    FROM api_learning_samples s
    WHERE s.api_endpoint_id = j.endpoint_id AND s.accepted
) a ON true
WHERE j.status='RUNNING' AND j.sample_target > 0
ORDER BY j.started_at, j.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LearningJobProgress{}
	for rows.Next() {
		var p LearningJobProgress
		err := rows.Scan(&p.ID, &p.EndpointID, &p.Status, &p.SampleTarget, &p.CollectedCount,
			&p.ValidCount, &p.ExcludedCount, &p.LastError, &p.StartedAt, &p.StoppedAt,
			&p.CreatedBy, &p.CreatedAt,
			&p.UniqueIPs, &p.UniqueIdentities, &p.FirstSampleAt,
			&p.StatusSampleCount, &p.SuccessCount)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// CompleteLearning 学习任务达标完成（事务）：任务置 COMPLETED(stopped_at=now)，
// 接口 learning_status=LEARNED，并写生命周期事件（LEARNING→LEARNED）。
// 任务不在 RUNNING 时返回 ErrLearningNotRunning。
func (s *Store) CompleteLearning(ctx context.Context, jobID, endpointID uuid.UUID, actor, reason string) (*LearningJob, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	job, err := scanLearningJob(tx.QueryRow(ctx, `
UPDATE api_learning_jobs SET status='COMPLETED', stopped_at=now()
WHERE id=$1 AND status='RUNNING'
RETURNING `+learningJobColumns, jobID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrLearningNotRunning
	}
	if err != nil {
		return nil, err
	}
	tag, err := tx.Exec(ctx, `
UPDATE api_endpoints SET learning_status='LEARNED', updated_at=now() WHERE id=$1`, endpointID)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	if _, err = tx.Exec(ctx, `
INSERT INTO api_lifecycle_events (endpoint_id, from_status, to_status, reason, actor)
VALUES ($1,'LEARNING','LEARNED',$2,$3)`, endpointID, reason, actor); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return job, nil
}

// RecordLearningError 记录学习任务最近错误（last_error；自动化环节失败可见、可排查）。
func (s *Store) RecordLearningError(ctx context.Context, jobID uuid.UUID, cause string) error {
	const maxCause = 500
	if len(cause) > maxCause {
		cause = cause[:maxCause]
	}
	tag, err := s.db.Exec(ctx, `
UPDATE api_learning_jobs SET last_error=$2 WHERE id=$1`, jobID, cause)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// FailLearning 学习任务置 FAILED（000038 超期未达标写入点）：status=FAILED +
// last_error 承载未达标说明（复用既有列，不新增 failed_reason）+ stopped_at。
// 端点 learning_status 不动：端点状态机（NOT_STARTED/LEARNING/PAUSED/LEARNED）无 FAILED 态，
// 任务级失败由任务行承载，LearningStatus 接口读最新任务即可暴露失败原因。
// 任务不在 RUNNING 时返回 ErrLearningNotRunning（并发/重复清扫安全）。
func (s *Store) FailLearning(ctx context.Context, jobID uuid.UUID, cause string) error {
	const maxCause = 500
	if len(cause) > maxCause {
		cause = cause[:maxCause]
	}
	tag, err := s.db.Exec(ctx, `
UPDATE api_learning_jobs SET status='FAILED', last_error=$2, stopped_at=now()
WHERE id=$1 AND status='RUNNING'`, jobID, cause)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrLearningNotRunning
	}
	return nil
}

// AttachLearningCandidate 回填达标自动生成的候选模型版本（candidate_version_id，任务→候选可追溯）。
// 任务不存在返回 ErrNotFound；重复回填以最后一次为准（候选创建失败重试会产生新版本）。
func (s *Store) AttachLearningCandidate(ctx context.Context, jobID, versionID uuid.UUID) error {
	tag, err := s.db.Exec(ctx, `
UPDATE api_learning_jobs SET candidate_version_id=$2 WHERE id=$1`, jobID, versionID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
