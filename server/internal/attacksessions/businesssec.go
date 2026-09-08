// businesssec.go Business 滥用检测（WDSP AI 自动化渗透防护增强 阶段4；设计 #12.2 / #13）。
// 每轮 Sweep 顺带判定，产出写 identity_behavior_events（event_kind='BUSINESS_ABUSE'，
// mode=OBSERVE，rule_version=1.0.0），天然汇入会话聚合（主锚 identity_id 直挂）。
// 默认 OBSERVE，不接处置；阈值均为包级常量，注释说明后续进策略（behavior/risk policy）。
//
// 三个判定器：
//
//	(a) Login Abuse      同身份多凭据 + 认证失败超阈（BIZ-LOGIN-001）；
//	(b) Export Abuse     身份 × business_type=EXPORT 端点滑窗计数超阈（BIZ-EXPORT-001，
//	                     仅覆盖 WDSP 流量——api_runtime_events 仅 API 动态防护开启时产生）；
//	(c) Object Enumeration 同身份/指纹对同路径模板不同对象 ID 序列访问
//	                     （数字 ID 连续或高基数十枚举；BIZ-OBJENUM-001）。
package attacksessions

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// 检测规则契约（identity_behavior_events.rule_code / signal；rule_version 恒 1.0.0）。
const (
	RuleLoginAbuse  = "BIZ-LOGIN-001"
	RuleExportAbuse = "BIZ-EXPORT-001"
	RuleObjectEnum  = "BIZ-OBJENUM-001"

	SignalLoginAbuse  = "LOGIN_ABUSE"
	SignalExportAbuse = "EXPORT_ABUSE"
	SignalObjectEnum  = "OBJECT_ENUMERATION"

	bizRuleVersion = "1.0.0"
	bizEventKind   = "BUSINESS_ABUSE"
)

// 阈值常量（后续进策略——行为策略/风险策略体系；本期固定常量）。
const (
	// LoginAbuseCredThreshold 同身份近 24h 不同凭据数阈值（默认 5；多账号代理——
	// identity_credential 无 account_id 列，迁移 000097 只存 credential_hash，
	// 以 distinct credential_hash 近似多账号：同账号多凭据会高估、注释说明）。
	LoginAbuseCredThreshold = 5
	// LoginAbuseFailThreshold 同身份近 24h（30m 窗口行）认证失败累计阈值（默认 10）。
	LoginAbuseFailThreshold = 10
	// ExportAbuseThreshold 同身份/指纹 10min 滑窗 EXPORT 端点请求数阈值（默认 20）。
	ExportAbuseThreshold = 20
	// ObjectEnumThreshold 同身份/指纹同路径模板 10min 滑窗不同对象 ID 数阈值（默认 10）。
	ObjectEnumThreshold = 10

	// bizScoreDelta 三类滥用事件风险分增量（默认 15/15/15，OBSERVE 仅观测）。
	bizScoreDelta = 15
	// bizWindow 滑窗宽度（Export/ObjectEnum）。
	bizWindow = 10 * time.Minute
	// bizLoginLookback Login Abuse 凭据/失败回看窗。
	bizLoginLookback = 24 * time.Hour
	// bizCooldown 同身份同规则产出冷却（防止每轮重复产出造成会话风险分膨胀）。
	bizCooldown = 30 * time.Minute
)

// LoginAbuseHit Login Abuse 候选行。
type LoginAbuseHit struct {
	IdentityID      uuid.UUID
	IdentityKey     string
	CredentialCount int
	AuthFailCount   int64
}

// ExportAbuseHit Export Abuse 候选行（identity_fingerprint 属凭据指纹域，
// 与 client_identity 不可 join——归属经 client_ip 反查）。
type ExportAbuseHit struct {
	ClientIP            string
	IdentityFingerprint string
	RequestCount        int64
}

// ObjectEnumHit Object Enumeration 候选行（同上经 client_ip 反查归属）。
type ObjectEnumHit struct {
	ClientIP            string
	IdentityFingerprint string
	EndpointKey         string
	DistinctObjectIDs   int64
	RequestCount        int64
}

// BusinessEventInput 滥用事件产出参数。
type BusinessEventInput struct {
	IdentityID  uuid.UUID
	IdentityKey string
	RuleCode    string
	Signal      string
	ScoreDelta  int
	Reason      string
	Metadata    map[string]any
	ClientIP    string
	OccurredAt  time.Time
}

// BusinessRepository 滥用检测持久化接口（*Store 实现；单测用内存假实现）。
type BusinessRepository interface {
	FetchLoginAbuseCandidates(ctx context.Context, since time.Time, credThreshold int) ([]LoginAbuseHit, error)
	FetchExportAbuse(ctx context.Context, since time.Time, threshold int) ([]ExportAbuseHit, error)
	FetchObjectEnum(ctx context.Context, since time.Time, threshold int) ([]ObjectEnumHit, error)
	ResolveIdentityByIP(ctx context.Context, ip string) (*uuid.UUID, string, error)
	EmitBusinessEvent(ctx context.Context, in BusinessEventInput) (bool, error)
}

// BusinessDetector Business 滥用判定器。
type BusinessDetector struct {
	repo BusinessRepository
}

// NewBusinessDetector 创建判定器。
func NewBusinessDetector(repo BusinessRepository) *BusinessDetector {
	return &BusinessDetector{repo: repo}
}

// DetectOnce 执行一轮三判定（可由聚合器与测试直接调用）；返回实际产出事件数
// （冷却去重：同身份同规则 bizCooldown 内已有产出则跳过）。单判定器失败不阻断其余
// （fail-open 记日志由聚合器统一处理错误返回——此处聚合产出计数，错误向上返回）。
func (d *BusinessDetector) DetectOnce(ctx context.Context, now time.Time) (int, error) {
	emitted := 0
	n, err := d.detectLoginAbuse(ctx, now)
	emitted += n
	if err != nil {
		return emitted, fmt.Errorf("login abuse: %w", err)
	}
	n, err = d.detectExportAbuse(ctx, now)
	emitted += n
	if err != nil {
		return emitted, fmt.Errorf("export abuse: %w", err)
	}
	n, err = d.detectObjectEnum(ctx, now)
	emitted += n
	if err != nil {
		return emitted, fmt.Errorf("object enumeration: %w", err)
	}
	return emitted, nil
}

// detectLoginAbuse 同身份多凭据 + 认证失败超阈（设计 #12.2「同Identity多账号失败」）。
func (d *BusinessDetector) detectLoginAbuse(ctx context.Context, now time.Time) (int, error) {
	hits, err := d.repo.FetchLoginAbuseCandidates(ctx, now.Add(-bizLoginLookback), LoginAbuseCredThreshold)
	if err != nil {
		return 0, err
	}
	emitted := 0
	for _, h := range hits {
		if h.AuthFailCount < LoginAbuseFailThreshold {
			continue
		}
		ok, err := d.repo.EmitBusinessEvent(ctx, BusinessEventInput{
			IdentityID:  h.IdentityID,
			IdentityKey: h.IdentityKey,
			RuleCode:    RuleLoginAbuse,
			Signal:      SignalLoginAbuse,
			ScoreDelta:  bizScoreDelta,
			Reason: fmt.Sprintf("同身份 %d 个不同凭据且近 24h 认证失败 %d 次（阈值 %d 凭据/%d 失败）",
				h.CredentialCount, h.AuthFailCount, LoginAbuseCredThreshold, LoginAbuseFailThreshold),
			Metadata:   map[string]any{"credential_count": h.CredentialCount, "auth_fail_count": h.AuthFailCount},
			OccurredAt: now,
		})
		if err != nil {
			return emitted, err
		}
		if ok {
			emitted++
		}
	}
	return emitted, nil
}

// detectExportAbuse 身份 × business_type=EXPORT 端点滑窗计数超阈
// （设计 #12.2「单账号持续大批量导出」；仅覆盖 WDSP 流量——api_runtime_events 仅
// API 动态防护开启时产生，纯 WAF 形态无数据源自然零产出）。
func (d *BusinessDetector) detectExportAbuse(ctx context.Context, now time.Time) (int, error) {
	hits, err := d.repo.FetchExportAbuse(ctx, now.Add(-bizWindow), ExportAbuseThreshold)
	if err != nil {
		return 0, err
	}
	emitted := 0
	for _, h := range hits {
		identityID, identityKey, err := d.resolveByIP(ctx, h.ClientIP)
		if err != nil {
			return emitted, err
		}
		if identityID == nil {
			continue // 未归属（IP 反查歧义/无 IP）本期跳过，注释见 Repository 接口
		}
		ok, err := d.repo.EmitBusinessEvent(ctx, BusinessEventInput{
			IdentityID:  *identityID,
			IdentityKey: identityKey,
			RuleCode:    RuleExportAbuse,
			Signal:      SignalExportAbuse,
			ScoreDelta:  bizScoreDelta,
			Reason: fmt.Sprintf("EXPORT 端点 %dmin 滑窗请求 %d 次（阈值 %d）",
				int(bizWindow/time.Minute), h.RequestCount, ExportAbuseThreshold),
			Metadata:   map[string]any{"request_count": h.RequestCount, "window_seconds": int(bizWindow / time.Second)},
			ClientIP:   h.ClientIP,
			OccurredAt: now,
		})
		if err != nil {
			return emitted, err
		}
		if ok {
			emitted++
		}
	}
	return emitted, nil
}

// detectObjectEnum 同身份/指纹对同路径模板不同对象 ID 序列访问
// （设计 #13「/api/user/1001 → /api/user/1002 → …」自动化枚举；判定口径：
// 数字 ID（任意位）或 hex/UUID 形态（8-64 位）末段，10min 滑窗 distinct 数超阈——
// 数字连续变异必然表现为高 distinct 计数，折叠为单一阈值；#13.1「数据量稳定」维度
// 本期无响应大小列，不判定，注释说明）。
func (d *BusinessDetector) detectObjectEnum(ctx context.Context, now time.Time) (int, error) {
	hits, err := d.repo.FetchObjectEnum(ctx, now.Add(-bizWindow), ObjectEnumThreshold)
	if err != nil {
		return 0, err
	}
	emitted := 0
	for _, h := range hits {
		identityID, identityKey, err := d.resolveByIP(ctx, h.ClientIP)
		if err != nil {
			return emitted, err
		}
		if identityID == nil {
			continue
		}
		ok, err := d.repo.EmitBusinessEvent(ctx, BusinessEventInput{
			IdentityID:  *identityID,
			IdentityKey: identityKey,
			RuleCode:    RuleObjectEnum,
			Signal:      SignalObjectEnum,
			ScoreDelta:  bizScoreDelta,
			Reason: fmt.Sprintf("端点 %s %dmin 滑窗访问 %d 个不同对象 ID（阈值 %d）",
				h.EndpointKey, int(bizWindow/time.Minute), h.DistinctObjectIDs, ObjectEnumThreshold),
			Metadata: map[string]any{"endpoint_key": h.EndpointKey, "distinct_object_ids": h.DistinctObjectIDs,
				"request_count": h.RequestCount, "window_seconds": int(bizWindow / time.Second)},
			ClientIP:   h.ClientIP,
			OccurredAt: now,
		})
		if err != nil {
			return emitted, err
		}
		if ok {
			emitted++
		}
	}
	return emitted, nil
}

// resolveByIP IP 反查身份（空 IP 直接未归属）。
func (d *BusinessDetector) resolveByIP(ctx context.Context, ip string) (*uuid.UUID, string, error) {
	if ip == "" {
		return nil, "", nil
	}
	return d.repo.ResolveIdentityByIP(ctx, ip)
}

// ---------- SQL 实现（*Store） ----------

// 编译期断言：*Store 实现 BusinessRepository。
var _ BusinessRepository = (*Store)(nil)

// FetchLoginAbuseCandidates 近 24h 不同凭据数达阈的身份（附 30m 窗口行认证失败累计，
// 失败阈值在 Go 侧过滤——两个阈值口径分开注释）。
func (s *Store) FetchLoginAbuseCandidates(ctx context.Context, since time.Time, credThreshold int) ([]LoginAbuseHit, error) {
	rows, err := s.db.Query(ctx, `
SELECT ci.id, ci.identity_key, COUNT(DISTINCT ic.credential_hash) AS cred_count,
       COALESCE((SELECT SUM(bs.auth_fail_count) FROM behavior_statistics bs
                 WHERE bs.identity_id = ci.id AND bs.window_type = '30m' AND bs.window_start >= $1), 0) AS fail_count
FROM client_identity ci
JOIN identity_credential ic ON ic.identity_id = ci.id AND ic.last_seen_at >= $1
GROUP BY ci.id, ci.identity_key
HAVING COUNT(DISTINCT ic.credential_hash) >= $2`, since, credThreshold)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LoginAbuseHit
	for rows.Next() {
		var h LoginAbuseHit
		if err := rows.Scan(&h.IdentityID, &h.IdentityKey, &h.CredentialCount, &h.AuthFailCount); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// FetchExportAbuse 滑窗内 EXPORT 端点请求计数达阈的（IP, 凭据指纹）分组。
func (s *Store) FetchExportAbuse(ctx context.Context, since time.Time, threshold int) ([]ExportAbuseHit, error) {
	rows, err := s.db.Query(ctx, `
SELECT COALESCE(are.client_ip, ''), are.identity_fingerprint, COUNT(*)
FROM api_runtime_events are
JOIN api_endpoints ep ON ep.endpoint_key = are.endpoint_key
JOIN api_assets aa ON aa.endpoint_id = ep.id AND aa.business_type = 'EXPORT'
WHERE are.occurred_at >= $1
GROUP BY COALESCE(are.client_ip, ''), are.identity_fingerprint
HAVING COUNT(*) >= $2`, since, threshold)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExportAbuseHit
	for rows.Next() {
		var h ExportAbuseHit
		if err := rows.Scan(&h.ClientIP, &h.IdentityFingerprint, &h.RequestCount); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// FetchObjectEnum 滑窗内同路径模板不同对象 ID 数达阈的（IP, 凭据指纹, endpoint）分组。
// 仅计 2xx 成功响应（#13.1「返回成功」；旧版网关未上报状态码 NULL 一并计入保覆盖）。
func (s *Store) FetchObjectEnum(ctx context.Context, since time.Time, threshold int) ([]ObjectEnumHit, error) {
	rows, err := s.db.Query(ctx, `
SELECT COALESCE(are.client_ip, ''), are.identity_fingerprint, are.endpoint_key,
       COUNT(DISTINCT regexp_replace(are.raw_path, '^.*/', '')) AS obj_cnt,
       COUNT(*) AS req_cnt
FROM api_runtime_events are
WHERE are.occurred_at >= $1
  AND are.endpoint_key <> ''
  AND are.raw_path IS NOT NULL AND are.raw_path <> ''
  AND (are.response_status BETWEEN 200 AND 299 OR are.response_status IS NULL)
  AND regexp_replace(are.raw_path, '^.*/', '') ~ '^([0-9]+|[0-9a-fA-F-]{8,64})$'
GROUP BY COALESCE(are.client_ip, ''), are.identity_fingerprint, are.endpoint_key
HAVING COUNT(DISTINCT regexp_replace(are.raw_path, '^.*/', '')) >= $2`, since, threshold)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ObjectEnumHit
	for rows.Next() {
		var h ObjectEnumHit
		if err := rows.Scan(&h.ClientIP, &h.IdentityFingerprint, &h.EndpointKey,
			&h.DistinctObjectIDs, &h.RequestCount); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// ResolveIdentityByIP identity_ip_history 反查：该 IP 唯一归属一个身份才采纳
// （多身份歧义 = NAT/共享出口存疑，返回 nil 不强挂）。
func (s *Store) ResolveIdentityByIP(ctx context.Context, ip string) (*uuid.UUID, string, error) {
	var identityID *uuid.UUID
	err := s.db.QueryRow(ctx, `
SELECT CASE WHEN count(DISTINCT identity_id) = 1 THEN max(identity_id::text)::uuid END
FROM identity_ip_history WHERE ip = $1`, ip).Scan(&identityID)
	if err != nil {
		return nil, "", err
	}
	if identityID == nil {
		return nil, "", nil
	}
	var identityKey string
	if err := s.db.QueryRow(ctx,
		`SELECT identity_key FROM client_identity WHERE id = $1`, *identityID).Scan(&identityKey); err != nil {
		return nil, "", err
	}
	return identityID, identityKey, nil
}

// EmitBusinessEvent 产出滥用事件（identity_behavior_events，OBSERVE；冷却去重：
// 同身份同规则 bizCooldown 内已有产出则跳过）并按 24h 滚动重算身份风险分/等级
// （与 identityevents.RecordSignal 同一口径，保持 client_identity 风险字段不变式）。
func (s *Store) EmitBusinessEvent(ctx context.Context, in BusinessEventInput) (bool, error) {
	metadata := []byte("{}")
	if len(in.Metadata) > 0 {
		if raw, err := json.Marshal(in.Metadata); err == nil {
			metadata = raw
		}
	}
	tag, err := s.db.Exec(ctx, `
INSERT INTO identity_behavior_events (identity_id, identity_key, occurred_at, event_kind,
  rule_code, rule_version, signal, risk_score_delta, mode, reason, metadata, client_ip)
SELECT $1::uuid,$2::varchar,$3::timestamptz,$4::varchar,$5::varchar,$6::varchar,$7::varchar,
  $8::int,'OBSERVE',$9::text,$10::jsonb,$11::varchar
WHERE NOT EXISTS (
  SELECT 1 FROM identity_behavior_events
  WHERE identity_id = $1::uuid AND rule_code = $5::varchar AND event_kind = $4::varchar
    AND occurred_at >= $12::timestamptz)`,
		in.IdentityID, in.IdentityKey, in.OccurredAt, bizEventKind,
		in.RuleCode, bizRuleVersion, in.Signal, in.ScoreDelta, in.Reason, metadata, in.ClientIP,
		in.OccurredAt.Add(-bizCooldown))
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() != 1 {
		return false, nil
	}
	// 身份风险分重算（24h 滚动求和，截断 [0,100]）
	var total int
	if err := s.db.QueryRow(ctx, `
SELECT COALESCE(SUM(risk_score_delta), 0) FROM identity_behavior_events
WHERE identity_id = $1 AND occurred_at >= now() - INTERVAL '24 hours'`, in.IdentityID).Scan(&total); err != nil {
		return true, fmt.Errorf("sum risk score delta: %w", err)
	}
	score := clampRiskScore(total)
	if _, err := s.db.Exec(ctx, `
UPDATE client_identity SET risk_score = $2, risk_level = $3, updated_at = now() WHERE id = $1`,
		in.IdentityID, score, RiskLevelForScore(score)); err != nil {
		return true, fmt.Errorf("update identity risk: %w", err)
	}
	return true, nil
}
