// value.go 资产价值评分（WDSP 任务书 §13 多维、可解释，P0-10 Known Gap ④）。
//
// 九维各 0-3 分（写能力 0-2），总分 0-26 映射 LOW / MEDIUM / HIGH / CRITICAL。
// 每维输出得分 + 输入值 + 中文理由（asset_value_explain 持久化形态），评分
// 结果可回溯、可解释。
//
// 数据源（ComputeAssetValueInput 装配）：
//
//	PURPOSE/EXPOSURE 分类维度  api_classification_dimensions（EXPOSURE 缺省回落 api_assets.exposure）
//	敏感字段计数               api_sensitive_fields
//	认证形态                   api_identity_profiles.auth_type 多数值
//	调用边                     api_call_edges（阶段8 起由 aggregations.RunCallEdges 分钟级生产写入）
//	流量规模                   api_endpoint_traffic_buckets 近 7 天（留存窗口，迁移 000034）
package apiassets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 资产价值等级（api_endpoints.asset_value 词表）。
const (
	AssetValueLow      = "LOW"
	AssetValueMedium   = "MEDIUM"
	AssetValueHigh     = "HIGH"
	AssetValueCritical = "CRITICAL"
)

// 评分区间阈值：总分 [0,assetValueMaxTotal]，
// [0,7) LOW、[7,14) MEDIUM、[14,20) HIGH、[20,26] CRITICAL。
// 注：26 为九维独立计分的理论满分；PURPOSE 相关三维互斥
// （business_sensitivity / admin_capability / transaction_capability），实际可达上限 23。
const (
	assetValueMaxTotal = 26
	thresholdMedium    = 7
	thresholdHigh      = 14
	thresholdCritical  = 20
)

// valueTrafficWindowDays 流量规模统计窗口（天）：与流量桶留存一致（000034）。
const valueTrafficWindowDays = 7

// 维度得分上限。
const (
	dimMax = 3
	// dimWriteMax 写能力上限 2（写操作抬升价值但有界）。
	dimWriteMax = 2
)

// AssetValueInput 资产价值评分输入（九维原料；零值语义 = 无数据，按各维默认计分）。
type AssetValueInput struct {
	Purpose             string // PURPOSE 分类值（AUTH/TRADE/FILE/ADMIN/USER_MGMT/QUERY/GENERAL；空 = 未分类）
	Exposure            string // EXPOSURE 分类值（INTERNAL/PARTNER/PUBLIC；空 = 未分类）
	AuthType            string // 主导认证形态（bearer_or_basic/api_key/cookie_session；空 = 匿名或无身份数据）
	HTTPMethod          string // 请求方法（GET/HEAD/OPTIONS 只读，其余写）
	SensitiveFieldCount int    // api_sensitive_fields 条数
	InboundEdges        int    // 调用入度（api_call_edges.target）
	OutboundEdges       int    // 调用出度（api_call_edges.source）
	DailyTraffic        int64  // 近 7 天日均请求量（traffic buckets 窗口和 / 窗口天数）
}

// ScoreDimension 单维得分（可解释：得分/上限/输入值/理由）。
type ScoreDimension struct {
	Name   string `json:"name"`
	Score  int    `json:"score"`
	Max    int    `json:"max"`
	Input  string `json:"input"`
	Reason string `json:"reason"`
}

// AssetValueScore 资产价值评分结果（asset_value_explain 持久化形态）。
type AssetValueScore struct {
	Level      string           `json:"level"`                 // LOW / MEDIUM / HIGH / CRITICAL
	Total      int              `json:"total"`                 // 总分
	MaxTotal   int              `json:"max_total"`             // 满分
	ComputedAt *time.Time       `json:"computed_at,omitempty"` // 计算时间（回填时写入；纯评分不置）
	Dimensions []ScoreDimension `json:"dimensions"`
}

// scoreBusinessSensitivity 业务敏感度（PURPOSE 分类维度）。
func scoreBusinessSensitivity(purpose string) ScoreDimension {
	d := ScoreDimension{Name: "business_sensitivity", Max: dimMax, Input: purpose}
	switch strings.ToUpper(strings.TrimSpace(purpose)) {
	case "TRADE":
		d.Score, d.Reason = 3, "purpose=TRADE：交易类业务，资金流直接相关"
	case "AUTH":
		d.Score, d.Reason = 2, "purpose=AUTH：认证入口，凭据集中"
	case "ADMIN":
		d.Score, d.Reason = 2, "purpose=ADMIN：管理面业务"
	case "USER_MGMT":
		d.Score, d.Reason = 2, "purpose=USER_MGMT：用户账号管理"
	case "FILE":
		d.Score, d.Reason = 1, "purpose=FILE：文件读写类业务"
	case "QUERY", "GENERAL":
		d.Score, d.Reason = 1, fmt.Sprintf("purpose=%s：一般业务", strings.ToUpper(purpose))
	default:
		d.Score, d.Reason = 1, "purpose 未分类，按一般业务保守计分"
	}
	return d
}

// scoreDataSensitivity 数据敏感度（敏感字段计数）。
func scoreDataSensitivity(count int) ScoreDimension {
	d := ScoreDimension{Name: "data_sensitivity", Max: dimMax, Input: fmt.Sprintf("%d", count)}
	switch {
	case count <= 0:
		d.Score, d.Reason = 0, "未识别到敏感字段"
	case count <= 2:
		d.Score, d.Reason = 1, fmt.Sprintf("敏感字段 %d 个（1-2）", count)
	case count <= 5:
		d.Score, d.Reason = 2, fmt.Sprintf("敏感字段 %d 个（3-5）", count)
	default:
		d.Score, d.Reason = 3, fmt.Sprintf("敏感字段 %d 个（≥6），敏感数据密集", count)
	}
	return d
}

// scoreInternetExposure 互联网暴露面（EXPOSURE 分类）。
func scoreInternetExposure(exposure string) ScoreDimension {
	d := ScoreDimension{Name: "internet_exposure", Max: dimMax, Input: exposure}
	switch strings.ToUpper(strings.TrimSpace(exposure)) {
	case "PUBLIC":
		d.Score, d.Reason = 3, "exposure=PUBLIC：互联网公开可达"
	case "PARTNER":
		d.Score, d.Reason = 2, "exposure=PARTNER：对合作方开放"
	case "INTERNAL":
		d.Score, d.Reason = 0, "exposure=INTERNAL：仅内网"
	default:
		d.Score, d.Reason = 1, "exposure 未分类，按内网与公开之间保守计分"
	}
	return d
}

// scorePrivilege 调用权限面（主导认证形态；auth_type 词表见迁移 000029）。
func scorePrivilege(authType string) ScoreDimension {
	d := ScoreDimension{Name: "privilege", Max: dimMax, Input: authType}
	switch strings.ToLower(strings.TrimSpace(authType)) {
	case "cookie_session":
		d.Score, d.Reason = 3, "auth_type=cookie_session：登录用户会话，权限面最大"
	case "bearer_or_basic":
		d.Score, d.Reason = 2, "auth_type=bearer_or_basic：令牌/基本认证调用"
	case "api_key":
		d.Score, d.Reason = 1, "auth_type=api_key：机器凭据，通常有作用域"
	case "":
		d.Score, d.Reason = 0, "未观测到认证凭据（匿名流量或无身份数据）"
	default:
		d.Score, d.Reason = 1, fmt.Sprintf("auth_type=%s 未在词表内，保守计分", authType)
	}
	return d
}

// scoreWriteCapability 写能力（请求方法）。
func scoreWriteCapability(method string) ScoreDimension {
	d := ScoreDimension{Name: "write_capability", Max: dimWriteMax, Input: method}
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "GET", "HEAD", "OPTIONS", "":
		d.Score, d.Reason = 0, "只读方法，无写能力"
	default:
		d.Score, d.Reason = 2, fmt.Sprintf("method=%s：写方法，可变更服务端状态", strings.ToUpper(method))
	}
	return d
}

// scoreAdminCapability 管理能力（PURPOSE=ADMIN）。
func scoreAdminCapability(purpose string) ScoreDimension {
	d := ScoreDimension{Name: "admin_capability", Max: dimMax, Input: purpose}
	if strings.EqualFold(strings.TrimSpace(purpose), "ADMIN") {
		d.Score, d.Reason = 3, "purpose=ADMIN：管理面接口"
	} else {
		d.Score, d.Reason = 0, "非管理面接口"
	}
	return d
}

// scoreTransactionCapability 交易能力（PURPOSE=TRADE）。
func scoreTransactionCapability(purpose string) ScoreDimension {
	d := ScoreDimension{Name: "transaction_capability", Max: dimMax, Input: purpose}
	if strings.EqualFold(strings.TrimSpace(purpose), "TRADE") {
		d.Score, d.Reason = 3, "purpose=TRADE：交易类接口"
	} else {
		d.Score, d.Reason = 0, "非交易类接口"
	}
	return d
}

// scoreDependencyDegree 依赖度（调用边入度+出度；api_call_edges 由 aggregations.RunCallEdges 分钟级生产，无记录时 0 分并注明）。
func scoreDependencyDegree(inbound, outbound int) ScoreDimension {
	total := inbound + outbound
	d := ScoreDimension{Name: "dependency_degree", Max: dimMax, Input: fmt.Sprintf("%d", total)}
	switch {
	case total <= 0:
		d.Score, d.Reason = 0, "无调用边数据（api_call_edges 无记录）"
	case total <= 3:
		d.Score, d.Reason = 1, fmt.Sprintf("调用边 %d 条（1-3）", total)
	case total <= 9:
		d.Score, d.Reason = 2, fmt.Sprintf("调用边 %d 条（4-9）", total)
	default:
		d.Score, d.Reason = 3, fmt.Sprintf("调用边 %d 条（≥10），拓扑核心节点", total)
	}
	return d
}

// scoreTrafficScale 流量规模（近 7 天日均请求量）。
func scoreTrafficScale(daily int64) ScoreDimension {
	d := ScoreDimension{Name: "traffic_scale", Max: dimMax, Input: fmt.Sprintf("%d", daily)}
	switch {
	case daily <= 0:
		d.Score, d.Reason = 0, "近 7 天无流量"
	case daily < 100:
		d.Score, d.Reason = 1, fmt.Sprintf("日均请求 %d（<100）", daily)
	case daily < 10000:
		d.Score, d.Reason = 2, fmt.Sprintf("日均请求 %d（100-9999）", daily)
	default:
		d.Score, d.Reason = 3, fmt.Sprintf("日均请求 %d（≥10000），高热接口", daily)
	}
	return d
}

// assetValueLevel 总分映射等级。
func assetValueLevel(total int) string {
	switch {
	case total >= thresholdCritical:
		return AssetValueCritical
	case total >= thresholdHigh:
		return AssetValueHigh
	case total >= thresholdMedium:
		return AssetValueMedium
	default:
		return AssetValueLow
	}
}

// ScoreAssetValue 资产价值评分（纯函数：同输入恒同输出，便于各维矩阵单测）。
func ScoreAssetValue(in AssetValueInput) AssetValueScore {
	dims := []ScoreDimension{
		scoreBusinessSensitivity(in.Purpose),
		scoreDataSensitivity(in.SensitiveFieldCount),
		scoreInternetExposure(in.Exposure),
		scorePrivilege(in.AuthType),
		scoreWriteCapability(in.HTTPMethod),
		scoreAdminCapability(in.Purpose),
		scoreTransactionCapability(in.Purpose),
		scoreDependencyDegree(in.InboundEdges, in.OutboundEdges),
		scoreTrafficScale(in.DailyTraffic),
	}
	total := 0
	for _, d := range dims {
		total += d.Score
	}
	return AssetValueScore{
		Level:      assetValueLevel(total),
		Total:      total,
		MaxTotal:   assetValueMaxTotal,
		Dimensions: dims,
	}
}

// ComputeAssetValueInput 从库内装配单端点评分输入（数据源见文件头注释；
// 流量规模为近 valueTrafficWindowDays 天日均）。
func (s *Store) ComputeAssetValueInput(ctx context.Context, id uuid.UUID) (AssetValueInput, error) {
	var in AssetValueInput
	var windowTotal int64
	since := time.Now().UTC().Add(-valueTrafficWindowDays * 24 * time.Hour)
	err := s.db.QueryRow(ctx, `
SELECT e.http_method,
  COALESCE((SELECT d.value FROM api_classification_dimensions d
            WHERE d.endpoint_id = e.id AND d.dimension = 'PURPOSE'), ''),
  COALESCE((SELECT d.value FROM api_classification_dimensions d
            WHERE d.endpoint_id = e.id AND d.dimension = 'EXPOSURE'),
           (SELECT a.exposure FROM api_assets a WHERE a.endpoint_id = e.id), ''),
  COALESCE((SELECT p.auth_type FROM api_identity_profiles p
            WHERE p.endpoint_id = e.id AND p.auth_type <> ''
            GROUP BY p.auth_type ORDER BY count(*) DESC, p.auth_type LIMIT 1), ''),
  (SELECT count(*) FROM api_sensitive_fields f WHERE f.endpoint_id = e.id),
  (SELECT count(*) FROM api_call_edges c WHERE c.target_endpoint_id = e.id),
  (SELECT count(*) FROM api_call_edges c WHERE c.source_endpoint_id = e.id),
  COALESCE((SELECT sum(b.request_count) FROM api_endpoint_traffic_buckets b
            WHERE b.endpoint_id = e.id AND b.bucket_start >= $2), 0)
FROM api_endpoints e WHERE e.id = $1`, id, since).Scan(
		&in.HTTPMethod, &in.Purpose, &in.Exposure, &in.AuthType,
		&in.SensitiveFieldCount, &in.InboundEdges, &in.OutboundEdges, &windowTotal)
	if errors.Is(err, pgx.ErrNoRows) {
		return in, ErrNotFound
	}
	if err != nil {
		return in, err
	}
	in.DailyTraffic = windowTotal / valueTrafficWindowDays
	return in, nil
}

// RefreshAssetValue 重算单端点资产价值评分并回填 asset_value/_explain。
// 派生数据回填不动 updated_at（避免清扫作业干扰资产编辑时序语义）。
func (s *Store) RefreshAssetValue(ctx context.Context, id uuid.UUID, now time.Time) error {
	in, err := s.ComputeAssetValueInput(ctx, id)
	if err != nil {
		return err
	}
	score := ScoreAssetValue(in)
	score.ComputedAt = &now
	raw, err := json.Marshal(score)
	if err != nil {
		return fmt.Errorf("序列化资产价值评分失败：%w", err)
	}
	tag, err := s.db.Exec(ctx, `
UPDATE api_endpoints SET asset_value=$2, asset_value_explain=$3::jsonb, asset_value_computed_at=$4 WHERE id=$1`,
		id, score.Level, string(raw), now.UTC())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// rfc3339TimestampRegex 用于在 PostgreSQL 侧安全守卫 asset_value_explain->>'computed_at' 的 ::timestamptz 强转，
// 防止历史畸形值（如 'not-a-date'、'2026-11-25Tnot-a-date'、非闰年 02-29、0000 年、超 ±15:59 时区偏移）触发 22007/22008/22009/22023 运行时异常。
const rfc3339TimestampRegex = `^(([1-9]\d{3}|0[1-9]\d{2}|00[1-9]\d|000[1-9])-((0[13578]|1[02])-(0[1-9]|[12]\d|3[01])|(0[469]|11)-(0[1-9]|[12]\d|30)|02-(0[1-9]|1\d|2[0-8]))|((0[48]|[2468][048]|[13579][26])00|\d{2}(0[48]|[2468][048]|[13579][26]))-02-29)T([01]\d|2[0-3]):[0-5]\d:[0-5]\d(\.\d+)?(Z|[+-](0\d|1[0-5]):?[0-5]\d)$`

const refreshAssetValuesSelectSQL = `
SELECT id FROM api_endpoints
WHERE asset_status <> 'IGNORED'
  AND (
    (asset_value_computed_at IS NOT NULL AND last_seen_at > asset_value_computed_at)
    OR (asset_value_computed_at IS NULL
        AND (asset_value_explain IS NULL
             OR last_seen_at > CASE
                 WHEN COALESCE(asset_value_explain->>'computed_at', '') ~ '` + rfc3339TimestampRegex + `'
                  AND pg_input_is_valid(COALESCE(asset_value_explain->>'computed_at', ''), 'timestamptz')
                 THEN (asset_value_explain->>'computed_at')::timestamptz
                 ELSE '-infinity'::timestamptz
             END))
  )
ORDER BY last_seen_at DESC
LIMIT $1`

// RefreshAssetValues 批量回填：未评分或评分后又有新流量（last_seen_at 晚于上次计算）的
// 端点重算，单轮 limit 截断（IGNORED 端点不参与评分）。返回本轮处理数。
func (s *Store) RefreshAssetValues(ctx context.Context, limit int) (int, error) {
	rows, err := s.db.Query(ctx, refreshAssetValuesSelectSQL, limit)
	if err != nil {
		return 0, err
	}
	ids := []uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	now := time.Now().UTC()
	for i, id := range ids {
		if err := s.RefreshAssetValue(ctx, id, now); err != nil {
			return i, fmt.Errorf("资产价值评分回填失败（端点 %s）: %w", id, err)
		}
	}
	return len(ids), nil
}
