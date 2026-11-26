// value_test.go 资产价值评分单测（§13 多维、可解释）：
// 九维计分矩阵、等级阈值边界、可解释输出结构、纯函数确定性、内存回填闭环。
package apiassets

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// dimScore 从评分结果中取指定维度得分（不存在则 -1）。
func dimScore(s AssetValueScore, name string) int {
	for _, d := range s.Dimensions {
		if d.Name == name {
			return d.Score
		}
	}
	return -1
}

// TestScoreAssetValueDimensions 各维计分矩阵（每维独立断言得分档）。
func TestScoreAssetValueDimensions(t *testing.T) {
	cases := []struct {
		name string
		in   AssetValueInput
		dim  string
		want int
	}{
		// business_sensitivity（PURPOSE 分类维度）
		{"业务-交易", AssetValueInput{Purpose: "TRADE"}, "business_sensitivity", 3},
		{"业务-认证", AssetValueInput{Purpose: "AUTH"}, "business_sensitivity", 2},
		{"业务-管理", AssetValueInput{Purpose: "ADMIN"}, "business_sensitivity", 2},
		{"业务-用户管理", AssetValueInput{Purpose: "USER_MGMT"}, "business_sensitivity", 2},
		{"业务-文件", AssetValueInput{Purpose: "FILE"}, "business_sensitivity", 1},
		{"业务-查询", AssetValueInput{Purpose: "QUERY"}, "business_sensitivity", 1},
		{"业务-未分类", AssetValueInput{}, "business_sensitivity", 1},
		// data_sensitivity（敏感字段计数）
		{"敏感-0", AssetValueInput{SensitiveFieldCount: 0}, "data_sensitivity", 0},
		{"敏感-1", AssetValueInput{SensitiveFieldCount: 1}, "data_sensitivity", 1},
		{"敏感-2", AssetValueInput{SensitiveFieldCount: 2}, "data_sensitivity", 1},
		{"敏感-3", AssetValueInput{SensitiveFieldCount: 3}, "data_sensitivity", 2},
		{"敏感-5", AssetValueInput{SensitiveFieldCount: 5}, "data_sensitivity", 2},
		{"敏感-6", AssetValueInput{SensitiveFieldCount: 6}, "data_sensitivity", 3},
		// internet_exposure（EXPOSURE 分类）
		{"暴露-PUBLIC", AssetValueInput{Exposure: "PUBLIC"}, "internet_exposure", 3},
		{"暴露-PARTNER", AssetValueInput{Exposure: "PARTNER"}, "internet_exposure", 2},
		{"暴露-INTERNAL", AssetValueInput{Exposure: "INTERNAL"}, "internet_exposure", 0},
		{"暴露-未分类", AssetValueInput{}, "internet_exposure", 1},
		// privilege（auth 类型，词表见迁移 000029）
		{"权限-会话", AssetValueInput{AuthType: "cookie_session"}, "privilege", 3},
		{"权限-令牌", AssetValueInput{AuthType: "bearer_or_basic"}, "privilege", 2},
		{"权限-apikey", AssetValueInput{AuthType: "api_key"}, "privilege", 1},
		{"权限-匿名", AssetValueInput{}, "privilege", 0},
		{"权限-未知", AssetValueInput{AuthType: "mtls"}, "privilege", 1},
		// write_capability（method）
		{"写-GET", AssetValueInput{HTTPMethod: "GET"}, "write_capability", 0},
		{"写-HEAD", AssetValueInput{HTTPMethod: "HEAD"}, "write_capability", 0},
		{"写-OPTIONS", AssetValueInput{HTTPMethod: "OPTIONS"}, "write_capability", 0},
		{"写-POST", AssetValueInput{HTTPMethod: "POST"}, "write_capability", 2},
		{"写-DELETE", AssetValueInput{HTTPMethod: "DELETE"}, "write_capability", 2},
		// admin_capability（PURPOSE=ADMIN）
		{"管理-是", AssetValueInput{Purpose: "ADMIN"}, "admin_capability", 3},
		{"管理-否", AssetValueInput{Purpose: "QUERY"}, "admin_capability", 0},
		// transaction_capability（PURPOSE=TRADE）
		{"交易-是", AssetValueInput{Purpose: "TRADE"}, "transaction_capability", 3},
		{"交易-否", AssetValueInput{Purpose: "AUTH"}, "transaction_capability", 0},
		// dependency_degree（调用边；无边表数据则 0）
		{"依赖-无", AssetValueInput{}, "dependency_degree", 0},
		{"依赖-低", AssetValueInput{InboundEdges: 2, OutboundEdges: 1}, "dependency_degree", 1},
		{"依赖-中", AssetValueInput{InboundEdges: 9}, "dependency_degree", 2},
		{"依赖-高", AssetValueInput{InboundEdges: 6, OutboundEdges: 4}, "dependency_degree", 3},
		// traffic_scale（近 7 天日均）
		{"流量-无", AssetValueInput{}, "traffic_scale", 0},
		{"流量-低", AssetValueInput{DailyTraffic: 99}, "traffic_scale", 1},
		{"流量-中", AssetValueInput{DailyTraffic: 100}, "traffic_scale", 2},
		{"流量-高", AssetValueInput{DailyTraffic: 9999}, "traffic_scale", 2},
		{"流量-峰值", AssetValueInput{DailyTraffic: 10000}, "traffic_scale", 3},
	}
	for _, c := range cases {
		if got := dimScore(ScoreAssetValue(c.in), c.dim); got != c.want {
			t.Errorf("%s: %s=%d, want %d", c.name, c.dim, got, c.want)
		}
	}
}

// TestScoreAssetValueLevels 等级阈值边界（LOW/MEDIUM/HIGH/CRITICAL 四档）。
func TestScoreAssetValueLevels(t *testing.T) {
	cases := []struct {
		name      string
		in        AssetValueInput
		wantTotal int
		wantLevel string
	}{
		{"空输入-LOW", AssetValueInput{}, 2, AssetValueLow}, // 未分类保守分 1+1
		{"边界6-LOW", AssetValueInput{
			Purpose: "GENERAL", Exposure: "INTERNAL", SensitiveFieldCount: 3, DailyTraffic: 10000,
		}, 6, AssetValueLow}, // 1+2+0+3
		{"边界7-MEDIUM", AssetValueInput{
			Purpose: "GENERAL", Exposure: "INTERNAL", SensitiveFieldCount: 3, InboundEdges: 1, DailyTraffic: 10000,
		}, 7, AssetValueMedium}, // 1+2+0+1+3
		{"公网交易-HIGH", AssetValueInput{
			Purpose: "TRADE", Exposure: "PUBLIC", HTTPMethod: "POST",
			SensitiveFieldCount: 1, DailyTraffic: 5000,
		}, 14, AssetValueHigh}, // 3+1+3+0+2+0+3+0+2
		{"边界19-HIGH", AssetValueInput{
			Purpose: "AUTH", Exposure: "PUBLIC", AuthType: "cookie_session", HTTPMethod: "POST",
			SensitiveFieldCount: 6, InboundEdges: 10, DailyTraffic: 10000,
		}, 19, AssetValueHigh}, // 2+3+3+3+2+0+0+3+3
		{"边界20-CRITICAL", AssetValueInput{
			Purpose: "TRADE", Exposure: "PUBLIC", AuthType: "cookie_session", HTTPMethod: "POST",
			SensitiveFieldCount: 6, DailyTraffic: 10000,
		}, 20, AssetValueCritical}, // 3+3+3+3+2+0+3+0+3
		{"满配-CRITICAL", AssetValueInput{
			Purpose: "TRADE", Exposure: "PUBLIC", AuthType: "cookie_session", HTTPMethod: "POST",
			SensitiveFieldCount: 6, InboundEdges: 8, OutboundEdges: 2, DailyTraffic: 10000,
		}, 23, AssetValueCritical}, // 实际可达上限 23（PURPOSE 三维互斥）
	}
	for _, c := range cases {
		got := ScoreAssetValue(c.in)
		if got.Total != c.wantTotal || got.Level != c.wantLevel {
			t.Errorf("%s: total=%d level=%s, want total=%d level=%s",
				c.name, got.Total, got.Level, c.wantTotal, c.wantLevel)
		}
	}
}

// TestScoreAssetValueExplain 可解释输出：九维齐全、各维含得分/上限/输入/理由、
// 无调用边时理由注明、总分=各维和、纯函数确定性、computed_at 由回填侧写入。
func TestScoreAssetValueExplain(t *testing.T) {
	in := AssetValueInput{
		Purpose: "TRADE", Exposure: "PUBLIC", AuthType: "bearer_or_basic", HTTPMethod: "PUT",
		SensitiveFieldCount: 2, DailyTraffic: 100,
	}
	score := ScoreAssetValue(in)

	wantDims := []string{
		"business_sensitivity", "data_sensitivity", "internet_exposure", "privilege",
		"write_capability", "admin_capability", "transaction_capability",
		"dependency_degree", "traffic_scale",
	}
	if len(score.Dimensions) != len(wantDims) {
		t.Fatalf("dimensions=%d, want %d", len(score.Dimensions), len(wantDims))
	}
	sum := 0
	for i, d := range score.Dimensions {
		if d.Name != wantDims[i] {
			t.Fatalf("dimensions[%d]=%s, want %s（次序固定便于审计比对）", i, d.Name, wantDims[i])
		}
		if d.Max <= 0 || d.Reason == "" || d.Score < 0 || d.Score > d.Max {
			t.Fatalf("dimension %s 不完整: %+v", d.Name, d)
		}
		sum += d.Score
	}
	if sum != score.Total || score.MaxTotal != assetValueMaxTotal {
		t.Fatalf("sum=%d total=%d max=%d", sum, score.Total, score.MaxTotal)
	}
	if got := dimScore(score, "dependency_degree"); got != 0 {
		t.Fatalf("dependency_degree=%d, want 0（无边数据）", got)
	}
	for _, d := range score.Dimensions {
		if d.Name == "dependency_degree" && d.Reason != "无调用边数据（api_call_edges 无记录）" {
			t.Fatalf("dependency_degree reason=%q", d.Reason)
		}
	}
	// 纯评分不置计算时间（由回填侧写入）
	if score.ComputedAt != nil {
		t.Fatalf("ComputedAt=%v, want nil（纯函数不写时间）", score.ComputedAt)
	}
	// 确定性：同输入两次评分 JSON 完全一致
	raw1, _ := json.Marshal(ScoreAssetValue(in))
	raw2, _ := json.Marshal(ScoreAssetValue(in))
	if string(raw1) != string(raw2) {
		t.Fatal("ScoreAssetValue 非确定性输出")
	}
}

// TestMemRefreshAssetValues 内存回填闭环：候选口径（未评分/评分后新流量/IGNORED 排除）、
// 评分输入装配（分类维度优先、EXPOSURE 回落 api_assets、敏感数/认证形态/流量窗口）、
// explain 持久化形态（computed_at 由回填侧写入）。
func TestMemRefreshAssetValues(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	now := time.Now().UTC()

	// ep1：已分类公网交易写接口 + 敏感字段 + 会话认证 + 7 天流量（日均 1）。
	// AutoClassify 路径含 /pay → PURPOSE=TRADE；EXPOSURE 维度=INTERNAL（分类维度优先，
	// 即使 api_assets.exposure=PARTNER 也不回落）。
	ep1 := mustSeed(t, store, "POST", "/api/pay-"+uuid.NewString()[:8]+"/{id}")
	if _, err := store.AutoClassify(ctx, ep1.ID); err != nil {
		t.Fatal(err)
	}
	store.SetSensitiveFieldCount(ep1.ID, 2)
	store.SetAuthType(ep1.ID, "cookie_session")
	for i := 0; i < 7; i++ {
		if err := store.RecordTrafficBucket(ctx, ep1.ID, now.Add(-time.Duration(i)*24*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.UpsertAsset(ctx, ep1.ID, AssetProfile{Exposure: "PARTNER"}); err != nil {
		t.Fatal(err)
	}

	// ep2：未分类端点，无 EXPOSURE 维度 → 回落 api_assets.exposure=PUBLIC；只读无流量。
	ep2 := mustSeed(t, store, "GET", "/api/pub-"+uuid.NewString()[:8])
	if _, err := store.UpsertAsset(ctx, ep2.ID, AssetProfile{Exposure: "PUBLIC"}); err != nil {
		t.Fatal(err)
	}

	// IGNORED 端点不参与评分
	ignored := mustSeed(t, store, "GET", "/api/ign-val-"+uuid.NewString()[:8])
	if _, err := store.SetAssetStatus(ctx, ignored.ID, "IGNORED", "tester"); err != nil {
		t.Fatal(err)
	}

	n, err := store.RefreshAssetValues(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("refreshed=%d, want 2（IGNORED 排除）", n)
	}

	// ep1 期望：TRADE(3)+敏感2(1)+INTERNAL(0)+session(3)+POST(2)+trans(3)+流量日均1(1)=13 → MEDIUM
	got, err := store.GetByID(ctx, ep1.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.AssetValue != AssetValueMedium {
		t.Fatalf("ep1 asset_value=%s, want MEDIUM", got.AssetValue)
	}
	var score AssetValueScore
	if err := json.Unmarshal(got.AssetValueExplain, &score); err != nil {
		t.Fatalf("explain not json: %v", err)
	}
	if score.Total != 13 || score.ComputedAt == nil {
		t.Fatalf("ep1 score total=%d computed=%v, want 13 + computed_at", score.Total, score.ComputedAt)
	}
	if dimScore(score, "internet_exposure") != 0 {
		t.Fatalf("ep1 exposure dim=%d, want 0（分类维度 INTERNAL 优先于 api_assets 回落）",
			dimScore(score, "internet_exposure"))
	}

	// ep2 期望：未分类(1)+PUBLIC(3)=4 → LOW（EXPOSURE 回落 api_assets）
	got2, err := store.GetByID(ctx, ep2.ID)
	if err != nil {
		t.Fatal(err)
	}
	var score2 AssetValueScore
	if err := json.Unmarshal(got2.AssetValueExplain, &score2); err != nil {
		t.Fatalf("ep2 explain not json: %v", err)
	}
	if got2.AssetValue != AssetValueLow || score2.Total != 4 || dimScore(score2, "internet_exposure") != 3 {
		t.Fatalf("ep2 value=%s total=%d exposure=%d, want LOW/4/3",
			got2.AssetValue, score2.Total, dimScore(score2, "internet_exposure"))
	}

	ign, _ := store.GetByID(ctx, ignored.ID)
	if ign.AssetValue != "" {
		t.Fatalf("IGNORED endpoint asset_value=%s, want 空", ign.AssetValue)
	}

	// 无新流量：二轮候选为空（last_seen_at 未晚于上次计算）
	n, err = store.RefreshAssetValues(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("second refresh=%d, want 0", n)
	}

	// 评分后又有新流量（last_seen_at 前进）：重新进入候选
	if _, err := store.UpsertDiscovery(ctx, DiscoveryInput{Method: "POST", PathTemplate: ep1.NormalizedPath, Confidence: 0.8, IsAPI: true}); err != nil {
		t.Fatal(err)
	}
	n, err = store.RefreshAssetValues(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("refresh after new traffic=%d, want 1", n)
	}
}

func TestRFC3339TimestampRegexAndRefreshSQL(t *testing.T) {
	re := regexp.MustCompile(rfc3339TimestampRegex)

	// Valid RFC3339 / RFC3339Nano outputs from Go time package
	now := time.Date(2026, 11, 25, 16, 4, 5, 123456789, time.UTC)
	bj := time.FixedZone("CST", 8*3600)
	ny := time.FixedZone("EST", -5*3600)
	leap := time.Date(2024, 2, 29, 23, 59, 59, 0, time.UTC)
	validSamples := []string{
		now.Format(time.RFC3339),
		now.Format(time.RFC3339Nano),
		now.In(bj).Format(time.RFC3339),
		now.In(bj).Format(time.RFC3339Nano),
		now.In(ny).Format(time.RFC3339),
		leap.Format(time.RFC3339),
		"2024-02-29T12:00:00Z",
		"2000-02-29T12:00:00Z",
		"2026-11-25T10:00:00+0000",
		"2026-11-25T10:00:00+15:59",
		"2026-11-25T10:00:00-15:59",
	}
	for _, s := range validSamples {
		if !re.MatchString(s) {
			t.Errorf("valid RFC3339 timestamp %q must match rfc3339TimestampRegex", s)
		}
	}

	// Malformed or partial strings that previously crashed ::timestamptz
	invalidSamples := []string{
		"",
		"not-a-date",
		"today",
		"infinity",
		"2026-11-25Tnot-a-date",
		"2026-11-25T",
		"2026-11-25",
		"2026-11-25T10:00:00",
		"0000-01-01T00:00:00Z",
		"2026-13-01T10:00:00Z",
		"2026-02-29T10:00:00Z",
		"1900-02-29T10:00:00Z",
		"2026-02-30T10:00:00Z",
		"2026-04-31T10:00:00Z",
		"2026-11-25T25:00:00Z",
		"2026-11-25T10:60:00Z",
		"2026-11-25T10:00:00+16:00",
		"2026-11-25T10:00:00-16:00",
		"2026-11-25T10:00:00+25:00",
		"2026-11-25T10:00:00Z trailing",
	}
	for _, s := range invalidSamples {
		if re.MatchString(s) {
			t.Errorf("malformed timestamp %q must NOT match rfc3339TimestampRegex", s)
		}
	}

	if !strings.Contains(refreshAssetValuesSelectSQL, "CASE") ||
		!strings.Contains(refreshAssetValuesSelectSQL, "pg_input_is_valid") ||
		!strings.Contains(refreshAssetValuesSelectSQL, "'-infinity'::timestamptz") {
		t.Fatalf("refreshAssetValuesSelectSQL must guard ::timestamptz with CASE + pg_input_is_valid fallback:\n%s", refreshAssetValuesSelectSQL)
	}
}
