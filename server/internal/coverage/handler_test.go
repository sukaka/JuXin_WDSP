// handler_test.go 统一执行覆盖查询 HTTP 入口测试：权限矩阵 / 参数校验 /
// agg 视图（E=0 口径、data_incomplete、空数据空数组）/ stages 视图（冻结顺序键集）/
// 窗口夹紧。内存仓储驱动真实 Handler 与路由（handler 与 store 解耦注入）。
package coverage

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// fakeRepo 内存仓储（按 stageSet 区分 guard 阶段集与 cov_ingest 摄入集）。
type fakeRepo struct {
	aggRows      []Metrics
	lastAggQuery AggQuery

	guardSnaps []NodeStageSnapshot
	ingestSnap []NodeStageSnapshot

	lastStageSet []string
	lastNodeID   string
	lastFrom     time.Time
	lastTo       time.Time
}

func (f *fakeRepo) QueryAggView(ctx context.Context, aq AggQuery) ([]Metrics, error) {
	f.lastAggQuery = aq
	return f.aggRows, nil
}

func (f *fakeRepo) LatestStageCounts(ctx context.Context, stageSet []string, nodeID string, from, to time.Time) ([]NodeStageSnapshot, error) {
	f.lastStageSet = stageSet
	f.lastNodeID = nodeID
	f.lastFrom = from
	f.lastTo = to
	for _, s := range stageSet {
		if s == "total" {
			return f.guardSnaps, nil
		}
	}
	return f.ingestSnap, nil
}

// injectPrincipal 模拟认证链：注入持有给定权限点集合的主体。
func injectPrincipal(perms ...string) func(http.Handler) http.Handler {
	set := map[string]bool{}
	for _, p := range perms {
		set[p] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: uuid.New(), Username: "cov-tester", PermsSet: set}
			ctx := authz.WithPrincipal(r.Context(), p)
			ctx = context.WithValue(ctx, response.RequestIDKey, "cov-rid")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// noPrincipal 模拟未注入主体的认证链（权限中间件应 401）。
func noPrincipal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

var fixedClock = time.Date(2026, 10, 3, 14, 0, 0, 0, time.UTC)

func newTestMux(repo *fakeRepo, authzFn func(http.Handler) http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	h := NewHandler(repo)
	h.now = func() time.Time { return fixedClock }
	RegisterRoutes(mux, authzFn, h)
	return mux
}

func doGet(t *testing.T, mux http.Handler, url string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

const covPath = "/api/v1/api-security/protection/coverage"

// 权限矩阵：未登录 401 / 无权限 403 / api_protection.read 200。
func TestCoveragePermissionMatrix(t *testing.T) {
	repo := &fakeRepo{}
	if rr := doGet(t, newTestMux(repo, noPrincipal), covPath); rr.Code != http.StatusUnauthorized {
		t.Fatalf("no principal: got %d", rr.Code)
	}
	if rr := doGet(t, newTestMux(repo, injectPrincipal("api_runtime.read")), covPath); rr.Code != http.StatusForbidden {
		t.Fatalf("wrong perm: got %d", rr.Code)
	}
	if rr := doGet(t, newTestMux(repo, injectPrincipal(PermProtectionRead)), covPath); rr.Code != http.StatusOK {
		t.Fatalf("api_protection.read: got %d body=%s", rr.Code, rr.Body.String())
	}
}

// 参数校验：非法 application_id / 超长 detector / 超长 node_id / 非法 view / 非数字 window_minutes → 400。
func TestCoverageQueryValidation(t *testing.T) {
	mux := newTestMux(&fakeRepo{}, injectPrincipal(PermProtectionRead))
	for _, url := range []string{
		covPath + "?application_id=not-a-uuid",
		covPath + "?detector=" + strings.Repeat("d", 97),
		covPath + "?node_id=" + strings.Repeat("n", 97),
		covPath + "?view=bogus",
		covPath + "?window_minutes=abc",
	} {
		if rr := doGet(t, mux, url); rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: got %d body=%s", url, rr.Code, rr.Body.String())
		}
	}
}

// agg 视图：E=0 行 no_applicable_traffic=true 且比率为 0（绝不出现 100%）；
// 正常行 E 与比率查询侧已算好透传；默认窗口 60 分钟。
func TestCoverageAggViewEZeroNeverHundred(t *testing.T) {
	repo := &fakeRepo{aggRows: []Metrics{
		{ // 有适用流量行：E=7，FULL=5 PARTIAL=1 SKIPPED=1
			DimKey: DimKey{ApplicationID: "app-1", EndpointKey: "GET /v1/a", Detector: "d1",
				Phase: "request", PolicyVersion: "p1", NodeID: "node-1", Minute: fixedClock.Add(-time.Hour)},
			Bucket: Bucket{Full: 5, Partial: 1, Skipped: 1},
			E:      7, FullRate: 5.0 / 7.0, EffectiveRate: 6.0 / 7.0,
		},
		{ // E=0 行（仅 NOT_APPLICABLE）：绝不显示 100%
			DimKey: DimKey{ApplicationID: "app-1", EndpointKey: "GET /v1/b", Detector: "d2",
				Phase: "request", PolicyVersion: "p1", NodeID: "node-1", Minute: fixedClock.Add(-time.Hour)},
			Bucket:              Bucket{NotApplicable: 3},
			E:                   0,
			NoApplicableTraffic: true,
		},
	}}
	mux := newTestMux(repo, injectPrincipal(PermProtectionRead))
	rr := doGet(t, mux, covPath)
	if rr.Code != http.StatusOK {
		t.Fatalf("agg: %d %s", rr.Code, rr.Body.String())
	}
	var body struct {
		Data aggViewData `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	d := body.Data
	if d.View != "agg" || d.WindowMinutes != defaultWindowMinutes || d.DataIncomplete {
		t.Fatalf("agg 视图元信息不符: %+v", d)
	}
	if len(d.Rows) != 2 {
		t.Fatalf("rows=%d want 2", len(d.Rows))
	}
	row0 := d.Rows[0]
	if row0.E != 7 || row0.FullRate != 5.0/7.0 || row0.EffectiveRate != 6.0/7.0 || row0.NoApplicableTraffic {
		t.Fatalf("正常行口径不符: %+v", row0)
	}
	row1 := d.Rows[1]
	if !row1.NoApplicableTraffic || row1.FullRate != 0 || row1.EffectiveRate != 0 || row1.E != 0 {
		t.Fatalf("E=0 行必须 no_applicable_traffic=true 且比率为 0（绝不 100%%）: %+v", row1)
	}
	// 窗口口径透传到仓储查询
	if repo.lastAggQuery.From != fixedClock.Add(-60*time.Minute) || !repo.lastAggQuery.To.Equal(fixedClock) {
		t.Fatalf("窗口不符: from=%v to=%v", repo.lastAggQuery.From, repo.lastAggQuery.To)
	}
}

// data_incomplete：窗口内最新 cov_ingest 快照 agg_overflow>0 → true；全零 → false。
func TestCoverageAggDataIncomplete(t *testing.T) {
	repo := &fakeRepo{
		ingestSnap: []NodeStageSnapshot{{
			NodeID: "node-1", CapturedAt: fixedClock.Add(-time.Minute),
			Counts: map[string]int64{stageAggOverflow: 2, stageAggInvalid: 0},
		}},
	}
	mux := newTestMux(repo, injectPrincipal(PermProtectionRead))
	var body struct {
		Data aggViewData `json:"data"`
	}
	rr := doGet(t, mux, covPath)
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Data.DataIncomplete {
		t.Fatal("agg_overflow>0 时 data_incomplete 必须为 true（不显示虚假完整）")
	}
	// 摄入遥测查询必须使用累计口径的两个 stage，且节点过滤透传
	if len(repo.lastStageSet) != 2 || repo.lastStageSet[0] != stageAggOverflow || repo.lastStageSet[1] != stageAggInvalid {
		t.Fatalf("data_incomplete stage 集不符: %v", repo.lastStageSet)
	}

	repo.ingestSnap = []NodeStageSnapshot{{
		NodeID: "node-1", CapturedAt: fixedClock.Add(-time.Minute),
		Counts: map[string]int64{stageAggOverflow: 0, stageAggInvalid: 0},
	}}
	rr = doGet(t, mux, covPath)
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if body.Data.DataIncomplete {
		t.Fatal("累计为零时 data_incomplete 必须为 false")
	}
}

// stages 视图：冻结顺序键集（11 阶段保序，缺失补零）+ captured_at。
func TestCoverageStagesViewFrozenOrder(t *testing.T) {
	captured := fixedClock.Add(-2 * time.Minute)
	repo := &fakeRepo{
		guardSnaps: []NodeStageSnapshot{{
			NodeID: "gateway-stage5-01", CapturedAt: captured,
			Counts: map[string]int64{"total": 42, "rejected_cc": 3, "reached_upstream": 30},
		}},
	}
	mux := newTestMux(repo, injectPrincipal(PermProtectionRead))
	rr := doGet(t, mux, covPath+"?view=stages")
	if rr.Code != http.StatusOK {
		t.Fatalf("stages: %d %s", rr.Code, rr.Body.String())
	}
	var body struct {
		Data stagesViewData `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	d := body.Data
	if d.View != "stages" || len(d.Nodes) != 1 {
		t.Fatalf("stages 元信息不符: %+v", d)
	}
	node := d.Nodes[0]
	if node.NodeID != "gateway-stage5-01" || !node.CapturedAt.Equal(captured) {
		t.Fatalf("节点行不符: %+v", node)
	}
	if len(node.Counts) != len(guardStageOrder) {
		t.Fatalf("counts 键数=%d want %d（冻结阶段集全量保序）", len(node.Counts), len(guardStageOrder))
	}
	for i, item := range node.Counts {
		if item.Stage != guardStageOrder[i] {
			t.Fatalf("第 %d 阶段=%s want %s（顺序冻结）", i, item.Stage, guardStageOrder[i])
		}
	}
	if node.Counts[0].Stage != "total" || node.Counts[0].Count != 42 {
		t.Fatalf("total 不符: %+v", node.Counts[0])
	}
	if node.Counts[5].Stage != "rejected_cc" || node.Counts[5].Count != 3 {
		t.Fatalf("rejected_cc 不符: %+v", node.Counts[5])
	}
	if node.Counts[10].Stage != "reached_upstream" || node.Counts[10].Count != 30 {
		t.Fatalf("reached_upstream 不符: %+v", node.Counts[10])
	}
	// 缺失阶段补零
	if node.Counts[8].Stage != "intercepted_waf" || node.Counts[8].Count != 0 {
		t.Fatalf("缺失阶段应补零: %+v", node.Counts[8])
	}
	// 查询须按 guard 阶段集过滤（与 cov_ingest 遥测同表不同 captured_at 源）
	if len(repo.lastStageSet) != len(guardStageOrder) || repo.lastStageSet[0] != "total" {
		t.Fatalf("stages 查询 stage 集不符: %v", repo.lastStageSet)
	}
}

// 窗口夹紧：越界夹紧 10080、非正数归一 60（非法非数字在参数校验用例已覆盖 400）。
func TestCoverageWindowClamp(t *testing.T) {
	repo := &fakeRepo{}
	mux := newTestMux(repo, injectPrincipal(PermProtectionRead))
	var body struct {
		Data aggViewData `json:"data"`
	}

	rr := doGet(t, mux, covPath+"?window_minutes=99999")
	if rr.Code != http.StatusOK {
		t.Fatalf("越界应夹紧不报错: %d", rr.Code)
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if body.Data.WindowMinutes != maxWindowMinutes {
		t.Fatalf("window_minutes=99999 应夹紧 %d, got %d", maxWindowMinutes, body.Data.WindowMinutes)
	}
	if repo.lastAggQuery.From != fixedClock.Add(-time.Duration(maxWindowMinutes)*time.Minute) {
		t.Fatalf("夹紧后窗口起点不符: %v", repo.lastAggQuery.From)
	}

	for _, raw := range []string{"0", "-5"} {
		rr = doGet(t, mux, covPath+"?window_minutes="+raw)
		if rr.Code != http.StatusOK {
			t.Fatalf("window_minutes=%s 应归一不报错: %d", raw, rr.Code)
		}
		_ = json.Unmarshal(rr.Body.Bytes(), &body)
		if body.Data.WindowMinutes != defaultWindowMinutes {
			t.Fatalf("window_minutes=%s 应归一 %d, got %d", raw, defaultWindowMinutes, body.Data.WindowMinutes)
		}
	}
}

// 空数据：rows/nodes 必须为空数组而非 null。
func TestCoverageEmptyDataEmptyArray(t *testing.T) {
	mux := newTestMux(&fakeRepo{}, injectPrincipal(PermProtectionRead))
	rr := doGet(t, mux, covPath)
	if !strings.Contains(rr.Body.String(), `"rows":[]`) {
		t.Fatalf("空 agg 数据必须 rows:[]: %s", rr.Body.String())
	}
	rr = doGet(t, mux, covPath+"?view=stages")
	if !strings.Contains(rr.Body.String(), `"nodes":[]`) {
		t.Fatalf("空 stages 数据必须 nodes:[]: %s", rr.Body.String())
	}
}
