// handler_test.go 节点授权 ACK 查询 HTTP 入口测试：权限矩阵（401/403/200）、
// 响应形状（§1.4 冻结字段）、设置覆盖漂移上限（含夹紧）、仓储错误 → 500。
package apiauthzacks

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apiruntime"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

type fakeAckStore struct {
	rows []AckRow
	mgmt apiruntime.VectorWatermark
	err  error
}

func (f *fakeAckStore) ListNodeAcks(context.Context) ([]AckRow, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.rows, nil
}

func (f *fakeAckStore) ManagementWatermark(context.Context) (apiruntime.VectorWatermark, error) {
	if f.err != nil {
		return apiruntime.VectorWatermark{}, f.err
	}
	return f.mgmt, nil
}

type fakeSettings struct{ v int }

func (f fakeSettings) GetInt(_ context.Context, group, key string, def int) int {
	if group == ClockSkewSettingGroup && key == ClockSkewSettingKey {
		return f.v
	}
	return def
}

var handlerNow = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

func injectPerms(perms ...string) func(http.Handler) http.Handler {
	set := map[string]bool{}
	for _, p := range perms {
		set[p] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: uuid.New(), Username: "ack-tester", PermsSet: set}
			ctx := authz.WithPrincipal(r.Context(), p)
			ctx = context.WithValue(ctx, response.RequestIDKey, "ack-rid")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func noPrincipal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { next.ServeHTTP(w, r) })
}

const nodeAcksURL = "/api/v1/api-security/authz/node-acks"

func newAckMux(store StoreAPI, settings SettingsReader, authzFn func(http.Handler) http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	h := NewHandler(store, settings)
	h.now = func() time.Time { return handlerNow }
	RegisterRoutes(mux, authzFn, h)
	return mux
}

func doGet(t *testing.T, mux http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, nodeAcksURL, nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, r)
	return rr
}

// 权限矩阵：api_authorization.read 放行；无权限 403；未登录 401（只读无新权限点）。
func TestNodeAcksPermissionMatrix(t *testing.T) {
	store := &fakeAckStore{mgmt: apiruntime.VectorWatermark{Sources: map[string]int64{}}}
	if rr := doGet(t, newAckMux(store, nil, injectPerms(PermAuthzRead))); rr.Code != http.StatusOK {
		t.Fatalf("with read perm: %d", rr.Code)
	}
	if rr := doGet(t, newAckMux(store, nil, injectPerms("api_policy.edit"))); rr.Code != http.StatusForbidden {
		t.Fatalf("wrong perm: %d, want 403", rr.Code)
	}
	if rr := doGet(t, newAckMux(store, nil, noPrincipal)); rr.Code != http.StatusUnauthorized {
		t.Fatalf("no principal: %d, want 401", rr.Code)
	}
}

// 统一信封 {code, message, data, request_id}（response.JSON）解包。
func decodeView(t *testing.T, rr *httptest.ResponseRecorder) View {
	t.Helper()
	var env struct {
		Data View `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode envelope: %v (body=%s)", err, rr.Body.String())
	}
	return env.Data
}

// 响应形状：items 冻结字段 + 顶层 max_staleness_seconds/management_watermark/
// generated_at；派生五态各一例；漂移上限经设置覆盖（120s 时 skew=100 不再越限）。
func TestNodeAcksListShape(t *testing.T) {
	applied := handlerNow.Add(-100 * time.Second)
	lastAck := handlerNow.Add(-5 * time.Second)
	wm := &apiruntime.VectorWatermark{ManualSeq: 7, Sources: map[string]int64{"s1": 3}}
	store := &fakeAckStore{
		mgmt: apiruntime.VectorWatermark{ManualSeq: 7, Sources: map[string]int64{"s1": 3}},
		rows: []AckRow{
			{NodeName: "gw-fresh", Status: "ACTIVE", HasAck: true, LastAckAt: &lastAck,
				AuthzPolicyVersion: "az-v7", AuthzWatermark: wm, AuthzAppliedAt: &applied,
				AuthzLeaseSeconds: int64p(300)},
			{NodeName: "gw-never", Status: "SILENT"},
			{NodeName: "gw-skew100", Status: "ACTIVE", HasAck: true, LastAckAt: &lastAck,
				AuthzWatermark: wm, AuthzAppliedAt: &applied, AuthzLeaseSeconds: int64p(300),
				ClockSkewSeconds: int64p(100)},
		},
	}

	// 默认上限 60：skew=100 越限 → CLOCK_SKEW
	rr := doGet(t, newAckMux(store, nil, injectPerms(PermAuthzRead)))
	if rr.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rr.Code, rr.Body.String())
	}
	view := decodeView(t, rr)
	states := map[string]string{}
	for _, it := range view.Items {
		states[it.NodeName] = it.AckState
	}
	if states["gw-fresh"] != StateFresh || states["gw-never"] != StateNeverAcked ||
		states["gw-skew100"] != StateClockSkew {
		t.Fatalf("states = %+v", states)
	}
	if view.MaxStalenessSeconds == nil || *view.MaxStalenessSeconds != 100 {
		t.Fatalf("max_staleness = %+v, want 100", view.MaxStalenessSeconds)
	}
	if view.ManagementWatermark.ManualSeq != 7 || view.ManagementWatermark.Sources["s1"] != 3 {
		t.Fatalf("management_watermark = %+v", view.ManagementWatermark)
	}
	for _, it := range view.Items {
		if it.NodeName == "gw-fresh" {
			if it.AuthzPolicyVersion != "az-v7" || it.LastAckAt == nil ||
				it.LeaseSeconds == nil || *it.LeaseSeconds != 300 || it.AuthzWatermark == nil {
				t.Fatalf("fresh item shape = %+v", it)
			}
		}
		if it.NodeName == "gw-never" && (it.StalenessSeconds != nil || it.AuthzWatermark != nil || it.LastAckAt != nil) {
			t.Fatalf("never-acked item must carry nulls: %+v", it)
		}
	}

	// 设置覆盖上限为 120：skew=100 不再越限 → FRESH（设置读取经 SettingsReader 注入）
	rr2 := doGet(t, newAckMux(store, fakeSettings{v: 120}, injectPerms(PermAuthzRead)))
	view2 := decodeView(t, rr2)
	for _, it := range view2.Items {
		if it.NodeName == "gw-skew100" && it.AckState != StateFresh {
			t.Fatalf("skew100 with max=120: %s, want FRESH", it.AckState)
		}
	}

	// 设置越界夹紧（9999 → 300 生效而非无限放宽：skew=250 在 300 内 → FRESH，
	// 但写入 5 → 夹紧 10，skew=50 越限 → CLOCK_SKEW）
	store.rows[2].ClockSkewSeconds = int64p(250)
	rr3 := doGet(t, newAckMux(store, fakeSettings{v: 9999}, injectPerms(PermAuthzRead)))
	view3 := decodeView(t, rr3)
	for _, it := range view3.Items {
		if it.NodeName == "gw-skew100" && it.AckState != StateFresh {
			t.Fatalf("skew250 with clamped max=300: %s, want FRESH", it.AckState)
		}
	}
}

// 仓储错误 → 500（不静默吞错、不伪装空视图）。
func TestNodeAcksStoreError(t *testing.T) {
	store := &fakeAckStore{err: errors.New("db down")}
	rr := doGet(t, newAckMux(store, nil, injectPerms(PermAuthzRead)))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("store error: %d, want 500", rr.Code)
	}
}
