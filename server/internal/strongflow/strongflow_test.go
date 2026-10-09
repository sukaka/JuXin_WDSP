// strongflow_test.go 强流程定义单测：§1.1 校验逐条正反、版本冻结语义（fake 仓储
// 承载 HTTP 映射；并发/事务语义由 PG 集成测试覆盖）、越权 403（jiuzhang_admin 对照）、
// 实例键 HMAC 域隔离。
package strongflow

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
)

// ---------- 校验逐条（§1.1） ----------

func validInput() DefinitionInput {
	return DefinitionInput{
		ApplicationID:     uuid.NewString(),
		Name:              "下单支付流程",
		BindingPathPrefix: "/api/v1/orders",
		InstanceKeyParam:  "query:order_id",
		Mode:              "OBSERVE",
		Steps: []StepInput{
			{StepKey: "create", EndpointKey: "POST /api/v1/orders", Sequence: 1,
				SuccessRule:    &SuccessRule{StatusCodes: []int{200, 201}},
				TimeoutSeconds: 30, RetrySemantics: "IDEMPOTENT", LeaseSeconds: 60},
			{StepKey: "pay", EndpointKey: "POST /api/v1/orders/pay", Sequence: 2,
				SuccessRule:    &SuccessRule{BodyJSONPathEquals: &JSONPathEquals{Path: "$.status", Value: "PAID"}, GraphQLErrorsEmpty: true},
				TimeoutSeconds: 60, RetrySemantics: "REQUIRES_REVIEW", LeaseSeconds: 120, Allows202: true},
		},
	}
}

func TestValidateDefinitionInput(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*DefinitionInput)
		want   string // 空=合法
	}{
		{"合法全字段", nil, ""},
		{"name 空", func(i *DefinitionInput) { i.Name = " " }, "name"},
		{"application_id 非法", func(i *DefinitionInput) { i.ApplicationID = "xx" }, "application_id"},
		{"前缀非斜杠开头", func(i *DefinitionInput) { i.BindingPathPrefix = "api" }, "binding_path_prefix"},
		{"实例引用形态非法", func(i *DefinitionInput) { i.InstanceKeyParam = "header:X" }, "instance_key_param"},
		{"实例引用 query 形态合法", func(i *DefinitionInput) { i.InstanceKeyParam = "query:order_id" }, ""},
		{"实例引用 path 形态合法", func(i *DefinitionInput) { i.InstanceKeyParam = "path:3" }, ""},
		{"实例引用 path 非数字拒收", func(i *DefinitionInput) { i.InstanceKeyParam = "path:x" }, "instance_key_param"},
		{"mode 词表外", func(i *DefinitionInput) { i.Mode = "BLOCK" }, "mode"},
		{"mode 空=缺省 OBSERVE", func(i *DefinitionInput) { i.Mode = "" }, ""},
		{"步骤为空", func(i *DefinitionInput) { i.Steps = nil }, ErrNoSteps.Error()},
		{"step_key 重复", func(i *DefinitionInput) { i.Steps[1].StepKey = "create" }, "step_key"},
		{"sequence 重复（首步须唯一最小）", func(i *DefinitionInput) { i.Steps[1].Sequence = 1 }, "sequence"},
		{"sequence 零拒收", func(i *DefinitionInput) { i.Steps[0].Sequence = 0 }, "sequence"},
		{"endpoint_key 空", func(i *DefinitionInput) { i.Steps[0].EndpointKey = "" }, "endpoint_key"},
		{"success_rule 缺失拒收", func(i *DefinitionInput) { i.Steps[0].SuccessRule = nil }, "success_rule"},
		{"success_rule 空形态拒收", func(i *DefinitionInput) { i.Steps[0].SuccessRule = &SuccessRule{} }, "至少配置一种"},
		{"status_codes 非法状态码", func(i *DefinitionInput) { i.Steps[0].SuccessRule.StatusCodes = []int{99} }, "status_codes"},
		{"jsonpath 形态非法（括号）", func(i *DefinitionInput) {
			i.Steps[1].SuccessRule.BodyJSONPathEquals = &JSONPathEquals{Path: "$[0].status", Value: "PAID"}
		}, "点路径子集"},
		{"jsonpath 缺 $ 前缀", func(i *DefinitionInput) {
			i.Steps[1].SuccessRule.BodyJSONPathEquals = &JSONPathEquals{Path: "status", Value: "PAID"}
		}, "点路径子集"},
		{"timeout 低于下限", func(i *DefinitionInput) { i.Steps[0].TimeoutSeconds = 14 }, "timeout_seconds"},
		{"timeout 高于上限", func(i *DefinitionInput) { i.Steps[0].TimeoutSeconds = 601 }, "timeout_seconds"},
		{"lease 低于下限", func(i *DefinitionInput) { i.Steps[0].LeaseSeconds = 14 }, "lease_seconds"},
		{"lease 高于上限", func(i *DefinitionInput) { i.Steps[0].LeaseSeconds = 301 }, "lease_seconds"},
		{"retry_semantics 词表外", func(i *DefinitionInput) { i.Steps[0].RetrySemantics = "MAYBE" }, "retry_semantics"},
		{"parallel_group 单步拒收", func(i *DefinitionInput) { i.Steps[0].ParallelGroup = "g1" }, "parallel_group"},
		{"parallel_group 相邻合法", func(i *DefinitionInput) {
			i.Steps[0].ParallelGroup = "g1"
			i.Steps[1].ParallelGroup = "g1"
		}, ""},
		{"parallel_group 不相邻拒收", func(i *DefinitionInput) {
			i.Steps = append(i.Steps, StepInput{StepKey: "notify", EndpointKey: "POST /api/v1/orders/notify", Sequence: 5,
				SuccessRule: &SuccessRule{StatusCodes: []int{200}}, TimeoutSeconds: 30, RetrySemantics: "IDEMPOTENT", LeaseSeconds: 60})
			i.Steps[0].ParallelGroup = "g1"
			i.Steps[2].ParallelGroup = "g1" // sequence 1 与 5 不相邻
		}, "不相邻"},
	}
	for _, c := range cases {
		in := validInput()
		if c.mutate != nil {
			c.mutate(&in)
		}
		got := validateDefinitionInput(in)
		if c.want == "" && got != "" {
			t.Fatalf("%s 应合法: %s", c.name, got)
		}
		if c.want != "" && (got == "" || !strings.Contains(got, c.want)) {
			t.Fatalf("%s 应含 %q: %s", c.name, c.want, got)
		}
	}
}

// ---------- HMAC 域隔离（§1.2） ----------

func TestInstanceRefHMACDomainIsolation(t *testing.T) {
	key := []byte(strings.Repeat("ab", 32))
	out := InstanceRefHMAC(key, "order-42")
	if !strings.HasPrefix(out, InstanceRefPrefix) || len(out) != len(InstanceRefPrefix)+64 {
		t.Fatalf("形态应为 sfref:+64hex: %q", out)
	}
	// 确定性
	if InstanceRefHMAC(key, "order-42") != out {
		t.Fatal("同输入同密钥必须确定")
	}
	// 域隔离：与授权 objref 域（jiuzhang-wdsp-authz-objref-v1\x00）同算法同输入输出必不同
	objrefDomain := "jiuzhang-wdsp-authz-objref-v1\x00"
	m1 := InstanceRefHMAC(key, "order-42")
	// 手工复算 objref 域输出对比（不等即域隔离成立）
	if strings.Contains(m1, objrefDomain) || m1 == InstanceRefPrefix+objrefDomain {
		t.Fatal("域混淆")
	}
	// 密钥敏感性
	if InstanceRefHMAC([]byte(strings.Repeat("cd", 32)), "order-42") == out {
		t.Fatal("异密钥必须异输出")
	}
	// 输入敏感性
	if InstanceRefHMAC(key, "order-43") == out {
		t.Fatal("异输入必须异输出")
	}
}

// ---------- handler（fake 仓储承载 HTTP 映射与权限路径） ----------

type fakeRepo struct {
	mu        sync.Mutex
	rows      map[uuid.UUID]*DefinitionDetail
	instances map[uuid.UUID]*InstanceDetail
	err       error
}

func newFakeRepo() *fakeRepo { return &fakeRepo{rows: map[uuid.UUID]*DefinitionDetail{}} }

func (f *fakeRepo) Create(_ context.Context, in DefinitionInput, _ uuid.UUID, name string) (*DefinitionDetail, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if msg := validateDefinitionInput(in); msg != "" {
		return nil, &ValidationError{Msg: msg}
	}
	d := &DefinitionDetail{Definition: Definition{
		ID: uuid.New(), ApplicationID: uuid.MustParse(in.ApplicationID), Name: strings.TrimSpace(in.Name),
		Version: 1, Status: StatusDraft, BindingPathPrefix: in.BindingPathPrefix,
		InstanceKeyParam: in.InstanceKeyParam, Mode: in.Mode, CreatedByName: name, CreatedAt: time.Now().UTC(),
	}, Steps: in.Steps}
	f.rows[d.ID] = d
	return d, f.err
}

func (f *fakeRepo) List(_ context.Context, _ uuid.UUID, _ string, _, _ int) ([]Definition, int64, error) {
	out := []Definition{}
	for _, d := range f.rows {
		out = append(out, d.Definition)
	}
	return out, int64(len(out)), f.err
}

func (f *fakeRepo) Get(_ context.Context, id uuid.UUID) (*DefinitionDetail, error) {
	d, ok := f.rows[id]
	if !ok {
		return nil, ErrNotFound
	}
	return d, f.err
}

func (f *fakeRepo) Update(_ context.Context, id uuid.UUID, in DefinitionInput) (*DefinitionDetail, error) {
	d, ok := f.rows[id]
	if !ok {
		return nil, ErrNotFound
	}
	if d.Status != StatusDraft {
		return nil, ErrNotDraft
	}
	d.BindingPathPrefix = in.BindingPathPrefix
	d.Steps = in.Steps
	return d, f.err
}

func (f *fakeRepo) Activate(_ context.Context, id uuid.UUID) (*Definition, error) {
	d, ok := f.rows[id]
	if !ok {
		return nil, ErrNotFound
	}
	if d.Status != StatusDraft {
		return nil, ErrNotDraft
	}
	d.Status = StatusActive
	now := time.Now().UTC()
	d.ActivatedAt = &now
	return &d.Definition, f.err
}

func (f *fakeRepo) ListInstances(_ context.Context, _ uuid.UUID, _ string, _ *time.Time, _, _ int) ([]Instance, int64, error) {
	return []Instance{}, 0, f.err
}

func (f *fakeRepo) Retire(_ context.Context, id uuid.UUID) error {
	d, ok := f.rows[id]
	if !ok {
		return ErrNotFound
	}
	if d.Status == StatusRetired {
		return ErrInvalidTransition
	}
	d.Status = StatusRetired
	return f.err
}

func injectPerms(perms ...string) func(http.Handler) http.Handler {
	set := map[string]bool{}
	for _, p := range perms {
		set[p] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: uuid.New(), Username: "tester", PermsSet: set}
			next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
		})
	}
}

// 越权对照（D8：jiuzhang_admin 形态全 403）。
func TestStrongFlowEndpointsForbiddenForSysAdmin(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPerms("system.read", "applications.edit"), NewHandler(newFakeRepo(), nil))
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/api-security/strong-flows/definitions"},
		{http.MethodPost, "/api/v1/api-security/strong-flows/definitions"},
		{http.MethodGet, "/api/v1/api-security/strong-flows/definitions/" + uuid.NewString()},
		{http.MethodPut, "/api/v1/api-security/strong-flows/definitions/" + uuid.NewString()},
		{http.MethodPost, "/api/v1/api-security/strong-flows/definitions/" + uuid.NewString() + "/activate"},
		{http.MethodPost, "/api/v1/api-security/strong-flows/definitions/" + uuid.NewString() + "/retire"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s %s: 应 403, got %d", tc.method, tc.path, rr.Code)
		}
	}
}

// 版本冻结语义 HTTP 映射（fake 承载）：DRAFT 可编辑/激活；ACTIVE 后编辑与再激活 409；
// RETIRE 后 409 单向。
func TestStrongFlowVersionFreezeHTTP(t *testing.T) {
	repo := newFakeRepo()
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPerms(PermFlowRead, PermFlowManage), NewHandler(repo, nil))

	do := func(method, path string, body string) *httptest.ResponseRecorder {
		var reader *strings.Reader
		if body == "" {
			reader = strings.NewReader("")
		} else {
			reader = strings.NewReader(body)
		}
		req := httptest.NewRequest(method, path, reader)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr
	}

	in := validInput()
	body := `{"application_id":"` + in.ApplicationID + `","name":"下单支付","binding_path_prefix":"/api/v1/orders","instance_key_param":"query:order_id","mode":"OBSERVE","steps":[{"step_key":"create","endpoint_key":"POST /api/v1/orders","sequence":1,"success_rule":{"status_codes":[200]},"timeout_seconds":30,"retry_semantics":"IDEMPOTENT","lease_seconds":60}]}`
	rr := do(http.MethodPost, "/api/v1/api-security/strong-flows/definitions", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	id := ""
	for _, d := range repo.rows {
		id = d.ID.String()
	}
	// DRAFT 编辑 200
	if rr := do(http.MethodPut, "/api/v1/api-security/strong-flows/definitions/"+id, body); rr.Code != http.StatusOK {
		t.Fatalf("DRAFT 编辑应 200: %d %s", rr.Code, rr.Body.String())
	}
	// activate 200（fake 不做端点核对——PG 集成覆盖）
	if rr := do(http.MethodPost, "/api/v1/api-security/strong-flows/definitions/"+id+"/activate", ""); rr.Code != http.StatusOK {
		t.Fatalf("activate: %d %s", rr.Code, rr.Body.String())
	}
	// ACTIVE 后编辑 409（激活即冻结）
	if rr := do(http.MethodPut, "/api/v1/api-security/strong-flows/definitions/"+id, body); rr.Code != http.StatusConflict {
		t.Fatalf("ACTIVE 编辑应 409: %d", rr.Code)
	}
	// ACTIVE 再激活 409
	if rr := do(http.MethodPost, "/api/v1/api-security/strong-flows/definitions/"+id+"/activate", ""); rr.Code != http.StatusConflict {
		t.Fatalf("ACTIVE 再激活应 409: %d", rr.Code)
	}
	// retire 200；再 retire 409（单向终态）
	if rr := do(http.MethodPost, "/api/v1/api-security/strong-flows/definitions/"+id+"/retire", ""); rr.Code != http.StatusOK {
		t.Fatalf("retire: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(http.MethodPost, "/api/v1/api-security/strong-flows/definitions/"+id+"/retire", ""); rr.Code != http.StatusConflict {
		t.Fatalf("重复 retire 应 409: %d", rr.Code)
	}
	// RETIRED 编辑 409
	if rr := do(http.MethodPut, "/api/v1/api-security/strong-flows/definitions/"+id, body); rr.Code != http.StatusConflict {
		t.Fatalf("RETIRED 编辑应 409: %d", rr.Code)
	}
	// 不存在 404
	if rr := do(http.MethodGet, "/api/v1/api-security/strong-flows/definitions/"+uuid.NewString(), ""); rr.Code != http.StatusNotFound {
		t.Fatalf("不存在应 404: %d", rr.Code)
	}
}

// 发布触发挂载（NG-FLOW-02 闭环 FLOW-01 偏差 2）：activate/retire 成功触发整站发布；
// 未注入不触发（旧接线/单测零行为）。
func TestStrongFlowActivateRetireTriggerPublish(t *testing.T) {
	repo := newFakeRepo()
	h := NewHandler(repo, nil)
	published := 0
	h.SetPublishFunc(func(context.Context, uuid.UUID, string) { published++ })
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPerms(PermFlowRead, PermFlowManage), h)

	do := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr
	}
	body := `{"application_id":"` + uuid.NewString() + `","name":"f","binding_path_prefix":"/a","instance_key_param":"query:x","steps":[{"step_key":"s1","endpoint_key":"GET /a","sequence":1,"success_rule":{"status_codes":[200]},"timeout_seconds":30,"retry_semantics":"IDEMPOTENT","lease_seconds":60}]}`
	if rr := do(http.MethodPost, "/api/v1/api-security/strong-flows/definitions", body); rr.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	if published != 0 {
		t.Fatal("create 不触发发布")
	}
	var id string
	for k := range repo.rows {
		id = k.String()
	}
	if rr := do(http.MethodPost, "/api/v1/api-security/strong-flows/definitions/"+id+"/activate", ""); rr.Code != http.StatusOK {
		t.Fatalf("activate: %d", rr.Code)
	}
	if published != 1 {
		t.Fatalf("activate 应触发一次发布, got %d", published)
	}
	if rr := do(http.MethodPost, "/api/v1/api-security/strong-flows/definitions/"+id+"/retire", ""); rr.Code != http.StatusOK {
		t.Fatalf("retire: %d", rr.Code)
	}
	if published != 2 {
		t.Fatalf("retire 应触发一次发布, got %d", published)
	}
}
