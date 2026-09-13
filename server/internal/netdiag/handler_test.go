// handler_test.go 网络诊断接口单元测试：参数校验矩阵、权限门控、
// 停止状态机、产物下载（404/409/sha256 不符）、审计记录。
package netdiag

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
)

// auditSpy 审计记录 spy。
type auditSpy struct {
	mu     sync.Mutex
	inputs []audits.RecordInput
}

func (s *auditSpy) Record(_ context.Context, in audits.RecordInput) error {
	s.mu.Lock()
	s.inputs = append(s.inputs, in)
	s.mu.Unlock()
	return nil
}

func (s *auditSpy) last() audits.RecordInput {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.inputs) == 0 {
		return audits.RecordInput{}
	}
	return s.inputs[len(s.inputs)-1]
}

// storeStub 任务仓储 stub（内存态，支持状态机断言）。
type storeStub struct {
	mu          sync.Mutex
	jobs        map[uuid.UUID]*Job
	stopPending bool // StopPending 返回值
	createErr   error
}

func newStoreStub() *storeStub {
	return &storeStub{jobs: map[uuid.UUID]*Job{}, stopPending: true}
}

func (s *storeStub) Create(_ context.Context, node, action, target string, params Params, requestedBy *uuid.UUID, requestID string) (*Job, error) {
	if s.createErr != nil {
		return nil, s.createErr
	}
	raw, _ := json.Marshal(params)
	j := &Job{
		ID: uuid.New(), Node: node, Action: action, Target: target, Params: raw,
		Status: StatusPending, RequestedBy: requestedBy, RequestID: requestID, CreatedAt: time.Now(),
	}
	s.mu.Lock()
	s.jobs[j.ID] = j
	s.mu.Unlock()
	return j, nil
}

func (s *storeStub) GetByID(_ context.Context, id uuid.UUID) (*Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if j, ok := s.jobs[id]; ok {
		return j, nil
	}
	return nil, ErrNotFound
}

func (s *storeStub) List(_ context.Context, action, status string, page, pageSize int) ([]Job, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Job{}
	for _, j := range s.jobs {
		if action != "" && j.Action != action {
			continue
		}
		if status != "" && j.Status != status {
			continue
		}
		out = append(out, *j)
		out[len(out)-1].CapturePackets = nil // 对齐生产 SQL：列表不查 capture_packets 列
	}
	return out, int64(len(out)), nil
}

func (s *storeStub) StopPending(_ context.Context, id uuid.UUID) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if j, ok := s.jobs[id]; ok && j.Status == StatusPending && s.stopPending {
		j.Status = StatusStopped
		return true, nil
	}
	return false, nil
}

func (s *storeStub) add(j *Job) {
	s.mu.Lock()
	s.jobs[j.ID] = j
	s.mu.Unlock()
}

// injectPrincipal 构造注入指定权限点主体的认证链。
func injectPrincipal(userID uuid.UUID, perms ...string) func(http.Handler) http.Handler {
	set := map[string]bool{}
	for _, p := range perms {
		set[p] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: userID, Username: "tester", PermsSet: set}
			next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
		})
	}
}

type handlerEnv struct {
	handler    http.Handler
	audits     *auditSpy
	store      *storeStub
	sidecarDir string
	dataDir    string
}

func newHandlerEnv(t *testing.T, authenticated bool, perms ...string) *handlerEnv {
	t.Helper()
	spy := &auditSpy{}
	st := newStoreStub()
	sidecar := t.TempDir()
	data := t.TempDir()
	uid := uuid.New()
	authChain := func(next http.Handler) http.Handler { return next }
	if authenticated {
		authChain = injectPrincipal(uid, perms...)
	}
	h := NewHandler(st, spy, sidecar, data, "it-gateway-01")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, authChain)
	return &handlerEnv{handler: mux, audits: spy, store: st, sidecarDir: sidecar, dataDir: data}
}

type apiBody struct {
	Code    string          `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

func doReq(t *testing.T, h http.Handler, method, path, body string) (int, apiBody, http.Header) {
	t.Helper()
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	} else {
		rdr = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out apiBody
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out, rec.Header()
}

const execPerm = "network_tools.execute"
const dlPerm = "network_tools.download"

func TestCreatePermissionDenied(t *testing.T) {
	env := newHandlerEnv(t, true) // 无任何权限点
	code, body, _ := doReq(t, env.handler, http.MethodPost, "/api/v1/network-tools/jobs", `{"action":"ping","target":"10.0.0.1"}`)
	if code != http.StatusForbidden || body.Code != "PERMISSION_DENIED" {
		t.Fatalf("无权限应 403: code=%d body=%+v", code, body)
	}
	if got := len(env.audits.inputs); got != 0 {
		t.Fatalf("权限拒绝不应记审计，实际 %d 条", got)
	}
}

func TestCreateSuccessAndAudit(t *testing.T) {
	env := newHandlerEnv(t, true, execPerm)
	code, body, _ := doReq(t, env.handler, http.MethodPost, "/api/v1/network-tools/jobs", `{"action":"ping","target":"10.0.0.1"}`)
	if code != http.StatusCreated || body.Code != "SUCCESS" {
		t.Fatalf("创建应 201: code=%d body=%+v", code, body)
	}
	var data struct {
		Job Job `json:"job"`
	}
	if err := json.Unmarshal(body.Data, &data); err != nil {
		t.Fatalf("解析 data: %v", err)
	}
	if data.Job.Status != StatusPending || data.Job.Action != ActionPing || data.Job.Node != "it-gateway-01" {
		t.Fatalf("任务内容不符: %+v", data.Job)
	}
	// 缺省 count=4 应补齐
	if got := data.Job.DecodeParams().Count; got != defaultPingCount {
		t.Fatalf("缺省 count 应为 %d，实际 %d", defaultPingCount, got)
	}
	au := env.audits.last()
	if au.Module != "network_tools" || au.Action != "execute" || au.Result != audits.ResultSuccess || au.RiskLevel != audits.RiskMedium {
		t.Fatalf("审计内容不符: %+v", au)
	}
}

func TestCreateValidationMatrix(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"非法 action", `{"action":"nmap","target":"10.0.0.1"}`},
		{"空 target", `{"action":"ping","target":""}`},
		{"target 含 shell 元字符", `{"action":"ping","target":"10.0.0.1;rm -rf /"}`},
		{"target 以 - 开头", `{"action":"ping","target":"-evil.com"}`},
		{"target 含空格", `{"action":"ping","target":"10.0.0.1 8.8.8.8"}`},
		{"ping count 越界", `{"action":"ping","target":"10.0.0.1","count":21}`},
		{"tcp_probe 缺 port", `{"action":"tcp_probe","target":"10.0.0.1"}`},
		{"tcp_probe port 越界", `{"action":"tcp_probe","target":"10.0.0.1","port":65536}`},
		{"traceroute max_hops 越界", `{"action":"traceroute","target":"10.0.0.1","max_hops":31}`},
		{"capture 缺 iface", `{"action":"capture","target":"10.0.0.1","duration_sec":10}`},
		{"capture iface 非法", `{"action":"capture","target":"10.0.0.1","iface":"eth0;id","duration_sec":10}`},
		{"capture duration 越界", `{"action":"capture","target":"10.0.0.1","iface":"eth0","duration_sec":4}`},
		{"capture filter_proto 非法", `{"action":"capture","target":"10.0.0.1","iface":"eth0","filter_proto":"gre"}`},
		{"capture filter_port 越界", `{"action":"capture","target":"10.0.0.1","iface":"eth0","filter_port":65536}`},
		{"capture filter_host 非法", `{"action":"capture","target":"10.0.0.1","iface":"eth0","filter_host":"$(id)"}`},
		{"node 非法", `{"action":"ping","target":"10.0.0.1","node":"node;rm"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newHandlerEnv(t, true, execPerm)
			code, body, _ := doReq(t, env.handler, http.MethodPost, "/api/v1/network-tools/jobs", tc.body)
			if code != http.StatusBadRequest || body.Code != "INVALID_ARGUMENT" {
				t.Fatalf("应 400: code=%d body=%+v", code, body)
			}
			if got := len(env.audits.inputs); got != 0 {
				t.Fatalf("参数错误不应记审计，实际 %d 条", got)
			}
		})
	}
}

func TestCreateValidVariants(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"ping 主机名", `{"action":"ping","target":"example.com","count":2}`},
		{"ping IPv6", `{"action":"ping","target":"::1"}`},
		{"tcp_probe", `{"action":"tcp_probe","target":"10.0.0.1","port":443}`},
		{"traceroute", `{"action":"traceroute","target":"10.0.0.1","max_hops":10}`},
		{"dns_query", `{"action":"dns_query","target":"example.com"}`},
		{"capture 全参数", `{"action":"capture","target":"10.0.0.1","iface":"eth0.100","duration_sec":30,"filter_proto":"tcp","filter_port":443,"filter_host":"example.com"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newHandlerEnv(t, true, execPerm)
			code, body, _ := doReq(t, env.handler, http.MethodPost, "/api/v1/network-tools/jobs", tc.body)
			if code != http.StatusCreated {
				t.Fatalf("应 201: code=%d body=%s", code, body.Data)
			}
		})
	}
}

func TestListAndGet(t *testing.T) {
	env := newHandlerEnv(t, true, execPerm)
	env.store.add(&Job{ID: uuid.New(), Node: "n1", Action: ActionPing, Target: "10.0.0.1", Status: StatusSuccess, ResultText: "ok", CreatedAt: time.Now()})
	env.store.add(&Job{ID: uuid.New(), Node: "n1", Action: ActionCapture, Target: "10.0.0.2", Status: StatusRunning, CreatedAt: time.Now()})

	code, body, _ := doReq(t, env.handler, http.MethodGet, "/api/v1/network-tools/jobs", "")
	if code != http.StatusOK {
		t.Fatalf("列表应 200: code=%d", code)
	}
	var page struct {
		Items []Job `json:"items"`
		Total int64 `json:"total"`
	}
	if err := json.Unmarshal(body.Data, &page); err != nil {
		t.Fatalf("解析分页: %v", err)
	}
	if page.Total != 2 || len(page.Items) != 2 {
		t.Fatalf("分页内容不符: %+v", page)
	}

	// 过滤
	code, body, _ = doReq(t, env.handler, http.MethodGet, "/api/v1/network-tools/jobs?action=capture", "")
	if code != http.StatusOK {
		t.Fatalf("过滤列表应 200: code=%d", code)
	}
	if err := json.Unmarshal(body.Data, &page); err != nil {
		t.Fatalf("解析分页: %v", err)
	}
	if page.Total != 1 {
		t.Fatalf("action 过滤应 1 条，实际 %d", page.Total)
	}
	// 非法过滤值
	code, _, _ = doReq(t, env.handler, http.MethodGet, "/api/v1/network-tools/jobs?status=BOGUS", "")
	if code != http.StatusBadRequest {
		t.Fatalf("非法 status 过滤应 400: code=%d", code)
	}

	// 详情
	var firstID uuid.UUID
	for id := range env.store.jobs {
		firstID = id
		break
	}
	code, body, _ = doReq(t, env.handler, http.MethodGet, "/api/v1/network-tools/jobs/"+firstID.String(), "")
	if code != http.StatusOK {
		t.Fatalf("详情应 200: code=%d", code)
	}
	var detail struct {
		Job Job `json:"job"`
	}
	if err := json.Unmarshal(body.Data, &detail); err != nil {
		t.Fatalf("解析详情: %v", err)
	}
	if detail.Job.ID != firstID {
		t.Fatalf("详情 ID 不符: %+v", detail.Job)
	}
	// 不存在
	code, _, _ = doReq(t, env.handler, http.MethodGet, "/api/v1/network-tools/jobs/"+uuid.NewString(), "")
	if code != http.StatusNotFound {
		t.Fatalf("不存在应 404: code=%d", code)
	}
	// 非法 ID
	code, _, _ = doReq(t, env.handler, http.MethodGet, "/api/v1/network-tools/jobs/not-a-uuid", "")
	if code != http.StatusBadRequest {
		t.Fatalf("非法 ID 应 400: code=%d", code)
	}
}

// TestGetDetailCapturePackets 详情响应带 capture_packets（数组）；
// 未解析（列 NULL）时字段为 null；列表响应不带大字段。
func TestGetDetailCapturePackets(t *testing.T) {
	env := newHandlerEnv(t, true, execPerm)
	parsed := &Job{
		ID: uuid.New(), Node: "it-gateway-01", Action: ActionCapture, Target: "10.0.0.1",
		Status: StatusSuccess, CaptureFile: "capture-x.pcap",
		CapturePackets: json.RawMessage(`[{"no":1,"ts":"2023-11-14T22:13:20.123456Z","src":"172.19.0.1","dst":"172.19.0.2","sport":52344,"dport":8080,"proto":"TCP","flags":"SYN,ACK","length":74,"preview":"GET / HTTP/1.1"}]`),
		CreatedAt:      time.Now(),
	}
	unparsed := &Job{
		ID: uuid.New(), Node: "it-gateway-01", Action: ActionCapture, Target: "10.0.0.2",
		Status: StatusSuccess, CaptureFile: "capture-y.pcap", CreatedAt: time.Now(),
	}
	env.store.add(parsed)
	env.store.add(unparsed)

	// 已解析 → 详情带数组
	code, body, _ := doReq(t, env.handler, http.MethodGet, "/api/v1/network-tools/jobs/"+parsed.ID.String(), "")
	if code != http.StatusOK {
		t.Fatalf("详情应 200: code=%d", code)
	}
	var detail struct {
		Job struct {
			CapturePackets []CapturePacket `json:"capture_packets"`
		} `json:"job"`
	}
	if err := json.Unmarshal(body.Data, &detail); err != nil {
		t.Fatalf("解析详情: %v", err)
	}
	if len(detail.Job.CapturePackets) != 1 || detail.Job.CapturePackets[0].Proto != "TCP" ||
		detail.Job.CapturePackets[0].Sport == nil || *detail.Job.CapturePackets[0].Sport != 52344 {
		t.Fatalf("capture_packets 不符: %+v", detail.Job.CapturePackets)
	}

	// 未解析 → 详情字段显式为 null
	code, body, _ = doReq(t, env.handler, http.MethodGet, "/api/v1/network-tools/jobs/"+unparsed.ID.String(), "")
	if code != http.StatusOK {
		t.Fatalf("详情应 200: code=%d", code)
	}
	var rawDetail struct {
		Job map[string]json.RawMessage `json:"job"`
	}
	if err := json.Unmarshal(body.Data, &rawDetail); err != nil {
		t.Fatalf("解析详情: %v", err)
	}
	if got := string(rawDetail.Job["capture_packets"]); got != "null" {
		t.Fatalf("未解析时 capture_packets 应为 null，实际 %q", got)
	}

	// 列表 → 不带 capture_packets 大字段（恒为 null）
	code, body, _ = doReq(t, env.handler, http.MethodGet, "/api/v1/network-tools/jobs", "")
	if code != http.StatusOK {
		t.Fatalf("列表应 200: code=%d", code)
	}
	var page struct {
		Items []map[string]json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(body.Data, &page); err != nil {
		t.Fatalf("解析分页: %v", err)
	}
	for _, item := range page.Items {
		if got := string(item["capture_packets"]); got != "null" {
			t.Fatalf("列表项 capture_packets 应为 null（不查该列），实际 %q", got)
		}
	}
}

func TestStopStateMachine(t *testing.T) {
	// PENDING → 受理，直接置 STOPPED
	env := newHandlerEnv(t, true, execPerm)
	pending := &Job{ID: uuid.New(), Node: "it-gateway-01", Action: ActionPing, Target: "10.0.0.1", Status: StatusPending, CreatedAt: time.Now()}
	env.store.add(pending)
	code, body, _ := doReq(t, env.handler, http.MethodPost, "/api/v1/network-tools/jobs/"+pending.ID.String()+"/stop", "")
	if code != http.StatusOK || body.Code != "SUCCESS" {
		t.Fatalf("PENDING 停止应 200: code=%d body=%+v", code, body)
	}
	if pending.Status != StatusStopped {
		t.Fatalf("PENDING 应直接置 STOPPED，实际 %s", pending.Status)
	}
	au := env.audits.last()
	if au.Action != "stop" || au.RiskLevel != audits.RiskLow || au.Result != audits.ResultSuccess {
		t.Fatalf("停止审计不符: %+v", au)
	}

	// RUNNING → 受理，写停止标记文件
	running := &Job{ID: uuid.New(), Node: "it-gateway-01", Action: ActionCapture, Target: "10.0.0.1", Status: StatusRunning, CreatedAt: time.Now()}
	env.store.add(running)
	code, _, _ = doReq(t, env.handler, http.MethodPost, "/api/v1/network-tools/jobs/"+running.ID.String()+"/stop", "")
	if code != http.StatusOK {
		t.Fatalf("RUNNING 停止应 200: code=%d", code)
	}
	if _, err := os.Stat(stopFlagPath(env.sidecarDir, running.ID)); err != nil {
		t.Fatalf("RUNNING 停止应写停止标记文件: %v", err)
	}

	// 终态 → 409
	for _, st := range []string{StatusSuccess, StatusFailed, StatusStopped, StatusTimeout} {
		done := &Job{ID: uuid.New(), Node: "n1", Action: ActionPing, Target: "10.0.0.1", Status: st, CreatedAt: time.Now()}
		env.store.add(done)
		code, _, _ = doReq(t, env.handler, http.MethodPost, "/api/v1/network-tools/jobs/"+done.ID.String()+"/stop", "")
		if code != http.StatusConflict {
			t.Fatalf("%s 停止应 409: code=%d", st, code)
		}
	}
	// 不存在 → 404
	code, _, _ = doReq(t, env.handler, http.MethodPost, "/api/v1/network-tools/jobs/"+uuid.NewString()+"/stop", "")
	if code != http.StatusNotFound {
		t.Fatalf("不存在应 404: code=%d", code)
	}
}

// makeCaptureArtifact 在数据目录伪造产物并返回入库元数据。
func makeCaptureArtifact(t *testing.T, dataDir string, id uuid.UUID, content []byte) (string, int64) {
	t.Helper()
	path, err := CapturePath(dataDir, id)
	if err != nil {
		t.Fatalf("CapturePath: %v", err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("写产物: %v", err)
	}
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:]), int64(len(content))
}

func TestDownload(t *testing.T) {
	env := newHandlerEnv(t, true, dlPerm)

	// 非 capture 任务 → 400
	pingJob := &Job{ID: uuid.New(), Node: "n1", Action: ActionPing, Target: "10.0.0.1", Status: StatusSuccess, CreatedAt: time.Now()}
	env.store.add(pingJob)
	code, _, _ := doReq(t, env.handler, http.MethodGet, "/api/v1/network-tools/jobs/"+pingJob.ID.String()+"/download", "")
	if code != http.StatusBadRequest {
		t.Fatalf("非 capture 下载应 400: code=%d", code)
	}

	// 非 SUCCESS → 409
	running := &Job{ID: uuid.New(), Node: "n1", Action: ActionCapture, Target: "10.0.0.1", Status: StatusRunning, CreatedAt: time.Now()}
	env.store.add(running)
	code, _, _ = doReq(t, env.handler, http.MethodGet, "/api/v1/network-tools/jobs/"+running.ID.String()+"/download", "")
	if code != http.StatusConflict {
		t.Fatalf("非 SUCCESS 下载应 409: code=%d", code)
	}

	// SUCCESS 但无产物 → 404
	noArtifact := &Job{ID: uuid.New(), Node: "n1", Action: ActionCapture, Target: "10.0.0.1", Status: StatusSuccess, CreatedAt: time.Now()}
	env.store.add(noArtifact)
	code, _, _ = doReq(t, env.handler, http.MethodGet, "/api/v1/network-tools/jobs/"+noArtifact.ID.String()+"/download", "")
	if code != http.StatusNotFound {
		t.Fatalf("无产物应 404: code=%d", code)
	}

	// sha256 不符 → 409 + 失败审计
	content := []byte("pcap-bytes")
	bad := &Job{ID: uuid.New(), Node: "n1", Action: ActionCapture, Target: "10.0.0.1", Status: StatusSuccess,
		CaptureFile: "capture-bad.pcap", CaptureHash: strings.Repeat("0", 64), CreatedAt: time.Now()}
	env.store.add(bad)
	if _, err := CapturePath(env.dataDir, bad.ID); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(env.dataDir, CaptureFileName(bad.ID)), content, 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, _ = doReq(t, env.handler, http.MethodGet, "/api/v1/network-tools/jobs/"+bad.ID.String()+"/download", "")
	if code != http.StatusConflict {
		t.Fatalf("sha256 不符应 409: code=%d", code)
	}
	au := env.audits.last()
	if au.Action != "download" || au.Result != audits.ResultFailure {
		t.Fatalf("完整性失败应记 FAILURE 审计: %+v", au)
	}

	// 正常下载 → 200 + 内容一致 + 审计
	good := &Job{ID: uuid.New(), Node: "n1", Action: ActionCapture, Target: "10.0.0.1", Status: StatusSuccess, CreatedAt: time.Now()}
	hash, size := makeCaptureArtifact(t, env.dataDir, good.ID, content)
	good.CaptureFile = CaptureFileName(good.ID)
	good.CaptureHash = hash
	good.CaptureSize = &size
	env.store.add(good)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/network-tools/jobs/"+good.ID.String()+"/download", nil)
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("下载应 200: code=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Disposition"); !strings.Contains(got, fmt.Sprintf("capture-%s.pcap", good.ID)) {
		t.Fatalf("Content-Disposition 不符: %s", got)
	}
	if rec.Body.String() != string(content) {
		t.Fatalf("下载内容不符: %q", rec.Body.String())
	}
	au = env.audits.last()
	if au.Action != "download" || au.Result != audits.ResultSuccess || au.RiskLevel != audits.RiskMedium {
		t.Fatalf("下载成功审计不符: %+v", au)
	}
}

func TestDownloadPermissionDenied(t *testing.T) {
	env := newHandlerEnv(t, true, execPerm) // 只有 execute 无 download
	code, body, _ := doReq(t, env.handler, http.MethodGet, "/api/v1/network-tools/jobs/"+uuid.NewString()+"/download", "")
	if code != http.StatusForbidden || body.Code != "PERMISSION_DENIED" {
		t.Fatalf("无下载权限应 403: code=%d body=%+v", code, body)
	}
}

func TestStoreErrorSurfaces(t *testing.T) {
	env := newHandlerEnv(t, true, execPerm)
	env.store.createErr = errors.New("db down")
	code, body, _ := doReq(t, env.handler, http.MethodPost, "/api/v1/network-tools/jobs", `{"action":"ping","target":"10.0.0.1"}`)
	if code != http.StatusInternalServerError || body.Code != "INTERNAL_ERROR" {
		t.Fatalf("仓储错误应 500: code=%d body=%+v", code, body)
	}
}

func TestValidHostSemantics(t *testing.T) {
	valid := []string{"10.0.0.1", "192.168.1.1", "::1", "2001:db8::1", "example.com", "a-b.example.com", "host"}
	invalid := []string{"", "-evil.com", "10.0.0.1;id", "$(id)", "a b.com", "host_name", strings.Repeat("a", 254), "host/"}
	for _, s := range valid {
		if !ValidHost(s) {
			t.Fatalf("%q 应合法", s)
		}
	}
	for _, s := range invalid {
		if ValidHost(s) {
			t.Fatalf("%q 应非法", s)
		}
	}
}
