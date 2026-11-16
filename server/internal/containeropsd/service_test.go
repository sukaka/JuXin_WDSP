// service_test.go containeropsd HTTP 协议集成测试：项目/白名单双重校验、
// Docker 错误映射、日志端到端、动作任务生命周期、update 重建与回滚。
package containeropsd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- 列表 ---

func TestListRequiresProject(t *testing.T) {
	_, dc := newFakeEngine(t)
	svc := newTestService(t, dc, shortTempDir(t), "", "web")
	code, body := doRequest(t, svc, http.MethodGet, "/v1/containers", "")
	if code != http.StatusServiceUnavailable || body["error"].(map[string]interface{})["code"] != "PROJECT_NOT_CONFIGURED" {
		t.Fatalf("项目未配置应 503 PROJECT_NOT_CONFIGURED: code=%d body=%v", code, body)
	}
}

func TestListFiltersWhitelistAndFields(t *testing.T) {
	engine, dc := newFakeEngine(t)
	engine.addContainer(&fakeContainer{
		name: "proj-web-1", service: "web", imageRef: "registry.example.com/stack/web:1.2.0",
		running: true, health: "healthy", restartCount: 2,
		startedAt: "2026-10-19T01:00:00Z", env: []string{"DB_PASSWORD=topsecret"},
	})
	engine.addContainer(&fakeContainer{name: "proj-db-1", service: "db", imageRef: "postgres:16.4", running: false})
	engine.addContainer(&fakeContainer{name: "proj-side-1", service: "notallowed", imageRef: "x:1", running: true})
	engine.addContainer(&fakeContainer{name: "other-web-1", service: "web", project: "other", imageRef: "x:1", running: true})

	svc := newTestService(t, dc, shortTempDir(t), "proj", "web", "db")
	code, body := doRequest(t, svc, http.MethodGet, "/v1/containers", "")
	if code != http.StatusOK {
		t.Fatalf("列表应 200: code=%d body=%v", code, body)
	}
	containers, ok := body["containers"].([]interface{})
	if !ok {
		t.Fatalf("缺少 containers 字段: %v", body)
	}
	if len(containers) != 2 {
		t.Fatalf("应只返回白名单+项目匹配的 2 个容器，实际 %d: %v", len(containers), containers)
	}
	raw, _ := json.Marshal(body)
	if strings.Contains(string(raw), "topsecret") || strings.Contains(string(raw), "DB_PASSWORD") {
		t.Fatalf("列表响应泄露环境变量: %s", raw)
	}
	first := containers[0].(map[string]interface{}) // 按 service 排序：db 在前
	if first["service"] != "db" || first["running"] != false {
		t.Fatalf("db 视图错误: %v", first)
	}
	second := containers[1].(map[string]interface{})
	if second["service"] != "web" || second["running"] != true ||
		second["health"] != "healthy" || second["restart_count"].(float64) != 2 ||
		second["started_at"] != "2026-10-19T01:00:00Z" {
		t.Fatalf("web 视图字段错误: %v", second)
	}
	for _, key := range []string{"id", "name", "image", "image_id", "state", "status", "project"} {
		if _, ok := second[key]; !ok {
			t.Fatalf("web 视图缺少字段 %q: %v", key, second)
		}
	}
}

func TestListEngineErrorMapping(t *testing.T) {
	engine, dc := newFakeEngine(t)
	engine.addContainer(&fakeContainer{name: "proj-web-1", service: "web"})
	// Engine socket 关闭 → 不可达映射 503
	svc := newTestService(t, dc, shortTempDir(t), "proj", "web")
	dc.hc.CloseIdleConnections()
	// 直接换一个指向不存在 socket 的客户端模拟 Engine 停机
	dead, err := NewDockerClient("unix://" + filepath.Join(shortTempDir(t), "gone.sock"))
	if err != nil {
		t.Fatalf("NewDockerClient: %v", err)
	}
	svcDead := newTestService(t, dc, shortTempDir(t), "proj", "web")
	svcDead.docker = dead
	code, body := doRequest(t, svcDead, http.MethodGet, "/v1/containers", "")
	if code != http.StatusServiceUnavailable || body["error"].(map[string]interface{})["code"] != "UNAVAILABLE" {
		t.Fatalf("Engine 不可达应 503 UNAVAILABLE: code=%d body=%v", code, body)
	}
	_ = svc
}

// --- 日志 ---

func TestLogsEndToEnd(t *testing.T) {
	engine, dc := newFakeEngine(t)
	engine.addContainer(&fakeContainer{name: "proj-web-1", service: "web", running: true})
	var buf strings.Builder
	buf.WriteString(string(muxFrame(1, "2026-10-19T01:02:03.1Z 正常日志\n")))
	buf.WriteString(string(muxFrame(2, "2026-10-19T01:02:04.2Z password=abc123\n")))
	engine.logBytes = []byte(buf.String())

	svc := newTestService(t, dc, shortTempDir(t), "proj", "web")
	code, body := doRequest(t, svc, http.MethodGet, "/v1/containers/web/logs?tail=100&since=1700000000", "")
	if code != http.StatusOK {
		t.Fatalf("日志应 200: code=%d body=%v", code, body)
	}
	if body["service"] != "web" || body["truncated"] != false {
		t.Fatalf("日志响应字段错误: %v", body)
	}
	lines := body["lines"].([]interface{})
	if len(lines) != 2 {
		t.Fatalf("应 2 行，实际 %d", len(lines))
	}
	second := lines[1].(map[string]interface{})
	if second["stream"] != "stderr" || strings.Contains(second["message"].(string), "abc123") {
		t.Fatalf("stderr 行脱敏失败: %v", second)
	}
	if body["next_since"].(float64) == 0 {
		t.Fatalf("next_since 应为最后行时间戳: %v", body)
	}
	// tail/since 透传到 Engine
	var logsCall string
	for _, c := range engine.callsWith("/logs") {
		logsCall = c
	}
	if !strings.Contains(logsCall, "tail=100") || !strings.Contains(logsCall, "since=1700000000") {
		t.Fatalf("tail/since 未透传: %q", logsCall)
	}
}

func TestLogsTailClampAndBadParams(t *testing.T) {
	engine, dc := newFakeEngine(t)
	engine.addContainer(&fakeContainer{name: "proj-web-1", service: "web", running: true})
	svc := newTestService(t, dc, shortTempDir(t), "proj", "web")

	code, _ := doRequest(t, svc, http.MethodGet, "/v1/containers/web/logs?tail=99999", "")
	if code != http.StatusOK {
		t.Fatalf("tail 超限应夹紧而非报错: %d", code)
	}
	var logsCall string
	for _, c := range engine.callsWith("/logs") {
		logsCall = c
	}
	if !strings.Contains(logsCall, fmt.Sprintf("tail=%d", MaxTail)) {
		t.Fatalf("tail 应夹紧到 %d: %q", MaxTail, logsCall)
	}
	code, body := doRequest(t, svc, http.MethodGet, "/v1/containers/web/logs?tail=abc", "")
	if code != http.StatusBadRequest {
		t.Fatalf("非法 tail 应 400: %d %v", code, body)
	}
	code, body = doRequest(t, svc, http.MethodGet, "/v1/containers/web/logs?since=-3", "")
	if code != http.StatusBadRequest {
		t.Fatalf("非法 since 应 400: %d %v", code, body)
	}
}

func TestLogsServiceNotWhitelisted(t *testing.T) {
	engine, dc := newFakeEngine(t)
	engine.addContainer(&fakeContainer{name: "proj-db-1", service: "db"})
	svc := newTestService(t, dc, shortTempDir(t), "proj", "web") // db 不在白名单
	code, body := doRequest(t, svc, http.MethodGet, "/v1/containers/db/logs", "")
	if code != http.StatusForbidden || body["error"].(map[string]interface{})["code"] != "SERVICE_NOT_ALLOWED" {
		t.Fatalf("未白名单服务应 403: code=%d body=%v", code, body)
	}
}

func TestLogsContainerNotFound(t *testing.T) {
	_, dc := newFakeEngine(t)
	svc := newTestService(t, dc, shortTempDir(t), "proj", "web")
	code, body := doRequest(t, svc, http.MethodGet, "/v1/containers/web/logs", "")
	if code != http.StatusNotFound || body["error"].(map[string]interface{})["code"] != "CONTAINER_NOT_FOUND" {
		t.Fatalf("容器不存在应 404: code=%d body=%v", code, body)
	}
}

// --- 动作任务 ---

func submitAction(t *testing.T, svc *Service, service, body string) (int, map[string]interface{}) {
	t.Helper()
	return doRequest(t, svc, http.MethodPost, "/v1/containers/"+service+"/actions", body)
}

func TestActionStartSuccess(t *testing.T) {
	engine, dc := newFakeEngine(t)
	target := engine.addContainer(&fakeContainer{name: "proj-web-1", service: "web", running: false})
	socketDir := shortTempDir(t)
	svc := newTestService(t, dc, socketDir, "proj", "web")

	code, body := submitAction(t, svc, "web", `{"action":"start"}`)
	if code != http.StatusAccepted || body["status"] != JobAccepted || body["job_id"] == nil ||
		body["service"] != "web" || body["action"] != "start" {
		t.Fatalf("受理应 202 ACCEPTED 且携带完整任务字段: code=%d body=%v", code, body)
	}
	job := waitJob(t, svc, body["job_id"].(string))
	if job.Status != JobSuccess {
		t.Fatalf("任务应成功: %+v", job)
	}
	if !target.running {
		t.Fatal("容器应已启动")
	}
	if job.StartedAt == nil || job.FinishedAt == nil {
		t.Fatalf("任务应带 started_at/finished_at: %+v", job)
	}
	// 结果落盘
	if _, err := os.Stat(filepath.Join(socketDir, "results", job.JobID+".json")); err != nil {
		t.Fatalf("任务结果未落盘: %v", err)
	}
	// 查询端点
	code, body = doRequest(t, svc, http.MethodGet, "/v1/actions/"+job.JobID, "")
	if code != http.StatusOK || body["status"] != JobSuccess || body["service"] != "web" || body["action"] != "start" {
		t.Fatalf("任务查询错误: code=%d body=%v", code, body)
	}
}

func TestActionValidationFailures(t *testing.T) {
	engine, dc := newFakeEngine(t)
	engine.addContainer(&fakeContainer{name: "proj-web-1", service: "web"})
	svc := newTestService(t, dc, shortTempDir(t), "proj", "web")

	code, body := submitAction(t, svc, "web", `{"action":"nuke"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("未知动作应 400: %d %v", code, body)
	}
	code, _ = submitAction(t, svc, "web", `{"action":"start","delay_seconds":-1}`)
	if code != http.StatusBadRequest {
		t.Fatalf("负延迟应 400: %d", code)
	}
	code, _ = submitAction(t, svc, "web", `{"action":`)
	if code != http.StatusBadRequest {
		t.Fatalf("非法 JSON 应 400: %d", code)
	}
	code, body = submitAction(t, svc, "ghost", `{"action":"start"}`)
	if code != http.StatusForbidden || body["error"].(map[string]interface{})["code"] != "SERVICE_NOT_ALLOWED" {
		t.Fatalf("未白名单服务应 403: %d %v", code, body)
	}
	code, body = submitAction(t, svc, "api", `{"action":"start"}`)
	if code != http.StatusForbidden {
		t.Fatalf("api 不在白名单应 403: %d %v", code, body)
	}
}

func TestApiSelfServiceRestartOnly(t *testing.T) {
	engine, dc := newFakeEngine(t)
	engine.addContainer(&fakeContainer{name: "proj-api-1", service: "api", running: true})
	svc := newTestService(t, dc, shortTempDir(t), "proj", "api", "web")

	for _, action := range []string{"stop", "update"} {
		code, body := submitAction(t, svc, "api", fmt.Sprintf(`{"action":%q}`, action))
		if code != http.StatusForbidden || body["error"].(map[string]interface{})["code"] != "ACTION_NOT_ALLOWED" {
			t.Fatalf("api %s 应 403 ACTION_NOT_ALLOWED: %d %v", action, code, body)
		}
	}
	code, body := submitAction(t, svc, "api", `{"action":"restart"}`)
	if code != http.StatusAccepted {
		t.Fatalf("api restart 应受理: %d %v", code, body)
	}
	if job := waitJob(t, svc, body["job_id"].(string)); job.Status != JobSuccess {
		t.Fatalf("api restart 应成功: %+v", job)
	}
}

func TestActionStopAlreadyStopped(t *testing.T) {
	engine, dc := newFakeEngine(t)
	engine.addContainer(&fakeContainer{name: "proj-web-1", service: "web", running: false})
	svc := newTestService(t, dc, shortTempDir(t), "proj", "web")
	code, body := submitAction(t, svc, "web", `{"action":"stop"}`)
	if code != http.StatusAccepted {
		t.Fatalf("受理应 202: %d", code)
	}
	// Engine 304 视为成功（幂等）
	if job := waitJob(t, svc, body["job_id"].(string)); job.Status != JobSuccess {
		t.Fatalf("已停止容器 stop 应幂等成功: %+v", job)
	}
}

func TestActionEngineFailure(t *testing.T) {
	engine, dc := newFakeEngine(t)
	engine.addContainer(&fakeContainer{name: "proj-web-1", service: "web", running: true})
	engine.createErr = "" // 不影响
	svc := newTestService(t, dc, shortTempDir(t), "proj", "web")
	// 删除容器后执行 start → resolveInspect 在受理时成功，执行时容器消失 → FAILED
	code, body := submitAction(t, svc, "web", `{"action":"restart"}`)
	if code != http.StatusAccepted {
		t.Fatalf("受理应 202: %d", code)
	}
	engine.mu.Lock()
	for id := range engine.containers {
		delete(engine.containers, id)
	}
	engine.mu.Unlock()
	job := waitJob(t, svc, body["job_id"].(string))
	if job.Status != JobFailed || job.Message == "" {
		t.Fatalf("执行失败应 FAILED 且带原因: %+v", job)
	}
}

func TestActionQueryValidation(t *testing.T) {
	_, dc := newFakeEngine(t)
	svc := newTestService(t, dc, shortTempDir(t), "proj", "web")
	code, _ := doRequest(t, svc, http.MethodGet, "/v1/actions/not-a-job-id", "")
	if code != http.StatusBadRequest {
		t.Fatalf("非法任务 ID 应 400: %d", code)
	}
	code, body := doRequest(t, svc, http.MethodGet, "/v1/actions/0123456789abcdef0123456789abcdef", "")
	if code != http.StatusNotFound || body["error"].(map[string]interface{})["code"] != "JOB_NOT_FOUND" {
		t.Fatalf("未知任务应 404: %d %v", code, body)
	}
}

func TestJobReloadAfterRestart(t *testing.T) {
	engine, dc := newFakeEngine(t)
	engine.addContainer(&fakeContainer{name: "proj-web-1", service: "web"})
	socketDir := shortTempDir(t)
	svc := newTestService(t, dc, socketDir, "proj", "web")
	code, body := submitAction(t, svc, "web", `{"action":"start"}`)
	if code != http.StatusAccepted {
		t.Fatalf("受理应 202: %d", code)
	}
	job := waitJob(t, svc, body["job_id"].(string))

	// 模拟 sidecar 重启：新建 Service（重载 results/ 目录）
	svc2 := newTestService(t, dc, socketDir, "proj", "web")
	code, body = doRequest(t, svc2, http.MethodGet, "/v1/actions/"+job.JobID, "")
	if code != http.StatusOK || body["status"] != JobSuccess {
		t.Fatalf("重启后应能查询历史任务: %d %v", code, body)
	}
}

func TestStaleAcceptedJobMarkedFailed(t *testing.T) {
	_, dc := newFakeEngine(t)
	socketDir := shortTempDir(t)
	resultsDir := filepath.Join(socketDir, "results")
	if err := os.MkdirAll(resultsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	stale := &ActionJob{JobID: "0123456789abcdef0123456789abcdef", Service: "web", Action: "start", Status: JobAccepted}
	raw, _ := json.Marshal(stale)
	if err := os.WriteFile(filepath.Join(resultsDir, stale.JobID+".json"), raw, 0o640); err != nil {
		t.Fatal(err)
	}
	svc := newTestService(t, dc, socketDir, "proj", "web")
	job, ok := svc.jobs.get(stale.JobID)
	if !ok || job.Status != JobFailed {
		t.Fatalf("悬挂 ACCEPTED 任务应标记 FAILED: %+v ok=%v", job, ok)
	}
}

// --- update ---

func TestUpdateRejectsLatest(t *testing.T) {
	engine, dc := newFakeEngine(t)
	engine.addContainer(&fakeContainer{
		name: "proj-web-1", service: "web", running: true,
		imageRef:    "registry.example.com/stack/web:1.0.0",
		extraLabels: map[string]string{LabelImage: "registry.example.com/stack/web:latest"},
	})
	svc := newTestService(t, dc, shortTempDir(t), "proj", "web")
	code, body := submitAction(t, svc, "web", `{"action":"update"}`)
	if code != http.StatusAccepted {
		t.Fatalf("受理应 202: %d", code)
	}
	job := waitJob(t, svc, body["job_id"].(string))
	if job.Status != JobFailed || !strings.Contains(job.Message, "latest") {
		t.Fatalf("latest 应被拒绝: %+v", job)
	}
	if len(engine.callsWith("/containers/create")) != 0 {
		t.Fatal("latest 拒绝后不应发生重建")
	}
}

func TestUpdateRejectsBareRepo(t *testing.T) {
	engine, dc := newFakeEngine(t)
	engine.addContainer(&fakeContainer{
		name: "proj-web-1", service: "web", running: true,
		imageRef:    "web",
		extraLabels: map[string]string{LabelImage: "registry.example.com/stack/web"},
	})
	svc := newTestService(t, dc, shortTempDir(t), "proj", "web")
	code, body := submitAction(t, svc, "web", `{"action":"update"}`)
	if code != http.StatusAccepted {
		t.Fatalf("受理应 202: %d", code)
	}
	job := waitJob(t, svc, body["job_id"].(string))
	if job.Status != JobFailed || !strings.Contains(job.Message, "锁定形态") {
		t.Fatalf("裸仓库名应被拒绝: %+v", job)
	}
}

func TestUpdateNoopWhenImageUnchanged(t *testing.T) {
	engine, dc := newFakeEngine(t)
	target := engine.addContainer(&fakeContainer{
		name: "proj-web-1", service: "web", running: true, imageRef: "registry.example.com/stack/web:1.2.0",
	})
	engine.images["registry.example.com/stack/web:1.2.0"] = target.imageID
	svc := newTestService(t, dc, shortTempDir(t), "proj", "web")
	code, body := submitAction(t, svc, "web", `{"action":"update"}`)
	if code != http.StatusAccepted {
		t.Fatalf("受理应 202: %d", code)
	}
	job := waitJob(t, svc, body["job_id"].(string))
	if job.Status != JobSuccess || !strings.Contains(job.Message, "无需更新") {
		t.Fatalf("镜像一致应成功空转: %+v", job)
	}
	if len(engine.callsWith("/containers/create")) != 0 {
		t.Fatal("镜像一致不应重建容器")
	}
}

func TestUpdateWithLocalImageRecreates(t *testing.T) {
	engine, dc := newFakeEngine(t)
	old := engine.addContainer(&fakeContainer{
		name: "proj-web-1", service: "web", running: true, health: "healthy",
		imageRef:    "registry.example.com/stack/web:1.2.0",
		env:         []string{"APP_MODE=prod", "DB_PASSWORD=topsecret"},
		extraLabels: map[string]string{LabelImage: "registry.example.com/stack/web:1.3.0"},
	})
	engine.images["registry.example.com/stack/web:1.3.0"] = "sha256:newimage130"
	engine.pullErr = true // 离线：拉取失败可容忍
	svc := newTestService(t, dc, shortTempDir(t), "proj", "web")

	code, body := submitAction(t, svc, "web", `{"action":"update"}`)
	if code != http.StatusAccepted {
		t.Fatalf("受理应 202: %d", code)
	}
	job := waitJob(t, svc, body["job_id"].(string))
	if job.Status != JobSuccess {
		t.Fatalf("本地新镜像更新应成功: %+v", job)
	}

	// 创建载荷断言：镜像替换 + Env/HostConfig/网络透传
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if len(engine.createBodies) != 1 {
		t.Fatalf("应创建 1 个新容器，实际 %d", len(engine.createBodies))
	}
	createBody := engine.createBodies[0]
	if createBody["Image"] != "registry.example.com/stack/web:1.3.0" {
		t.Fatalf("新容器镜像错误: %v", createBody["Image"])
	}
	env, _ := createBody["Env"].([]interface{})
	if len(env) != 2 || env[0] != "APP_MODE=prod" {
		t.Fatalf("Env 未透传: %v", env)
	}
	if _, ok := createBody["HostConfig"].(map[string]interface{}); !ok {
		t.Fatalf("HostConfig 未透传: %v", createBody)
	}
	netCfg, ok := createBody["NetworkingConfig"].(map[string]interface{})
	if !ok || netCfg["EndpointsConfig"].(map[string]interface{})["proj_default"] == nil {
		t.Fatalf("NetworkingConfig 未透传: %v", createBody)
	}
	// 旧容器已移除，新容器以原名运行
	if engine.findByID(old.id) != nil {
		t.Fatal("旧容器应被移除")
	}
	var newC *fakeContainer
	for _, c := range engine.containers {
		if c.name == "proj-web-1" {
			newC = c
		}
	}
	if newC == nil || !newC.running {
		t.Fatalf("新容器应以原名运行: %+v", newC)
	}
	// 改名先于创建
	renameIdx, createIdx := -1, -1
	for i, c := range engine.calls {
		if strings.Contains(c, "/rename") && renameIdx < 0 {
			renameIdx = i
		}
		if strings.Contains(c, "/containers/create") && createIdx < 0 {
			createIdx = i
		}
	}
	if renameIdx < 0 || createIdx < 0 || renameIdx > createIdx {
		t.Fatalf("应先改名再创建: rename=%d create=%d calls=%v", renameIdx, createIdx, engine.calls)
	}
}

func TestUpdateIgnoresComposeImageIDLabel(t *testing.T) {
	engine, dc := newFakeEngine(t)
	engine.addContainer(&fakeContainer{
		name: "proj-web-1", service: "web", running: true, health: "healthy",
		imageRef: "registry.example.com/stack/web:1.3.0",
		// Docker Compose 的 com.docker.compose.image 可能是创建时镜像 ID，而不是可拉取引用。
		extraLabels: map[string]string{LabelImage: strings.Repeat("a", 64)},
	})
	engine.images["registry.example.com/stack/web:1.3.0"] = "sha256:newimage130"
	engine.pullErr = true
	svc := newTestService(t, dc, shortTempDir(t), "proj", "web")

	code, body := submitAction(t, svc, "web", `{"action":"update"}`)
	if code != http.StatusAccepted {
		t.Fatalf("受理应 202: %d", code)
	}
	job := waitJob(t, svc, body["job_id"].(string))
	if job.Status != JobSuccess {
		t.Fatalf("镜像 ID label 应回退 Config.Image 并更新成功: %+v", job)
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if len(engine.createBodies) != 1 || engine.createBodies[0]["Image"] != "registry.example.com/stack/web:1.3.0" {
		t.Fatalf("新容器镜像应取 Config.Image: %+v", engine.createBodies)
	}
}

func TestUpdateRollbackOnUnhealthyNewContainer(t *testing.T) {
	engine, dc := newFakeEngine(t)
	old := engine.addContainer(&fakeContainer{
		name: "proj-web-1", service: "web", running: true, health: "healthy",
		imageRef:    "registry.example.com/stack/web:1.2.0",
		extraLabels: map[string]string{LabelImage: "registry.example.com/stack/web:1.3.0"},
	})
	engine.images["registry.example.com/stack/web:1.3.0"] = "sha256:badimage130"
	engine.exitOnStart = true // 新容器启动即退出
	svc := newTestService(t, dc, shortTempDir(t), "proj", "web")

	code, body := submitAction(t, svc, "web", `{"action":"update"}`)
	if code != http.StatusAccepted {
		t.Fatalf("受理应 202: %d", code)
	}
	job := waitJob(t, svc, body["job_id"].(string))
	if job.Status != JobFailed || !strings.Contains(job.Message, "健康检查") {
		t.Fatalf("健康失败应 FAILED: %+v", job)
	}

	engine.mu.Lock()
	defer engine.mu.Unlock()
	// 回滚后：旧容器以原名运行，新容器已移除
	if !old.running {
		t.Fatal("回滚后旧容器应重新拉起")
	}
	if old.name != "proj-web-1" {
		t.Fatalf("回滚后旧容器应改回原名，实际 %q", old.name)
	}
	if len(engine.containers) != 1 {
		t.Fatalf("回滚后应只剩旧容器，实际 %d 个", len(engine.containers))
	}
}

func TestUpdateCreateFailureRollback(t *testing.T) {
	engine, dc := newFakeEngine(t)
	old := engine.addContainer(&fakeContainer{
		name: "proj-web-1", service: "web", running: true,
		imageRef:    "registry.example.com/stack/web:1.2.0",
		extraLabels: map[string]string{LabelImage: "registry.example.com/stack/web:1.3.0"},
	})
	engine.images["registry.example.com/stack/web:1.3.0"] = "sha256:newimage130"
	engine.createErr = "mock create boom"
	svc := newTestService(t, dc, shortTempDir(t), "proj", "web")

	code, body := submitAction(t, svc, "web", `{"action":"update"}`)
	if code != http.StatusAccepted {
		t.Fatalf("受理应 202: %d", code)
	}
	job := waitJob(t, svc, body["job_id"].(string))
	if job.Status != JobFailed || !strings.Contains(job.Message, "创建新容器失败") {
		t.Fatalf("创建失败应 FAILED: %+v", job)
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if !old.running || old.name != "proj-web-1" {
		t.Fatalf("创建失败回滚后旧容器应恢复运行与原名: %+v", old)
	}
}

func TestUpdateOfflinePullAndMissingLocalImage(t *testing.T) {
	engine, dc := newFakeEngine(t)
	engine.addContainer(&fakeContainer{
		name: "proj-web-1", service: "web", running: true,
		imageRef:    "registry.example.com/stack/web:1.2.0",
		extraLabels: map[string]string{LabelImage: "registry.example.com/stack/web:9.9.9"},
	})
	engine.pullErr = true // 离线且无本地镜像
	svc := newTestService(t, dc, shortTempDir(t), "proj", "web")
	code, body := submitAction(t, svc, "web", `{"action":"update"}`)
	if code != http.StatusAccepted {
		t.Fatalf("受理应 202: %d", code)
	}
	job := waitJob(t, svc, body["job_id"].(string))
	if job.Status != JobFailed || !strings.Contains(job.Message, "离线") {
		t.Fatalf("离线且无本地镜像应明确失败: %+v", job)
	}
	if len(engine.callsWith("/containers/create")) != 0 {
		t.Fatal("失败场景不应重建容器")
	}
}

// --- Run 生命周期 ---

func TestRunLifecycleSocketFile(t *testing.T) {
	_, dc := newFakeEngine(t)
	dir := shortTempDir(t)
	svc := newTestService(t, dc, dir, "proj", "web")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- svc.Run(ctx) }()

	sockPath := filepath.Join(dir, "containerops.sock")
	deadline := time.Now().Add(3 * time.Second)
	var fi os.FileInfo
	var err error
	for time.Now().Before(deadline) {
		fi, err = os.Stat(sockPath)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("socket 文件未创建: %v", err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		t.Fatal("应为 socket 类型文件")
	}
	if perm := fi.Mode().Perm(); perm != 0o660 {
		t.Fatalf("socket 权限 = %o, want 660", perm)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("优雅关停应无错误: %v", err)
	}
	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Fatal("退出后 socket 文件应被移除")
	}
}

func TestRunRefusesNonSocketOccupant(t *testing.T) {
	_, dc := newFakeEngine(t)
	dir := shortTempDir(t)
	sockPath := filepath.Join(dir, "containerops.sock")
	if err := os.WriteFile(sockPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	svc := newTestService(t, dc, dir, "proj", "web")
	if err := svc.Run(context.Background()); err == nil {
		t.Fatal("socket 路径被普通文件占用时应拒绝启动")
	}
}
