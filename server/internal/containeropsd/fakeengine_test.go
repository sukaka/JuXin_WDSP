// fakeengine_test.go 假 Docker Engine API：真实 Unix Socket 上的 HTTP 服务，
// 支持容器状态机、inspect、日志流、镜像 pull/inspect、create/rename/remove，
// 记录调用序列供断言（不要求真实 Docker）。
package containeropsd

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeContainer 假容器状态。
type fakeContainer struct {
	id           string
	name         string
	service      string
	project      string
	imageRef     string // Config.Image（repo:tag）
	imageID      string // 运行镜像 ID（sha256:...）
	running      bool
	health       string // "" = 无健康检查；否则 healthy/starting/unhealthy
	tty          bool
	env          []string
	restartCount int
	startedAt    string
	exitCode     int
	stateErr     string
	extraLabels  map[string]string
	fromCreate   bool // 经 /containers/create 创建（exitOnStart 注入只作用于新容器）
}

// fakeEngine 假 Docker Engine。
type fakeEngine struct {
	t *testing.T

	mu           sync.Mutex
	seq          int
	containers   map[string]*fakeContainer
	images       map[string]string // ref → image ID
	pullErr      bool              // 模拟离线：images/create 返回错误流
	createErr    string            // 非空时 /containers/create 返回 500
	exitOnStart  bool              // 新建容器 start 后立即退出（健康失败注入）
	calls        []string          // 已记录调用（方法+路径）
	createBodies []map[string]interface{}

	logBytes []byte // /containers/{id}/logs 返回的固定字节

	restartStarted chan struct{}
	restartRelease chan struct{}
}

// addContainer 登记一个容器并返回其 ID。
func (f *fakeEngine) addContainer(c *fakeContainer) *fakeContainer {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	if c.id == "" {
		c.id = fmt.Sprintf("%064x", f.seq)
	}
	if c.imageID == "" {
		c.imageID = "sha256:img-" + c.id[:8]
	}
	if c.project == "" {
		c.project = "proj"
	}
	f.containers[c.id] = c
	return c
}

func (f *fakeEngine) record(call string) {
	f.calls = append(f.calls, call)
}

// callsWith 返回包含子串的调用序列。
func (f *fakeEngine) callsWith(sub string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if strings.Contains(c, sub) {
			out = append(out, c)
		}
	}
	return out
}

func (f *fakeEngine) serve() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /_ping", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("OK"))
	})
	mux.HandleFunc("GET /containers/json", f.handleList)
	mux.HandleFunc("GET /containers/{id}/json", f.handleInspect)
	mux.HandleFunc("GET /containers/{id}/logs", f.handleLogs)
	mux.HandleFunc("POST /containers/{id}/start", f.handleStart)
	mux.HandleFunc("POST /containers/{id}/stop", f.handleStop)
	mux.HandleFunc("POST /containers/{id}/restart", f.handleRestart)
	mux.HandleFunc("POST /containers/{id}/rename", f.handleRename)
	mux.HandleFunc("POST /containers/create", f.handleCreate)
	mux.HandleFunc("DELETE /containers/{id}", f.handleRemove)
	mux.HandleFunc("GET /images/", f.handleImageInspect) // 前缀匹配，手工解析含斜杠的镜像名
	mux.HandleFunc("POST /images/create", f.handlePull)
	return mux
}

func (f *fakeEngine) engineErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": msg})
}

func (f *fakeEngine) handleList(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("GET /containers/json")
	project := ""
	if raw := r.URL.Query().Get("filters"); raw != "" {
		var filters map[string][]string
		if json.Unmarshal([]byte(raw), &filters) == nil {
			for _, l := range filters["label"] {
				if strings.HasPrefix(l, LabelProject+"=") {
					project = strings.TrimPrefix(l, LabelProject+"=")
				}
			}
		}
	}
	var out []map[string]interface{}
	for _, c := range f.containers {
		if project != "" && c.project != project {
			continue
		}
		state := "exited"
		status := "Exited (0) 2 hours ago"
		if c.running {
			state = "running"
			status = "Up 2 hours"
		}
		labels := map[string]string{
			LabelProject: c.project,
			LabelService: c.service,
		}
		for k, v := range c.extraLabels {
			labels[k] = v
		}
		out = append(out, map[string]interface{}{
			"Id": c.id, "Names": []string{"/" + c.name}, "Image": c.imageRef,
			"ImageID": c.imageID, "State": state, "Status": status,
			"Labels": labels, "Created": time.Now().Unix(),
		})
	}
	_ = json.NewEncoder(w).Encode(out)
}

func (f *fakeEngine) findByID(id string) *fakeContainer {
	if c, ok := f.containers[id]; ok {
		return c
	}
	for _, c := range f.containers {
		if strings.HasPrefix(c.id, id) {
			return c
		}
	}
	return nil
}

func (f *fakeEngine) handleInspect(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.findByID(r.PathValue("id"))
	f.record("GET /containers/" + r.PathValue("id") + "/json")
	if c == nil {
		f.engineErr(w, http.StatusNotFound, "No such container: "+r.PathValue("id"))
		return
	}
	labels := map[string]string{
		LabelProject: c.project,
		LabelService: c.service,
	}
	for k, v := range c.extraLabels {
		labels[k] = v
	}
	cfg := map[string]interface{}{
		"Image":    c.imageRef,
		"Tty":      c.tty,
		"Env":      c.env,
		"Labels":   labels,
		"Hostname": c.id[:12],
	}
	if c.health != "" {
		cfg["Healthcheck"] = map[string]interface{}{"Test": []string{"CMD-SHELL", "true"}}
	}
	state := map[string]interface{}{
		"Status":    "exited",
		"Running":   false,
		"ExitCode":  c.exitCode,
		"Error":     c.stateErr,
		"StartedAt": c.startedAt,
	}
	if c.running {
		state["Status"] = "running"
		state["Running"] = true
	}
	if c.health != "" && c.running {
		state["Health"] = map[string]interface{}{"Status": c.health}
	} else if c.health != "" {
		state["Health"] = map[string]interface{}{"Status": "unhealthy"}
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"Id":     c.id,
		"Name":   "/" + c.name,
		"Image":  c.imageID,
		"Config": cfg,
		"HostConfig": map[string]interface{}{
			"Binds":         []string{"vol-" + c.name + ":/data"},
			"PortBindings":  map[string]interface{}{"8080/tcp": []map[string]string{{"HostPort": "8080"}}},
			"RestartPolicy": map[string]interface{}{"Name": "unless-stopped"},
		},
		"NetworkSettings": map[string]interface{}{
			"Networks": map[string]interface{}{
				c.project + "_default": map[string]interface{}{
					"NetworkID":  "net-123",
					"Aliases":    []string{c.service, c.name},
					"IPAddress":  "172.20.0.5",
					"IPAMConfig": nil,
				},
			},
		},
		"State":        state,
		"RestartCount": c.restartCount,
	})
}

func (f *fakeEngine) handleLogs(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record(fmt.Sprintf("GET /containers/%s/logs?%s", r.PathValue("id"), r.URL.RawQuery))
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(f.logBytes)
}

func (f *fakeEngine) handleStart(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("POST /containers/" + r.PathValue("id") + "/start")
	c := f.findByID(r.PathValue("id"))
	if c == nil {
		f.engineErr(w, http.StatusNotFound, "No such container")
		return
	}
	if c.running {
		f.engineErr(w, http.StatusNotModified, "container already started")
		return
	}
	if f.exitOnStart && c.fromCreate {
		c.running = false
		c.exitCode = 1
		c.stateErr = "bootstrap failed"
	} else {
		c.running = true
		c.exitCode = 0
		c.startedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeEngine) handleStop(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("POST /containers/" + r.PathValue("id") + "/stop")
	c := f.findByID(r.PathValue("id"))
	if c == nil {
		f.engineErr(w, http.StatusNotFound, "No such container")
		return
	}
	if !c.running {
		f.engineErr(w, http.StatusNotModified, "container already stopped")
		return
	}
	c.running = false
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeEngine) handleRestart(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.record("POST /containers/" + r.PathValue("id") + "/restart")
	c := f.findByID(r.PathValue("id"))
	started, release := f.restartStarted, f.restartRelease
	f.mu.Unlock()
	if c == nil {
		f.engineErr(w, http.StatusNotFound, "No such container")
		return
	}
	if release != nil {
		if started != nil {
			started <- struct{}{}
		}
		<-release
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	c = f.findByID(r.PathValue("id"))
	if c == nil {
		f.engineErr(w, http.StatusNotFound, "No such container")
		return
	}
	c.running = true
	c.startedAt = time.Now().UTC().Format(time.RFC3339Nano)
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeEngine) handleRename(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.findByID(r.PathValue("id"))
	newName := r.URL.Query().Get("name")
	f.record("POST /containers/" + r.PathValue("id") + "/rename?name=" + newName)
	if c == nil {
		f.engineErr(w, http.StatusNotFound, "No such container")
		return
	}
	c.name = newName
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeEngine) handleCreate(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("POST /containers/create?name=" + r.URL.Query().Get("name"))
	if f.createErr != "" {
		f.engineErr(w, http.StatusInternalServerError, f.createErr)
		return
	}
	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		f.engineErr(w, http.StatusBadRequest, "bad body")
		return
	}
	f.createBodies = append(f.createBodies, body)
	f.seq++
	id := fmt.Sprintf("%064x", 1000+f.seq)
	imageRef, _ := body["Image"].(string)
	c := &fakeContainer{
		id:         id,
		name:       r.URL.Query().Get("name"),
		imageRef:   imageRef,
		running:    false,
		fromCreate: true,
	}
	// 从请求体 Labels/Env 继承，便于断言透传
	if labels, ok := body["Labels"].(map[string]interface{}); ok {
		c.service, _ = labels[LabelService].(string)
		c.project, _ = labels[LabelProject].(string)
	}
	if env, ok := body["Env"].([]interface{}); ok {
		for _, e := range env {
			if s, ok := e.(string); ok {
				c.env = append(c.env, s)
			}
		}
	}
	if _, ok := body["Healthcheck"]; ok {
		c.health = "healthy"
	}
	// 镜像 ID 与目标引用一致（模拟新镜像）
	if imgID, ok := f.images[imageRef]; ok {
		c.imageID = imgID
	} else {
		c.imageID = "sha256:new-" + id[:8]
	}
	f.containers[id] = c
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"Id": id})
}

func (f *fakeEngine) handleRemove(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("DELETE /containers/" + r.PathValue("id"))
	c := f.findByID(r.PathValue("id"))
	if c == nil {
		f.engineErr(w, http.StatusNotFound, "No such container")
		return
	}
	if c.running && r.URL.Query().Get("force") == "" {
		f.engineErr(w, http.StatusConflict, "container is running")
		return
	}
	delete(f.containers, c.id)
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeEngine) handleImageInspect(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// 前缀路由手工解析：/images/<ref>/json（ref 可含斜杠/冒号）
	ref := strings.TrimPrefix(r.URL.Path, "/images/")
	ref = strings.TrimSuffix(ref, "/json")
	f.record("GET /images/" + ref + "/json")
	if id, ok := f.images[ref]; ok {
		_ = json.NewEncoder(w).Encode(map[string]string{"Id": id})
		return
	}
	f.engineErr(w, http.StatusNotFound, "No such image: "+ref)
}

func (f *fakeEngine) handlePull(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	from := r.URL.Query().Get("fromImage")
	tag := r.URL.Query().Get("tag")
	f.record(fmt.Sprintf("POST /images/create?fromImage=%s&tag=%s", from, tag))
	if f.pullErr {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"errorDetail": map[string]string{"message": "dial tcp: registry unreachable"},
			"error":       "dial tcp: registry unreachable",
		})
		return
	}
	ref := from
	if tag != "" {
		ref = from + ":" + tag
	}
	if _, ok := f.images[ref]; !ok {
		f.images[ref] = "sha256:pulled-" + fmt.Sprintf("%x", len(f.images))
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "Pull complete"})
}

// shortTempDir 返回短路径临时目录：macOS 上 t.TempDir() 的路径很长，
// 超过 Unix Socket 地址约 104 字节的限制会导致 bind 失败。
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "co")
	if err != nil {
		t.Fatalf("创建临时目录: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// newFakeEngine 启动假 Engine（Unix Socket）并返回 DockerClient 与其本体。
func newFakeEngine(t *testing.T) (*fakeEngine, *DockerClient) {
	t.Helper()
	f := &fakeEngine{
		t:          t,
		containers: map[string]*fakeContainer{},
		images:     map[string]string{},
	}
	sock := filepath.Join(shortTempDir(t), "docker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("监听假 Engine socket: %v", err)
	}
	srv := &http.Server{Handler: f.serve(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	dc, err := NewDockerClient("unix://" + sock)
	if err != nil {
		t.Fatalf("创建 Docker 客户端: %v", err)
	}
	dc.pullTimeout = 5 * time.Second
	return f, dc
}

// newTestService 装配测试用 Service（快速健康等待参数）。
func newTestService(t *testing.T, dc *DockerClient, socketDir string, project string, allowed ...string) *Service {
	t.Helper()
	cfg := Config{
		SocketPath:      socketDir + "/containerops.sock",
		DockerHost:      "unix:///unused.sock",
		Project:         project,
		AllowedServices: map[string]bool{},
	}
	for _, s := range allowed {
		cfg.AllowedServices[s] = true
	}
	svc, err := NewService(cfg, dc, nil)
	if err != nil {
		t.Fatalf("创建 Service: %v", err)
	}
	svc.stopTimeoutSec = 1
	svc.healthTimeout = 3 * time.Second
	svc.healthInterval = 20 * time.Millisecond
	svc.settleWait = 50 * time.Millisecond
	svc.jobTimeout = 30 * time.Second
	return svc
}

// doRequest 直接对 Handler 发请求（不经真实 socket）。
func doRequest(t *testing.T, svc *Service, method, path string, body string) (int, map[string]interface{}) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rec, req)
	var out map[string]interface{}
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("响应非 JSON: %v body=%s", err, rec.Body.String())
		}
	}
	return rec.Code, out
}

// waitJob 轮询任务直至终态。
func waitJob(t *testing.T, svc *Service, jobID string) *ActionJob {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		job, ok := svc.jobs.get(jobID)
		if !ok {
			t.Fatalf("任务 %s 不存在", jobID)
		}
		if job.Status == JobSuccess || job.Status == JobFailed {
			return job
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("任务 %s 未在超时内到达终态", jobID)
	return nil
}

// muxFrame 构造一帧多路复用日志。
func muxFrame(stream byte, payload string) []byte {
	out := make([]byte, 8+len(payload))
	out[0] = stream
	out[4] = byte(len(payload) >> 24)
	out[5] = byte(len(payload) >> 16)
	out[6] = byte(len(payload) >> 8)
	out[7] = byte(len(payload))
	copy(out[8:], payload)
	return out
}
