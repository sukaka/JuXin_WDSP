// docker.go Docker Engine API 客户端：仅 Go 标准库，HTTP/1.1 over Unix Socket，
// 使用无版本路径（/_ping、/containers/json、/containers/{id}/json 等）。
// 所有容器标识均作为 URL 路径/查询参数传递，绝不拼接 shell。
package containeropsd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// EngineError 是 Docker Engine API 返回的结构化错误。
type EngineError struct {
	Status  int
	Message string
}

func (e *EngineError) Error() string {
	return fmt.Sprintf("docker engine: status %d: %s", e.Status, e.Message)
}

// IsNotFound 判断错误是否为 Engine 侧 404。
func IsNotFound(err error) bool {
	var ee *EngineError
	return errors.As(err, &ee) && ee.Status == http.StatusNotFound
}

// EngineUnreachable Docker API 连接失败（socket 不存在/权限不足/Engine 停机）。
type EngineUnreachable struct{ Err error }

func (e *EngineUnreachable) Error() string { return "docker engine 不可达: " + e.Err.Error() }
func (e *EngineUnreachable) Unwrap() error { return e.Err }

// errAlreadyInState 目标状态已达成（Engine 304：重复 start 运行中容器 / stop 已停容器）。
func isNotModified(err error) bool {
	var ee *EngineError
	return errors.As(err, &ee) && ee.Status == http.StatusNotModified
}

// DockerClient 调用 Docker Engine API。
type DockerClient struct {
	socketPath string
	hc         *http.Client
	// pullTimeout 镜像拉取超时（离线环境快速失败，在线大镜像给足余量）
	pullTimeout time.Duration
}

// NewDockerClient 创建 Docker 客户端。host 仅支持 unix:// 方案。
func NewDockerClient(host string) (*DockerClient, error) {
	socketPath, err := parseDockerHost(host)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 10 * time.Second}
			return d.DialContext(ctx, "unix", socketPath)
		},
		// 单 socket 上串行化长请求，连接池保持小余量即可
		MaxIdleConns:        4,
		MaxConnsPerHost:     8,
		MaxIdleConnsPerHost: 4,
	}
	return &DockerClient{
		socketPath:  socketPath,
		hc:          &http.Client{Transport: transport, Timeout: 30 * time.Second},
		pullTimeout: 5 * time.Minute,
	}, nil
}

// do 发起一次 Engine API 调用；调用方负责关闭响应体。
// 非 2xx 统一转换为 *EngineError（错误体截断 4KB，不向上传播原始堆栈）。
func (c *DockerClient) do(ctx context.Context, method, path string, query url.Values, body io.Reader) (*http.Response, error) {
	u := &url.URL{Scheme: "http", Host: "docker", Path: path, RawQuery: query.Encode()}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, &EngineUnreachable{Err: err}
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp, nil
	}
	defer func() { _ = resp.Body.Close() }()
	var parsed struct {
		Message string `json:"message"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	msg := strings.TrimSpace(string(raw))
	if json.Unmarshal(raw, &parsed) == nil && parsed.Message != "" {
		msg = parsed.Message
	}
	if len(msg) > 300 {
		msg = msg[:300] + "…"
	}
	return nil, &EngineError{Status: resp.StatusCode, Message: msg}
}

// Ping 探测 Engine 可用性（GET /_ping）。
func (c *DockerClient) Ping(ctx context.Context) error {
	resp, err := c.do(ctx, http.MethodGet, "/_ping", nil, nil)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

// ContainerSummary 是 /containers/json 列表项（仅取用所需字段）。
type ContainerSummary struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`
	ImageID string            `json:"ImageID"`
	State   string            `json:"State"`
	Status  string            `json:"Status"`
	Labels  map[string]string `json:"Labels"`
	Created int64             `json:"Created"`
}

// Name 返回去斜杠的主容器名。
func (cs ContainerSummary) Name() string {
	if len(cs.Names) == 0 {
		return ""
	}
	return strings.TrimPrefix(cs.Names[0], "/")
}

// ListContainers 按 compose 项目标签过滤列出全部容器（含已停止）。
func (c *DockerClient) ListContainers(ctx context.Context, project string) ([]ContainerSummary, error) {
	filters, _ := json.Marshal(map[string][]string{"label": {LabelProject + "=" + project}})
	q := url.Values{}
	q.Set("all", "1")
	q.Set("filters", string(filters))
	resp, err := c.do(ctx, http.MethodGet, "/containers/json", q, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var out []ContainerSummary
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("解析容器列表失败: %w", err)
	}
	return out, nil
}

// ContainerInspect 是 /containers/{id}/json 的关键字段视图。
// Config/HostConfig 保留原始 JSON 以便 update 重建时全量透传（卷/端口/网络/环境）。
type ContainerInspect struct {
	ID              string          `json:"Id"`
	Name            string          `json:"Name"`
	Image           string          `json:"Image"` // 容器实际运行的镜像 ID（sha256:...）
	Config          json.RawMessage `json:"Config"`
	HostConfig      json.RawMessage `json:"HostConfig"`
	NetworkSettings struct {
		Networks map[string]json.RawMessage `json:"Networks"`
	} `json:"NetworkSettings"`
	State struct {
		Status    string `json:"Status"`
		Running   bool   `json:"Running"`
		ExitCode  int    `json:"ExitCode"`
		Error     string `json:"Error"`
		StartedAt string `json:"StartedAt"`
		Health    *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	RestartCount int `json:"RestartCount"`
}

// ShortID 返回 12 位短 ID。
func (ci *ContainerInspect) ShortID() string {
	if len(ci.ID) > 12 {
		return ci.ID[:12]
	}
	return ci.ID
}

// ObjectName 返回去斜杠容器名。
func (ci *ContainerInspect) ObjectName() string {
	return strings.TrimPrefix(ci.Name, "/")
}

// ConfigValue 从原始 Config JSON 取一个字段。
func (ci *ContainerInspect) ConfigValue(key string) interface{} {
	var m map[string]interface{}
	if json.Unmarshal(ci.Config, &m) != nil {
		return nil
	}
	return m[key]
}

// ConfigImage 返回容器创建时使用的镜像引用（repo:tag 形态）。
func (ci *ContainerInspect) ConfigImage() string {
	if s, ok := ci.ConfigValue("Image").(string); ok {
		return s
	}
	return ""
}

// TTY 报告容器是否以 TTY 模式运行（决定日志流是否为原始流）。
func (ci *ContainerInspect) TTY() bool {
	if b, ok := ci.ConfigValue("Tty").(bool); ok {
		return b
	}
	return false
}

// HasHealthcheck 依据 State.Health 是否出现判断容器是否定义了健康检查。
func (ci *ContainerInspect) HasHealthcheck() bool {
	return ci.State.Health != nil
}

// InspectContainer 读取容器完整信息。
func (c *DockerClient) InspectContainer(ctx context.Context, id string) (*ContainerInspect, error) {
	resp, err := c.do(ctx, http.MethodGet, "/containers/"+id+"/json", nil, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var out ContainerInspect
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("解析容器详情失败: %w", err)
	}
	return &out, nil
}

// ContainerLogs 打开日志流（stdout+stderr、带时间戳、尾部 tail 行、since 之后）。
// 返回的 ReadCloser 由调用方关闭；是否为多路复用流取决于容器的 Tty 配置（调用方先 inspect）。
func (c *DockerClient) ContainerLogs(ctx context.Context, id string, tail int, since int64) (io.ReadCloser, error) {
	q := url.Values{}
	q.Set("stdout", "1")
	q.Set("stderr", "1")
	q.Set("timestamps", "1")
	q.Set("tail", strconv.Itoa(tail))
	if since > 0 {
		q.Set("since", strconv.FormatInt(since, 10))
	}
	resp, err := c.do(ctx, http.MethodGet, "/containers/"+id+"/logs", q, nil)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// StartContainer 启动容器；已运行（304）视为成功。
func (c *DockerClient) StartContainer(ctx context.Context, id string) error {
	resp, err := c.do(ctx, http.MethodPost, "/containers/"+id+"/start", nil, nil)
	if err != nil {
		if isNotModified(err) {
			return nil
		}
		return err
	}
	_ = resp.Body.Close()
	return nil
}

// StopContainer 停止容器（timeoutSec 为 SIGKILL 前等待秒数）；已停止（304）视为成功。
func (c *DockerClient) StopContainer(ctx context.Context, id string, timeoutSec int) error {
	q := url.Values{}
	q.Set("t", strconv.Itoa(timeoutSec))
	resp, err := c.do(ctx, http.MethodPost, "/containers/"+id+"/stop", q, nil)
	if err != nil {
		if isNotModified(err) {
			return nil
		}
		return err
	}
	_ = resp.Body.Close()
	return nil
}

// RestartContainer 重启容器。
func (c *DockerClient) RestartContainer(ctx context.Context, id string, timeoutSec int) error {
	q := url.Values{}
	q.Set("t", strconv.Itoa(timeoutSec))
	resp, err := c.do(ctx, http.MethodPost, "/containers/"+id+"/restart", q, nil)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

// RenameContainer 重命名容器（update 重建前腾出原名）。
func (c *DockerClient) RenameContainer(ctx context.Context, id, newName string) error {
	q := url.Values{}
	q.Set("name", newName)
	resp, err := c.do(ctx, http.MethodPost, "/containers/"+id+"/rename", q, nil)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

// CreateContainer 以给定名称与完整配置体创建容器，返回新容器 ID。
func (c *DockerClient) CreateContainer(ctx context.Context, name string, body []byte) (string, error) {
	q := url.Values{}
	q.Set("name", name)
	resp, err := c.do(ctx, http.MethodPost, "/containers/create", q, strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", fmt.Errorf("解析创建容器响应失败: %w", err)
	}
	if out.ID == "" {
		return "", fmt.Errorf("创建容器响应缺少 Id")
	}
	return out.ID, nil
}

// RemoveContainer 删除容器。
func (c *DockerClient) RemoveContainer(ctx context.Context, id string, force bool) error {
	q := url.Values{}
	if force {
		q.Set("force", "1")
	}
	resp, err := c.do(ctx, http.MethodDelete, "/containers/"+id, q, nil)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

// ImageInspect 返回镜像 ID（用于比对更新前后镜像是否变化）。
func (c *DockerClient) ImageInspect(ctx context.Context, ref string) (imageID string, err error) {
	resp, err := c.do(ctx, http.MethodGet, "/images/"+ref+"/json", nil, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&out); err != nil {
		return "", fmt.Errorf("解析镜像详情失败: %w", err)
	}
	return out.ID, nil
}

// PullImage 拉取镜像（POST /images/create）。ref 为 name:tag 或 name:tag@sha256:digest。
// 响应为 JSON 进度流：逐行读取，任何 error/errorDetail 条目都使拉取失败。
func (c *DockerClient) PullImage(ctx context.Context, ref string) error {
	ctx, cancel := context.WithTimeout(ctx, c.pullTimeout)
	defer cancel()
	q := url.Values{}
	// repo 可能含 registry 端口（host:5000/repo:tag），取最后一个斜杠之后的冒号分段
	if strings.Contains(ref, "@") {
		q.Set("fromImage", ref)
	} else if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		q.Set("fromImage", ref[:i])
		q.Set("tag", ref[i+1:])
	} else {
		q.Set("fromImage", ref)
	}
	resp, err := c.do(ctx, http.MethodPost, "/images/create", q, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	dec := json.NewDecoder(io.LimitReader(resp.Body, 32<<20))
	for {
		var line struct {
			Error       string `json:"error"`
			ErrorDetail struct {
				Message string `json:"message"`
			} `json:"errorDetail"`
		}
		if err := dec.Decode(&line); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("读取镜像拉取进度流失败: %w", err)
		}
		if line.ErrorDetail.Message != "" {
			return fmt.Errorf("拉取镜像失败: %s", line.ErrorDetail.Message)
		}
		if line.Error != "" {
			return fmt.Errorf("拉取镜像失败: %s", line.Error)
		}
	}
}
