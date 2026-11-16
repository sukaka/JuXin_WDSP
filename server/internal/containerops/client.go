// Package containerops 容器运维管理后端：经共享卷 Unix Socket 调用 containeropsd
// sidecar（管理 API 不挂载 docker.sock，唯一通道见 docs/CONTAINER_OPS_DESIGN.md）。
// CONTAINEROPS_SOCKET 未配置时功能不可用，接口返回明确 503，不伪造空数据。
package containerops

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

// 权限点
const (
	PermRead    = "containers.read"
	PermLogs    = "containers.logs"
	PermControl = "containers.control"
	PermUpdate  = "containers.update"
)

// UpdateConfirmText 更新容器的确认文本（严格相等）。
const UpdateConfirmText = "更新容器"

// 日志参数口径（与 sidecar 一致）
const (
	DefaultLogTail = 200
	MaxLogTail     = 1000
)

// Container 是容器状态视图（sidecar 白名单字段）。
type Container struct {
	Service      string `json:"service"`
	Project      string `json:"project"`
	ID           string `json:"id"`
	Name         string `json:"name"`
	Image        string `json:"image"`
	ImageID      string `json:"image_id"`
	State        string `json:"state"`
	Status       string `json:"status"`
	Health       string `json:"health"`
	Running      bool   `json:"running"`
	RestartCount int    `json:"restart_count"`
	StartedAt    string `json:"started_at"`
}

// LogLine 是一条日志行。
type LogLine struct {
	Timestamp string `json:"timestamp"`
	Stream    string `json:"stream"`
	Message   string `json:"message"`
}

// LogsResult 是日志读取结果。
type LogsResult struct {
	Service   string    `json:"service"`
	Lines     []LogLine `json:"lines"`
	Truncated bool      `json:"truncated"`
	NextSince int64     `json:"next_since"`
}

// ActionJob 是运维动作任务状态。
type ActionJob struct {
	JobID      string     `json:"job_id"`
	Service    string     `json:"service"`
	Action     string     `json:"action"`
	Status     string     `json:"status"`
	Message    string     `json:"message"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// ErrorKind 错误类别。
type ErrorKind int

const (
	// KindUnavailable 通道不可达（socket 不存在/连接失败/超时）→ 503
	KindUnavailable ErrorKind = iota
	// KindUpstream sidecar 返回的结构化错误（携带其 HTTP 状态与错误码）
	KindUpstream
)

// Error 是调用 sidecar 的 typed 错误。
type Error struct {
	Kind    ErrorKind
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e.Kind == KindUnavailable {
		return "containerops 通道不可用: " + e.Message
	}
	return fmt.Sprintf("containerops 错误: status=%d code=%s: %s", e.Status, e.Code, e.Message)
}

// IsUnavailable 判断错误是否为通道不可达。
func IsUnavailable(err error) bool {
	var ce *Error
	return errors.As(err, &ce) && ce.Kind == KindUnavailable
}

// Client 是 containeropsd 的 Unix Socket HTTP 客户端。
type Client struct {
	socketPath string
	hc         *http.Client
}

// NewClient 创建客户端；socketPath 为空时客户端不可用（Available() == false），
// 所有调用返回 KindUnavailable 错误。
func NewClient(socketPath string) *Client {
	c := &Client{socketPath: socketPath}
	if socketPath == "" {
		return c
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "unix", socketPath)
		},
		MaxIdleConns:        4,
		MaxConnsPerHost:     8,
		MaxIdleConnsPerHost: 4,
	}
	// 日志读取有 256KiB 上限，30s 足够；update 是异步任务，不经同步等待
	c.hc = &http.Client{Transport: transport, Timeout: 30 * time.Second}
	return c
}

// Available 报告通道是否已配置。
func (c *Client) Available() bool {
	return c != nil && c.socketPath != ""
}

// call 发起一次调用并解码成功响应；失败归一为 *Error。
func (c *Client) call(ctx context.Context, method, path string, query url.Values, body io.Reader, out interface{}) error {
	if !c.Available() {
		return &Error{Kind: KindUnavailable, Message: "CONTAINEROPS_SOCKET 未配置"}
	}
	u := &url.URL{Scheme: "http", Host: "containerops", Path: path, RawQuery: query.Encode()}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return &Error{Kind: KindUnavailable, Message: err.Error()}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return &Error{Kind: KindUnavailable, Message: err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return &Error{Kind: KindUnavailable, Message: "读取响应失败: " + err.Error()}
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if out == nil {
			return nil
		}
		if err := json.Unmarshal(raw, out); err != nil {
			return &Error{Kind: KindUnavailable, Message: "解析响应失败: " + err.Error()}
		}
		return nil
	}
	var errBody struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &errBody) == nil && errBody.Error.Code != "" {
		return &Error{Kind: KindUpstream, Status: resp.StatusCode, Code: errBody.Error.Code, Message: errBody.Error.Message}
	}
	return &Error{Kind: KindUpstream, Status: resp.StatusCode, Code: "UNKNOWN", Message: "containerops 返回非预期错误"}
}

// ListContainers GET /v1/containers
func (c *Client) ListContainers(ctx context.Context) ([]Container, error) {
	var out struct {
		Containers []Container `json:"containers"`
	}
	if err := c.call(ctx, http.MethodGet, "/v1/containers", nil, nil, &out); err != nil {
		return nil, err
	}
	return out.Containers, nil
}

// ContainerLogs GET /v1/containers/{service}/logs
func (c *Client) ContainerLogs(ctx context.Context, service string, tail int, since int64) (*LogsResult, error) {
	q := url.Values{}
	q.Set("tail", strconv.Itoa(tail))
	if since > 0 {
		q.Set("since", strconv.FormatInt(since, 10))
	}
	var out LogsResult
	if err := c.call(ctx, http.MethodGet, "/v1/containers/"+service+"/logs", q, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SubmitAction POST /v1/containers/{service}/actions
func (c *Client) SubmitAction(ctx context.Context, service, action string, delaySeconds int) (*ActionJob, error) {
	payload, _ := json.Marshal(map[string]interface{}{
		"action":        action,
		"delay_seconds": delaySeconds,
	})
	var out ActionJob
	if err := c.call(ctx, http.MethodPost, "/v1/containers/"+service+"/actions", nil,
		strings.NewReader(string(payload)), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ActionStatus GET /v1/actions/{job_id}
func (c *Client) ActionStatus(ctx context.Context, jobID string) (*ActionJob, error) {
	var out ActionJob
	if err := c.call(ctx, http.MethodGet, "/v1/actions/"+jobID, nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
