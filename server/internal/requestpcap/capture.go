package requestpcap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
	"github.com/jiuzhang-waf/server/internal/systemops"
)

const PermissionCaptureControl = "request_pcap.capture_control"

var (
	ErrCaptureInvalid = errors.New("invalid PCAP capture configuration")
	captureInterface  = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
	capturePath       = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
)

type CaptureConfig struct {
	Enabled     bool      `json:"enabled"`
	Interface   string    `json:"interface"`
	Ports       []int     `json:"ports"`
	HotDir      string    `json:"hot_dir"`
	WarmDir     string    `json:"warm_dir"`
	RequestID   string    `json:"request_id"`
	RequestedAt time.Time `json:"requested_at"`
}

type CaptureStatus struct {
	CaptureConfig
	State   string `json:"state"`
	Message string `json:"message,omitempty"`
}

type captureSettings interface {
	GetStringWithSource(context.Context, string, string) (string, bool, error)
	UpsertString(context.Context, string, string, string, string, uuid.UUID) error
}

type CaptureController struct {
	settings captureSettings
	hostctl  string
	nodeID   string
	audits   auditRecorder
	now      func() time.Time
}

func NewCaptureController(settings captureSettings, hostctl, nodeID string, audits auditRecorder) *CaptureController {
	return &CaptureController{settings: settings, hostctl: hostctl, nodeID: nodeID, audits: audits, now: func() time.Time { return time.Now().UTC() }}
}

func (c *CaptureController) principal(w http.ResponseWriter, r *http.Request) *authz.Principal {
	principal := authz.PrincipalFrom(r.Context())
	if principal == nil || principal.UserID == uuid.Nil || principal.SessionID == "" {
		response.Error(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, "未登录或会话已过期")
		return nil
	}
	if c.settings == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "系统设置服务不可用")
		return nil
	}
	return principal
}

func (c *CaptureController) load(ctx context.Context) (*CaptureConfig, error) {
	value, found, err := c.settings.GetStringWithSource(ctx, "request_pcap_capture", "config")
	if err != nil {
		return nil, err
	}
	if !found || strings.TrimSpace(value) == "" {
		return nil, nil
	}
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.DisallowUnknownFields()
	var config CaptureConfig
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("decode PCAP capture settings: %w", err)
	}
	if decoder.More() {
		return nil, ErrCaptureInvalid
	}
	return &config, nil
}

func validateCaptureConfig(config CaptureConfig) error {
	if !captureInterface.MatchString(config.Interface) {
		return fmt.Errorf("%w: 网卡名称不合法", ErrCaptureInvalid)
	}
	if len(config.Ports) == 0 || len(config.Ports) > 128 {
		return fmt.Errorf("%w: 需要1至128个明确端口", ErrCaptureInvalid)
	}
	seen := make(map[int]bool, len(config.Ports))
	for _, port := range config.Ports {
		if port < 1 || port > 65535 || seen[port] {
			return fmt.Errorf("%w: 端口越界或重复", ErrCaptureInvalid)
		}
		seen[port] = true
	}
	if err := captureStoragePath(config.HotDir); err != nil {
		return err
	}
	if err := captureStoragePath(config.WarmDir); err != nil {
		return err
	}
	hot, warm := filepath.Clean(config.HotDir), filepath.Clean(config.WarmDir)
	if hot == warm || strings.HasPrefix(hot+"/", warm+"/") || strings.HasPrefix(warm+"/", hot+"/") {
		return fmt.Errorf("%w: 热目录与温目录必须独立且不能嵌套", ErrCaptureInvalid)
	}
	return nil
}

func captureStoragePath(path string) error {
	if !capturePath.MatchString(path) || !filepath.IsAbs(path) || path != filepath.Clean(path) || len(path) > 240 || strings.ContainsAny(path, "\x00\r\n'") {
		return fmt.Errorf("%w: 存储路径必须是规范绝对路径", ErrCaptureInvalid)
	}
	allowed := false
	for _, prefix := range []string{"/srv/", "/var/lib/", "/data/", "/mnt/", "/media/"} {
		if strings.HasPrefix(path, prefix) && len(path) > len(prefix) {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("%w: 存储路径仅允许位于受控数据盘目录", ErrCaptureInvalid)
	}
	return nil
}

func (c *CaptureController) Get(w http.ResponseWriter, r *http.Request) {
	if c.principal(w, r) == nil {
		return
	}
	config, err := c.load(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, c.status(config))
}

func (c *CaptureController) status(config *CaptureConfig) CaptureStatus {
	if config == nil {
		return CaptureStatus{CaptureConfig: CaptureConfig{Enabled: false, Ports: []int{}}, State: "DISABLED"}
	}
	result := CaptureStatus{CaptureConfig: *config, State: "PENDING"}
	statusPath := filepath.Join(c.hostctl, "pcap-status.json")
	stat, err := os.Stat(statusPath)
	if err == nil {
		if stat.Size() > 65536 {
			result.State, result.Message = "FAILED", "宿主状态文件异常"
		} else if raw, err := os.ReadFile(statusPath); err != nil {
			result.State, result.Message = "FAILED", "无法读取宿主执行状态"
		} else {
			var hostResult struct {
				RequestID string `json:"requestID"`
				State     string `json:"state"`
				Message   string `json:"message"`
			}
			if err := json.Unmarshal(raw, &hostResult); err != nil {
				result.State, result.Message = "FAILED", "宿主状态文件格式非法"
			} else if hostResult.RequestID == config.RequestID {
				switch hostResult.State {
				case "ENABLED", "DISABLED", "FAILED":
					result.State, result.Message = hostResult.State, hostResult.Message
				default:
					result.State, result.Message = "FAILED", "宿主返回了未知状态"
				}
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		result.State, result.Message = "FAILED", "无法访问宿主执行状态"
	}
	if result.State == "PENDING" && c.now().Sub(config.RequestedAt) > 2*time.Minute {
		result.State = "FAILED"
		result.Message = "宿主执行超时，请检查 hostctl、API 与 pcapd 状态"
	}
	result.Enabled = result.State == "ENABLED"
	return result
}

func (c *CaptureController) Set(w http.ResponseWriter, r *http.Request) {
	principal := c.principal(w, r)
	if principal == nil {
		return
	}
	var input struct {
		Enabled   bool   `json:"enabled"`
		Interface string `json:"interface"`
		Ports     []int  `json:"ports"`
		HotDir    string `json:"hot_dir"`
		WarmDir   string `json:"warm_dir"`
		Reason    string `json:"reason"`
	}
	if err := response.DecodeJSON(w, r, &input, 16384); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if !validReason(strings.TrimSpace(input.Reason)) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请填写1至500字符的操作理由")
		return
	}
	previous, err := c.load(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	config := CaptureConfig{Enabled: input.Enabled, Interface: strings.TrimSpace(input.Interface), Ports: input.Ports,
		HotDir: strings.TrimSpace(input.HotDir), WarmDir: strings.TrimSpace(input.WarmDir)}
	if !input.Enabled {
		if previous == nil || !previous.Enabled {
			response.JSON(w, r, http.StatusOK, c.status(previous))
			return
		}
		config.Interface, config.Ports, config.HotDir, config.WarmDir = previous.Interface, previous.Ports, previous.HotDir, previous.WarmDir
	}
	if err := validateCaptureConfig(config); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	config.RequestID = uuid.NewString()
	config.RequestedAt = c.now()
	raw, err := json.Marshal(config)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if err := c.settings.UpsertString(r.Context(), "request_pcap_capture", "config", string(raw), "系统管理员控制的PCAP采集范围与开关", principal.UserID); err != nil {
		response.InternalError(w, r, err)
		return
	}
	_, err = systemops.WriteFlagFile(c.hostctl, systemops.Command{
		Action: systemops.ActionPCAPCapture, RequestedBy: principal.Username, UserID: principal.UserID.String(),
		RequestID: config.RequestID, RequestedAt: config.RequestedAt.Format(time.RFC3339), DelaySeconds: 0,
		Interface: config.Interface, Ports: config.Ports, HotDir: config.HotDir, WarmDir: config.WarmDir,
		NodeID: c.nodeID, Enabled: &config.Enabled,
	})
	if c.audits != nil {
		action := "request_pcap.capture_disable"
		if config.Enabled {
			action = "request_pcap.capture_enable"
		}
		record := audits.RecordInput{UserID: &principal.UserID, Username: principal.Username, SourceIP: middleware.RemoteIP(r),
			ConnectionIP: middleware.ConnectionIP(r), UserAgent: r.UserAgent(), Module: "api_audit", Action: action,
			ObjectType: "request_pcap", ObjectID: config.RequestID, Result: audits.ResultSuccess,
			AfterSummary: "操作理由：" + strings.TrimSpace(input.Reason), RiskLevel: audits.RiskHigh, RequestID: response.RequestIDFrom(r)}
		if err != nil {
			record.Result, record.FailureReason = audits.ResultFailure, "宿主控制指令写入失败"
		}
		if auditErr := c.audits.Record(context.WithoutCancel(r.Context()), record); auditErr != nil {
			response.InternalError(w, r, auditErr)
			return
		}
	}
	if err != nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "宿主控制指令写入失败，请检查hostctl通道")
		return
	}
	response.JSON(w, r, http.StatusAccepted, c.status(&config))
}
