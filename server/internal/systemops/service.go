// Package systemops 系统控制（重启/关机/恢复出厂设置）。
// 管理面不直接执行宿主命令：校验通过后向 HOSTCTL_DIR 写入原子标志文件，
// 由宿主侧 hostctl 组件（带外/特权进程）消费执行，管理容器保持最小权限。
package systemops

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// 控制动作
const (
	ActionReboot         = "reboot"
	ActionShutdown       = "shutdown"
	ActionFactoryReset   = "factory_reset"
	ActionFirewallEnsure = "firewall_ensure"
	ActionPCAPCapture    = "pcap_capture"
)

// FactoryResetConfirmText 恢复出厂设置的确认文本（严格相等）。
const FactoryResetConfirmText = "恢复出厂"

// 指令延迟执行秒数（写入标志文件，给 HTTP 响应返回留出时间）。
const delaySeconds = 3

const maxFirewallPorts = 128

// HostctlSecretName 共享密钥文件名（置于标志目录下，hostctl-exec.sh 启动时也会
// 自举同名文件，先到者生效）。内容为 32 字节随机数的 hex 编码（64 字符），
// 写入方与验签方均以该 hex 字符串作为 HMAC-SHA256 密钥。
const HostctlSecretName = ".hostctl-secret"

// hostctlSignVersion 签名规范化载荷版本前缀；签名字段集合变更时必须递增并同步
// hostctl-exec.sh 验签逻辑。
const hostctlSignVersion = "v1"
const hostctlFirewallSignVersion = "v2"
const hostctlPCAPSignVersion = "v3"

// Command 是写入 HOSTCTL_DIR 的宿主控制指令标志文件内容。
// HMAC 为对 CanonicalPayload 的 HMAC-SHA256（hex）；宿主侧 fail-closed 验签，
// 未携带有效签名的标志（含升级窗口内旧版本写出的未签名标志）一律拒绝执行。
type Command struct {
	Action       string `json:"action"`
	RequestedBy  string `json:"requestedBy"`
	UserID       string `json:"userID"`
	RequestID    string `json:"requestID"`
	RequestedAt  string `json:"requestedAt"`
	DelaySeconds int    `json:"delaySeconds"`
	Ports        []int  `json:"ports,omitempty"`
	Interface    string `json:"interface,omitempty"`
	HotDir       string `json:"hot_dir,omitempty"`
	WarmDir      string `json:"warm_dir,omitempty"`
	NodeID       string `json:"node_id,omitempty"`
	Enabled      *bool  `json:"enabled,omitempty"`
	HMAC         string `json:"hmac"`
}

// CanonicalPayload 生成标志文件的规范化签名载荷：固定字段顺序覆盖全部语义字段
// （requestedAt 兼作防重放时间戳，requestID 兼作 nonce），以 \n 连接、无结尾
// 换行；hostctl-exec.sh 验签侧必须保持逐字节一致。firewall_ensure 使用 v2，
// 第八字段为排序去重后的逗号分隔 TCP 端口；旧动作保持 v1 字节级兼容。
func CanonicalPayload(cmd Command) string {
	fields := []string{
		hostctlSignVersion,
		cmd.Action,
		cmd.RequestedBy,
		cmd.UserID,
		cmd.RequestID,
		cmd.RequestedAt,
		strconv.Itoa(cmd.DelaySeconds),
	}
	if cmd.Action == ActionFirewallEnsure || cmd.Action == ActionPCAPCapture {
		ports := sortedUniquePorts(cmd.Ports)
		values := make([]string, len(ports))
		for i, port := range ports {
			values[i] = strconv.Itoa(port)
		}
		fields = append(fields, strings.Join(values, ","))
	}
	if cmd.Action == ActionFirewallEnsure {
		fields[0] = hostctlFirewallSignVersion
	}
	if cmd.Action == ActionPCAPCapture {
		fields[0] = hostctlPCAPSignVersion
		enabled := false
		if cmd.Enabled != nil {
			enabled = *cmd.Enabled
		}
		fields = append(fields, cmd.Interface, cmd.HotDir, cmd.WarmDir, cmd.NodeID, strconv.FormatBool(enabled))
	}
	return strings.Join(fields, "\n")
}

func sortedUniquePorts(ports []int) []int {
	out := append([]int(nil), ports...)
	sort.Ints(out)
	write := 0
	for _, port := range out {
		if write > 0 && out[write-1] == port {
			continue
		}
		out[write] = port
		write++
	}
	return out[:write]
}

// EnsureFirewallPorts 提交网关监听 TCP 端口的宿主防火墙放行指令。空列表不写标志；
// 非空列表校验 1..65535，排序去重后最多 128 个端口。返回成功仅表示指令已写入
// 宿主通道，不表示宿主防火墙已经执行完成。
func EnsureFirewallPorts(dir string, ports []int, userID uuid.UUID, requestID string) error {
	if len(ports) == 0 {
		return nil
	}
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("firewall port out of range: %d", port)
		}
	}
	ports = sortedUniquePorts(ports)
	if len(ports) > maxFirewallPorts {
		return fmt.Errorf("too many firewall ports: %d, maximum is %d", len(ports), maxFirewallPorts)
	}
	_, err := WriteFlagFile(dir, Command{
		Action:       ActionFirewallEnsure,
		RequestedBy:  "gateway-publish",
		UserID:       userID.String(),
		RequestID:    requestID,
		RequestedAt:  time.Now().UTC().Format(time.RFC3339),
		DelaySeconds: 0,
		Ports:        ports,
	})
	return err
}

// SignCommand 用共享密钥对规范化载荷计算 HMAC-SHA256（hex）并填入 cmd.HMAC。
func SignCommand(cmd *Command, secret []byte) {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(CanonicalPayload(*cmd)))
	cmd.HMAC = hex.EncodeToString(mac.Sum(nil))
}

// LoadOrCreateHostctlSecret 读取 dir 下的共享密钥；不存在时以 0600 权限原子排他
// 创建（O_EXCL 避免与宿主侧自举并发覆盖，后到者读取先到者的密钥）。密钥格式非法
// 时返回错误（fail-closed，由调用方记失败审计并拒绝受理）。
func LoadOrCreateHostctlSecret(dir string) ([]byte, error) {
	path := filepath.Join(dir, HostctlSecretName)
	readValid := func() ([]byte, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read hostctl secret: %w", err)
		}
		key := []byte(strings.TrimSpace(string(b)))
		if len(key) != 64 {
			return nil, fmt.Errorf("hostctl secret malformed: expect 64 hex chars, got %d", len(key))
		}
		if _, err := hex.DecodeString(string(key)); err != nil {
			return nil, fmt.Errorf("hostctl secret malformed: %w", err)
		}
		return key, nil
	}
	key, err := readValid()
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("generate hostctl secret: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return readValid()
		}
		return nil, fmt.Errorf("create hostctl secret: %w", err)
	}
	if _, err := f.WriteString(hex.EncodeToString(raw) + "\n"); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("write hostctl secret: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("close hostctl secret: %w", err)
	}
	return readValid()
}

// FlagFileName 生成标志文件名：<action>-<unixts>-<requestid>.json。
// requestID 为空时使用随机 UUID 兜底，保证文件名唯一且不含路径分隔符。
func FlagFileName(action, requestID string, now time.Time) string {
	id := requestID
	if id == "" {
		id = uuid.NewString()
	}
	return fmt.Sprintf("%s-%d-%s.json", action, now.Unix(), id)
}

// WriteFlagFile 原子写入控制指令标志文件（写临时文件 + fsync + rename），
// 写入前加载/自举共享密钥并对指令签名（hmac 字段）。
// 返回最终文件路径。目录不存在时自动创建；不可写/写失败/密钥异常返回错误。
func WriteFlagFile(dir string, cmd Command) (string, error) {
	if cmd.Action == ActionPCAPCapture && (cmd.Enabled == nil || cmd.Interface == "" || cmd.HotDir == "" || cmd.WarmDir == "" || cmd.NodeID == "") {
		return "", fmt.Errorf("incomplete PCAP capture command")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("create hostctl dir: %w", err)
	}
	secret, err := LoadOrCreateHostctlSecret(dir)
	if err != nil {
		return "", err
	}
	SignCommand(&cmd, secret)
	payload, err := json.Marshal(cmd)
	if err != nil {
		return "", fmt.Errorf("marshal hostctl command: %w", err)
	}
	payload = append(payload, '\n')

	tmp, err := os.CreateTemp(dir, ".hostctl-*.tmp")
	if err != nil {
		return "", fmt.Errorf("create temp flag file: %w", err)
	}
	tmpName := tmp.Name()
	// 出错时清理临时文件
	defer func() {
		_ = os.Remove(tmpName)
	}()
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("write flag file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("fsync flag file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("close flag file: %w", err)
	}
	final := filepath.Join(dir, FlagFileName(cmd.Action, cmd.RequestID, time.Now()))
	if err := os.Rename(tmpName, final); err != nil {
		return "", fmt.Errorf("rename flag file: %w", err)
	}
	return final, nil
}
