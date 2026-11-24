package nodesync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
	"github.com/jiuzhang-waf/server/internal/hagroups"
)

// ErrNodeNotFound indicates the requested gateway node does not exist in the backing store.
var ErrNodeNotFound = errors.New("sync node not found")

// NodeCredential represents a registered gateway node's sync endpoint, encrypted secret,
// and latest converged runtime status snapshots (adapted from apinodes.Store in app.go).
type NodeCredential struct {
	NodeID               uuid.UUID
	NodeName             string
	AdminAddr            string
	SyncAgentAddr        string
	SyncSecretCiphertext string `json:"-"`
	SyncEnabled          bool
	ReportedVersion      string
	HaVipStatus          json.RawMessage
	HaVipStatusAt        *time.Time
	NetworkStatus        json.RawMessage
	NetworkStatusAt      *time.Time
}

// NodeStore provides read access to node credentials and converged snapshots.
type NodeStore interface {
	GetCredentialByID(ctx context.Context, nodeID uuid.UUID) (*NodeCredential, error)
	GetCredentialByName(ctx context.Context, nodeName string) (*NodeCredential, error)
	ListSyncAgentNodes(ctx context.Context) ([]NodeCredential, error)
	ListNodesByNames(ctx context.Context, nodeNames []string) ([]NodeCredential, error)
}

// SecretDecryptor decrypts stored sync_secret_ciphertext values (*encryption.Service).
type SecretDecryptor interface {
	Decrypt(encoded string) (string, error)
}

// ManagerConfig configures the control-plane nodesync Manager.
type ManagerConfig struct {
	LocalNodeName string
	TLSCAPEM      []byte
	TLSCertSHA256 string
	Timeout       time.Duration
	UploadTimeout time.Duration
	Resolver      IPResolver
	NowFunc       func() time.Time
}

// Manager coordinates authenticated control-plane RPCs to remote gateway hasyncd agents
// and exposes converged remote status snapshots for gatewayconfig, hagroups, netconfig,
// apinodes, and upgrades.
type Manager struct {
	store     NodeStore
	decryptor SecretDecryptor
	cfg       ManagerConfig
	now       func() time.Time
}

// Compile-time interface assertions against gatewayconfig and hagroups hooks.
var (
	_ gatewayconfig.NodeAgentSyncer = (*Manager)(nil)
	_ hagroups.RemoteSyncer         = (*Manager)(nil)
	_ hagroups.NodeStatusProvider   = (*Manager)(nil)
)

// NewManager creates a nodesync Manager.
func NewManager(store NodeStore, decryptor SecretDecryptor, cfg ManagerConfig) *Manager {
	nowFn := cfg.NowFunc
	if nowFn == nil {
		nowFn = time.Now
	}
	return &Manager{
		store:     store,
		decryptor: decryptor,
		cfg:       cfg,
		now:       nowFn,
	}
}

// LocalNodeName returns the configured local control-plane/gateway node identifier.
func (m *Manager) LocalNodeName() string {
	return strings.TrimSpace(m.cfg.LocalNodeName)
}

// ClientForCredential builds a validated, HMAC-signing Client for the given node credential.
func (m *Manager) ClientForCredential(cred *NodeCredential) (*Client, error) {
	if cred == nil {
		return nil, ErrNodeNotFound
	}
	addr := strings.TrimSpace(cred.SyncAgentAddr)
	if addr == "" {
		return nil, fmt.Errorf("节点 %s 未配置协同代理地址 (sync_agent_addr)", cred.NodeName)
	}
	cipher := strings.TrimSpace(cred.SyncSecretCiphertext)
	if cipher == "" {
		return nil, fmt.Errorf("节点 %s 未配置协同代理密钥 (sync_secret)", cred.NodeName)
	}
	if m.decryptor == nil {
		return nil, errors.New("加密服务未初始化，无法解密节点协同代理密钥")
	}
	plainSecret, err := m.decryptor.Decrypt(cipher)
	if err != nil {
		return nil, fmt.Errorf("解密节点 %s 协同代理密钥失败: %w", cred.NodeName, err)
	}
	callerNode := strings.TrimSpace(m.cfg.LocalNodeName)
	if callerNode == "" {
		callerNode = "control-plane"
	}
	return NewClient(ClientConfig{
		Addr:          addr,
		SecretHex:     plainSecret,
		NodeName:      callerNode,
		TLSCAPEM:      m.cfg.TLSCAPEM,
		TLSCertSHA256: m.cfg.TLSCertSHA256,
		Timeout:       m.cfg.Timeout,
		UploadTimeout: m.cfg.UploadTimeout,
		Resolver:      m.cfg.Resolver,
		NowFunc:       m.now,
	})
}

// ClientForNodeID resolves a node by UUID and returns a configured Client.
func (m *Manager) ClientForNodeID(ctx context.Context, nodeID uuid.UUID) (*Client, *NodeCredential, error) {
	if m.store == nil {
		return nil, nil, errors.New("nodesync store is not configured")
	}
	cred, err := m.store.GetCredentialByID(ctx, nodeID)
	if err != nil {
		return nil, nil, err
	}
	cli, err := m.ClientForCredential(cred)
	if err != nil {
		return nil, cred, err
	}
	return cli, cred, nil
}

// ClientForNodeName resolves a node by name and returns a configured Client.
func (m *Manager) ClientForNodeName(ctx context.Context, nodeName string) (*Client, *NodeCredential, error) {
	if m.store == nil {
		return nil, nil, errors.New("nodesync store is not configured")
	}
	cred, err := m.store.GetCredentialByName(ctx, strings.TrimSpace(nodeName))
	if err != nil {
		return nil, nil, err
	}
	cli, err := m.ClientForCredential(cred)
	if err != nil {
		return nil, cred, err
	}
	return cli, cred, nil
}

func (m *Manager) clientForSyncTarget(ctx context.Context, target gatewayconfig.SyncTarget) (*Client, error) {
	if target.NodeID != uuid.Nil {
		cli, _, err := m.ClientForNodeID(ctx, target.NodeID)
		return cli, err
	}
	cli, _, err := m.ClientForNodeName(ctx, target.NodeName)
	return cli, err
}

// ---------- gatewayconfig.NodeAgentSyncer ----------

// SyncCaddyConfig pushes Caddy JSON via hasyncd POST /v1/caddy/load and verifies the
// active canonical business config hash via GET /v1/caddy/config-hash.
func (m *Manager) SyncCaddyConfig(ctx context.Context, target gatewayconfig.SyncTarget, configJSON string) (string, error) {
	cli, err := m.clientForSyncTarget(ctx, target)
	if err != nil {
		return "", err
	}
	loadResp, err := cli.LoadCaddyConfig(ctx, []byte(configJSON))
	if err != nil {
		return "", fmt.Errorf("推送远端节点 %s Caddy 配置失败: %w", target.NodeName, err)
	}
	if loadResp != nil && !loadResp.OK {
		msg := strings.TrimSpace(loadResp.Error)
		if msg == "" {
			msg = fmt.Sprintf("caddy status %d", loadResp.CaddyStatus)
		}
		return "", fmt.Errorf("远端节点 %s 加载 Caddy 配置失败: %s", target.NodeName, msg)
	}
	hashResp, err := cli.GetCaddyConfigHash(ctx)
	if err != nil {
		return "", fmt.Errorf("查询远端节点 %s 配置哈希失败: %w", target.NodeName, err)
	}
	if hashResp == nil || strings.TrimSpace(hashResp.ConfigHash) == "" {
		return "", fmt.Errorf("远端节点 %s 未返回有效配置哈希", target.NodeName)
	}
	return strings.TrimSpace(hashResp.ConfigHash), nil
}

// SyncSidecarFile pushes an allowlisted sidecar JSON file (tproxyd.json / mirrorcap.json / etc.)
// to the target gateway node via PUT /v1/sidecars/{name}.
func (m *Manager) SyncSidecarFile(ctx context.Context, target gatewayconfig.SyncTarget, name string, payload []byte) error {
	cli, err := m.clientForSyncTarget(ctx, target)
	if err != nil {
		return err
	}
	if _, err := cli.PutSidecar(ctx, name, payload); err != nil {
		return fmt.Errorf("推送远端节点 %s 边车配置 %s 失败: %w", target.NodeName, name, err)
	}
	return nil
}

// SyncFirewallPorts ensures site listener ports are opened on the target gateway node's host firewall
// via hasyncd POST /v1/firewall/ensure.
func (m *Manager) SyncFirewallPorts(ctx context.Context, target gatewayconfig.SyncTarget, ports []int, requestedBy uuid.UUID, requestID string) error {
	if len(ports) == 0 {
		return nil
	}
	cli, err := m.clientForSyncTarget(ctx, target)
	if err != nil {
		return err
	}
	reqBy := "system"
	userID := ""
	if requestedBy != uuid.Nil {
		reqBy = requestedBy.String()
		userID = requestedBy.String()
	}
	rid := strings.TrimSpace(requestID)
	if rid == "" {
		rid = fmt.Sprintf("fw-sync-%d", m.now().UTC().UnixNano())
	}
	_, err = cli.EnsureFirewallPorts(ctx, FirewallEnsureRequest{
		Ports:       ports,
		RequestID:   rid,
		RequestedBy: reqBy,
		UserID:      userID,
	})
	if err != nil {
		return fmt.Errorf("同步远端节点 %s 防火墙端口失败: %w", target.NodeName, err)
	}
	return nil
}

// ---------- hagroups.RemoteSyncer & hagroups.NodeStatusProvider ----------

// PushHaVip pushes ha-vip.json to a remote HA member node via hasyncd.
func (m *Manager) PushHaVip(ctx context.Context, nodeName string, payload []byte) error {
	cli, _, err := m.ClientForNodeName(ctx, nodeName)
	if err != nil {
		return err
	}
	if _, err := cli.PutSidecar(ctx, SidecarHaVip, payload); err != nil {
		return fmt.Errorf("推送节点 %s 主备配置失败: %w", nodeName, err)
	}
	return nil
}

// DeleteHaVip deletes ha-vip.json on a remote HA member node via hasyncd.
func (m *Manager) DeleteHaVip(ctx context.Context, nodeName string) error {
	cli, _, err := m.ClientForNodeName(ctx, nodeName)
	if err != nil {
		return err
	}
	if _, err := cli.DeleteSidecar(ctx, SidecarHaVip); err != nil {
		return fmt.Errorf("收回节点 %s 主备配置失败: %w", nodeName, err)
	}
	return nil
}

// GetNodeHaVipStatuses returns the converged ha_vip_status snapshots for the requested nodes.
func (m *Manager) GetNodeHaVipStatuses(ctx context.Context, nodeNames []string) (map[string]hagroups.NodeRuntimeStatus, error) {
	if m.store == nil || len(nodeNames) == 0 {
		return map[string]hagroups.NodeRuntimeStatus{}, nil
	}
	creds, err := m.store.ListNodesByNames(ctx, nodeNames)
	if err != nil {
		return nil, err
	}
	out := make(map[string]hagroups.NodeRuntimeStatus, len(creds))
	for _, c := range creds {
		if len(c.HaVipStatus) == 0 {
			continue
		}
		out[c.NodeName] = hagroups.NodeRuntimeStatus{
			NodeName:  c.NodeName,
			Status:    c.HaVipStatus,
			UpdatedAt: c.HaVipStatusAt,
			Source:    "remote",
		}
	}
	return out, nil
}

// ---------- netconfig Remote Sync & Status ----------

// PushNetworkConfig pushes network.json to a remote gateway node via hasyncd.
func (m *Manager) PushNetworkConfig(ctx context.Context, nodeName string, payload []byte) error {
	cli, _, err := m.ClientForNodeName(ctx, nodeName)
	if err != nil {
		return err
	}
	if _, err := cli.PutSidecar(ctx, SidecarNetwork, payload); err != nil {
		return fmt.Errorf("推送节点 %s 网络配置失败: %w", nodeName, err)
	}
	return nil
}

// IsRemoteEditable reports whether nodeName has sync enabled alongside a configured
// hasyncd endpoint and HMAC secret.
func (m *Manager) IsRemoteEditable(ctx context.Context, nodeName string) (bool, error) {
	if m.store == nil || strings.TrimSpace(nodeName) == "" {
		return false, nil
	}
	cred, err := m.store.GetCredentialByName(ctx, strings.TrimSpace(nodeName))
	if err != nil {
		if errors.Is(err, ErrNodeNotFound) {
			return false, nil
		}
		return false, err
	}
	return cred.SyncEnabled && strings.TrimSpace(cred.SyncAgentAddr) != "" && strings.TrimSpace(cred.SyncSecretCiphertext) != "", nil
}

// GetNodeNetworkStatus returns the converged remote network-status.json snapshot for nodeName.
func (m *Manager) GetNodeNetworkStatus(ctx context.Context, nodeName string) (json.RawMessage, error) {
	if m.store == nil || strings.TrimSpace(nodeName) == "" {
		return nil, nil
	}
	cred, err := m.store.GetCredentialByName(ctx, strings.TrimSpace(nodeName))
	if err != nil {
		if errors.Is(err, ErrNodeNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return cred.NetworkStatus, nil
}

// ListRemoteEditableNodes returns node names that have sync enabled plus both sync_agent_addr
// and sync_secret configured (excluding localNodeName).
func (m *Manager) ListRemoteEditableNodes(ctx context.Context) ([]string, error) {
	if m.store == nil {
		return nil, nil
	}
	creds, err := m.store.ListSyncAgentNodes(ctx)
	if err != nil {
		return nil, err
	}
	local := strings.TrimSpace(m.cfg.LocalNodeName)
	out := make([]string, 0, len(creds))
	for _, c := range creds {
		if c.NodeName == "" || (local != "" && c.NodeName == local) {
			continue
		}
		if c.SyncEnabled && strings.TrimSpace(c.SyncAgentAddr) != "" && strings.TrimSpace(c.SyncSecretCiphertext) != "" {
			out = append(out, c.NodeName)
		}
	}
	return out, nil
}

// ---------- Health Probe & Remote Upgrade Primitives ----------

// ProbeNodeHealth calls GET /v1/health on a node's hasyncd agent and measures round-trip latency.
func (m *Manager) ProbeNodeHealth(ctx context.Context, nodeID uuid.UUID) (*HealthResponse, int64, error) {
	start := m.now()
	cli, _, err := m.ClientForNodeID(ctx, nodeID)
	if err != nil {
		return nil, m.now().Sub(start).Milliseconds(), err
	}
	resp, err := cli.Health(ctx)
	latency := m.now().Sub(start).Milliseconds()
	if latency < 0 {
		latency = 0
	}
	if err != nil {
		return nil, latency, err
	}
	return resp, latency, nil
}

// UploadUpgradePackage streams a local upgrade package to a remote node via hasyncd
// and verifies the returned SHA-256 digest when expectedSHA256 is non-empty.
func (m *Manager) UploadUpgradePackage(ctx context.Context, nodeID uuid.UUID, filePath, remoteFilename, expectedSHA256 string) (*UpgradePackageUploadResponse, error) {
	cli, cred, err := m.ClientForNodeID(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	resp, err := cli.UploadUpgradePackage(ctx, filePath, remoteFilename)
	if err != nil {
		return nil, fmt.Errorf("上传升级包到节点 %s 失败: %w", cred.NodeName, err)
	}
	if exp := strings.ToLower(strings.TrimSpace(expectedSHA256)); exp != "" && resp != nil {
		if !strings.EqualFold(strings.TrimSpace(resp.SHA256), exp) {
			return nil, fmt.Errorf("节点 %s 接收升级包校验和不匹配: got=%s want=%s", cred.NodeName, resp.SHA256, exp)
		}
	}
	return resp, nil
}

// ExecuteUpgrade dispatches a remote upgrade execution request to hasyncd POST /v1/upgrades/execute.
func (m *Manager) ExecuteUpgrade(ctx context.Context, nodeID uuid.UUID, req UpgradeExecuteRequest) (*UpgradeExecuteResponse, error) {
	cli, cred, err := m.ClientForNodeID(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	resp, err := cli.ExecuteUpgrade(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("下发节点 %s 升级指令失败: %w", cred.NodeName, err)
	}
	return resp, nil
}

// GetUpgradeJobResult polls a remote upgrade job result via hasyncd GET /v1/upgrades/jobs/{job_id}.
func (m *Manager) GetUpgradeJobResult(ctx context.Context, nodeID uuid.UUID, jobID string) (*UpgradeJobResult, error) {
	cli, cred, err := m.ClientForNodeID(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	resp, err := cli.GetUpgradeJobResult(ctx, jobID)
	if err != nil {
		return nil, fmt.Errorf("查询节点 %s 升级结果失败: %w", cred.NodeName, err)
	}
	return resp, nil
}
