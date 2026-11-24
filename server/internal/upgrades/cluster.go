// cluster.go HA 集群滚动升级（先备后主）：节点协同接口、双机预检、备节点顺序编排与单节点重试。
package upgrades

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/backups"
)

const (
	defaultStandbyVerifyWait = 5 * time.Minute
	defaultNodeProbeTimeout  = 5 * time.Second
)

// ClusterNode 表示可用于 HA 集群滚动升级的已登记网关节点。
type ClusterNode struct {
	NodeID          uuid.UUID `json:"node_id"`
	NodeName        string    `json:"node_name"`
	SyncAgentAddr   string    `json:"sync_agent_addr"`
	ReportedVersion string    `json:"reported_version"`
	SyncEnabled     bool      `json:"sync_enabled"`
}

// ClusterNodeHealth 表示远端 hasyncd GET /v1/health 的实时健康状态。
type ClusterNodeHealth struct {
	Node           string `json:"node"`
	Version        string `json:"version"`
	CaddyReachable bool   `json:"caddy_reachable"`
	HostctlReady   bool   `json:"hostctl_ready"`
	UpgradeReady   bool   `json:"upgrade_ready"`
}

// ClusterSyncClient 抽象 HA 集群滚动升级所需的跨节点协同能力（由 nodesync.Manager 实现）。
type ClusterSyncClient interface {
	ListClusterNodes(ctx context.Context) ([]ClusterNode, error)
	HasOpenSplitBrain(ctx context.Context) (bool, error)
	CheckNodeHealth(ctx context.Context, nodeID uuid.UUID) (*ClusterNodeHealth, error)
	UploadPackage(ctx context.Context, nodeID uuid.UUID, filePath, fileName, sha256Hex string) error
	StartRemoteUpgrade(ctx context.Context, nodeID uuid.UUID, req ExecutorRequest) error
	PollRemoteResult(ctx context.Context, nodeID uuid.UUID, jobID string) (*ExecutorResult, bool, error)
}

// ClusterNodeStatusItem 为 GET /api/v1/upgrades/nodes 返回的单节点版本与就绪状态。
type ClusterNodeStatusItem struct {
	NodeID          uuid.UUID `json:"node_id"`
	NodeName        string    `json:"node_name"`
	Role            string    `json:"role"`
	SyncAgentAddr   string    `json:"sync_agent_addr"`
	SyncEnabled     bool      `json:"sync_enabled"`
	ReportedVersion string    `json:"reported_version"`
	VersionAligned  bool      `json:"version_aligned"`
	Reachable       bool      `json:"reachable"`
	CaddyReachable  bool      `json:"caddy_reachable"`
	HostctlReady    bool      `json:"hostctl_ready"`
	UpgradeReady    bool      `json:"upgrade_ready"`
	Error           string    `json:"error,omitempty"`
}

// ClusterNodesResponse 为 GET /api/v1/upgrades/nodes 响应载体。
type ClusterNodesResponse struct {
	Items          []ClusterNodeStatusItem `json:"items"`
	CurrentVersion string                  `json:"current_version"`
	SplitBrain     bool                    `json:"split_brain"`
	ClusterReady   bool                    `json:"cluster_ready"`
}

// clusterRepo 是滚动升级编排所需的最小仓储接口（*Store 天然实现，单测可注入内存实现）。
type clusterRepo interface {
	GetPackage(ctx context.Context, id uuid.UUID) (*Package, error)
	GetJob(ctx context.Context, id uuid.UUID) (*Job, error)
	HasActiveJob(ctx context.Context) (bool, error)
	CreateJobWithModeIfNoActive(ctx context.Context, packageID uuid.UUID, requestedBy *uuid.UUID, requestID, clusterMode string) (*Job, error)
	CreateScheduledJobWithModeIfNoActive(ctx context.Context, packageID uuid.UUID, requestedBy *uuid.UUID, requestID string, scheduledAt time.Time, clusterMode string) (*Job, error)
	Transition(ctx context.Context, id uuid.UUID, from, to string) error
	SetPrecheck(ctx context.Context, id uuid.UUID, items []CheckItem) error
	SetBackupJob(ctx context.Context, id, backupJobID uuid.UUID) error
	SetExecutorDeadline(ctx context.Context, id uuid.UUID, deadline time.Time) error
	MarkFailed(ctx context.Context, id uuid.UUID, code string, err error) error
	MarkFinished(ctx context.Context, id uuid.UUID, status string) error
	CreateNodeExecutions(ctx context.Context, execs []NodeExecution) ([]NodeExecution, error)
	ListNodeExecutions(ctx context.Context, jobID uuid.UUID) ([]NodeExecution, error)
	GetNodeExecution(ctx context.Context, jobID, nodeID uuid.UUID) (*NodeExecution, error)
	UpdateNodeExecutionStatus(ctx context.Context, id uuid.UUID, status, errorCode, errorMessage string, setStarted, setFinished bool) error
	ResetNodeExecutionForRetry(ctx context.Context, id uuid.UUID, initialStatus string) error
	MarkPrimaryNodeExecution(ctx context.Context, jobID uuid.UUID, status, errorCode, errorMessage string) error
}

// primaryNodeMarker 允许 executor 结果处理/对账在重启后同步更新 PRIMARY 节点明细状态。
type primaryNodeMarker interface {
	MarkPrimaryNodeExecution(ctx context.Context, jobID uuid.UUID, status, errorCode, errorMessage string) error
}

// SetClusterSyncClient 注入 HA 集群滚动升级节点协同客户端。
func (s *Service) SetClusterSyncClient(c ClusterSyncClient) *Service {
	s.clusterClient = c
	return s
}

// SetLocalNodeName 注入本机（主节点）名称，用于在节点清单中区分 PRIMARY 与 STANDBY。
func (s *Service) SetLocalNodeName(name string) *Service {
	s.localNodeName = strings.TrimSpace(name)
	return s
}

// SetStandbyVerifyWait 覆盖备节点升级后健康/版本验证等待上限（测试用）。
func (s *Service) SetStandbyVerifyWait(d time.Duration) *Service {
	if d > 0 {
		s.standbyVerifyWait = d
	}
	return s
}

func (s *Service) clusterStoreRepo() clusterRepo {
	if s.clusterStore != nil {
		return s.clusterStore
	}
	if s.store != nil {
		return s.store
	}
	return nil
}

func (s *Service) standbyVerifyTimeout() time.Duration {
	if s.standbyVerifyWait > 0 {
		return s.standbyVerifyWait
	}
	return defaultStandbyVerifyWait
}

func (s *Service) currentSystemVersion(ctx context.Context) string {
	if s.prechecker != nil {
		return s.prechecker.currentSystemVersion(ctx)
	}
	return CurrentVersion
}

func (s *Service) isLocalNode(nodeName string) bool {
	return s.localNodeName != "" && strings.EqualFold(strings.TrimSpace(nodeName), s.localNodeName)
}

func (s *Service) filterEligibleStandbys(nodes []ClusterNode) []ClusterNode {
	standbys := make([]ClusterNode, 0, len(nodes))
	for _, n := range nodes {
		if s.isLocalNode(n.NodeName) {
			continue
		}
		if !n.SyncEnabled || strings.TrimSpace(n.SyncAgentAddr) == "" {
			continue
		}
		standbys = append(standbys, n)
	}
	sort.Slice(standbys, func(i, j int) bool {
		if standbys[i].NodeName != standbys[j].NodeName {
			return standbys[i].NodeName < standbys[j].NodeName
		}
		return standbys[i].NodeID.String() < standbys[j].NodeID.String()
	})
	return standbys
}

func versionsEqual(a, b string) bool {
	va, errA := ParseVersion(a)
	vb, errB := ParseVersion(b)
	if errA != nil || errB != nil {
		return false
	}
	return va.Compare(vb) == 0
}

// RunPrecheckWithMode 按指定集群模式（LOCAL / HA_ROLLING）执行升级前检查。
func (s *Service) RunPrecheckWithMode(ctx context.Context, packageID uuid.UUID, clusterMode string) ([]CheckItem, error) {
	mode, err := NormalizeClusterMode(clusterMode)
	if err != nil {
		return nil, err
	}
	repo := s.clusterStoreRepo()
	if repo == nil {
		return nil, errors.New("升级任务存储未配置")
	}
	pkg, err := repo.GetPackage(ctx, packageID)
	if err != nil {
		return nil, err
	}
	var items []CheckItem
	if s.precheckLocalFn != nil {
		items = s.precheckLocalFn(ctx, pkg)
	} else {
		facts := s.prechecker.Gather(ctx, pkg)
		items = Evaluate(facts)
	}
	if mode != ClusterModeHARolling {
		return items, nil
	}
	items = append(items, s.evaluateClusterPrecheck(ctx, pkg)...)
	return items, nil
}

func (s *Service) evaluateClusterPrecheck(ctx context.Context, pkg *Package) []CheckItem {
	if s.clusterClient == nil {
		return []CheckItem{{
			Name:    "cluster_sync_configured",
			Result:  CheckFail,
			Message: "未配置集群节点协同通道（hasyncd），无法执行 HA 集群滚动升级",
		}}
	}

	items := make([]CheckItem, 0, 4)

	// 1. 脑裂强门禁：存在未解决的 HA_SPLIT_BRAIN 告警时一律阻断滚动升级。
	splitBrain, err := s.clusterClient.HasOpenSplitBrain(ctx)
	switch {
	case err != nil:
		items = append(items, CheckItem{
			Name:    "cluster_split_brain",
			Result:  CheckFail,
			Message: "检查主备脑裂告警状态失败（保守阻断）：" + truncate(err.Error(), 240),
		})
	case splitBrain:
		items = append(items, CheckItem{
			Name:    "cluster_split_brain",
			Result:  CheckFail,
			Message: "存在未处置的主备双主脑裂告警（HA_SPLIT_BRAIN），必须先解决脑裂后再执行集群滚动升级",
		})
	default:
		items = append(items, CheckItem{
			Name:    "cluster_split_brain",
			Result:  CheckPass,
			Message: "无未处置的主备脑裂告警",
		})
	}

	// 2. 枚举并逐台检查已启用同步的备节点。
	nodes, err := s.clusterClient.ListClusterNodes(ctx)
	if err != nil {
		items = append(items, CheckItem{
			Name:    "cluster_standby_nodes",
			Result:  CheckFail,
			Message: "查询集群节点列表失败：" + truncate(err.Error(), 240),
		})
		return items
	}
	standbys := s.filterEligibleStandbys(nodes)
	if len(standbys) == 0 {
		items = append(items, CheckItem{
			Name:    "cluster_standby_nodes",
			Result:  CheckFail,
			Message: "未发现已启用协同同步（sync_enabled + sync_agent_addr）的备节点，请选择单机升级或先配置备节点协同代理",
		})
		return items
	}
	items = append(items, CheckItem{
		Name:    "cluster_standby_nodes",
		Result:  CheckPass,
		Message: fmt.Sprintf("发现 %d 台待滚动升级的备节点", len(standbys)),
	})

	// 并发探测备节点健康与版本兼容性，结果按节点名保序输出。
	nodeChecks := make([]CheckItem, len(standbys))
	var wg sync.WaitGroup
	for i, node := range standbys {
		wg.Add(1)
		go func(idx int, n ClusterNode) {
			defer wg.Done()
			nodeChecks[idx] = s.checkStandbyPrecheckNode(ctx, n, pkg)
		}(i, node)
	}
	wg.Wait()
	items = append(items, nodeChecks...)
	return items
}

func (s *Service) checkStandbyPrecheckNode(ctx context.Context, node ClusterNode, pkg *Package) CheckItem {
	it := CheckItem{Name: "cluster_node_" + node.NodeName}
	probeCtx, cancel := context.WithTimeout(ctx, defaultNodeProbeTimeout)
	defer cancel()

	health, err := s.clusterClient.CheckNodeHealth(probeCtx, node.NodeID)
	if err != nil {
		it.Result = CheckFail
		it.Message = fmt.Sprintf("备节点 %s 协同代理不可达：%s", node.NodeName, truncate(err.Error(), 240))
		return it
	}
	if health == nil {
		it.Result = CheckFail
		it.Message = fmt.Sprintf("备节点 %s 健康探针返回空结果", node.NodeName)
		return it
	}
	if !health.UpgradeReady {
		it.Result = CheckFail
		it.Message = fmt.Sprintf("备节点 %s 升级执行器目录未就绪（upgrade_ready=false）", node.NodeName)
		return it
	}
	if !health.CaddyReachable {
		it.Result = CheckFail
		it.Message = fmt.Sprintf("备节点 %s 防护网关不可达（caddy_reachable=false），无法安全承接主节点升级期间流量", node.NodeName)
		return it
	}

	nodeVer := strings.TrimSpace(health.Version)
	if nodeVer == "" || strings.EqualFold(nodeVer, "unknown") {
		nodeVer = strings.TrimSpace(node.ReportedVersion)
	}
	fromVer, fromErr := ParseVersion(pkg.VersionFrom)
	curVer, curErr := ParseVersion(nodeVer)
	if fromErr != nil {
		it.Result = CheckFail
		it.Message = fmt.Sprintf("升级包起始版本号无效：%s", pkg.VersionFrom)
		return it
	}
	if curErr != nil {
		it.Result = CheckFail
		it.Message = fmt.Sprintf("备节点 %s 当前版本 %q 无法解析，与升级包起始版本 %s 不兼容", node.NodeName, nodeVer, fromVer)
		return it
	}
	if curVer.Compare(fromVer) != 0 {
		it.Result = CheckFail
		it.Message = fmt.Sprintf("备节点 %s 当前版本 %s 与升级包要求起始版本 %s 不匹配", node.NodeName, curVer, fromVer)
		return it
	}

	it.Result = CheckPass
	it.Message = fmt.Sprintf("备节点 %s 就绪（版本 %s -> %s，网关与执行器正常）", node.NodeName, curVer, pkg.VersionTo)
	return it
}

// ListClusterNodeStatuses 聚合主备节点当前版本、对齐状态与协同通道就绪态（GET /api/v1/upgrades/nodes）。
func (s *Service) ListClusterNodeStatuses(ctx context.Context) (*ClusterNodesResponse, error) {
	curVer := s.currentSystemVersion(ctx)
	resp := &ClusterNodesResponse{
		Items:          make([]ClusterNodeStatusItem, 0),
		CurrentVersion: curVer,
		SplitBrain:     false,
		ClusterReady:   false,
	}
	if s.clusterClient == nil {
		return resp, nil
	}

	splitBrain, err := s.clusterClient.HasOpenSplitBrain(ctx)
	if err != nil {
		// 查询脑裂状态失败保守视为未就绪
		slog.Warn("check split-brain status for upgrade nodes failed", "error", err)
		splitBrain = true
	}
	resp.SplitBrain = splitBrain

	nodes, err := s.clusterClient.ListClusterNodes(ctx)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return resp, nil
	}

	sorted := append([]ClusterNode(nil), nodes...)
	sort.Slice(sorted, func(i, j int) bool {
		iPrimary := s.isLocalNode(sorted[i].NodeName)
		jPrimary := s.isLocalNode(sorted[j].NodeName)
		if iPrimary != jPrimary {
			return iPrimary
		}
		return sorted[i].NodeName < sorted[j].NodeName
	})

	items := make([]ClusterNodeStatusItem, len(sorted))
	var wg sync.WaitGroup
	for i, n := range sorted {
		role := NodeRoleStandby
		if s.isLocalNode(n.NodeName) {
			role = NodeRolePrimary
		}
		if role == NodeRolePrimary {
			items[i] = ClusterNodeStatusItem{
				NodeID:          n.NodeID,
				NodeName:        n.NodeName,
				Role:            NodeRolePrimary,
				SyncAgentAddr:   n.SyncAgentAddr,
				SyncEnabled:     n.SyncEnabled,
				ReportedVersion: curVer,
				VersionAligned:  true,
				Reachable:       true,
				CaddyReachable:  true,
				HostctlReady:    true,
				UpgradeReady:    s.executorDir != "" && s.packagesDir != "",
			}
			continue
		}
		item := ClusterNodeStatusItem{
			NodeID:          n.NodeID,
			NodeName:        n.NodeName,
			Role:            NodeRoleStandby,
			SyncAgentAddr:   n.SyncAgentAddr,
			SyncEnabled:     n.SyncEnabled,
			ReportedVersion: strings.TrimSpace(n.ReportedVersion),
		}
		if !n.SyncEnabled || strings.TrimSpace(n.SyncAgentAddr) == "" {
			item.VersionAligned = versionsEqual(item.ReportedVersion, curVer)
			items[i] = item
			continue
		}
		wg.Add(1)
		go func(idx int, node ClusterNode, base ClusterNodeStatusItem) {
			defer wg.Done()
			probeCtx, cancel := context.WithTimeout(ctx, defaultNodeProbeTimeout)
			defer cancel()
			health, herr := s.clusterClient.CheckNodeHealth(probeCtx, node.NodeID)
			if herr != nil {
				base.Reachable = false
				base.Error = truncate(herr.Error(), 240)
				base.VersionAligned = versionsEqual(base.ReportedVersion, curVer)
				items[idx] = base
				return
			}
			if health != nil {
				base.Reachable = true
				base.CaddyReachable = health.CaddyReachable
				base.HostctlReady = health.HostctlReady
				base.UpgradeReady = health.UpgradeReady
				if v := strings.TrimSpace(health.Version); v != "" && !strings.EqualFold(v, "unknown") {
					base.ReportedVersion = v
				}
			}
			base.VersionAligned = versionsEqual(base.ReportedVersion, curVer)
			items[idx] = base
		}(i, n, item)
	}
	wg.Wait()

	resp.Items = items
	standbyEligible := 0
	allStandbyReady := true
	for _, it := range items {
		if it.Role != NodeRoleStandby {
			continue
		}
		if !it.SyncEnabled || strings.TrimSpace(it.SyncAgentAddr) == "" {
			continue
		}
		standbyEligible++
		if !it.Reachable || !it.UpgradeReady || !it.CaddyReachable {
			allStandbyReady = false
		}
	}
	resp.ClusterReady = !resp.SplitBrain && standbyEligible > 0 && allStandbyReady
	return resp, nil
}

// ExecuteWithMode 按指定集群模式创建并异步执行升级任务（LOCAL 保持原有单机行为，HA_ROLLING 执行先备后主滚动升级）。
func (s *Service) ExecuteWithMode(ctx context.Context, packageID, requestedBy uuid.UUID, requestID, clusterMode string) (*Job, error) {
	mode, err := NormalizeClusterMode(clusterMode)
	if err != nil {
		return nil, err
	}
	repo := s.clusterStoreRepo()
	if repo == nil {
		return nil, errors.New("升级任务存储未配置")
	}
	pkg, err := repo.GetPackage(ctx, packageID)
	if err != nil {
		return nil, err
	}
	if pkg.Status != PackageVerified {
		return nil, ErrPackageNotVerified
	}
	job, err := repo.CreateJobWithModeIfNoActive(ctx, packageID, &requestedBy, requestID, mode)
	if err != nil {
		return nil, err
	}
	s.startRun(job.ID)
	return job, nil
}

// ScheduleWithMode 按指定集群模式创建定时升级任务（SCHEDULED）。
func (s *Service) ScheduleWithMode(ctx context.Context, packageID, requestedBy uuid.UUID, requestID string, scheduledAt time.Time, clusterMode string) (*Job, error) {
	mode, err := NormalizeClusterMode(clusterMode)
	if err != nil {
		return nil, err
	}
	if mode == ClusterModeLocal && s.schedStore != nil {
		return s.Schedule(ctx, packageID, requestedBy, requestID, scheduledAt)
	}
	repo := s.clusterStoreRepo()
	if repo == nil {
		return nil, errors.New("升级任务存储未配置")
	}
	pkg, err := repo.GetPackage(ctx, packageID)
	if err != nil {
		return nil, err
	}
	if pkg.Status != PackageVerified {
		return nil, ErrPackageNotVerified
	}
	return repo.CreateScheduledJobWithModeIfNoActive(ctx, packageID, &requestedBy, requestID, scheduledAt.UTC(), mode)
}

type standbyFailureError struct {
	code     string
	nodeName string
	err      error
}

func (e *standbyFailureError) Error() string {
	return fmt.Sprintf("备节点 %s 升级失败：%v", e.nodeName, e.err)
}

func (e *standbyFailureError) Unwrap() error { return e.err }

func (s *Service) verifyLocalArtifact(pkg *Package) (string, error) {
	if s.packagesDir == "" {
		return "", errors.New("升级包存储目录未配置")
	}
	if err := validatePackageFileName(pkg.FileName); err != nil {
		return "", fmt.Errorf("升级包文件名无效: %w", err)
	}
	if len(pkg.FileHash) != 64 {
		return "", errors.New("升级包 SHA-256 无效")
	}
	packagePath := filepath.Join(s.packagesDir, pkg.FileName)
	if _, err := os.Stat(packagePath); err != nil {
		return "", fmt.Errorf("升级包文件不可用: %w", err)
	}
	if s.prechecker != nil {
		if err := s.prechecker.VerifyArtifact(packagePath, pkg); err != nil {
			return "", fmt.Errorf("升级包固定信任根验证失败: %w", err)
		}
	} else if err := verifyPackageArtifact(packagePath, pkg); err != nil {
		return "", fmt.Errorf("升级包固定信任根验证失败: %w", err)
	}
	return packagePath, nil
}

// runClusterStandbys 在 HA_ROLLING 模式下执行全部备节点的顺序升级；
// 任一备节点失败即标记该节点 FAILED、其余 PENDING 节点（含主节点）为 SKIPPED，
// 返回 standbyFailureError，由调用方标记任务 FAILED 并立即中止，绝不触碰主节点。
func (s *Service) runClusterStandbys(ctx context.Context, job *Job) (*NodeExecution, error) {
	repo := s.clusterStoreRepo()
	if s.clusterClient == nil {
		return nil, &standbyFailureError{
			code:     FailStandbyUpgrade,
			nodeName: "cluster",
			err:      ErrClusterSyncNotConfigured,
		}
	}
	pkg, err := repo.GetPackage(ctx, *job.PackageID)
	if err != nil {
		return nil, &standbyFailureError{code: FailStandbyUpgrade, nodeName: "cluster", err: err}
	}

	// 推送到任何备节点之前，再次通过固定信任根复验本地升级包归档与签名。
	packagePath, err := s.verifyLocalArtifact(pkg)
	if err != nil {
		return nil, &standbyFailureError{code: FailApply, nodeName: "primary-verify", err: err}
	}

	allNodes, err := s.clusterClient.ListClusterNodes(ctx)
	if err != nil {
		return nil, &standbyFailureError{code: FailStandbyUpgrade, nodeName: "cluster", err: fmt.Errorf("查询集群节点失败: %w", err)}
	}
	standbys := s.filterEligibleStandbys(allNodes)
	if len(standbys) == 0 {
		return nil, &standbyFailureError{code: FailStandbyUpgrade, nodeName: "cluster", err: errors.New("未发现可用的同步备节点")}
	}

	// 构造 upgrade_node_executions 计划：备节点 seq=1..N，主节点 seq=N+1。
	plan := make([]NodeExecution, 0, len(standbys)+1)
	for i, n := range standbys {
		nid := n.NodeID
		fromVer := strings.TrimSpace(n.ReportedVersion)
		if fromVer == "" {
			fromVer = pkg.VersionFrom
		}
		plan = append(plan, NodeExecution{
			JobID:       job.ID,
			NodeID:      &nid,
			NodeName:    n.NodeName,
			Role:        NodeRoleStandby,
			Seq:         i + 1,
			Status:      NodeStatusPending,
			FromVersion: fromVer,
			ToVersion:   pkg.VersionTo,
		})
	}
	primaryName := s.localNodeName
	if primaryName == "" {
		primaryName = "primary"
	}
	var primaryNodeID *uuid.UUID
	for _, n := range allNodes {
		if s.isLocalNode(n.NodeName) {
			nid := n.NodeID
			primaryNodeID = &nid
			break
		}
	}
	plan = append(plan, NodeExecution{
		JobID:       job.ID,
		NodeID:      primaryNodeID,
		NodeName:    primaryName,
		Role:        NodeRolePrimary,
		Seq:         len(standbys) + 1,
		Status:      NodeStatusPending,
		FromVersion: s.currentSystemVersion(ctx),
		ToVersion:   pkg.VersionTo,
	})

	created, err := repo.CreateNodeExecutions(ctx, plan)
	if err != nil {
		return nil, &standbyFailureError{code: FailStandbyUpgrade, nodeName: "cluster", err: fmt.Errorf("创建节点执行计划失败: %w", err)}
	}
	if len(created) < 2 {
		return nil, &standbyFailureError{code: FailStandbyUpgrade, nodeName: "cluster", err: errors.New("节点执行计划不完整")}
	}
	standbyRows := created[:len(created)-1]
	primaryRow := &created[len(created)-1]

	// 逐台串行升级备节点；任一台失败立即止损。
	for i := range standbyRows {
		row := &standbyRows[i]
		code, stepErr := s.executeStandbyNode(ctx, job.ID.String(), row, pkg, packagePath)
		if stepErr != nil {
			if code == "" {
				code = FailStandbyUpgrade
			}
			_ = repo.UpdateNodeExecutionStatus(context.Background(), row.ID, NodeStatusFailed, code, stepErr.Error(), true, true)
			skipMsg := fmt.Sprintf("前置备节点 %s 升级失败，已中止集群滚动升级", row.NodeName)
			for j := i + 1; j < len(standbyRows); j++ {
				_ = repo.UpdateNodeExecutionStatus(context.Background(), standbyRows[j].ID, NodeStatusSkipped, "", skipMsg, false, true)
			}
			_ = repo.UpdateNodeExecutionStatus(context.Background(), primaryRow.ID, NodeStatusSkipped, "", skipMsg, false, true)
			return nil, &standbyFailureError{code: FailStandbyUpgrade, nodeName: row.NodeName, err: stepErr}
		}
	}

	// 全部备节点验证通过，标记主节点进入 APPLYING。
	if err := repo.UpdateNodeExecutionStatus(ctx, primaryRow.ID, NodeStatusApplying, "", "", true, false); err != nil {
		slog.Warn("mark primary node execution applying failed", "job_id", job.ID, "error", err)
	}
	return primaryRow, nil
}

// executeStandbyNode 对单台备节点执行完整的 TRANSFERRING → APPLYING → VERIFYING → SUCCESS 流程。
func (s *Service) executeStandbyNode(ctx context.Context, remoteJobID string, row *NodeExecution, pkg *Package, packagePath string) (string, error) {
	repo := s.clusterStoreRepo()
	if row.NodeID == nil {
		return FailStandbyUpgrade, fmt.Errorf("备节点 %s 缺少 node_id", row.NodeName)
	}
	nodeID := *row.NodeID
	shaHex := strings.ToLower(strings.TrimSpace(pkg.FileHash))

	// 1. TRANSFERRING：流式上传升级包到备机 hasyncd
	if err := repo.UpdateNodeExecutionStatus(ctx, row.ID, NodeStatusTransferring, "", "", true, false); err != nil {
		return FailStandbyUpgrade, fmt.Errorf("更新节点传输状态失败: %w", err)
	}
	if err := s.clusterClient.UploadPackage(ctx, nodeID, packagePath, pkg.FileName, shaHex); err != nil {
		return FailStandbyUpgrade, fmt.Errorf("推送升级包失败: %w", err)
	}

	// 2. APPLYING：触发备机执行器并轮询终态结果
	if err := repo.UpdateNodeExecutionStatus(ctx, row.ID, NodeStatusApplying, "", "", false, false); err != nil {
		return FailStandbyUpgrade, fmt.Errorf("更新节点执行状态失败: %w", err)
	}
	execReq := ExecutorRequest{
		JobID:         remoteJobID,
		PackageFile:   pkg.FileName,
		PackageSHA256: shaHex,
		VersionFrom:   pkg.VersionFrom,
		VersionTo:     pkg.VersionTo,
		RequestedAt:   s.nowFn().UTC(),
	}
	if err := s.clusterClient.StartRemoteUpgrade(ctx, nodeID, execReq); err != nil {
		return FailStandbyUpgrade, fmt.Errorf("触发备节点执行器失败: %w", err)
	}
	res, err := s.waitRemoteExecutorResult(ctx, nodeID, remoteJobID)
	if err != nil {
		return FailExecutorTimeout, err
	}
	if res.Status != "SUCCESS" {
		code := strings.TrimSpace(res.ErrorCode)
		if code == "" {
			code = FailApply
		}
		msg := strings.TrimSpace(res.Message)
		if msg == "" {
			msg = "备节点宿主机执行器返回 FAILED"
		}
		return code, fmt.Errorf("备节点执行失败（%s）：%s", code, msg)
	}

	// 3. VERIFYING：轮询备机 /v1/health 直到网关可达且上报版本已切换为 version_to
	if err := repo.UpdateNodeExecutionStatus(ctx, row.ID, NodeStatusVerifying, "", "", false, false); err != nil {
		return FailVerify, fmt.Errorf("更新节点验证状态失败: %w", err)
	}
	if err := s.waitStandbyHealthyVersion(ctx, nodeID, pkg.VersionTo); err != nil {
		return FailVerify, err
	}

	// 4. SUCCESS
	if err := repo.UpdateNodeExecutionStatus(ctx, row.ID, NodeStatusSuccess, "", "", false, true); err != nil {
		return FailVerify, fmt.Errorf("更新节点成功状态失败: %w", err)
	}
	return "", nil
}

func (s *Service) waitRemoteExecutorResult(ctx context.Context, nodeID uuid.UUID, remoteJobID string) (*ExecutorResult, error) {
	wait := s.executorWait
	if wait <= 0 {
		wait = defaultExecutorWait
	}
	poll := s.poll
	if poll <= 0 {
		poll = defaultPoll
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	ticker := time.NewTicker(poll)
	defer ticker.Stop()

	for {
		res, done, err := s.clusterClient.PollRemoteResult(ctx, nodeID, remoteJobID)
		if err != nil {
			// 升级重启期间 hasyncd 瞬时不可达属于预期，继续等待直到超时或 ctx 取消
			slog.Debug("poll remote upgrade result transient error", "node_id", nodeID, "job_id", remoteJobID, "error", err)
		} else if done {
			if res == nil {
				return nil, errors.New("备节点执行器返回空结果")
			}
			return res, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, errors.New("等待备节点宿主机升级执行器终态结果超时")
		case <-ticker.C:
		}
	}
}

func (s *Service) waitStandbyHealthyVersion(ctx context.Context, nodeID uuid.UUID, wantVersion string) error {
	wait := s.standbyVerifyTimeout()
	poll := s.poll
	if poll <= 0 {
		poll = defaultPoll
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	ticker := time.NewTicker(poll)
	defer ticker.Stop()

	var lastDiag string
	for {
		probeCtx, cancel := context.WithTimeout(ctx, defaultNodeProbeTimeout)
		health, err := s.clusterClient.CheckNodeHealth(probeCtx, nodeID)
		cancel()
		if err == nil && health != nil {
			if health.CaddyReachable && versionsEqual(health.Version, wantVersion) {
				return nil
			}
			lastDiag = fmt.Sprintf("caddy_reachable=%v, version=%q (期望 %s)", health.CaddyReachable, health.Version, wantVersion)
		} else if err != nil {
			lastDiag = err.Error()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("备节点升级后健康或版本验证超时（最近状态：%s）", lastDiag)
		case <-ticker.C:
		}
	}
}

// RetryNodeUpgrade 在修复故障备节点后，对单台 FAILED/SKIPPED 备节点重新执行上传、升级与验证。
func (s *Service) RetryNodeUpgrade(ctx context.Context, jobID, nodeID, requestedBy uuid.UUID, requestID string) (*NodeExecution, error) {
	if s.clusterClient == nil {
		return nil, ErrClusterSyncNotConfigured
	}
	repo := s.clusterStoreRepo()
	if repo == nil {
		return nil, errors.New("升级任务存储未配置")
	}

	// 不允许在有活跃升级任务运行时并发重试单节点。
	active, err := repo.HasActiveJob(ctx)
	if err != nil {
		return nil, err
	}
	if active {
		return nil, ErrActiveUpgrade
	}

	job, err := repo.GetJob(ctx, jobID)
	if err != nil {
		return nil, err
	}
	if !TerminalStatus(job.Status) {
		return nil, ErrActiveUpgrade
	}
	if job.ClusterMode != ClusterModeHARolling {
		return nil, fmt.Errorf("%w: 仅 HA_ROLLING 集群升级任务支持单节点重试", ErrInvalidStatus)
	}
	if job.PackageID == nil {
		return nil, fmt.Errorf("%w: 任务未关联升级包", ErrInvalidInput)
	}

	execRow, err := repo.GetNodeExecution(ctx, jobID, nodeID)
	if err != nil {
		return nil, err
	}
	if execRow.Role != NodeRoleStandby {
		return nil, fmt.Errorf("%w: 仅备节点（STANDBY）支持单节点补升重试", ErrInvalidStatus)
	}
	if execRow.Status != NodeStatusFailed && execRow.Status != NodeStatusSkipped {
		return nil, fmt.Errorf("%w: 仅 FAILED 或 SKIPPED 状态的备节点支持重试（当前 %s）", ErrInvalidStatus, execRow.Status)
	}

	// 脑裂守卫：存在未解决脑裂时同样拒绝单节点补升。
	splitBrain, err := s.clusterClient.HasOpenSplitBrain(ctx)
	if err != nil {
		return nil, fmt.Errorf("检查主备脑裂状态失败: %w", err)
	}
	if splitBrain {
		return nil, fmt.Errorf("%w: 存在未处置的主备脑裂告警，请先解决脑裂后再重试", ErrClusterSplitBrain)
	}

	pkg, err := repo.GetPackage(ctx, *job.PackageID)
	if err != nil {
		return nil, err
	}
	packagePath, err := s.verifyLocalArtifact(pkg)
	if err != nil {
		return nil, err
	}

	// 同步重置为 TRANSFERRING 防止并发重复点击，并立即返回更新后的明细。
	if err := repo.ResetNodeExecutionForRetry(ctx, execRow.ID, NodeStatusTransferring); err != nil {
		return nil, err
	}
	updated, err := repo.GetNodeExecution(ctx, jobID, nodeID)
	if err != nil {
		updated = execRow
		updated.Status = NodeStatusTransferring
		updated.ErrorCode = ""
		updated.ErrorMessage = ""
		updated.FinishedAt = nil
	}

	// 远端重试使用全新执行 UUID，避免与备机旧 results/<job_id>.json 冲突。
	remoteRetryID := uuid.New().String()
	rowCopy := *updated
	pkgCopy := *pkg
	runRetry := func() {
		rctx, cancel := context.WithTimeout(context.Background(), s.executorWait+s.standbyVerifyTimeout()+5*time.Minute)
		defer cancel()
		code, stepErr := s.executeStandbyNode(rctx, remoteRetryID, &rowCopy, &pkgCopy, packagePath)
		if stepErr != nil {
			if code == "" {
				code = FailStandbyUpgrade
			}
			slog.Error("retry standby node upgrade failed", "job_id", jobID, "node_id", nodeID, "node_name", rowCopy.NodeName, "error", stepErr)
			_ = repo.UpdateNodeExecutionStatus(context.Background(), rowCopy.ID, NodeStatusFailed, code, stepErr.Error(), true, true)
			backups.NotifyAlert(s.alertFn, "UPGRADE_FAILED", "UPGRADE", "备节点补升重试失败",
				fmt.Sprintf("升级任务 %s 重试备节点 %s 失败（%s）：%s", jobID, rowCopy.NodeName, code, failMsg(stepErr)))
			s.recordRetryNodeAudit(context.Background(), jobID, &rowCopy, requestedBy, requestID, audits.ResultFailure, stepErr.Error())
			return
		}
		slog.Info("retry standby node upgrade succeeded", "job_id", jobID, "node_id", nodeID, "node_name", rowCopy.NodeName)
		s.recordRetryNodeAudit(context.Background(), jobID, &rowCopy, requestedBy, requestID, audits.ResultSuccess, "")
	}
	if s.startRetryNode != nil {
		s.startRetryNode(runRetry)
	} else {
		go runRetry()
	}
	return updated, nil
}

func (s *Service) recordRetryNodeAudit(ctx context.Context, jobID uuid.UUID, row *NodeExecution, requestedBy uuid.UUID, requestID, result, failReason string) {
	if s.auditFn == nil {
		return
	}
	uid := requestedBy
	in := audits.RecordInput{
		UserID:        &uid,
		Module:        "upgrades",
		Action:        "retry_node_result",
		ObjectType:    "upgrade",
		ObjectID:      jobID.String(),
		ObjectName:    row.NodeName,
		AfterSummary:  fmt.Sprintf("备节点 %s 补升重试结果：%s", row.NodeName, result),
		Result:        result,
		FailureReason: failReason,
		RiskLevel:     audits.RiskHigh,
		RequestID:     requestID,
	}
	if err := s.auditFn(ctx, in); err != nil {
		slog.Error("record retry node audit failed", "job_id", jobID, "node", row.NodeName, "error", err)
	}
}

func (s *Service) markPrimaryNodeTerminal(ctx context.Context, jobID uuid.UUID, status, code, msg string) {
	if repo := s.clusterStoreRepo(); repo != nil {
		_ = repo.MarkPrimaryNodeExecution(ctx, jobID, status, code, msg)
		return
	}
	if pm, ok := s.resultRepo().(primaryNodeMarker); ok {
		_ = pm.MarkPrimaryNodeExecution(ctx, jobID, status, code, msg)
	}
}

func hasSplitBrainFailure(items []CheckItem) bool {
	for _, it := range items {
		if it.Name == "cluster_split_brain" && it.Result == CheckFail {
			return true
		}
	}
	return false
}
