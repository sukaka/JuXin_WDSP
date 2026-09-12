// compat_g5_test.go G5 兼容矩阵与部分 ACK 状态分离补验证（任务书
// docs/tasks/wdsp-p1/P1-03_AGENT_GATEWAY_PROTOCOLS.md §7 G5、§8 AGT-023/AGT-024）：
//   - 旧 Agent（v1 线格式、无能力声明）对新 Server：v1 批次语义与响应形状完全不变，
//     能力集落库默认 {1}（管理端据此显示「需升级」，不假报 v2 已启用）；
//   - 策略部分 ACK 状态分离：目标版本（config_version）与 Agent 实际加载版本
//     （applied_config_version）在管理端分别可见，部分生效期间不合并、不伪造同步。
package agents

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestG5OldAgentV1OnNewServer 旧 Agent → 新 Server（AGT-023）：
// 未声明能力的 Agent（等效旧程序）发送经典 v1 批次（无 schema_version 字段）：
// 202 + v1 响应形状 {"accepted": n}（不得携带 v2 的 accepted_count/duplicate_count），
// 记录按 v1 路径入库；该 Agent 能力集为非 v2（管理端「需升级」判定依据）。
func TestG5OldAgentV1OnNewServer(t *testing.T) {
	store := newFakeMachineStore()
	agentID := uuid.New()
	cred := registerAgent(store, agentID, false) // 无能力声明 = 旧 Agent
	mux := newMachineMux(NewMachineHandler(store))

	// 经典 v1 批次：顶层无 schema_version，记录为 v1 字段集
	body := `{"records":[` + mustV1JSON(t) + `]}`
	rr := doMachine(t, mux, http.MethodPost, "/api/v1/agents/"+agentID.String()+"/http", body, cred)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (body=%s)", rr.Code, rr.Body.String())
	}
	out := rr.Body.String()
	if !strings.Contains(out, `"accepted":1`) {
		t.Errorf("v1 响应形状应保持 {\"accepted\": n}: %s", out)
	}
	if strings.Contains(out, "accepted_count") || strings.Contains(out, "duplicate_count") {
		t.Errorf("v1 响应不得携带 v2 分账字段: %s", out)
	}
	if len(store.insertedHTTP) != 1 {
		t.Fatalf("v1 记录应按旧路径入库: %d", len(store.insertedHTTP))
	}
	// 能力集非 v2：管理端不得假报该 Agent 已启用 v2
	if schemas := store.agentsByID[agentID].HTTPEventSchemas; len(schemas) != 0 {
		t.Errorf("未声明能力的 Agent 生效集不应含 v2: %v", schemas)
	}
}

// TestG5PartialACKStateSeparation 策略部分 ACK 状态分离（AGT-024 补验证）：
// 目标版本（config_version=5，策略保存/发布侧）与 Agent 实际加载版本
// （applied_config_version=3，ACK 回填侧）在管理端列表分别输出；部分生效期间
// 健康评分给出 config_not_synced 扣分原因，不把目标版本冒充为已生效版本。
func TestG5PartialACKStateSeparation(t *testing.T) {
	agentID := uuid.New()
	store := newFakeAdminStore()
	lastSeen := time.Now() // 在线（避免 offline 扣分干扰原因断言）
	store.agents = []Agent{{
		AgentID: agentID, Hostname: "web-prod-01", LastSeen: &lastSeen,
		LastStatus:           StatusOnline,
		ConfigVersion:        5, // 服务端目标版本（策略已保存/发布）
		AppliedConfigVersion: 3, // Agent 实际加载版本（部分 ACK：尚未追到目标）
	}}
	mux := newAdminMux(NewHandler(store), injectPerms(PermAgentsView))

	rr := doAdmin(t, mux, http.MethodGet, "/api/v1/traffic/agents", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d (body=%s)", rr.Code, rr.Body.String())
	}
	var resp struct {
		Items []struct {
			ConfigVersion        int64    `json:"config_version"`
			AppliedConfigVersion int64    `json:"applied_config_version"`
			HealthReasons        []string `json:"health_reasons"`
		} `json:"items"`
	}
	decodeEnvelope(t, rr, &resp)
	if len(resp.Items) != 1 {
		t.Fatalf("items = %+v", resp.Items)
	}
	it := resp.Items[0]
	if it.ConfigVersion != 5 || it.AppliedConfigVersion != 3 {
		t.Errorf("目标/生效版本须分别输出: config_version=%d applied_config_version=%d",
			it.ConfigVersion, it.AppliedConfigVersion)
	}
	found := false
	for _, rsn := range it.HealthReasons {
		if rsn == "config_not_synced" {
			found = true
		}
	}
	if !found {
		t.Errorf("部分 ACK 期间应给出 config_not_synced 原因: %v", it.HealthReasons)
	}
}

// TestG5ConfigAckFailedKeepsPartialState FAILED ACK 不推进生效版本（AGT-024：
// 保存/发布成功 ≠ Agent 实际加载成功；加载失败如实保持部分状态不伪造同步）。
// 机器端 APPLIED/FAILED 语义已有 TestConfigAck 覆盖，本测试复核仓储层口径：
// FAILED 不回填 applied_config_version，目标版本保持不变。
func TestG5ConfigAckFailedKeepsPartialState(t *testing.T) {
	store := newFakeMachineStore()
	agentID := uuid.New()
	cred := registerAgent(store, agentID, false)
	mux := newMachineMux(NewMachineHandler(store))

	// FAILED ACK：如实上报加载失败
	rr := doMachine(t, mux, http.MethodPost, "/api/v1/agents/"+agentID.String()+"/config/ack",
		`{"version":5,"status":"FAILED","error":"bpf load failed"}`, cred)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rr.Code)
	}
	if store.ackedApplied {
		t.Error("FAILED ACK 不得回填 applied_config_version（不得伪造同步）")
	}
	// APPLIED ACK 才推进生效版本
	rr = doMachine(t, mux, http.MethodPost, "/api/v1/agents/"+agentID.String()+"/config/ack",
		`{"version":5,"status":"APPLIED","error":""}`, cred)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rr.Code)
	}
	if !store.ackedApplied || store.ackedVersion != 5 {
		t.Errorf("APPLIED 应回填版本 5: (%d, %v)", store.ackedVersion, store.ackedApplied)
	}
}
