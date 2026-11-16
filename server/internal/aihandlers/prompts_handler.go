// prompts_handler.go Prompt 管理：创建/版本/静态测试/对抗测试/发布/回滚。
// 版本不可变；发布门（store.Publish 强制，本层先给出友好错误）：
// 静态安全检查 + 测试集回归 PASSED + 对抗测试 ADVERSARIAL_PASSED 齐备方可发布，人工审核为发布动作本身。
package aihandlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/aiaudit"
	"github.com/jiuzhang-waf/server/internal/aiprompts"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// Prompt 类型白名单。
var promptTypes = map[string]bool{
	"SYSTEM": true, "ORCHESTRATOR": true, "AGENT": true, "TOOL": true,
	"TASK": true, "SAFETY": true, "EVALUATION": true,
}

// PromptList Prompt 列表（prompt_type/status 可选过滤）。
func (d *Deps) PromptList(w http.ResponseWriter, r *http.Request) {
	pt := r.URL.Query().Get("prompt_type")
	status := r.URL.Query().Get("status")
	if pt != "" && !promptTypes[pt] {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 Prompt 类型")
		return
	}
	list, err := d.Prompts.List(r.Context(), pt, status)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": list})
}

// PromptCreate 创建 Prompt 及首版本。
func (d *Deps) PromptCreate(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req struct {
		Code          string `json:"code"`
		Name          string `json:"name"`
		PromptType    string `json:"prompt_type"`
		Content       string `json:"content"`
		ChangeSummary string `json:"change_summary"`
	}
	if err := decodeJSON(w, r, &req, 65536); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	req.Code = strings.TrimSpace(req.Code)
	req.Name = strings.TrimSpace(req.Name)
	if req.Code == "" || len(req.Code) > 50 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "Prompt 编码必填且不超过 50 字符")
		return
	}
	if req.Name == "" || len(req.Name) > 100 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "Prompt 名称必填且不超过 100 字符")
		return
	}
	if !promptTypes[req.PromptType] {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 Prompt 类型")
		return
	}
	// 编码唯一性预检查（避免唯一索引冲突报 500）
	existing, err := d.Prompts.List(r.Context(), "", "")
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	for _, e := range existing {
		if e.Code == req.Code {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "Prompt 编码已存在")
			return
		}
	}
	prompt, version, err := d.Prompts.CreatePrompt(r.Context(), req.Code, req.Name, req.PromptType,
		req.Content, trunc(req.ChangeSummary, 500), &p.UserID)
	if err != nil {
		if errors.Is(err, aiprompts.ErrUnsafeContent) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "Prompt 内容包含禁止内容（密钥/Shell/越权/思维链等）")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	d.recordAIAudit(p, aiaudit.Record{
		Action: "prompt_create", PromptVersion: "1",
		RequestSummary: "创建 Prompt " + req.Code, ResultSummary: "SUCCESS",
	})
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"prompt": prompt, "version": version})
}

// PromptVersionList 版本列表。
func (d *Deps) PromptVersionList(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的Prompt ID")
		return
	}
	versions, err := d.Prompts.ListVersions(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": versions})
}

// PromptVersionCreate 创建新版本（不可变）。
func (d *Deps) PromptVersionCreate(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的Prompt ID")
		return
	}
	var req struct {
		Content       string `json:"content"`
		ChangeSummary string `json:"change_summary"`
	}
	if err := decodeJSON(w, r, &req, 65536); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	v, err := d.Prompts.CreateVersion(r.Context(), id, req.Content, trunc(req.ChangeSummary, 500), &p.UserID)
	if err != nil {
		if errors.Is(err, aiprompts.ErrUnsafeContent) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "Prompt 内容包含禁止内容（密钥/Shell/越权/思维链等）")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	d.recordAIAudit(p, aiaudit.Record{
		Action: "prompt_version_create", PromptVersion: fmt.Sprint(v.VersionNumber),
		RequestSummary: "创建 Prompt 版本 " + id.String(), ResultSummary: "SUCCESS",
	})
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"version": v})
}

// PromptVersionTest 版本测试（静态检查 + 真实 Prompt 回归）。
// 静态检查：非空与长度 + 禁止内容扫描（不通过则 FAILED 且不跑回归——候选内容不安全不进模型）。
// 真实回归：候选内容覆盖 orchestrator_answer_summary（仅本次运行有效，不触碰发布存储），
// 逐集运行 eval_prompt_injection / eval_privilege_denial / eval_insufficient_data /
// eval_api_security_analysis；安全类阈值 100%、一般阈值 80%，全部达标才 PASSED。
// 模型不可用/评估失败如实 FAILED 并记录失败摘要（不伪装 PASSED），发布门 fail-closed 不变。
// 结果与逐集分数/模型/失败摘要写 test_detail（ai_prompt_versions.test_detail，迁移 000187）。
func (d *Deps) PromptVersionTest(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	vid, err := uuid.Parse(r.PathValue("versionId"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的版本ID")
		return
	}
	v, err := d.Prompts.GetVersion(r.Context(), vid)
	if err != nil {
		d.promptError(w, r, err)
		return
	}
	// 检查明细：长度/非空 + 禁止内容扫描
	checks := []map[string]interface{}{}
	lenOK := len(v.Content) > 0 && len(v.Content) <= 50000
	checks = append(checks, map[string]interface{}{
		"name": "非空与长度（≤50000 字符）", "passed": lenOK,
	})
	valErr := aiprompts.ValidateContent(v.Content)
	patternCheck := map[string]interface{}{
		"name": "禁止内容扫描（密钥/Shell/越权/思维链）", "passed": valErr == nil,
	}
	if valErr != nil {
		patternCheck["message"] = "命中禁止内容"
	}
	checks = append(checks, patternCheck)
	staticOK := lenOK && valErr == nil

	// test_detail 骨架：静态检查项恒定落库；回归段仅静态通过时执行
	detail := map[string]interface{}{"static_checks": checks}
	result := "PASSED"
	var regressionResp interface{}
	if !staticOK {
		result = "FAILED"
		detail["failure_summary"] = "静态检查未通过，跳过真实回归（候选内容不安全不进模型）"
	} else {
		// 回归串行跑 4 个评估集可能远超服务器 WriteTimeout（默认 30s），放宽本请求写期限
		if rc := http.NewResponseController(w); rc != nil {
			_ = rc.SetWriteDeadline(time.Now().Add(20 * time.Minute))
		}
		runCtx, cancel := context.WithTimeout(r.Context(), promptRegressionTimeout)
		defer cancel()
		sets, model := d.runPromptRegression(runCtx, p, v)
		allPass, failureSummary := summarizeRegression(sets)
		regression := map[string]interface{}{"model": model, "sets": sets}
		if failureSummary != "" {
			regression["failure_summary"] = failureSummary
			detail["failure_summary"] = failureSummary
		}
		detail["regression"] = regression
		regressionResp = regression
		if !allPass {
			result = "FAILED"
		}
	}
	detailJSON, err := json.Marshal(detail)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if err := d.Prompts.MarkTestResult(r.Context(), vid, result, detailJSON); err != nil {
		response.InternalError(w, r, err)
		return
	}
	d.recordAIAudit(p, aiaudit.Record{
		Action: "prompt_test", PromptVersion: fmt.Sprint(v.VersionNumber),
		RequestSummary: "测试 Prompt 版本 " + vid.String(), ResultSummary: result,
	})
	resp := map[string]interface{}{
		"test_result": result, "checks": checks, "test_detail": json.RawMessage(detailJSON),
	}
	if regressionResp != nil {
		resp["regression"] = regressionResp
	}
	response.JSON(w, r, http.StatusOK, resp)
}

// PromptVersionAdversarialTest 版本对抗测试（§24.4）：
// 对版本内容跑内置对抗样本集（提示注入/越权诱导/数据泄露诱导），逐样本判定并回写
// adversarial_result（ADVERSARIAL_PASSED/ADVERSARIAL_FAILED）与明细；失败原因如实返回。
func (d *Deps) PromptVersionAdversarialTest(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	vid, err := uuid.Parse(r.PathValue("versionId"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的版本ID")
		return
	}
	v, err := d.Prompts.GetVersion(r.Context(), vid)
	if err != nil {
		d.promptError(w, r, err)
		return
	}
	result, cases := aiprompts.RunAdversarial(v.Content)
	detailJSON, err := json.Marshal(cases)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if err := d.Prompts.MarkAdversarialResult(r.Context(), vid, result, detailJSON); err != nil {
		response.InternalError(w, r, err)
		return
	}
	d.recordAIAudit(p, aiaudit.Record{
		Action: "prompt_adversarial_test", PromptVersion: fmt.Sprint(v.VersionNumber),
		RequestSummary: "对抗测试 Prompt 版本 " + vid.String(), ResultSummary: result,
	})
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"adversarial_result": result, "cases": cases,
	})
}

// PromptDiff 比较两个版本内容差异摘要（行级统计 + 截断预览）。
func (d *Deps) PromptDiff(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的Prompt ID")
		return
	}
	fromS := r.URL.Query().Get("from")
	toS := r.URL.Query().Get("to")
	if fromS == "" || toS == "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "需要 from 与 to 版本号或版本ID")
		return
	}
	versions, err := d.Prompts.ListVersions(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	find := func(key string) *aiprompts.Version {
		for i := range versions {
			v := &versions[i]
			if v.ID.String() == key || fmt.Sprint(v.VersionNumber) == key {
				return v
			}
		}
		return nil
	}
	a, b := find(fromS), find(toS)
	if a == nil || b == nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "版本不存在")
		return
	}
	aLines := strings.Split(a.Content, "\n")
	bLines := strings.Split(b.Content, "\n")
	// 简单 LCS 近似：统计仅左右侧独有行数
	setA := map[string]int{}
	for _, l := range aLines {
		setA[l]++
	}
	onlyB, onlyA, same := 0, 0, 0
	setB := map[string]int{}
	for _, l := range bLines {
		setB[l]++
	}
	for l, c := range setA {
		if setB[l] > 0 {
			m := c
			if setB[l] < m {
				m = setB[l]
			}
			same += m
			onlyA += c - m
			onlyB += setB[l] - m
			delete(setB, l)
		} else {
			onlyA += c
		}
	}
	for _, c := range setB {
		onlyB += c
	}
	preview := func(s string) string {
		if len(s) > 500 {
			return s[:500] + "..."
		}
		return s
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"from": map[string]interface{}{"version_id": a.ID, "version_number": a.VersionNumber, "content_hash": a.ContentHash, "preview": preview(a.Content)},
		"to":   map[string]interface{}{"version_id": b.ID, "version_number": b.VersionNumber, "content_hash": b.ContentHash, "preview": preview(b.Content)},
		"stats": map[string]interface{}{
			"from_lines": len(aLines), "to_lines": len(bLines),
			"same_lines": same, "removed_lines": onlyA, "added_lines": onlyB,
			"content_equal": a.ContentHash == b.ContentHash,
		},
	})
}

// PromptPublish 发布版本（人工审核动作；发布门：回归测试 PASSED + 对抗测试 ADVERSARIAL_PASSED，store 层强制）。
func (d *Deps) PromptPublish(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的Prompt ID")
		return
	}
	var req struct {
		VersionID string `json:"version_id"`
	}
	if err := decodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	vid, err := uuid.Parse(req.VersionID)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的版本ID")
		return
	}
	if err := d.Prompts.Publish(r.Context(), id, vid, &p.UserID); err != nil {
		if errors.Is(err, aiprompts.ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "Prompt 或版本不存在")
			return
		}
		var gateErr *aiprompts.PublishGateError
		if errors.As(err, &gateErr) {
			gateState := func(s string) string {
				if s == "" {
					return "未执行"
				}
				return s
			}
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
				fmt.Sprintf("仅回归测试 PASSED 且对抗测试 ADVERSARIAL_PASSED 的版本可发布（当前：回归测试=%s，对抗测试=%s）",
					gateState(gateErr.TestResult), gateState(gateErr.AdversarialResult)))
			return
		}
		response.InternalError(w, r, err)
		return
	}
	d.recordAIAudit(p, aiaudit.Record{
		Action: "prompt_publish", RequestSummary: "发布 Prompt " + id.String() + " 版本 " + vid.String(),
		ResultSummary: "SUCCESS",
	})
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "版本已发布"})
}

// PromptRollback 回滚到已发布过的版本。
func (d *Deps) PromptRollback(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的Prompt ID")
		return
	}
	var req struct {
		VersionID string `json:"version_id"`
	}
	if err := decodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	vid, err := uuid.Parse(req.VersionID)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的版本ID")
		return
	}
	if err := d.Prompts.Rollback(r.Context(), id, vid, &p.UserID); err != nil {
		if errors.Is(err, aiprompts.ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "Prompt 或版本不存在")
			return
		}
		if strings.Contains(err.Error(), "previously published") {
			response.Error(w, r, http.StatusConflict, response.CodeInvalidArgument, "仅可回滚到已发布过的版本")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	d.recordAIAudit(p, aiaudit.Record{
		Action: "prompt_rollback", RequestSummary: "回滚 Prompt " + id.String() + " 至版本 " + vid.String(),
		ResultSummary: "SUCCESS",
	})
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "已回滚到指定版本"})
}

// promptError Prompt 错误映射。
func (d *Deps) promptError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, aiprompts.ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "Prompt 或版本不存在")
		return
	}
	response.InternalError(w, r, err)
}

// PromptRename PATCH /api/v1/ai/prompts/{id}：编辑 Prompt 名称（编码不可变）。
func (d *Deps) PromptRename(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的Prompt ID")
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := response.DecodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	prompt, err := d.Prompts.Rename(r.Context(), id, req.Name, &p.UserID)
	if err != nil {
		d.promptError(w, r, err)
		return
	}
	d.recordAIAudit(p, aiaudit.Record{
		Action:         "prompt_rename",
		RequestSummary: "重命名 Prompt " + prompt.Code + " 为 " + prompt.Name, ResultSummary: "SUCCESS",
	})
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"prompt": prompt})
}

// PromptDelete DELETE /api/v1/ai/prompts/{id}：删除未发布（DRAFT）Prompt 及全部版本。
func (d *Deps) PromptDelete(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的Prompt ID")
		return
	}
	if err := d.Prompts.Delete(r.Context(), id); err != nil {
		if errors.Is(err, aiprompts.ErrActivePrompt) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "已发布的 Prompt 不可删除")
			return
		}
		d.promptError(w, r, err)
		return
	}
	d.recordAIAudit(p, aiaudit.Record{
		Action:         "prompt_delete",
		RequestSummary: "删除 Prompt " + id.String(), ResultSummary: "SUCCESS",
	})
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "Prompt 已删除"})
}
