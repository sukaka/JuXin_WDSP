// tasks.go 五种内置运营任务：确定性查询（Source）→ 结构化报告 + 模板化中文摘要。
// 纪律（设计稿 §5.1/§8.1）：任务只产出报告与建议文本，不执行任何业务变更；
// LLM 仅经 Summarizer 润色摘要，nil 或失败一律回退模板摘要（降级而非失败）。
package apiops

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Summarizer LLM 摘要润色接口（装配时可接现有 AI 服务；nil 时纯模板输出）。
// 实现方必须只返回展示文本，不得把润色结果回灌为任何 Tool/任务入参（提示注入防线，
// 设计稿 §8.2-5）；润色输入为结构化报告与模板草稿，输出仅用于展示。
type Summarizer interface {
	Polish(ctx context.Context, taskType string, report json.RawMessage, draft string) (string, error)
}

// taskResult 任务产物：结构化报告（落 report_json）+ 模板摘要草稿（润色前）。
type taskResult struct {
	Report any
	Draft  string
}

// taskFunc 内置任务函数签名。now 为执行时刻（测试可注入固定时钟）。
type taskFunc func(ctx context.Context, src Source, cfg TaskConfig, now time.Time) (*taskResult, error)

// taskRegistry 内置任务注册表（代码内词表，与迁移 000062 CHECK 一致；非自由文本）。
var taskRegistry = map[string]taskFunc{
	TaskAssetDigest:     runAssetDigest,
	TaskShadowReview:    runShadowReview,
	TaskWeaknessFollow:  runWeaknessFollow,
	TaskRiskDigest:      runRiskDigest,
	TaskSensitiveDigest: runSensitiveDigest,
}

// polishSummary LLM 润色挂点：summarizer 为 nil、润色失败或返回空白时回退模板草稿。
func polishSummary(ctx context.Context, s Summarizer, taskType string, report any, draft string) string {
	if s == nil {
		return draft
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return draft // 报告序列化异常不影响摘要产出（模板草稿兜底）
	}
	polished, err := s.Polish(ctx, taskType, raw, draft)
	if err != nil || strings.TrimSpace(polished) == "" {
		return draft
	}
	return polished
}

// statusCount 从状态分桶中取指定状态计数（无该状态返回 0）。
func statusCount(counts []TypeCount, status string) int64 {
	for _, c := range counts {
		if c.Type == status {
			return c.Count
		}
	}
	return 0
}

// endpointLabel 端点展示标签（method + path，无前导空格问题由数据侧保证）。
func endpointLabel(it EndpointItem) string {
	return fmt.Sprintf("%s %s", it.Method, it.Path)
}

// runAssetDigest API_ASSET_DIGEST：资产变化摘要（新增/确认/Shadow/Zombie 计数与清单）。
func runAssetDigest(ctx context.Context, src Source, cfg TaskConfig, now time.Time) (*taskResult, error) {
	since := now.Add(-time.Duration(cfg.WindowHours) * time.Hour)
	data, err := src.AssetDigest(ctx, since, cfg.Limit)
	if err != nil {
		return nil, err
	}
	discovered := statusCount(data.StatusCounts, "DISCOVERED")
	var b strings.Builder
	fmt.Fprintf(&b, "截至 %s，API 资产共 %d 个（待确认 %d）。", now.Format("2006-01-02 15:04"), data.TotalEndpoints, discovered)
	fmt.Fprintf(&b, "近 %d 小时：新发现端点 %d 个，人工确认 %d 个。", cfg.WindowHours, data.NewInWindow, data.ConfirmedInWindow)
	fmt.Fprintf(&b, "Shadow 未闭环 %d 项，Zombie 未闭环 %d 项。", data.ShadowOpen, data.ZombieOpen)
	if data.NewInWindow > 0 {
		b.WriteString("新增端点（部分）：")
		for i, it := range data.NewEndpoints {
			if i >= 5 {
				fmt.Fprintf(&b, " 等 %d 个", data.NewInWindow)
				break
			}
			fmt.Fprintf(&b, "%s（%s） ", endpointLabel(it), it.AssetStatus)
		}
	}
	if discovered > 0 {
		fmt.Fprintf(&b, "建议：%d 个端点待人工确认，请前往资产中心处理。", discovered)
	}
	return &taskResult{Report: data, Draft: strings.TrimSpace(b.String())}, nil
}

// runShadowReview SHADOW_REVIEW：Shadow API 运营（未闭环 + 窗口新增清单 + 纳管建议）。
func runShadowReview(ctx context.Context, src Source, cfg TaskConfig, now time.Time) (*taskResult, error) {
	since := now.Add(-time.Duration(cfg.WindowHours) * time.Hour)
	data, err := src.ShadowReview(ctx, since, cfg.Limit)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Shadow API 运营简报：未闭环 Shadow 发现共 %d 项，近 %d 小时新增 %d 项。", data.OpenTotal, cfg.WindowHours, data.NewInWindow)
	if len(data.Items) > 0 {
		b.WriteString("清单（按最近命中倒序）：")
		for i, it := range data.Items {
			if i >= 5 {
				fmt.Fprintf(&b, " 等 %d 项", len(data.Items))
				break
			}
			label := it.EndpointKey
			if label == "" {
				label = it.Title
			}
			fmt.Fprintf(&b, "%s（%s，命中 %d 次） ", label, it.Severity, it.Count)
		}
	}
	if data.OpenTotal > 0 {
		b.WriteString("建议：Shadow API 未纳入规范管理面，请人工核对后决定纳管（确认资产并启动学习）或下线；本任务不执行任何变更。")
	} else {
		b.WriteString("当前无未闭环 Shadow 发现，保持观测。")
	}
	return &taskResult{Report: data, Draft: strings.TrimSpace(b.String())}, nil
}

// runWeaknessFollow WEAKNESS_FOLLOW：到期/超期弱点清单 + 催办建议。
func runWeaknessFollow(ctx context.Context, src Source, cfg TaskConfig, now time.Time) (*taskResult, error) {
	data, err := src.WeaknessFollow(ctx, now, cfg.DueWithinDays, cfg.Limit)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "弱点整改跟进：待整改弱点共 %d 项，其中已超期 %d 项、%d 天内到期 %d 项、未设期限 %d 项。",
		data.OpenTotal, len(data.Overdue), cfg.DueWithinDays, len(data.DueSoon), data.NoDueDate)
	writeWeaknessList := func(title string, items []WeaknessItem) {
		if len(items) == 0 {
			return
		}
		b.WriteString(title)
		for i, it := range items {
			if i >= 5 {
				fmt.Fprintf(&b, " 等 %d 项", len(items))
				break
			}
			owner := it.Owner
			if owner == "" {
				owner = "未指派"
			}
			due := ""
			if it.DueDate != nil {
				due = it.DueDate.Format("2006-01-02")
			}
			fmt.Fprintf(&b, "%s（%s，%s，期限 %s） ", it.WeaknessName, it.Severity, owner, due)
		}
	}
	writeWeaknessList("超期清单：", data.Overdue)
	writeWeaknessList("临期清单：", data.DueSoon)
	if len(data.Overdue) > 0 {
		b.WriteString("建议：请按上述清单催办负责人整改并复测；弱点状态流转均为人工动作。")
	} else if len(data.DueSoon) > 0 {
		b.WriteString("建议：临期弱点请提前跟进，避免超期。")
	} else {
		b.WriteString("当前无超期或临期弱点。")
	}
	return &taskResult{Report: data, Draft: strings.TrimSpace(b.String())}, nil
}

// runRiskDigest RISK_DIGEST：高风险 findings 摘要（HIGH/CRITICAL 未闭环）。
func runRiskDigest(ctx context.Context, src Source, cfg TaskConfig, now time.Time) (*taskResult, error) {
	since := now.Add(-time.Duration(cfg.WindowHours) * time.Hour)
	data, err := src.RiskDigest(ctx, since, cfg.Limit)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "高风险发现摘要：未闭环 HIGH/CRITICAL 发现共 %d 项（CRITICAL %d 项），近 %d 小时新增 %d 项。",
		data.OpenHighTotal, data.OpenCritical, cfg.WindowHours, data.NewInWindow)
	if len(data.TypeDistribution) > 0 {
		b.WriteString("类型分布：")
		for i, tc := range data.TypeDistribution {
			if i >= 5 {
				fmt.Fprintf(&b, " 等 %d 类", len(data.TypeDistribution))
				break
			}
			fmt.Fprintf(&b, "%s %d 项 ", tc.Type, tc.Count)
		}
	}
	if len(data.Items) > 0 {
		b.WriteString("重点清单：")
		for i, it := range data.Items {
			if i >= 5 {
				fmt.Fprintf(&b, " 等 %d 项", len(data.Items))
				break
			}
			label := it.EndpointKey
			if label == "" {
				label = it.Title
			}
			fmt.Fprintf(&b, "%s（%s/%s） ", label, it.FindingType, it.Severity)
		}
	}
	if data.OpenHighTotal > 0 {
		b.WriteString("建议：请优先处置 CRITICAL 发现；风险确认/处理/解决均为人工动作，本任务不流转状态。")
	} else {
		b.WriteString("当前无未闭环高风险发现。")
	}
	return &taskResult{Report: data, Draft: strings.TrimSpace(b.String())}, nil
}

// runSensitiveDigest SENSITIVE_DIGEST：涉敏概览变化（总量/类型分布/窗口新增清单）。
func runSensitiveDigest(ctx context.Context, src Source, cfg TaskConfig, now time.Time) (*taskResult, error) {
	since := now.Add(-time.Duration(cfg.WindowHours) * time.Hour)
	data, err := src.SensitiveDigest(ctx, since, cfg.Limit)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "涉敏概览：涉敏端点 %d 个、涉敏字段 %d 行；近 %d 小时新增涉敏字段 %d 行。",
		data.SensitiveEndpointCount, data.SensitiveFieldCount, cfg.WindowHours, data.NewFieldsInWindow)
	if len(data.TypeDistribution) > 0 {
		b.WriteString("类型分布：")
		for i, tc := range data.TypeDistribution {
			if i >= 5 {
				fmt.Fprintf(&b, " 等 %d 类", len(data.TypeDistribution))
				break
			}
			fmt.Fprintf(&b, "%s %d 行 ", tc.Type, tc.Count)
		}
	}
	if len(data.NewFields) > 0 {
		b.WriteString("新增涉敏字段（部分）：")
		for i, it := range data.NewFields {
			if i >= 5 {
				fmt.Fprintf(&b, " 等 %d 行", data.NewFieldsInWindow)
				break
			}
			fmt.Fprintf(&b, "%s %s（%s/%s） ", it.EndpointKey, it.Path, it.Direction, it.DataType)
		}
	}
	if data.NewFieldsInWindow > 0 {
		b.WriteString("建议：请核对新增涉敏字段的脱敏规则覆盖情况；脱敏规则变更走既有人工发布流程。")
	}
	return &taskResult{Report: data, Draft: strings.TrimSpace(b.String())}, nil
}
