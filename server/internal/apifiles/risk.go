// risk.go 文件风险 v1（§107 子集）：同身份批量下载判定。
//
// 规则：近 1 小时（bulkDownloadWindow）同一身份指纹下载的不同文件数
// （DISTINCT filename 口径）严格超过阈值 → 物化 api_runtime_findings
// （finding_type=FILE_BULK_DOWNLOAD，severity=HIGH——阈值即"明显异常"水位，
// 批量下载属数据批量导出/窃取信号）。
//
// 写入路径选择说明（任务书允许二选一，此处选简单方案并注释）：
// 既有物化路径（apiruntime.Collector.recordFindings）是事件驱动的——由单条事件的
// DetectorMatch 派生 finding；批量下载是窗口聚合判定，没有对应的单事件明细，
// 套事件物化路径需要伪造 DetectorMatch，反而失真。故直接复用 findings 仓储接口
// （apiruntime.FindingSaver / SaveFindings）：dedup_fingerprint
// （key: + FILE_BULK_DOWNLOAD + 身份指纹）稳定，重复 Sweep 命中 ON CONFLICT
// count+1 刷新 last_seen（幂等，不产生重复行）。
package apifiles

import (
	"context"
	"fmt"

	"github.com/jiuzhang-waf/server/internal/apiruntime"
)

// SettingsReader 设置读取窄接口（settings.Service 满足；测试注入假实现）。
type SettingsReader interface {
	GetInt(ctx context.Context, group, key string, def int) int
}

// RiskSweepResult 一次批量下载判定的结果统计。
type RiskSweepResult struct {
	Threshold  int    `json:"threshold"`  // 本次生效阈值
	Window     string `json:"window"`     // 判定窗口（固定 1h）
	Candidates int    `json:"candidates"` // 超阈值身份数
	Findings   int    `json:"findings"`   // 实际提交物化的 finding 数（findings 未注入时为 0）
}

// RiskSweeper 同身份批量下载判定器（无内部状态，并发安全；阈值每轮重读即时生效）。
type RiskSweeper struct {
	store    riskStore
	findings apiruntime.FindingSaver // nil = 跳过物化（仅统计候选）
	settings SettingsReader          // nil = 默认阈值
}

// NewRiskSweeper 创建判定器。riskStore 为窄接口（*Store 满足；测试注入内存实现）。
func NewRiskSweeper(store riskStore, findings apiruntime.FindingSaver, settings SettingsReader) *RiskSweeper {
	return &RiskSweeper{store: store, findings: findings, settings: settings}
}

// SweepOnce 执行一次批量下载判定。空表/无超阈值身份安全返回零值结果。
func (s *RiskSweeper) SweepOnce(ctx context.Context) (*RiskSweepResult, error) {
	threshold := DefaultBulkDownloadThreshold
	if s.settings != nil {
		threshold = s.settings.GetInt(ctx, SettingsGroup, SettingsKeyBulkDownloadThreshold, DefaultBulkDownloadThreshold)
	}
	if threshold <= 0 {
		threshold = DefaultBulkDownloadThreshold // 非法取值回退默认（不误放开也不误禁用）
	}
	res := &RiskSweepResult{Threshold: threshold, Window: bulkDownloadWindow.String()}
	candidates, err := s.store.BulkDownloadCandidates(ctx, bulkDownloadWindow, threshold)
	if err != nil {
		return nil, err
	}
	res.Candidates = len(candidates)
	if len(candidates) == 0 || s.findings == nil {
		return res, nil
	}
	in := make([]apiruntime.FindingInput, 0, len(candidates))
	for _, c := range candidates {
		in = append(in, apiruntime.FindingInput{
			// 身份级判定不锚定单端点：EndpointKey 置空，dedup 锚点落 "key:" 兜底
			// （见 apiruntime findings 仓储注释），指纹随身份稳定
			EndpointKey: "",
			FindingType: "FILE_BULK_DOWNLOAD",
			Severity:    "HIGH",
			Title: fmt.Sprintf("同一身份近1小时批量下载 %d 个不同文件（阈值 %d）",
				c.DistinctFiles, threshold),
			Detail: map[string]any{
				"detector":       "api_files",
				"rule_id":        "file.bulk_download",
				"window":         bulkDownloadWindow.String(),
				"threshold":      threshold,
				"distinct_files": c.DistinctFiles,
				"transfers":      c.Transfers,
			},
			// 证据只含统计元信息（无文件名清单——明细可查 file-assets 接口，
			// finding 不复制大清单）
			Evidence: map[string]any{
				"window":         bulkDownloadWindow.String(),
				"threshold":      threshold,
				"distinct_files": c.DistinctFiles,
				"transfers":      c.Transfers,
			},
			SubjectType: "IDENTITY",
			SubjectID:   c.IdentityFingerprint,
			RiskScore:   60, // HIGH 档（50-79）下限上方，留给更重规则的空间
			RiskLevel:   "HIGH",
		})
	}
	if err := s.findings.SaveFindings(ctx, in); err != nil {
		return nil, fmt.Errorf("save file bulk download findings: %w", err)
	}
	res.Findings = len(in)
	return res, nil
}
