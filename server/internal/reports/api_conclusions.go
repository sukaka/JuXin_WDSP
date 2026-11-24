package reports

import "fmt"

// API 报告结论与建议：与 WAF 域同一纪律——确定性模板规则生成，
// 按固定顺序评估，相同输入必然产生相同输出，禁止 AI/随机判断。

// BuildAPIConclusions 生成 API 报告结论（按报告类型分支）。
func BuildAPIConclusions(d *APIReportData) []string {
	switch d.ReportType {
	case TypeAPIAsset:
		return apiAssetConclusions(d.Asset)
	case TypeAPIRisk:
		return apiRiskConclusions(d.Risk)
	case TypeAPIWeak:
		return apiWeaknessConclusions(d.Weakness)
	case TypeAPISens:
		return apiSensitiveConclusions(d.Sensitive)
	}
	return nil
}

// BuildAPISuggestions 生成 API 报告建议（无任何规则命中时给出默认建议）。
func BuildAPISuggestions(d *APIReportData) []string {
	var out []string
	switch d.ReportType {
	case TypeAPIAsset:
		out = apiAssetSuggestions(d.Asset)
	case TypeAPIRisk:
		out = apiRiskSuggestions(d.Risk)
	case TypeAPIWeak:
		out = apiWeaknessSuggestions(d.Weakness)
	case TypeAPISens:
		out = apiSensitiveSuggestions(d.Sensitive)
	}
	if len(out) == 0 {
		out = append(out, "当前API资产与风险态势良好，建议保持现有学习与防护策略并定期复核。")
	}
	return out
}

// confirmedRate 端点确认率（分母为0时返回0），保证确定性。
func confirmedRate(confirmed, total int64) float64 {
	return pct(confirmed, total)
}

func apiAssetConclusions(r *APIAssetReport) []string {
	if r == nil {
		return nil
	}
	var out []string
	if r.TotalEndpoints == 0 {
		out = append(out, "报告期内未发现API端点资产，请确认网关采集链路已开启。")
		return out
	}
	out = append(out, fmt.Sprintf("截至报告期末共发现API端点%d个，报告期内新增%d个，端点确认率为%.1f%%。",
		r.TotalEndpoints, r.NewEndpoints, confirmedRate(r.Confirmed, r.TotalEndpoints)))
	if r.ShadowOpen > 0 {
		out = append(out, fmt.Sprintf("当前存在%d条未关闭的Shadow API发现，涉及未登记接口仍在对外提供服务。", r.ShadowOpen))
	}
	if r.Zombie > 0 {
		out = append(out, fmt.Sprintf("当前存在%d个僵尸端点（已下线但仍有流量），存在长期暴露风险。", r.Zombie))
	}
	if r.Deprecated > 0 {
		out = append(out, fmt.Sprintf("当前有%d个端点处于已下线状态。", r.Deprecated))
	}
	return out
}

func apiAssetSuggestions(r *APIAssetReport) []string {
	if r == nil {
		return nil
	}
	var out []string
	if r.TotalEndpoints > 0 && confirmedRate(r.Confirmed, r.TotalEndpoints) < 50 {
		out = append(out, fmt.Sprintf("端点确认率仅为%.1f%%，建议资产管理员尽快确认新发现端点的归属与责任人。",
			confirmedRate(r.Confirmed, r.TotalEndpoints)))
	}
	if r.ShadowOpen > 0 {
		out = append(out, fmt.Sprintf("存在%d条未关闭的Shadow API发现，建议核实相关接口是否纳入资产管理与防护基线。", r.ShadowOpen))
	}
	if r.Zombie > 0 {
		out = append(out, fmt.Sprintf("存在%d个僵尸端点，建议推动业务方完成下线清理或在网关侧实施阻断。", r.Zombie))
	}
	return out
}

func apiRiskConclusions(r *APIRiskReport) []string {
	if r == nil {
		return nil
	}
	var out []string
	if r.NewFindings == 0 {
		out = append(out, "报告期内未产生新的API运行时发现。")
	} else {
		out = append(out, fmt.Sprintf("报告期内新增API运行时发现%d条，关闭%d条，当前未关闭%d条。",
			r.NewFindings, r.ClosedFindings, r.OpenFindings))
		if len(r.TypeDist) > 0 {
			top := r.TypeDist[0]
			out = append(out, fmt.Sprintf("%s为报告期内最主要的发现类型，共%d条，占新增发现的%.1f%%。",
				top.Key, top.Value, pct(top.Value, r.NewFindings)))
		}
		if len(r.TopEndpoints) > 0 {
			top := r.TopEndpoints[0]
			out = append(out, fmt.Sprintf("端点 %s %s 风险最为集中，报告期内新增发现%d条（其中高危及以上%d条）。",
				top.Method, top.Path, top.Findings, top.High))
		}
	}
	return out
}

func apiRiskSuggestions(r *APIRiskReport) []string {
	if r == nil {
		return nil
	}
	var out []string
	if r.OpenFindings > 0 && r.NewFindings > 0 && pct(r.ClosedFindings, r.NewFindings) < 50 {
		out = append(out, fmt.Sprintf("报告期内发现关闭率仅为%.1f%%，未关闭发现积压%d条，建议运维管理员及时处置。",
			pct(r.ClosedFindings, r.NewFindings), r.OpenFindings))
	}
	for _, ep := range r.TopEndpoints {
		if ep.High > 0 {
			out = append(out, fmt.Sprintf("端点 %s %s 报告期内新增高危及以上发现%d条，建议优先排查并纳入整改。",
				ep.Method, ep.Path, ep.High))
			break // 仅针对最集中的端点给出一条定向建议
		}
	}
	return out
}

func apiWeaknessConclusions(r *APIWeaknessReport) []string {
	if r == nil {
		return nil
	}
	var out []string
	total := int64(0)
	for _, kv := range r.StatusDist {
		total += kv.Value
	}
	if total == 0 {
		out = append(out, "报告期内无API弱点记录。")
		return out
	}
	out = append(out, fmt.Sprintf("当前累计API弱点%d个，报告期内新派生%d个、完成整改%d个。",
		total, r.NewInRange, r.FixedInRange))
	if r.OverdueOpen > 0 {
		out = append(out, fmt.Sprintf("存在%d个弱点已超过整改期限仍未闭环，整改超期问题突出。", r.OverdueOpen))
	}
	if r.RetestPass+r.RetestFail > 0 {
		out = append(out, fmt.Sprintf("报告期内完成复测%d次（通过%d次、失败%d次）。",
			r.RetestPass+r.RetestFail, r.RetestPass, r.RetestFail))
	}
	return out
}

func apiWeaknessSuggestions(r *APIWeaknessReport) []string {
	if r == nil {
		return nil
	}
	var out []string
	if r.OverdueOpen > 0 {
		out = append(out, fmt.Sprintf("存在%d个超期未闭环弱点，建议督促整改负责人限期完成并安排复测。", r.OverdueOpen))
	}
	if r.RetestFail > 0 {
		out = append(out, fmt.Sprintf("报告期内复测失败%d次，建议复核整改方案的有效性并重新整改。", r.RetestFail))
	}
	if r.FixedInRange > 0 && r.RetestPass+r.RetestFail == 0 {
		out = append(out, fmt.Sprintf("报告期内有%d个弱点标记为已整改但未开展复测，建议及时安排复测验证。", r.FixedInRange))
	}
	return out
}

func apiSensitiveConclusions(r *APISensitiveReport) []string {
	if r == nil {
		return nil
	}
	var out []string
	if r.TotalFields == 0 {
		out = append(out, "报告期内未识别到API敏感数据字段。")
		return out
	}
	out = append(out, fmt.Sprintf("当前累计识别API敏感字段%d个，报告期内新识别%d个。", r.TotalFields, r.NewInRange))
	if len(r.TypeDist) > 0 {
		top := r.TypeDist[0]
		out = append(out, fmt.Sprintf("%s为占比最高的敏感数据类型，共%d个字段，占全部敏感字段的%.1f%%。",
			SensitiveDataTypeName(top.Key), top.Value, pct(top.Value, r.TotalFields)))
	}
	if len(r.TopEndpoints) > 0 {
		top := r.TopEndpoints[0]
		out = append(out, fmt.Sprintf("端点 %s %s 涉敏字段最多（%d个，涉及%d类敏感数据）。",
			top.Method, top.Path, top.Fields, top.Types))
	}
	return out
}

func apiSensitiveSuggestions(r *APISensitiveReport) []string {
	if r == nil {
		return nil
	}
	var out []string
	if len(r.TopEndpoints) > 0 {
		out = append(out, "建议对涉敏端点Top清单逐一确认脱敏规则覆盖情况，未覆盖的接口应尽快配置脱敏策略。")
	}
	if r.NewInRange > 0 {
		out = append(out, fmt.Sprintf("报告期内新识别敏感字段%d个，建议复核相关接口的数据出参是否满足最小化原则。", r.NewInRange))
	}
	return out
}

// BuildCombinedAPIConclusions 合并版 API 结论（主报告 API 安全部分用）：
// 四类数据各自的确定性规则独立评估，每类取首条，按固定顺序拼接（最多 4 条）。
func BuildCombinedAPIConclusions(d *APIReportData) []string {
	var out []string
	if d.Asset != nil {
		if c := apiAssetConclusions(d.Asset); len(c) > 0 {
			out = append(out, c[0])
		}
	}
	if d.Risk != nil {
		if c := apiRiskConclusions(d.Risk); len(c) > 0 {
			out = append(out, c[0])
		}
	}
	if d.Weakness != nil {
		if c := apiWeaknessConclusions(d.Weakness); len(c) > 0 {
			out = append(out, c[0])
		}
	}
	if d.Sensitive != nil {
		if c := apiSensitiveConclusions(d.Sensitive); len(c) > 0 {
			out = append(out, c[0])
		}
	}
	return out
}

// BuildCombinedAPISuggestions 合并版 API 建议：四类数据各自规则独立评估，
// 每类取首条命中建议，按固定顺序拼接（最多 4 条）。
func BuildCombinedAPISuggestions(d *APIReportData) []string {
	var out []string
	if d.Asset != nil {
		if s := apiAssetSuggestions(d.Asset); len(s) > 0 {
			out = append(out, s[0])
		}
	}
	if d.Risk != nil {
		if s := apiRiskSuggestions(d.Risk); len(s) > 0 {
			out = append(out, s[0])
		}
	}
	if d.Weakness != nil {
		if s := apiWeaknessSuggestions(d.Weakness); len(s) > 0 {
			out = append(out, s[0])
		}
	}
	if d.Sensitive != nil {
		if s := apiSensitiveSuggestions(d.Sensitive); len(s) > 0 {
			out = append(out, s[0])
		}
	}
	return out
}
