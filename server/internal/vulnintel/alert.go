package vulnintel

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/systemalerts"
)

// AlertStore 是提醒引擎依赖的存储接口（*Store 实现；单测用内存 fake）。
type AlertStore interface {
	FilterAlerted(ctx context.Context, advisoryIDs []uuid.UUID, tech string) (map[uuid.UUID]bool, error)
	RecordAlerted(ctx context.Context, advisoryIDs []uuid.UUID, tech string, alertID *uuid.UUID) error
	AffectedApps(ctx context.Context, tech string) ([]AppRef, error)
}

// RaiseFunc 是系统告警触发函数（装配层注入 systemalerts.Engine.Raise；
// 本包不直接持有 Engine，便于单测注入捕获）。
type RaiseFunc func(ctx context.Context, req systemalerts.RaiseRequest) (*systemalerts.Alert, error)

// 提醒文案截断（system_alerts.message 列 1000 字符上限，文案预算内组装）。
const (
	alertMaxCVEs = 10
	alertMaxApps = 5
)

// Alerter 是漏洞情报提醒引擎：本批新建情报按订阅技术栈聚合，
// 每个技术栈合并为一条 VULN_INTEL_NEW 系统告警，vuln_alerted 防重复提醒。
type Alerter struct {
	store    AlertStore
	raise    RaiseFunc // nil = 不投递（测试与降级形态；此时不记 vuln_alerted，下轮重试）
	settings SettingsReader
}

// NewAlerter 创建提醒引擎。
func NewAlerter(store AlertStore, settings SettingsReader) *Alerter {
	return &Alerter{store: store, settings: settings}
}

// SetRaiseFunc 注入系统告警触发函数。
func (a *Alerter) SetRaiseFunc(fn RaiseFunc) { a.raise = fn }

// ProcessNew 处理本批新建情报：按订阅技术栈过滤/去重/聚合提醒。
// 返回实际触发提醒的技术栈数。任一技术栈处理失败如实返回错误
// （未记录 vuln_alerted 的条目下轮同步/导入会重新评估，不会漏提醒）。
func (a *Alerter) ProcessNew(ctx context.Context, advisories []Advisory) (int, error) {
	if a.raise == nil || len(advisories) == 0 {
		return 0, nil
	}
	sub := LoadSubscription(ctx, a.settings)
	raised := 0
	for _, tech := range sub.WatchTechs {
		matched := make([]Advisory, 0, len(advisories))
		for _, adv := range advisories {
			if adv.HasTech(tech) && SeverityGte(adv.Severity, sub.MinSeverity) {
				matched = append(matched, adv)
			}
		}
		if len(matched) == 0 {
			continue
		}
		ids := make([]uuid.UUID, len(matched))
		for i, adv := range matched {
			ids[i] = adv.ID
		}
		alerted, err := a.store.FilterAlerted(ctx, ids, tech)
		if err != nil {
			return raised, fmt.Errorf("check alerted for tech %s: %w", tech, err)
		}
		fresh := matched[:0]
		for _, adv := range matched {
			if !alerted[adv.ID] {
				fresh = append(fresh, adv)
			}
		}
		if len(fresh) == 0 {
			continue
		}

		severity := systemalerts.SeverityHigh
		for _, adv := range fresh {
			if adv.Severity == SeverityCritical {
				severity = systemalerts.SeverityCritical
				break
			}
		}
		apps, err := a.store.AffectedApps(ctx, tech)
		if err != nil {
			return raised, fmt.Errorf("load affected apps for tech %s: %w", tech, err)
		}
		techUpper := strings.ToUpper(tech)
		alert, err := a.raise(ctx, systemalerts.RaiseRequest{
			AlertType: systemalerts.TypeVulnIntelNew,
			Component: "vuln_intel:" + tech,
			Title:     fmt.Sprintf("发现 %d 个 %s 相关新漏洞", len(fresh), techUpper),
			Message:   buildAlertMessage(fresh, apps, techUpper, severity),
			Severity:  severity,
		})
		if err != nil {
			return raised, fmt.Errorf("raise vuln intel alert for tech %s: %w", tech, err)
		}
		var alertID *uuid.UUID
		if alert != nil {
			alertID = &alert.ID
		}
		freshIDs := make([]uuid.UUID, len(fresh))
		for i, adv := range fresh {
			freshIDs[i] = adv.ID
		}
		if err := a.store.RecordAlerted(ctx, freshIDs, tech, alertID); err != nil {
			return raised, fmt.Errorf("record alerted for tech %s: %w", tech, err)
		}
		raised++
	}
	return raised, nil
}

// buildAlertMessage 组装提醒文案：最高级别 / CVE 列表 / 发布日期范围 / 受影响应用 / 参考链接。
func buildAlertMessage(fresh []Advisory, apps []AppRef, techUpper, severity string) string {
	cves := make([]string, 0, len(fresh))
	for i, adv := range fresh {
		if i >= alertMaxCVEs {
			cves = append(cves, fmt.Sprintf("等 %d 个", len(fresh)))
			break
		}
		cves = append(cves, adv.CVEID)
	}
	var minPub, maxPub *time.Time
	for _, adv := range fresh {
		if adv.PublishedAt == nil {
			continue
		}
		if minPub == nil || adv.PublishedAt.Before(*minPub) {
			t := *adv.PublishedAt
			minPub = &t
		}
		if maxPub == nil || adv.PublishedAt.After(*maxPub) {
			t := *adv.PublishedAt
			maxPub = &t
		}
	}
	pubRange := "未知"
	if minPub != nil {
		pubRange = minPub.Format("2006-01-02")
		if maxPub != nil && !minPub.Equal(*maxPub) {
			pubRange += " ~ " + maxPub.Format("2006-01-02")
		}
	}
	appSeg := "未标记使用 " + techUpper + " 的应用（请在技术资产映射中维护）"
	if len(apps) > 0 {
		names := make([]string, 0, len(apps))
		for i, app := range apps {
			if i >= alertMaxApps {
				names = append(names, fmt.Sprintf("等 %d 个应用", len(apps)))
				break
			}
			names = append(names, app.Name)
		}
		appSeg = strings.Join(names, "、")
	}
	ref := ""
	for _, adv := range fresh {
		if len(adv.References) > 0 {
			ref = adv.References[0]
			break
		}
	}
	if ref == "" {
		ref = "https://nvd.nist.gov/vuln/detail/" + fresh[0].CVEID
	}
	return fmt.Sprintf("最高级别：%s；CVE 列表：%s；发布日期：%s；受影响应用：%s；参考链接：%s",
		severity, strings.Join(cves, ", "), pubRange, appSeg, ref)
}
