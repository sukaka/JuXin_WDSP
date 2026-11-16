package vulnintel

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/systemalerts"
)

// memAlertStore 是提醒引擎单测用内存存储。
type memAlertStore struct {
	alerted     map[string]bool // advisoryID|tech
	recorded    []string
	recordAlert *uuid.UUID
	apps        map[string][]AppRef
	filterErr   error
	recordErr   error
	appsErr     error
}

func newMemAlertStore() *memAlertStore {
	return &memAlertStore{alerted: map[string]bool{}, apps: map[string][]AppRef{}}
}

func (m *memAlertStore) FilterAlerted(_ context.Context, ids []uuid.UUID, tech string) (map[uuid.UUID]bool, error) {
	if m.filterErr != nil {
		return nil, m.filterErr
	}
	out := map[uuid.UUID]bool{}
	for _, id := range ids {
		if m.alerted[id.String()+"|"+tech] {
			out[id] = true
		}
	}
	return out, nil
}

func (m *memAlertStore) RecordAlerted(_ context.Context, ids []uuid.UUID, tech string, alertID *uuid.UUID) error {
	if m.recordErr != nil {
		return m.recordErr
	}
	for _, id := range ids {
		m.alerted[id.String()+"|"+tech] = true
		m.recorded = append(m.recorded, id.String()+"|"+tech)
	}
	m.recordAlert = alertID
	return nil
}

func (m *memAlertStore) AffectedApps(_ context.Context, tech string) ([]AppRef, error) {
	if m.appsErr != nil {
		return nil, m.appsErr
	}
	return m.apps[tech], nil
}

// memSettings 是单测用设置源。
type memSettings struct {
	strs  map[string]string
	bools map[string]bool
}

func (m *memSettings) GetString(_ context.Context, group, key, def string) string {
	if v, ok := m.strs[group+":"+key]; ok {
		return v
	}
	return def
}

func (m *memSettings) GetBool(_ context.Context, group, key string, def bool) bool {
	if v, ok := m.bools[group+":"+key]; ok {
		return v
	}
	return def
}

// raiseCapture 捕获 Raise 调用。
type raiseCapture struct {
	reqs  []systemalerts.RaiseRequest
	err   error
	alert *systemalerts.Alert
}

func (c *raiseCapture) raise(_ context.Context, req systemalerts.RaiseRequest) (*systemalerts.Alert, error) {
	if c.err != nil {
		return nil, c.err
	}
	c.reqs = append(c.reqs, req)
	if c.alert != nil {
		return c.alert, nil
	}
	return &systemalerts.Alert{ID: uuid.New()}, nil
}

func adv(cve string, sev string, techs ...string) Advisory {
	t := time.Date(2026, 10, 21, 8, 0, 0, 0, time.UTC)
	return Advisory{
		ID:          uuid.New(),
		CVEID:       cve,
		Title:       cve,
		Severity:    sev,
		PublishedAt: &t,
		TechTags:    techs,
		References:  []string{"https://example.com/" + cve},
		Source:      SourceNVD,
	}
}

func TestAlerterProcessNew(t *testing.T) {
	store := newMemAlertStore()
	appID := uuid.New()
	store.apps["php"] = []AppRef{{ID: appID, Code: "shop", Name: "商城门户"}}
	settings := &memSettings{strs: map[string]string{}, bools: map[string]bool{}}
	capture := &raiseCapture{}
	a := NewAlerter(store, settings)
	a.SetRaiseFunc(capture.raise)

	// 3 条新建：CRITICAL + HIGH + LOW（LOW 低于默认 min_severity=HIGH 不提醒）
	fresh := []Advisory{
		adv("CVE-2026-0001", SeverityCritical, "php"),
		adv("CVE-2026-0002", SeverityHigh, "php"),
		adv("CVE-2026-0003", SeverityLow, "php"),
		adv("CVE-2026-0004", SeverityCritical, "nodejs"), // 非订阅技术栈
	}
	raised, err := a.ProcessNew(context.Background(), fresh)
	if err != nil {
		t.Fatalf("ProcessNew: %v", err)
	}
	if raised != 1 {
		t.Fatalf("raised = %d, want 1（按技术栈聚合）", raised)
	}
	if len(capture.reqs) != 1 {
		t.Fatalf("Raise 次数 = %d", len(capture.reqs))
	}
	req := capture.reqs[0]
	if req.AlertType != systemalerts.TypeVulnIntelNew {
		t.Errorf("AlertType = %q", req.AlertType)
	}
	if req.Component != "vuln_intel:php" {
		t.Errorf("Component = %q", req.Component)
	}
	if req.Severity != systemalerts.SeverityCritical {
		t.Errorf("含 CRITICAL 应升 CRITICAL, got %s", req.Severity)
	}
	if !strings.Contains(req.Title, "发现 2 个 PHP 相关新漏洞") {
		t.Errorf("Title = %q", req.Title)
	}
	for _, want := range []string{"CVE-2026-0001", "CVE-2026-0002", "最高级别：CRITICAL",
		"发布日期：2026-10-21", "商城门户", "https://example.com/CVE-2026-0001"} {
		if !strings.Contains(req.Message, want) {
			t.Errorf("Message 缺少 %q\n%s", want, req.Message)
		}
	}
	if strings.Contains(req.Message, "CVE-2026-0003") {
		t.Errorf("低于 min_severity 的 CVE 不应出现\n%s", req.Message)
	}
	// 只记录 2 条 php 达标条目
	if len(store.recorded) != 2 {
		t.Errorf("vuln_alerted 记录 = %v", store.recorded)
	}
	if store.recordAlert == nil {
		t.Error("vuln_alerted 应携带 alert_id")
	}

	// 重复处理同批：vuln_alerted 去重 → 不再 Raise
	raised2, err := a.ProcessNew(context.Background(), fresh)
	if err != nil {
		t.Fatalf("ProcessNew 重复: %v", err)
	}
	if raised2 != 0 || len(capture.reqs) != 1 {
		t.Errorf("重复提醒应被去重: raised=%d raise=%d", raised2, len(capture.reqs))
	}
}

func TestAlerterSeverityAndSubscription(t *testing.T) {
	// 无 CRITICAL → HIGH；min_severity=CRITICAL 时 HIGH 条目不提醒
	store := newMemAlertStore()
	settings := &memSettings{strs: map[string]string{}, bools: map[string]bool{}}
	capture := &raiseCapture{}
	a := NewAlerter(store, settings)
	a.SetRaiseFunc(capture.raise)

	fresh := []Advisory{adv("CVE-2026-0010", SeverityHigh, "php"), adv("CVE-2026-0011", SeverityMedium, "php")}
	if _, err := a.ProcessNew(context.Background(), fresh); err != nil {
		t.Fatal(err)
	}
	if capture.reqs[0].Severity != systemalerts.SeverityHigh {
		t.Errorf("无 CRITICAL 应落 HIGH, got %s", capture.reqs[0].Severity)
	}

	// 调高门槛到 CRITICAL：仅剩 HIGH/MEDIUM → 不提醒
	settings.strs[SettingsGroup+":"+KeyMinSeverity] = "CRITICAL"
	raised, err := a.ProcessNew(context.Background(), []Advisory{adv("CVE-2026-0012", SeverityHigh, "php")})
	if err != nil {
		t.Fatal(err)
	}
	if raised != 0 {
		t.Errorf("min_severity=CRITICAL 时 HIGH 不应提醒: raised=%d", raised)
	}

	// 订阅多技术栈：按技术栈分别聚合
	settings.strs[SettingsGroup+":"+KeyMinSeverity] = "LOW"
	settings.strs[SettingsGroup+":"+KeyWatchTechs] = "php,nodejs"
	raised, err = a.ProcessNew(context.Background(), []Advisory{
		adv("CVE-2026-0020", SeverityHigh, "nodejs"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if raised != 1 || capture.reqs[len(capture.reqs)-1].Component != "vuln_intel:nodejs" {
		t.Errorf("nodejs 订阅聚合错误: raised=%d reqs=%+v", raised, capture.reqs)
	}
	// 未标记应用时文案兜底
	if !strings.Contains(capture.reqs[len(capture.reqs)-1].Message, "未标记使用 NODEJS 的应用") {
		t.Errorf("无映射应用时应给出兜底文案\n%s", capture.reqs[len(capture.reqs)-1].Message)
	}
}

func TestAlerterFailurePaths(t *testing.T) {
	// Raise 失败：错误如实返回且不记 vuln_alerted（下轮重试不漏提醒）
	store := newMemAlertStore()
	settings := &memSettings{strs: map[string]string{}, bools: map[string]bool{}}
	capture := &raiseCapture{err: errors.New("engine down")}
	a := NewAlerter(store, settings)
	a.SetRaiseFunc(capture.raise)

	_, err := a.ProcessNew(context.Background(), []Advisory{adv("CVE-2026-0100", SeverityHigh, "php")})
	if err == nil || !strings.Contains(err.Error(), "engine down") {
		t.Errorf("Raise 失败应返回错误: %v", err)
	}
	if len(store.recorded) != 0 {
		t.Errorf("Raise 失败不应记录 vuln_alerted: %v", store.recorded)
	}

	// raise=nil（未注入）：不提醒也不报错
	a2 := NewAlerter(newMemAlertStore(), settings)
	raised, err := a2.ProcessNew(context.Background(), []Advisory{adv("CVE-2026-0101", SeverityCritical, "php")})
	if err != nil || raised != 0 {
		t.Errorf("raise=nil 应跳过: raised=%d err=%v", raised, err)
	}
}

func TestLoadSubscriptionDefaults(t *testing.T) {
	settings := &memSettings{strs: map[string]string{}, bools: map[string]bool{}}
	sub := LoadSubscription(context.Background(), settings)
	if len(sub.WatchTechs) != 1 || sub.WatchTechs[0] != "php" {
		t.Errorf("默认 watch_techs = %v", sub.WatchTechs)
	}
	if sub.MinSeverity != SeverityHigh || sub.SyncEnabled {
		t.Errorf("默认 min_severity/sync_enabled = %s/%v", sub.MinSeverity, sub.SyncEnabled)
	}
	// DB 值为非法词表时回落默认（防御性）
	settings.strs[SettingsGroup+":"+KeyMinSeverity] = "P0"
	if sub := LoadSubscription(context.Background(), settings); sub.MinSeverity != SeverityHigh {
		t.Errorf("非法 min_severity 应回落 HIGH: %s", sub.MinSeverity)
	}
}
