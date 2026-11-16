package vulnintel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// NVD API 2.0 硬编码地址（在线同步为纯下行，仅访问该白名单地址，不接受任何自定义 URL；
// 安全设计：管理面不开放出站地址配置，杜绝 SSRF 面）。
const NVDBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// 同步参数。
const (
	// SyncSourceNVD 是 vuln_intel_sync_state 的 source 键。
	SyncSourceNVD = "NVD"
	// keywordSearch 固定 php（MVP 只订阅 PHP 场景闭环）。
	nvdKeyword = "php"
	// 首次同步窗口：最近 2 天。
	firstSyncLookback = 48 * time.Hour
	// 增量同步窗口回拨：以上次窗口终点为基准回拨 1 小时防漏（NVD 修订会刷新 lastModified，
	// upsert 幂等吸收重复）。
	syncWindowOverlap = time.Hour
	// NVD 建议无 API Key 时 30 秒 5 次请求：分页间隔取 7 秒留有余量。
	defaultPageDelay = 7 * time.Second
	// 单页大小（NVD 上限 2000）。
	nvdPageSize = 2000
	// 单次同步最大页数保护（异常窗口下防无限翻页）。
	maxSyncPages = 50
)

// nvdTimeLayout 是 NVD 时间戳格式（无时区，按 UTC 解释）。
const nvdTimeLayout = "2006-01-02T15:04:05.000"

// SyncStore 是同步器依赖的存储接口（*Store 实现；单测用内存 fake）。
type SyncStore interface {
	GetSyncState(ctx context.Context, source string) (*SyncState, error)
	SaveSyncState(ctx context.Context, st *SyncState) error
	UpsertAdvisory(ctx context.Context, a *Advisory, raw json.RawMessage) (bool, error)
}

// SyncResult 是一次同步的结果。
type SyncResult struct {
	Source          string     `json:"source"`
	WindowStart     time.Time  `json:"window_start"`
	WindowEnd       time.Time  `json:"window_end"`
	Fetched         int        `json:"fetched"`
	Upserted        int        `json:"upserted"`
	NewAdvisories   []Advisory `json:"-"` // 新建条目（供提醒引擎；不经接口返回）
	RecordsUpserted int        `json:"records_upserted"`
	CompletedAt     time.Time  `json:"completed_at"`
}

// Syncer 是 NVD 漏洞同步器：每日同步 keywordSearch=php 的新发布漏洞。
// baseURL 仅由 NewSyncer 固定为 NVDBaseURL；包内测试可覆盖（fake HTTP 服务端）。
type Syncer struct {
	store     SyncStore
	client    *http.Client
	baseURL   string
	pageDelay time.Duration
	now       func() time.Time

	mu      sync.Mutex
	running bool
}

// NewSyncer 创建同步器（URL 固定 NVD API 2.0；client 为 nil 时用 60s 超时默认客户端）。
func NewSyncer(store SyncStore, client *http.Client) *Syncer {
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	return &Syncer{
		store:     store,
		client:    client,
		baseURL:   NVDBaseURL,
		pageDelay: defaultPageDelay,
		now:       func() time.Time { return time.Now().UTC() },
	}
}

// tryEnter 进入同步临界区（已在同步返回 false）。
func (s *Syncer) tryEnter() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return false
	}
	s.running = true
	return true
}

func (s *Syncer) leave() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running = false
}

// Run 执行一次同步：
//   - 窗口：无历史状态取最近 2 天；否则从上回窗口终点回拨 1 小时至当前；
//   - 分页拉取 keywordSearch=php 漏洞，逐条 upsert（按 cve_id 幂等）；
//   - 成功/失败均如实落 vuln_intel_sync_state（失败不写窗口终点，下轮重试同窗口）；
//   - 已在同步时返回 ErrSyncRunning。
func (s *Syncer) Run(ctx context.Context) (*SyncResult, error) {
	if !s.tryEnter() {
		return nil, ErrSyncRunning
	}
	defer s.leave()

	now := s.now()
	state, err := s.store.GetSyncState(ctx, SyncSourceNVD)
	if err != nil {
		return nil, fmt.Errorf("load sync state: %w", err)
	}
	windowStart := now.Add(-firstSyncLookback)
	if state.LastWindowEnd != nil {
		windowStart = state.LastWindowEnd.Add(-syncWindowOverlap)
	}
	res := &SyncResult{Source: SyncSourceNVD, WindowStart: windowStart, WindowEnd: now}

	fail := func(cause error) (*SyncResult, error) {
		// 失败如实落状态（不刷新窗口终点与完成时刻，保留上次成功现场）
		st := &SyncState{
			Source:         SyncSourceNVD,
			Status:         SyncStatusFailed,
			FailureMessage: truncateRunes(cause.Error(), 500),
		}
		if prev, err := s.store.GetSyncState(ctx, SyncSourceNVD); err == nil {
			st.LastSyncAt = prev.LastSyncAt
			st.LastWindowStart = prev.LastWindowStart
			st.LastWindowEnd = prev.LastWindowEnd
			st.RecordsUpserted = prev.RecordsUpserted
		}
		if err := s.store.SaveSyncState(ctx, st); err != nil {
			slog.Error("save vuln intel sync failure state failed", "error", err)
		}
		return res, cause
	}

	advisories, raws, err := s.fetchAll(ctx, windowStart, now)
	if err != nil {
		return fail(err)
	}
	res.Fetched = len(advisories)
	for i := range advisories {
		isNew, err := s.store.UpsertAdvisory(ctx, &advisories[i], raws[i])
		if err != nil {
			return fail(fmt.Errorf("upsert advisory %s: %w", advisories[i].CVEID, err))
		}
		res.Upserted++
		if isNew {
			res.NewAdvisories = append(res.NewAdvisories, advisories[i])
		}
	}
	res.RecordsUpserted = res.Upserted
	res.CompletedAt = s.now()

	if err := s.store.SaveSyncState(ctx, &SyncState{
		Source:          SyncSourceNVD,
		LastSyncAt:      &res.CompletedAt,
		LastWindowStart: &windowStart,
		LastWindowEnd:   &now,
		RecordsUpserted: res.Upserted,
		Status:          SyncStatusSuccess,
	}); err != nil {
		return fail(fmt.Errorf("save sync state: %w", err))
	}
	return res, nil
}

// RunDaily 每日同步循环：每轮先判定 sync_enabled 开关（settings 热读，界面即时生效），
// 开启才执行同步；启动后 1 分钟首轮（避让启动期），之后每 24 小时一轮。
// 单轮失败仅记日志（失败原因已由 Run 如实落 vuln_intel_sync_state），ctx 取消即退出。
// enabled 为 nil 时视为恒开启（测试注入缝）。
func (s *Syncer) RunDaily(ctx context.Context, enabled func(context.Context) bool) {
	timer := time.NewTimer(time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if enabled == nil || enabled(ctx) {
			if _, err := s.Run(ctx); err != nil && !errors.Is(err, ErrSyncRunning) {
				slog.Warn("vuln intel daily sync failed", "error", err)
			}
		}
		timer.Reset(24 * time.Hour)
	}
}

// fetchAll 分页拉取窗口内 PHP 相关漏洞并解析（页间限速）。
func (s *Syncer) fetchAll(ctx context.Context, start, end time.Time) ([]Advisory, []json.RawMessage, error) {
	var out []Advisory
	var raws []json.RawMessage
	startIndex := 0
	for page := 0; ; page++ {
		if page > 0 {
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(s.pageDelay):
			}
		}
		if page >= maxSyncPages {
			return nil, nil, fmt.Errorf("NVD 同步分页超过保护上限 %d 页，已中止", maxSyncPages)
		}
		body, err := s.fetchPage(ctx, start, end, startIndex)
		if err != nil {
			return nil, nil, err
		}
		var resp nvdResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, nil, fmt.Errorf("parse NVD response: %w", err)
		}
		for _, v := range resp.Vulnerabilities {
			raw, _ := json.Marshal(v.CVE)
			adv, err := mapNVDCVE(&v.CVE)
			if err != nil {
				slog.Warn("skip malformed NVD entry", "cve_id", v.CVE.ID, "error", err)
				continue
			}
			out = append(out, *adv)
			raws = append(raws, truncateRaw(raw, MaxRawBytes))
		}
		startIndex += len(resp.Vulnerabilities)
		if startIndex >= resp.TotalResults || len(resp.Vulnerabilities) == 0 {
			break
		}
	}
	return out, raws, nil
}

// fetchPage 拉取单页（pubStartDate/pubEndDate 闭区间，格式含毫秒与 Z 时区——NVD 强校验）。
func (s *Syncer) fetchPage(ctx context.Context, start, end time.Time, startIndex int) ([]byte, error) {
	u, err := url.Parse(s.baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid NVD base url: %w", err)
	}
	q := u.Query()
	q.Set("keywordSearch", nvdKeyword)
	q.Set("pubStartDate", start.UTC().Format("2006-01-02T15:04:05.000Z"))
	q.Set("pubEndDate", end.UTC().Format("2006-01-02T15:04:05.000Z"))
	q.Set("resultsPerPage", strconv.Itoa(nvdPageSize))
	q.Set("startIndex", strconv.Itoa(startIndex))
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "jiuzhang-wdsp-vuln-intel/1.0")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("NVD 请求失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("NVD 返回 HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, fmt.Errorf("read NVD response: %w", err)
	}
	return body, nil
}

// ---------- NVD 响应解析（确定性提取） ----------

type nvdResponse struct {
	ResultsPerPage  int                `json:"resultsPerPage"`
	StartIndex      int                `json:"startIndex"`
	TotalResults    int                `json:"totalResults"`
	Vulnerabilities []nvdVulnerability `json:"vulnerabilities"`
}

type nvdVulnerability struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID           string `json:"id"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	Metrics      struct {
		CvssMetricV40 []nvdCvssMetric `json:"cvssMetricV40"`
		CvssMetricV31 []nvdCvssMetric `json:"cvssMetricV31"`
		CvssMetricV30 []nvdCvssMetric `json:"cvssMetricV30"`
		CvssMetricV2  []nvdCvssMetric `json:"cvssMetricV2"`
	} `json:"metrics"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
	Configurations []struct {
		Nodes []struct {
			CPEMatch []struct {
				Criteria string `json:"criteria"`
			} `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
}

type nvdCvssMetric struct {
	CvssData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}

// mapNVDCVE 把 NVD CVE 条目映射为 Advisory（source=NVD）。
// 技术标签确定性提取：英文描述命中 php 关键词（大小写不敏感）或 CPE 命中
// cpe:2.3:a:php:php → tech=php；severity 取全部 CVSS 指标的最高分值派生。
func mapNVDCVE(c *nvdCVE) (*Advisory, error) {
	summary := ""
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			summary = d.Value
			break
		}
	}
	if summary == "" && len(c.Descriptions) > 0 {
		summary = c.Descriptions[0].Value
	}

	var published, modified *time.Time
	if t, err := time.Parse(nvdTimeLayout, c.Published); err == nil {
		t = t.UTC()
		published = &t
	}
	if t, err := time.Parse(nvdTimeLayout, c.LastModified); err == nil {
		t = t.UTC()
		modified = &t
	}

	refs := make([]string, 0, len(c.References))
	for _, r := range c.References {
		if r.URL != "" {
			refs = append(refs, r.URL)
		}
	}

	var cpes []string
	for _, cfg := range c.Configurations {
		for _, n := range cfg.Nodes {
			for _, m := range n.CPEMatch {
				cpes = append(cpes, m.Criteria)
			}
		}
	}

	maxScore := -1.0
	for _, group := range [][]nvdCvssMetric{
		c.Metrics.CvssMetricV40, c.Metrics.CvssMetricV31, c.Metrics.CvssMetricV30, c.Metrics.CvssMetricV2,
	} {
		for _, m := range group {
			if m.CvssData.BaseScore > maxScore {
				maxScore = m.CvssData.BaseScore
			}
		}
	}
	severity := SeverityNone
	var score *float64
	if maxScore >= 0 {
		severity = SeverityFromScore(maxScore)
		v := maxScore
		score = &v
	}

	a := &Advisory{
		CVEID:          c.ID,
		Title:          c.ID,
		Summary:        summary,
		Severity:       severity,
		CVSSScore:      score,
		PublishedAt:    published,
		LastModifiedAt: modified,
		TechTags:       ExtractTechTags(summary, cpes),
		References:     refs,
		Source:         SourceNVD,
	}
	if err := ValidateAdvisory(a); err != nil {
		return nil, err
	}
	return a, nil
}

// ExtractTechTags 确定性技术标签提取（MVP 仅 php 一条规则）：
// 描述命中 php 关键词（大小写不敏感子串）或任一 CPE 以 cpe:2.3:a:php:php 开头。
func ExtractTechTags(description string, cpes []string) []string {
	if strings.Contains(strings.ToLower(description), "php") {
		return []string{"php"}
	}
	for _, cpe := range cpes {
		if strings.HasPrefix(strings.ToLower(cpe), "cpe:2.3:a:php:php") {
			return []string{"php"}
		}
	}
	return nil
}

// truncateRaw 截断 raw_json：超长时改写为 {"truncated":true,"prefix":...} 结构，
// 保证落库的始终是合法 JSON（直接截断字节会产生非法 JSON 被 JSONB 拒收；
// 截断点的非法 UTF-8 由 json.Marshal 归一为 U+FFFD）。
func truncateRaw(raw []byte, n int) json.RawMessage {
	if len(raw) <= n {
		return json.RawMessage(raw)
	}
	out, err := json.Marshal(map[string]interface{}{
		"truncated": true,
		"prefix":    string(raw[:n]),
	})
	if err != nil {
		return nil
	}
	return json.RawMessage(out)
}

// truncateRunes 按 rune 截断字符串（失败消息上限，避免截断多字节字符）。
func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
