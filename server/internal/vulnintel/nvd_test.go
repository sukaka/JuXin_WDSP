package vulnintel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// nvdFixture 两条 PHP 漏洞 + 一条无 PHP 信号条目（应被确定性提取跳过）。
const nvdFixture = `{
  "resultsPerPage": 3,
  "startIndex": 0,
  "totalResults": 3,
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2024-9001",
        "descriptions": [
          {"lang": "en", "value": "A SQL injection vulnerability in PHP-based admin panel allows remote attackers."},
          {"lang": "zh", "value": "中文描述"}
        ],
        "published": "2026-10-20T10:15:00.000",
        "lastModified": "2026-10-21T08:00:00.000",
        "metrics": {
          "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
          "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}]
        },
        "references": [
          {"url": "https://example.com/advisory-1"},
          {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-9001"}
        ],
        "configurations": [
          {"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:vendor:panel:*:*:*:*:*:*:*:*"}]}]}
        ]
      }
    },
    {
      "cve": {
        "id": "CVE-2024-9002",
        "descriptions": [
          {"lang": "en", "value": "Session fixation in a web framework."}
        ],
        "published": "2026-10-21T03:00:00.000",
        "lastModified": "2026-10-21T09:30:00.000",
        "metrics": {
          "cvssMetricV40": [{"cvssData": {"baseScore": 6.3}}],
          "cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]
        },
        "references": [{"url": "https://example.com/advisory-2"}],
        "configurations": [
          {"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:php:php:8.3.0:*:*:*:*:*:*:*"}]}]}
        ]
      }
    },
    {
      "cve": {
        "id": "CVE-2024-9003",
        "descriptions": [
          {"lang": "en", "value": "Integer overflow in an image codec with no product naming."}
        ],
        "published": "2026-10-21T05:00:00.000",
        "lastModified": "2026-10-21T05:10:00.000",
        "metrics": {},
        "references": [],
        "configurations": []
      }
    }
  ]
}`

// memSyncStore 是同步器单测用内存存储。
type memSyncStore struct {
	mu     sync.Mutex
	state  *SyncState
	byID   map[string]*Advisory
	upsert map[string]int
}

func newMemSyncStore() *memSyncStore {
	return &memSyncStore{byID: map[string]*Advisory{}, upsert: map[string]int{}}
}

func (m *memSyncStore) GetSyncState(_ context.Context, source string) (*SyncState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state == nil {
		return &SyncState{Source: source, Status: SyncStatusIdle}, nil
	}
	cp := *m.state
	return &cp, nil
}

func (m *memSyncStore) SaveSyncState(_ context.Context, st *SyncState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *st
	m.state = &cp
	return nil
}

func (m *memSyncStore) UpsertAdvisory(_ context.Context, a *Advisory, raw json.RawMessage) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upsert[a.CVEID]++
	_, existed := m.byID[a.CVEID]
	cp := *a
	if !existed {
		cp.ID = uuid.New()
	}
	m.byID[a.CVEID] = &cp
	return !existed, nil
}

// newTestSyncer 指向 fake NVD 的同步器（包内测试缝：覆盖硬编码地址与分页限速）。
func newTestSyncer(store *memSyncStore, baseURL string, now time.Time) *Syncer {
	s := NewSyncer(store, nil)
	s.baseURL = baseURL
	s.pageDelay = 0
	s.now = func() time.Time { return now }
	return s
}

// TestMapNVDCVE 解析与 severity/tech 确定性提取。
func TestMapNVDCVE(t *testing.T) {
	var resp nvdResponse
	if err := json.Unmarshal([]byte(nvdFixture), &resp); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if len(resp.Vulnerabilities) != 3 {
		t.Fatalf("fixture 条数 = %d", len(resp.Vulnerabilities))
	}

	// 条目1：描述命中 php；severity 取最高（v31 9.8 > v2 5.0）→ CRITICAL
	a1, err := mapNVDCVE(&resp.Vulnerabilities[0].CVE)
	if err != nil {
		t.Fatalf("mapNVDCVE 条目1: %v", err)
	}
	if a1.Severity != SeverityCritical || a1.CVSSScore == nil || *a1.CVSSScore != 9.8 {
		t.Errorf("条目1 severity/cvss = %s/%v", a1.Severity, a1.CVSSScore)
	}
	if len(a1.TechTags) != 1 || a1.TechTags[0] != "php" {
		t.Errorf("条目1 tech = %v", a1.TechTags)
	}
	if a1.PublishedAt == nil || a1.PublishedAt.Format("2006-01-02 15:04") != "2026-10-20 10:15" {
		t.Errorf("条目1 published = %v", a1.PublishedAt)
	}
	if len(a1.References) != 2 {
		t.Errorf("条目1 references = %v", a1.References)
	}
	if a1.Source != SourceNVD {
		t.Errorf("条目1 source = %q", a1.Source)
	}

	// 条目2：描述无 php 关键词，CPE 命中 php:php；v31 7.5 > v40 6.3 → HIGH
	a2, err := mapNVDCVE(&resp.Vulnerabilities[1].CVE)
	if err != nil {
		t.Fatalf("mapNVDCVE 条目2: %v", err)
	}
	if a2.Severity != SeverityHigh || a2.CVSSScore == nil || *a2.CVSSScore != 7.5 {
		t.Errorf("条目2 severity/cvss = %s/%v", a2.Severity, a2.CVSSScore)
	}
	if len(a2.TechTags) != 1 || a2.TechTags[0] != "php" {
		t.Errorf("条目2 tech（CPE 提取）= %v", a2.TechTags)
	}

	// 条目3：无 php 信号 → tech 提取为空，ValidateAdvisory 拒绝（同步侧跳过）
	if _, err := mapNVDCVE(&resp.Vulnerabilities[2].CVE); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("条目3 应因无技术标签被拒绝: %v", err)
	}
}

// TestSyncerRunFirstAndIncremental 首次窗口 2 天 + 增量窗口回拨 1 小时 + 状态落库。
func TestSyncerRunFirstAndIncremental(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	var gotQuery url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(nvdFixture))
	}))
	defer srv.Close()

	store := newMemSyncStore()
	s := newTestSyncer(store, srv.URL, now)

	res, err := s.Run(context.Background())
	if err != nil {
		t.Fatalf("首次同步: %v", err)
	}
	// 窗口 = 最近 2 天；参数契约（keyword/页大小/起止）
	if got := gotQuery.Get("keywordSearch"); got != "php" {
		t.Errorf("keywordSearch = %q", got)
	}
	if got := gotQuery.Get("pubStartDate"); got != now.Add(-48*time.Hour).Format("2006-01-02T15:04:05.000Z") {
		t.Errorf("首次 pubStartDate = %q", got)
	}
	if got := gotQuery.Get("pubEndDate"); got != now.Format("2006-01-02T15:04:05.000Z") {
		t.Errorf("首次 pubEndDate = %q", got)
	}
	// 3 条 fixture：2 条入库（条目3 无 tech 被跳过）
	if res.Fetched != 2 || res.Upserted != 2 || len(res.NewAdvisories) != 2 {
		t.Errorf("首次结果 fetched/upserted/new = %d/%d/%d", res.Fetched, res.Upserted, len(res.NewAdvisories))
	}
	st, err := store.GetSyncState(context.Background(), SyncSourceNVD)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != SyncStatusSuccess || st.RecordsUpserted != 2 || st.LastWindowEnd == nil || !st.LastWindowEnd.Equal(now) {
		t.Errorf("同步状态 = %+v", st)
	}

	// 二次同步（1 小时后）：窗口 = 上回终点 - 1h；条目按 cve_id 幂等更新，不再是新建
	now2 := now.Add(time.Hour)
	s.now = func() time.Time { return now2 }
	res2, err := s.Run(context.Background())
	if err != nil {
		t.Fatalf("增量同步: %v", err)
	}
	if got := gotQuery.Get("pubStartDate"); got != now.Add(-time.Hour).Format("2006-01-02T15:04:05.000Z") {
		t.Errorf("增量 pubStartDate = %q（期望上回终点回拨 1 小时）", got)
	}
	if len(res2.NewAdvisories) != 0 {
		t.Errorf("重复条目不应再判新建: %d", len(res2.NewAdvisories))
	}
	if store.upsert["CVE-2024-9001"] != 2 {
		t.Errorf("CVE-2024-9001 upsert 次数 = %d", store.upsert["CVE-2024-9001"])
	}
}

// TestSyncerFailureState 同步失败：错误如实返回并落 FAILED 状态（保留上次成功现场）。
func TestSyncerFailureState(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	store := newMemSyncStore()
	// 预置一次成功现场（失败不应覆盖窗口终点）
	successAt := now.Add(-24 * time.Hour)
	if err := store.SaveSyncState(context.Background(), &SyncState{
		Source: SyncSourceNVD, LastSyncAt: &successAt, LastWindowStart: &successAt, LastWindowEnd: &successAt,
		RecordsUpserted: 7, Status: SyncStatusSuccess,
	}); err != nil {
		t.Fatal(err)
	}

	s := newTestSyncer(store, srv.URL, now)
	_, err := s.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("应返回 NVD HTTP 503 错误, got %v", err)
	}
	st, serr := store.GetSyncState(context.Background(), SyncSourceNVD)
	if serr != nil {
		t.Fatal(serr)
	}
	if st.Status != SyncStatusFailed {
		t.Errorf("status = %s, want FAILED", st.Status)
	}
	if !strings.Contains(st.FailureMessage, "HTTP 503") {
		t.Errorf("failure_message = %q", st.FailureMessage)
	}
	if st.LastWindowEnd == nil || !st.LastWindowEnd.Equal(successAt) || st.RecordsUpserted != 7 {
		t.Errorf("失败不应覆盖上次成功现场: %+v", st)
	}
}

// TestSyncerConcurrent 并发同步互斥。
func TestSyncerConcurrent(t *testing.T) {
	store := newMemSyncStore()
	s := newTestSyncer(store, "http://127.0.0.1:1/unreachable", time.Now().UTC())
	if !s.tryEnter() {
		t.Fatal("首次进入临界区失败")
	}
	defer s.leave()
	if _, err := s.Run(context.Background()); !errors.Is(err, ErrSyncRunning) {
		t.Errorf("并发同步应返回 ErrSyncRunning, got %v", err)
	}
}

// TestTruncateRaw raw_json 截断保持合法 JSON。
func TestTruncateRaw(t *testing.T) {
	small := []byte(`{"id":"CVE-2024-1"}`)
	if got := truncateRaw(small, MaxRawBytes); string(got) != string(small) {
		t.Errorf("小载荷不应改写: %s", got)
	}
	big := make([]byte, MaxRawBytes+100)
	for i := range big {
		big[i] = 'a'
	}
	got := truncateRaw(big, MaxRawBytes)
	var parsed map[string]interface{}
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("截断后应为合法 JSON: %v", err)
	}
	if parsed["truncated"] != true {
		t.Errorf("截断标记缺失: %v", parsed)
	}
}
