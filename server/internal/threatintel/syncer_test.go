package threatintel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/protectedaddresses"
)

type memFeedRepo struct {
	mu          sync.Mutex
	feeds       map[uuid.UUID]*Feed
	runs        []SyncRun
	activeCount map[string]int
}

func newMemFeedRepo(seed ...*Feed) *memFeedRepo {
	m := &memFeedRepo{
		feeds:       map[uuid.UUID]*Feed{},
		activeCount: map[string]int{},
	}
	now := time.Now().UTC()
	for _, f := range seed {
		cp := *f
		if cp.ID == uuid.Nil {
			cp.ID = uuid.New()
		}
		if cp.LastStatus == "" {
			cp.LastStatus = RunStatusIdle
		}
		if cp.CreatedAt.IsZero() {
			cp.CreatedAt = now
		}
		if cp.UpdatedAt.IsZero() {
			cp.UpdatedAt = now
		}
		m.feeds[cp.ID] = &cp
		m.activeCount[cp.FeedKey] = cp.ActiveRuleCount
	}
	return m
}

func (m *memFeedRepo) ListFeeds(context.Context) ([]Feed, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Feed, 0, len(m.feeds))
	for _, f := range m.feeds {
		out = append(out, *f)
	}
	// Deterministic order: builtin first, then feed_key asc
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			swap := false
			if out[i].IsBuiltin != out[j].IsBuiltin {
				swap = !out[i].IsBuiltin && out[j].IsBuiltin
			} else if out[i].FeedKey > out[j].FeedKey {
				swap = true
			}
			if swap {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out, nil
}

func (m *memFeedRepo) GetFeed(_ context.Context, id uuid.UUID) (*Feed, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.feeds[id]
	if !ok {
		return nil, ErrFeedNotFound
	}
	cp := *f
	return &cp, nil
}

func (m *memFeedRepo) GetFeedByKey(_ context.Context, feedKey string) (*Feed, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := strings.ToLower(strings.TrimSpace(feedKey))
	for _, f := range m.feeds {
		if f.FeedKey == key {
			cp := *f
			return &cp, nil
		}
	}
	return nil, ErrFeedNotFound
}

func (m *memFeedRepo) CreateFeed(_ context.Context, feed *Feed) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, f := range m.feeds {
		if f.FeedKey == feed.FeedKey {
			return ErrFeedKeyConflict
		}
	}
	if feed.ID == uuid.Nil {
		feed.ID = uuid.New()
	}
	now := time.Now().UTC()
	feed.IsBuiltin = false
	feed.CreatedAt = now
	feed.UpdatedAt = now
	if feed.LastStatus == "" {
		feed.LastStatus = RunStatusIdle
	}
	cp := *feed
	m.feeds[cp.ID] = &cp
	return nil
}

func (m *memFeedRepo) UpdateFeed(_ context.Context, feed *Feed) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.feeds[feed.ID]
	if !ok {
		return ErrFeedNotFound
	}
	cp := *feed
	cp.FeedKey = cur.FeedKey
	cp.IsBuiltin = cur.IsBuiltin
	cp.CreatedAt = cur.CreatedAt
	cp.UpdatedAt = time.Now().UTC()
	feed.UpdatedAt = cp.UpdatedAt
	m.feeds[cp.ID] = &cp
	return nil
}

func (m *memFeedRepo) DeleteFeed(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.feeds[id]
	if !ok {
		return ErrFeedNotFound
	}
	if cur.IsBuiltin {
		return ErrBuiltinProtected
	}
	delete(m.feeds, id)
	return nil
}

func (m *memFeedRepo) UpdateFeedSyncResult(_ context.Context, u FeedSyncUpdate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.feeds[u.ID]
	if !ok {
		return ErrFeedNotFound
	}
	if u.UpdateCacheHeaders {
		f.ETag = u.ETag
		f.LastModified = u.LastModified
		f.LastContentSHA256 = u.LastContentSHA256
	}
	if u.UpdateActiveCount {
		f.ActiveRuleCount = u.ActiveRuleCount
	}
	if u.UpdateCircuit {
		f.ConsecutiveFailures = u.ConsecutiveFailures
		f.CircuitOpen = u.CircuitOpen
	}
	t := u.LastSyncAt
	if t.IsZero() {
		t = time.Now().UTC()
	}
	f.LastSyncAt = &t
	f.LastStatus = u.LastStatus
	f.LastError = u.LastError
	f.UpdatedAt = t
	return nil
}

func (m *memFeedRepo) CountActiveFeedRules(_ context.Context, feedKey string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.activeCount[strings.ToLower(strings.TrimSpace(feedKey))], nil
}

func (m *memFeedRepo) InsertRun(_ context.Context, run *SyncRun) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *run
	if cp.ID == uuid.Nil {
		cp.ID = uuid.New()
	}
	run.ID = cp.ID
	m.runs = append([]SyncRun{cp}, m.runs...)
	return nil
}

func (m *memFeedRepo) ListRuns(_ context.Context, f RunFilter) ([]SyncRun, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var filtered []SyncRun
	for _, r := range m.runs {
		if f.FeedKey != "" && r.FeedKey != strings.ToLower(f.FeedKey) {
			continue
		}
		if f.TriggerType != "" && r.TriggerType != strings.ToUpper(f.TriggerType) {
			continue
		}
		if f.Status != "" && r.Status != strings.ToUpper(f.Status) {
			continue
		}
		filtered = append(filtered, r)
	}
	total := int64(len(filtered))
	page := f.Page
	if page <= 0 {
		page = 1
	}
	pageSize := f.PageSize
	if pageSize <= 0 {
		pageSize = 20
	}
	start := (page - 1) * pageSize
	if start >= len(filtered) {
		return []SyncRun{}, total, nil
	}
	end := start + pageSize
	if end > len(filtered) {
		end = len(filtered)
	}
	return filtered[start:end], total, nil
}

type fakeReconciler struct {
	mu       sync.Mutex
	calls    []ImportInput
	rules    map[string]map[string]bool
	repo     *memFeedRepo
	forceErr error
}

func newFakeReconciler(repo *memFeedRepo) *fakeReconciler {
	return &fakeReconciler{
		rules: map[string]map[string]bool{},
		repo:  repo,
	}
}

func (r *fakeReconciler) Import(_ context.Context, in ImportInput) (*Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.forceErr != nil {
		return nil, r.forceErr
	}
	r.calls = append(r.calls, in)
	if r.rules[in.Feed] == nil {
		r.rules[in.Feed] = map[string]bool{}
	}
	cur := r.rules[in.Feed]
	next := map[string]bool{}
	res := &Result{
		BatchID:   "batch-" + in.Feed + "-" + fmt.Sprintf("%d", len(r.calls)),
		Feed:      in.Feed,
		TTLDays:   in.TTLDays,
		Conflicts: []ConflictItem{},
	}
	for _, e := range in.Entries {
		next[e.IP] = true
		if cur[e.IP] {
			res.Refreshed++
		} else {
			res.Added++
		}
	}
	for ip := range cur {
		if !next[ip] {
			res.Expired++
		}
	}
	r.rules[in.Feed] = next
	if r.repo != nil {
		r.repo.mu.Lock()
		r.repo.activeCount[in.Feed] = len(next)
		r.repo.mu.Unlock()
	}
	return res, nil
}

type fakeDownloader struct {
	mu       sync.Mutex
	requests []FeedFetchRequest
	fn       func(ctx context.Context, req FeedFetchRequest) (*FeedFetchResponse, error)
}

func (d *fakeDownloader) Fetch(ctx context.Context, req FeedFetchRequest) (*FeedFetchResponse, error) {
	d.mu.Lock()
	d.requests = append(d.requests, req)
	fn := d.fn
	d.mu.Unlock()
	return fn(ctx, req)
}

type fakeSettingsReader struct {
	autoUpdate bool
	threshold  int
}

func (s *fakeSettingsReader) GetBool(_ context.Context, _, _ string, def bool) bool {
	if s == nil {
		return def
	}
	return s.autoUpdate
}

func (s *fakeSettingsReader) GetInt(_ context.Context, _, _ string, def int) int {
	if s == nil || s.threshold == 0 {
		return def
	}
	return s.threshold
}

type recordedAlert struct {
	AlertType string
	Component string
	Title     string
	Message   string
}

func TestOfficialPresets_CC0OnlyNoGPL(t *testing.T) {
	presets := OfficialPresets()
	if len(presets) != 2 {
		t.Fatalf("expected exactly 2 CC0 official presets, got %d: %+v", len(presets), presets)
	}
	keys := map[string]OfficialPreset{}
	for _, p := range presets {
		keys[p.Key] = p
		if p.License != "CC0-1.0" {
			t.Errorf("preset %s license=%q, want CC0-1.0", p.Key, p.License)
		}
		lower := strings.ToLower(p.Key + " " + p.Name + " " + p.URL)
		if strings.Contains(lower, "firehol") || strings.Contains(lower, "gpl") {
			t.Errorf("forbidden GPL/FireHOL preset detected: %+v", p)
		}
	}
	if keys["feodo"].URL != "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt" {
		t.Errorf("unexpected feodo URL: %s", keys["feodo"].URL)
	}
	if keys["sslbl"].URL != "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt" {
		t.Errorf("unexpected sslbl URL: %s", keys["sslbl"].URL)
	}
}

func TestCronSchedule_ParseAndMatch(t *testing.T) {
	spec, err := ParseCron("0 */6 * * *")
	if err != nil {
		t.Fatalf("ParseCron: %v", err)
	}
	if !spec.Match(time.Date(2026, 11, 28, 6, 0, 0, 0, time.UTC)) {
		t.Fatal("06:00 should match 0 */6 * * *")
	}
	if spec.Match(time.Date(2026, 11, 28, 6, 1, 0, 0, time.UTC)) {
		t.Fatal("06:01 should not match 0 */6 * * *")
	}
	if spec.Match(time.Date(2026, 11, 28, 7, 0, 0, 0, time.UTC)) {
		t.Fatal("07:00 should not match 0 */6 * * *")
	}

	if err := ValidateCron("@daily"); err != nil {
		t.Fatalf("@daily should be valid: %v", err)
	}
	for _, bad := range []string{"", "* * *", "60 * * * *", "0 0 30 2 *", "bad cron expr"} {
		if err := ValidateCron(bad); err == nil {
			t.Errorf("expected ValidateCron(%q) error", bad)
		}
	}
}

func TestSyncer_ConditionalGetAndSHA256Shortcut(t *testing.T) {
	body := []byte("192.0.2.10\n198.51.100.20\n")
	sum := sha256.Sum256(body)
	bodySHA := hex.EncodeToString(sum[:])

	feed := &Feed{
		ID:                uuid.New(),
		FeedKey:           "feodo",
		Name:              "Feodo",
		IsBuiltin:         true,
		Enabled:           true,
		SourceMode:        SourceModeOfficial,
		OfficialPreset:    "feodo",
		Format:            "text",
		TTLDays:           30,
		ScheduleCron:      "0 */6 * * *",
		MinEntriesGuard:   true,
		MaxDropRatio:      0.80,
		ETag:              `"etag-v1"`,
		LastModified:      "Sat, 28 Nov 2026 00:00:00 GMT",
		LastContentSHA256: bodySHA,
		ActiveRuleCount:   2,
	}
	repo := newMemFeedRepo(feed)
	rec := newFakeReconciler(repo)
	pubCount := 0

	// 1. 304 Not Modified shortcut
	dl := &fakeDownloader{
		fn: func(_ context.Context, req FeedFetchRequest) (*FeedFetchResponse, error) {
			if req.ETag != `"etag-v1"` || req.LastModified != "Sat, 28 Nov 2026 00:00:00 GMT" {
				t.Errorf("expected conditional headers, got %+v", req)
			}
			return &FeedFetchResponse{NotModified: true, StatusCode: 304}, nil
		},
	}
	syncer := NewSyncer(repo, rec, dl, &fakeSettingsReader{threshold: 5}).
		SetPublishFunc(func(context.Context, uuid.UUID, string) { pubCount++ })

	res, err := syncer.SyncFeed(context.Background(), feed.ID, SyncOptions{TriggerType: TriggerManual})
	if err != nil {
		t.Fatalf("SyncFeed 304: %v", err)
	}
	if res.Run.Status != RunStatusSkippedNotModified {
		t.Fatalf("status=%s, want SKIPPED_NOT_MODIFIED", res.Run.Status)
	}
	if len(rec.calls) != 0 || pubCount != 0 {
		t.Fatalf("expected 0 reconcile calls and 0 publishes on 304, got rec=%d pub=%d", len(rec.calls), pubCount)
	}

	// 2. 200 OK with identical SHA-256 shortcut
	dl.fn = func(_ context.Context, _ FeedFetchRequest) (*FeedFetchResponse, error) {
		return &FeedFetchResponse{Body: body, ETag: `"etag-v2"`, StatusCode: 200}, nil
	}
	res2, err := syncer.SyncFeed(context.Background(), feed.ID, SyncOptions{TriggerType: TriggerManual})
	if err != nil {
		t.Fatalf("SyncFeed sha shortcut: %v", err)
	}
	if res2.Run.Status != RunStatusSkippedNotModified {
		t.Fatalf("status=%s, want SKIPPED_NOT_MODIFIED", res2.Run.Status)
	}
	if len(rec.calls) != 0 || pubCount != 0 {
		t.Fatalf("expected 0 reconcile calls and 0 publishes on SHA shortcut, got rec=%d pub=%d", len(rec.calls), pubCount)
	}
}

func TestSyncer_MinEntriesGuardAbortsAndAlerts(t *testing.T) {
	feed := &Feed{
		ID:              uuid.New(),
		FeedKey:         "feodo",
		Name:            "Feodo",
		Enabled:         true,
		SourceMode:      SourceModeOfficial,
		OfficialPreset:  "feodo",
		Format:          "text",
		TTLDays:         30,
		ScheduleCron:    "0 */6 * * *",
		MinEntriesGuard: true,
		MaxDropRatio:    0.80,
		ActiveRuleCount: 5,
	}
	repo := newMemFeedRepo(feed)
	rec := newFakeReconciler(repo)
	dl := &fakeDownloader{
		fn: func(_ context.Context, _ FeedFetchRequest) (*FeedFetchResponse, error) {
			return &FeedFetchResponse{Body: []byte("# empty feed\n; nothing valid\n"), StatusCode: 200}, nil
		},
	}
	var alerts []recordedAlert
	pubCount := 0
	syncer := NewSyncer(repo, rec, dl, &fakeSettingsReader{threshold: 5}).
		SetPublishFunc(func(context.Context, uuid.UUID, string) { pubCount++ }).
		SetAlertFunc(func(_ context.Context, typ, comp, title, msg string) {
			alerts = append(alerts, recordedAlert{typ, comp, title, msg})
		})

	res, err := syncer.SyncFeed(context.Background(), feed.ID, SyncOptions{TriggerType: TriggerManual})
	if err != nil {
		t.Fatalf("SyncFeed: %v", err)
	}
	if !res.GuardTriggered || res.Run.Status != RunStatusGuardAborted {
		t.Fatalf("expected GUARD_ABORTED, got %+v", res)
	}
	if len(rec.calls) != 0 || pubCount != 0 {
		t.Fatalf("must not reconcile or publish when min_entries_guard aborts")
	}
	if len(alerts) != 1 || alerts[0].AlertType != AlertTypeSyncFailed {
		t.Fatalf("expected 1 THREAT_INTEL_SYNC_FAILED alert, got %+v", alerts)
	}
	updated, _ := repo.GetFeed(context.Background(), feed.ID)
	if updated.ActiveRuleCount != 5 {
		t.Fatalf("active_rule_count=%d, want 5 preserved", updated.ActiveRuleCount)
	}
}

func TestSyncer_MaxDropRatioGuardAndForceOverride(t *testing.T) {
	feed := &Feed{
		ID:              uuid.New(),
		FeedKey:         "sslbl",
		Name:            "SSLBL",
		Enabled:         true,
		SourceMode:      SourceModeOfficial,
		OfficialPreset:  "sslbl",
		Format:          "text",
		TTLDays:         30,
		ScheduleCron:    "0 */6 * * *",
		MinEntriesGuard: true,
		MaxDropRatio:    0.80,
		ActiveRuleCount: 25, // >= 20 triggers drop ratio guard
	}
	repo := newMemFeedRepo(feed)
	rec := newFakeReconciler(repo)
	// Seed 25 existing rules in reconciler
	rec.rules["sslbl"] = map[string]bool{}
	for i := 1; i <= 25; i++ {
		rec.rules["sslbl"][fmt.Sprintf("198.51.100.%d", i)] = true
	}

	// Only 4 entries -> dropRatio = 21/25 = 0.84 > 0.80 -> GUARD_ABORTED
	smallList := []byte("198.51.100.1\n198.51.100.2\n198.51.100.3\n198.51.100.4\n")
	dl := &fakeDownloader{
		fn: func(_ context.Context, _ FeedFetchRequest) (*FeedFetchResponse, error) {
			return &FeedFetchResponse{Body: smallList, StatusCode: 200}, nil
		},
	}
	var alerts []recordedAlert
	pubCount := 0
	syncer := NewSyncer(repo, rec, dl, &fakeSettingsReader{threshold: 5}).
		SetPublishFunc(func(context.Context, uuid.UUID, string) { pubCount++ }).
		SetAlertFunc(func(_ context.Context, typ, comp, title, msg string) {
			alerts = append(alerts, recordedAlert{typ, comp, title, msg})
		})

	res, err := syncer.SyncFeed(context.Background(), feed.ID, SyncOptions{TriggerType: TriggerManual})
	if err != nil {
		t.Fatalf("SyncFeed: %v", err)
	}
	if !res.GuardTriggered || res.Run.Status != RunStatusGuardAborted {
		t.Fatalf("expected GUARD_ABORTED on 84%% drop, got %+v", res)
	}
	if len(rec.calls) != 0 || pubCount != 0 {
		t.Fatal("must not reconcile or publish when max_drop_ratio guard aborts")
	}
	if len(alerts) != 1 || alerts[0].AlertType != AlertTypeSyncFailed {
		t.Fatalf("expected THREAT_INTEL_SYNC_FAILED alert, got %+v", alerts)
	}

	// Now force override -> succeeds, reconciles & publishes
	resForce, err := syncer.SyncFeed(context.Background(), feed.ID, SyncOptions{
		TriggerType:      TriggerManual,
		ForceIgnoreGuard: true,
	})
	if err != nil {
		t.Fatalf("SyncFeed force: %v", err)
	}
	if resForce.GuardTriggered || resForce.Run.Status != RunStatusSuccess {
		t.Fatalf("expected SUCCESS on force override, got %+v", resForce)
	}
	if resForce.Run.Refreshed != 4 || resForce.Run.Expired != 21 || pubCount != 1 {
		t.Fatalf("unexpected force result: run=%+v pub=%d", resForce.Run, pubCount)
	}
}

func TestSyncer_CircuitBreakerOpenAndManualReset(t *testing.T) {
	feed := &Feed{
		ID:              uuid.New(),
		FeedKey:         "corp_feed",
		Name:            "Corp Feed",
		Enabled:         true,
		SourceMode:      SourceModeCustomURL,
		CustomURL:       "https://intel.example.com/list.txt",
		Format:          "text",
		TTLDays:         30,
		ScheduleCron:    "* * * * *",
		MinEntriesGuard: true,
		MaxDropRatio:    0.80,
	}
	repo := newMemFeedRepo(feed)
	rec := newFakeReconciler(repo)
	failUpstream := true
	dl := &fakeDownloader{
		fn: func(_ context.Context, _ FeedFetchRequest) (*FeedFetchResponse, error) {
			if failUpstream {
				return nil, errors.New("connection refused")
			}
			return &FeedFetchResponse{Body: []byte("203.0.113.10\n"), StatusCode: 200}, nil
		},
	}
	var alerts []recordedAlert
	syncer := NewSyncer(repo, rec, dl, &fakeSettingsReader{autoUpdate: true, threshold: 3}).
		SetAlertFunc(func(_ context.Context, typ, comp, title, msg string) {
			alerts = append(alerts, recordedAlert{typ, comp, title, msg})
		})

	for i := 1; i <= 3; i++ {
		res, err := syncer.SyncFeed(context.Background(), feed.ID, SyncOptions{TriggerType: TriggerScheduled})
		if err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
		if res.Run.Status != RunStatusFailed {
			t.Fatalf("attempt %d status=%s, want FAILED", i, res.Run.Status)
		}
		if i < 3 && res.CircuitOpened {
			t.Fatalf("attempt %d should not open circuit yet", i)
		}
		if i == 3 && !res.CircuitOpened {
			t.Fatalf("attempt 3 must open circuit")
		}
	}

	got, _ := repo.GetFeed(context.Background(), feed.ID)
	if !got.CircuitOpen || got.ConsecutiveFailures != 3 {
		t.Fatalf("feed circuit state wrong: open=%v failures=%d", got.CircuitOpen, got.ConsecutiveFailures)
	}

	// Verify THREAT_INTEL_CIRCUIT_OPEN alert was emitted once
	cbAlerts := 0
	for _, a := range alerts {
		if a.AlertType == AlertTypeCircuitOpen {
			cbAlerts++
		}
	}
	if cbAlerts != 1 {
		t.Fatalf("expected 1 THREAT_INTEL_CIRCUIT_OPEN alert, got %d (%+v)", cbAlerts, alerts)
	}

	// Scheduled sweep must skip circuit-open feed (zero downloader calls)
	reqBefore := len(dl.requests)
	syncer.SetClock(func() time.Time { return time.Date(2026, 11, 28, 12, 5, 0, 0, time.UTC) })
	stats, err := syncer.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if stats.Due != 0 || len(dl.requests) != reqBefore {
		t.Fatalf("circuit-open feed must be skipped by scheduler: stats=%+v reqs=%d/%d", stats, len(dl.requests), reqBefore)
	}

	// Manual sync success closes circuit and resets consecutive_failures=0
	failUpstream = false
	resOK, err := syncer.SyncFeed(context.Background(), feed.ID, SyncOptions{TriggerType: TriggerManual})
	if err != nil {
		t.Fatalf("manual recovery sync: %v", err)
	}
	if resOK.Run.Status != RunStatusSuccess {
		t.Fatalf("recovery status=%s, want SUCCESS", resOK.Run.Status)
	}
	got, _ = repo.GetFeed(context.Background(), feed.ID)
	if got.CircuitOpen || got.ConsecutiveFailures != 0 {
		t.Fatalf("circuit must reset after manual sync success: open=%v failures=%d", got.CircuitOpen, got.ConsecutiveFailures)
	}
}

func TestSyncer_SweepOnce_BatchedSinglePublishAndOfflineZeroCalls(t *testing.T) {
	f1 := &Feed{
		ID:              uuid.New(),
		FeedKey:         "feodo",
		Name:            "Feodo",
		IsBuiltin:       true,
		Enabled:         true,
		SourceMode:      SourceModeOfficial,
		OfficialPreset:  "feodo",
		Format:          "text",
		TTLDays:         30,
		ScheduleCron:    "0 */6 * * *",
		MinEntriesGuard: true,
		MaxDropRatio:    0.80,
	}
	f2 := &Feed{
		ID:              uuid.New(),
		FeedKey:         "sslbl",
		Name:            "SSLBL",
		IsBuiltin:       true,
		Enabled:         true,
		SourceMode:      SourceModeOfficial,
		OfficialPreset:  "sslbl",
		Format:          "text",
		TTLDays:         30,
		ScheduleCron:    "0 */6 * * *",
		MinEntriesGuard: true,
		MaxDropRatio:    0.80,
	}
	fOffline := &Feed{
		ID:              uuid.New(),
		FeedKey:         "offline_feed",
		Name:            "Offline",
		Enabled:         true,
		SourceMode:      SourceModeOfflineOnly,
		Format:          "text",
		TTLDays:         30,
		ScheduleCron:    "0 */6 * * *",
		MinEntriesGuard: true,
		MaxDropRatio:    0.80,
	}
	repo := newMemFeedRepo(f1, f2, fOffline)
	rec := newFakeReconciler(repo)
	dl := &fakeDownloader{
		fn: func(_ context.Context, req FeedFetchRequest) (*FeedFetchResponse, error) {
			if strings.Contains(req.URL, "feodotracker") {
				return &FeedFetchResponse{Body: []byte("192.0.2.10\n"), StatusCode: 200}, nil
			}
			return &FeedFetchResponse{Body: []byte("203.0.113.20\n"), StatusCode: 200}, nil
		},
	}
	st := &fakeSettingsReader{autoUpdate: false, threshold: 5}
	pubCount := 0
	syncer := NewSyncer(repo, rec, dl, st).
		SetPublishFunc(func(context.Context, uuid.UUID, string) { pubCount++ }).
		SetClock(func() time.Time { return time.Date(2026, 11, 28, 6, 0, 15, 0, time.UTC) })

	// 1. auto_update_enabled=false -> 0 outbound calls
	stats, err := syncer.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("SweepOnce disabled: %v", err)
	}
	if stats.Due != 0 || len(dl.requests) != 0 || pubCount != 0 {
		t.Fatalf("disabled scheduler must make zero calls: stats=%+v reqs=%d pub=%d", stats, len(dl.requests), pubCount)
	}

	// 2. Enable auto_update -> both feodo & sslbl due, offline skipped, ONE batched publish!
	st.autoUpdate = true
	stats, err = syncer.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("SweepOnce enabled: %v", err)
	}
	if stats.Due != 2 || stats.Succeeded != 2 || stats.TotalChanged != 2 || !stats.PublishedOnce || pubCount != 1 {
		t.Fatalf("expected 2 due feeds and 1 batched publish, got stats=%+v pub=%d", stats, pubCount)
	}

	// 3. Re-running within same minute must skip already-synced feeds (no duplicate fetch)
	stats2, err := syncer.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("SweepOnce same minute: %v", err)
	}
	if stats2.Due != 0 || pubCount != 1 {
		t.Fatalf("expected 0 due in same minute, got stats=%+v pub=%d", stats2, pubCount)
	}
}

func TestMatchProtectedEntry_CIDROverlap(t *testing.T) {
	addrs := []protectedaddresses.ProtectedAddress{
		{Name: "管理端", Address: "203.0.113.5", Status: protectedaddresses.StatusEnabled},
		{Name: "上游段", CIDR: "198.51.100.128/25", Status: protectedaddresses.StatusEnabled},
		{Name: "停用保护", Address: "45.33.32.1", Status: "DISABLED"},
	}
	if hit, name := matchProtectedEntry(addrs, "203.0.113.0/24"); !hit || name != "管理端" {
		t.Fatalf("CIDR containing protected single IP must match: hit=%v name=%q", hit, name)
	}
	if hit, name := matchProtectedEntry(addrs, "198.51.100.0/24"); !hit || name != "上游段" {
		t.Fatalf("CIDR overlapping protected CIDR must match: hit=%v name=%q", hit, name)
	}
	if hit, _ := matchProtectedEntry(addrs, "45.33.32.0/24"); hit {
		t.Fatal("disabled protected address must not match")
	}
	if hit, _ := matchProtectedEntry(addrs, "192.0.2.0/24"); hit {
		t.Fatal("unrelated CIDR must not match")
	}
}

func TestSyncer_MaxOnlineContentBytesAndConcurrentInflight(t *testing.T) {
	feed := &Feed{
		ID: uuid.New(), FeedKey: "feodo", Name: "Feodo",
		Enabled: true, SourceMode: SourceModeOfficial, OfficialPreset: "feodo",
		Format: "text", TTLDays: 30, ScheduleCron: DefaultScheduleCron,
		MinEntriesGuard: true, MaxDropRatio: 0.80,
	}
	repo := newMemFeedRepo(feed)
	rec := newFakeReconciler(repo)

	// 1. Oversized body (> 2MiB) fails safely
	big := make([]byte, MaxOnlineContentBytes+1)
	dl := &fakeDownloader{
		fn: func(_ context.Context, _ FeedFetchRequest) (*FeedFetchResponse, error) {
			return &FeedFetchResponse{Body: big, StatusCode: 200}, nil
		},
	}
	syncer := NewSyncer(repo, rec, dl, &fakeSettingsReader{threshold: 5})
	res, err := syncer.SyncFeed(context.Background(), feed.ID, SyncOptions{TriggerType: TriggerManual})
	if err != nil {
		t.Fatalf("SyncFeed oversized: %v", err)
	}
	if res.Run.Status != RunStatusFailed || !strings.Contains(res.Run.ErrorMessage, "上限") {
		t.Fatalf("expected FAILED oversized error, got %+v", res.Run)
	}

	// 2. Concurrent sync on same feed returns ErrSyncInProgress
	started := make(chan struct{})
	release := make(chan struct{})
	dl.fn = func(_ context.Context, _ FeedFetchRequest) (*FeedFetchResponse, error) {
		close(started)
		<-release
		return &FeedFetchResponse{Body: []byte("192.0.2.10\n"), StatusCode: 200}, nil
	}
	done := make(chan error, 1)
	go func() {
		_, err := syncer.SyncFeed(context.Background(), feed.ID, SyncOptions{TriggerType: TriggerManual})
		done <- err
	}()
	<-started
	_, err2 := syncer.SyncFeed(context.Background(), feed.ID, SyncOptions{TriggerType: TriggerManual})
	close(release)
	if !errors.Is(err2, ErrSyncInProgress) {
		t.Fatalf("expected ErrSyncInProgress, got %v", err2)
	}
	if err1 := <-done; err1 != nil {
		t.Fatalf("first sync failed: %v", err1)
	}
}
