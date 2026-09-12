// aggregator_test.go 聚合器 SweepOnce 用例（内存假 Repository，无 DB）：
// 滑动窗并入/新建/收口/幂等重放/request_id 双落去重/未归属跳过/单源 fail-open。
package attacksessions

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fakeRepo 内存仓储假实现（聚合逻辑单测；SQL 行为由集成测试覆盖）。
type fakeRepo struct {
	events    map[string][]Event // 按源
	fetchErr  map[string]error
	sessions  map[uuid.UUID]*Session // id → 会话（UpdateSession 写回）
	links     map[string]uuid.UUID   // source_table|source_id → session_id
	sessEvts  map[uuid.UUID][]Event  // session_id → 已挂事件
	createdAt int
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		events:   map[string][]Event{},
		sessions: map[uuid.UUID]*Session{},
		links:    map[string]uuid.UUID{},
		sessEvts: map[uuid.UUID][]Event{},
	}
}

func (f *fakeRepo) Watermark(_ context.Context, source string) (time.Time, bool, error) {
	// 与 SQL 同口径：派生自已挂事件 max(occurred_at) per source
	var max time.Time
	found := false
	for sid := range f.sessions {
		for _, ev := range f.sessEvts[sid] {
			if ev.SourceTable == source && (!found || ev.OccurredAt.After(max)) {
				max = ev.OccurredAt
				found = true
			}
		}
	}
	return max, found, nil
}

func (f *fakeRepo) fetch(source string, since time.Time, limit int) ([]Event, error) {
	if err := f.fetchErr[source]; err != nil {
		return nil, err
	}
	var out []Event
	for _, ev := range f.events[source] {
		if !ev.OccurredAt.Before(since) {
			out = append(out, ev)
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (f *fakeRepo) FetchBehaviorEvents(ctx context.Context, since time.Time, limit int) ([]Event, error) {
	return f.fetch(SourceBehaviorEvents, since, limit)
}
func (f *fakeRepo) FetchAccessControlEvents(ctx context.Context, since time.Time, limit int) ([]Event, error) {
	return f.fetch(SourceAccessControlEvents, since, limit)
}
func (f *fakeRepo) FetchSecurityEvents(ctx context.Context, since time.Time, limit int) ([]Event, error) {
	return f.fetch(SourceSecurityEvents, since, limit)
}
func (f *fakeRepo) FetchAPIRuntimeEvents(ctx context.Context, since time.Time, limit int) ([]Event, error) {
	return f.fetch(SourceAPIRuntimeEvents, since, limit)
}

func (f *fakeRepo) FindOpenSession(_ context.Context, identityID uuid.UUID) (*Session, error) {
	var latest *Session
	for _, s := range f.sessions {
		if s.IdentityID != nil && *s.IdentityID == identityID && s.Status == "OPEN" {
			if latest == nil || s.EndTime.After(latest.EndTime) {
				latest = s
			}
		}
	}
	if latest == nil {
		return nil, nil
	}
	cp := *latest
	return &cp, nil
}

func (f *fakeRepo) CreateSession(_ context.Context, sess *Session) (*Session, bool, error) {
	for _, s := range f.sessions {
		if s.SessionKey == sess.SessionKey {
			cp := *s
			return &cp, false, nil
		}
	}
	f.createdAt++
	cp := *sess
	cp.ID = uuid.MustParse(fmt.Sprintf("00000000-0000-0000-0000-%012d", f.createdAt))
	cp.Status = "OPEN"
	cp.RiskLevel = "LOW"
	cp.AttackStage = StageUnknown
	f.sessions[cp.ID] = &cp
	out := cp
	return &out, true, nil
}

func (f *fakeRepo) CloseOtherOpenSessions(_ context.Context, identityID, excludeID uuid.UUID) error {
	for _, s := range f.sessions {
		if s.IdentityID != nil && *s.IdentityID == identityID && s.Status == "OPEN" && s.ID != excludeID {
			s.Status = "CLOSED"
		}
	}
	return nil
}

func (f *fakeRepo) AlreadyLinked(_ context.Context, sourceTable, sourceID string) (uuid.UUID, bool, error) {
	sid, ok := f.links[sourceTable+"|"+sourceID]
	return sid, ok, nil
}

func (f *fakeRepo) LinkEvent(_ context.Context, sessionID uuid.UUID, ev Event) (bool, error) {
	key := ev.SourceTable + "|" + ev.SourceID
	if _, ok := f.links[key]; ok {
		return false, nil
	}
	f.links[key] = sessionID
	f.sessEvts[sessionID] = append(f.sessEvts[sessionID], ev)
	return true, nil
}

func (f *fakeRepo) HasRequest(_ context.Context, sessionID uuid.UUID, requestID string) (bool, error) {
	if requestID == "" {
		return false, nil
	}
	for _, ev := range f.sessEvts[sessionID] {
		if ev.RequestID == requestID {
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeRepo) HasRequestFrom(_ context.Context, sessionID uuid.UUID, requestID string, sources ...string) (bool, error) {
	if requestID == "" {
		return false, nil
	}
	for _, ev := range f.sessEvts[sessionID] {
		if ev.RequestID != requestID {
			continue
		}
		for _, s := range sources {
			if ev.SourceTable == s {
				return true, nil
			}
		}
	}
	return false, nil
}

func (f *fakeRepo) UpdateSession(_ context.Context, sess *Session) error {
	cp := *sess
	f.sessions[sess.ID] = &cp
	return nil
}

func (f *fakeRepo) CloseStaleSessions(_ context.Context, before time.Time) (int64, error) {
	var n int64
	for _, s := range f.sessions {
		if s.Status == "OPEN" && s.EndTime.Before(before) {
			s.Status = "CLOSED"
			n++
		}
	}
	return n, nil
}

// 测试辅助：构造归属事件。
func evAt(source, sourceID, reqID string, identityID uuid.UUID, at time.Time, score int, stage string) Event {
	return Event{
		SourceTable: source, SourceID: sourceID, RequestID: reqID,
		IdentityID: &identityID, IdentityKey: "ik-x",
		OccurredAt: at, Score: score, Stage: stage,
	}
}

func newTestAggregator(repo *fakeRepo, now time.Time) *Aggregator {
	a := NewAggregator(repo)
	a.now = func() time.Time { return now }
	return a
}

func (f *fakeRepo) onlySession(t *testing.T) *Session {
	t.Helper()
	if len(f.sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(f.sessions))
	}
	for _, s := range f.sessions {
		return s
	}
	return nil
}

// 滑动窗并入：同身份 30min 内两事件聚成 1 个会话，阶段取最高，分数求和。
func TestSweepOnceSlidingWindowMerge(t *testing.T) {
	repo := newFakeRepo()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	identityID := uuid.New()
	t0 := now.Add(-time.Hour)
	repo.events[SourceBehaviorEvents] = []Event{
		evAt(SourceBehaviorEvents, "b1", "req-1", identityID, t0, 15, StageRecon),
		evAt(SourceBehaviorEvents, "b2", "req-2", identityID, t0.Add(10*time.Minute), 15, StageAuthProbe),
	}
	stats, err := newTestAggregator(repo, now).SweepOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Linked != 2 || stats.SessionsCreated != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	sess := repo.onlySession(t)
	if sess.EventCount != 2 || sess.RequestCount != 2 {
		t.Errorf("counts = %d/%d, want 2/2", sess.EventCount, sess.RequestCount)
	}
	if sess.AttackStage != StageAuthProbe {
		t.Errorf("stage = %s, want AUTH_PROBE（成员最高）", sess.AttackStage)
	}
	if sess.RiskScore != 30 || sess.RiskLevel != "MEDIUM" {
		t.Errorf("risk = %d/%s, want 30/MEDIUM", sess.RiskScore, sess.RiskLevel)
	}
	if !sess.StartTime.Equal(t0) || !sess.EndTime.Equal(t0.Add(10*time.Minute)) {
		t.Errorf("window = %s ~ %s", sess.StartTime, sess.EndTime)
	}
}

// 超 30min 不活跃间隔 → 新建会话，旧会话立即 CLOSED（至多一个 OPEN 不变式）。
func TestSweepOnceNewSessionAfterGap(t *testing.T) {
	repo := newFakeRepo()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	identityID := uuid.New()
	t0 := now.Add(-50 * time.Minute)
	repo.events[SourceBehaviorEvents] = []Event{
		evAt(SourceBehaviorEvents, "b1", "req-1", identityID, t0, 10, StageRecon),
	}
	if _, err := newTestAggregator(repo, now).SweepOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	// 45 分钟后新事件（last_event_at+30min 之外）
	repo.events[SourceBehaviorEvents] = append(repo.events[SourceBehaviorEvents],
		evAt(SourceBehaviorEvents, "b2", "req-2", identityID, t0.Add(45*time.Minute), 50, StageExploit))
	stats, err := newTestAggregator(repo, now).SweepOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.SessionsCreated != 1 || stats.Linked != 1 || stats.Replayed != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	if len(repo.sessions) != 2 {
		t.Fatalf("sessions = %d, want 2", len(repo.sessions))
	}
	openCount := 0
	for _, s := range repo.sessions {
		if s.Status == "OPEN" {
			openCount++
			if s.AttackStage != StageExploit || s.EventCount != 1 {
				t.Errorf("new session = stage %s events %d", s.AttackStage, s.EventCount)
			}
		}
	}
	if openCount != 1 {
		t.Errorf("OPEN sessions = %d, want 1（旧会话已关闭）", openCount)
	}
}

// CLOSED 桶碰撞：旧会话已收口，迟到事件落在旧会话同 30min 桶（且超出其 last_event+30min
// 滑动窗）→ 桶键冲突回退精确盐键新建，不复活 CLOSED 会话（旧会话计数字段不变）。
func TestSweepOnceStaleBucketCollision(t *testing.T) {
	repo := newFakeRepo()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	identityID := uuid.New()
	first := time.Date(2026, 9, 1, 10, 0, 30, 0, time.UTC)
	repo.events[SourceBehaviorEvents] = []Event{
		evAt(SourceBehaviorEvents, "b1", "req-1", identityID, first, 10, StageRecon),
	}
	if _, err := newTestAggregator(repo, now).SweepOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	// 旧会话已被收口（end 远超 30min）。迟到新事件：同 30min 桶（10:00-10:30），
	// 且 10:29 > 10:00:30+30min 滑动窗外？——10:00:30+30m=10:30:30 仍覆盖 10:29，
	// 但会话已 CLOSED 不复活，必须新建；桶键 sha256(identity|10:00) 冲突 → 盐键回退。
	late := time.Date(2026, 9, 1, 10, 29, 0, 0, time.UTC)
	repo.events[SourceBehaviorEvents] = append(repo.events[SourceBehaviorEvents],
		evAt(SourceBehaviorEvents, "b2", "req-2", identityID, late, 20, StageDiscovery))
	stats, err := newTestAggregator(repo, now).SweepOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.SessionsCreated != 1 || stats.Linked != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	if len(repo.sessions) != 2 {
		t.Fatalf("sessions = %d, want 2（碰撞后盐键新建）", len(repo.sessions))
	}
	var oldCount, newCount int64
	for _, s := range repo.sessions {
		if s.StartTime.Equal(first) {
			oldCount = s.EventCount
		} else {
			newCount = s.EventCount
			if !s.StartTime.Equal(late) {
				t.Errorf("new session start = %s, want %s", s.StartTime, late)
			}
		}
	}
	if oldCount != 1 || newCount != 1 {
		t.Errorf("counts old/new = %d/%d, want 1/1（旧会话未被污染）", oldCount, newCount)
	}
}

// 30min 内的乱序到达事件仍并入同一会话（滑动语义不按固定对齐窗切分）。
func TestSweepOnceOutOfOrderWithinWindow(t *testing.T) {
	repo := newFakeRepo()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	identityID := uuid.New()
	t0 := now.Add(-time.Hour)
	repo.events[SourceBehaviorEvents] = []Event{
		evAt(SourceBehaviorEvents, "b1", "req-1", identityID, t0.Add(20*time.Minute), 10, StageRecon),
		evAt(SourceBehaviorEvents, "b2", "req-2", identityID, t0, 10, StageRecon), // 更早的事件后到达
	}
	stats, err := newTestAggregator(repo, now).SweepOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.SessionsCreated != 1 || stats.Linked != 2 {
		t.Fatalf("stats = %+v", stats)
	}
	sess := repo.onlySession(t)
	if !sess.StartTime.Equal(t0) {
		t.Errorf("start = %s, want 最早事件 %s", sess.StartTime, t0)
	}
}

// 幂等重放：同一事件再次到达（水位线重叠窗）不重复累计会话字段。
func TestSweepOnceIdempotentReplay(t *testing.T) {
	repo := newFakeRepo()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	identityID := uuid.New()
	ev := evAt(SourceBehaviorEvents, "b1", "req-1", identityID, now.Add(-time.Hour), 40, StageRecon)
	repo.events[SourceBehaviorEvents] = []Event{ev}
	if _, err := newTestAggregator(repo, now).SweepOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	stats, err := newTestAggregator(repo, now).SweepOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Replayed != 1 || stats.Linked != 0 {
		t.Fatalf("replay stats = %+v, want Replayed=1 Linked=0", stats)
	}
	sess := repo.onlySession(t)
	if sess.EventCount != 1 || sess.RiskScore != 40 {
		t.Errorf("session after replay = events %d score %d, want 1/40", sess.EventCount, sess.RiskScore)
	}
}

// WDSP 双落去重：security_events 与 api_runtime_events（waf 明细）同 request_id 只计一次。
func TestSweepOnceRequestIDDedup(t *testing.T) {
	repo := newFakeRepo()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	identityID := uuid.New()
	t0 := now.Add(-time.Hour)
	repo.events[SourceSecurityEvents] = []Event{
		evAt(SourceSecurityEvents, "se-1", "req-sqli", identityID, t0, 50, StageExploit),
	}
	repo.events[SourceAPIRuntimeEvents] = []Event{
		evAt(SourceAPIRuntimeEvents, "are-1", "req-sqli", identityID, t0.Add(time.Second), 50, StageExploit),
	}
	stats, err := newTestAggregator(repo, now).SweepOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Deduped != 1 || stats.Linked != 1 {
		t.Fatalf("stats = %+v, want Deduped=1 Linked=1", stats)
	}
	sess := repo.onlySession(t)
	if sess.EventCount != 1 || sess.RequestCount != 1 || sess.RiskScore != 50 {
		t.Errorf("session = events %d requests %d score %d, want 1/1/50",
			sess.EventCount, sess.RequestCount, sess.RiskScore)
	}
}

// 跨源不去重：同请求的行为信号（RECON）与安全事件（EXPLOIT）语义不同，两者都计入，
// 仅 request_count 按 request_id 去重为 1。
func TestSweepOnceCrossSourceSameRequestNotDeduped(t *testing.T) {
	repo := newFakeRepo()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	identityID := uuid.New()
	t0 := now.Add(-time.Hour)
	repo.events[SourceBehaviorEvents] = []Event{
		evAt(SourceBehaviorEvents, "be-1", "req-shared", identityID, t0, 15, StageRecon),
	}
	repo.events[SourceSecurityEvents] = []Event{
		evAt(SourceSecurityEvents, "se-1", "req-shared", identityID, t0.Add(time.Second), 50, StageExploit),
	}
	stats, err := newTestAggregator(repo, now).SweepOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Deduped != 0 || stats.Linked != 2 {
		t.Fatalf("stats = %+v, want Deduped=0 Linked=2", stats)
	}
	sess := repo.onlySession(t)
	if sess.EventCount != 2 || sess.RequestCount != 1 || sess.RiskScore != 65 {
		t.Errorf("session = events %d requests %d score %d, want 2/1/65",
			sess.EventCount, sess.RequestCount, sess.RiskScore)
	}
	if sess.AttackStage != StageExploit {
		t.Errorf("attack_stage = %s, want EXPLOIT（取成员最高阶段）", sess.AttackStage)
	}
}

// 未归属事件（IP 反查歧义/降级链穷尽，IdentityID 为空）本期跳过，不建 NULL 会话。
func TestSweepOnceUnattributedSkipped(t *testing.T) {
	repo := newFakeRepo()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	ev := evAt(SourceSecurityEvents, "se-orphan", "req-x", uuid.Nil, now.Add(-time.Hour), 50, StageExploit)
	ev.IdentityID = nil // SQL 反查失败 → NULL
	repo.events[SourceSecurityEvents] = []Event{ev}
	stats, err := newTestAggregator(repo, now).SweepOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.SkippedUnattributed != 1 || stats.Linked != 0 || len(repo.sessions) != 0 {
		t.Fatalf("stats = %+v sessions = %d, want 跳过且无会话", stats, len(repo.sessions))
	}
}

// 单源失败 fail-open：其余源照常聚合，SourceErrors 计数，水位线不前移由仓储天然保证。
func TestSweepOnceSourceFailOpen(t *testing.T) {
	repo := newFakeRepo()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	identityID := uuid.New()
	repo.events[SourceBehaviorEvents] = []Event{
		evAt(SourceBehaviorEvents, "b1", "req-1", identityID, now.Add(-time.Hour), 10, StageRecon),
	}
	repo.fetchErr = map[string]error{SourceAPIRuntimeEvents: errors.New("connection reset")}
	stats, err := newTestAggregator(repo, now).SweepOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.SourceErrors != 1 || stats.Linked != 1 {
		t.Fatalf("stats = %+v, want SourceErrors=1 Linked=1", stats)
	}
}

// 收口：last_event_at 超 30min 的 OPEN 会话 → CLOSED。
func TestSweepOnceCloseStale(t *testing.T) {
	repo := newFakeRepo()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	identityID := uuid.New()
	repo.events[SourceBehaviorEvents] = []Event{
		evAt(SourceBehaviorEvents, "b1", "req-1", identityID, now.Add(-31*time.Minute), 10, StageRecon),
	}
	stats, err := newTestAggregator(repo, now).SweepOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.SessionsClosed != 1 {
		t.Fatalf("closed = %d, want 1", stats.SessionsClosed)
	}
	sess := repo.onlySession(t)
	if sess.Status != "CLOSED" {
		t.Errorf("status = %s, want CLOSED", sess.Status)
	}
}

// 会话键稳定：同身份同 30min 桶起点同键（崩溃重建幂等）；不同桶不同键。
func TestSessionKeyOf(t *testing.T) {
	identityID := uuid.New()
	at := time.Date(2026, 9, 1, 12, 7, 33, 0, time.UTC)
	k1 := SessionKeyOf(identityID, at)
	k2 := SessionKeyOf(identityID, time.Date(2026, 9, 1, 12, 29, 59, 0, time.UTC)) // 同桶（12:00-12:30）
	k3 := SessionKeyOf(identityID, time.Date(2026, 9, 1, 12, 30, 0, 0, time.UTC))  // 下一桶
	if k1 != k2 {
		t.Errorf("same bucket keys differ: %s vs %s", k1, k2)
	}
	if k1 == k3 {
		t.Errorf("different bucket keys equal: %s", k1)
	}
	if len(k1) != 64 {
		t.Errorf("key len = %d, want sha256 hex 64", len(k1))
	}
}

// 风险分截断与等级档（与 client_identity 20/40/70 口径一致）。
func TestRiskScoreClampAndLevel(t *testing.T) {
	if got := clampRiskScore(120); got != 100 {
		t.Errorf("clamp(120) = %d", got)
	}
	if got := clampRiskScore(-5); got != 0 {
		t.Errorf("clamp(-5) = %d", got)
	}
	for score, want := range map[int]string{0: "LOW", 19: "LOW", 20: "MEDIUM", 39: "MEDIUM", 40: "HIGH", 69: "HIGH", 70: "CRITICAL", 100: "CRITICAL"} {
		if got := RiskLevelForScore(score); got != want {
			t.Errorf("RiskLevelForScore(%d) = %s, want %s", score, got, want)
		}
	}
}
