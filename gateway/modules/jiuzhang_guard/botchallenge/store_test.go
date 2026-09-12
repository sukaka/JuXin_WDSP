package botchallenge

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func testState(sd string, now time.Time) ChallengeState {
	return ChallengeState{
		SessionDigest: sd,
		HostDigest:    "hh",
		PolicyEpoch:   7,
		Difficulty:    MinDifficulty,
		Nonce:         strings.Repeat("cd", nonceBytes),
		ExpiresAt:     now.Add(90 * time.Second),
	}
}

// 签发/读取/消费生命周期 + 键纪律（前缀 + 哈希，无原始 challenge_id 明文拼键）。
func TestStoreLifecycleAndKeys(t *testing.T) {
	fk := newFakeBotValkey()
	st := NewStore(fk, "")
	now := time.Now().UTC()
	st.now = func() time.Time { return now }
	cid := strings.Repeat("ab", challengeIDBytes)
	ok, err := st.Issue("app-1", cid, testState("sd-1", now), 90*time.Second, 10)
	if err != nil || !ok {
		t.Fatalf("issue: %v %v", ok, err)
	}
	rd, err := st.Read("app-1", cid)
	if err != nil || rd.State == nil {
		t.Fatalf("read: %+v %v", rd, err)
	}
	if rd.State.SessionDigest != "sd-1" || rd.State.Difficulty != MinDifficulty || rd.State.Attempts != 0 {
		t.Fatalf("state round trip: %+v", rd.State)
	}
	// 键纪律：前缀 jiuzhang:guard:bot；challengeID（客户端回交材料）不直接入键
	for _, k := range fk.keyDump() {
		if !strings.HasPrefix(k, "jiuzhang:guard:bot:") {
			t.Fatalf("key prefix: %s", k)
		}
		if strings.Contains(k, cid) {
			t.Fatalf("raw challenge id must not appear in key: %s", k)
		}
		if strings.Contains(k, "app-1") {
			t.Fatalf("raw app id must not appear in key: %s", k)
		}
	}
	// 消费成功
	cr, err := st.Consume("app-1", cid, rd.State, 3)
	if err != nil || !cr.Consumed {
		t.Fatalf("consume: %+v %v", cr, err)
	}
	// 重放：NOT_FOUND
	cr, err = st.Consume("app-1", cid, rd.State, 3)
	if err != nil || cr.Consumed || cr.Reason != "NOT_FOUND" {
		t.Fatalf("replay must be NOT_FOUND: %+v %v", cr, err)
	}
}

// 容量上限：达到 cap 后签发返回 ok=false（不允许无限增长）；惰性清理后可再签发。
func TestStoreCapacity(t *testing.T) {
	fk := newFakeBotValkey()
	st := NewStore(fk, "")
	now := time.Now().UTC()
	st.now = func() time.Time { return now }
	issueN := func(id byte) bool {
		cid := strings.Repeat(string([]byte{id, id}), challengeIDBytes)
		ok, err := st.Issue("app-1", cid, testState("sd", now), 90*time.Second, 2)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !issueN('a') || !issueN('b') {
		t.Fatal("first two issues must succeed")
	}
	if issueN('c') {
		t.Fatal("third issue must hit capacity")
	}
	// 全部过期后惰性清理 → 可再签发
	st.now = func() time.Time { return now.Add(2 * time.Minute) }
	if !issueN('d') {
		t.Fatal("after lazy expiry cleanup issue must succeed")
	}
}

// 双节点并发原子消费：两个 Store 实例（模拟两个 Guard 节点）共享同一 Valkey，
// 同一 nonce 并发提交至多一次成功。
func TestStoreConcurrentConsumeTwoNodes(t *testing.T) {
	fk := newFakeBotValkey()
	now := time.Now().UTC()
	nodeA := NewStore(fk, "")
	nodeA.now = func() time.Time { return now }
	nodeB := NewStore(fk, "")
	nodeB.now = func() time.Time { return now }
	cid := strings.Repeat("ef", challengeIDBytes)
	state := testState("sd-x", now)
	if ok, err := nodeA.Issue("app-1", cid, state, 90*time.Second, 100); err != nil || !ok {
		t.Fatalf("issue: %v %v", ok, err)
	}
	rd, err := nodeB.Read("app-1", cid) // 节点 B 读到节点 A 签发的状态（跨节点共享）
	if err != nil || rd.State == nil {
		t.Fatalf("cross-node read: %+v %v", rd, err)
	}
	const n = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	consumed := 0
	notFound := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(node *Store) {
			defer wg.Done()
			cr, err := node.Consume("app-1", cid, rd.State, 3)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				t.Errorf("consume err: %v", err)
				return
			}
			if cr.Consumed {
				consumed++
			} else if cr.Reason == "NOT_FOUND" {
				notFound++
			} else {
				t.Errorf("unexpected reason: %s", cr.Reason)
			}
		}(map[int]*Store{0: nodeA, 1: nodeB}[i%2])
	}
	wg.Wait()
	if consumed != 1 {
		t.Fatalf("exactly-once violated: consumed=%d (want 1)", consumed)
	}
	if notFound != n-1 {
		t.Fatalf("losers must see NOT_FOUND: %d (want %d)", notFound, n-1)
	}
}

// 过期 nonce：消费/记账均归因 EXPIRED；Read 的 hint 区分 expired 与 not-found。
func TestStoreExpiry(t *testing.T) {
	fk := newFakeBotValkey()
	st := NewStore(fk, "")
	now := time.Now().UTC()
	st.now = func() time.Time { return now }
	cid := strings.Repeat("aa", challengeIDBytes)
	state := testState("sd", now)
	if ok, _ := st.Issue("app-1", cid, state, 90*time.Second, 10); !ok {
		t.Fatal("issue")
	}
	// 时钟越过 nonce_ttl（HASH TTL 在替身中不自动失效——权威过期判定在 Lua exp 字段）
	later := now.Add(91 * time.Second)
	st.now = func() time.Time { return later }
	rd, _ := st.Read("app-1", cid)
	cr, err := st.Consume("app-1", cid, rd.State, 3)
	if err != nil || cr.Consumed || cr.Reason != "EXPIRED" {
		t.Fatalf("expired consume: %+v %v", cr, err)
	}
	// 状态已被 EXPIRED 分支删除；HASH 消失后按在途计量提示归因 EXPIRED
	rd2, _ := st.Read("app-1", cid)
	if rd2.State != nil || rd2.Hint != "EXPIRED" {
		t.Fatalf("expired hint: %+v", rd2)
	}
	// 从未存在：NOT_FOUND
	rd3, _ := st.Read("app-1", strings.Repeat("bb", challengeIDBytes))
	if rd3.State != nil || rd3.Hint != "NOT_FOUND" {
		t.Fatalf("not-found hint: %+v", rd3)
	}
}

// 尝试计数：错误解答记账到达 max_attempts 即作废；MISMATCH（伪造期望）不记账。
func TestStoreFailAttempts(t *testing.T) {
	fk := newFakeBotValkey()
	st := NewStore(fk, "")
	now := time.Now().UTC()
	st.now = func() time.Time { return now }
	cid := strings.Repeat("cc", challengeIDBytes)
	state := testState("sd", now)
	if ok, _ := st.Issue("app-1", cid, state, 90*time.Second, 10); !ok {
		t.Fatal("issue")
	}
	rd, _ := st.Read("app-1", cid)
	fr, err := st.FailAttempt("app-1", cid, rd.State, 3)
	if err != nil || !fr.Recorded || fr.Attempts != 1 {
		t.Fatalf("attempt 1: %+v %v", fr, err)
	}
	fr, _ = st.FailAttempt("app-1", cid, rd.State, 3)
	if !fr.Recorded || fr.Attempts != 2 {
		t.Fatalf("attempt 2: %+v", fr)
	}
	fr, _ = st.FailAttempt("app-1", cid, rd.State, 3)
	if fr.Recorded || fr.Reason != "EXHAUSTED" || fr.Attempts != 3 {
		t.Fatalf("exhausted: %+v", fr)
	}
	// 作废后消费失败
	cr, _ := st.Consume("app-1", cid, rd.State, 3)
	if cr.Consumed || cr.Reason != "NOT_FOUND" {
		t.Fatalf("exhausted challenge must be gone: %+v", cr)
	}
	// MISMATCH：篡改期望值不记账
	cid2 := strings.Repeat("dd", challengeIDBytes)
	if ok, _ := st.Issue("app-1", cid2, state, 90*time.Second, 10); !ok {
		t.Fatal("issue 2")
	}
	tampered := testState("sd-forged", now)
	fr2, _ := st.FailAttempt("app-1", cid2, &tampered, 3)
	if fr2.Recorded || fr2.Reason != "MISMATCH" {
		t.Fatalf("mismatch must not count: %+v", fr2)
	}
	rd2, _ := st.Read("app-1", cid2)
	if rd2.State == nil || rd2.State.Attempts != 0 {
		t.Fatalf("mismatch must leave attempts=0: %+v", rd2.State)
	}
}

// 存储故障/悬挂：ErrStateUnavailable（errors.Is 可判——fail-closed 例外语义）。
func TestStoreFailureSemantics(t *testing.T) {
	fk := newFakeBotValkey()
	st := NewStore(fk, "")
	cid := strings.Repeat("ab", challengeIDBytes)
	state := testState("sd", time.Now())
	fk.fail = true
	if _, err := st.Issue("app-1", cid, state, 90*time.Second, 10); !errors.Is(err, ErrStateUnavailable) {
		t.Fatalf("issue failure must wrap ErrStateUnavailable: %v", err)
	}
	if _, err := st.Read("app-1", cid); !errors.Is(err, ErrStateUnavailable) {
		t.Fatalf("read failure: %v", err)
	}
	if _, err := st.Consume("app-1", cid, &state, 3); !errors.Is(err, ErrStateUnavailable) {
		t.Fatalf("consume failure: %v", err)
	}
	if _, err := st.FailAttempt("app-1", cid, &state, 3); !errors.Is(err, ErrStateUnavailable) {
		t.Fatalf("fail-attempt failure: %v", err)
	}
	if err := st.Ping(); !errors.Is(err, ErrStateUnavailable) {
		t.Fatalf("ping failure: %v", err)
	}
	// 悬挂：300ms 超时内返回（fail-closed 有界阻塞）
	fk.fail = false
	fk.hang = true
	start := time.Now()
	_, err := st.Read("app-1", cid)
	if !errors.Is(err, ErrStateUnavailable) {
		t.Fatalf("hang must surface as unavailable: %v", err)
	}
	if elapsed := time.Since(start); elapsed > opTimeout+200*time.Millisecond {
		t.Fatalf("hang must return within opTimeout: %v", elapsed)
	}
}

// 限速器故障包装为 ErrStateUnavailable（fail-closed）。
func TestAllowRateFailure(t *testing.T) {
	fk := newFakeBotValkey()
	lim := &fakeLimiter{denyKeys: map[string]bool{}, failKeys: map[string]bool{"vfy-ip": true}}
	svc, _ := newTestService(t, fk, lim, nil, testServiceOpts{})
	_, _, err := svc.allowRate("vfy", "203.0.113.9", "sd")
	if !errors.Is(err, ErrStateUnavailable) {
		t.Fatalf("limiter failure must wrap ErrStateUnavailable: %v", err)
	}
	lim.failKeys = map[string]bool{}
	lim.deny("iss-ip")
	ok, retry, err := svc.allowRate("iss", "203.0.113.9", "sd")
	if err != nil || ok || retry <= 0 {
		t.Fatalf("deny: %v %v %v", ok, retry, err)
	}
}
