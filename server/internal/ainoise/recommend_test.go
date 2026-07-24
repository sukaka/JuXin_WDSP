// recommend_test.go 降噪推荐测试：DRAFT 写入（类型/证据引用）、非误报跳过、去重跳过。
package ainoise

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func likeFPCluster(t *testing.T, store *MemStore) *Cluster {
	t.Helper()
	ctx := context.Background()
	rule := 942100
	conf := 0.85
	_, id, err := store.UpsertEvent(ctx, EventInput{
		EventID: uuid.New(), Source: SourceWAF, Host: "a.com", RawURI: "/search",
		RuleID: &rule, ClientIP: "1.2.3.4", OccurredAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateVerdict(ctx, id, VerdictLikelyFalsePositive, &conf, "单一低风险规则高频重复"); err != nil {
		t.Fatal(err)
	}
	c, err := store.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestMaybeRecommendWritesDraft(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	c := likeFPCluster(t, store)
	rec := &fakeRecorder{store: store}
	r := NewRecommender(rec)

	ok, err := r.MaybeRecommend(ctx, store, c)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if len(rec.recorded) != 1 || !strings.HasPrefix(rec.recorded[0], RecommendationType+":"+c.ID.String()) {
		t.Fatalf("recorded=%v", rec.recorded)
	}
}

func TestMaybeRecommendSkipsNonFalsePositive(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	_, id, _ := store.UpsertEvent(ctx, EventInput{
		EventID: uuid.New(), Source: SourceWAF, Host: "a.com", RawURI: "/x", OccurredAt: time.Now().UTC(),
	})
	c, _ := store.Get(ctx, id) // UNKNOWN
	rec := &fakeRecorder{store: store}
	ok, err := NewRecommender(rec).MaybeRecommend(ctx, store, c)
	if err != nil || ok || len(rec.recorded) != 0 {
		t.Fatalf("ok=%v err=%v recorded=%v", ok, err, rec.recorded)
	}
}

func TestMaybeRecommendSkipsWhenOpenExists(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	c := likeFPCluster(t, store)
	store.SetOpenRecommendation(c.ID)
	rec := &fakeRecorder{store: store}
	ok, err := NewRecommender(rec).MaybeRecommend(ctx, store, c)
	if err != nil || ok || len(rec.recorded) != 0 {
		t.Fatalf("should skip duplicate: ok=%v err=%v recorded=%v", ok, err, rec.recorded)
	}
}

func TestMaybeRecommendNilRecorder(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	c := likeFPCluster(t, store)
	ok, err := NewRecommender(nil).MaybeRecommend(ctx, store, c)
	if err != nil || ok {
		t.Fatalf("nil recorder should skip: ok=%v err=%v", ok, err)
	}
}
