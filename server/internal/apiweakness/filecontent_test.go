package apiweakness

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

type fileContentSignals struct {
	fakeSignals
	signals []EndpointSignal
}

func (s *fileContentSignals) FileContentTypeMismatch(ctx context.Context, since time.Time) ([]EndpointSignal, error) {
	return s.signals, nil
}

func TestFileContentMismatchWeaknessAndHTTP(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	endpointID := uuid.New()
	source := &fileContentSignals{signals: []EndpointSignal{sigFor(endpointID, "GET /v1/files/{id}", 2, now)}}
	store := NewMemStore()
	store.SetEndpointKey(endpointID, "GET /v1/files/{id}")
	result, err := newTestSweeper(source, store, now).SweepOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.Inserted != 1 || result.ByCode[CodeFileContentTypeMismatch] != 1 {
		t.Fatalf("unexpected file weakness derivation: %+v", result)
	}
	mux := newTestMux(NewHandler(store, nil))
	rr := doJSON(t, mux, "GET", "/api/v1/api-security/weaknesses?category=SENSITIVE", nil)
	if rr.Code != 200 {
		t.Fatalf("file weakness HTTP status=%d body=%s", rr.Code, rr.Body.String())
	}
	data := decodeData(t, rr)
	if data["total"] != float64(1) {
		t.Fatalf("file weakness should use existing list API: %+v", data)
	}
	items, _, err := store.List(ctx, ListFilter{Category: CategorySensitive, Page: 1, PageSize: 20})
	if err != nil || len(items) != 1 || items[0].WeaknessCode != CodeFileContentTypeMismatch || items[0].Severity != SeverityMedium {
		t.Fatalf("unexpected file weakness: %+v err=%v", items, err)
	}
}

func TestFileContentNormalResponseProducesNothing(t *testing.T) {
	store := NewMemStore()
	result, err := newTestSweeper(&fileContentSignals{}, store, time.Now().UTC()).SweepOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Inserted != 0 || result.Updated != 0 {
		t.Fatalf("normal or uninspected responses must not derive mismatch: %+v", result)
	}
}
