package apiweakness

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

type fileSensitiveSignals struct {
	fakeSignals
	signals []EndpointSignal
}

func (s *fileSensitiveSignals) FileSensitiveContent(ctx context.Context, since time.Time) ([]EndpointSignal, error) {
	return s.signals, nil
}

func TestFileSensitiveContentWeaknessAndHTTP(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	endpointID := uuid.New()
	store := NewMemStore()
	store.SetEndpointKey(endpointID, "POST /v1/files/upload")
	source := &fileSensitiveSignals{signals: []EndpointSignal{sigFor(endpointID, "POST /v1/files/upload", 1, now)}}
	result, err := newTestSweeper(source, store, now).SweepOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Inserted != 1 || result.ByCode[CodeSensitiveFileContent] != 1 {
		t.Fatalf("unexpected sensitive-file derivation: %+v", result)
	}
	mux := newTestMux(NewHandler(store, nil))
	rr := doJSON(t, mux, "GET", "/api/v1/api-security/weaknesses?category=SENSITIVE", nil)
	if rr.Code != 200 {
		t.Fatalf("sensitive file weakness HTTP status=%d body=%s", rr.Code, rr.Body.String())
	}
	if data := decodeData(t, rr); data["total"] != float64(1) {
		t.Fatalf("sensitive content must use the existing weakness API: %+v", data)
	}
}
