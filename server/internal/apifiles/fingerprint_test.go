package apifiles

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apidata"
)

func TestFileAssetSHA256Filter(t *testing.T) {
	store := NewMemStore()
	hash := strings.Repeat("ab", 32)
	store.addAsset(FileAsset{
		ID: uuid.New(), EndpointKey: "GET /v1/report", Direction: DirectionDownload,
		FileName: "report.pdf", Extension: "pdf", MIME: "application/pdf", SHA256: &hash,
		LastSeen: time.Now().UTC(), SensitiveTypes: []string{},
	})
	store.addAsset(FileAsset{
		ID: uuid.New(), EndpointKey: "GET /v1/other", Direction: DirectionDownload,
		FileName: "other.pdf", Extension: "pdf", MIME: "application/pdf",
		LastSeen: time.Now().UTC(), SensitiveTypes: []string{},
	})
	mux := newTestMux(store, injectPrincipal(apidata.PermDataRead))
	rr := do(t, mux, "/api/v1/api-security/file-assets?sha256="+strings.ToUpper(hash))
	if rr.Code != http.StatusOK {
		t.Fatalf("sha256 filter: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Data struct {
			Total int64       `json:"total"`
			Items []FileAsset `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Data.Total != 1 || len(body.Data.Items) != 1 || body.Data.Items[0].SHA256 == nil || *body.Data.Items[0].SHA256 != hash {
		t.Fatalf("unexpected sha256 filter result: %+v", body.Data)
	}
	for _, query := range []string{"short", strings.Repeat("x", 64)} {
		if rr := do(t, mux, "/api/v1/api-security/file-assets?sha256="+query); rr.Code != http.StatusBadRequest {
			t.Fatalf("invalid sha256 %q: status=%d, want 400", query, rr.Code)
		}
	}
}
