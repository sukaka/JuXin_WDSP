package apifiles

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apidata"
)

func TestFileAssetLineage(t *testing.T) {
	store := NewMemStore()
	hash := strings.Repeat("cd", 32)
	now := time.Now().UTC()
	for _, asset := range []FileAsset{
		{ID: uuid.New(), EndpointKey: "POST /v1/imports", Direction: DirectionUpload, FileName: "report.docx", SHA256: &hash, LastSeen: now, TransferCount: 3, SensitiveTypes: []string{}},
		{ID: uuid.New(), EndpointKey: "GET /v1/exports", Direction: DirectionDownload, FileName: "report.docx", SHA256: &hash, LastSeen: now, TransferCount: 4, SensitiveTypes: []string{}},
		{ID: uuid.New(), EndpointKey: "GET /v1/other", Direction: DirectionDownload, FileName: "other.docx", LastSeen: now, SensitiveTypes: []string{}},
	} {
		store.addAsset(asset)
	}
	mux := newTestMux(store, injectPrincipal(apidata.PermDataRead))
	rr := do(t, mux, "/api/v1/api-security/file-assets/lineage?sha256="+strings.ToUpper(hash))
	if rr.Code != http.StatusOK {
		t.Fatalf("lineage: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Data FileLineage `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	got := body.Data
	if got.SHA256 != hash || got.Total != 2 || got.UploadAssets != 1 || got.DownloadAssets != 1 || len(got.Items) != 2 || got.Truncated {
		t.Fatalf("unexpected lineage: %+v", got)
	}
	if got.Items[0].EndpointKey != "GET /v1/exports" || got.Items[1].EndpointKey != "POST /v1/imports" {
		t.Fatalf("lineage must preserve endpoint attribution: %+v", got.Items)
	}
	for _, query := range []string{"", "short", strings.Repeat("z", 64)} {
		rr := do(t, mux, "/api/v1/api-security/file-assets/lineage?sha256="+query)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("invalid lineage hash %q: status=%d, want 400", query, rr.Code)
		}
	}
}

func TestFileAssetLineageTruncationAndPermissions(t *testing.T) {
	store := NewMemStore()
	hash := strings.Repeat("ef", 32)
	for i := 0; i < 101; i++ {
		store.addAsset(FileAsset{
			ID: uuid.New(), EndpointKey: fmt.Sprintf("GET /v1/%d", i), Direction: DirectionDownload,
			FileName: fmt.Sprintf("report-%d.docx", i), SHA256: &hash,
			LastSeen: time.Now().UTC(), SensitiveTypes: []string{},
		})
	}
	rr := do(t, newTestMux(store, injectPrincipal(apidata.PermDataRead)), "/api/v1/api-security/file-assets/lineage?sha256="+hash)
	var body struct {
		Data FileLineage `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if rr.Code != http.StatusOK || body.Data.Total != 101 || len(body.Data.Items) != 100 || !body.Data.Truncated || body.Data.DownloadAssets != 100 {
		t.Fatalf("lineage truncation not disclosed: status=%d data=%+v", rr.Code, body.Data)
	}
	if rr := do(t, newTestMux(store, noPrincipal), "/api/v1/api-security/file-assets/lineage?sha256="+hash); rr.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous lineage: status=%d, want 401", rr.Code)
	}
	if rr := do(t, newTestMux(store, injectPrincipal("other.read")), "/api/v1/api-security/file-assets/lineage?sha256="+hash); rr.Code != http.StatusForbidden {
		t.Fatalf("forbidden lineage: status=%d, want 403", rr.Code)
	}
}
