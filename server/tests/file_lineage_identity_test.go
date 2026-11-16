package tests

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestFileLineageIdentityFields(t *testing.T) {
	env := setupStage8Env(t)
	rid := s5Rand()
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte("file-lineage-identity-"+rid)))
	now := time.Now().UTC().Truncate(time.Microsecond)

	type seed struct {
		endpointKey string
		direction   string
		identity    string
		ipMasked    string
		firstSeen   time.Time
		lastSeen    time.Time
	}
	seeds := []seed{
		{
			endpointKey: "POST /api/v1/files/upload-" + rid,
			direction:   "UPLOAD",
			identity:    "auth:uploader-" + rid,
			ipMasked:    "203.0.113.0",
			firstSeen:   now.Add(-3 * time.Hour),
			lastSeen:    now.Add(-2 * time.Hour),
		},
		{
			endpointKey: "GET /api/v1/files/download-" + rid,
			direction:   "DOWNLOAD",
			identity:    "auth:downloader-" + rid,
			ipMasked:    "198.51.100.0",
			firstSeen:   now.Add(-2 * time.Hour),
			lastSeen:    now.Add(-time.Hour),
		},
		{
			endpointKey: "GET /api/v1/files/anonymous-" + rid,
			direction:   "DOWNLOAD",
			identity:    "",
			ipMasked:    "192.0.2.0",
			firstSeen:   now.Add(-90 * time.Minute),
			lastSeen:    now.Add(-30 * time.Minute),
		},
	}
	for _, asset := range seeds {
		s8Exec(t, env, `INSERT INTO api_file_assets
			(endpoint_key, direction, filename, extension, mime, size_bytes, sha256,
			 identity_fingerprint, client_ip_masked, first_seen, last_seen)
			VALUES ($1,$2,'lineage.pdf','pdf','application/pdf',128,$3,$4,$5,$6,$7)`,
			asset.endpointKey, asset.direction, hash, asset.identity, asset.ipMasked,
			asset.firstSeen, asset.lastSeen)
	}

	cookies, _ := env.s5Login(t, "file_lineage", "SYSTEM_ADMIN")
	resp := env.get(t, "/api/v1/api-security/file-assets/lineage?sha256="+hash+"&days=7", cookies)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("lineage status = %d, want 200, body: %s", resp.StatusCode, readBodyString(t, resp))
	}
	var body struct {
		Data struct {
			SHA256         string `json:"sha256"`
			Total          int64  `json:"total"`
			UploadAssets   int64  `json:"upload_assets"`
			DownloadAssets int64  `json:"download_assets"`
			Items          []struct {
				EndpointKey         string    `json:"endpoint_key"`
				Direction           string    `json:"direction"`
				IdentityFingerprint *string   `json:"identity_fingerprint"`
				ClientIPMasked      string    `json:"client_ip_masked"`
				FirstSeen           time.Time `json:"first_seen"`
				LastSeen            time.Time `json:"last_seen"`
			} `json:"items"`
		} `json:"data"`
	}
	readJSON(t, resp, &body)
	got := body.Data
	if got.SHA256 != hash || got.Total != 3 || got.UploadAssets != 1 || got.DownloadAssets != 2 || len(got.Items) != 3 {
		t.Fatalf("unexpected lineage response: %+v", got)
	}

	items := make(map[string]int, len(got.Items))
	for i := range got.Items {
		items[got.Items[i].EndpointKey] = i
	}
	for _, want := range seeds {
		i, ok := items[want.endpointKey]
		if !ok {
			t.Fatalf("lineage item missing for %s: %+v", want.endpointKey, got.Items)
		}
		item := got.Items[i]
		if item.IdentityFingerprint == nil {
			t.Fatalf("identity_fingerprint missing for %s", want.endpointKey)
		}
		if *item.IdentityFingerprint != want.identity || item.ClientIPMasked != want.ipMasked ||
			item.Direction != want.direction || !item.FirstSeen.Equal(want.firstSeen) ||
			!item.LastSeen.Equal(want.lastSeen) {
			t.Fatalf("lineage item changed source fields: got %+v, want %+v", item, want)
		}
	}
}
