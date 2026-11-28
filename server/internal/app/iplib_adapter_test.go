package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/jiuzhang-waf/server/internal/apigeo"
	"github.com/jiuzhang-waf/server/internal/iplibhttp"
	"github.com/jiuzhang-waf/server/internal/nodesync"
	"github.com/jiuzhang-waf/server/internal/systemalerts"
	"github.com/jiuzhang-waf/server/internal/threatintel"
)

type stubGeoIPNodeSyncer struct {
	pushResults []nodesync.GeoIPPeerPushResult
	pushErr     error
	peerStatus  []nodesync.GeoIPPeerStatus
	statusErr   error

	gotSlot     string
	gotPath     string
	gotSHA      string
	gotRevision string
}

func (s *stubGeoIPNodeSyncer) PushGeoIPSlotToPeers(_ context.Context, slot, filePath, expectedSHA256, revision string) ([]nodesync.GeoIPPeerPushResult, error) {
	s.gotSlot, s.gotPath, s.gotSHA, s.gotRevision = slot, filePath, expectedSHA256, revision
	return s.pushResults, s.pushErr
}

func (s *stubGeoIPNodeSyncer) ListPeerGeoIPStatus(_ context.Context) ([]nodesync.GeoIPPeerStatus, error) {
	return s.peerStatus, s.statusErr
}

func TestHAGeoPusherAdapter(t *testing.T) {
	now := time.Date(2026, 11, 28, 17, 0, 0, 0, time.UTC)
	stub := &stubGeoIPNodeSyncer{
		pushResults: []nodesync.GeoIPPeerPushResult{
			{NodeID: "id-1", NodeName: "standby-1", OK: true, Slot: "ip2region_v4", SHA256: "aaa"},
			{NodeID: "id-2", NodeName: "standby-2", OK: false, Slot: "ip2region_v4", Error: "dial timeout"},
		},
		peerStatus: []nodesync.GeoIPPeerStatus{
			{
				NodeID:     "id-1",
				NodeName:   "standby-1",
				Reachable:  true,
				GeoIPReady: true,
				Revision:   "rev-1",
				UpdatedAt:  &now,
				Slots: map[string]nodesync.GeoIPSlotMeta{
					"ip2region_v4": {Filename: "ip2region_v4.xdb", SHA256: "aaa", SizeBytes: 1234},
				},
			},
			{
				NodeID:    "id-2",
				NodeName:  "standby-2",
				Reachable: false,
				Error:     "unreachable",
			},
		},
	}

	adapter := haGeoPusherAdapter{mgr: stub}

	pushRes, err := adapter.PushGeoIPSlot(context.Background(), "ip2region_v4", "/data/geoip/ip2region_v4.xdb", "aaa", "rev-1")
	if err != nil {
		t.Fatalf("PushGeoIPSlot: %v", err)
	}
	if stub.gotSlot != "ip2region_v4" || stub.gotPath != "/data/geoip/ip2region_v4.xdb" || stub.gotSHA != "aaa" || stub.gotRevision != "rev-1" {
		t.Fatalf("forwarded args mismatch: %+v", stub)
	}
	if len(pushRes) != 2 || pushRes[0].Status != "SUCCESS" || pushRes[0].SHA256 != "aaa" ||
		pushRes[1].Status != "FAILED" || pushRes[1].Error != "dial timeout" {
		t.Fatalf("unexpected push results: %+v", pushRes)
	}

	peers, err := adapter.ListPeerGeoIPStatus(context.Background())
	if err != nil {
		t.Fatalf("ListPeerGeoIPStatus: %v", err)
	}
	if len(peers) != 2 || !peers[0].Reachable || !peers[0].GeoIPReady ||
		peers[0].Slots["ip2region_v4"].SHA256 != "aaa" || peers[0].Slots["ip2region_v4"].SizeBytes != 1234 {
		t.Fatalf("unexpected peer[0]: %+v", peers)
	}
	if peers[1].Reachable || peers[1].Error != "unreachable" || peers[1].Slots == nil {
		t.Fatalf("unexpected peer[1]: %+v", peers[1])
	}

	// nil manager 保护
	nilAdapter := haGeoPusherAdapter{}
	if _, err := nilAdapter.PushGeoIPSlot(context.Background(), "ip2region_v4", "/x", "a", "r"); !errors.Is(err, apigeo.ErrHAPusherUnavailable) {
		t.Fatalf("nil manager push = %v, want ErrHAPusherUnavailable", err)
	}
	if emptyPeers, err := nilAdapter.ListPeerGeoIPStatus(context.Background()); err != nil || len(emptyPeers) != 0 {
		t.Fatalf("nil manager status = (%+v, %v), want empty", emptyPeers, err)
	}
}

type stubIPLibFetcher struct {
	gotReq iplibhttp.FetchRequest
	res    *iplibhttp.FetchResult
	err    error
}

func (s *stubIPLibFetcher) Fetch(_ context.Context, req iplibhttp.FetchRequest) (*iplibhttp.FetchResult, error) {
	s.gotReq = req
	return s.res, s.err
}

func TestThreatIntelDownloaderAdapter(t *testing.T) {
	// 1. 200 OK 正常流式读取并回传 ETag/LastModified，缺省 MaxBytes 兜底为 MaxOnlineContentBytes
	closed := false
	rc := &trackCloseReader{Reader: bytes.NewReader([]byte("1.2.3.4\n5.6.7.8\n")), closed: &closed}
	stub := &stubIPLibFetcher{
		res: &iplibhttp.FetchResult{
			StatusCode:   http.StatusOK,
			Body:         rc,
			ETag:         `"e1"`,
			LastModified: "Sat, 28 Nov 2026 08:00:00 GMT",
		},
	}
	adapter := threatIntelDownloaderAdapter{fetcher: stub}
	resp, err := adapter.Fetch(context.Background(), threatintel.FeedFetchRequest{
		SourceMode:   iplibhttp.SourceModeOfficial,
		URL:          "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
		ETag:         `"old"`,
		LastModified: "Fri, 27 Nov 2026 08:00:00 GMT",
	})
	if err != nil {
		t.Fatalf("Fetch 200: %v", err)
	}
	if !closed {
		t.Fatal("expected underlying response body to be closed")
	}
	if stub.gotReq.MaxBytes != threatintel.MaxOnlineContentBytes || stub.gotReq.ETag != `"old"` {
		t.Fatalf("unexpected forwarded request: %+v", stub.gotReq)
	}
	if resp.NotModified || string(resp.Body) != "1.2.3.4\n5.6.7.8\n" || resp.ETag != `"e1"` {
		t.Fatalf("unexpected resp: %+v", resp)
	}

	// 2. 304 Not Modified 短路
	stub.res = &iplibhttp.FetchResult{
		StatusCode:  http.StatusNotModified,
		NotModified: true,
		ETag:        `"e1"`,
	}
	resp304, err := adapter.Fetch(context.Background(), threatintel.FeedFetchRequest{
		SourceMode: iplibhttp.SourceModeOfficial,
		URL:        "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
		ETag:       `"e1"`,
		MaxBytes:   4096,
	})
	if err != nil || !resp304.NotModified || len(resp304.Body) != 0 || stub.gotReq.MaxBytes != 4096 {
		t.Fatalf("unexpected 304 resp: %+v err=%v", resp304, err)
	}

	// 3. nil fetcher 返回 ErrOfflineOnly
	if _, err := (threatIntelDownloaderAdapter{}).Fetch(context.Background(), threatintel.FeedFetchRequest{}); !errors.Is(err, iplibhttp.ErrOfflineOnly) {
		t.Fatalf("nil fetcher = %v, want ErrOfflineOnly", err)
	}
}

type trackCloseReader struct {
	io.Reader
	closed *bool
}

func (r *trackCloseReader) Close() error {
	*r.closed = true
	return nil
}

type stubAlertNotifier struct {
	alertType string
	component string
	title     string
	message   string
	err       error
}

func (s *stubAlertNotifier) NotifyFailure(_ context.Context, alertType, component, title, message string) (*systemalerts.Alert, error) {
	s.alertType, s.component, s.title, s.message = alertType, component, title, message
	return nil, s.err
}

func TestMakeIPLibAlertFunc(t *testing.T) {
	stub := &stubAlertNotifier{}
	fn := makeIPLibAlertFunc(stub)
	fn(context.Background(), systemalerts.TypeGeoIPSyncFailed, "geoip:ip2region_v4", "更新失败", "detail")
	if stub.alertType != systemalerts.TypeGeoIPSyncFailed || stub.component != "geoip:ip2region_v4" || stub.message != "detail" {
		t.Fatalf("alert not forwarded: %+v", stub)
	}
	// nil notifier 安全空操作
	makeIPLibAlertFunc(nil)(context.Background(), systemalerts.TypeGeoIPNodeDrift, "geoip:country", "drift", "msg")
}
