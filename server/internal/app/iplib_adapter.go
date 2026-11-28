// iplib_adapter.go 装配层窄接口适配器：桥接 nodesync.Manager → apigeo.HAGeoPusher、
// iplibhttp.Downloader → threatintel.FeedDownloader 与 systemalerts.Engine → 告警回调，
// 保持各业务领域包零循环依赖。
package app

import (
	"context"
	"io"
	"log/slog"

	"github.com/jiuzhang-waf/server/internal/apigeo"
	"github.com/jiuzhang-waf/server/internal/iplibhttp"
	"github.com/jiuzhang-waf/server/internal/nodesync"
	"github.com/jiuzhang-waf/server/internal/systemalerts"
	"github.com/jiuzhang-waf/server/internal/threatintel"
)

// geoIPNodeSyncer 是 *nodesync.Manager 的窄接口抽象，便于装配层单测注入桩实现。
type geoIPNodeSyncer interface {
	PushGeoIPSlotToPeers(ctx context.Context, slot, filePath, expectedSHA256, revision string) ([]nodesync.GeoIPPeerPushResult, error)
	ListPeerGeoIPStatus(ctx context.Context) ([]nodesync.GeoIPPeerStatus, error)
}

var _ geoIPNodeSyncer = (*nodesync.Manager)(nil)

// haGeoPusherAdapter 将 nodesync.Manager 适配为 apigeo.HAGeoPusher。
type haGeoPusherAdapter struct {
	mgr geoIPNodeSyncer
}

var _ apigeo.HAGeoPusher = haGeoPusherAdapter{}

func (a haGeoPusherAdapter) PushGeoIPSlot(ctx context.Context, slot, filePath, sha256Hex, revision string) ([]apigeo.HANodeSyncResult, error) {
	if a.mgr == nil {
		return nil, apigeo.ErrHAPusherUnavailable
	}
	rawResults, err := a.mgr.PushGeoIPSlotToPeers(ctx, slot, filePath, sha256Hex, revision)
	if err != nil {
		return nil, err
	}
	out := make([]apigeo.HANodeSyncResult, 0, len(rawResults))
	for _, r := range rawResults {
		status := "FAILED"
		if r.OK && r.Error == "" {
			status = "SUCCESS"
		}
		out = append(out, apigeo.HANodeSyncResult{
			NodeID:   r.NodeID,
			NodeName: r.NodeName,
			Status:   status,
			SHA256:   r.SHA256,
			Error:    r.Error,
		})
	}
	return out, nil
}

func (a haGeoPusherAdapter) ListPeerGeoIPStatus(ctx context.Context) ([]apigeo.HANodeGeoStatus, error) {
	if a.mgr == nil {
		return []apigeo.HANodeGeoStatus{}, nil
	}
	peers, err := a.mgr.ListPeerGeoIPStatus(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]apigeo.HANodeGeoStatus, 0, len(peers))
	for _, p := range peers {
		slots := make(map[string]apigeo.HANodeSlotDigest, len(p.Slots))
		for k, meta := range p.Slots {
			slots[k] = apigeo.HANodeSlotDigest{
				Filename:  meta.Filename,
				SHA256:    meta.SHA256,
				SizeBytes: meta.SizeBytes,
			}
		}
		out = append(out, apigeo.HANodeGeoStatus{
			NodeID:     p.NodeID,
			NodeName:   p.NodeName,
			Reachable:  p.Reachable,
			GeoIPReady: p.GeoIPReady,
			Revision:   p.Revision,
			UpdatedAt:  p.UpdatedAt,
			Slots:      slots,
			Error:      p.Error,
		})
	}
	return out, nil
}

// ipLibFetcher 是 *iplibhttp.Downloader 的窄接口抽象。
type ipLibFetcher interface {
	Fetch(ctx context.Context, req iplibhttp.FetchRequest) (*iplibhttp.FetchResult, error)
}

var _ ipLibFetcher = (*iplibhttp.Downloader)(nil)

// threatIntelDownloaderAdapter 将 iplibhttp.Downloader 适配为 threatintel.FeedDownloader。
type threatIntelDownloaderAdapter struct {
	fetcher ipLibFetcher
}

var _ threatintel.FeedDownloader = threatIntelDownloaderAdapter{}

func (a threatIntelDownloaderAdapter) Fetch(ctx context.Context, req threatintel.FeedFetchRequest) (*threatintel.FeedFetchResponse, error) {
	if a.fetcher == nil {
		return nil, iplibhttp.ErrOfflineOnly
	}
	maxBytes := req.MaxBytes
	if maxBytes <= 0 {
		maxBytes = threatintel.MaxOnlineContentBytes
	}
	res, err := a.fetcher.Fetch(ctx, iplibhttp.FetchRequest{
		SourceMode:   req.SourceMode,
		URL:          req.URL,
		ETag:         req.ETag,
		LastModified: req.LastModified,
		MaxBytes:     maxBytes,
	})
	if err != nil {
		return nil, err
	}
	if res.NotModified {
		return &threatintel.FeedFetchResponse{
			NotModified:  true,
			ETag:         res.ETag,
			LastModified: res.LastModified,
			StatusCode:   res.StatusCode,
		}, nil
	}
	var body []byte
	if res.Body != nil {
		defer res.Body.Close()
		body, err = io.ReadAll(res.Body)
		if err != nil {
			return nil, err
		}
	}
	return &threatintel.FeedFetchResponse{
		NotModified:  false,
		Body:         body,
		ETag:         res.ETag,
		LastModified: res.LastModified,
		StatusCode:   res.StatusCode,
	}, nil
}

// failureAlertNotifier 是 *systemalerts.Engine 的窄接口抽象。
type failureAlertNotifier interface {
	NotifyFailure(ctx context.Context, alertType, component, title, message string) (*systemalerts.Alert, error)
}

var _ failureAlertNotifier = (*systemalerts.Engine)(nil)

func makeIPLibAlertFunc(notifier failureAlertNotifier) func(ctx context.Context, alertType, component, title, message string) {
	return func(ctx context.Context, alertType, component, title, message string) {
		if notifier == nil {
			return
		}
		if _, err := notifier.NotifyFailure(ctx, alertType, component, title, message); err != nil {
			slog.Warn("raise ip library system alert failed",
				"alert_type", alertType, "component", component, "error", err)
		}
	}
}
