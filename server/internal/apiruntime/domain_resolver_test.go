package apiruntime

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apiassets"
)

type fakeDomainAppResolver struct {
	byHost map[string]struct {
		appID uuid.UUID
		domID uuid.UUID
	}
}

func (f *fakeDomainAppResolver) ResolveApplication(context.Context, string) (*uuid.UUID, error) {
	return nil, nil
}

func (f *fakeDomainAppResolver) ResolveDomain(context.Context, *uuid.UUID, string) (*uuid.UUID, error) {
	return nil, nil
}

func (f *fakeDomainAppResolver) ResolveApplicationByDomain(_ context.Context, hostname string) (*uuid.UUID, *uuid.UUID, error) {
	if e, ok := f.byHost[normalizeResolveHost(hostname)]; ok {
		a, d := e.appID, e.domID
		return &a, &d, nil
	}
	return nil, nil, nil
}

type captureDiscoveryUpserter struct {
	inputs []apiassets.DiscoveryInput
}

func (c *captureDiscoveryUpserter) UpsertDiscovery(_ context.Context, in apiassets.DiscoveryInput) (*apiassets.Endpoint, error) {
	c.inputs = append(c.inputs, in)
	return &apiassets.Endpoint{EndpointKey: in.Method + " " + in.PathTemplate}, nil
}

// 回归验证：mirrorcap 旁路事件不携带 app_code/application_id，采集器按 domain 反查归属后，
// 主事件（api_runtime_events）与端点资产发现均带正确的 application_id 与 domain_id。
func TestCollectorBackfillsMirrorAppOwnershipByDomain(t *testing.T) {
	logDir := t.TempDir()
	cpDir := t.TempDir()
	logPath := filepath.Join(logDir, "api-runtime-events.log")
	cpPath := filepath.Join(cpDir, "api-runtime-events.checkpoint")

	appID := uuid.New()
	domID := uuid.New()
	line := `{"request_id":"mirror-1","occurred_at":"2026-11-24T04:00:00Z","domain":"shop.example.com","endpoint_key":"GET /api/items","method":"GET","path_template":"/api/items","is_api":true,"api_confidence":0.95,"risk_score":50,"risk_level":"HIGH","final_action":"OBSERVE","details":[{"detector":"mirror","rule_id":"mirror.capture","category":"INFO","severity":"INFO"}]}` + "\n"
	badLine := "{not-json\n"
	if err := os.WriteFile(logPath, []byte(line+badLine), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	saver := &fakeSaver{}
	disc := &captureDiscoveryUpserter{}
	c := NewCollector(saver, "mirror-owner-test", logPath, cpPath, "gw-1")
	c.SetDiscoveryUpserter(disc)
	c.SetResolver(&fakeDomainAppResolver{
		byHost: map[string]struct {
			appID uuid.UUID
			domID uuid.UUID
		}{
			"shop.example.com": {appID: appID, domID: domID},
		},
	})

	if _, err := c.CollectOnce(context.Background()); err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if len(saver.saved) != 1 {
		t.Fatalf("saved primary events = %d, want 1", len(saver.saved))
	}
	if saver.saved[0].ApplicationID != appID.String() {
		t.Fatalf("PrimaryEvent.ApplicationID = %q, want %q", saver.saved[0].ApplicationID, appID.String())
	}
	if len(disc.inputs) != 1 {
		t.Fatalf("discovery inputs = %d, want 1", len(disc.inputs))
	}
	if disc.inputs[0].ApplicationID == nil || *disc.inputs[0].ApplicationID != appID {
		t.Fatalf("DiscoveryInput.ApplicationID = %v, want %s", disc.inputs[0].ApplicationID, appID)
	}
	if disc.inputs[0].DomainID == nil || *disc.inputs[0].DomainID != domID {
		t.Fatalf("DiscoveryInput.DomainID = %v, want %s", disc.inputs[0].DomainID, domID)
	}
	// 错误文件落入可写 checkpoint 目录，而非只读日志目录
	wantErrFile := filepath.Join(cpDir, "api-runtime-events.log.errors")
	if _, err := os.Stat(wantErrFile); err != nil {
		t.Fatalf("expected error file in checkpoint dir %s: %v", wantErrFile, err)
	}
	if _, err := os.Stat(logPath + ".errors"); !os.IsNotExist(err) {
		t.Fatalf("error file must not be written into log dir when checkpoint dir differs")
	}
}

func TestMatchHostEntryExactAndWildcard(t *testing.T) {
	exactID := uuid.New()
	wildID := uuid.New()
	deepWildID := uuid.New()
	entries := map[string]domainAppEntry{
		"api.example.com":    {appID: exactID},
		"*.example.com":      {appID: wildID},
		"*.prod.example.com": {appID: deepWildID},
	}
	if got, ok := matchHostEntry(normalizeResolveHost("API.Example.COM:8080"), entries); !ok || got.appID != exactID {
		t.Fatalf("exact match failed: %+v ok=%v", got, ok)
	}
	if got, ok := matchHostEntry(normalizeResolveHost("a.prod.example.com"), entries); !ok || got.appID != deepWildID {
		t.Fatalf("more specific wildcard should win: %+v ok=%v", got, ok)
	}
	if got, ok := matchHostEntry(normalizeResolveHost("other.example.com"), entries); !ok || got.appID != wildID {
		t.Fatalf("wildcard match failed: %+v ok=%v", got, ok)
	}
}
