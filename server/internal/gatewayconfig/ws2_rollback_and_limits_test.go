package gatewayconfig

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type fakeSecretsOnlyGuardProvider struct {
	fakeGuardProvider
	secretsCfg   *GuardConfig
	secretsErr   error
	secretsCalls int
}

func (f *fakeSecretsOnlyGuardProvider) LoadCurrentSecrets(context.Context) (*GuardConfig, error) {
	f.secretsCalls++
	return f.secretsCfg, f.secretsErr
}

// TestReinjectConfigSecretsPrefersLoadCurrentSecretsOverBuildGuardConfig 验证当 GuardProvider
// 实现窄接口 LoadCurrentSecrets 时，即使 BuildGuardConfig 因当前策略损坏而失败，应急回滚仍能成功重注入密钥。
func TestReinjectConfigSecretsPrefersLoadCurrentSecretsOverBuildGuardConfig(t *testing.T) {
	stored, err := RedactConfigSecrets(generateGuardJSON(t, secretTestGuardConfig("old")))
	if err != nil {
		t.Fatalf("RedactConfigSecrets: %v", err)
	}
	fake := &fakeSecretsOnlyGuardProvider{
		fakeGuardProvider: fakeGuardProvider{buildErr: errors.New("current policy gate broken")},
		secretsCfg:        secretTestGuardConfig("new"),
	}
	p := &Publisher{guard: fake}
	out, err := p.reinjectConfigSecrets(context.Background(), stored)
	if err != nil {
		t.Fatalf("reinjectConfigSecrets should succeed via LoadCurrentSecrets even when BuildGuardConfig fails: %v", err)
	}
	if fake.secretsCalls != 1 || fake.buildCalls != 0 {
		t.Fatalf("expected secretsCalls=1 buildCalls=0, got secrets=%d build=%d", fake.secretsCalls, fake.buildCalls)
	}
	if !strings.Contains(out, "new-valkey-secret") {
		t.Fatalf("expected reinjected secret in output")
	}
}

// TestStripAPIGuardSectionsCoversAllNewWDSPSections 验证 stripAPIGuardSections 剥除全部
// 新增 API 段（强流程/gRPC 绑定/MCP 目录与绑定/机器身份三段/授权快照元数据）且不修改入参。
func TestStripAPIGuardSectionsCoversAllNewWDSPSections(t *testing.T) {
	now := time.Now().UTC()
	orig := secretTestGuardConfig("old")
	orig.APIAuthzSnapshotStale = true
	orig.APIAuthzSnapshotExpiresAt = &now
	orig.APIStrongFlows = []GuardStrongFlowDefinition{{DefinitionID: "sf-1", Name: "pay"}}
	orig.APIGRPCBindings = []GuardGRPCBinding{{ApplicationID: "app-1", Service: "svc", Mode: "PROTECT"}}
	orig.APIMCPToolCatalogs = []GuardMCPToolCatalog{{Name: "cat-1"}}
	orig.APIMCPBindings = []GuardMCPBinding{{ApplicationID: "app-1", EndpointPath: "/mcp", Mode: "PROTECT"}}
	orig.APIMachineIdentities = []GuardMachineIdentity{{IdentityName: "mid-1", Status: "ENABLED"}}
	orig.APIMachineIdentityBindings = []GuardMachineIdentityBinding{{ApplicationID: "app-1", PathPrefix: "/api", Mode: "PROTECT"}}
	orig.APIMachineIdentityMeta = &GuardMachineIdentityMeta{RevocationWatermark: 7, RegistryVersion: 123}

	stripped := stripAPIGuardSections(orig)
	if stripped.APIAuthzSnapshotStale || stripped.APIAuthzSnapshotExpiresAt != nil ||
		stripped.APIStrongFlows != nil || stripped.APIGRPCBindings != nil ||
		stripped.APIMCPToolCatalogs != nil || stripped.APIMCPBindings != nil ||
		stripped.APIMachineIdentities != nil || stripped.APIMachineIdentityBindings != nil ||
		stripped.APIMachineIdentityMeta != nil {
		t.Fatalf("stripAPIGuardSections leaked WDSP sections: %+v", stripped)
	}
	if !orig.APIAuthzSnapshotStale || len(orig.APIStrongFlows) != 1 || orig.APIMachineIdentityMeta == nil {
		t.Fatal("stripAPIGuardSections must not mutate original GuardConfig")
	}
}

// TestCaddyClientGetCurrentConfigSupportsLargePayloadAndFailsClosedOnOverflow 验证：
// 1) 超过旧 4 MiB 上限（例如 5 MiB）的配置可完整读取不被静默截断；
// 2) 超过 32 MiB 硬上限时显式报错（fail-closed）而非截断返回半截 JSON。
func TestCaddyClientGetCurrentConfigSupportsLargePayloadAndFailsClosedOnOverflow(t *testing.T) {
	largePayload := `{"pad":"` + strings.Repeat("a", 5<<20) + `"}`
	clientOK := &CaddyClient{
		baseURL: "http://admin",
		httpClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(largePayload)),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		})},
	}
	got, err := clientOK.GetCurrentConfig(context.Background())
	if err != nil {
		t.Fatalf("GetCurrentConfig(5 MiB): %v", err)
	}
	if len(got) != len(largePayload) {
		t.Fatalf("GetCurrentConfig truncated payload: got %d bytes, want %d", len(got), len(largePayload))
	}

	oversize := bytes.Repeat([]byte("x"), maxCurrentConfigBytes+1)
	clientOverflow := &CaddyClient{
		baseURL: "http://admin",
		httpClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(oversize)),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		})},
	}
	if _, err := clientOverflow.GetCurrentConfig(context.Background()); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("GetCurrentConfig(>32 MiB) err = %v, want explicit size limit error", err)
	}
}
