package tests

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
)

func runCloudAPIDataFlowBrowser(t *testing.T, env *testEnv, applicationID uuid.UUID, username, password string) {
	t.Helper()
	runRequestEvidenceBrowser(t, env, applicationID, username, password, "api-data-flow.spec.ts")
}

func runRequestAuditBrowser(t *testing.T, env *testEnv, username, password string) {
	t.Helper()
	if os.Getenv("WDSP_DATA_FLOW_BROWSER_E2E") != "1" {
		return
	}
	runRequestEvidenceBrowser(t, env, uuid.Nil, username, password, "request-audit.spec.ts")
}

func runRequestEvidenceBrowser(t *testing.T, env *testEnv, applicationID uuid.UUID, username, password, spec string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate browser test port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("release browser test port: %v", err)
	}
	webDir, err := filepath.Abs("../../web")
	if err != nil {
		t.Fatalf("resolve web directory: %v", err)
	}
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	artifactDir, err := os.MkdirTemp("", "wdsp-data-flow-browser-")
	if err != nil {
		t.Fatalf("create browser artifact directory: %v", err)
	}
	t.Cleanup(func() {
		if !t.Failed() {
			_ = os.RemoveAll(artifactDir)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "npx", "playwright", "test", "--config=playwright.data-flow.config.ts", spec)
	command.WaitDelay = 10 * time.Second
	command.Dir = webDir
	command.Env = append(os.Environ(),
		"CI=1",
		"WDSP_REQUEST_AUDIT_E2E="+strconv.FormatBool(spec == "request-audit.spec.ts" || spec == "request-pcap.spec.ts"),
		"E2E_BASE_URL="+baseURL,
		"E2E_SEC_USER="+username,
		"E2E_SEC_PWD="+password,
		"VITE_API_PROXY="+env.server.URL,
		"VALKEY_HOST="+env.cfg.Cache.Host,
		"VALKEY_PORT="+strconv.Itoa(env.cfg.Cache.Port),
		"VALKEY_PASSWORD="+env.cfg.Cache.Password,
		"VALKEY_DB="+strconv.Itoa(env.cfg.Cache.DB),
		"WDSP_DATA_FLOW_APPLICATION_ID="+applicationID.String(),
		"WDSP_DATA_FLOW_FRONTEND_PORT="+strconv.Itoa(port),
		"WDSP_DATA_FLOW_TEST_OUTPUT="+filepath.Join(artifactDir, "playwright"),
	)
	output, err := command.CombinedOutput()
	t.Logf("真实数据流浏览器验收:\n%s", output)
	if ctx.Err() != nil {
		t.Fatalf("browser E2E timed out: %v (artifacts=%s)", ctx.Err(), artifactDir)
	}
	if err != nil {
		t.Fatalf("browser E2E failed: %v (artifacts=%s)", err, artifactDir)
	}
}
