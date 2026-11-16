package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

func TestLLMTokenBudgetLiveGateway(t *testing.T) {
	if os.Getenv("WDSP_LLM_BUDGET_LIVE_TEST") != "1" {
		t.Skip("set WDSP_LLM_BUDGET_LIVE_TEST=1 to use the isolated live gateway verification")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := gatewayconfig.NewCaddyClient("/var/run/caddy/admin.sock").Ping(ctx); err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", "/var/run/caddy/admin.sock")
	}}
	admin := &http.Client{Transport: transport}
	defer transport.CloseIdleConnections()
	adminPath := "/config/apps/http/servers/wdsp_llm_budget_verification"
	missing, err := ooxmlLiveServerMissing(ctx, admin, adminPath)
	if err != nil {
		t.Fatal(err)
	}
	if !missing {
		t.Fatal("temporary server must not already exist")
	}

	runID := fmt.Sprintf("%d", time.Now().UnixNano())
	applicationID := "22222222-2222-4222-8222-222222222222"
	logPaths := map[string]string{}
	guard := func(mode string, policyAppID string, logName string) map[string]any {
		logPath := "/var/log/caddy/wdsp-llm-budget-" + logName + "-" + runID + ".jsonl"
		logPaths[logName] = logPath
		return map[string]any{
			"handler": "jiuzhang_guard", "app_id": policyAppID, "app_code": "llm-budget-verification",
			"counter_backend": "memory", "events_log": "/tmp/wdsp-llm-budget-" + logName + ".log",
			"api_dynamic_protection": true, "api_protection_mode": "PROTECT", "api_events_log": logPath,
			"api_llm_security_policies": []detectors.LLMSecurityPolicy{{
				ID: "11111111-1111-4111-8111-111111111111", ApplicationID: applicationID,
				Name: "隔离 Token 预算验收", Version: 6, Mode: mode, MaxOutputTokens: 2048,
			}},
		}
	}
	route := func(name string, policyAppID string, mode string) map[string]any {
		return map[string]any{
			"match": []map[string]any{{"host": []string{"llm-budget-" + name + ".verify.local"}, "path": []string{"/v1/chat/completions"}}},
			"handle": []map[string]any{
				guard(mode, policyAppID, name),
				{"handler": "reverse_proxy", "upstreams": []map[string]any{{"dial": "testorigin:8081"}}},
			},
		}
	}
	raw, err := json.Marshal(map[string]any{
		"listen": []string{":18117"}, "automatic_https": map[string]any{"disable": true},
		"routes": []map[string]any{
			route("protect", applicationID, detectors.LLMSecurityProtect),
			route("observe", applicationID, detectors.LLMSecurityObserve),
			route("normal", applicationID, detectors.LLMSecurityProtect),
			route("isolated", "33333333-3333-4333-8333-333333333333", detectors.LLMSecurityProtect),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	status, err := ooxmlLiveAdminRequest(ctx, admin, http.MethodPost, adminPath, raw)
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK {
		t.Fatalf("create temporary server: HTTP %d", status)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		status, err := ooxmlLiveAdminRequest(cleanupCtx, admin, http.MethodDelete, adminPath, nil)
		if err != nil || status != http.StatusOK {
			t.Errorf("remove temporary server: HTTP %d, %v", status, err)
		}
		for _, path := range logPaths {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				t.Errorf("remove test event file: %v", err)
			}
		}
	})

	for _, tc := range []struct {
		name       string
		tokens     int
		wantStatus int
		wantAction string
		wantMatch  bool
	}{
		{"protect", 4096, http.StatusTooManyRequests, "RATE_LIMIT", true},
		{"observe", 4096, http.StatusOK, "OBSERVE", true},
		{"normal", 1024, http.StatusOK, "ALLOW", false},
		{"isolated", 4096, http.StatusOK, "ALLOW", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := requestLLMTokenBudgetLive(t, ctx, tc.name, tc.tokens)
			defer resp.Body.Close()
			_, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("HTTP %d want %d", resp.StatusCode, tc.wantStatus)
			}
			if tc.wantStatus == http.StatusOK && resp.Header.Get("X-Wdsp-Origin-Mark") != "jiuzhang-test-origin" {
				t.Fatal("allowed request did not reach the isolated origin")
			}
			record := readLLMTokenBudgetLiveEvent(t, logPaths[tc.name])
			if record.FinalAction != tc.wantAction {
				t.Fatalf("final_action=%s want %s", record.FinalAction, tc.wantAction)
			}
			found := false
			for _, match := range record.Details {
				if match.RuleID != "llm.output_token_budget_exceeded" {
					continue
				}
				found = true
				if match.Evidence["limit_tokens"] != "2048" || match.Evidence["requested_tokens"] != fmt.Sprintf("%d", tc.tokens) {
					t.Fatalf("evidence=%+v", match.Evidence)
				}
			}
			if found != tc.wantMatch {
				t.Fatalf("finding=%v want %v", found, tc.wantMatch)
			}
		})
	}
}

func requestLLMTokenBudgetLive(t *testing.T, ctx context.Context, name string, tokens int) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`{"model":"gpt-4o","messages":[{"role":"user","content":"普通摘要请求"}],"max_tokens":%d}`, tokens)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://jiuzhang-stage5-gateway:18117/v1/chat/completions", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "llm-budget-" + name + ".verify.local"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "wdsp-llm-budget-"+name)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func readLLMTokenBudgetLiveEvent(t *testing.T, path string) struct {
	FinalAction string `json:"final_action"`
	Details     []struct {
		RuleID   string            `json:"rule_id"`
		Evidence map[string]string `json:"evidence"`
	} `json:"details"`
} {
	t.Helper()
	var record struct {
		FinalAction string `json:"final_action"`
		Details     []struct {
			RuleID   string            `json:"rule_id"`
			Evidence map[string]string `json:"evidence"`
		} `json:"details"`
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) != 1 {
		t.Fatalf("test event lines=%d want 1", len(lines))
	}
	if err := json.Unmarshal(lines[0], &record); err != nil {
		t.Fatal(err)
	}
	return record
}
