package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/uuid"
	"github.com/jiuzhang-waf/gateway/dynamic_security/evidencekey"
	"github.com/jiuzhang-waf/gateway/pcapevidence"
	"github.com/jiuzhang-waf/server/internal/accesslogs"
	"github.com/jiuzhang-waf/server/internal/config"
	"github.com/jiuzhang-waf/server/internal/requestpcap"
)

func TestRequestPCAPFullStackEndToEnd(t *testing.T) {
	root := t.TempDir()
	hotRoot, warmRoot := filepath.Join(root, "hot"), filepath.Join(root, "warm")
	publicDir := filepath.Join(root, "public")
	privateDir := filepath.Join(root, "private")
	for _, directory := range []string{hotRoot, warmRoot, publicDir, privateDir} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := baseTestCfg()
	cfg.Security.TrustedProxyCIDRs = []string{"127.0.0.1/32"}
	cfg.WAF.GatewayNodeName = "gw-pcap-e2e"
	cfg.RequestPCAP = config.RequestPCAPConfig{HotDir: hotRoot, WarmDir: warmRoot, KeyFile: filepath.Join(privateDir, "private.key"), PublicDir: publicDir,
		Retention: time.Hour, HotAge: time.Hour, GrantTTL: time.Hour, MigrateBytesPerSecond: 32 << 20, MinFreePercent: 1}
	env := newTestEnv(t, cfg)
	env.sourceIP = "192.0.2.40"
	env.importBaseLicense(t)
	username := "pcap_" + s5Rand()
	password := "S5@Test2026!"
	env.createUserDirect(t, username, password, "SECURITY_ADMIN")
	cookies, csrf := env.login(t, username, password)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	env.app.StartRequestPCAP(ctx)
	grantBytes, err := os.ReadFile(filepath.Join(publicDir, "pcap-public.json"))
	if err != nil {
		t.Fatal(err)
	}
	trust, err := os.ReadFile(filepath.Join(publicDir, "pcap-release.pub"))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, initialKeyID, err := evidencekey.VerifyPublicKeyGrant(grantBytes, trust, cfg.WAF.GatewayNodeName, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	provider, err := pcapevidence.NewPublicKeyDEKProvider(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	requestID := "req-pcap-e2e"
	traceID := "0123456789abcdef0123456789abcdef"
	logEntry := &accesslogs.LogEntry{OccurredAt: time.Now().UTC(), RequestID: requestID, Domain: "shop.internal", GatewayNodeID: cfg.WAF.GatewayNodeName,
		ClientIP: "192.0.2.10", RequestMethod: "POST", RequestURI: "/v1/pcap", RequestPath: "/v1/pcap", EndpointKey: "POST /v1/pcap", PathTemplate: "/v1/pcap", TraceID: traceID,
		RequestHeaders: map[string][]string{}, ResponseHeaders: map[string][]string{}}
	if _, err := accesslogs.NewStore(env.db).Insert(ctx, logEntry); err != nil {
		t.Fatal(err)
	}
	artifactID, plaintext := writeRealPCAPSpool(t, provider, hotRoot, cfg.WAF.GatewayNodeName, requestID, traceID)
	var lookup struct {
		Data requestpcap.EvidenceStatus `json:"data"`
	}
	deadline := time.Now().Add(12 * time.Second)
	for {
		resp := env.get(t, "/api/v1/request-pcap/lookup?request_id="+requestID, cookies)
		if err := json.NewDecoder(resp.Body).Decode(&lookup); err != nil {
			resp.Body.Close()
			t.Fatal(err)
		}
		resp.Body.Close()
		if len(lookup.Data.Items) == 1 {
			artifactID = lookup.Data.Items[0].ArtifactID
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("PCAP spool did not produce request evidence: %+v", lookup.Data)
		}
		time.Sleep(100 * time.Millisecond)
	}
	verifyBody := fmt.Sprintf(`{"request_id":%q,"reason":%q}`, requestID, "真实完整性核验")
	resp := env.post(t, "/api/v1/request-pcap/artifacts/"+artifactID.String()+"/verify", verifyBody, cookies, csrf)
	assertRequestAuditStatus(t, resp, http.StatusOK)
	resp.Body.Close()
	grantPath := "/api/v1/request-pcap/artifacts/" + artifactID.String() + "/download-grants"
	grantBody := fmt.Sprintf(`{"request_id":%q,"reason":%q,"password":%q}`, requestID, "真实安全事件取证", password)
	resp = env.post(t, grantPath, grantBody, cookies, "")
	assertRequestAuditStatus(t, resp, http.StatusForbidden)
	resp.Body.Close()
	resp = env.post(t, grantPath, fmt.Sprintf(`{"request_id":%q,"reason":%q,"password":%q}`, requestID, "真实安全事件取证", "wrong-password"), cookies, csrf)
	assertRequestAuditStatus(t, resp, http.StatusBadRequest)
	resp.Body.Close()
	resp = env.post(t, grantPath, grantBody, cookies, csrf)
	assertRequestAuditStatus(t, resp, http.StatusCreated)
	var grant struct {
		Data struct {
			ID uuid.UUID `json:"grant_id"`
		} `json:"data"`
	}
	decodeRequestAuditResponse(t, resp, &grant)
	downloadPath := fmt.Sprintf("/api/v1/request-pcap/artifacts/%s/download?request_id=%s&grant_id=%s", artifactID, requestID, grant.Data.ID)
	resp = env.get(t, downloadPath, cookies)
	assertRequestAuditStatus(t, resp, http.StatusOK)
	downloaded, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	var expected bytes.Buffer
	if _, err := pcapevidence.ExportPCAPRange(bytes.NewReader(plaintext), &expected, 1, 1); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(downloaded, expected.Bytes()) {
		t.Fatal("full-stack downloaded PCAP does not match the real encrypted evidence")
	}
	resp = env.get(t, downloadPath, cookies)
	assertRequestAuditStatus(t, resp, http.StatusForbidden)
	resp.Body.Close()

	resp = env.post(t, "/api/v1/request-pcap/keys/rotate", fmt.Sprintf(`{"reason":%q,"password":%q}`, "轮换后验证历史证据", password), cookies, csrf)
	assertRequestAuditStatus(t, resp, http.StatusOK)
	resp.Body.Close()
	rotatedGrant, err := os.ReadFile(filepath.Join(publicDir, "pcap-public.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, rotatedKeyID, err := evidencekey.VerifyPublicKeyGrant(rotatedGrant, trust, cfg.WAF.GatewayNodeName, time.Now())
	if err != nil || rotatedKeyID == initialKeyID {
		t.Fatalf("rotated public key grant invalid: %v", err)
	}
	resp = env.post(t, grantPath, grantBody, cookies, csrf)
	assertRequestAuditStatus(t, resp, http.StatusCreated)
	decodeRequestAuditResponse(t, resp, &grant)
	resp = env.get(t, fmt.Sprintf("/api/v1/request-pcap/artifacts/%s/download?request_id=%s&grant_id=%s", artifactID, requestID, grant.Data.ID), cookies)
	assertRequestAuditStatus(t, resp, http.StatusOK)
	resp.Body.Close()

	auditUser := "pcap_audit_" + s5Rand()
	env.createUserDirect(t, auditUser, password, "AUDIT_ADMIN")
	auditCookies, _ := env.login(t, auditUser, password)
	resp = env.get(t, "/api/v1/request-pcap/lookup?request_id="+requestID, auditCookies)
	assertRequestAuditStatus(t, resp, http.StatusOK)
	resp.Body.Close()
	resp = env.get(t, downloadPath, auditCookies)
	assertRequestAuditStatus(t, resp, http.StatusForbidden)
	resp.Body.Close()
	var failureAudits int
	if err := env.db.QueryRow(ctx, `SELECT count(*) FROM operation_audits WHERE action='request_pcap.download_grant' AND result='FAILURE'`).Scan(&failureAudits); err != nil || failureAudits < 1 {
		t.Fatalf("wrong-password audit missing: count=%d err=%v", failureAudits, err)
	}
	if _, err := env.db.Exec(ctx, `INSERT INTO api_runtime_events(request_id,endpoint_key,identity_fingerprint,jwt_verification,details_json,occurred_at)
		VALUES($1,'POST /v1/pcap','identity-pcap-e2e','{"status":"VERIFIED"}',
		'[{"detector":"sensitive_data","rule_id":"sensitive.field","evidence":{"field":"pwd","location":"form","direction":"REQUEST","data_type":"credential"}}]',now())`, requestID); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("WDSP_DATA_FLOW_BROWSER_E2E") == "1" {
		runRequestEvidenceBrowser(t, env, uuid.Nil, username, password, "request-pcap.spec.ts")
	}
}

func writeRealPCAPSpool(t *testing.T, provider *pcapevidence.PublicKeyDEKProvider, hotRoot, nodeID, requestID, traceID string) (uuid.UUID, []byte) {
	t.Helper()
	artifactID, err := pcapevidence.NewArtifactID()
	if err != nil {
		t.Fatal(err)
	}
	dek, err := provider.NewDEK(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(hotRoot, artifactID.String()+".wpcap")
	writer, err := pcapevidence.NewSegmentWriter(path, pcapevidence.Segment{ArtifactID: artifactID, NodeID: nodeID, CapturePoint: "GATEWAY_EGRESS", StartedAt: time.Now().UTC(), PacketCount: 1, PolicyVersion: "full-stack-test"}, dek.Key)
	clear(dek.Key)
	if err != nil {
		t.Fatal(err)
	}
	var plaintext bytes.Buffer
	pcapWriter := pcapgo.NewWriter(&plaintext)
	if err := pcapWriter.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	packet := bytes.Repeat([]byte{0x5a}, 64)
	if err := pcapWriter.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now().UTC(), CaptureLength: len(packet), Length: len(packet)}, packet); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(plaintext.Bytes()); err != nil {
		t.Fatal(err)
	}
	manifest, err := writer.Commit()
	if err != nil {
		t.Fatal(err)
	}
	record := struct {
		Manifest   pcapevidence.Manifest          `json:"manifest"`
		KeyID      string                         `json:"key_id"`
		WrappedKey []byte                         `json:"wrapped_key"`
		Requests   []pcapevidence.RequestEvidence `json:"requests"`
	}{Manifest: manifest, KeyID: dek.KeyID, WrappedKey: dek.WrappedKey, Requests: []pcapevidence.RequestEvidence{{
		RequestID: requestID, TraceID: traceID, ConnectionID: strings.Repeat("a", 64), ObservedAt: time.Now().UTC(),
		CapturePoint: "GATEWAY_EGRESS", Method: "POST", Path: "/v1/pcap", FirstPacketNo: 1, LastPacketNo: 1,
	}}}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".json", encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return uuid.MustParse(artifactID.String()), plaintext.Bytes()
}

func TestRequestPCAPCaptureAdminRBAC(t *testing.T) {
	cfg := baseTestCfg()
	cfg.SystemOps.HostctlDir = filepath.Join(t.TempDir(), "hostctl")
	cfg.WAF.GatewayNodeName = "gw-capture-control"
	env := newTestEnv(t, cfg)
	env.importBaseLicense(t)
	systemPassword, securityPassword := "S5@Test2026!", "S5@Test2026!"
	systemUser, securityUser := "capture_system_"+s5Rand(), "capture_security_"+s5Rand()
	env.createUserDirect(t, systemUser, systemPassword, "SYSTEM_ADMIN")
	env.createUserDirect(t, securityUser, securityPassword, "SECURITY_ADMIN")
	systemCookies, systemCSRF := env.login(t, systemUser, systemPassword)
	securityCookies, securityCSRF := env.login(t, securityUser, securityPassword)

	resp := env.get(t, "/api/v1/request-pcap/capture", systemCookies)
	assertRequestAuditStatus(t, resp, http.StatusOK)
	resp.Body.Close()
	resp = env.get(t, "/api/v1/request-pcap/capture", securityCookies)
	assertRequestAuditStatus(t, resp, http.StatusForbidden)
	resp.Body.Close()
	body := `{"enabled":true,"interface":"eth0","ports":[80,443],"hot_dir":"/srv/hot","warm_dir":"/srv/warm","reason":"采集授权"}`
	resp = env.post(t, "/api/v1/request-pcap/capture", body, securityCookies, securityCSRF)
	assertRequestAuditStatus(t, resp, http.StatusForbidden)
	resp.Body.Close()
	resp = env.post(t, "/api/v1/request-pcap/capture", `{"enabled":true,"interface":"eth0;id","ports":[80],"hot_dir":"/srv/hot","warm_dir":"/srv/warm","reason":"非法范围"}`, systemCookies, systemCSRF)
	assertRequestAuditStatus(t, resp, http.StatusBadRequest)
	resp.Body.Close()
	resp = env.post(t, "/api/v1/request-pcap/capture", body, systemCookies, systemCSRF)
	assertRequestAuditStatus(t, resp, http.StatusAccepted)
	var status struct {
		Data requestpcap.CaptureStatus `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		resp.Body.Close()
		t.Fatal(err)
	}
	resp.Body.Close()
	if status.Data.State != "PENDING" || status.Data.Enabled {
		t.Fatalf("accepted command was presented as running: %+v", status.Data)
	}
	matches, err := filepath.Glob(filepath.Join(cfg.SystemOps.HostctlDir, "pcap_capture-*.json"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("expected one signed capture command, matches=%v err=%v", matches, err)
	}
	var command struct {
		Enabled bool   `json:"enabled"`
		HMAC    string `json:"hmac"`
		Ports   []int  `json:"ports"`
	}
	raw, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &command); err != nil {
		t.Fatal(err)
	}
	if !command.Enabled || command.HMAC == "" || len(command.Ports) != 2 {
		t.Fatalf("invalid capture command: %+v", command)
	}
}
