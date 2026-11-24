#!/usr/bin/env bash
# 九章 WDSP 跨平台 Agent 安装端到端闭环验收脚本（Debian DEB + RPM + macOS）
#
# 验证完整链路：
#   1. 从源码构建四平台 10 个安装包 + manifest.json + SHA256SUMS；
#   2. 启动真实装配 server/internal/agents MachineHandler（含真实 AgentCA + 一次性 Token 原子消耗）的 HTTPS 服务端；
#   3. 在真实 Debian (dpkg) 容器内执行在线一键安装命令：
#      Bearer Token 拉脚本 -> 拉 .deb -> 强校 X-WDSP-SHA256 -> dpkg -i -> wdsp-agent install -> 真实 enroll 签发 PoP 证书 -> 复用同 Token 返回 401；
#   4. 在真实 RPM (openEuler) 容器内执行在线一键安装命令（全同上，走 rpm -Uvh）；
#   5. 在 macOS 宿主（如当前为 Darwin）执行在线拉脚本/拉 .tar.gz + SHA-256 校验 + 真二进制 enroll + 复用同 Token 返回 401；
#   6. 校验 Windows 安装脚本与 .zip 在线拉取的 SHA-256 完整性（真机服务拉起需 Windows 宿主，如实标 NOT_RUN）。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

DEBIAN_IMAGE="golang:1.25.6-bookworm@sha256:f4490d7b261d73af4543c46ac6597d7d101b6e1755bcdd8c5159fda7046b6b3e"
RPM_IMAGE="openeuler/openeuler:24.03-lts-sp4@sha256:17c15554be2a5bc46023acb6e04d609d77642b8c20e236e88deb18e41ae4558e"
VERSION="${WDSP_AGENT_VERSION:-2.4.0}"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/wdsp-xplat-e2e.XXXXXX")"
SRV_PID=""
cleanup() {
  if [[ -n "$SRV_PID" ]]; then
    kill "$SRV_PID" >/dev/null 2>&1 || true
    wait "$SRV_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

log() { printf '[xplat-e2e] %s\n' "$*"; }

PKG_DIR="$WORK_DIR/packages"
log "1/6 构建四平台安装包（version=${VERSION}）..."
bash "$REPO_ROOT/packaging/wdsp-agent/build-packages.sh" --version "$VERSION" --output "$PKG_DIR" >/dev/null

# 2. 启动绑定 0.0.0.0 随机端口的真实 MachineHandler HTTPS 引导服务（内置真实 AgentCA 与原子 Token 消费）
HARNESS_DIR="$REPO_ROOT/server/internal/agents"
READY_FILE="$WORK_DIR/server.ready"
SRV_LOG="$WORK_DIR/server.log"

TOK_DEB="wdt_$(openssl rand -hex 32)"
TOK_RPM="wdt_$(openssl rand -hex 32)"
TOK_MAC="wdt_$(openssl rand -hex 32)"
TOK_WIN="wdt_$(openssl rand -hex 32)"

cat > "$WORK_DIR/harness_test.go" <<'GOEOF'
package agents_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/agents"
)

type memHarnessStore struct {
	mu     sync.Mutex
	tokens map[string]bool
	byID   map[uuid.UUID]*agents.Agent
}

func (s *memHarnessStore) IsEnrollmentTokenActive(_ context.Context, tokenHash string, _ time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokens[tokenHash], nil
}

func (s *memHarnessStore) Enroll(_ context.Context, in agents.EnrollInput) (*agents.Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.tokens[in.TokenHash] {
		return nil, agents.ErrTokenInvalid
	}
	// 原子消费一次性注册令牌
	delete(s.tokens, in.TokenHash)
	ag := &agents.Agent{
		AgentID:  in.AgentID,
		Hostname: in.Hostname,
		IP:       in.IP,
		OS:       in.OS,
		Kernel:   in.Kernel,
		Arch:     in.Arch,
		Version:  in.Version,
	}
	s.byID[in.AgentID] = ag
	return ag, nil
}

func (s *memHarnessStore) AgentByCredentialHash(context.Context, string) (*agents.Agent, error) { return nil, agents.ErrAgentNotFound }
func (s *memHarnessStore) RecordHeartbeat(context.Context, uuid.UUID, string, []byte, *int64, []int16, time.Time) (int64, error) { return 0, nil }
func (s *memHarnessStore) RecordMetrics(context.Context, uuid.UUID, []byte, time.Time) error { return nil }
func (s *memHarnessStore) AgentConfig(context.Context, uuid.UUID) (int64, *agents.Policy, error) { return 0, nil, nil }
func (s *memHarnessStore) AckConfig(context.Context, uuid.UUID, int64, bool) error { return nil }
func (s *memHarnessStore) InsertFlowEvents(context.Context, uuid.UUID, []agents.FlowEvent) error { return nil }
func (s *memHarnessStore) InsertHTTPEvents(context.Context, uuid.UUID, []agents.HTTPRecord) error { return nil }
func (s *memHarnessStore) InsertHTTPEventsV2(context.Context, uuid.UUID, []agents.HTTPRecordV2, time.Time) ([]int, int, error) { return nil, 0, nil }
func (s *memHarnessStore) UpsertHTTPAssetSource(context.Context, agents.HTTPAssetSourceInput) error { return nil }
func (s *memHarnessStore) AddRawCounters(context.Context, uuid.UUID, int64, int64) error { return nil }
func (s *memHarnessStore) AgentByID(_ context.Context, id uuid.UUID) (*agents.Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.byID[id]; ok {
		return a, nil
	}
	return nil, agents.ErrAgentNotFound
}
func (s *memHarnessStore) CertFingerprintUsable(context.Context, uuid.UUID, string, time.Time) (bool, error) { return true, nil }
func (s *memHarnessStore) HasCertRevocations(context.Context, uuid.UUID) (bool, error) { return false, nil }
func (s *memHarnessStore) RotateAgentCert(context.Context, agents.RotateCertInput) (*agents.RotateCertResult, error) { return nil, nil }
func (s *memHarnessStore) ActiveCaptureOverrides(context.Context, uuid.UUID, time.Time) ([]agents.CaptureOverride, error) { return nil, nil }

func selfSignedTLS() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "host.docker.internal"},
		DNSNames:     []string{"localhost", "host.docker.internal"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

type memKV struct{ val string }

func (m *memKV) GetString(_ context.Context, _, _, def string) string {
	if m.val == "" {
		return def
	}
	return m.val
}
func (m *memKV) UpsertString(_ context.Context, _, _, value, _ string, _ uuid.UUID) error {
	m.val = value
	return nil
}

type noopEnc struct{}

func (noopEnc) Encrypt(s string) (string, error) { return s, nil }
func (noopEnc) Decrypt(s string) (string, error) { return s, nil }

func TestRunBootstrapHarness(t *testing.T) {
	pkgDir := os.Getenv("HARNESS_PKG_DIR")
	readyFile := os.Getenv("HARNESS_READY_FILE")
	if pkgDir == "" || readyFile == "" {
		t.Skip("harness env not set")
	}
	store := &memHarnessStore{tokens: map[string]bool{}, byID: map[uuid.UUID]*agents.Agent{}}
	for _, tok := range strings.Split(os.Getenv("HARNESS_TOKENS"), ",") {
		if tok = strings.TrimSpace(tok); tok != "" {
			store.tokens[agents.HashSecret(tok)] = true
		}
	}
	agentCA, err := agents.LoadOrCreateAgentCA(context.Background(), &memKV{}, noopEnc{})
	if err != nil {
		t.Fatalf("LoadOrCreateAgentCA: %v", err)
	}

	mh := agents.NewMachineHandler(store).SetCA(agentCA).SetPackageDir(pkgDir)
	mux := http.NewServeMux()
	agents.RegisterMachineRoutes(mux, mh)

	tlsCert, err := selfSignedTLS()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "0.0.0.0:0", &tls.Config{Certificates: []tls.Certificate{tlsCert}})
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = os.WriteFile(readyFile, []byte(fmt.Sprintf("%d", port)), 0o600)

	srv := &http.Server{Handler: mux}
	_ = srv.Serve(ln)
}
GOEOF

# 使用临时测试文件构建独立 test binary，不污染仓库目录
cp "$WORK_DIR/harness_test.go" "$HARNESS_DIR/zz_xplat_e2e_harness_tmp_test.go"
trap 'rm -f "$HARNESS_DIR/zz_xplat_e2e_harness_tmp_test.go"; cleanup' EXIT
(
  cd "$REPO_ROOT/server"
  go test -c -o "$WORK_DIR/bootstrap-harness.test" ./internal/agents
)
rm -f "$HARNESS_DIR/zz_xplat_e2e_harness_tmp_test.go"
trap cleanup EXIT

log "2/6 启动真实 HTTPS 引导与注册服务端..."
HARNESS_PKG_DIR="$PKG_DIR" \
HARNESS_READY_FILE="$READY_FILE" \
HARNESS_TOKENS="${TOK_DEB},${TOK_RPM},${TOK_MAC},${TOK_WIN}" \
  "$WORK_DIR/bootstrap-harness.test" -test.run TestRunBootstrapHarness >"$SRV_LOG" 2>&1 &
SRV_PID=$!

for _ in $(seq 1 50); do
  [[ -s "$READY_FILE" ]] && break
  sleep 0.1
done
[[ -s "$READY_FILE" ]] || { cat "$SRV_LOG" >&2; exit 1; }
PORT="$(cat "$READY_FILE")"
log "引导服务端就绪: https://127.0.0.1:${PORT} (容器访问 https://host.docker.internal:${PORT})"

log "3/6 真实 Debian (DEB) 容器端到端单行全自动一键安装（自动识别 DEB/amd64 + PoP 注册 + Token 消费）..."
docker run --rm --platform linux/amd64 \
  --add-host=host.docker.internal:host-gateway \
  -e "WDSP_ENROLL_TOKEN=${TOK_DEB}" \
  -e "SERVER=https://host.docker.internal:${PORT}" \
  "$DEBIAN_IMAGE" \
  bash -ceu '
    # 使用与 WDSP 前端一键部署完全一致的单行全自动命令形态（不手传 --format / --arch，由脚本自动识别）
    WDSP_ENROLL_TOKEN="$WDSP_ENROLL_TOKEN" bash -c '\''set -o pipefail; curl -fsSL -k -H "Authorization: Bearer $WDSP_ENROLL_TOKEN" "$1/api/v1/agents/bootstrap/script/linux" | ( [ "$(id -u)" -eq 0 ] && exec bash -s -- --server "$1" --insecure-skip-verify --skip-service || exec sudo -E bash -s -- --server "$1" --insecure-skip-verify --skip-service )'\'' _ "$SERVER"
    /usr/local/bin/wdsp-agent status --json | grep -q "\"enrolled\": true"
    /usr/local/bin/wdsp-agent status --json | grep -q "\"auth_mode\": \"PoP\""
    test "$(stat -c %a /etc/wdsp-agent/agent.json)" = "600"
    test "$(stat -c %a /var/lib/wdsp-agent/agent.key)" = "600"
    # Token 已在 enroll 中原子消耗，再次拉包必须返回 401
    code=$(curl -s -k -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $WDSP_ENROLL_TOKEN" "$SERVER/api/v1/agents/bootstrap/packages/linux/amd64/deb")
    test "$code" = "401"
    echo "DEBIAN_E2E_PASS"
  '

log "4/6 真实 RPM (openEuler) 容器端到端单行全自动一键安装（自动识别 RPM/amd64 + PoP 注册 + Token 消费）..."
docker run --rm --platform linux/amd64 \
  --add-host=host.docker.internal:host-gateway \
  -e "WDSP_ENROLL_TOKEN=${TOK_RPM}" \
  -e "SERVER=https://host.docker.internal:${PORT}" \
  "$RPM_IMAGE" \
  bash -ceu '
    # 同上：与 WDSP 一键部署相同，不手传 --format / --arch，由客户端脚本自动识别 openEuler RPM 与 amd64
    WDSP_ENROLL_TOKEN="$WDSP_ENROLL_TOKEN" bash -c '\''set -o pipefail; curl -fsSL -k -H "Authorization: Bearer $WDSP_ENROLL_TOKEN" "$1/api/v1/agents/bootstrap/script/linux" | ( [ "$(id -u)" -eq 0 ] && exec bash -s -- --server "$1" --insecure-skip-verify --skip-service || exec sudo -E bash -s -- --server "$1" --insecure-skip-verify --skip-service )'\'' _ "$SERVER"
    /usr/local/bin/wdsp-agent status --json | grep -q "\"enrolled\": true"
    /usr/local/bin/wdsp-agent status --json | grep -q "\"auth_mode\": \"PoP\""
    /usr/local/bin/wdsp-agent status --json | grep -qi "openEuler"
    test "$(stat -c %a /etc/wdsp-agent/agent.json)" = "600"
    code=$(curl -s -k -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $WDSP_ENROLL_TOKEN" "$SERVER/api/v1/agents/bootstrap/packages/linux/amd64/rpm")
    test "$code" = "401"
    echo "RPM_E2E_PASS"
  '

if [[ "$(uname -s)" == "Darwin" ]]; then
  log "5/6 macOS 宿主真实引导拉取 + SHA-256 校验 + PoP 注册 + Token 消费验证..."
  MAC_ARCH="arm64"
  [[ "$(uname -m)" == "x86_64" ]] && MAC_ARCH="amd64"
  MAC_WORK="$WORK_DIR/macos-e2e"
  mkdir -p "$MAC_WORK"
  curl -fsSL -k -D "$MAC_WORK/pkg.hdr" -H "Authorization: Bearer ${TOK_MAC}" \
    -o "$MAC_WORK/agent.tar.gz" "https://127.0.0.1:${PORT}/api/v1/agents/bootstrap/packages/darwin/${MAC_ARCH}/targz"
  SRV_SHA="$(tr -d '\r' < "$MAC_WORK/pkg.hdr" | awk -F':' 'tolower($1) == "x-wdsp-sha256" {gsub(/^[ \t]+|[ \t]+$/, "", $2); print tolower($2)}' | tail -n 1)"
  ACT_SHA="$(shasum -a 256 "$MAC_WORK/agent.tar.gz" | awk '{print tolower($1)}')"
  [[ "$SRV_SHA" == "$ACT_SHA" ]] || { echo "macOS SHA256 mismatch" >&2; exit 1; }
  tar -xzf "$MAC_WORK/agent.tar.gz" -C "$MAC_WORK"
  MAC_BIN="$(find "$MAC_WORK" -type f -name wdsp-agent | head -n 1)"
  WDSP_ENROLL_TOKEN="${TOK_MAC}" "$MAC_BIN" install \
    --server "https://127.0.0.1:${PORT}" \
    --config "$MAC_WORK/agent.json" \
    --state-dir "$MAC_WORK/state" \
    --insecure-skip-verify \
    --skip-service
  "$MAC_BIN" status --config "$MAC_WORK/agent.json" --state-dir "$MAC_WORK/state" --json | grep -q '"auth_mode": "PoP"'
  "$MAC_BIN" status --config "$MAC_WORK/agent.json" --state-dir "$MAC_WORK/state" --json | grep -q '"os": "macOS'
  CODE="$(curl -s -k -o /dev/null -w "%{http_code}" -H "Authorization: Bearer ${TOK_MAC}" "https://127.0.0.1:${PORT}/api/v1/agents/bootstrap/manifest")"
  [[ "$CODE" == "401" ]] || { echo "expected 401 after macOS enroll, got $CODE" >&2; exit 1; }
  log "MACOS_E2E_PASS"
fi

log "6/6 Windows 引导脚本与 .zip 完整性拉取校验（注：Windows 真机 Service/Npcap 需在 Windows 宿主实测，本机标 NOT_RUN）..."
WIN_WORK="$WORK_DIR/win-e2e"
mkdir -p "$WIN_WORK"
curl -fsSL -k -D "$WIN_WORK/ps1.hdr" -H "Authorization: Bearer ${TOK_WIN}" \
  -o "$WIN_WORK/install-agent.ps1" "https://127.0.0.1:${PORT}/api/v1/agents/bootstrap/script/windows"
grep -q '#Requires -Version 5.1' "$WIN_WORK/install-agent.ps1"
curl -fsSL -k -D "$WIN_WORK/zip.hdr" -H "Authorization: Bearer ${TOK_WIN}" \
  -o "$WIN_WORK/agent.zip" "https://127.0.0.1:${PORT}/api/v1/agents/bootstrap/packages/windows/amd64/zip"
WIN_SRV_SHA="$(tr -d '\r' < "$WIN_WORK/zip.hdr" | awk -F':' 'tolower($1) == "x-wdsp-sha256" {gsub(/^[ \t]+|[ \t]+$/, "", $2); print tolower($2)}' | tail -n 1)"
WIN_ACT_SHA="$(shasum -a 256 "$WIN_WORK/agent.zip" | awk '{print tolower($1)}')"
[[ "$WIN_SRV_SHA" == "$WIN_ACT_SHA" ]] || { echo "Windows zip SHA256 mismatch" >&2; exit 1; }
# 确认 URL Query 传 Token 被严格拒绝（400）
QCODE="$(curl -s -k -o /dev/null -w "%{http_code}" -H "Authorization: Bearer ${TOK_WIN}" "https://127.0.0.1:${PORT}/api/v1/agents/bootstrap/script/windows?token=${TOK_WIN}")"
[[ "$QCODE" == "400" ]] || { echo "expected 400 for query token, got $QCODE" >&2; exit 1; }
log "WINDOWS_BOOTSTRAP_ARTIFACT_VERIFY_PASS (WINDOWS_HOST_RUNTIME: NOT_RUN)"
log "全部跨平台端到端验收通过！"
