// publish_smoke.go 发布后流量验证的 WDSP 内部精确端点。
//
// /_wdsp/internal/v1/publish-smoke 在 serveNextViaBot 最前置处理：请求已经过
// REAL_IP、封禁、黑白名单、L7、风险、配额与 CC 等既有步骤，但不依赖 Bot 配置或
// 路由保留状态。每次发布下发独立随机 HMAC 密钥与发布任务 ID；请求和响应同时
// 绑定应用、规范化 Host、发布 ID、nonce、时间戳与探针类型。所有结局均在 guard
// 本地写出，绝不调用 next，普通源站 404 或固定标记头不能冒充验证通过。
package jiuzhang_guard

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
)

const (
	publishSmokePath           = "/_wdsp/internal/v1/publish-smoke"
	publishSmokeMarkerHeader   = "X-Jiuzhang-Publish-Smoke"
	publishSmokeAppIDHeader    = "X-Jiuzhang-Publish-Smoke-App-ID"
	publishSmokeAppCodeHeader  = "X-Jiuzhang-Publish-Smoke-App-Code"
	publishSmokePublishHeader  = "X-Jiuzhang-Publish-Smoke-Publish-ID"
	publishSmokeNonceHeader    = "X-Jiuzhang-Publish-Smoke-Nonce"
	publishSmokeTimeHeader     = "X-Jiuzhang-Publish-Smoke-Timestamp"
	publishSmokeSigHeader      = "X-Jiuzhang-Publish-Smoke-Signature"
	publishSmokeMaxAge         = 30 * time.Second
	publishSmokeMaxPublishID   = 128
	publishSmokeMaxProbeLength = 64
)

// publishSmokeJSON 是单次发布的短暂认证材料。密钥只经既有受控配置发布通道
// 下发；管理面版本快照不保存该段，回滚重放也不会恢复旧发布身份。
type publishSmokeJSON struct {
	PublishID string `json:"publish_id"`
	KeyHex    string `json:"key_hex"`
}

type publishSmokeBinding struct {
	appID     string
	appCode   string
	host      string
	publishID string
	nonce     string
	timestamp int64
	probe     string
}

type publishSmokeResponse struct {
	AppID     string `json:"app_id"`
	AppCode   string `json:"app_code"`
	Host      string `json:"host"`
	PublishID string `json:"publish_id"`
	Nonce     string `json:"nonce"`
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"`
}

func decodePublishSmokeKey(sec *publishSmokeJSON) ([]byte, error) {
	if sec == nil {
		return nil, nil
	}
	key, err := hex.DecodeString(strings.TrimSpace(sec.KeyHex))
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("publish_smoke.key_hex must be 32-byte hex")
	}
	return key, nil
}

func validatePublishSmokeConfig(sec *publishSmokeJSON) error {
	if sec == nil {
		return nil
	}
	if sec.PublishID == "" || len(sec.PublishID) > publishSmokeMaxPublishID || strings.TrimSpace(sec.PublishID) != sec.PublishID {
		return fmt.Errorf("publish_smoke.publish_id must be non-empty, trimmed and at most 128 characters")
	}
	_, err := decodePublishSmokeKey(sec)
	return err
}

func (g *Guard) assemblePublishSmoke() error {
	if err := validatePublishSmokeConfig(g.PublishSmoke); err != nil {
		return err
	}
	key, err := decodePublishSmokeKey(g.PublishSmoke)
	if err != nil {
		return err
	}
	g.publishSmokeKey = key
	return nil
}

func publishSmokeMAC(key []byte, parts ...string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("jiuzhang-wdsp-publish-smoke/v1"))
	for _, part := range parts {
		_, _ = mac.Write([]byte(strconv.Itoa(len(part))))
		_, _ = mac.Write([]byte{':'})
		_, _ = mac.Write([]byte(part))
	}
	return mac.Sum(nil)
}

func publishSmokeHost(host string) string {
	return strings.ToLower(host)
}

func publishSmokeRequestSignature(key []byte, b publishSmokeBinding) []byte {
	return publishSmokeMAC(key, "request", http.MethodGet, publishSmokePath,
		b.appID, b.appCode, b.host, b.publishID, b.nonce,
		strconv.FormatInt(b.timestamp, 10), b.probe)
}

func publishSmokeResponseSignature(key []byte, b publishSmokeBinding) []byte {
	return publishSmokeMAC(key, "response", strconv.Itoa(http.StatusOK),
		b.appID, b.appCode, b.host, b.publishID, b.nonce,
		strconv.FormatInt(b.timestamp, 10), b.probe)
}

func (g *Guard) authenticatedPublishSmokeBinding(r *http.Request, now time.Time) (publishSmokeBinding, bool) {
	if g.PublishSmoke == nil || len(g.publishSmokeKey) != 32 {
		return publishSmokeBinding{}, false
	}
	b := publishSmokeBinding{
		appID:     r.Header.Get(publishSmokeAppIDHeader),
		appCode:   r.Header.Get(publishSmokeAppCodeHeader),
		host:      publishSmokeHost(r.Host),
		publishID: r.Header.Get(publishSmokePublishHeader),
		nonce:     r.Header.Get(publishSmokeNonceHeader),
		probe:     r.Header.Get(publishSmokeMarkerHeader),
	}
	if b.appID == "" || b.appID != g.AppID || b.appCode == "" || b.appCode != g.AppCode ||
		b.host == "" || b.publishID == "" || b.publishID != g.PublishSmoke.PublishID ||
		b.probe == "" || len(b.probe) > publishSmokeMaxProbeLength {
		return publishSmokeBinding{}, false
	}
	nonce, err := hex.DecodeString(b.nonce)
	if err != nil || len(nonce) != 16 {
		return publishSmokeBinding{}, false
	}
	b.timestamp, err = strconv.ParseInt(strings.TrimSpace(r.Header.Get(publishSmokeTimeHeader)), 10, 64)
	if err != nil {
		return publishSmokeBinding{}, false
	}
	delta := now.UTC().Sub(time.Unix(b.timestamp, 0))
	if delta < 0 {
		delta = -delta
	}
	if delta > publishSmokeMaxAge {
		return publishSmokeBinding{}, false
	}
	sig, err := hex.DecodeString(strings.TrimSpace(r.Header.Get(publishSmokeSigHeader)))
	if err != nil || len(sig) != sha256.Size ||
		!hmac.Equal(sig, publishSmokeRequestSignature(g.publishSmokeKey, b)) {
		return publishSmokeBinding{}, false
	}
	return b, true
}

// isAuthenticatedPublishSmoke 判断当前请求是否为携带有效当次发布 HMAC 的精确冒烟探针。
// 仅在路径严格等于 publishSmokePath、方法为 GET 且 HMAC 鉴权通过时返回 true，
// 用于在 L7 域名重定向等全局规则前放行内部冒烟探针（探针仍会经过真实 IP、黑名单与 CC，且绝不反代源站）。
func (g *Guard) isAuthenticatedPublishSmoke(r *http.Request, now time.Time) bool {
	if r.Method != http.MethodGet || normalizer.CanonicalPath(r.URL.Path) != publishSmokePath {
		return false
	}
	_, ok := g.authenticatedPublishSmokeBinding(r, now)
	return ok
}

// servePublishSmoke 本地处理精确内部端点；认证失败与未配置同样返回无认证信息的
// 404，避免把无效/过期/跨站点/跨发布探针误判为既有防护步骤的 403/429 通过证据。
func (g *Guard) servePublishSmoke(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Cache-Control", "no-store")
	dispo := DispositionFrom(r.Context())
	writeLocal := func(status int, reason string) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(strconv.Itoa(status) + " " + strings.ToLower(http.StatusText(status))))
		dispo.RecordTerminal(ExecutorNone, DisActionNone, status, true, []string{reason}, nil)
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeLocal(http.StatusMethodNotAllowed, "PUBLISH_SMOKE_METHOD_NOT_ALLOWED")
		return nil
	}
	b, ok := g.authenticatedPublishSmokeBinding(r, time.Now())
	if !ok {
		writeLocal(http.StatusNotFound, "PUBLISH_SMOKE_AUTH_FAILED")
		return nil
	}
	resp := publishSmokeResponse{
		AppID: b.appID, AppCode: b.appCode, Host: b.host, PublishID: b.publishID,
		Nonce: b.nonce, Timestamp: b.timestamp,
		Signature: hex.EncodeToString(publishSmokeResponseSignature(g.publishSmokeKey, b)),
	}
	body, err := json.Marshal(resp)
	if err != nil {
		writeLocal(http.StatusInternalServerError, "PUBLISH_SMOKE_RESPONSE_FAILED")
		return nil
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set(publishSmokeMarkerHeader, b.probe)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
	dispo.RecordTerminal(ExecutorNone, DisActionNone, http.StatusOK, true, []string{"PUBLISH_SMOKE_OK"}, nil)
	return nil
}
