package detectors

import (
	"net/http"
	"sort"
	"strconv"
	"strings"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// 凭据异常检测补充（任务书 §35「API身份与凭据模型」检测项）：
// 本文件覆盖 Token 跨应用（第5项）、同一凭据多设备异常窗口计数（第9项，与
// envanomaly.go 的 UA 族突变互补：突变看单次切换，本规则看窗口内 distinct 族数）、
// 凭据位置异常（第2项，值形态级 URL 明文凭据，补 sensitive.in_query 固定键名表的盲区）。
//
// 纪律与 envanomaly.go 同组：仅凭据维度（CredentialKey）聚合，匿名流量直接跳过；
// 全部 OBSERVE 级只 AddMatch，动作统一由决策引擎输出；
// 证据不含凭证明文、不含应用 ID（只含 distinct 数与窗口等计数事实）。
//
// §35 第10项「已吊销凭据继续访问」已由 credrevoked.go 落地：发布通道下发
// api_revoked_credentials 指纹清单，按凭据键全等比对（详见该文件）。
const (
	// DefaultCredentialCrossAppLimit 同凭据滑窗 distinct 应用默认阈值：
	// 同一凭据在同一窗口出现于 ≥2 个受保护应用即视为跨应用扩散信号。
	DefaultCredentialCrossAppLimit = 2
	// DefaultCredentialDeviceSpreadLimit 同凭据滑窗 distinct UA 族默认阈值
	// （UA 族全集仅 empty/script/bot/browser/other，≥3 族已属异常扩散）。
	DefaultCredentialDeviceSpreadLimit = 3
)

// 跨应用与多设备追踪器复用 ipSpreadTracker（其本质是「键 → 自然分钟窗口内
// distinct 成员集合」的通用结构，成员为任意字符串，非 IP 专有）；与
// hourHist/uaFamily 同一纪律：仅进程内实现，无 StoreOverrides 注入
// （StoreOverrides 扩展需 behaviorstore 配套，超出本波范围）。
var (
	defaultAppSpreadTracker    = newIPSpreadTracker(envAnomalyMaxKeys, nil)
	defaultDeviceSpreadTracker = newIPSpreadTracker(envAnomalyMaxKeys, nil)
)

// CheckCredentialCrossApp Token 跨应用：同一凭据指纹在滑窗内出现于 ≥limit 个不同
// 应用（appID 经 pipeline.Config.ApplicationID 由装配层取自 Guard.AppID 显式传入；
// 空 = 应用未识别，跳过不判，不凭空捏造归属）→ auth.credential_cross_app
// （OBSERVE/MEDIUM，只 AddMatch 不定案）。
// credKey/appID 任一为空（匿名或应用未识别）直接跳过；证据只含 distinct 数与窗口。
func CheckCredentialCrossApp(ctx *dsctx.RequestContext, credKey, appID string, limit int) {
	if ctx == nil || credKey == "" || appID == "" {
		return
	}
	if limit <= 0 {
		limit = DefaultCredentialCrossAppLimit
	}
	distinct := defaultAppSpreadTracker.add(credKey, appID)
	if distinct < limit {
		return
	}
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector: "authentication",
		RuleID:   "auth.credential_cross_app",
		Category: "OBSERVE",
		Severity: "MEDIUM",
		Message:  "credential used across multiple applications",
		Evidence: map[string]string{
			"distinct_apps": strconv.Itoa(distinct),
			"window":        "1m",
		},
		ScoreDelta: 20,
	})
}

// CheckCredentialDeviceSpread 同一凭据多设备异常（窗口计数面）：滑窗内 distinct
// UA 族数 ≥ limit → auth.credential_device_spread（OBSERVE/LOW，只 AddMatch 不定案）。
// 与 auth.credential_ua_change（单次族切换）互补：族反复横跳或多个客户端并行持同一
// 凭据时本规则命中；证据只含 distinct 族数与窗口，不落 UA/族名明细。
func CheckCredentialDeviceSpread(ctx *dsctx.RequestContext, r *http.Request, credKey string, limit int) {
	if ctx == nil || r == nil || credKey == "" {
		return
	}
	if limit <= 0 {
		limit = DefaultCredentialDeviceSpreadLimit
	}
	distinct := defaultDeviceSpreadTracker.add(credKey, uaFamily(r.Header.Get("User-Agent")))
	if distinct < limit {
		return
	}
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector: "authentication",
		RuleID:   "auth.credential_device_spread",
		Category: "OBSERVE",
		Severity: "LOW",
		Message:  "credential used from multiple user-agent families in window",
		Evidence: map[string]string{
			"distinct_families": strconv.Itoa(distinct),
			"window":            "1m",
		},
		ScoreDelta: 10,
	})
}

// credentialURLShape 识别 query 值中的凭据形态；非凭据形态返回空串。
// Bearer/Basic scheme 前缀与 JWT 形态（eyJ 开头三段式）均为强特征；
// 凭据值只入本函数作用域，判定结果仅为形态标签。
func credentialURLShape(v string) string {
	lv := strings.ToLower(v)
	if strings.HasPrefix(lv, "bearer ") || strings.HasPrefix(lv, "basic ") {
		return "scheme_prefixed"
	}
	if strings.HasPrefix(v, "eyJ") && strings.Count(v, ".") == 2 {
		return "jwt"
	}
	return ""
}

// CheckCredentialLocationAnomaly 凭据位置异常：凭据形态值出现在 URL query
// （标准位置为 Authorization/X-API-Key/Cookie 头）→ auth.credential_in_url
// （OBSERVE/MEDIUM，只 AddMatch 不定案）。与 sensitive.in_query（固定敏感键名表，
// BLOCK 类）互补：本规则按值形态识别，覆盖非标准键名下的凭据外泄。
// 每请求至多一条明细（避免多参数刷屏）；证据只含参数名与形态标签，绝不含值。
func CheckCredentialLocationAnomaly(ctx *dsctx.RequestContext, r *http.Request) {
	if ctx == nil || r == nil || r.URL == nil {
		return
	}
	q := r.URL.Query()
	if len(q) == 0 {
		return
	}
	// 键序排序遍历：事件确定性（与 sensitive.go 同一纪律）
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range q[k] {
			if shape := credentialURLShape(v); shape != "" {
				ctx.AddMatch(dsctx.DetectorMatch{
					Detector: "authentication",
					RuleID:   "auth.credential_in_url",
					Category: "OBSERVE",
					Severity: "MEDIUM",
					Message:  "credential-shaped value in url query",
					Evidence: map[string]string{
						"location": "query",
						"param":    k,
						"shape":    shape,
					},
					ScoreDelta: 15,
				})
				return
			}
		}
	}
}
