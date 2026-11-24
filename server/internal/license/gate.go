// gate.go 授权门控中间件：按授权内存状态（Service.State 原子快照，无 IO）逐请求实时判定——
//
//   - 无有效授权：白名单外一律 423 Locked（code LICENSE_INVALID）；白名单 =
//     /api/v1/auth/ 前缀（登录/会话永远可达）、/api/v1/health、/api/v1/license/ 前缀
//     （状态查询与导入）、/api/v1/product/edition（能力探测，如实返回锁定态字段）、
//     /api/v1/upgrades/ 前缀（系统升级恢复通道：信任根轮换等场景下锁定态必须仍能
//     上传并应用签名升级包，否则「验签失败 → 无法导入 → 无法升级」死锁；
//     该前缀仍受会话认证 + CSRF + 系统管理员角色约束，且升级包须通过发布签名校验）；
//   - 有效授权 product=waf：/api/v1/api-security 及以下 403（code LICENSE_FEATURE_DENIED）；
//   - 有效授权 product=api：Web 防护专属接口 403 同码——路由集合与 app.go 中
//     cfg.Product.WebWAFProtectionEnabled() 门控的注册块一致（/api/v1/l7-rules*）。
//
// 非 /api/v1/ 路径不拦截（管理面 mux 仅挂 API 路由；静态资源不经此链）。
// 状态翻转（导入/到期/指纹变化）即时生效，无需重启或动态增删路由。
package license

import (
	"net/http"
	"strings"

	"github.com/jiuzhang-waf/server/internal/response"
)

// 授权业务错误码（响应信封 code；前端与其他包按码分支处理，集中在授权域定义）。
const (
	// CodeLicenseInvalid 无有效授权（HTTP 423 Locked）。
	CodeLicenseInvalid = "LICENSE_INVALID"
	// CodeLicenseFeatureDenied 授权产品形态不含该能力域（HTTP 403）。
	CodeLicenseFeatureDenied = "LICENSE_FEATURE_DENIED"
	// CodeLicenseQuotaExceeded 授权配额超限（HTTP 403）。
	CodeLicenseQuotaExceeded = "LICENSE_QUOTA_EXCEEDED"
	// CodeLicenseProductBound 授权产品形态与首次导入绑定不一致（HTTP 409）：
	// 产品形态首导永久绑定（历史任意状态均计入），切换必须重新安装部署。
	CodeLicenseProductBound = "LICENSE_PRODUCT_BOUND"
)

// gateWhitelistPrefixes 锁定态白名单前缀：登录/会话、健康检查、授权管理与
// 能力探测永远可达（锁定状态下前端仍需查询状态并导入授权）。
var gateWhitelistPrefixes = []string{
	"/api/v1/auth/",
	"/api/v1/health",
	"/api/v1/license/",
	"/api/v1/product/edition",
	// 系统升级恢复通道：锁定态也必须可升级（见文件头注释）；认证/CSRF/管理员角色不受影响。
	"/api/v1/upgrades/",
}

// Gate 授权门控中间件（装配在认证链之后：session → CSRF → RequireAuth → Gate → 路由）。
// svc 为 nil 时直通（装配保证非 nil，nil 防御仅避免空指针，不改变既有链路行为）。
func Gate(svc *Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if svc == nil || !strings.HasPrefix(r.URL.Path, "/api/v1/") {
				next.ServeHTTP(w, r)
				return
			}
			st := svc.State()
			if !st.Valid {
				if gateWhitelisted(r.URL.Path) {
					next.ServeHTTP(w, r)
					return
				}
				msg := "授权无效，系统已锁定，请导入有效授权"
				if st.Reason != "" {
					msg = "授权无效（" + st.Reason + "），系统已锁定，请导入有效授权"
				}
				response.Error(w, r, http.StatusLocked, CodeLicenseInvalid, msg)
				return
			}
			switch st.Product {
			case "waf":
				// waf 授权不含 API 动态防护能力域（wdsp 包装配了 API 路由时此处实时门控）；
				// 放行只读 GET /api/v1/api-security/nodes 供主备高可用（/ha-groups）拉取已登记网关节点列表。
				if pathWithin(r.URL.Path, "/api/v1/api-security") &&
					!(r.Method == http.MethodGet && r.URL.Path == "/api/v1/api-security/nodes") {
					response.Error(w, r, http.StatusForbidden, CodeLicenseFeatureDenied,
						"当前授权产品形态（waf）不含 API 动态防护能力")
					return
				}
			case "api":
				// api 授权不含 Web 防护专属能力（路由集合与 WebWAFProtectionEnabled 门控一致）
				if pathWithin(r.URL.Path, "/api/v1/l7-rules") {
					response.Error(w, r, http.StatusForbidden, CodeLicenseFeatureDenied,
						"当前授权产品形态（api）不含 Web 防护专属能力")
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// gateWhitelisted 锁定态白名单判定（前缀匹配）。
func gateWhitelisted(path string) bool {
	for _, p := range gateWhitelistPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// pathWithin path 等于 base 或位于 base/ 前缀之下（避免 /api/v1/l7-rulesx 误伤）。
func pathWithin(path, base string) bool {
	return path == base || strings.HasPrefix(path, base+"/")
}
