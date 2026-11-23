// lookup_handler.go 统一 GeoIP 归属地单条 / 批量查询接口：
//   - GET  /api/v1/geoip/lookup?ip=1.2.3.4
//   - POST /api/v1/geoip/lookup   {"ips": ["1.2.3.4", "2001:4860:4860::8888"]}
//
// 鉴权：要求已登录会话（authz 中间件），纯只读内存查询，无敏感数据泄露风险；
// 参数校验：批量单次上限 200 条、单条最长 64 字节、拒绝控制字符，自动去重。
package apigeo

import (
	"net/http"
	"strings"

	"github.com/jiuzhang-waf/server/internal/response"
)

const (
	geoBatchMaxIPs   = 200
	geoMaxIPLen      = 64
	geoBatchMaxBytes = 32 * 1024
)

// LookupHandler 统一 GeoIP 归属地 HTTP 处理器。
type LookupHandler struct {
	engine GeoLookup
}

// NewLookupHandler 创建统一归属地查询处理器（engine 可为 nil，此时如实标注 geo_enabled=false）。
func NewLookupHandler(engine GeoLookup) *LookupHandler {
	return &LookupHandler{engine: engine}
}

// RegisterLookupRoutes 注册统一归属地查询路由（要求登录态 authz）。
func RegisterLookupRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *LookupHandler) {
	mux.Handle("GET /api/v1/geoip/lookup", authz(http.HandlerFunc(h.LookupOne)))
	mux.Handle("POST /api/v1/geoip/lookup", authz(http.HandlerFunc(h.LookupBatch)))
}

type lookupOneResponse struct {
	Geo        *GeoInfo `json:"geo"`
	GeoEnabled bool     `json:"geo_enabled"`
	Sources    []string `json:"sources"`
}

type lookupBatchRequest struct {
	IPs []string `json:"ips"`
}

type lookupBatchResponse struct {
	Items      map[string]*GeoInfo `json:"items"`
	GeoEnabled bool                `json:"geo_enabled"`
	Sources    []string            `json:"sources"`
}

// LookupOne GET /api/v1/geoip/lookup?ip=...
func (h *LookupHandler) LookupOne(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if !validIPParam(ip) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请提供有效的 ip 查询参数")
		return
	}
	geo := h.lookup(ip)
	response.JSON(w, r, http.StatusOK, lookupOneResponse{
		Geo:        geo,
		GeoEnabled: h.enabled(),
		Sources:    h.sources(),
	})
}

// LookupBatch POST /api/v1/geoip/lookup
func (h *LookupHandler) LookupBatch(w http.ResponseWriter, r *http.Request) {
	var req lookupBatchRequest
	if err := response.DecodeJSON(w, r, &req, geoBatchMaxBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求体必须是合法 JSON")
		return
	}
	if len(req.IPs) == 0 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "ips 不能为空")
		return
	}
	if len(req.IPs) > geoBatchMaxIPs {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "单次批量查询最多支持 200 个 IP")
		return
	}
	items := make(map[string]*GeoInfo, len(req.IPs))
	for _, raw := range req.IPs {
		ip := strings.TrimSpace(raw)
		if !validIPParam(ip) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "ips 包含非法或超长项")
			return
		}
		if _, exists := items[ip]; exists {
			continue
		}
		items[ip] = h.lookup(ip)
	}
	response.JSON(w, r, http.StatusOK, lookupBatchResponse{
		Items:      items,
		GeoEnabled: h.enabled(),
		Sources:    h.sources(),
	})
}

func (h *LookupHandler) lookup(ip string) *GeoInfo {
	if h == nil || h.engine == nil {
		var nilEngine *Engine
		return nilEngine.LookupGeo(ip)
	}
	return h.engine.LookupGeo(ip)
}

func (h *LookupHandler) enabled() bool {
	return h != nil && h.engine != nil && h.engine.Enabled()
}

func (h *LookupHandler) sources() []string {
	if h == nil || h.engine == nil {
		return []string{}
	}
	return h.engine.Sources()
}

func validIPParam(s string) bool {
	if s == "" || len(s) > geoMaxIPLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
