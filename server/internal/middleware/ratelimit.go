package middleware

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/jiuzhang-waf/server/internal/cache"
	"github.com/jiuzhang-waf/server/internal/response"
)

// RateLimiter 是基于 Valkey 固定窗口计数器的接口限速器。
type RateLimiter struct {
	cache *cache.Client
}

// NewRateLimiter 创建限速器。
func NewRateLimiter(c *cache.Client) *RateLimiter {
	return &RateLimiter{cache: c}
}

// Limit 返回限速中间件。
// name: 限速维度名称（如 login/captcha/export）；maxPerWindow: 窗口内最大次数；
// window: 时间窗口；keyFunc: 提取限速键（通常为 IP 或用户名+IP）。
func (l *RateLimiter) Limit(name string, maxPerWindow int, window time.Duration, keyFunc func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if maxPerWindow <= 0 {
				next.ServeHTTP(w, r)
				return
			}
			key := fmt.Sprintf("jiuzhang:ratelimit:%s:%s", name, keyFunc(r))
			ctx := r.Context()

			count, err := l.cache.Redis().Incr(ctx, key).Result()
			if err != nil {
				// Valkey 故障时安全失败：不静默放行，返回服务不可用
				response.Error(w, r, http.StatusServiceUnavailable,
					response.CodeServiceUnavailable, "服务暂时不可用，请稍后重试")
				return
			}
			if count == 1 {
				_ = l.cache.Redis().Expire(ctx, key, window).Err()
			}
			// 剩余次数响应头
			remaining := maxPerWindow - int(count)
			if remaining < 0 {
				remaining = 0
			}
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(maxPerWindow))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))

			if int(count) > maxPerWindow {
				ttl, _ := l.cache.Redis().TTL(ctx, key).Result()
				w.Header().Set("Retry-After", strconv.Itoa(int(ttl.Seconds())))
				response.Error(w, r, http.StatusTooManyRequests,
					response.CodeRateLimited, "请求过于频繁，请稍后重试")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// IPKey 按来源 IP 限速。
func IPKey(r *http.Request) string {
	return RemoteIP(r)
}

// IPAndUsernameKey 按 IP+用户名限速（登录等场景）。
func IPAndUsernameKey(r *http.Request) string {
	return RemoteIP(r)
}

// IsValkeyErr 判断是否 Valkey 错误。
func IsValkeyErr(err error) bool {
	return err != nil && err != redis.Nil
}
