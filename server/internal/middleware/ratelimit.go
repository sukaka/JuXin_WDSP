package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/jiuzhang-waf/server/internal/cache"
	"github.com/jiuzhang-waf/server/internal/response"
	"github.com/redis/go-redis/v9"
)

// RateLimiter 是基于 Valkey 固定窗口计数器的接口限速器。
type RateLimiter struct {
	rdb *redis.Client
}

// NewRateLimiter 创建限速器。
func NewRateLimiter(c *cache.Client) *RateLimiter {
	return &RateLimiter{rdb: c.Redis()}
}

// Limit 返回限速中间件（固定限速值）。
func (l *RateLimiter) Limit(name string, maxPerWindow int, window time.Duration, keyFunc func(*http.Request) string) func(http.Handler) http.Handler {
	return l.LimitDynamic(name, func(context.Context) int { return maxPerWindow }, window, keyFunc)
}

// LimitDynamic 返回限速中间件，限速值由 limitFunc 动态获取（支持配置热更新）。
// name: 限速维度名称；limitFunc: 动态限速值；window: 时间窗口；keyFunc: 限速键。
func (l *RateLimiter) LimitDynamic(name string, limitFunc func(context.Context) int, window time.Duration, keyFunc func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			maxPerWindow := limitFunc(r.Context())
			if maxPerWindow <= 0 {
				next.ServeHTTP(w, r)
				return
			}
			key := fmt.Sprintf("jiuzhang:ratelimit:%s:%s", name, keyFunc(r))
			ctx := r.Context()

			count, err := l.rdb.Incr(ctx, key).Result()
			if err != nil {
				// Valkey 故障时安全失败：不静默放行，返回服务不可用
				response.Error(w, r, http.StatusServiceUnavailable,
					response.CodeServiceUnavailable, "服务暂时不可用，请稍后重试")
				return
			}
			if count == 1 {
				if err := l.rdb.Expire(ctx, key, window).Err(); err != nil {
					// Expire 失败会让计数键无 TTL、固定窗口永不过期（该来源被永久 429）。
					// 与 Incr 失败同口径安全失败：删除计数键并如实报错。
					_ = l.rdb.Del(ctx, key).Err()
					response.Error(w, r, http.StatusServiceUnavailable,
						response.CodeServiceUnavailable, "服务暂时不可用，请稍后重试")
					return
				}
			}
			// 剩余次数响应头
			remaining := maxPerWindow - int(count)
			if remaining < 0 {
				remaining = 0
			}
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(maxPerWindow))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))

			if int(count) > maxPerWindow {
				// 键无 TTL（-1）或不存在（-2）时 TTL 为负，Retry-After 负值非法：
				// 退化为窗口长度作为合理默认。
				retryAfter := int(window.Seconds())
				if ttl, err := l.rdb.TTL(ctx, key).Result(); err == nil && ttl > 0 {
					retryAfter = int(ttl.Seconds())
					if retryAfter < 1 {
						retryAfter = 1
					}
				}
				w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
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
