package jiuzhang_guard

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/valkey-io/valkey-go"
	"go.uber.org/zap"
)

const (
	// ACMEHTTP01PathPrefix 是 RFC 8555 HTTP-01 验证固定路径前缀。
	ACMEHTTP01PathPrefix = "/.well-known/acme-challenge/"
	// ACMEHTTP01ValkeyKeyPrefix 是共享 Valkey 中 HTTP-01 挑战令牌的键前缀（与管理后端 solver.go 一致）。
	ACMEHTTP01ValkeyKeyPrefix = "jiuzhang:acme:http01:"
	acmeHTTP01MaxBodyBytes    = 1024
	acmeHTTP01ValkeyTimeout   = 2 * time.Second
)

// acmeHTTP01TokenPattern 严格限定 RFC 8555 base64url 令牌字符与长度，杜绝路径穿越。
var acmeHTTP01TokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

func init() {
	caddy.RegisterModule(&ACMEHTTP01{})
}

// ACMEHTTP01 是九章网关 ACME HTTP-01 挑战应答器（优先读取共享 Valkey 以支持 Active-Active HA，
// 未配置或未命中时回退本地共享证书目录）。仅拦截已注册的挑战令牌请求，未命中一律原样透传后续链，
// 不破坏源站自管理的 HTTP-01 或正常业务请求。
type ACMEHTTP01 struct {
	ChallengeDir string      `json:"challenge_dir,omitempty"`
	Valkey       *valkeyJSON `json:"valkey,omitempty"`

	logger     *zap.Logger
	valkeyCli  valkey.Client
	lookupFunc func(ctx context.Context, token string) (string, bool, error)
}

// CaddyModule 返回模块元信息。
func (ACMEHTTP01) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.jiuzhang_acme_http01",
		New: func() caddy.Module { return new(ACMEHTTP01) },
	}
}

// Provision 初始化 Valkey 客户端与目录配置（Valkey 暂不可用时 fail-open 记告警并回退本地目录，不阻断网关重载）。
func (a *ACMEHTTP01) Provision(ctx caddy.Context) error {
	a.logger = ctx.Logger()
	a.ChallengeDir = strings.TrimSpace(a.ChallengeDir)
	if a.Valkey != nil && strings.TrimSpace(a.Valkey.Address) != "" {
		opt := valkey.ClientOption{
			InitAddress:      []string{strings.TrimSpace(a.Valkey.Address)},
			Username:         a.Valkey.Username,
			Password:         a.Valkey.Password,
			SelectDB:         a.Valkey.DB,
			DisableCache:     true,
			Dialer:           net.Dialer{Timeout: acmeHTTP01ValkeyTimeout},
			ConnWriteTimeout: acmeHTTP01ValkeyTimeout,
		}
		cli, err := valkey.NewClient(opt)
		if err != nil {
			a.logger.Warn("acme_http01: valkey unavailable during provision, falling back to challenge_dir",
				zap.String("address", a.Valkey.Address), zap.Error(err))
		} else {
			a.valkeyCli = cli
		}
	}
	return nil
}

// Cleanup 释放 Valkey 客户端资源。
func (a *ACMEHTTP01) Cleanup() error {
	if a.valkeyCli != nil {
		a.valkeyCli.Close()
		a.valkeyCli = nil
	}
	return nil
}

// ServeHTTP 匹配 /.well-known/acme-challenge/<token> 并应答有效挑战令牌；其余请求原样放行。
func (a *ACMEHTTP01) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if (r.Method != http.MethodGet && r.Method != http.MethodHead) ||
		!strings.HasPrefix(r.URL.Path, ACMEHTTP01PathPrefix) {
		return next.ServeHTTP(w, r)
	}
	token := strings.TrimPrefix(r.URL.Path, ACMEHTTP01PathPrefix)
	if !acmeHTTP01TokenPattern.MatchString(token) {
		return next.ServeHTTP(w, r)
	}
	keyAuth, found := a.lookupToken(r.Context(), token)
	if !found {
		return next.ServeHTTP(w, r)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return nil
	}
	_, _ = io.WriteString(w, keyAuth)
	return nil
}

func (a *ACMEHTTP01) lookupToken(ctx context.Context, token string) (string, bool) {
	if a.lookupFunc != nil {
		val, ok, err := a.lookupFunc(ctx, token)
		if err == nil && ok && isValidACMEKeyAuth(val) {
			return val, true
		}
		if err != nil && a.logger != nil {
			a.logger.Warn("acme_http01: custom lookup failed, falling back to file", zap.Error(err))
		}
	} else if a.valkeyCli != nil {
		qctx, cancel := context.WithTimeout(ctx, acmeHTTP01ValkeyTimeout)
		res := a.valkeyCli.Do(qctx, a.valkeyCli.B().Get().Key(ACMEHTTP01ValkeyKeyPrefix+token).Build())
		cancel()
		val, err := res.ToString()
		if err == nil {
			val = strings.TrimSpace(val)
			if isValidACMEKeyAuth(val) {
				return val, true
			}
		} else if !valkey.IsValkeyNil(err) && a.logger != nil {
			a.logger.Warn("acme_http01: valkey lookup failed, falling back to challenge_dir", zap.Error(err))
		}
	}

	if a.ChallengeDir != "" {
		if val, ok := readACMEChallengeFile(a.ChallengeDir, token); ok {
			return val, true
		}
	}
	return "", false
}

func readACMEChallengeFile(dir, token string) (string, bool) {
	if !acmeHTTP01TokenPattern.MatchString(token) {
		return "", false
	}
	fullPath := filepath.Join(dir, token)
	info, err := os.Lstat(fullPath)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > acmeHTTP01MaxBodyBytes {
		return "", false
	}
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return "", false
	}
	val := strings.TrimSpace(string(data))
	if !isValidACMEKeyAuth(val) {
		return "", false
	}
	return val, true
}

func isValidACMEKeyAuth(s string) bool {
	if len(s) == 0 || len(s) > acmeHTTP01MaxBodyBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

var (
	_ caddy.Provisioner           = (*ACMEHTTP01)(nil)
	_ caddy.CleanerUpper          = (*ACMEHTTP01)(nil)
	_ caddyhttp.MiddlewareHandler = (*ACMEHTTP01)(nil)
)

// ErrACMEInvalidToken 用于显式单元测试断言。
var ErrACMEInvalidToken = errors.New("invalid acme http-01 token")
