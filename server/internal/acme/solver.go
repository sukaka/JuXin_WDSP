package acme

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/jiuzhang-waf/server/internal/cache"
)

const (
	// HTTP01ValkeyKeyPrefix 与网关 jiuzhang_acme_http01 模块共享同一键前缀。
	HTTP01ValkeyKeyPrefix = "jiuzhang:acme:http01:"
	http01DefaultTTL      = 10 * time.Minute
)

var validHTTP01TokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

// ChallengeSolver 定义 ACME 域名所有权验证求解器抽象（一期实现 HTTP-01，预留 DNS-01 扩展）。
type ChallengeSolver interface {
	Type() string
	Present(ctx context.Context, domain, token, keyAuth string) error
	CleanUp(ctx context.Context, domain, token string) error
}

// HTTP01Solver 通过共享 Valkey（支持 Active-Active 多节点 HA）与本地证书目录原子写
// （单机无 Valkey 或 Valkey 瞬断回退）双写发布 HTTP-01 挑战响应。
type HTTP01Solver struct {
	cache        *cache.Client
	challengeDir string
	ttl          time.Duration
}

// NewHTTP01Solver 创建 HTTP-01 挑战求解器。dataDir 为网关发布器数据目录（实际写入 <dataDir>/certificates/.acme-challenges）。
func NewHTTP01Solver(c *cache.Client, dataDir string) *HTTP01Solver {
	dir := ""
	if strings.TrimSpace(dataDir) != "" {
		dir = filepath.Join(strings.TrimSpace(dataDir), "certificates", ".acme-challenges")
	}
	return &HTTP01Solver{
		cache:        c,
		challengeDir: dir,
		ttl:          http01DefaultTTL,
	}
}

// Type 返回挑战类型标识。
func (s *HTTP01Solver) Type() string { return ChallengeHTTP01 }

// ChallengeDir 返回本地挑战文件目录。
func (s *HTTP01Solver) ChallengeDir() string { return s.challengeDir }

// Present 写入挑战令牌到 Valkey 与本地目录（至少一侧成功即视为就绪；两侧均失败则报错）。
func (s *HTTP01Solver) Present(ctx context.Context, domain, token, keyAuth string) error {
	if !validHTTP01TokenPattern.MatchString(token) {
		return fmt.Errorf("无效的 HTTP-01 token 格式")
	}
	keyAuth = strings.TrimSpace(keyAuth)
	if keyAuth == "" || len(keyAuth) > 1024 {
		return fmt.Errorf("无效的 HTTP-01 key authorization")
	}

	var valkeyErr, fileErr error
	wroteAny := false

	if s.cache != nil {
		if err := s.cache.Set(ctx, HTTP01ValkeyKeyPrefix+token, keyAuth, s.ttl); err != nil {
			valkeyErr = err
			slog.Warn("acme http-01 present to valkey failed", "domain", domain, "error", err)
		} else {
			wroteAny = true
		}
	}

	if s.challengeDir != "" {
		if err := writeChallengeFileAtomic(s.challengeDir, token, keyAuth); err != nil {
			fileErr = err
			slog.Warn("acme http-01 present to challenge dir failed", "domain", domain, "dir", s.challengeDir, "error", err)
		} else {
			wroteAny = true
		}
	}

	if !wroteAny {
		if valkeyErr != nil {
			return fmt.Errorf("发布 HTTP-01 挑战令牌失败（Valkey: %v, File: %v）", valkeyErr, fileErr)
		}
		if fileErr != nil {
			return fmt.Errorf("发布 HTTP-01 挑战令牌失败: %w", fileErr)
		}
		return fmt.Errorf("HTTP-01 挑战存储未配置（Valkey 与本地挑战目录均为空）")
	}
	return nil
}

// CleanUp 清理 Valkey 与本地挑战文件（幂等，单侧清理失败仅记日志）。
func (s *HTTP01Solver) CleanUp(ctx context.Context, domain, token string) error {
	if !validHTTP01TokenPattern.MatchString(token) {
		return nil
	}
	if s.cache != nil {
		if err := s.cache.Del(ctx, HTTP01ValkeyKeyPrefix+token); err != nil {
			slog.Warn("acme http-01 cleanup valkey failed", "domain", domain, "error", err)
		}
	}
	if s.challengeDir != "" {
		path := filepath.Join(s.challengeDir, token)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			slog.Warn("acme http-01 cleanup file failed", "domain", domain, "path", path, "error", err)
		}
	}
	return nil
}

// CleanStaleFiles 清理超过 maxAge 的陈旧挑战文件（防止进程异常重启后残留临时令牌）。
func (s *HTTP01Solver) CleanStaleFiles(maxAge time.Duration) int {
	if s.challengeDir == "" {
		return 0
	}
	entries, err := os.ReadDir(s.challengeDir)
	if err != nil {
		return 0
	}
	cutoff := time.Now().Add(-maxAge)
	removed := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			if err := os.Remove(filepath.Join(s.challengeDir, entry.Name())); err == nil {
				removed++
			}
		}
	}
	return removed
}

func writeChallengeFileAtomic(dir, token, content string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".acme-tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return err
	}
	// 0644：保障容器/裸机下网关非 root 进程只读挂载卷后均可读取公开的 HTTP-01 挑战响应
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, filepath.Join(dir, token)); err != nil {
		return err
	}
	cleanup = false
	return nil
}
