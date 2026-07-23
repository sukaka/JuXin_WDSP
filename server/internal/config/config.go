// Package config 加载管理后端配置。
// 所有敏感配置通过环境变量注入，禁止写死默认值。
package config

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config 是管理后端完整配置。
type Config struct {
	Env      string // dev / staging / prod
	HTTP     HTTPConfig
	DB       DBConfig
	Cache    CacheConfig
	Security SecurityConfig
	Gateway  GatewayConfig
	WAF      WAFConfig
	AI       AIConfig
}

// AIConfig 阶段7 AI 模块开关（关闭时 /api/v1/ai/* 返回不可用，不影响 WAF 核心）。
type AIConfig struct {
	// Enabled 是否启用 AI 安全运营模块；环境变量 AI_ENABLED，默认 true
	Enabled bool
}

// WAFConfig 是 WAF 配置（阶段4）。
type WAFConfig struct {
	// CRSDir OWASP CRS 规则目录
	CRSDir string
	// CRSVersion CRS 版本标识
	CRSVersion string
	// AuditLogPath Coraza 审计日志路径（事件采集）
	AuditLogPath string
	// GatewayNodeName 网关节点标识
	GatewayNodeName string
	// GuardEventsLog jiuzhang_guard 访问控制事件日志路径（API 侧采集，阶段5）
	GuardEventsLog string
	// GuardEventsLogGateway 网关容器内事件日志路径（下发网关配置用，阶段5）
	GuardEventsLogGateway string
	// GuardFailOpen CC 计数引擎故障策略：dev 默认 true；prod 默认 false（可用 GUARD_FAIL_OPEN 覆盖）
	GuardFailOpen bool
	// AccessLogPath Caddy 访问日志路径（API 侧采集，阶段6）
	AccessLogPath string
}

// GatewayConfig 是网关配置（阶段3）。
type GatewayConfig struct {
	// AdminSocket Caddy Admin Unix Socket 路径
	AdminSocket string
	// DataDir 配置与证书数据目录
	DataDir string
}

// HTTPConfig 是 HTTP 服务配置。
type HTTPConfig struct {
	Host         string
	Port         int
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

// DBConfig 是 PostgreSQL 配置。
type DBConfig struct {
	Host     string
	Port     int
	Database string
	User     string
	Password string
	SSLMode  string
	MaxConns int32
}

// CacheConfig 是 Valkey 配置。
type CacheConfig struct {
	Host     string
	Port     int
	Password string
	DB       int
}

// SecurityConfig 是安全配置。
type SecurityConfig struct {
	// CookieSecure 生产环境必须为 true（仅 HTTPS 下发 Cookie）
	CookieSecure bool
	// InitialAdminPassword 初始管理员密码（可选注入；为空则启动时生成一次性随机密码）
	InitialAdminPassword string
	// InitialAdminUsername 初始管理员用户名，默认 jiuzhang_admin
	InitialAdminUsername string
	// CORSAllowedOrigins 允许的来源（开发环境为空时允许 vite dev server）
	CORSAllowedOrigins []string
	// TrustedProxyCIDRs 管理面可信反向代理网段；仅来自这些网段的转发头会被解析
	TrustedProxyCIDRs []string
}

// DSN 返回 PostgreSQL 连接串。
func (c DBConfig) DSN() string {
	query := url.Values{}
	query.Set("sslmode", c.SSLMode)
	dsn := &url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(c.User, c.Password),
		Host:     net.JoinHostPort(c.Host, strconv.Itoa(c.Port)),
		Path:     "/" + c.Database,
		RawPath:  "/" + url.PathEscape(c.Database),
		RawQuery: query.Encode(),
	}
	return dsn.String()
}

// Addr 返回 Valkey 地址。
func (c CacheConfig) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// HTTPAddr 返回 HTTP 监听地址。
func (c HTTPConfig) HTTPAddr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// Load 从环境变量加载配置。
func Load() (*Config, error) {
	cfg := &Config{
		Env: getEnv("APP_ENV", "dev"),
		HTTP: HTTPConfig{
			Host:         getEnv("SERVER_HOST", "0.0.0.0"),
			Port:         getEnvInt("SERVER_PORT", 8080),
			ReadTimeout:  getEnvDuration("SERVER_READ_TIMEOUT", 30*time.Second),
			WriteTimeout: getEnvDuration("SERVER_WRITE_TIMEOUT", 30*time.Second),
			IdleTimeout:  getEnvDuration("SERVER_IDLE_TIMEOUT", 60*time.Second),
		},
		DB: DBConfig{
			Host:     getEnv("POSTGRES_HOST", "127.0.0.1"),
			Port:     getEnvInt("POSTGRES_PORT", 5432),
			Database: getEnv("POSTGRES_DB", "jiuzhang_waf"),
			User:     getEnv("POSTGRES_USER", "jiuzhang"),
			Password: os.Getenv("POSTGRES_PASSWORD"),
			SSLMode:  getEnv("POSTGRES_SSLMODE", "disable"),
			MaxConns: int32(getEnvInt("POSTGRES_MAX_CONNS", 10)),
		},
		Cache: CacheConfig{
			Host:     getEnv("VALKEY_HOST", "127.0.0.1"),
			Port:     getEnvInt("VALKEY_PORT", 6379),
			Password: os.Getenv("VALKEY_PASSWORD"),
			DB:       getEnvInt("VALKEY_DB", 0),
		},
		Security: SecurityConfig{
			CookieSecure:         getEnvBool("COOKIE_SECURE", false),
			InitialAdminPassword: os.Getenv("INITIAL_ADMIN_PASSWORD"),
			InitialAdminUsername: getEnv("INITIAL_ADMIN_USERNAME", "jiuzhang_admin"),
			CORSAllowedOrigins:   getEnvList("CORS_ALLOWED_ORIGINS"),
			TrustedProxyCIDRs:    getEnvList("MANAGEMENT_TRUSTED_PROXY_CIDRS"),
		},
		Gateway: GatewayConfig{
			AdminSocket: getEnv("CADDY_ADMIN_SOCKET", "/var/run/caddy/admin.sock"),
			DataDir:     getEnv("GATEWAY_DATA_DIR", "runtime"),
		},
		WAF: WAFConfig{
			CRSDir:                getEnv("WAF_CRS_DIR", "gateway/rules/crs/rules"),
			CRSVersion:            getEnv("WAF_CRS_VERSION", "4.28.0"),
			AuditLogPath:          getEnv("WAF_AUDIT_LOG", "runtime/logs/stage1/coraza-audit.log"),
			GatewayNodeName:       getEnv("GATEWAY_NODE_NAME", "gateway-poc-01"),
			GuardEventsLog:        getEnv("WAF_GUARD_EVENTS_LOG", "runtime/logs/guard-events.log"),
			GuardEventsLogGateway: getEnv("GATEWAY_GUARD_EVENTS_LOG", "/var/log/caddy/guard-events.log"),
			// 非 prod 默认 fail-open 便于开发；prod 默认 fail-closed（可用 GUARD_FAIL_OPEN 覆盖）
			GuardFailOpen: getEnvBool("GUARD_FAIL_OPEN", getEnv("APP_ENV", "dev") != "prod"),
			AccessLogPath: getEnv("WAF_ACCESS_LOG", "runtime/logs/access.log"),
		},
		AI: AIConfig{
			Enabled: getEnvBool("AI_ENABLED", true),
		},
	}
	if cfg.DB.Password == "" {
		return nil, fmt.Errorf("POSTGRES_PASSWORD is required")
	}
	if cfg.Cache.Password == "" {
		return nil, fmt.Errorf("VALKEY_PASSWORD is required")
	}
	if cfg.Env == "prod" && !cfg.Security.CookieSecure {
		return nil, fmt.Errorf("COOKIE_SECURE must be true in prod")
	}
	for _, cidr := range cfg.Security.TrustedProxyCIDRs {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return nil, fmt.Errorf("invalid MANAGEMENT_TRUSTED_PROXY_CIDRS entry %q: %w", cidr, err)
		}
	}
	// 生产默认 fail-closed：若未显式设置 GUARD_FAIL_OPEN，强制 false
	if cfg.Env == "prod" && os.Getenv("GUARD_FAIL_OPEN") == "" {
		cfg.WAF.GuardFailOpen = false
	}
	return cfg, nil
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func getEnvBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func getEnvDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func getEnvList(key string) []string {
	v := os.Getenv(key)
	if v == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i <= len(v); i++ {
		if i == len(v) || v[i] == ',' {
			item := strings.TrimSpace(v[start:i])
			if item != "" {
				out = append(out, item)
			}
			start = i + 1
		}
	}
	return out
}
