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

	"github.com/jiuzhang-waf/server/internal/product"
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
	APM      APMConfig
	Kafka    KafkaConfig
	// SystemOps 系统控制（重启/关机/恢复出厂）宿主控制指令配置
	SystemOps SystemOpsConfig
	// ContainerOps 容器运维 sidecar（containeropsd）通道配置
	ContainerOps ContainerOpsConfig
	// RequestPCAP 默认空配置即关闭；三个路径配置完整时才加载证据服务。
	RequestPCAP RequestPCAPConfig
	// Product 产品 edition 与 WDSP/API 能力开关（阶段8）
	Product product.Settings
}

// SystemOpsConfig 系统控制配置（管理面只写标志文件，由宿主侧 hostctl 消费执行）。
type SystemOpsConfig struct {
	// HostctlDir 宿主控制指令标志文件目录；环境变量 HOSTCTL_DIR，默认 /app/runtime/hostctl
	HostctlDir string
}

// ContainerOpsConfig 容器运维通道配置：管理 API 不挂载 docker.sock，
// 经共享卷 Unix Socket 调用 containeropsd sidecar（docs/CONTAINER_OPS_DESIGN.md）。
type ContainerOpsConfig struct {
	// Socket containeropsd 本地 Unix Socket 路径；环境变量 CONTAINEROPS_SOCKET，
	// 默认空 = 功能不可用（裸机/未部署 sidecar 形态），接口返回明确 503，不伪造空列表
	Socket string
}

type RequestPCAPConfig struct {
	HotDir                   string
	WarmDir                  string
	KeyFile                  string
	PublicDir                string
	Retention                time.Duration
	HotAge                   time.Duration
	GrantTTL                 time.Duration
	MigrateBytesPerSecond    int64
	MinFreePercent           int
	CaptureEnabled           bool
	CaptureControlConfigured bool
}

func (c RequestPCAPConfig) Enabled() bool {
	return c.HotDir != "" && c.WarmDir != "" && c.KeyFile != "" && (!c.CaptureControlConfigured || c.CaptureEnabled)
}

func (c RequestPCAPConfig) Validate() error {
	complete := c.HotDir != "" && c.WarmDir != "" && c.KeyFile != ""
	if !complete && (c.HotDir != "" || c.WarmDir != "" || c.KeyFile != "") {
		return fmt.Errorf("REQUEST_PCAP_HOT_DIR, REQUEST_PCAP_WARM_DIR and REQUEST_PCAP_KEY_FILE must be configured together")
	}
	if c.Enabled() && (c.Retention <= 0 || c.HotAge <= 0 || c.GrantTTL < time.Minute || c.GrantTTL > 7*24*time.Hour ||
		c.MigrateBytesPerSecond <= 0 || c.MigrateBytesPerSecond > 1<<30 || c.MinFreePercent < 1 || c.MinFreePercent > 95) {
		return fmt.Errorf("invalid request PCAP retention, migration limit or capacity watermark")
	}
	return nil
}

// AIConfig 阶段7 AI 模块开关（关闭时 /api/v1/ai/* 返回不可用，不影响 WAF 核心）。
type AIConfig struct {
	// Enabled 是否启用 AI 安全运营模块；环境变量 AI_ENABLED，默认 true
	Enabled bool
}

// APMConfig APM 业务性能监控开关（ADR D11；关闭时 /api/v1/apm/* 挂 503 降级 stub，
// 不影响 WAF 核心与既有聚合任务）。
type APMConfig struct {
	// Enabled 是否启用 APM 查询接口；环境变量 APM_ENABLED，默认 false
	Enabled bool
	// CollectorAddr Agent 数据面 OTLP Collector 地址（阶段2 下半部署后下发给 Agent；
	// 环境变量 APM_COLLECTOR_ADDR，默认空串——数据面未就绪时如实返回空）
	CollectorAddr string
	// AgentCertTTLHours Agent 客户端证书有效期（小时）；环境变量
	// APM_AGENT_CERT_TTL_HOURS，默认 72（合法区间 24~168，越界由装配侧夹紧）
	AgentCertTTLHours int
	// AgentOfflineMinutes 心跳超时多少分钟判定 Agent OFFLINE（查询侧推导，不落库）；
	// 环境变量 APM_AGENT_OFFLINE_MINUTES，默认 10（越界由装配侧夹紧）
	AgentOfflineMinutes int
	// ClickHouseDSN APM 数据面 ClickHouse 连接串（阶段2 下半；环境变量
	// APM_CLICKHOUSE_DSN，默认空串 = 未配置 → 保持纯无 Agent 模式，
	// trace 检索/瀑布等 OTel 数据如实降级为空，不影响既有 agentless 数据）
	ClickHouseDSN string
	// SelfTelemetryEnabled 管理后端自埋点开关（阶段2 收尾；环境变量
	// APM_SELF_TELEMETRY_ENABLED，默认 false = 零开销零行为变化）。
	// 仅包裹管理 API 的 HTTP Handler，不影响网关数据面。
	SelfTelemetryEnabled bool
	// OTLPAddr 自埋点 OTLP/HTTP 导出端点（指向本地 Collector；环境变量
	// APM_OTLP_ADDR，默认 http://127.0.0.1:4318）
	OTLPAddr string
}

type KafkaConfig struct {
	Enabled           bool
	Brokers           []string
	Topic             string
	DLQTopic          string
	TLSEnabled        bool
	TLSCAFile         string
	TLSCertFile       string
	TLSKeyFile        string
	TLSServerName     string
	SASLMechanism     string
	SASLUsername      string
	SASLPassword      string
	AllowInsecureSASL bool
	ProduceTimeout    time.Duration
	MaxBatchBytes     int
	MaxBatchRecords   int
}

func (c KafkaConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if len(c.Brokers) == 0 {
		return fmt.Errorf("KAFKA_BROKERS is required when KAFKA_ENABLED=true")
	}
	if c.Topic == "" || c.DLQTopic == "" {
		return fmt.Errorf("Kafka observation and DLQ topics are required")
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return fmt.Errorf("KAFKA_TLS_CERT_FILE and KAFKA_TLS_KEY_FILE must be configured together")
	}
	return nil
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
	// APIEventsLog API 动态防护运行时事件日志路径（API 侧采集，阶段8）
	APIEventsLog string
	// APIEventsLogGateway 网关容器内 API 事件日志路径（下发网关配置用，阶段8）
	APIEventsLogGateway string
	// AccessFullLog 全量访问日志路径（API 侧采集，二期）
	AccessFullLog string
	// AccessFullLogGateway 网关容器内全量访问日志路径（下发网关配置用，二期）
	AccessFullLogGateway string
	// IdentityEventsLog 身份与行为事件日志路径（API 侧采集，client_identity 体系；
	// 空 = 不启动 identity-events 采集器）
	IdentityEventsLog string
	// IdentityEventsLogGateway 网关容器内身份与行为事件日志路径（下发网关配置用）
	IdentityEventsLogGateway string
	// CoverageObsLog 执行覆盖观测日志路径（API 侧采集，NG-COV-01 摄入段；
	// 文件未生成时采集器空转不 crash，与其他日志采集器同一缺文件行为）
	CoverageObsLog string
	// CoverageObsLogGateway 网关容器内覆盖观测日志路径（coverage.FileSink 装配默认）
	CoverageObsLogGateway string
	// CoverageSampleN 覆盖观测明细采样率 1/N（NG-COV-02：聚合不受影响；<=1 全保留）
	CoverageSampleN int
	// NodeIfacesLog 节点网口清单快照日志路径（API 侧采集，WDSP 阶段A；api 容器内 /var/log/caddy-audit/ 前缀）
	NodeIfacesLog string
	// SiteDiscoveryLog 站点资产被动发现日志路径（API 侧采集；网关 mirrorcap 按窗口聚合写入）
	SiteDiscoveryLog string
	// CollectorFlushBatch 采集器批量 flush 阈值（处理记录数，W20 批量化修复；
	// 作用于 API 运行时事件与全量访问日志采集器，默认值与采集器内建默认一致）
	CollectorFlushBatch int
	// CollectorFlushInterval 采集器周期 flush 阈值（距上次 flush 时长，W20 批量化修复）
	CollectorFlushInterval time.Duration
	// SidecarDir 边车配置共享卷目录（api 容器内路径，与网关容器共享；
	// mirrorcap/tproxyd/network 边车配置与 network-status.json 均在此目录）
	SidecarDir string
}

// GatewayConfig 是网关配置（阶段3）。
type GatewayConfig struct {
	// AdminSocket Caddy Admin Unix Socket 路径
	AdminSocket string
	// DataDir 配置与证书数据目录
	DataDir string
	// ValkeyAddr guard 配置发布使用的 Valkey 地址；为空时回退到 Cache 配置。
	ValkeyAddr string
	// TracingEnabled 网关 Caddy 原生 OTel tracing 下发开关（http.handlers.tracing，
	// 阶段2 收尾；环境变量 GATEWAY_TRACING_ENABLED，默认 false）。
	// 开启时发布配置在每个路由链首注入 tracing handler；
	// exporter/采样由网关进程 OTEL_* 环境变量控制（见 docs/APM_DATA_PLANE_DEPLOYMENT.md）。
	TracingEnabled bool
}

// ValkeyAddress 返回 guard 配置发布使用的 Valkey 地址。
// 生产离线包的 gateway 使用 host 网络，因此可通过 GATEWAY_VALKEY_ADDR 连接宿主机端口；
// 未配置时保持开发与 bridge 网络下的 Cache 默认行为。
func (g GatewayConfig) ValkeyAddress(cache CacheConfig) string {
	if g.ValkeyAddr != "" {
		return g.ValkeyAddr
	}
	return cache.Addr()
}

// HTTPConfig 是 HTTP 服务配置。
type HTTPConfig struct {
	Host         string
	Port         int
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

const (
	DBDialectPostgres = "postgres"
	DBDialectKingbase = "kingbase"
	DBDialectDameng   = "dameng"
)

// DBConfig 是主业务数据库配置。空 Dialect 按 PostgreSQL 处理，兼容既有调用方。
type DBConfig struct {
	Dialect  string
	Host     string
	Port     int
	Database string
	User     string
	Password string
	SSLMode  string
	MaxConns int32
}

// DialectName 返回归一化后的数据库方言。
func (c DBConfig) DialectName() string {
	if strings.TrimSpace(c.Dialect) == "" {
		return DBDialectPostgres
	}
	return strings.ToLower(strings.TrimSpace(c.Dialect))
}

// Validate 校验数据库方言是否属于受支持的范围。
func (c DBConfig) Validate() error {
	switch c.DialectName() {
	case DBDialectPostgres, DBDialectKingbase, DBDialectDameng:
		return nil
	default:
		return fmt.Errorf("unsupported DB_DIALECT %q (want postgres, kingbase or dameng)", c.Dialect)
	}
}

func defaultDBPort(dialect string) int {
	switch dialect {
	case DBDialectKingbase:
		return 54321
	case DBDialectDameng:
		return 5236
	default:
		return 5432
	}
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

func loadDBConfig(dialect string) DBConfig {
	cfg := DBConfig{
		Dialect:  dialect,
		Host:     getEnv("DB_HOST", "127.0.0.1"),
		Port:     getEnvInt("DB_PORT", defaultDBPort(dialect)),
		Database: getEnv("DB_NAME", "jiuzhang_waf"),
		User:     getEnv("DB_USER", "jiuzhang"),
		Password: os.Getenv("DB_PASSWORD"),
		SSLMode:  getEnv("DB_SSLMODE", "disable"),
		MaxConns: int32(getEnvInt("DB_MAX_CONNS", 10)),
	}
	if dialect == DBDialectPostgres {
		cfg.Host = getEnv("DB_HOST", getEnv("POSTGRES_HOST", "127.0.0.1"))
		cfg.Port = getEnvInt("DB_PORT", getEnvInt("POSTGRES_PORT", defaultDBPort(dialect)))
		cfg.Database = getEnv("DB_NAME", getEnv("POSTGRES_DB", "jiuzhang_waf"))
		cfg.User = getEnv("DB_USER", getEnv("POSTGRES_USER", "jiuzhang"))
		cfg.Password = getEnv("DB_PASSWORD", os.Getenv("POSTGRES_PASSWORD"))
		cfg.SSLMode = getEnv("DB_SSLMODE", getEnv("POSTGRES_SSLMODE", "disable"))
		cfg.MaxConns = int32(getEnvInt("DB_MAX_CONNS", getEnvInt("POSTGRES_MAX_CONNS", 10)))
	}
	return cfg
}

// Load 从环境变量加载配置。
func Load() (*Config, error) {
	dialect := strings.ToLower(strings.TrimSpace(getEnv("DB_DIALECT", DBDialectPostgres)))
	captureEnabled, captureControlConfigured := false, false
	if strings.TrimSpace(os.Getenv("REQUEST_PCAP_CAPTURE_ENABLED")) != "" {
		captureControlConfigured = true
		captureEnabled = getEnvBool("REQUEST_PCAP_CAPTURE_ENABLED", false)
	}
	cfg := &Config{
		Env: getEnv("APP_ENV", "dev"),
		HTTP: HTTPConfig{
			Host:         getEnv("SERVER_HOST", "0.0.0.0"),
			Port:         getEnvInt("SERVER_PORT", 8080),
			ReadTimeout:  getEnvDuration("SERVER_READ_TIMEOUT", 30*time.Second),
			WriteTimeout: getEnvDuration("SERVER_WRITE_TIMEOUT", 30*time.Second),
			IdleTimeout:  getEnvDuration("SERVER_IDLE_TIMEOUT", 60*time.Second),
		},
		DB: loadDBConfig(dialect),
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
			AdminSocket:    getEnv("CADDY_ADMIN_SOCKET", "/var/run/caddy/admin.sock"),
			DataDir:        getEnv("GATEWAY_DATA_DIR", "runtime"),
			ValkeyAddr:     getEnv("GATEWAY_VALKEY_ADDR", ""),
			TracingEnabled: getEnvBool("GATEWAY_TRACING_ENABLED", false),
		},
		WAF: WAFConfig{
			CRSDir:                getEnv("WAF_CRS_DIR", "gateway/rules/crs/rules"),
			CRSVersion:            getEnv("WAF_CRS_VERSION", "4.28.0"),
			AuditLogPath:          getEnv("WAF_AUDIT_LOG", "runtime/logs/stage1/coraza-audit.log"),
			GatewayNodeName:       getEnv("GATEWAY_NODE_NAME", "gateway-poc-01"),
			GuardEventsLog:        getEnv("WAF_GUARD_EVENTS_LOG", "runtime/logs/guard-events.log"),
			GuardEventsLogGateway: getEnv("GATEWAY_GUARD_EVENTS_LOG", "/var/log/caddy/guard-events.log"),
			// 非 prod 默认 fail-open 便于开发；prod 默认 fail-closed（可用 GUARD_FAIL_OPEN 覆盖）
			GuardFailOpen:        getEnvBool("GUARD_FAIL_OPEN", getEnv("APP_ENV", "dev") != "prod"),
			AccessLogPath:        getEnv("WAF_ACCESS_LOG", "runtime/logs/access.log"),
			APIEventsLog:         getEnv("WAF_API_EVENTS_LOG", "runtime/logs/api-runtime-events.log"),
			APIEventsLogGateway:  getEnv("GATEWAY_API_EVENTS_LOG", "/var/log/caddy/api-runtime-events.log"),
			AccessFullLog:        getEnv("WAF_ACCESS_FULL_LOG", "runtime/logs/access-full.jsonl"),
			AccessFullLogGateway: getEnv("GATEWAY_ACCESS_FULL_LOG", "/var/log/caddy/access-full.jsonl"),
			// client_identity 体系：采集路径空 = 不启动 identity-events 采集器（main.go 装配门控）；
			// 网关侧路径下发 identity_events_log（与 guard-events.log 同目录推导）
			IdentityEventsLog:        getEnv("WAF_IDENTITY_EVENTS_LOG", ""),
			IdentityEventsLogGateway: getEnv("GATEWAY_IDENTITY_EVENTS_LOG", "/var/log/caddy/identity-events.log"),
			// 执行覆盖观测（NG-COV-01 摄入段）：读侧与网关侧默认同值（同一 /var/log/caddy 卷内文件；
			// 部署形态经 compose 把读侧改指 /var/log/caddy-audit 只读卷，本地缺文件时采集器空转不 crash）
			CoverageObsLog:        getEnv("WAF_COVERAGE_OBS_LOG", "/var/log/caddy/coverage-observations.jsonl"),
			CoverageObsLogGateway: getEnv("GATEWAY_COVERAGE_OBS_LOG", "/var/log/caddy/coverage-observations.jsonl"),
			CoverageSampleN:       getEnvInt("WAF_COVERAGE_SAMPLE_N", 10),
			NodeIfacesLog:         getEnv("WAF_NODE_IFACES_LOG", "runtime/logs/node-interfaces.jsonl"),
			SiteDiscoveryLog:      getEnv("WAF_SITE_DISCOVERY_LOG", "runtime/logs/site-discovery.jsonl"),
			// 采集器批量/周期 flush 阈值（W20；默认值与 apiruntime/accesslogs 采集器内建默认一致）
			CollectorFlushBatch:    getEnvInt("WAF_COLLECTOR_FLUSH_BATCH", 2000),
			CollectorFlushInterval: getEnvDuration("WAF_COLLECTOR_FLUSH_INTERVAL", 2*time.Second),
			// 边车共享卷目录（与 gatewayconfig.DefaultSidecarDir / netconfig.DefaultSidecarDir 一致）
			SidecarDir: getEnv("GATEWAY_SIDECAR_DIR", "/var/run/caddy/sidecars"),
		},
		AI: AIConfig{
			Enabled: getEnvBool("AI_ENABLED", true),
		},
		APM: APMConfig{
			Enabled: getEnvBool("APM_ENABLED", false),
			// 阶段2 上半 Agent 控制面：Collector 地址/证书有效期/离线判定阈值
			CollectorAddr:       getEnv("APM_COLLECTOR_ADDR", ""),
			AgentCertTTLHours:   getEnvInt("APM_AGENT_CERT_TTL_HOURS", 72),
			AgentOfflineMinutes: getEnvInt("APM_AGENT_OFFLINE_MINUTES", 10),
			// 阶段2 下半数据面：ClickHouse DSN（空 = 纯无 Agent 模式）
			ClickHouseDSN: getEnv("APM_CLICKHOUSE_DSN", ""),
			// 阶段2 收尾：管理后端自埋点（默认关）
			SelfTelemetryEnabled: getEnvBool("APM_SELF_TELEMETRY_ENABLED", false),
			OTLPAddr:             getEnv("APM_OTLP_ADDR", "http://127.0.0.1:4318"),
		},
		Kafka: KafkaConfig{
			Enabled: getEnvBool("KAFKA_ENABLED", false), Brokers: getEnvList("KAFKA_BROKERS"),
			Topic:      getEnv("KAFKA_API_OBSERVATION_TOPIC", "wdsp.api.observations.v1"),
			DLQTopic:   getEnv("KAFKA_API_OBSERVATION_DLQ_TOPIC", "wdsp.api.observations.dlq.v1"),
			TLSEnabled: getEnvBool("KAFKA_TLS_ENABLED", false), TLSCAFile: os.Getenv("KAFKA_TLS_CA_FILE"),
			TLSCertFile: os.Getenv("KAFKA_TLS_CERT_FILE"), TLSKeyFile: os.Getenv("KAFKA_TLS_KEY_FILE"),
			TLSServerName: os.Getenv("KAFKA_TLS_SERVER_NAME"), SASLMechanism: os.Getenv("KAFKA_SASL_MECHANISM"),
			SASLUsername: os.Getenv("KAFKA_SASL_USERNAME"), SASLPassword: os.Getenv("KAFKA_SASL_PASSWORD"),
			AllowInsecureSASL: getEnvBool("KAFKA_ALLOW_INSECURE_SASL", false),
			ProduceTimeout:    getEnvDuration("KAFKA_PRODUCE_TIMEOUT", 10*time.Second),
			MaxBatchBytes:     getEnvInt("KAFKA_MAX_BATCH_BYTES", 4<<20), MaxBatchRecords: getEnvInt("KAFKA_MAX_BATCH_RECORDS", 100),
		},
		RequestPCAP: RequestPCAPConfig{
			HotDir: strings.TrimSpace(os.Getenv("REQUEST_PCAP_HOT_DIR")), WarmDir: strings.TrimSpace(os.Getenv("REQUEST_PCAP_WARM_DIR")),
			KeyFile:                  strings.TrimSpace(os.Getenv("REQUEST_PCAP_KEY_FILE")),
			PublicDir:                strings.TrimSpace(os.Getenv("REQUEST_PCAP_PUBLIC_DIR")),
			Retention:                getEnvDuration("REQUEST_PCAP_RETENTION", 24*time.Hour),
			HotAge:                   getEnvDuration("REQUEST_PCAP_HOT_AGE", 15*time.Minute),
			GrantTTL:                 getEnvDuration("REQUEST_PCAP_GRANT_TTL", 24*time.Hour),
			MigrateBytesPerSecond:    int64(getEnvInt("REQUEST_PCAP_MIGRATE_BPS", 32<<20)),
			MinFreePercent:           getEnvInt("REQUEST_PCAP_MIN_FREE_PERCENT", 10),
			CaptureControlConfigured: captureControlConfigured,
			CaptureEnabled:           captureEnabled,
		},
		Product: product.Load(),
		SystemOps: SystemOpsConfig{
			HostctlDir: getEnv("HOSTCTL_DIR", "/app/runtime/hostctl"),
		},
		ContainerOps: ContainerOpsConfig{
			Socket: getEnv("CONTAINEROPS_SOCKET", ""),
		},
	}
	if err := cfg.DB.Validate(); err != nil {
		return nil, err
	}
	if err := cfg.Kafka.Validate(); err != nil {
		return nil, err
	}
	if err := cfg.RequestPCAP.Validate(); err != nil {
		return nil, err
	}
	if cfg.DB.Password == "" {
		if cfg.DB.DialectName() == DBDialectPostgres {
			return nil, fmt.Errorf("POSTGRES_PASSWORD is required")
		}
		return nil, fmt.Errorf("DB_PASSWORD is required")
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
