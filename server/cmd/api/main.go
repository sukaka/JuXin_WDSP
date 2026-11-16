// 九章管理后端 API 服务
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/accesscontrolevents"
	"github.com/jiuzhang-waf/server/internal/accesslogs"
	"github.com/jiuzhang-waf/server/internal/accessrules"
	"github.com/jiuzhang-waf/server/internal/aggregations"
	"github.com/jiuzhang-waf/server/internal/aiaudit"
	"github.com/jiuzhang-waf/server/internal/apiassets"
	"github.com/jiuzhang-waf/server/internal/apiauthz"
	"github.com/jiuzhang-waf/server/internal/apidata"
	"github.com/jiuzhang-waf/server/internal/apiexposure"
	"github.com/jiuzhang-waf/server/internal/apifiles"
	"github.com/jiuzhang-waf/server/internal/apigeo"
	"github.com/jiuzhang-waf/server/internal/apillm"
	"github.com/jiuzhang-waf/server/internal/apimodels"
	"github.com/jiuzhang-waf/server/internal/apinodes"
	"github.com/jiuzhang-waf/server/internal/apiruntime"
	"github.com/jiuzhang-waf/server/internal/apiweakness"
	"github.com/jiuzhang-waf/server/internal/apm"
	"github.com/jiuzhang-waf/server/internal/app"
	"github.com/jiuzhang-waf/server/internal/applications"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/cache"
	"github.com/jiuzhang-waf/server/internal/config"
	"github.com/jiuzhang-waf/server/internal/coverage"
	"github.com/jiuzhang-waf/server/internal/database"
	"github.com/jiuzhang-waf/server/internal/exceptions"
	"github.com/jiuzhang-waf/server/internal/guardjanitor"
	"github.com/jiuzhang-waf/server/internal/identityevents"
	"github.com/jiuzhang-waf/server/internal/learningjobs"
	"github.com/jiuzhang-waf/server/internal/nodeinterfaces"
	"github.com/jiuzhang-waf/server/internal/protectedaddresses"
	"github.com/jiuzhang-waf/server/internal/security"
	"github.com/jiuzhang-waf/server/internal/securityevents"
	"github.com/jiuzhang-waf/server/internal/settings"
	"github.com/jiuzhang-waf/server/internal/sitediscovery"
	"github.com/jiuzhang-waf/server/internal/strongflow"
	"github.com/jiuzhang-waf/server/internal/syslogfw"
	"github.com/jiuzhang-waf/server/internal/systemalerts"
	"github.com/jiuzhang-waf/server/internal/temporaryblocks"
	"github.com/jiuzhang-waf/server/internal/users"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// 结构化日志
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	ctx := context.Background()

	// 数据库迁移
	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		return runMigrate(ctx, cfg, os.Args[2:])
	}

	// 连接数据库
	db, err := database.Connect(ctx, cfg.DB)
	if err != nil {
		return fmt.Errorf("connect database: %w", err)
	}
	defer db.Close()

	// 连接 Valkey
	cacheClient, err := cache.New(ctx, cfg.Cache)
	if err != nil {
		return fmt.Errorf("connect valkey: %w", err)
	}
	defer cacheClient.Close()

	// 初始化管理员（首次启动）
	if err := ensureInitialAdmin(ctx, db, cfg); err != nil {
		return fmt.Errorf("ensure initial admin: %w", err)
	}

	// 装配应用
	application, err := app.New(cfg, db, cacheClient)
	if err != nil {
		return fmt.Errorf("initialize application: %w", err)
	}

	// syslog 外发（三期）：后台发送循环 + spool 重放，采集器入库成功后 fan-out 投递
	collectorCtx, collectorCancel := context.WithCancel(context.Background())
	defer collectorCancel()
	syslogFw := application.SyslogForwarder()
	go syslogFw.Run(collectorCtx)

	// 告警通知外发（一期）：后台发送循环 + 聚合摘要 + spool 重放
	go application.NotifyDispatcher().Run(collectorCtx)

	// 阶段4：启动安全事件采集器（后台 goroutine）
	eventCollector := securityevents.NewCollector(db, "collector-01", cfg.WAF.AuditLogPath, cfg.WAF.GatewayNodeName)
	eventCollector.SetSyslogForwarder(syslogFw)
	go eventCollector.Run(collectorCtx, 2*time.Second)

	// 阶段5：启动访问控制/CC 事件采集器（断点续传，封禁与命中联动）
	// 注意：checkpoint 必须落在可写数据目录（日志卷以只读方式挂载，不能存放断点）
	acEventStore := accesscontrolevents.NewStore(db)
	acTempBlocks := temporaryblocks.NewStore(db, cacheClient)
	// 阶段5 §十五：CC 自动封禁前的共享出口（NAT）风险检查——命中疑似共享出口
	// 降档缩短封禁时长并写 CC_TEMP_BLOCK_DOWNGRADED 审计事件（配置走
	// system_settings cc_auto_block 组，种子见迁移 000153）。
	acTempBlocks.SetNATGuardSettings(settings.NewService(db))
	acTempBlocks.SetNATDowngradeEmitter(func(ctx context.Context, b *temporaryblocks.Block, d temporaryblocks.NATDowngrade) {
		if b == nil {
			return
		}
		expiresAt := b.BlockExpiresAt
		ev := accesscontrolevents.Event{
			OccurredAt:     time.Now().UTC(),
			ApplicationID:  b.ApplicationID,
			ClientIP:       b.ClientIP,
			EventType:      accesscontrolevents.EventTypeCCTempBlockDowngraded,
			Action:         accesscontrolevents.ActionTempBlock,
			AccessRuleID:   b.ID.String(),
			BlockExpiresAt: &expiresAt,
			Message:        "自动封禁命中共享出口（NAT）风险，降档缩短封禁时长",
			GatewayNodeID:  "management-api",
			Details:        map[string]interface{}{"nat_guard": d},
		}
		if _, err := acEventStore.Insert(ctx, []accesscontrolevents.Event{ev}); err != nil {
			slog.Error("write CC_TEMP_BLOCK_DOWNGRADED event failed", "error", err, "block_id", b.ID)
		}
	})
	acRules := accessrules.NewStore(db)
	acCollector := accesscontrolevents.NewCollector(acEventStore, "ac-collector-01",
		cfg.WAF.GuardEventsLog, filepath.Join(cfg.Gateway.DataDir, "guard-events.checkpoint"), cfg.WAF.GatewayNodeName)
	acCollector.SetBlockUpserter(acTempBlocks)
	acCollector.SetHitRecorder(acRules)
	acCollector.SetSyslogForwarder(syslogFw)
	go acCollector.Run(collectorCtx, 2*time.Second)

	// 阶段5：到期自动失效调度（临时规则/临时封禁/临时例外标记 EXPIRED + 系统审计）
	auditSvcForJanitor := audits.NewService(db)
	auditSvcForJanitor.SetSyslogForwarder(func(severityHint string, payload interface{}) {
		syslogFw.Enqueue(syslogfw.KindOperationAudit, severityHint, payload)
	})
	exceptionStoreForJanitor := exceptions.NewStore(db)
	go guardjanitor.RunFull(collectorCtx, time.Minute, acRules, acTempBlocks, exceptionStoreForJanitor, auditSvcForJanitor, acEventStore)

	// 阶段5 §七：保护地址自动维护（系统自动登记；启动时一次 + 周期刷新，
	// 周期由 PROTECTED_ADDRESS_REFRESH_INTERVAL 配置，默认 1 小时；
	// 单次刷新失败仅记错误日志，不阻断启动与后续调度；手动刷新端点保留）
	go protectedaddresses.NewRefresher(protectedaddresses.NewStore(db),
		protectedaddresses.RefreshIntervalFromEnv(os.Getenv)).Run(collectorCtx)

	// 阶段7 §26.4：AI 数据保留清理（会话/Tool 调用/草稿/用量分批限量清理 + 系统审计；
	// 审计表哈希链只校验不删除；保留天数经 system_settings ai 组配置，默认 90/90/90/180/365 天）
	aiRetentionCleaner := guardjanitor.NewAIRetentionCleaner(db, settings.NewService(db), auditSvcForJanitor, aiaudit.NewService(db))
	go aiRetentionCleaner.Run(collectorCtx, guardjanitor.DefaultAIRetentionInterval)

	// 阶段6：访问日志采集器与数据聚合任务
	aggStore := aggregations.NewStore(db)
	accessCollector := aggregations.NewAccessLogCollector(aggStore,
		cfg.WAF.AccessLogPath, filepath.Join(cfg.Gateway.DataDir, "access-log.checkpoint"))
	go accessCollector.Run(collectorCtx, 2*time.Second)
	aggJobs := aggregations.NewJobs(aggStore)
	go aggJobs.Run(collectorCtx)

	// 全量访问日志（二期）：JSON Lines 采集器 + 留存清理（开关默认关闭，无日志文件时采集器空转）
	accessFullCollector := accesslogs.NewCollector(db, "accesslog-01", cfg.WAF.AccessFullLog)
	accessFullCollector.SetSyslogForwarder(syslogFw)
	accessFullCollector.SetFlushPolicy(cfg.WAF.CollectorFlushBatch, cfg.WAF.CollectorFlushInterval)
	// W22 事务批量化（与 apiruntime 采集器同手法）：每个 flush 批次一个 DB 事务，
	// 行数据 + 失败队列 + 断点原子提交，消除逐行 commit 开销；失败回滚、断点不前移
	accessFullCollector.SetBatchTxFactory(db.Begin)
	go accessFullCollector.Run(collectorCtx, 2*time.Second)
	go accesslogs.NewRetentionCleaner(db, settings.NewService(db)).Run(collectorCtx, 10*time.Minute)

	// 站点资产被动发现：mirrorcap site-discovery.jsonl 断点续传 upsert（幂等键 domain+ip+port；
	// 日志文件未生成时采集器空转；checkpoint 落在可写数据目录，日志卷只读挂载）
	siteDiscoveryCollector := sitediscovery.NewCollector(sitediscovery.NewStore(db), "site-discovery-01",
		cfg.WAF.SiteDiscoveryLog, filepath.Join(cfg.Gateway.DataDir, "site-discovery.checkpoint"), cfg.WAF.GatewayNodeName)
	go siteDiscoveryCollector.Run(collectorCtx, 2*time.Second)

	// client_identity 体系：身份与行为事件采集器（identity-events.log 三种记录——
	// 身份观测/行为快照/侦察信号，断点名 identity-events.checkpoint；WAF_IDENTITY_EVENTS_LOG
	// 为空 = 不启动该采集器；checkpoint 落在可写数据目录，日志卷只读挂载）
	if cfg.WAF.IdentityEventsLog != "" {
		identityCollector := identityevents.NewCollector(identityevents.NewStore(db), db.Begin,
			"identity-events-01", cfg.WAF.IdentityEventsLog,
			filepath.Join(cfg.Gateway.DataDir, "identity-events.checkpoint"), cfg.WAF.GatewayNodeName)
		go identityCollector.Run(collectorCtx, 2*time.Second)
	}

	// 执行覆盖观测（NG-COV-01/02 摄入段）：coverage-observations.jsonl 断点续传——
	// 明细 1/N 采样落 coverage_observations、五态聚合 upsert coverage_minute_agg、
	// 每次 flush 落 coverage_counter_snapshots 阶段计数；checkpoint 落在可写数据目录
	// （日志卷只读挂载）；观测日志未生成时采集器空转不 crash（与其他采集器同一缺文件行为）
	coverageCollector := coverage.NewCollector(coverage.NewStore(db), db.Begin,
		"coverage-obs-01", cfg.WAF.CoverageObsLog,
		filepath.Join(cfg.Gateway.DataDir, "coverage-observations.checkpoint"), cfg.WAF.GatewayNodeName)
	coverageCollector.SetSampleN(uint64(cfg.WAF.CoverageSampleN))
	coverageCollector.SetFlushPolicy(cfg.WAF.CollectorFlushBatch, cfg.WAF.CollectorFlushInterval)
	go coverageCollector.Run(collectorCtx, 2*time.Second)

	// 阶段8 / WDSP：API 运行时事件采集器（仅 WDSP 且开关开启时启动；
	// checkpoint 落在可写数据目录，日志卷只读挂载）
	if cfg.Product.APIDynamicProtectionEnabled() {
		apiRuntimeStore := apiruntime.NewStore(db)
		apiAssetStore := apiassets.NewStore(db)
		apiCollector := apiruntime.NewCollector(apiRuntimeStore, "api-collector-01",
			cfg.WAF.APIEventsLog, filepath.Join(cfg.Gateway.DataDir, "api-runtime-events.checkpoint"), cfg.WAF.GatewayNodeName)
		apiCollector.SetDiscoveryUpserter(apiAssetStore)
		// 端点归属解析：app_code → application_id，host → domain_id
		apiCollector.SetResolver(apiruntime.NewAppResolver(applications.NewStore(db)))
		// 学习自动化闭环（P0-1）：样本按学习任务落库 + 达阈值自动完成学习并生成候选模型
		apiCollector.SetSampleRecorder(apiAssetStore)
		// 参数约束/Schema 偏离专项落库（P0-2）：schema 类明细写 api_schema_violations（request_id 幂等）
		apiCollector.SetViolationSaver(apiRuntimeStore)
		// 风险发现物化（P0-13）：检测明细按 dedup 指纹 upsert 进 api_runtime_findings（风险中心数据源）
		apiCollector.SetFindingSaver(apiRuntimeStore)
		// 参数值脱敏观测聚合（三微模型增强批）：param_observations → api_parameter_value_obs
		apiCollector.SetParamObsRecorder(apiruntime.NewParamObsStore(db))
		// 响应 Schema 学习（P0-06）：response_observations → api_response_schemas（运行时学习行）
		apiCollector.SetRespSchemaRecorder(apiruntime.NewRespSchemaStore(db))
		// 接口访问趋势波形图：端点 × 5 分钟桶全量流量计数（api_endpoint_traffic_buckets）
		apiCollector.SetTrafficRecorder(apiAssetStore)
		// 文件资产观测（P1-04）：file_observations → api_file_assets（去重键 UPSERT）
		apiCollector.SetFileObsRecorder(apiruntime.NewFileObsStore(db))
		// LLM 调用观测（P2-04）：llm_observation → api_llm_observations（request_id 派生幂等）
		apiCollector.SetLLMObsRecorder(apillm.NewObsStore(db))
		// W20 批量化修复：批量/周期 flush 阈值（默认 2000 行 / 2s，深 backlog 下入库滞后与重扫量有界）
		apiCollector.SetFlushPolicy(cfg.WAF.CollectorFlushBatch, cfg.WAF.CollectorFlushInterval)
		// W22 事务批量化：每个 flush 批次一个 DB 事务（副作用 + 主事件整批一次 COMMIT），
		// 消除逐语句 commit 开销（§11.8 入库瓶颈）；失败整体回滚、断点不前移、重放幂等
		apiCollector.SetBatchTxFactory(db.Begin)
		// 节点心跳（W17-HB）：heartbeat 记录仅透传节点活性聚合（不落事件表、不产业务数据），
		// 节点视图 ACTIVE/STALE/SILENT 不再依赖业务流量
		apiCollector.SetHeartbeatRecorder(apinodes.NewStore(db))
		// 强流程事件（NG-FLOW-02）：strong_flow 对象透传落实例/步骤事件表
		// （迁移 000177；表缺失时消费报错仅记日志不阻断采集——同心跳纪律）
		apiCollector.SetStrongFlowRecorder(strongflow.NewStrongFlowEventStore(db))
		// 暴露面来源聚合（迁移 000190）：每条事件按 client_ip 范围（内网/公网/合作方出口）
		// 落自然日计数桶 + 盐化指纹去重明细；partner CIDR 分类在 apiexposure 侧读 settings
		// 缓存完成；fail-open 仅限此聚合（失败记日志不影响主事件链路）
		apiCollector.SetSourceRecorder(apiexposure.NewSourceRecorder(
			apiexposure.NewStore(db), settings.NewService(db)))
		// 离线授权：端点发现配额强制（license 内存状态无 IO；无效授权返回 0=不限制——
		// 无效态下网关透传无 API 事件，管理面已被授权门控锁定，此处不重复强制）
		if licSvc := application.LicenseService(); licSvc != nil {
			apiAssetStore.SetEndpointQuotaProvider(func(context.Context) int64 {
				st := licSvc.State()
				if !st.Valid {
					return 0
				}
				return st.Quotas.MaxAPIEndpoints
			})
		}
		// 端点配额超限告警：接系统告警（同指纹合并/冷却复用引擎机制；detail 不落授权原文）
		if engine := application.AlertEngine(); engine != nil {
			apiCollector.SetQuotaAlertFunc(func(ctx context.Context, endpointKey string) {
				if _, err := engine.NotifyFailure(ctx, systemalerts.TypeLicenseQuotaExceeded, "API_ENDPOINT_DISCOVERY",
					"API 端点配额超限",
					fmt.Sprintf("授权 API 端点配额已达上限，新端点 %s 未落库（已有端点不受影响）", endpointKey)); err != nil {
					slog.Warn("raise license quota alert failed", "error", err)
				}
			})
		}
		go apiCollector.Run(collectorCtx, 2*time.Second)

		// WDSP 阶段A：节点网口清单采集（网关 node-interfaces.jsonl 全量快照，60s 周期重建；
		// 保留用户 sort_order/role，新口排末尾，消失口置 present=false）
		ifaceCollector := nodeinterfaces.NewCollector(nodeinterfaces.NewStore(db),
			"iface-collector-01", cfg.WAF.NodeIfacesLog)
		go ifaceCollector.Run(collectorCtx, 60*time.Second)
		// 学习闭环审计同样纳入 syslog 外发（setter 注入，可为 nil 时跳过）
		learningAuditSvc := audits.NewService(db)
		learningAuditSvc.SetSyslogForwarder(func(severityHint string, payload interface{}) {
			syslogFw.Enqueue(syslogfw.KindOperationAudit, severityHint, payload)
		})
		learningWorker := learningjobs.NewWorker(apiAssetStore, apimodels.NewStore(db),
			learningAuditSvc, settings.NewService(db))
		// 参数统计画像（三微模型 §四.5，第二批）：学习样本离线聚合 →
		// api_parameter_statistics + observed/recommended（幂等可重算，随学习调度周期刷新）
		// 增强批：合并 value_obs 回填长度/值域/基数 + semantic_type 推断 + 关系候选
		modelStore := apimodels.NewStore(db)
		learningWorker.SetProfileRefresher(modelStore)
		learningWorker.SetRelationRefresher(modelStore)
		go learningWorker.Run(collectorCtx)

		// 弱点派生（P0-13）、敏感字段台账回流（P0-19）、对象权属学习（P0-15）与
		// 资产生命周期作业（Zombie 判定/价值评分回填）：周期扫描；失败仅告警，不影响采集主流程
		weaknessSweeper := apiweakness.NewSweeper(db)
		sensitiveStore := apidata.NewStore(db)
		authzModelStore := apiauthz.NewStore(db)
		assetSweeper := apiassets.NewSweeper(apiAssetStore, apiassets.SweepOptions{})
		geoSweeper := apigeo.NewSweeper(apigeo.NewStore(db), application.APIGeoLookup(), settings.NewService(db))
		// 文件风险 v1（§107 子集）：同身份批量下载 → FILE_BULK_DOWNLOAD 风险发现
		fileRiskSweeper := apifiles.NewRiskSweeper(apifiles.NewStore(db), apiruntime.NewStore(db), settings.NewService(db))
		go func() {
			t := time.NewTicker(5 * time.Minute)
			defer t.Stop()
			for {
				select {
				case <-collectorCtx.Done():
					return
				case <-t.C:
					if _, err := weaknessSweeper.SweepOnce(collectorCtx); err != nil {
						slog.Warn("api weakness sweep failed", "error", err)
					}
					// HasMore 时本轮继续排空，避免大数据量下台账长期滞后
					for {
						res, err := sensitiveStore.SweepOnce(collectorCtx)
						if err != nil {
							slog.Warn("api sensitive field sweep failed", "error", err)
							break
						}
						if res == nil || !res.HasMore {
							break
						}
					}
					// 对象模型：端点对象面候选（路径占位段/Query 对象参数形态；HasMore 排空）
					for {
						res, err := authzModelStore.SweepObjectModelsOnce(collectorCtx)
						if err != nil {
							slog.Warn("api object model sweep failed", "error", err)
							break
						}
						if res == nil || !res.HasMore {
							break
						}
					}
					// 资产生命周期：Zombie 判定 + 资产价值评分回填
					if _, err := assetSweeper.SweepOnce(collectorCtx); err != nil {
						slog.Warn("api asset lifecycle sweep failed", "error", err)
					}
					// 数据出境（P1-03）：涉敏事件 client_ip 归属判定（GeoIP 缺失时 nil 降级空转；HasMore 排空）
					for {
						res, err := geoSweeper.SweepOnce(collectorCtx)
						if err != nil {
							slog.Warn("api cross-border sweep failed", "error", err)
							break
						}
						if res == nil || !res.HasMore {
							break
						}
					}
					// 文件风险 v1（§107）：同身份批量下载检测
					if _, err := fileRiskSweeper.SweepOnce(collectorCtx); err != nil {
						slog.Warn("api file risk sweep failed", "error", err)
					}
				}
			}
		}()

		// 暴露面判定引擎（迁移 000190）：10 分钟周期评估（近窗口有流量 + 到期未评端点；
		// 评估明细与来源聚合留存 30 天清理并入本调度；单端点失败隔离不中断批次）
		if exposureSweeper := application.APIExposureSweeper(); exposureSweeper != nil {
			go exposureSweeper.Run(collectorCtx)
		}

		// API 专项指标采集（§158 子集）：采集器在 app 装配（路由挂载点），此处仅启动
		application.StartAPIMetrics(collectorCtx)
	}

	// 阶段6：报告/备份/健康采集/告警评估后台工人
	application.StartStage6Workers(collectorCtx)

	// APM 阶段2 收尾：管理后端自埋点（默认关）。仅包裹管理 API 的 http.Server.Handler，
	// 与网关数据面（Caddy 原生 tracing，GATEWAY_TRACING_ENABLED 下发）相互独立；
	// 关闭时不初始化 exporter、不包裹 Handler——零开销零行为变化。
	var selfTelemetry *apm.SelfTelemetry
	if cfg.APM.SelfTelemetryEnabled {
		selfTelemetry = apm.InitSelfTelemetry(ctx, cfg.APM.OTLPAddr)
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			selfTelemetry.Shutdown(shutdownCtx)
		}()
	}

	handler := application.Handler
	if selfTelemetry != nil {
		handler = selfTelemetry.WrapHTTP(handler)
	}

	srv := &http.Server{
		Addr:         cfg.HTTP.HTTPAddr(),
		Handler:      handler,
		ReadTimeout:  cfg.HTTP.ReadTimeout,
		WriteTimeout: cfg.HTTP.WriteTimeout,
		IdleTimeout:  cfg.HTTP.IdleTimeout,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("jiuzhang api server started", "addr", cfg.HTTP.HTTPAddr(), "env", cfg.Env)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	case sig := <-sigCh:
		slog.Info("shutting down", "signal", sig.String())
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

func runMigrate(ctx context.Context, cfg *config.Config, args []string) error {
	direction := "up"
	if len(args) > 0 {
		direction = args[0]
	}
	db, err := database.Connect(ctx, cfg.DB)
	if err != nil {
		return err
	}
	defer db.Close()
	migrationsDir := os.Getenv("MIGRATIONS_DIR")
	if migrationsDir == "" {
		migrationsDir = "migrations"
	}
	return database.Migrate(ctx, db, migrationsDir, direction)
}

// ensureInitialAdmin 首次启动时创建初始管理员。
// 密码优先级：环境变量注入 > 生成一次性随机密码（仅打印一次到 stdout）。
// 临时密码必须首次登录修改，不写入任何日志文件。
func ensureInitialAdmin(ctx context.Context, db *pgxpool.Pool, cfg *config.Config) error {
	store := users.NewStore(db)
	has, err := store.HasUsers(ctx)
	if err != nil {
		return err
	}
	if has {
		return nil
	}

	username := cfg.Security.InitialAdminUsername
	password := cfg.Security.InitialAdminPassword
	generated := false
	if password == "" {
		password, err = security.GenerateTemporaryPassword(16)
		if err != nil {
			return err
		}
		generated = true
	}
	hash, err := security.HashPassword(password)
	if err != nil {
		return err
	}

	now := time.Now()
	user := &users.User{
		Username:           username,
		DisplayName:        "系统管理员",
		PasswordHash:       hash,
		Status:             users.StatusActive,
		MustChangePassword: true,
		PasswordChangedAt:  &now,
	}
	if err := store.Create(ctx, user); err != nil {
		return err
	}
	roleID, err := store.GetRoleIDByCode(ctx, "SYSTEM_ADMIN")
	if err != nil {
		return err
	}
	if err := store.AssignRole(ctx, user.ID, roleID, user.ID); err != nil {
		return err
	}

	if generated {
		// 仅打印一次到 stdout，不写入日志文件，首次登录必须修改
		fmt.Fprintf(os.Stdout, "\n")
		fmt.Fprintf(os.Stdout, "╔══════════════════════════════════════════════════════════════╗\n")
		fmt.Fprintf(os.Stdout, "║  九章WAF 初始管理员已创建（仅此一次显示，请立即记录）          ║\n")
		fmt.Fprintf(os.Stdout, "╠══════════════════════════════════════════════════════════════╣\n")
		fmt.Fprintf(os.Stdout, "║  用户名: %-51s ║\n", username)
		fmt.Fprintf(os.Stdout, "║  临时密码: %-49s ║\n", password)
		fmt.Fprintf(os.Stdout, "║  首次登录必须修改密码                                          ║\n")
		fmt.Fprintf(os.Stdout, "╚══════════════════════════════════════════════════════════════╝\n\n")
	} else {
		slog.Info("initial admin created from environment variable", "username", username)
	}
	return nil
}
