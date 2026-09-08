# APM 业务性能监控排障手册

> 适用：docs/BUSINESS_PERFORMANCE_APM_DESIGN.md 阶段1～阶段4 已落地能力的现场排障。
> 读者：交付工程师、现场运维与二线支持。
> 组织方式：按症状索引，每条给出排查路径（看哪个页面/哪张表/哪个日志/哪个指标）与处置。
> 组件、端口、阈值与告警 SOP 见 docs/APM_OPERATIONS_GUIDE.md；接入步骤见
> docs/APM_ONBOARDING_GUIDE.md；接口契约真源 server/openapi/fragments/12-apm.yaml。

通用原则：

- **遥测故障 fail-open**——APM 链路任何一环故障都不影响 WAF 转发与业务请求；排障时
  不要把遥测组件重启当作业务风险操作，但也不要因页面无数据怀疑业务故障。
- **先分管道再怀疑**：应用级 RED（Caddy access.log 聚合，常开）与端点级数据（guard
  全量访问日志，`logging.access_log_enabled` 控制，默认关）是两条独立管道；ClickHouse
  OTel 数据面是第三条。症状定位第一步永远是确认数据来自哪条管道。
- **降级不报错**：ClickHouse 未配置/不可用时，trace 检索、SQL、异常、依赖、运行时各页
  返回空数据 + 降级提示（`data_source=agentless` + message），不返回 500——空页先看
  降级提示，再查组件。

---

## 1. 看不到数据

### 1.1 「业务性能」菜单不可见 / APM 接口全部 503

排查：

1. 管理后端环境变量 `APM_ENABLED` 是否为 `true`（默认 false；改动需重启管理后端）；
2. 前端能力：`GET /product/edition` 下发的 `apm_enabled` 是否为 true（前端按能力过滤
   菜单与路由）；
3. 当前账号角色/权限：页面角色口径 SECURITY_ADMIN 全量、AUDIT_ADMIN 只读、SYSTEM_ADMIN
   不含业务观测权限；自定义角色需持有 `apm.*` 权限点（如 `apm.traces.read`）。

处置：开启开关并重启管理后端；按角色/权限点授权。

### 1.2 应用级有数据，端点级榜单/列表为空

排查：

1. 「性能总览」「端点性能」页是否显示"端点级数据需开启全量访问日志"提示（接口
   `access_log_enabled=false` 时如实降级）；
2. 「系统设置」`logging.access_log_enabled` 当前值（默认关，不翻转存量部署）。

处置：由系统管理员在「系统设置」logging 组开启全量访问日志；开启前按运维手册 §4.1
复核 `access_logs` 磁盘容量。应用级 RED 不受该开关影响，无需处置。

### 1.3 服务列表全零值、`last_seen_at` 为 null

排查：

1. 时间窗是否正确（缺省最近 1 小时；窗口 ≤6h 读分钟聚合表，否则读小时聚合表）；
2. 窗口内该应用是否确有流量（「访问日志」页或网关侧确认）；
3. 应用级聚合任务是否在运行：「系统运维 → 运行监控」聚合/采集项状态。

处置：无流量属正常（页面如实返回零值）；有流量无聚合时查管理后端聚合任务日志。

### 1.4 trace 检索/瀑布/SQL/异常/依赖/运行时各页为空且提示降级

排查：

1. 页面或响应的 `message` 字段（降级原因）；
2. 管理后端 `APM_CLICKHOUSE_DSN` 是否配置（空 = 纯无 Agent 模式，此为正常形态）；
3. 已配置时：ClickHouse `curl http://127.0.0.1:8123/ping`；DSN 连通性与账号权限
   （查询侧需要 `apm` 库只读权限）。

处置：按提示分别处理——未配置数据面则当前形态正确（属无 Agent 模式能力边界）；已配置
但不可达则恢复 ClickHouse 后刷新，管理面无需重启之外的任何操作。

---

## 2. 数据延迟 / 趋势滞后

排查路径：

1. **分钟聚合节拍**：端点级聚合每分钟重算当前与上一分钟桶，页面趋势天然滞后 1～2 分钟，
   属正常；告警评估窗口整体上移 1 分钟避开在途桶（同理）。
2. **accesslog-01 断点滞后**：「系统运维 → 运行监控」EVENT_COLLECTOR 项（断点名
   `accesslog_full`）；滞后超 120s（默认，`logging.access_log_stale_seconds` 可覆盖）
   判 DEGRADED 并触发 `EVENT_COLLECTOR_LAG`。低流量站点分钟级无日志属正常，不要误判。
3. **ClickHouse 侧固有延迟**：中央 Collector 尾采样 `decision_wait: 10s` + batch
   `timeout: 5s` + 写入重试，trace 入库比请求发生晚十几秒到一分钟属正常。
4. **队列积压放大延迟**：见 §8「Collector 队列积压」。

处置：节拍性延迟无需处置；断点停滞按运维手册 §8.4 SOP 处置。

---

## 3. trace 不完整（检索到但 `partial=true`）

`partial=true` 的三种成因（接口如实标识）：

| 成因 | 确认方式 | 处置 |
|---|---|---|
| 无 OTel span（只有网关侧访问记录） | trace 视图 `data_source=agentless`、`otel_spans` 为空 | 该链路未接 Agent 属预期；需要内部链路时按接入指南部署 Agent |
| 缺根 span | 检索结果 `root_service`/`root_operation` 为空串 | 入口服务未上报 Server span 或已被 TTL 清理；查入口服务 Agent 与采样策略 |
| 超上限截断 | `truncated=true`（单 trace 上限 1000 span） | 属保护性截断；分析时聚焦前段与错误 span，必要时缩小诊断范围提高有效密度 |

另注意**采样丢弃**：中央尾采样保留错误 100%、慢 ≥2s 与 WAF 高风险，正常流量基线 5%——
正常请求在检索中查不到是采样设计行为，不是故障。

## 4. 瀑布缺段（跨服务链路断在某一段）

排查：

1. **下游未部署 Agent**：链路中有服务未插桩时页面如实显示"部分链路"（能力如实降级
   原则），缺口段即未覆盖服务；
2. **traceparent 未传到下游**：当前版本网关默认**不向上游注入** traceparent
   （`trace_inject_upstream` 网关侧已实现，但发布侧恒按 false 下发、管理面取值接线
   待后续工作包）——网关 → 第一个业务服务之间的关联依赖业务侧自行透传或后续接线；
   业务服务之间由 OTel 自动插桩注入/提取 traceparent，自研 HTTP 客户端、消息队列
   不在自动覆盖范围内的需手工埋点；
3. **tracestate 不续传**：网关入口一律丢弃外部 tracestate（跨信任域清理，ADR D5-3），
   依赖 tracestate 的第三方关联会断，属设计行为；
4. **TTL 清理**：原始正常 trace 保留 7 天（错误/慢/高风险 14 天），超期分段被整分区
   删除；
5. **时钟漂移**：span 时间线错乱/倒挂时先按 §10 排查各节点时钟。

处置：确认缺口成因后对症补齐（部署 Agent / 手工埋点 / 等待网关注入接线），不伪装
完整链路。

## 5. 端点未归类 / 出现 `__UNCLASSIFIED__`、`__OTHER__`

含义：

- `__UNCLASSIFIED__`：endpoint_key 缺失治理桶（无法归一化的请求，如空路径）；
- `__OTHER__`：基数护栏合并桶——每应用每分钟桶仅保留请求数 Top-200 端点，其余并入
  该桶。

排查与处置：

1. 「端点性能」页这两个保留桶原样展示并特殊标注；`__UNCLASSIFIED__` 请求数在
   「性能总览」有汇总（`unclassified_requests`）；
2. 未归类高 → 检查该应用路径是否大量非常规（空路径、异常编码）；正常 REST 路径会
   被归一化为 `METHOD /path/{id}` 模板（数字段→`{id}`、UUID→`{uuid}`、长 hex→`{hex}`）；
3. `__OTHER__` 占比高 → 该应用端点基数超 Top-200，评估是否确为大量低流量端点
   （治理问题）还是归一化未覆盖的 ID 形态（反馈归一化规则评审）；
4. 两个保留桶**不参与**端点性能告警评估（不代表单一可处置端点），无需为它们配告警。

## 6. Agent 离线（Agent 管理页状态 OFFLINE）

判定口径：心跳超 `APM_AGENT_OFFLINE_MINUTES`（默认 10 分钟）由查询侧推导为 OFFLINE
（不落库）；REVOKED 不计入在线/总数。**Agent 心跳 ≠ 业务服务健康**，页面分列展示，
先确认业务进程本身是否正常。

排查路径：

1. 业务进程是否存活、Agent 是否随进程启动（Java `-javaagent` 参数、Node `--require`
   是否仍在启动命令中）；
2. Agent → 管理面心跳链路：`POST /api/v1/apm/agent/heartbeat` 的返回码——
   - **401**：证书过期或未登记——证书默认 72h 有效（`APM_AGENT_CERT_TTL_HOURS`），
     检查证书轮换是否执行（`POST /api/v1/apm/agent/rotate-cert`）；
   - **403**：Agent 已被撤销（REVOKED 终态），确认是否人工撤销；
   - PoP 签名头时间戳允许 **±5 分钟**偏差——宿主机时钟漂移超差会导致 401，先校时（§10）；
3. Agent → 本地 Collector → 中央链路：本地 Collector 13133 健康检查与
   `otelcol_exporter_enqueue_failed_spans` 丢弃计数；
4. 管理面不可达时 Agent 按设计继续使用最后一份有效基线策略（fail-open），恢复后
   自动回连，无需重装。

处置：按返回码分别执行证书轮换/重新注册/恢复链路；确认误撤销的需重新注册（撤销
不可逆）。

## 7. 诊断会话不生效

排查路径（按创建到生效的顺序逐环确认）：

1. **创建是否成功**：「诊断中心」会话列表确认状态为 ACTIVE；422 表示被护栏拦截——
   scope 未匹配到在线 Agent / duration>120 分钟 / sampling_rate 越界（function_probe
   ≤0.5，其余 ≤1.0）/ function_probe 未精确指定实例或服务 / kill switch 开启中；
   409 表示同应用已有进行中会话；
2. **kill switch 状态**：列表响应级 `kill_switch_enabled`；开启时全部 ACTIVE 会话
   已被置 KILLED 且新建一律 422；
3. **策略下发节拍**：会话创建即以 `application:<uuid>` 作用域发布更高版本签名诊断
   叠加策略，**匹配 Agent 下次拉取才生效**并置 DIAGNOSING——创建后短时间内数据未变
   属正常节拍；
4. **会话已到期**：默认 15 分钟、最长 120 分钟，到期自动 EXPIRED 并恢复基线；Agent
   失联时也依靠策略信封 `expires_at` 本地自动失效；
5. **能力/语言匹配**：诊断能力白名单 `sql_detail`/`function_probe`/`thread_block`/
   `gc_detail`/`mq_wait`；线程阻塞、函数探针等深度能力依赖语言诊断能力（设计 §8.1
   差异表），页面如实展示探针命中率——函数不可见（编译器内联、异步边界、动态代理）
   属已知限制；
6. **基线恢复未生效**：停止/到期后 Agent 未回基线时，查会话详情 `baseline_restored`
   字段——恢复发布失败由每分钟到期扫描任务对账重试，该字段如实反映当前状态。

处置：护栏类 422 按提示调整参数重新 dry_run；下发节拍等待一个拉取周期；超时未生效
查管理后端诊断任务日志。

## 8. Collector 队列积压

排查路径：

1. 中央 Collector 自监控（`127.0.0.1:8888`）：
   `otelcol_exporter_queue_size`/`otelcol_exporter_enqueue_failed_spans` 持续增长 =
   出口（ClickHouse）跟不上入口；
2. 本地 Collector 自监控（`127.0.0.1:9888`）同名指标增长 = 中央网关不可达或限速；
3. `otelcol_process_memory_rss` 逼近 memory_limiter（中央 2G×75%、本地 512M×70%）=
   内存限幅即将触发丢数据保护；
4. 下游：ClickHouse `/ping`、磁盘水位、`system.mutations` 积压、merge 压力。

处置：

- ClickHouse 故障：恢复存储——中央队列限量缓存 600s（`max_elapsed_time`），超时按
  优先级丢弃并计数（设计行为，不无限堆积）；
- 遥测突增：确认是否诊断会话高采样或新版本发布窗口导致；评估后调尾采样 baseline
  百分比或扩容中央 Collector（tail_sampling 扩容必须前置 trace ID 一致性路由，见
  运维手册 §4.3）；
- **禁止**为消积压改接 file_storage 磁盘无限队列（填满业务主机磁盘是红线）；
- 丢弃量有自监控指标，处置后以 `enqueue_failed` 归零为恢复确认。

## 9. ClickHouse 写入失败

排查路径：

1. ClickHouse 存活：`curl http://127.0.0.1:8123/ping`；
2. 写入账号：`apm_writer` 是否已建并授权（`GRANT INSERT ON apm.otel_traces` +
   阶段3 起 `otel_metrics_*` 五表；建号 SQL 见 deployment/apm/clickhouse/README.md）；
   口令与中央 Collector 环境变量 `CLICKHOUSE_APM_WRITER_*` 一致；
3. schema：`apm` 库表是否齐全（`001_otel_traces.sql`/`002_aggregates.sql`/
   `003_metrics.sql`；Collector 配 `create_schema: false` 不自动建表，缺表即写入失败）；
4. 磁盘与分区：磁盘水位、`system.parts` 活跃分区数、mutation 积压；
5. 中央 Collector 日志（docker logs / journalctl）中 clickhouse exporter 报错原文。

处置：

- 缺表/权限：按 README 手工初始化（DDL 全 `IF NOT EXISTS` 幂等）并授权；
- 磁盘满：按分区紧急清理（`ALTER TABLE apm.otel_traces DROP PARTITION 'YYYY-MM-DD'`）
  或扩容；确认 TTL 分层符合容量规划（运维手册 §5.1）；
- 恢复后确认中央队列丢弃计数停止增长；中断窗口的数据不可回填（超限已丢弃），
  页面如实出现数据空洞。

## 10. 时钟漂移

影响面与排查：

1. **Agent 心跳/策略拉取 401**：PoP 签名头时间戳仅允许 ±5 分钟偏差——Agent 宿主机
   与管理面时钟差超差即认证失败（现象同 §6 的 401 分支）；
2. **瀑布时间线异常**：span 起止时间倒挂、负耗时、缺口位置飘忽，多为各节点时钟
   不一致（瀑布数据为各实例本地时钟打戳，接口不做跨实例校时）；
3. **采集停滞误判**：`lastEvent` 晚于 now（时钟回拨/跨节点时钟差）时停滞按 0 处理，
   不会误报；但时钟跳变会导致趋势桶错位；
4. **SLO/告警窗口**：窗口聚合按服务端时钟，节点间漂移影响趋势对齐。

处置：全部节点（管理面、ClickHouse、中央/本地 Collector、业务宿主机）统一 NTP 校时；
校时后重试失败的心跳/注册；瀑布图在时钟校正前按提示谨慎解读耗时绝对值。

---

## 附：排障证据收集清单（提工单前）

- 页面：相关 APM 页面截图（含降级提示/数据时间列）、「运行监控」EVENT_COLLECTOR 项、
  「系统告警」相关条目；
- 接口：问题接口的完整响应（`message`/`data_source`/`request_id` 字段务必保留）；
- 组件：ClickHouse `/ping`、`system.parts`/`system.mutations` 快照；中央/本地 Collector
  Prometheus 自监控关键指标（accepted/sent/enqueue_failed/memory_rss）；
- 日志：管理后端 APM 模块日志、Collector 日志（distroless 容器用 `docker logs`）、
  Agent 侧应用日志中的 OTel 初始化/导出报错；
- 配置：相关环境变量（`APM_ENABLED`/`APM_CLICKHOUSE_DSN`/阈值组当前值，**脱敏后**提供，
  不含口令与令牌）。

---

Copyright © 聚信得仁
All Rights Reserved.
