# API 行为检测分布式状态设计（计数存储抽象与 Valkey 实现）

> 对应补全任务书 §229（`docs/API_MICRO_MODELS.md` §四第 9 项、
> `docs/API_BEHAVIOR_ANALYSIS.md` §八演进方向的落地）。本文以代码为准描述
> 计数接口抽象、Valkey 实现、Fail-open 与发布下发链路；对象枚举共享窗口
> 复用同一套存储与配置，hourHist/UA 族未抽象的限制如实说明（见 §六）。

## 一、目的与范围

行为/环境异常类检测器依赖跨请求计数状态（滑窗、游标、集合、并发数）。阶段8 初版
全部使用进程内内存实现，多网关节点各自计数、存在**计数盲区**。本设计把计数存储
抽象为可插拔接口，默认仍是进程内内存（零行为变化），可按配置注入 Valkey 实现
消除多节点盲区。本文覆盖：

- Store 四接口与默认内存实现（`gateway/dynamic_security/detectors/store.go`）；
- Valkey 实现（`gateway/modules/jiuzhang_guard/behaviorstore/`：Lua/TTL/键纪律）；
- Fail-open 三层与启用方式（`gateway_runtime` 设置经发布下发）；
- 未抽象部分（hourHist/UA 族）与多节点语义。

## 二、Store 接口抽象（detectors/store.go）

核心计数接口对应各类计数形态；**方法不返回错误**——存储实现负责
自身故障策略（Fail-open 时自行降级并告警），检测器不感知后端故障，检测语义不得
因存储故障中断（store.go 接口契约注释）：

| 接口 | 方法 | 服务检测面 |
|---|---|---|
| `WindowStore` | `AddAndCount(key) (count, history []int)` | behavior、apiwrite 及凭据/租户/对象/分组/操作动作等自然分钟窗口（命名空间须隔离） |
| `QuotaStore` | `AddAndCount(key) int` | 身份+端点自然小时/UTC 自然日配额；跨窗重置，不保留历史样本 |
| `ObjectCursorStore` | `Consecutive(key, id) bool` | resource 连续数字 ID 遍历识别（id == prev+1） |
| `ObjectEnumerationStore` | `ObserveObject(key, ref, nextRef) ObjectEnumerationResult` | 可信主体对象集合窗口；ref/nextRef 只接受 HMAC |
| `IPSpreadStore` | `AddDistinct(key, member) int` | 同凭据窗口 distinct IP 指纹集合 |
| `ConcurrencyStore` | `Acquire(key) int` / `Release(key)` / `Current(key) int` | 同凭据 in-flight 并发计数 |

注入与路由：

- `StoreOverrides` 各字段对应独立检测面；**nil 字段 = 该检测面维持进程内默认实现**
  （支持部分注入），WebShell C&C 与流程会话另有专用扩展；
- `pipeline.Config.Stores` 在每次 `Process` 绑定到该请求的 `RequestContext`，Guard
  实例之间不共享配置；配置重载替换实例绑定的注入集合；
- 检测器经 `behaviorCounts` / `apiWriteCounts` / `credentialRateCounts` /
  `tenantRateCounts` / `objectRateCounts` / `groupRateCounts` / `actionRateCounts` /
  `hourlyQuotaCounts` / `dailyQuotaCounts` / `objectConsecutive` /
  `objectEnumerationObserve` / `ipSpreadAdd` / `credentialInflightCurrent` 路由：
  注入优先，包级默认追踪器兜底。

共享窗口常量导出（store.go，供 Valkey 实现对齐同一边界/上限）：
`WindowSize = 1min`（自然分钟对齐）、`MaxHistoryWindows = 10`、
`MaxSpreadIPsPerWindow = 1024`、`DefaultStoreCapacity = 10000`（LRU 定容）。
对象枚举另导出 `ObjectEnumerationWindow = 60s`、最少对象数 8、连续步进 3、
高基数阈值 16 和集合上限 32。小时/日配额由 `NewMemoryQuotaStore` 接收独立窗口参数。

默认内存实现使用 window.go / envanomaly.go / quota.go / store.go 中的包级有界追踪器，
包括行为、写限速、凭据/租户/对象/分组/动作窗口、小时/日配额、对象游标、IP 集合与并发；
单节点限制为进程重启清零、多节点不共享。装配层回退用 `NewMemory*Store` 构造器
（与默认路径同一代码，但为**独立实例**，不回灌包级默认追踪器）。

## 三、Valkey 实现（jiuzhang_guard/behaviorstore）

### 3.1 键纪律（复用阶段5 CC 防护既定纪律）

- 键形：`jiuzhang:guard:api:<命名空间>:<哈希>`；键材料一律经
  `counters.HashParts`（长度前缀分帧的 sha256，截断 32 hex 字符），**禁止拼接原始
  输入**——凭据指纹/API路径/IP 均不落明文键；
- 命名空间隔离（behaviorstore.go）：`behavior` / `apiwrite` / `credrate` / `tenrate` /
  `objrate` / `grouprate` / `actionrate` / `quota_hour` / `quota_day` / `objcur` /
  `objenum` / `ipspread` / `concur`——所有窗口与配额均须隔离命名空间防串计数；
- `ipspread` 键名追加窗口起点（自然分钟对齐），窗口滚动即换新键，旧键 TTL 自动过期；
- `quota_hour/quota_day` 的键哈希材料包含身份+端点及当前自然窗口起点，跨窗使用新键；
- `objenum` 的 Hash 键由主体/应用/接口键材料哈希生成，字段仅为计数元数据和
  HMAC 对象引用；单个 Hash 避免多键槽位和跨键状态不一致；
- 全部键带 TTL 自动过期；`behavior_store_ttl_seconds` 配置值**大于内置下限时生效**，
  否则用下限（`ttlFor`）。

### 3.2 Lua 原子往返与 TTL 下限

每类操作一个 Lua 脚本，单次原子往返完成「计数 + 汇总 + 刷新 TTL」，多节点并发安全：

| 操作 | 脚本要点 | TTL 内置下限 |
|---|---|---|
| 滑窗 `windowAddLua` | hash 键 field=窗口起点秒：`HINCRBY` 当前窗 → `HGETALL` 汇总已完成窗口（升序、封顶 10、淘汰更老 field `HDEL`）→ `PEXPIRE`；空窗不补零（与内存 windowTracker 样本语义一致） | 12 min（10 历史窗 + 当前窗 + 1 窗余量） |
| 小时/日配额 `quotaAddLua` | 当前窗口键 `INCR` → `PEXPIRE`；无历史窗口扫描 | 小时 2 h / 日 48 h |
| 对象游标 `cursorSetLua` | `GET` 旧值 → `SET` 新值 → `PEXPIRE`，返回是否紧邻上一 ID | 1 h（内存实现无时间界仅 LRU，Valkey 侧给保守下限防无限堆积） |
| 对象枚举 `objectEnumerationObserveLua` | 单 Hash 原子重置滚动窗 → 对 HMAC 引用去重（上限 32）→ 请求/连续步进计数 → 每窗首次达阈置位 → `PEXPIRE` | 2 min（60 秒窗口 + 1 窗余量） |
| 跨 IP 集合 `spreadAddLua` | `SCARD` 达上限 1024 不再新增（远超判定阈值 3，不影响结论；防 botnet 泛洪撑爆内存）→ `SADD` → `PEXPIRE` | 2 min（窗口级键） |
| 并发 `concurAcquireLua` / `concurReleaseLua` / `concurCurrentLua` | `INCR` / 读后减 1（下界 0；键不存在视为计数已丢失，不重建）/ 读取（无键=0） | 5 min（同时承担**节点崩溃未释放的脏计数清理**） |

### 3.3 与内存实现的语义对齐

行为/限速窗口边界同为 UTC 自然分钟、历史样本同为「活跃窗口不补零」、IP 集合上限同为 1024、
游标判定同为 `id == prev+1`。对象枚举单独采用首次访问起 60 秒的滚动窗口，
集合上限 32、每窗告警一次，两种存储均遵守相同的达阈与重置语义。
多节点请求的先后顺序由 Valkey 原子操作串行化，节点时钟依赖 NTP 校时。

## 四、Fail-open 三层

1. **装配期**（`apiprotect.go:60` `buildBehaviorStores`）：`behavior_store=valkey`
   但共享引擎无 Valkey 连接（未配置 valkey 地址或 `counter_backend` 非 valkey）→
   Warn 并回退 nil（进程内默认内存），**不阻断启动**；
2. **运行期**（behaviorstore 各方法）：任何 `Eval` 故障（含空返回
   `errEmptyEvalResult`）→ zap Warn（**每分钟节流一条**，防日志洪泛）+ 降级到该
   Store 持有的内存回退实例（`detectors.NewMemory*`，与默认路径同一代码、各自独立
   实例、与主存储共用同一时钟源，测试注入时钟对降级路径同样确定）；
3. **接口契约层**：接口方法不返回错误，检测器永不因存储故障中断；并发计数配对
   韧性——`Acquire` 落 Valkey 而 `Release` 遇故障时，Valkey 侧脏计数由 TTL（5 min
   下限）兜底清理，内存侧对未记账键的 release 为空操作，两侧互不击穿
   （behaviorstore.go:321-322 注释）。

已知代价（如实）：故障期间计数留在内存侧，恢复后 Valkey 侧基线可能滞后且不回灌。
OBSERVE 信号可能降低灵敏度；凭据限速等 RATE_LIMIT 面在故障期可能放宽集群阈值，
不得把 Fail-open 描述成故障期间仍保持精确全局限额。

## 五、默认 memory 与启用方式（gateway_runtime 经发布下发）

- **默认**：`behavior_store` 缺省/`memory` → `StoreOverrides` 为 nil → 全部检测面
  进程内默认内存，零行为变化；
- **启用 Valkey**：管理面系统设置 `gateway_runtime` 组写 `behavior_store=valkey`
  （白名单见 `server/internal/settings/settings.go`；同时配置对应阈值，例如
  `credential_rate_per_minute`）→ **整站发布**时 `guardconfig` 读取该组写入
  GuardConfig（读取失败或取值非法中止发布，不静默回退）→ 网关 `Validate` 校验词表
  （`behavior_store must be memory or valkey`）→ `Provision` 建存储
  → 每次 `Process` 幂等注入生效；
- 前置条件：网关须有 Valkey 连接（复用共享引擎连接，即 `counter_backend=valkey`
  体系）；回滚发布时组内键不进快照语义，按当前设置重放；
- `identity_salt` 属敏感盐值：版本快照脱敏为 `***`，回滚时按当前设置重新注入
  （与 valkey.password 同一纪律）。

## 六、未抽象部分（限制，如实）

以下状态仍为**进程内实现、未纳入 Store 接口**，Valkey 注入与否不影响它们：

- **时段基线** `defaultHourHist`（envanomaly.go）：同凭据 24 小时桶累计，
  进程内 LRU 近似基线；
- **UA 族** `defaultUAFamily`（envanomaly.go）：同凭据最近 UA 族指纹，
  进程内 LRU；
- 后果：多节点下这两条信号（`auth.credential_unusual_hour` /
  `auth.credential_ua_change`）各节点基线独立，且节点重启清零；二者均为
  OBSERVE 级（+10/+15），不单独定案，影响限于信号灵敏度；
- 同凭据并发的**记账埋点**在挂点侧（`serveNext` 入口 +1、检测+下游转发全程结束 -1），
  其计数存储可走 Valkey，但埋点位置本身与存储无关；
- 分页/批量属于单次请求结构边界，不使用跨请求窗口；设备和通用请求成本等其他
  §36 维度不得因上述共享计数接入而被宣称已全覆盖；动作限速支持内置及自定义 ACTION。

## 七、多节点语义

- **Valkey 模式**：键材料不含节点标识，全部网关节点共享同一计数空间——行为基线、
  写限速、凭据/可信租户/对象/接口组/操作动作每分钟窗口、小时/日配额、对象游标、
  对象枚举、跨 IP 集合、并发计数均为**集群级视图**；行为/限速窗口按 UTC 自然分钟对齐，
  配额按自然小时/UTC 自然日，对象枚举为首次访问起 60 秒滚动窗口；节点时钟依赖 NTP 校时。
  租户只使用 JWT VERIFIED 声明的加盐指纹，动作/接口组只消费发布的真实分类与成员映射；
- **memory 模式（默认）**：各节点独立计数、不共享基线；配置重载不重置，进程重启
  清零；多节点部署下限速阈值实际为「每节点阈值」，基线各建各的；
- **故障切换期**：Valkey 故障时各节点退回本地内存计数，彼此与恢复后的 Valkey 基线
  均可能不一致（§四已知代价）；故障期并发计数以本地为准，恢复后 Valkey 侧脏数据
  由 TTL 自清；
- **切换语义**：`behavior_store` 切换经发布生效，Guard 实例绑定的注入集合随配置替换；
  切换不清空任一后端的历史计数（内存包级追踪器与 Valkey 键各自保留），
  即从 memory 切 valkey 后基线从零开始积累（12 min 内窗口键即覆盖一个样本周期）。

## 八、测试证据

- `dynamic_security/detectors/store_test.go`、`quota_store_test.go`、`tenant_rate_store_test.go`、
  `group_rate_test.go` 与 `action_rate_test.go`：窗口/配额接口路由、默认回退及证据脱敏；
- `dynamic_security/pipeline/pipeline_store_test.go`、`pipeline_action_rate_test.go` 与
  `pipeline_group_rate_test.go`：Process 幂等注入、各窗口/配额路由、真实映射消费与隔离；
- `jiuzhang_guard/behaviorstore/behaviorstore_test.go`：Lua 语义（窗口汇总/游标/
  集合上限/并发下界）、TTL 下限与配置覆盖、键哈希不落明文、Fail-open 降级与
  Warn 节流、Release 配对韧性；
- `credential_rate_store_test.go`、`tenant_rate_store_test.go`、`object_rate_store_test.go`、
  `group_rate_store_test.go`、`action_rate_store_test.go` 与 `quota_store_test.go`：
  各独立命名空间、跨 Store 计数、窗口重置、TTL、键脱敏、独立内存降级与恢复不回灌；
  相关 `-race` 回归通过；
- `apicredentialrate_test.go`、`apitenant_rate_store_test.go`、`apiobjectrate_store_test.go`、
  `apigrouprate_test.go`、`apiactionrate_test.go` 与 `apiquota_store_test.go`：
  两个 Guard 共享存储时跨实例累计达阈，独立内存不共享，PROTECT/OBSERVE 语义保持；
  覆盖身份/租户/端点/对象/接口组/动作隔离；
- `credential_rate_integration_test.go`、`tenant_rate_integration_test.go`、
  `object_rate_integration_test.go`、`group_rate_integration_test.go`、
  `action_rate_integration_test.go` 与 `quota_integration_test.go` 已覆盖真实 Valkey
  双客户端及窗口/配额原子计数；本轮因 Docker daemon 不可用而 SKIP，未实际执行；
- `object_enumeration_integration_test.go` 的历史验证不代表正式多主机故障演练、
  端到端吞吐或海量数据容量验收。
