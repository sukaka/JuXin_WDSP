# API 行为分析设计（阶段8 / WDSP）

## 一、目的与范围

本文档描述阶段8 行为基线检测能力：进程内滑动窗口基础设施、RATE_SPIKE 突增规则、
同源的 API 写限速信号、`api_behavior_profiles` 表结构，以及单节点限制与后续
Valkey 化的演进方向。

行为检测回答一个问题：**同一身份在同一端点上的调用速率是否显著偏离其自身基线**。
它不依赖任何跨端点、跨身份的全局阈值，基线完全来自该身份-端点维度的历史窗口。

覆盖代码：`gateway/dynamic_security/detectors/window.go`（滑窗与 LRU）、
`gateway/dynamic_security/detectors/behavior.go`（RATE_SPIKE）、
`gateway/dynamic_security/detectors/ratelimit.go`（写限速信号）、
迁移 000018 `api_behavior_profiles`。

## 二、架构与数据流

```text
pipeline.Process
  │  identity = detectors.IdentityKey(r)（凭据指纹优先，IP 回退）
  │  ek = normalizer.EndpointKey(method, rawPath)
  ├─ detectors.CheckBehavior(ctx, identity, ek)        （behavior.go:23）
  │    defaultBehaviorTracker.add(identity|ek)
  │    → 当前窗口计数 + 历史窗口样本
  │    → 超阈值 → behavior.rate_spike（OBSERVE / MEDIUM / +15）
  └─ detectors.CheckAPIWriteRate(ctx, identity, ek, n) （ratelimit.go:33；仅写方法且 API 流量）
       defaultAPIWriteTracker.add(identity|ek)
       → 超 limit → ratelimit.api_write_rate（RATE_LIMIT / HIGH / +30）
  ▼
decision.Decide：OBSERVE → ActionObserve；RATE_LIMIT → ActionRateLimit
```

两个检测器共用同一套 `windowTracker` 基础设施但各自持有独立的包级计数器实例，
键空间互不干扰。

## 三、进程内滑动窗口

### 3.1 窗口结构

`windowTracker`（window.go:72-110）按 `identity|endpoint_key` 键计数：

- **窗口长度**：1 分钟（`windowSize = time.Minute`，window.go:15），
  按 UTC 自然分钟对齐（`now().UTC().Truncate(windowSize)`，window.go:90）；
- **当前窗口**：`windowEntry.windowStart` + `count`（window.go:62-66）；
- **历史归档**：窗口跨越时把上一活跃窗口计数追加进 `history`
  （window.go:98-105），每键最多保留 10 个历史样本
  （`maxHistoryWindows = 10`，window.go:69）；**空窗不补零**——归档的样本即
  活跃窗口，长时间静默不会把基线均值稀释到 0（window.go:86-87 注释）。

### 3.2 LRU 定容

计数器容量有界（window.go:18-59）：

- 标准 `container/list` 实现 LRU，`get`/`set` 命中即 `MoveToFront`；
- 超容量淘汰尾端最久未用键；`behaviorMaxKeys = 10000`（behavior.go:12）、
  `apiWriteMaxKeys = 10000`（ratelimit.go:15）、对象游标同值
  （resource.go:15）；
- 与阶段5 内存计数器同一纪律：防随机键（伪造身份/随机路径）耗尽内存。

### 3.3 单节点语义

代码注释明确的部署语义（window.go:9-12）：状态仅存于本网关进程内存；
多网关部署时各节点独立计数、不共享基线；配置重载不重置计数；进程重启清零。

## 四、RATE_SPIKE 规则

`CheckBehavior`（behavior.go:23-45）在每次请求时执行：

1. `add(identity|endpointKey)` 得当前窗口计数与历史样本副本；
2. `behaviorSpikeThreshold`（behavior.go:48-65）判定：

```text
历史样本 < 5 个窗口              → 不判定（基线不足）
阈值 = max(20, 3 × 历史均值)     （均值为整数除法）
当前窗口计数 ≤ 阈值              → 不命中
否则                            → behavior.rate_spike
```

3. 命中产生 match：`OBSERVE` / `MEDIUM` / ScoreDelta 15，Evidence 含
   `window_count`、`threshold`、`history_windows` 三项。

规则要点：

- **双门槛防冷启动误报**：历史不足 5 个窗口一律不判，新端点/新身份的学习期
  不产生突增告警；
- **绝对下限 20**：低频端点（均值 1-2 次/分）上 5 次请求不构成"突增 3 倍"，
  `max(20, 3×均值)` 避免低基数抖动淹没事件；
- **OBSERVE 不定案**：突增只抬高风险分与事件，阻断由策略与决策引擎决定；
- 对应任务书第四十三章"正式行为基线同样需要确认或明确策略阈值，不能无限
  自适应"——当前实现选择了**显式固定阈值参数**（5 窗 / 3 倍 / 20 次），
  而非自适应放宽。

## 五、同源信号：API 写限速

`CheckAPIWriteRate`（ratelimit.go:33-57）是同一滑窗上的固定阈值规则：
写方法（POST/PUT/PATCH/DELETE）且 API 流量时按 `identity|endpoint` 计数，
当前窗口计数超过 limit（默认 `DefaultAPIWriteRatePerMinute = 60`，
ratelimit.go:14；可经 `pipeline.Config.APIWriteRatePerMinute` 覆盖）→
`ratelimit.api_write_rate`（RATE_LIMIT / HIGH / +30）。决策引擎将 RATE_LIMIT 类
映射为 `ActionRateLimit`（engine.go:60-61,79-80），网关侧返回 429。
它与 RATE_SPIKE 的差异：一个是**固定上限**（防写滥用），一个是**相对基线突增**
（防低速慢扫后的爆发），两者独立判定可叠加。

## 六、api_behavior_profiles 表结构

迁移 000018 第 255-265 行：

| 列 | 说明 |
|----|------|
| `endpoint_id` | 端点，FK 级联删除 |
| `identity_fingerprint` | 身份指纹（空串表示端点级聚合） |
| `window_seconds` | 窗口长度，默认 3600 |
| `request_count` | 窗口内累计请求数 |
| `avg_rate` | 平均速率 |
| `status_code_dist` | 状态码分布（JSONB） |
| `updated_at` | 更新时间 |

约束：`UNIQUE (endpoint_id, identity_fingerprint, window_seconds)`——
端点 × 身份 × 窗口三维聚合，对应任务书第四十三章调用频率、成功失败比
（status_code_dist）等基线的持久化载体。

## 七、关键设计决策

1. **基线相对自身，不设全局阈值**。突增判定只用同身份同端点的历史窗口，
   避免热门端点与冷门端点共用阈值造成的系统性误报。
2. **活跃窗口归档、空窗不补零**。基线反映"活跃时的强度"，低频但规律的调用
   模式不会因静默期被稀释后误判突增。
3. **冷启动免判**。少于 5 个历史窗口不出结论——学习期不产生任何行为告警，
   宁缺毋滥。
4. **定容有界**。所有进程内状态（滑窗、对象游标）一律 LRU 定容，
   恶意构造的随机身份键只能挤占自己的 LRU 槽位。
5. **测试可注入时钟**。`newWindowTracker` 接受 `now` 函数（window.go:78-83），
   窗口跨越与归档逻辑可确定性单测。

## 八、当前实现范围与限制

- **单节点限制（核心限制）**。计数与基线只在单网关进程内存：多节点部署各算各的，
  全局视角的突增可能每节点都不超阈；进程重启基线清零，需重新积累 5 个窗口。
  **演进方向**：将窗口计数与历史样本迁往 Valkey（哈希键 + TTL），复用阶段5
  CC 防护已建立的 Valkey 键纪律（sha256 键、TTL 自动过期、Fail-open/Fail-closed
  策略），实现跨节点共享基线；迁移前 `api_behavior_profiles` 可作为离线聚合的
  落库形态。
- **api_behavior_profiles 仅建表**。无写入方与查询接口；行为基线当前完全是
  网关进程内状态，管理面不可见。
- **仅速率维度**。任务书第四十三章的调用时段、调用顺序、单次对象数量、
  单次数据量、设备地域变化、Token 使用模式均未实现；`status_code_dist`
  列无生产方。
- **业务流程偏离未实现**。任务书第四十四章的候选流程识别、跳步/逆序/重复提交
  检测无对应代码。
- **均值整数化**。历史均值用整数除法（behavior.go:56），小均值场景阈值粒度粗；
  属可接受的简化，参数固化在常量中，未开放配置。
- **身份键质量依赖 IdentityKey**。无凭据流量回退 IP 维度，NAT 后多用户共享
  同一基线；凭据轮换（Token 刷新）会另起基线。

## 九、与任务书对应章节

- 第四十三章（业务行为学习）：调用频率基线与显式阈值的落地；其余维度见第八节；
- 第四十四章（业务流程偏离）：当前未实现；
- 第三十六章（API 维度资源保护）：按身份 × API 的写限速信号；
- 2.4（统一决策）：检测器只 AddMatch；
- 第五十章：`api_behavior_profiles` 表结构。

Copyright © 聚信得仁
All Rights Reserved.
