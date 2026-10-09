# S1 出口门禁自检报告（NG-COV-01～04 + NG-HTTP-01）

> 日期：2026-10-03。依据：docs/nextgen/NG-S1-TASKBOOK.md §7 出口门禁。
> 结论：**S1 主体出口条件满足**（除两项如实标注的后续/环境项：性能门槛需专用环境复测、h2 链路未测）。
> 本报告只登记已执行证据；未执行项一律明示，不折算为通过。

## 1. NG-T-C01～C10 映射证据

| 用例 | 断言 | 证据 |
|---|---|---|
| NG-T-C01 新配置缺省、升级旧配置 | `COVERAGE_OBSERVATIONS_ENABLED` 缺省关闭 → `pipeline.Config.Coverage=nil` 零行为；`TestCoverageEmitterDisabledByDefault`、黄金对照 `TestCoverageGoldenNoBehaviorChange`（同请求接入/不接入 FinalAction 与 Matches 完全一致） | gateway pipeline/guard 测试全绿 |
| NG-T-C02 OBSERVE 命中不阻断 | OBSERVE 模式发布成功且同一请求放行不阻断（=200）；模拟报告 `would_block` 标注模拟语义非已执行 | custom-pack-blocking §5；validations OpenAPI description |
| NG-T-C03 覆盖信号不贡献攻击分 | Observation 独立通道（独立 JSONL/三表），结构上无入分路径（ADR-2）+ 引擎决策只读 Matches（golden 测试证明接入发射器后决策输入不变） | coverage/emitter 设计与黄金对照 |
| NG-T-C04 白名单不绕过既有底线 | 未改动该路径；stage5-gateway-tests 40/40 全过（含白名单/放行出口语义） | 连续两轮 40/40 |
| NG-T-C05 精确例外 | 例外命中保留证据并打标、不升级阻断 | `TestSimulateExceptionHitKeepsEvidence`（validations 8 例） |
| NG-T-C06 五态/零分母/缺节点/队列丢弃一致 | 聚合器 E=0→`NoApplicableTraffic`（纯 NA 桶同语义）；API agg 视图 E=0 行 `no_applicable_traffic=true` 比率 0 不显示 100%；stages 视图 11 阶段保序缺省补零；队列丢弃计数（emitter Dropped / collector delta counters / data_incomplete） | coverage 聚合 6 例、handler 7 例、stage5 实测 stages/agg 双视图 |
| NG-T-C07 模拟零外部调用 | Simulator 空结构体（类型层面无依赖），`TestSimulatorHasNoExternalDependencies` 锁定形状 | validations 测试 |
| NG-T-C08 报告失效/旧节点拒收 | 配置内容变化后报告读出时 STALE（DB 行不回写实测）；能力门三态 fail-closed：CAPABILITY_MISSING（不发送 /load）/ CAPABILITY_MANIFEST_UNAVAILABLE（stale）/ 缺失同码；空需求免门禁（存量发布零变化） | validations stage5 实测、能力门 stage5 三态实测 |
| NG-T-C09 越权/跨应用读取拒绝 | jiuzhang_admin（SYSTEM_ADMIN）对 coverage/validations 一律 403 PERMISSION_DENIED；sec_admin_s5 200；权限点落库（api_protection.read/validate） | stage5 两角色实测 |
| NG-T-C10 上传超大/异常输入有界 | validations 批次>100 → 400；字段超限 400；evidence 原文拒绝；httpchain 4KB 大头一致处理无 5xx | handler 实测、T1-bigheader-consistent |

## 2. 回归结果（2026-10-03 回跑）

| 套件 | 结果 |
|---|---|
| stage5-gateway-tests.sh | **40/40 连续两轮** |
| custom-pack-blocking-tests.sh | **13/13 连续两轮**（本轮修复事件归因取错事件的测试侧抖动：三阻断探针并发采集序下按内容（1001101）定位 SSTI 事件，根治非产品性 flake） |
| server 全量 go test | 94 包 ok（含新增 coverage/validations 20 例、threatintel、license 等） |
| gateway/dynamic_security 全量 | 15 包 ok（coverage/capability/pipeline 新增用例全绿） |
| gateway/modules/jiuzhang_guard 全量 | 17 包 ok（coverage_counters/coverage_out/capability_report 全绿） |
| web Vitest | 127 文件 / 993 用例全过（10-03 登记） |
| OpenAPI 对账 | **675/675 双向零差集** |
| go-ftw v2.4.0（stage5 容器直挂卷路径） | 10006xx 系列通过不回退；1001408~1001417 簇失败已定责为 ftw 用例设计问题（CRS 先行中断期归因，见 NG-BASE-01 §3.1），webshell-content 在 CRS 未中断路径工作正常——不属 S1 回退 |

## 3. 性能门槛（如实标注：未通过环境，不算通过）

候选门槛（RD_PLAN §14.2）：新能力全 OFF 吞吐降 ≤2% / P99 增量 ≤1ms；覆盖开 ≤3%。
实测：stage5（Mac 构建机 + Docker Desktop）在覆盖开/关 A/B 间请求时延波动 ±4 倍（2.7ms~15ms 同状态不稳定），**环境噪声远大于门槛**，且同状态热身后的抽检无稳定可分辨差异。**结论：本环境无法有效判定，必须在固定硬件/受控负载的专用性能环境复测（列入 S8/性能基线项），不以 Mac 结果冒充通过。**
可引用的替代证据：发射器满队列 1s 非阻塞单测、非法记录静默丢弃单测、接入/不接入的黄金对照零差异单测、采集器 2s 批量 flush（2000 行/批）。

## 4. 关键阻断的源站计数证据

- 守恒等式（stage5 实测）：`total=9 = intercepted_waf=6 + reached_upstream=3`（proxyAndCount 精确归因，Coraza 中断不计源站到达）；
- httpchain T1：CL/TE 冲突夹带的 `/v1/admin` 源站计数=0，且同连接后继请求无串扰；
- stage5-gateway-tests `blocked-not-upstream`：阻断响应不含源站标记（REACHED_ORIGIN）。

## 5. 偏差与遗留（全部如实登记）

1. 性能门槛 → 专用环境复测（§3）。
2. h2→h1.1 链路：stage5 网关 h2 支持面未建拓扑，topology.yaml 标 untested（另有 path-rewrite 链待扩）。
3. go-ftw 10014xx 簇 → 用例整改（payload 换「CRS 低分本包命中」或放宽期望），列入 S1 语料扩编。
4. SHADOW/CANARY 灰度生命周期与远端次要节点 manifest 通道 → NG-COV-04 后续批（任务书 §4 已标注边界）。
5. 前端「覆盖与验证」视图 → 后续批（查询 API 已就绪，视图未建不算 S1 主体出口阻塞项——API/数据面已闭环）。
6. 能力清单 h2 层级评估（capability_report 注释在案）。
7. NG-HTTP-02：三条链路无可利用解释差异，按出口判据**保留证据关闭**（HC 语料与 topology.yaml 已归档；唯一登记观察项：发布冒烟墓碑三重判据与「从未启用 Bot 应用命名空间落上游」的设计张力，已在 httpchain 源站同形规避并注释）。

## 6. 交付物索引

- 网关：`gateway/dynamic_security/coverage/`（类型+发射器+FileSink）、`capability/`（Manifest+CheckRequirements）、`pipeline`（3 发射点）、`jiuzhang_guard/`（coverage_counters/coverage_out/capability_report + 15 接线点）
- server：`server/internal/coverage/`（聚合/采集/存储/查询 handler）、`server/internal/validations/`（模拟器/service/handler）、迁移 000168~000170、权限 api_protection.read/validate
- 测试基建：`test/httpchain/`（origin+语料+T0/T1/chains+topology.yaml）
- 文档：docs/nextgen/（BASE-01~04、NG-S1-TASKBOOK、本报告）
