# API 安全性能基线实测（W18-PERF，任务书 §202-203 最小矩阵尝试）

> 实测日期：2026-08-20（UTC 01:15-01:25）。本文所有数字均为真实测量输出，无编造、无目标值冒充结果。
> 复跑入口：`bash test/performance/w18-performance-baseline.sh`（结果落 `test/performance/w18-performance-baseline-result.txt`）。
> 扩展矩阵（§202 四臂，2026-08-20 UTC 02:11-02:22）见 §10，复跑入口：`bash test/performance/w18-performance-matrix.sh`。
> 追补矩阵（WAF Only / Multipart / 高并发观察，2026-08-20 UTC 02:51-03:36）见 §11，复跑入口：`bash test/performance/w18-performance-matrix2.sh`（multipart 修正补测 `w18-performance-matrix2b.sh`）。

## 1. 概要

在共享 stage5 编排（`deployment/docker-compose.stage5.yml` + `docker-compose.wdsp.yml`）上完成最小性能矩阵两档实测，**两臂打同一 URL、变量只有 API 动态防护开关**：

| 档位 | 定义 | QPS | P50 | P95 | P99 | max | 失败 |
|------|------|-----|-----|-----|-----|-----|------|
| Baseline Proxy | `api_dynamic_protection=false`（发布配置与纯 WAF 一致，网关 `serveNext` 直接放行，不进 API 管线） | **5337.35** | 3ms | 9ms | 17ms | 75ms | 0/160150 |
| Full API Security | wdsp 形态 + 策略 OBSERVE（解析→分类→归一化→全检测器→事件输出→采集入库全链路） | **3539.67** | 4ms | 13ms | 24ms | 1211ms | 0/106225 |
| 差值 | API 动态防护开销 | **-33.7% QPS** | +1ms | **+4ms（+44%）** | +7ms | — | — |

事件正确性校验：Baseline 臂 16 万请求产事件 **0** 条（证明真绕过管线）；Full 臂网关产出事件日志 **114651** 条，采集器最终 **全部入库、零丢失**（追平约 6.5 分钟，见 §5）。

## 2. 测试环境

| 项目 | 值 |
|------|-----|
| 主机 | macOS 26.2（25C56），Apple M1 Pro 10 核 / 16 GiB |
| 容器平台 | Docker Desktop 4.43.1（linux/arm64 VM：10 vCPU / 7.65 GiB），compose v2.38.1 |
| 压测工具 | ApacheBench 2.3（macOS 系统自带 `/usr/sbin/ab`，未安装任何新工具） |
| 管理后端镜像 | `jiuzhang-server:stage5` sha256:edec8af1d0ad（2026-08-19T05:46Z 构建） |
| 网关镜像 | `jiuzhang-gateway:stage5` sha256:145e27c98420（**本次实测前由工作树重建**，见 §7.2） |
| 源站镜像 | `jiuzhang-testorigin:stage1`（2026-08-15T16:22Z 构建） |
| 数据组件 | postgres:16.4-alpine（digest 锁定）、valkey:8.1.8-alpine（digest 锁定） |
| 应用/策略 | 应用 `s5app` protection_mode=OFF（Coraza 不干扰计时）；API 安全策略 OBSERVE（db 来源，全程未改动） |
| 拓扑 | 宿主 ab → 127.0.0.1:18080（gateway 发布端口）→ 内部网络 → testorigin:8081；管理面 127.0.0.1:18081 |
| 负载特征 | 本机为共享开发机，同机另有 20+ 容器（含其他项目）；压测窗口外网关空闲 CPU <2% |

注意：Docker Desktop 下宿主打包流量需穿越 VM 端口发布路径，绝对延迟高于裸金属；两臂同路径测量，**档间差值可信，绝对值仅供参考**。

## 3. 测试方法

### 3.1 档位实现（先读后改的关键结论）

- 策略 `mode=OFF` **不能**充当基线：OFF 只在 decision 层强制 ALLOW，解析/分类/检测器照样全跑（`gateway/dynamic_security/decision/engine.go:36`）。
- 真基线只有 `api_dynamic_protection=false`：该开关由管理后端 `API_DYNAMIC_PROTECTION_ENABLED` 环境变量决定（`server/internal/guardconfig/provider.go:353-355`，关闭时发布 JSON 与纯 WAF 完全一致），无运行期开关。因此 Baseline 臂通过「不带 wdsp 覆盖重建 api 容器 + 重新发布」实现，测完立即恢复（脚本含 EXIT trap 兜底恢复）。
- 档位生效双侧校验：①容器环境变量断言（`API_DYNAMIC_PROTECTION_ENABLED=false/true`）；②行为断言——Baseline 臂前缀事件数必须为 0、Full 臂计量前 20 个探针请求必须产出主事件（`resource.unauthenticated_object_access`，无凭据+数字对象段命中）。

### 3.2 流量参数

| 参数 | 值 | 理由 |
|------|-----|------|
| URL | 每臂单一 `GET /v1/<run>-{base,full}/1`（Host: waf-s5.local） | 两臂同 URL 集，排除路径差异；数字段归一化命中 `{id}` 模板 |
| 方法 | GET（读方法） | 写方法有 60/min/API进程内限速会 429 污染采样 |
| 源站响应 | 404 / 19 字节固定体（testorigin 未知路径） | 开销集中在网关管线而非源站渲染 |
| 并发 / 时长 | 20 并发 × 30s 计量，5s 预热丢弃 | 适度并发（共享开发机）；预热消除首连/懒初始化/重载抖动 |
| 连接 | `ab -k` 长连接 | 避免 macOS ephemeral 端口（~1.6 万）在短连接高 QPS 下耗尽；两臂一致可比 |
| 资源采集 | 压测窗口内 `docker stats --no-stream` 约 2s 周期采样 gateway/api/postgres/valkey | 与计量窗对齐 |

## 4. 实测结果

### 4.1 吞吐与延迟（ab 原文见附录 A）

| 指标 | Baseline Proxy | Full API Security | 差值 |
|------|---------------|-------------------|------|
| Complete requests | 160150 | 106225 | -33.7% |
| Failed requests | 0 | 0 | — |
| Non-2xx（预期内 404） | 160150 | 106225 | — |
| QPS（req/s） | 5337.35 | 3539.67 | **-33.7%** |
| 平均延迟 | 3.747ms | 5.650ms | +1.90ms |
| P50 | 3ms | 4ms | +1ms |
| P90 | 7ms | 10ms | +3ms |
| P95 | 9ms | 13ms | **+4ms（+44%）** |
| P98 | 13ms | 19ms | +6ms |
| P99 | 17ms | 24ms | +7ms |
| max | 75ms | 1211ms | 单发离群，见下注 |

注：Full 臂最长单发 1211ms 为孤立离群点（P99 仅 24ms，98 分位外尾部极薄），疑似 Docker VM 调度/GC 停顿，未复现于 P99 以内；如实保留。

### 4.2 资源消耗（压测窗口 docker stats 采样均值/峰值）

| 容器 | 指标 | 空闲 | Baseline | Full |
|------|------|------|----------|------|
| gateway | CPU 均值（峰值） | 0.86%（1.57%） | 198.22%（314.22%） | **288.53%（372.32%）** |
| gateway | 内存峰值 | 131.9MiB | 176.5MiB | 204.5MiB |
| api | CPU 均值（峰值） | 0.87%（1.68%） | 51.42%（64.10%） | 61.42%（92.55%） |
| api | 内存峰值 | 201.7MiB | 126.8MiB | 92.2MiB |
| postgres | CPU 均值（峰值） | 0.23%（0.27%） | 41.47%（68.74%） | **62.05%（68.35%）** |
| postgres | 内存峰值 | 166.4MiB | 144.4MiB | 157.0MiB |
| valkey | CPU 均值（峰值） | 0.43%（0.52%） | 1.89%（13.75%） | 1.16%（3.36%） |
| valkey | 内存峰值 | 13.5MiB | 13.2MiB | 13.2MiB |

（VM 总额 10 vCPU=1000%；空闲行采样仅 2 点，参考意义有限。Baseline 臂 postgres CPU 主要来自访问日志/CC 等既有采集；Full 臂增量主要来自 API 事件采集入库。）

## 5. 采集吞吐观察（任务书 §55「采集吞吐」大尺度补充）

- Full 臂 30s 计量 + 5s 预热 + 20 探针共 114626 个可归因请求，网关产出事件日志 **114651** 条（request_id 全唯一；残余 25 条 0.02% 未逐条归因，疑为预热/重试边缘请求）；探测器构成抽样 6000 条全部为 `resource_access`、final_action=OBSERVE。
- 采集器（2s 周期、断点续传、逐条 UPSERT + 每记录API发现/流量桶/样本/违例/Finding/参数·响应·文件观测等副作用）在事件洪峰下**入库速率显著低于网关产出速率**：计量结束后约 4 分钟入库仅 20 条，随后单事务长 flush 追平，至 T+约 6.5 分钟 **114651/114651 全部入库、零丢失**（实测 60s 窗口增量 71697 条）。
- 结论：本尺度下事件**不丢**，但持续 3.5k 事件/s 的流量会使采集 backlog 持续增长；阶段8 既有判据（200 事件 15s 内可检索 ≥180）在小尺度通过（见 `stage8-performance-result.txt`），十万级尺度入库时延分钟级——此为后续采集器批量化的真实依据。

## 6. 与既有 harness/结果的关系

- 复用资产：`test/waf/scripts/stage5-setup.sh`（登录/应用/发布工具）、stage5+wdsp 编排、stage8 的唯一前缀防串扰与读方法采样约定。
- 新增：`test/performance/w18-performance-baseline.sh`（两档矩阵、dry-run 预检、EXIT trap 恢复、资源采样、事件双侧校验）；`test/performance/w18-performance-matrix.sh`（§202 扩展四臂，见 §10）。
- stage8（2026-07-23，curl 顺序采样 c=10/n=200）：API 臂 p95=4.3ms vs Web 臂 p95=5.2ms——方法学不同（小样本、异路径、无持续压力），量级与本文一致，不可直接对比。
- 本文相对 stage8 的增量：QPS/P50/P99/max、资源消耗、十万级事件入库追踪、同 URL 两臂严格对照。

## 7. 过程发现（harness 缺口与事故，全部已修复并固化进脚本）

### 7.1 compose 重建 api 会连带重建数据容器（端口覆盖缺失）

`docker compose up -d api` 会按 compose 文件调和依赖链：运行中的 stage5 栈为避让本机其他项目使用非默认宿主端口（postgres 15432 / valkey 16379 / ollama 21434，经命令行环境注入），不带同名端口覆盖执行 compose 会把 postgres/valkey 按默认端口重建并在 5432 被占处失败（本分片首次执行触发，已当场用原端口覆盖恢复，数据卷无损、登录与策略验证完好）。**脚本对策**：导出 `POSTGRES_PORT/VALKEY_PORT/OLLAMA_PORT` 覆盖 + `up -d --no-deps api`（只动 api）+ 每次翻转前 `--dry-run` 预检（非 api 容器出现 Recreate 即中止）。

### 7.2 共享环境 api/gateway 镜像漂移导致 wdsp 发布全线 400（本次实测前已存在）

实测前环境 api 镜像（2026-08-19 构建）发布配置含 `api_scan_verification` 段，而 gateway 镜像（2026-08-18 构建）的 guard 模块尚无该字段——Caddy 拒载：`json: unknown field "api_scan_verification"`，**任何 wdsp 发布必败**（Baseline 臂的纯 WAF 发布因不含 api_* 字段而幸免）。该漂移在本次实测前即存在于共享环境（最后一版 gateway 容器已运行 45h）。**处置**：由当前工作树重建 `jiuzhang-gateway:stage5` 镜像并重建网关容器后发布恢复（PUBLISH_OK）；两臂最终在同一 gateway 构建上测量（重建前的 Baseline 预跑数据 QPS 2409.69 已作废，不混入矩阵）。给集成方提示：凡在该环境做 wdsp 发布的分片，须先确认 api/gateway 镜像同代。

### 7.3 管线活性探针的路径形态假阴性

初版探针用 `/v1/<pfx>/probeN`（字母数字混排段）——不归一化为 `{id}`、无对象标识、不产 `resource_access` 事件，探针误报「管线无事件」。修正为数字段 `/0`（与计量 URL 同模板），手动验证 3 请求 → 3 事件后方才计量。该经验已写入脚本注释。

## 8. 局限与 §202-203 全矩阵残余缺口

本次为最小矩阵（任务边界）。以下清单经 2026-08-20 扩展矩阵（§10）与追补矩阵（§11）两次修订，已测项标注划掉：

- 档位不全：~~PROTECT 模式档~~（§10.1-10.2 已测：敏感 query 触发 `sensitive.in_query` BLOCK，真实 403 阻断路径）；~~WAF Only~~（§11.1-11.2 已测：应用 protection_mode=OBSERVE → SecRuleEngine DetectionOnly 全量 CRS PL1 评估，wdsp off）；Schema 检测/响应检测**单独分档在当前架构不可实现**——检测器无独立运行期开关，管线整体执行（§10.6 诚实声明），只能以「有无触发形态」对比近似（§10.2 body/阻断两臂即此方法）；
- 流量形态单一：~~大 JSON 体~~（§10.1 已测 64KiB vs 1KiB POST；~1MB 由 stage8 覆盖 p95<2s）；~~Multipart/文件上传~~（§11.1 已测：512KiB 全管线 + /upload 源站消费形态 512KiB vs 1MiB 对比；**1MiB + API 分类 + 源站消费三者兼具的形态在当前拓扑不可测**，根因见 §11.6）；深嵌套、大数组、多API（10 万级API、百万级参数模型）与版本对比/图谱查询性能仍未覆盖；
- 并发/时长适度（20×30s）：~~高并发观察~~（§11.1 已测 c=100×15s 短促臂：零失败、p99 212ms、吞吐饱和拐点）；高并发压垮曲线与长时稳定性仍未做（共享环境不宜长时间高压）；
- 环境噪声：共享开发机 + Docker Desktop VM 路径，绝对值不可外推生产（§10 run 与采集器追平窗口重叠、§11 run 与采集器全量重扫重叠，均为噪声影响的现场实例）；
- 采集器入库速率（§5）仅在单 run 观察，未做独立标定（§10.3 再次现场复现 backlog 低报现象，佐证 §5 结论）；§11.8 进一步发现**断点仅在 flush 落盘 + flush 仅在读到 EOF 触发 + api 容器重建重置扫描**三者叠加，深 backlog 下入库可冻结数十分钟（现场实例：计数 709297 在 03:13-03:45 观察窗口全程冻结，当前采集器运行 ≥50 分钟未提交主事件批次），此为采集器批量化与断点粒度改造的直接依据。

## 9. 附录

### 附录 A：ab 原始输出（关键行）

Baseline Proxy（`ab -k -r -c 20 -t 30`，URL `/v1/w18p1787188546-base/1`）：

```text
Concurrency Level:      20
Time taken for tests:   30.006 seconds
Complete requests:      160150
Failed requests:        0
Non-2xx responses:      160150
Keep-Alive requests:    160150
Requests per second:    5337.35 [#/sec] (mean)
Time per request:       3.747 [ms] (mean)
Connection Times (ms)   min  mean[+/-sd] median   max
Total:                    1    4   3.2      3      75
Percentage of the requests served within a certain time (ms)
  50% 3   66% 4   75% 4   80% 5   90% 7   95% 9   98% 13   99% 17   100% 75 (longest request)
```

Full API Security（URL `/v1/w18p1787188546-full/1`）：

```text
Concurrency Level:      20
Time taken for tests:   30.010 seconds
Complete requests:      106225
Failed requests:        0
Non-2xx responses:      106225
Keep-Alive requests:    106225
Requests per second:    3539.67 [#/sec] (mean)
Time per request:       5.650 [ms] (mean)
Connection Times (ms)   min  mean[+/-sd] median   max
Total:                    1    6  17.2      4    1211
Percentage of the requests served within a certain time (ms)
  50% 4   66% 5   75% 6   80% 7   90% 10   95% 13   98% 19   99% 24   100% 1211 (longest request)
```

### 附录 B：原始数据位置

- 汇总报告：`test/performance/w18-performance-baseline-result.txt`
- ab 原文与 docker stats 采样：`/tmp/w18-perf-1787188546/`（`baseline-ab.txt`、`full-ab.txt`、`*-stats.txt`、compose 日志；/tmp 为易失目录，关键数字已落入本文与结果文件）
- 事件计数复核：`GET /api/v1/api-security/runtime/events?endpoint_key=GET /v1/w18p1787188546-full/{id}` → 114651；`...-base/{id}` → 0

## 10. §202 扩展矩阵实测（四臂扩展，2026-08-20 UTC 02:11-02:22）

> 复跑入口：`bash test/performance/w18-performance-matrix.sh`（结果落 `test/performance/w18-performance-matrix-result.txt`，原始数据 `/tmp/w18-matrix-1787191902/`）。
> 口径与 W18 最小矩阵完全一致（c=20 × 30s 计量 + 5s 预热、`ab -k`、同机同栈同镜像 api sha256:edec8af1d0ad / gateway sha256:145e27c98420），两臂基线复测用于跨 run 对照。

### 10.1 概要

在 W18 两档基础上扩展为四臂六测量，**全部真实实测，零失败请求**：

| 测量 | 定义 | 完整请求 | QPS | 平均 | P50 | P95 | P99 | max |
|------|------|---------|-----|------|-----|-----|-----|-----|
| baseline | `api_dynamic_protection=false`（同 W18 臂1） | 165004 | **5498.58** | 3.64ms | 3 | 9 | 15 | 48 |
| observe | wdsp + OBSERVE，GET 透传（同 W18 臂2） | 96336 | **3211.02** | 6.23ms | 4 | 14 | 25 | 2019 |
| protect-block | wdsp + **PROTECT**，GET 带敏感 query 键名 → 真实 403 阻断 | 132168 | **4405.18** | 4.54ms | 3 | 10 | 18 | 1511 |
| protect-pass | wdsp + PROTECT，干净 GET 透传（子测量） | 82577 | **2751.73** | 7.27ms | 5 | 17 | 35 | 1229 |
| body-1k | wdsp + OBSERVE，POST 1KiB JSON | 93983 | **3132.52** | 6.39ms | 5 | 13 | 22 | 1189 |
| body-64k | wdsp + OBSERVE，POST 64KiB JSON | 28825 | **960.73** | 20.82ms | 17 | 41 | 81 | 588 |

核心结论：

- **真实阻断路径开销为负**：protect-block 比 protect-pass 快 60.1%（4405 vs 2752 QPS，P95 10ms vs 17ms）——PROTECT 下命中 BLOCK 的请求在决策后 403 短路，省去源站往返；管线解析/检测成本两者相同。即「开启阻断」本身不增加时延，反而因拦截流量不再转发而降低网关负载。
- **大 body 成本显著**：64KiB JSON 比 1KiB 慢 69.3% QPS（960.73 vs 3132.52），P95 13→41ms；均摊每请求 +14.4ms/63KiB ≈ 0.22µs/字节（含 Docker VM 端口发布路径传输 + 解析/字段遍历），960 QPS × 64KiB ≈ 入向 60MB/s。
- **baseline/observe 复测与 W18 同量级**：baseline 5498.58 vs W18 5337.35（+3.0%）；observe 3211.02 vs W18 3539.67（-9.3%）——方向一致，差异归因见 §10.5 噪声分析。

### 10.2 档位实现（先读后改结论的扩展）

- **PROTECT 切换**：`PUT /api/v1/api-security/policy {mode:"PROTECT"}`（settings 表 `api_protection.mode` db 覆盖）+ 发布下发 `api_protection_mode`；测完同路径回 OBSERVE。全程经管理面 API，无直接改库（settings 行版本 26→30 的变迁即本矩阵两次 PUT + trap 恢复的记录）。
- **真实 BLOCK 触发形态**：静态 URL 可复现的 BLOCK 类匹配只有 `sensitive.in_query`（query 键名命中内置敏感词表 → BLOCK/HIGH，`gateway/dynamic_security/detectors/sensitive.go:151-163`）；`resource.unauthenticated_object_access` 读方法仅 OBSERVE/MEDIUM，写方法+连续数字 ID 才升 BLOCK（`detectors/resource.go:234-244`），ab 固定 URL 无法构造。故 protect-block 臂用 `GET /v1/<run>-prot/1?password=perfprobe`。臂前行为断言：PROTECT 下该 URL 必须 403、干净 URL 必须 404（均实测通过）。
- **大 body 臂前置**：写方法有 60/min/API进程内限速且 OBSERVE 模式也定案 429（`decision/engine.go:83`，已实测：70×POST → 60×404+10×429），不提升限速无法计量。经 `system_settings` 注入 `gateway_runtime/api_write_rate_per_minute="200000000"`（仅此一行，发布通道随 `SetGatewayRuntimeSettingsLoader` 下发，`server/internal/app/app.go:256-275`），测完删除同一行并再发布；臂前 100×POST 探针全 404 无 429 才计量。GET/HEAD 不解析体（`parser/parse.go:114`），无法用 GET 绕过。
- **body 规格**：合法 JSON `{"order_id":12345,"channel":"perf","note":"x…"}` 填充至 1024/65536 字节整（字段数 3，长字符串；`max_body_parse_bytes=1MiB` 完整解析不截断，`MaxFieldCount=2048` 远未触及）。

### 10.3 事件计数校验（网关侧精确 + 入库侧参考）

网关事件日志（`/var/log/caddy/api-runtime-events.log`，每请求一行）按 run 前缀精确计数：

| 臂 | 网关侧事件数 | 下限（计量+探针） | 判定 |
|----|------------|------------------|------|
| baseline | **0** | 0 | ✓ 真绕过管线 |
| observe | 104345 | ≥96356 | ✓（含预热+20 探针） |
| protect-block（`final_action:"BLOCK"`） | 143434 | ≥132188 | ✓ 阻断事件全量产出 |
| protect-pass | 89471 | ≥82578 | ✓ 透传也产 OBSERVE 事件 |
| body | 134611 | ≥122908 | ✓（含 100 探针） |

入库侧 60s 窗口计数（参考）：observe=20、protect BLOCK=0、body=0、baseline=0——采集器当时仍在追平前两轮 ~40 万事件 backlog（§10.5），入库计数严重滞后，与 W18 §5「事件不丢但入库时延分钟级」结论一致；本矩阵故以网关侧日志为事件校验主口径（见 §10.8 过程发现 2）。

### 10.4 资源消耗（压测窗口 docker stats 采样均值/峰值）

| 容器 | 指标 | idle* | baseline | observe | protect-block | protect-pass | body-1k | body-64k |
|------|------|-------|----------|---------|---------------|--------------|---------|----------|
| gateway | CPU 均值%（峰值） | 32.74（65.27） | 223.92（301.73） | 209.45（287.21） | 228.42（318.09） | 217.29（322.22） | 226.96（336.81） | 247.21（347.78） |
| gateway | 内存峰值 MiB | 166.9 | 220.8 | 250.1 | 373.6 | 432.8 | 434.2 | 470.5 |
| api | CPU 均值%（峰值） | 2.10（2.92） | 53.23（64.69） | 43.68（63.95） | 58.08（62.86） | 57.21（104.52） | 54.62（71.66） | 37.18（60.35） |
| postgres | CPU 均值%（峰值） | 85.89（169.84） | 39.13（45.29） | 99.40（252.09） | 124.39（475.19） | 91.81（182.70） | 67.47（78.74） | 37.85（61.43） |
| valkey | CPU 均值%（峰值） | 0.38（0.39） | 0.40（0.58） | 0.35（0.57） | 0.37（0.48） | 3.31（24.16） | 0.42（0.87） | 1.72（6.03） |

*idle 采样时采集器正在追平前两轮事件风暴，postgres 基线偏高（对比 W18 idle：postgres 0.23%）——本轮所有臂都在「采集器后台追平」噪声下进行，这是 observe/protect-pass 偏慢的主要环境因素（§10.5）。valkey 内存全线 13.2-13.7MiB，无压力。

### 10.5 分析

- **observe 比 W18 慢 9.3%（3211 vs 3540 QPS）**：本轮测量与采集器追平窗口重叠（前两轮 run 产生 ~40 万事件，采集器以数百~千余条/s 入库），postgres CPU 均值在 observe 臂达 99.40%（W18 full 臂为 62.05%），管理面与网关同机竞争 CPU。两臂同条件测量，档间差值仍有效，但本 run 的 observe 开销差值（-41.6%）相对 W18（-33.7%）偏大即此噪声所致；**采纳 W18 的 -33.7% 为管线开销主参考，本轮为噪声上界**。
- **protect-pass 比 observe 慢 14.3%（2752 vs 3211 QPS）**：PROTECT 与 OBSERVE 的管线工作完全相同，差异仅在 decision 末段分支（`decision/engine.go:84-87`，ns 级），理论上应无差。实测差值判读为噪声为主（protect-pass 臂 gateway/api/valkey 采样均高于 observe 臂——valkey 峰值 24.16% vs 0.57%、api 峰值 104.52% vs 63.95%；唯 postgres 峰值 182.70% 反低于 observe 臂 252.09%，噪声方向不完全一致），但不排除 PROTECT 下事件字段/动作映射的微小差异；标注为**未完全归因，需噪声更低时复测标定**，不作为 PROTECT 模式开销结论。
- **protect-block 最快于全管线臂（4405 QPS）**：阻断请求 403 短路（`apiprotect.go` 返回 HandlerError 403，事件照常产出），不经 reverse_proxy；在源站 404 也要一次内部往返的拓扑下，短路净省 ~2.7ms/请求（protect-pass 7.27ms vs protect-block 4.54ms 平均）。意义：**PROTECT 模式下被拦流量的网关成本低于透传流量**，「开阻断会更慢」不成立。
- **body-64k 网关 CPU 最高（均值 247.21%）而 QPS 最低**：单请求成本随体长近线性增长（传输+读体+JSON 字段遍历+标量留存），网关进程是瓶颈；api/postgres CPU 反而随 QPS 下降而下降（事件速率降低）。
- **max 离群**：observe 2019ms / protect-block 1511ms / body-1k 1189ms 均为孤立单发（各臂 P99 ≤ 81ms），与 W18 同款 Docker VM 调度/GC 停顿特征，如实保留。

### 10.6 §202 矩阵覆盖度与不可分档声明（诚实边界）

§202 要求的 WAF Only / API Discovery / Schema / Auth / AuthZ / Response Parse / Sensitive / Behavior 分档中：

- **已覆盖**：Baseline Proxy（wdsp off）、Full OBSERVE、Full PROTECT（真实阻断）、大 body（64KiB vs 1KiB）；事件风暴对转发的影响引用 W18 §5 与 §10.3（3.5k 事件/s 持续产出下转发零失败，采集 backlog 增长但不丢）。
- **架构上不可单独分档**：API Discovery/Schema/Auth/AuthZ/Response Parse/Sensitive Data/Behavior 各检测器**无独立运行期开关**——管线 `pipeline.go` 顺序执行全部检测器，发布配置仅有总开关（`api_dynamic_protection`）与模式（OFF/OBSERVE/PROTECT）；`mode=OFF` 只在 decision 层强制 ALLOW、管线工作不减少（`decision/engine.go:36`），不能充当检测器档。**本矩阵不伪造此类分档**；单项成本只能用「有无触发形态」对比近似（body 两臂隔离报文成本、protect 两臂隔离阻断动作成本）。
- **仍未覆盖**：WAF Only（应用 protection_mode 开启 Coraza 臂）——应用保护模式翻转影响面大于本任务边界，留待后续分片；深嵌套/大数组/Multipart/多API规模化；高并发压垮曲线与长时稳定性；采集器独立标定。

### 10.7 终态核验证据（共享环境恢复原状，全部实测通过）

脚本尾部自动核验 + 事后独立复核（UTC 02:25-02:30）：

- 容器：stage5 六容器（api/gateway/postgres/valkey/testorigin/ollama）全部 `Up … (healthy)`；数据容器全程未重建（`--no-deps` + dry-run 预检，compose 日志见原始目录）。
- api 容器环境：`API_DYNAMIC_PROTECTION_ENABLED=true`、`PRODUCT_EDITION=wdsp` ✓
- 策略：`GET /api/v1/api-security/policy` → `wdsp True OBSERVE db`；settings 表 `api_protection.mode="OBSERVE"`、`gateway_runtime` 组 **0 行残留**（临时限速行已删）。
- 网关行为：`GET /` → 200；敏感 query URL 在 OBSERVE 下恢复透传 404（不再 403）；写限速恢复默认——70×POST 实测 **60×404 + 10×429**，60/min 限速精确生效。
- 数据抽查：`applications=5`、`api_endpoints=99`、`api_runtime_events=265342`、`users=29` 均可正常查询；本矩阵产生的API/事件属正常测试数据（与 W18 探针同类）。

### 10.8 过程发现（harness 迭代，全部固化进脚本）

1. **bash 3.2 变量名并入全角字符**：`$VAR（` 中全角括号被 bash 3.2 并入变量名，`set -u` 下 `unbound variable` 中止（首轮 run 在 protect 臂前中断；EXIT trap 按设计恢复 OBSERVE）。修复：变量引用一律 `${VAR}` 花括号形式，并以 python 正则扫描 `$VAR<非ASCII>` 归零为验收。
2. **入库侧管线活性探针在采集器 backlog 下假阴性**：次轮 run observe 臂探针 20 请求网关侧事件齐（20/20）、入库侧 20s 窗口为 0（采集器正追平前轮 ~24 万事件），探针误判「管线无事件」中止。修复：活性与事件校验主口径改为网关侧 `/var/log/caddy/api-runtime-events.log` 前缀精确计数（不受 backlog 影响，且比入库侧更贴近「网关产出」语义），入库侧降为参考。该现象本身即 W18 §5 结论的现场复现。
3. 首轮（protect 臂未测）与次轮（仅 baseline 完成）数据作废不混入矩阵；本章节全部数字来自第三次完整 run（`/tmp/w18-matrix-1787191902/`）。

### 附录 C：扩展矩阵 ab 原始输出（关键行）

```text
baseline    c=20 t=30s GET /v1/w18m1787191902-base/1
  Complete 165004  Failed 0  QPS 5498.58  mean 3.637ms
  50% 3  66% 4  75% 4  80% 5  90% 7  95% 9  98% 12  99% 15  100% 48
observe     GET /v1/w18m1787191902-obs/1
  Complete 96336  Failed 0  QPS 3211.02  mean 6.229ms
  50% 4  66% 6  75% 7  80% 8  90% 11  95% 14  98% 20  99% 25  100% 2019
protect-block  GET /v1/w18m1787191902-prot/1?password=perfprobe（PROTECT，403 阻断）
  Complete 132168  Failed 0  QPS 4405.18  mean 4.540ms
  50% 3  66% 4  75% 5  80% 6  90% 8  95% 10  98% 14  99% 18  100% 1511
protect-pass   GET /v1/w18m1787191902-protok/1（PROTECT 透传）
  Complete 82577  Failed 0  QPS 2751.73  mean 7.268ms
  50% 5  66% 7  75% 8  80% 9  90% 13  95% 17  98% 25  99% 35  100% 1229
body-1k     POST 1024B JSON /v1/w18m1787191902-body/1（OBSERVE）
  Complete 93983  Failed 0  QPS 3132.52  mean 6.385ms
  50% 5  66% 6  75% 7  80% 8  90% 10  95% 13  98% 18  99% 22  100% 1189
body-64k    POST 65536B JSON 同 URL（OBSERVE）
  Complete 28825  Failed 0  QPS 960.73  mean 20.818ms
  50% 17  66% 21  75% 24  80% 26  90% 33  95% 41  98% 56  99% 81  100% 588
```

### 附录 D：扩展矩阵原始数据位置

- 汇总报告：`test/performance/w18-performance-matrix-result.txt`
- ab 原文与 stats 采样：`/tmp/w18-matrix-1787191902/`（六臂 `*-ab.txt`、`*-stats.txt`、compose 日志；/tmp 易失，关键数字已落入本文与结果文件）
- 网关侧事件计数复核：`docker exec jiuzhang-stage5-gateway sh -c "grep -c '<前缀>' /var/log/caddy/api-runtime-events.log"`，前缀 `w18m1787191902-{base,obs,prot,protok,body}`

## 11. §202 追补矩阵实测（WAF Only / Multipart / 高并发观察，2026-08-20 UTC 02:51-03:36）

> 复跑入口：`bash test/performance/w18-performance-matrix2.sh`（结果落 `test/performance/w18-performance-matrix2-result.txt`，原始数据 `/tmp/w18-matrix2-1787194263/`）；
> multipart 修正补测 `bash test/performance/w18-performance-matrix2b.sh`（结果落 `w18-performance-matrix2b-result.txt`，原始数据 `/tmp/w18-matrix2b-1787196723/`）。
> 口径与前两轮完全一致（c=20 × 30s 计量 + 5s 预热、`ab -k`、同机同栈同镜像 api sha256:edec8af1d0ad / gateway sha256:145e27c98420；conc100 臂 c=100 × 15s）。
> baseline / observe-api 两臂复测用于跨 run 对照；本 run 全程采集器在对 §10 起累积的百万级事件日志做全量重扫（§11.8 发现 2），api/postgres 背景 CPU 偏高，档间差值有效、绝对值为噪声上界。

### 11.1 概要

七测量全部真实实测、零失败请求（mp-1m 404 路径形态除外——ab 早退无统计，根因见 §11.6/11.8，不计入矩阵）：

| 测量 | 定义 | 完整请求 | QPS | 平均 | P50 | P95 | P99 | max |
|------|------|---------|-----|------|-----|-----|-----|-----|
| baseline | wdsp off + 应用 OFF（纯反代，本轮复测） | 156884 | **5229.45** | 3.82ms | 3 | 10 | 19 | 84 |
| waf-only | wdsp off + 应用 OBSERVE（Coraza DetectionOnly，全量 CRS PL1） | 43950 | **1464.97** | 13.65ms | 11 | 28 | 47 | 158 |
| observe-api | wdsp on + 策略 OBSERVE + 应用 OFF（本轮复测） | 115784 | **3859.46** | 5.18ms | 4 | 13 | 22 | 128 |
| mp-512k（404 路径） | OBSERVE POST 512KiB multipart 到未知路径（源站早期 404） | 2944 | **98.09** | 203.90ms | 169 | 384 | 498 | 706 |
| mp-512k-up | OBSERVE POST 512KiB multipart 到 `/upload`（源站消费 body） | 2754 | **91.76** | 217.97ms | 157 | 577 | 907 | 1298 |
| mp-1m-up | 同上 POST 1MiB 文件（体 >1MiB 解析上限，截断） | 2369 | **78.91** | 253.45ms | 228 | 434 | 638 | 802 |
| conc100 | OBSERVE GET，c=100 × 15s 短促 | 29406 | **1960.12** | 51.02ms | 35 | 136 | 212 | 775 |

核心结论：

- **WAF（Coraza）本身开销约为 API 动态防护开销的 2.7 倍**。同 run 同 URL 三臂对照：纯反代 5229.45 QPS → 只开 Coraza（DetectionOnly 全量 CRS PL1）1464.97 QPS（**-72.0%**，均值 +9.83ms，p95 10→28ms）；只开 API 动态防护（OBSERVE 全管线）3859.46 QPS（**-26.2%**，均值 +1.36ms，p95 10→13ms）。资源侧同向：gateway CPU 均值 baseline 174.62% → waf-only **630.86%**（峰值 708.17%）→ observe-api 226.48%。Coraza 逐请求评估数百条 CRS 规则是本网关最重的单请求成本；API 管线（解析→分类→检测器→事件输出）相对轻量。
- **Multipart 文件上传成本以体长为主导**：512KiB 文件两种形态均 ~92-98 QPS（均值 ~204-218ms）；1MiB 78.91 QPS（均值 253.45ms）。512KiB→1MiB 体长翻倍 QPS -14.0%，单请求 +35.5ms/512KiB ≈ 68ns/字节（VM 端口发布路径传输 + 流式解析逐字节 FNV-1a 计数，`parser/parse_multipart.go` hashCounter）。p95 两臂重叠（577 vs 434ms），方差大，以均值/QPS 为准。
- **c=100 短促观察：零失败，吞吐饱和拐点清晰**。QPS 1960.12（为 c=20 时 3859.46 的 50.8%），p50 35ms / p99 212ms / max 775ms；gateway CPU 均值 406.54%（峰值 501.22%）、api 213.91%。并发升 5 倍吞吐反降——网关在本机 VM 资源下已饱和，表现为延迟换吞吐的软性拐点，无错误率抬升（0/29406 失败）。
- **baseline/observe-api 三 run 跨对照稳定**：baseline 5229.45（W18 5337.35 / §10 5498.58，带内 ±5%）；observe-api 3859.46（W18 3539.67 / §10 3211.02）——本 run 反而最快，三 run 差异均为采集器后台负载噪声量级，§10.5 的判读（采纳 W18 -33.7% 为管线开销主参考）不变。

### 11.2 档位实现（先读后改结论的扩展）

- **WAF Only 臂**：应用 `s5app` 无策略绑定（`application_policies` 0 行，`publisher.go:631` 的策略覆盖不生效），应用字段直达发布。经管理面 `PUT /api/v1/applications/{id}`（GET 全量回传、仅改 `protection_mode` + 乐观锁 `version`）切 OFF→OBSERVE，发布 JSON 中 SecRuleEngine 由 `Off` 变 `DetectionOnly`（`generator.go:16-20` modeToRuleEngine）；wdsp 保持 off（api 容器不带 wdsp 覆盖，与 baseline 臂同一容器形态）。测完同路径回 OFF。
- **Coraza 活性双侧验证**（run 唯一 marker 探针）：①baseline 臂 5 个 XSS 探针在 coraza-audit.log 命中 **0**（engine Off 时审计条目 uri/args 为空，证明真跳过）；②waf-only 臂同探针命中 5 条且均为 `DetectionOnly` 条目、均含 XSS 规则命中消息（证明全量评估）；③干净 GET 404 透传（DetectionOnly 不阻断）。臂间 API 事件双侧校验：baseline/waf-only 两臂 run 前缀 API 事件均为 **0**（Coraza 不产 API 事件，证明 wdsp 真关闭）。
- **Multipart 修正补测（matrix2b）**：首版两臂打未知路径，testorigin 对未知路径立即 404 且不读请求体（`deployment/stage1/testorigin/main.go:121-125`），1MiB 上传被早期响应截断致 ab 写错误早退（§11.8 发现 1）。修正为打 `/upload` 固定路由（`buildEcho` 完整读取 ≤1MiB body 回 200），两臂体规格不变（512KiB 完整解析 / 1MiB 超 `max_body_parse_bytes=1MiB` 截断）。
- **Multipart 形态与 API 分类的相互制约**（诚实口径声明）：`classifier/api.go` 打分制（IsAPI ≥ 0.35），multipart/form-data 不提供 content_type 信号——`/upload` 路径得分 0、 `/api/json` 路径 0.15，均不产 API 事件（实测：/upload multipart 两臂窗口事件 13/0，余为 JSON 探针尾数；/api/json multipart 3 请求 0 事件）；`/v1/<pfx>-mp512/1` 路径形态产事件（事件字段 `api_confidence=0.9`，首轮 3433 事件 ≥ 计量+探针 ✓ 全管线在跑）。故本矩阵两个 multipart 数字各测一段：**404 路径臂 = 全管线（解析+分类+检测器+事件）但源站早期响应；/upload 臂 = 解析+代理全流程但按分类规则不进检测器/事件**。主检测器挂 `api.IsAPI` 门槛（`pipeline/pipeline.go:125-127`），解析在分类之前恒执行——两臂的解析成本一致，数字接近（98.09 vs 91.76 QPS）说明体长成本主导、检测器/事件开销在小 QPS 下占比小。
- **写限速**：两臂均沿用 `system_settings` 注入 `gateway_runtime/api_write_rate_per_minute=200000000`（仅此一行）+ 发布 + 100×POST 探针无 429 才计量；测完删行再发布。首轮复核曾遇全放行瞬态（§11.8 发现 3），matrix2b 复核 60×200+10×429 精确生效。
- **conc100 臂**：仅计量参数不同（c=100、t=15s），置于全程最后，避免其事件洪峰污染他臂。

### 11.3 事件计数校验（网关侧日志精确口径）

| 臂 | 网关侧事件数 | 判定 |
|----|------------|------|
| baseline | **0** | ✓ 真绕过管线 |
| waf-only | **0** | ✓ Coraza 不产 API 事件（wdsp 真关闭） |
| observe-api | 124861 / ≥115804 | ✓（含预热+20 探针） |
| mp-512k（404 路径） | 3433 / ≥3044 | ✓（含 100 探针，全管线在跑） |
| mp-1m（404 路径） | **0**（ab 仅完成 61 请求即早退） | 早期响应截断，请求流未完整到达管线，无事件（§11.8 发现 1） |
| mp-512k-up / mp-1m-up（/upload） | 13 / 0（时间窗，均为 JSON 探针尾数） | 符合分类器规则（multipart 非 API 信号，§11.2）——**不产事件为预期行为，非丢失** |
| conc100 | 34594 / ≥29406 | ✓ |

入库侧：本 run 全程 `api_runtime_events` 计数冻结于 709297（max occurred_at 02:15:42，先于本 run 起点），drain 轮询全部超时——根因分析见 §11.8 发现 2；事件以网关侧日志为准（1.17GB 完整在盘，无丢失，仅入库延迟）。

### 11.4 资源消耗（压测窗口 docker stats 采样均值/峰值）

| 容器 | 指标 | idle* | baseline | waf-only | observe-api | mp-512k(404) | mp-512k-up | mp-1m-up | conc100 |
|------|------|-------|----------|----------|-------------|--------------|------------|----------|---------|
| gateway | CPU 均值%（峰值） | 0.38（0.40） | 174.62（283.17） | **630.86（708.17）** | 226.48（346.72） | 127.98（153.26） | 124.08（193.07） | 49.63（103.61） | 406.54（501.22） |
| gateway | 内存峰值 MiB | 141.6 | 168.0 | 229.2 | 171.1 | 261.4 | 235.6 | 240.0 | 277.1 |
| api | CPU 均值%（峰值） | 46.78（53.07） | 51.46（63.42） | 24.36（58.51） | 68.16（83.79） | 42.91（99.94） | 46.59（96.44） | 174.15（548.29） | 213.91（347.03） |
| postgres | CPU 均值%（峰值） | 36.15（37.73） | 64.49（216.49） | 19.68（40.06） | 118.28（441.96） | 258.62（602.49） | 100.57（386.66） | 53.25（206.08） | 70.20（163.61） |
| valkey | CPU 均值%（峰值） | 0.25（0.26） | 1.54（11.09） | 1.24（4.83） | 0.55（1.17） | 2.45（12.61） | 2.69（10.91） | 1.45（7.28） | 5.82（20.95） |

*idle 起即偏高：采集器正在对历史事件日志全量重扫（§11.8 发现 2），api/postgres 基线负载贯穿本 run 全部臂；valkey 内存全线 ≤12.9MiB 无压力。mp-1m(404) 臂期间 api 峰值 1009.57%（全 10 vCPU）为采集器重扫与测量叠加的极值，如实保留。

### 11.5 分析

- **「WAF 本身开销 vs API 防护开销」的回答**：本机同口径下 Coraza DetectionOnly（CRS 4.28 PL1 全量规则集、每请求评估）使吞吐降为纯反代的 28.0%，API 动态防护全管线降为 73.8%；两者叠加形态（生产常见）可粗略预期为两段成本相加（未在本任务测量，标注为后续档位）。WAF 臂 gateway CPU 630.86% 已接近单机瓶颈——**网关水平扩展的首要驱动是 Coraza 规则评估，而非 API 管线**。
- **waf-only 臂 max 158ms 无离群毛刺**（W18/§10 各臂均有秒级单发离群），p99 47ms 收敛——CRS 评估成本是确定性的逐请求成本，非尾部现象。
- **Multipart 两臂（512KiB，两种形态）数字互证**：98.09（全管线+早期 404）vs 91.76 QPS（解析+全消费），差 6.5% 在噪声带内——佐证体长（传输+逐字节哈希）主导成本；源站是否消费 body 对网关侧成本影响 <7%。
- **mp-1m-up 截断形态符合设计**：体 1048756B > 1MiB 解析上限，流式解析至上限置 `BodyTruncated`，文件元数据仍留存（part 名/大小）；源站读满 1MiB 回 200。截断未造成错误（0/2369 失败）。
- **conc100 拐点判读**：20→100 并发吞吐 -49.2%、p99 22→212ms，无失败——饱和形态为排队延迟而非拒绝；gateway 406% CPU 下仍留有余量（VM 1000% 总额），瓶颈判读为网关进程 + VM 调度综合。共享环境不做更高并发/更长时（铁律）。
- **max 离群**：mp-512k-up 1298ms、conc100 775ms 均为孤立单发（p99 以内收敛），与前两轮同款 Docker VM 调度特征，如实保留。

### 11.6 覆盖度与不可行声明（诚实边界）

- **已覆盖**：WAF Only（Coraza DetectionOnly 全量 CRS，含活性双侧验证）；Multipart 512KiB（全管线 404 路径形态 + /upload 源站消费形态）；Multipart 1MiB 截断（/upload 形态）；c=100 短促高并发观察。
- **当前拓扑不可测（不造假分档）**：**1MiB + API 分类 + 源站消费三者兼具的 multipart 形态**——①打未知路径（有 /v1/ API 信号）源站早期 404 截断上传，ab 写错误早退（§11.8 发现 1）；②打消费型固定路由（/upload、/api/json、/echo、/login）均无 /v1/ 等 API 信号（分类器得分 <0.35），不产事件不进检测器；③分类器信号无 query/路径模板注入手段。要补此档需 testorigin 增加带 API 信号的消费型路由（如 `/v1/upload`），属产品代码变更，超出本任务边界。
- **仍架构上不可分档**：检测器级独立开关不存在（§10.6 结论不变）。
- **仍未覆盖**：WAF+API 叠加臂（生产常见组合）；深嵌套/大数组/多API规模化；高并发压垮曲线与长时稳定性；采集器独立标定（§11.8 发现 2 为其改造依据）。

### 11.7 终态核验证据（共享环境恢复原状，全部实测通过）

matrix2 脚本尾部自动核验 + matrix2b 尾部核验 + 事后独立复核（UTC 03:36-03:45）：

- 容器：stage5 六容器全部 `Up … (healthy)`；数据容器全程未重建（`--no-deps` + dry-run 预检）；api 容器自 02:54 起为 wdsp 形态并保持运行（不再重启，让采集器重扫自然完成，见 §11.8 发现 2）。
- api 容器环境：`API_DYNAMIC_PROTECTION_ENABLED=true`、`PRODUCT_EDITION=wdsp` ✓
- 策略：`wdsp True OBSERVE db`；应用 `s5app` protection_mode=**OFF**（与本 run 起点一致）；settings 表 `api_protection.mode="OBSERVE"`、`gateway_runtime` 组 **0 行残留**（临时限速行已删）。
- 网关行为：`GET /` → 200；写限速恢复默认——两次独立复核精确生效（03:21 `60×404+10×429`、03:36 `60×200+10×429`）。
- 数据抽查：`applications=5`、`api_endpoints=104`、`api_runtime_events=709297`、`users=29` 均可正常查询（api_endpoints 自 99 增至 104 为采集器重扫推进API发现的正常测试数据；本 run 事件在网关侧日志完整在盘，入库延迟见 §11.8 发现 2）。

### 11.8 过程发现（harness 与采集器，全部固化进脚本或形成改造依据）

1. **大 body 打 404 路径会被源站早期响应截断（ab 写错误早退）**：testorigin 对未知路径立即 404 不读 body；Go net/http 仅在剩余未读 body ≤256KB（maxPostHandlerReadBytes）时 drain 保连。512KiB 上传侥幸完成（连接存续），1MiB 上传在源站 404 到达后连接被 RST，ab（`-r` 只忽略读错误）写方向出错退出，输出仅 `Total of 61 requests completed`；对应请求流未完整到达管线，网关侧事件 0 条。手工 curl 复现：1MiB 上传仅发出 393216B 即收到 404（9ms）。**对策**：multipart/大 body 臂一律打消费型路由（`/upload`），已固化进 matrix2.sh 修订与 matrix2b.sh；body ≤64KiB 的前两轮不受影响（剩余未读 <256KB，drain 保连）。
2. **采集器在深 backlog + 容器重建下入库冻结数十分钟（现场根因分析）**：`apiruntime/collector.go` 的 `CollectOnce` 从断点读至当前 EOF 才执行唯一一次 flush（SavePrimary 逐条 + saveCheckpoint），**断点文件仅在 flush 时落盘**；api 容器每次重建（本 run 2 次、§10 run 多次）都杀死在途扫描，新容器从无断点（实测 `/var/log/caddy-audit/api-runtime-events.log.checkpoint` 不存在）重新从 offset 0 扫 1.17GB 日志。现场：§10 文档快照（02:25-02:30，计数 265342）后入库曾继续推进，本 run 观察窗口（03:13-03:45 UTC）内计数冻结于 709297 未动（max occurred_at 02:15:42，积压主体为 §10 及更早流量），当前采集器（02:54 随 wdsp 容器启动）运行 ≥50 分钟未提交主事件批次；`api_endpoints` 同期 99→104（handleRecord 副作用即时执行，证明扫描在推进），主事件待 EOF flush 一次性提交。事件不丢（网关日志在盘），仅入库延迟——但「重建即重扫」叠加「深 backlog」使追平时间不可控。**此为本任务留档的采集器改造依据**（flush 批量化/断点周期落盘），本任务按铁律不做产品变更，api 容器自 02:54 起保持运行待其自然追平。

   **已修复（W20 采集器批量化修复分片，2026-08-20）**：`apiruntime/collector.go` 的 `CollectOnce` 不再等 EOF 才唯一一次 flush——每处理 2000 行或距上次 flush 超 2s 即落一次主事件批次 + 断点（断点与批次同节奏，崩溃重扫量有界 ≤2000 行 + ≤2s），EOF 末次 flush 维持不变；幂等语义不变（重放由 `SavePrimary` 的 request_id `WHERE NOT EXISTS` 兜底）。阈值可配：`WAF_COLLECTOR_FLUSH_BATCH` / `WAF_COLLECTOR_FLUSH_INTERVAL`（config.go）→ `SetFlushPolicy`（main.go 接线），默认 2000/2s（依据本节现场：11.5 万条 ≈6.5 分钟追平 ≈300 行/s，2000 行 ≈7s 扫描量，取值保守）。`accesslogs/collector.go` 同构问题同手法修复：断点由「仅 EOF 落盘」改为批量/周期落盘（行数据本即逐行入库，重放由 request_id 唯一索引去重）；顺带修正两处同域缺陷——断点 offset 改按完整行累计（旧实现含结尾残行字节，残行补全后会被错位截读）、EOF 落盘失败不再 `_ =` 静默吞掉（现返回错误由 Run 记录，重放安全）。验证：`server/internal/apiruntime/collector_flush_test.go` 单测 4 项（批量触发中途落盘 / 周期触发中途落盘 / 中途失败断点保持 + 新实例有界重扫 3/5 行且零重复 / 默认参数与 SetFlushPolicy 纪律），`server/tests/accesslogs_collector_flush_test.go` 真实 PG 集成（全量入库 + 断点精确落文件尾、重复采集零新增、断点回退重放行数不增、增量续传）；既有采集链路集成 `TestStage8NodeHeartbeatCollection` / `TestStage8FileAssetsCollectUpsert` / `TestStage8ModelPoisoningResilience` / `TestStage8RuntimeEventIdentity` / `TestStage8RuntimeEventEnrichment` 全过。集成用一次性 PG/Valkey 容器（127.0.0.1:55444 / 127.0.0.1:56379，镜像 digest 与 docker-compose.yml 一致），测完自删。

   **复测（W21 flush 修复效果复测分片，2026-08-20 UTC 04:38-04:58，真实实测）**：运行中 api 镜像（sha256:edec8af1d0ad，2026-08-19 构建）经二进制符号核验不含修复（无 `WAF_COLLECTOR_FLUSH`）→ 用当前工作树重建镜像（sha256:a4533411670e）并 `--no-deps` + dry-run 预检仅重建 api 容器（数据容器未动；迁移 66→75 随 ENTRYPOINT 自动应用，均为增量 DDL——000067 对 `api_call_edges` 做自然键合并去重、聚合值保留，无数据丢失）；重建后 8s 健康、断点与数据完好（events=900520、断点 offset=1174809478=EOF 原位续扫零重扫）、发布 PUBLISH_OK。复测口径与 W18/§10/§11 同栈同形态（wdsp + 策略 OBSERVE + 应用 s5app OFF）：ab `-k` 两臂并发 c=10+10 × 30s 敏感/偏离混合（`GET /v1/<pfx>-dev/1` + `GET /v1/<pfx>-sens/1?password=perfprobe`，前缀 w21f1787201388），95779 计量请求零失败（两臂 1599.27/1593.36 QPS），网关侧前缀总产出 **110751** 事件（含预热+20 探针）；全程每 2s 采样入库前缀计数与断点（`/tmp/w21-flush-1787201388/catchup.csv`，脚本 `test/performance/w21-flush-retest.sh`，结果 `w21-flush-retest-result.txt`）。修复前后对比：

   | 指标 | 修复前（本节现场） | 修复后（本复测） |
   |------|-------------------|------------------|
   | 11 万级洪峰追平时间 | ≈6.5 分钟（11.5 万，无重启，§5/本节标定） | **386s**（11.08 万，含一次 4s 中途重启） |
   | 入库可见性 | 冻结至 EOF 一次性跳变（现场冻结 ≥50 分钟：计数 709297 在 03:13-03:45+ 全程未动） | 秒级连续爬升：洪峰窗内即并发入库（洪峰结束时已入库 17593），全程 2s 采样无冻结 |
   | 断点更新频率 | 仅 EOF 落盘（深 backlog 下全程不写） | 洪峰窗 7 次 / 追平窗 97 次推进，中位间隔 **4s** |
   | 重建/重启重扫 | 断点缺失 → offset 0 全量重扫 1.17GB（≥50 分钟量级） | 断点 2s 新鲜（mtime 距 kill 2s），新进程自 1198675107 续扫；重放仅未提交尾批（实测 ≈503 行，上界 ≤2000 行+≤2s），request_id 去重零双计（110751 行 == 110751 distinct） |

   **结论**：追平时间同量级未收敛——瓶颈在逐行 `SavePrimary` 幂等插入 + `handleRecord` 逐行副作用（API upsert/样本/违例/findings/参数观测/响应 schema/流量桶），flush 节奏不改变单行处理成本；实测洪峰窗入库 ≈586 行/s、追平窗 ≈244 行/s（含 4s 重启停机），与修复前 ≈300 行/s 标定同带。批量阈值与扫描速率关系：2000 行批量在该速率带 3-8s 填满、批量触发为主导（周期 2s 仅在更低速率时兜底），与断点中位推进间隔 4s 互证。修复价值在**可见性与有界性**而非吞吐：入库进度实时可见、崩溃重放有界（≤2000 行+≤2s）、重建/重启不再全量重扫（同场景旧实现追平时间不可控）；吞吐提升须另行批量化 INSERT（多行 VALUES / COPY），超出本修复范围。复测终态：六容器全 healthy、策略 `wdsp True OBSERVE db`、应用 s5app=OFF、`gateway_runtime` 0 残留、`GET /`→200、数据抽查可查（events=1011271、endpoints=110、apps=5、users=29；表净增 110731+起点已计探针 20 == 网关前缀产出 110751，分毫不差）。

   **吞吐批量化（W22 事务批量化，2026-08-21 实测）**：按上述结论落地「每个 flush 批次一个 DB 事务」（`server/internal/apiruntime/batchtx.go`：批次窗口内副作用与主事件并入单事务整批 COMMIT，副作用错误经记录级 SAVEPOINT 容忍，失败整体回滚断点不前移、重放幂等；`SetBatchTxFactory` 接线，未接线保持 autocommit 零行为变化；accesslogs 采集器同手法）。机制级基准（`collector_batchtx_bench_test.go`，同机同库临时表 3×10000 行 `WHERE NOT EXISTS` 幂等插入，`VirtualApple 2.50GHz`，共享负载机绝对值偏低、比值有效）：**逐行 autocommit 143.6 rows/s → 每 2000 行单事务 272.2 rows/s（≈1.9 倍）**。真实 PG 集成 4 用例全过（端到端一致/重放安全/毒记录回滚/死事务回滚）；单元测试 6 项全过（逐 flush 提交/保存失败断点不前移/提交失败重放幂等/副作用失败保批次/心跳不开事务/开启失败）。注意：该基准仅测事务边界机制（单 INSERT/行），生产链路每行另有发现 upsert/样本/观测等副作用，端到端提升幅度以生产复测为准（见下段）。

   **生产复测（W22 复测分片，2026-08-20 UTC 08:33-09:26，真实实测）**：运行中 api 镜像（sha256:a4533411670e，W21 复测构建）经二进制符号核验不含 W22（无 `SetBatchTxFactory`）→ 用当前工作树重建镜像（sha256:c8dbb9ebb6cf），沿用 W18/W21 固化手法（.env+端口覆盖+wdsp 叠加+`--no-deps`+dry-run 预检仅 api Recreate）仅重建 api 容器（数据容器未动；迁移仍 75 无新增；重建后 7s 健康、断点 offset=1311538382=EOF 原位续扫零重扫、数据抽查分毫不变 events=1011272/endpoints=110/apps=5/users=29、发布 PUBLISH_OK、新二进制符号 SetBatchTxFactory=3 / WAF_COLLECTOR_FLUSH=2）。复测口径与 W21 完全相同（wdsp + 策略 OBSERVE + 应用 s5app OFF，ab `-k` 两臂 c=10+10 敏感/偏离混合，全程 2s 采样入库计数与断点，追平中途 docker restart api 一次；脚本 `test/performance/w22-batchtx-retest.sh`，结果 `w22-batchtx-retest-result.txt`（run2）与 `w22-batchtx-retest-run1-result.txt`（run1），原始 `/tmp/w22-batchtx-{1787215052,1787216123}/`）。两轮真实实测——run1 30s 洪峰 42,248 事件；run2 95s 洪峰（`W22_FLOOD_DUR=95`）169,117 事件，覆盖并超过 W21 的 11 万量级：

   | 指标 | W21 复测（逐行 autocommit） | W22 run1 | W22 run2 |
   |------|------------------------------|----------|----------|
   | 洪峰产出 | 95,779 请求/30s（1599+1593 QPS）→ 110,751 事件 | 36,299 请求/30s（605+602 QPS）→ 42,248 事件 | 162,493 请求/95s（856+855 QPS）→ 169,117 事件 |
   | 追平时间（洪峰结束→追平，含 4s 重启） | **386s** | 450s | 1,581s |
   | 追平窗入库速率（2s 采样：中位/均值） | ≈244 行/s | 92.0 / 91.5 行/s | 111.4 / 102.6 行/s（窗内随负载 132→76 递减） |
   | 洪峰窗并发入库速率（中位/均值） | ≈586 行/s | 48.1 / 52.1 行/s | 70.7 / 71.8 行/s |
   | 断点推进（洪峰/追平次数，中位间隔） | 7 / 97 次，4s | 4 / 65 次，6s | 15 / 269 次，5s |
   | 重启重放（已提交未记断点行数） | ≈503 行（幂等去重零双计） | **0 行**（提交与断点原子，构造性消除） | **0 行** |
   | 幂等校验（行数==distinct request_id） | 110,751==110,751 | 42,248==42,248 | 169,117==169,117 |

   **结论（如实）**：事务批量化的机制级 1.9 倍提升**未在生产链路端到端体现**。两轮绝对速率均低于 W21，但差异可由宿主机负载解释——复测时段共享机 load average 150-180（10 核超订，另有 code-audit/zabbix 等栈与桌面负载），洪峰臂 QPS 仅为 W21 安静机的 0.38-0.54 倍；按网关路径吞吐归一化（追平速率 × W21/本轮洪峰 QPS 比）后 W22 追平速率为 W21 的 **≈0.8-1.0 倍**（run1 91.5×3193/1210≈242 vs 244 ≈1.0 倍；run2 102.6×3193/1710≈192 vs 244 ≈0.8 倍，run2 追平窗负载仍在爬升，归一化分母偏低），噪声内**持平**。根因与 W21 结论一致且更进一步：生产链路每行成本由副作用语句执行主导（发现 upsert/样本/findings/参数观测/响应 schema/流量桶等 ≈10+ 语句/行；两轮追平期间 stage5-postgres CPU 387-396% 而 api 仅 ≈43%，DB 执行受限），事务批量化每行仅省 ≤1 次 COMMIT，并引入 SAVEPOINT+RELEASE 每行 2 次额外往返（机制基准的单 INSERT/行场景 COMMIT 占比高，故见 1.9 倍）；且 ~50-110 行/s 速率带下 flush 由 2s 周期触发主导（每事务仅 ~150-250 行，2000 行整批需 20-40s 才填满，难得触发——与 W21 高速率带批量触发主导相反）。断点中位间隔三轮均受采样器漂移下限所限（负载下实际采样间隔 5-7s），不宜据此比较 flush 节奏。W22 的确定性收益在**正确性与重放结构**：批次原子可见（消除「副作用已提交、主事件未落」中间态）、「已提交未记断点」重放由 ≈503 行降为 **0**（两轮重启各 4s 恢复、断点 1-2s 新鲜、自原位续扫零回退、零双计）；重启杀死在途批次时失败语义按设计工作（连接断开→保存点/回滚错误逐条如实记录→整批回滚→断点不前移→重放幂等，逐条错误记录见 api 容器日志同时段（run1 08:41:18 / run2 09:00:22，docker logs 至今可查；`restart-api.log` 按脚本过滤仅收重启后启动行））。吞吐进一步提升须走副作用批量化（多行 VALUES/COPY）或削减每行语句数，超出 W22 范围。复测终态：六容器全 healthy、策略 `wdsp True OBSERVE db`、应用 s5app=OFF、`gateway_runtime` 0 残留、`GET /`→200、数据可查（events=1,222,638、endpoints=114、apps=5、users=29；run2 表净增 169,097+起点已计探针 20 == 网关前缀产出 169,117，分毫不差；accesslogs 采集器同手法代码随本镜像在线，断点秒级推进无停滞）。**独立复核（2026-08-21 UTC 02:07，复测后 17.5h，真实实测）**：运行中 api 容器镜像仍为 sha256:c8dbb9ebb6cf（StartedAt 2026-08-20T09:00:24Z=run2 中途重启点，此后再未被触碰），二进制符号 SetBatchTxFactory=3 / WAF_COLLECTOR_FLUSH=2；六容器全 healthy；库内策略覆盖 `api_protection:mode="OBSERVE"`（source=db）、s5app=OFF、`gateway_runtime` 残留 0；数据零漂移——events=1,222,639（=run2 快照 1,222,638+其终态探针事件 1 条，时序完全对账）、endpoints=114、apps=5、users=29，run1 前缀 42,249==distinct 42,249、run2 前缀 169,118==distinct 169,118（各 +1 为结果文件快照后本脚本终态探针入库，零双计）；事件断点 offset=1,572,348,067==日志大小（EOF 就位），access-log 断点 offset==当前文件大小且同 inode、秒级新鲜；`GET /`→200。
3. **写限速配置热更新存在秒级瞬态窗口**：matrix2 终态复核（删临时行+发布 PUBLISH_OK 后数秒）70×POST 全 404 无 429；65 秒后复核 60+10 精确生效（matrix2b 复核亦一次通过）。判读为发布后限速配置生效的短暂过渡，非功能缺陷；matrix2.sh 终态复核已加「首轮无 429 则 65s 后复核」固化。
4. **/tmp 原始数据**：run3 `/tmp/w18-matrix2-1787194263/`、run3b `/tmp/w18-matrix2b-1787196723/`（ab 原文、stats 采样、compose/restore 日志；/tmp 易失，关键数字已落入本文与结果文件）。

### 附录 E：追补矩阵 ab 原始输出（关键行）

```text
baseline    c=20 t=30s GET /v1/w18x1787194263-base/1（wdsp off + 应用 OFF）
  Complete 156884  Failed 0  QPS 5229.45  mean 3.824ms
  50% 3  90% 7  95% 10  98% 15  99% 19  100% 84
waf-only    GET /v1/w18x1787194263-waf/1（wdsp off + 应用 OBSERVE = Coraza DetectionOnly）
  Complete 43950  Failed 0  QPS 1464.97  mean 13.652ms
  50% 11  90% 23  95% 28  98% 38  99% 47  100% 158
observe-api GET /v1/w18x1787194263-obs/1（wdsp on + OBSERVE + 应用 OFF）
  Complete 115784  Failed 0  QPS 3859.46  mean 5.182ms
  50% 4  90% 10  95% 13  98% 18  99% 22  100% 128
mp-512k(404) POST 524459B multipart /v1/w18x1787194263-mp512/1（OBSERVE，源站早期404）
  Complete 2944  Failed 0  QPS 98.09  mean 203.895ms
  50% 169  90% 329  95% 384  98% 473  99% 498  100% 706
mp-512k-up  POST 524470B multipart /upload（OBSERVE，源站消费 body 回 200）
  Complete 2754  Failed 0  QPS 91.76  mean 217.971ms
  50% 157  90% 422  95% 577  98% 770  99% 907  100% 1298
mp-1m-up    POST 1048756B multipart /upload（OBSERVE，超 1MiB 解析上限截断）
  Complete 2369  Failed 0  QPS 78.91  mean 253.454ms
  50% 228  90% 352  95% 434  98% 488  99% 638  100% 802
conc100     c=100 t=15s GET /v1/w18x1787194263-conc/1（OBSERVE）
  Complete 29406  Failed 0  QPS 1960.12  mean 51.017ms
  50% 35  90% 99  95% 136  98% 185  99% 212  100% 775
```

### 附录 F：追补矩阵原始数据位置

- 汇总报告：`test/performance/w18-performance-matrix2-result.txt`、`test/performance/w18-performance-matrix2b-result.txt`
- ab 原文与 stats 采样：`/tmp/w18-matrix2-1787194263/`、`/tmp/w18-matrix2b-1787196723/`
- 网关侧事件计数复核：`docker exec jiuzhang-stage5-gateway sh -c "grep -c '<前缀>' /var/log/caddy/api-runtime-events.log"`，前缀 `w18x1787194263-{base,waf,obs,mp512,conc}`；/upload 两臂按 occurred_at 时间窗计数（脚本内 `gw_ev_count_since`）
- Coraza 活性复核：`docker exec jiuzhang-stage5-gateway sh -c "grep -c 'w18mk1787194263' /var/log/caddy/coraza-audit.log"`（baseline 臂 0 / waf-only 臂 5，含 DetectionOnly 与 XSS 命中消息）
