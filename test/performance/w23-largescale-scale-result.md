# 九章 §55 性能矩阵缺口项实测：大规模维度（10 万 API / 百万参数 / 图谱查询）

- 日期：2026-09-11（W23）
- 基线：develop @ b3745cc（fix(wdsp): resolve 1.1.4 review findings）
- 环境：macOS 25.2.0 arm64（10 核 / 16 GB），Go 1.25.6；PostgreSQL 16.14（一次性隔离容器 p0s3-pg，127.0.0.1:55432，postgres:16-alpine）上的独立临时库 `jiuzhang_perf`（专用一次性角色 `perf`，测后即删；全程未触碰 `jiuzhang_waf` / `jiuzhang_waf_test`）
- 任务书口径：docs/tasks/STAGE_8_UNIFIED_WEB_API_DYNAMIC_PROTECTION.md 五十五「性能要求」。**§55 未给数值目标**（原文：「基准目标应在测试报告中以实际结果为准」「不得将目标值写成已完成结果」），故本报告如实记录实测值与观察点，不作达标/不达标判定；是否达标需产品侧先定阈值。
- 既有六项（baseline/OBSERVE/PROTECT/body/multipart/c=100）见 w18-performance-matrix*.txt，本报告不重复。

## 1. 数据规模（造数口径）

全量迁移（000001–000158，生产迁移命令 `cmd/api migrate up`）后由 `w23-largescale-seed.sql` 生成：

| 表 | 行数 | 表+索引体积 |
|---|---|---|
| api_endpoints | 100,000 | 51 MB |
| api_model_versions | 120,000（FORMAL 100,000 + SUPERSEDED 20,000） | 57 MB |
| api_parameter_models | 1,200,000（下发过滤命中 1,000,000） | 359 MB |
| api_parameter_relations（confirmed） | 50,161 | 13 MB |
| api_call_edges | 700,000（20% 源端点为 NULL；5,000 调用方指纹） | 167 MB |
| api_runtime_findings（status=NEW） | 60,000 | 16 MB |
| applications | 10 | — |

造数分批：参数模型按 endpoint_key 哈希非负化（`hashtextextended(...) & 2^62-1`）分 6 批、每批单事务约 20 万行（实测 1.9–4.8 s/批）；边分 3 趟不同盐值各 30 万（自然键 `uq_api_call_edges_caller_source_target` 零冲突）。首轮造数踩坑已修正进 seed.sql：`hashtextextended` 返回有符号 bigint（mod 6 有负余数，首轮只覆盖 58% 版本）；uuid 无 min/max 聚合；边三元组全部由 `g` 派生时单趟只有 10 万不同键。造数后 `VACUUM ANALYZE`。

## 2. 测量方法

测量程序 `w23-largescale/bench/main.go`（Go + pgx v5.7.2，与 server/go.mod 同版本），**不改生产代码**，逐字复刻以下生产 SQL 与 Go 侧组装逻辑：

- 下发构建：`guardconfig.Provider.BuildGuardConfig` 的 API 段五个规模敏感查询——
  `apimodels/store.go ListFormalSchemas`、`ListFormalModelVersions`、
  `apimodels/parameters.go ListFormalParameterConstraints`、
  `apimodels/relations.go ListConfirmedParameterRelations`、
  `apiassets/store.go ListKeyStatus`，
  含 provider.go 的 GuardParamConstraint/GuardParamRelation 逐字段转换与 jsonb 解码，
  以及按 `gatewayconfig.GuardConfig` 相同 json 字段名的 `json.Marshal` 序列化。
  每查询 5 次计量；内存用 `runtime.ReadMemStats`（GC 后基线 vs 构建后）与 TotalAlloc 差值。
- 图谱查询：`apisecurity/store.go` 的 ListGraphFiltered 节点查询、ListTopologyFiltered 节点查询
  （含 activeFindingsJoin 未闭环 findings 聚合）、listEdges 三种过滤形态（无过滤 / 近 24h 时间窗 /
  min_count≥1000）、metrics 边总数 `count(*)`。每项 21 次**全行扫描**计量（与生产 rows.Next 同成本），
  另各留一份 `EXPLAIN (ANALYZE, BUFFERS)`。

原始产物：`w23-largescale/raw/`（bench 逐次原始值 JSON、stdout、6 份 EXPLAIN）；完整运行副本在 /tmp/w23-largescale-run/（含 148 MB 下发产物 gzip）。

## 3. 实测结果

### 3.1 下发构建（10 万端点 + 百万参数），5 次计量

| 查询（生产函数） | 行数 | P50 | P95 | min | max |
|---|---|---|---|---|---|
| ListFormalSchemas | 100,000 | 806.8 ms | 836.3 ms | 674.3 | 889.5 |
| ListFormalModelVersions | 100,000 | 219.7 ms | 224.1 ms | 214.2 | 282.7 |
| ListFormalParameterConstraints | 1,000,000 | 5997.5 ms | 6541.0 ms | 5403.5 | 9973.0 |
| ListConfirmedParameterRelations | 50,161 | 1468.6 ms | 1593.4 ms | 699.3 | 2379.1 |
| ListKeyStatus | 100,000 | 51.6 ms | 56.9 ms | 42.5 | 137.6 |
| **五查询 P50 合计** | | **8544.1 ms** | | | |
| json.Marshal（GuardConfig API 段） | 148 MB | P50 1457.8 ms | | | |

- 下发产物大小：**JSON 148.41 MB（155,614,813 字节）；gzip 1.56 MB**（造数高度重复，gzip 率异常好，真实数据 gzip 后预计明显大于此值）。
- 构建期内存（Go 进程）：GC 后基线 0.2 MB → 构建后 256.4 MB，**常驻增量 256.1 MB**；构建过程累计分配（TotalAlloc）9.85 GB（百万行 jsonb 解码 + map 组装的 GC 压力来源）。
- 观察点（非结论，阈值待产品侧定义）：
  1. 构建耗时 ≈8.5 s（查询+组装）+1.5 s（序列化）≈ **10 s 级**，其中 ListFormalParameterConstraints 一项占 70%；
  2. 148 MB 的 GuardConfig 会经版本快照（accesscontrolversions.config jsonb）落库并下发网关，快照表写放大与网关 /load 载荷均需评估；
  3. TotalAlloc ≈10 GB/次构建，频繁发布会造成明显 GC 压力。

### 3.2 图谱查询（10 万节点 / 70 万边 / 6 万未闭环 findings），21 次全行扫描

| 查询（生产函数/形态） | 行数 | P50 | P95 | min | max | EXPLAIN 执行时间（DB 侧） |
|---|---|---|---|---|---|---|
| graph_nodes（ListGraphFiltered） | 100,000 | 298.9 ms | 349.2 ms | 274.7 | 620.8 | 246.0 ms |
| topology_nodes（ListTopologyFiltered） | 100,000 | 228.9 ms | 326.4 ms | 211.1 | 330.4 | 214.5 ms |
| edges_all（listEdges 无过滤） | 700,000 | 756.4 ms | 854.4 ms | 704.2 | 914.7 | 248.2 ms |
| edges_timerange（近 24h） | 700,000 | 848.9 ms | 1659.1 ms | 719.1 | 1866.8 | 469.0 ms |
| edges_mincount（≥1000） | 692,008 | 914.8 ms | 1593.4 ms | 803.1 | 3283.6 | 344.9 ms |
| edges_count（metrics `count(*)`） | 1 | 26.8 ms | 32.2 ms | 25.1 | 125.0 | 44.1 ms |

- 所有边查询均为 Parallel Seq Scan + **external merge 磁盘排序**（work_mem 默认 4 MB 放不下 70 万行排序，temp 读写 ≈20–25 MB/次）；`count(*)` 走 Parallel Index Only Scan。
- 客户端 P50（含 70 万行传输与解码）约为 DB 执行时间的 2–3.7 倍；P95/max 尾部受磁盘排序与 JIT 影响明显（mincount 单次最大 3.28 s）。
- 观察点：listEdges 无 LIMIT，图谱接口在 70 万边规模下单次响应体与耗时就绪于「秒级」；如需亚秒级需引入分页/LIMIT 或预聚合（超本测量范围，如实记录现状）。

## 4. 复现

```bash
# 依赖：p0s3-pg 容器在 127.0.0.1:55432（docker 内 trust 可执行 psql），本机 Go 1.24+，pgx 模块缓存
bash test/performance/w23-largescale.sh            # 建库→迁移→造数→测量→删库
SKIP_SEED=1 KEEP_DB=1 bash test/performance/w23-largescale.sh   # 复测保留库
```

## 5. 清理与边界确认

- `jiuzhang_perf` 库与一次性角色 `perf` 测后已删，凭据临时文件 /tmp/.jiuzhang_perf_pw 已删；
- `jiuzhang_waf` / `jiuzhang_waf_test` 未做任何写入（建库/迁移/造数全部指向 jiuzhang_perf）；
- server/gateway/web 源码零改动；测量 SQL 逐字复制自生产仓储（main.go 文件头标注出处），未加生产测量钩子；
- 未执行任何 git 写操作。

## 6. 遗留

1. §55 无数值目标：本报告三项缺口的「达标与否」需产品/架构侧先定义阈值后回填结论。
2. 未覆盖项：学习任务并发、版本对比性能（§55 另两个未测项）；一次解析收益、文件上传等在 w18 已测或亦未覆盖，以 w18 系列报告为准。
3. 造数为合成数据（参数名/约束高度重复），gzip 体积偏乐观；约束 jsonb 均为同形小对象，真实多样性数据下 ListFormalParameterConstraints 解码耗时与产物体积预计更高。
4. 测量在容器 PG（默认 work_mem=4MB、shared_buffers=128MB）+ 本机直连下进行，与生产裸机 PG 参数不同，数字只作同环境相对比较基准。
