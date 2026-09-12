# P0-02 同配置安全与性能基准 — 工具与语料（S2 交付）

对应任务书：[P0-02_SECURITY_PERFORMANCE_BENCHMARK.md](../../../docs/tasks/wdsp-p0/P0-02_SECURITY_PERFORMANCE_BENCHMARK.md)。

本目录交付**测试工具与语料**。正式测量（matrix/soak/recovery）需要专用隔离基准硬件；
在共享开发机上这些子命令不得执行，缺失环境如实标记 `status=BLOCKED /
reason=ENVIRONMENT_UNAVAILABLE`，不得以短测或本机数据冒充正式结果。

## 目录结构

```text
test/performance/p0/
├── run.sh                  # 运行器：preflight/smoke/correctness/matrix/soak/recovery
├── collect.py              # 采集/对账 CLI（纯标准库）
├── report.py               # 报告生成器（只读 run 目录 → report.md）
├── run-plan.schema.json    # 预登记计划文档化 schema（权威校验在 p0bench/plan.py）
├── run-plan.example.json   # 示例计划（通过全量校验；语料哈希与仓库语料一致）
├── corpus/manifest.json    # 正常/攻击语料真值（自研合成，见 §5 字段）
├── p0bench/                # 共享库：plan/isolation/corpus/replay/metrics/reconcile/collectors/report_core/jwttool/cli
└── tests/                  # unittest（123 例）
deployment/docker-compose.p0-benchmark.yml   # 隔离编排（无固定容器名/固定端口）
docs/evidence/benchmarks/<run-id>/           # 每次运行的证据目录
```

## 使用方式

```sh
# 1. 复制示例计划并填写目标硬件实际值（环境标识、构建、门槛冻结值……）
cp test/performance/p0/run-plan.example.json my-plan.json

# 2. 预检（不起栈；§3.1 全部检查）
bash test/performance/p0/run.sh preflight --plan my-plan.json

# 3. 短时 smoke（起隔离栈，仅证明工具可运行，不产生容量结论）
bash test/performance/p0/run.sh smoke --plan my-plan.json

# 4. 正式测量（缺任一 §7 必填字段即拒绝启动）
bash test/performance/p0/run.sh correctness --plan my-plan.json
bash test/performance/p0/run.sh matrix      --plan my-plan.json
bash test/performance/p0/run.sh soak        --plan my-plan.json
bash test/performance/p0/run.sh recovery    --plan my-plan.json

# 5. 报告（只读，任何状态都能生成；缺失项显示 NOT_RUN/BLOCKED）
python3 test/performance/p0/report.py --run-dir docs/evidence/benchmarks/<run-id>
```

## 隔离保证

- 每次运行生成唯一 `run_id`（`YYYYMMDDTHHMMSS-xxxxxx`）与 compose project
  `p0bench-<run_id>`；容器/网络/卷名全部由 project 前缀派生，编排文件**无**
  `name:`/`container_name:`。
- 对外端口仅绑定 `127.0.0.1`，`P0B_*_PORT` 缺省为空即由 Docker 随机分配，
  不占用生产固定端口。
- 预检：run-plan 结构（§7）、语料哈希、环境唯一标识（宿主指纹比对）、
  显式端口占用、时钟偏差、压测器存在性与版本采集。正式子命令任一不过即拒绝。
- 目标地址判定：仅允许本 project 发布端口与计划登记的专用测试地址；
  重定向逐跳校验，逃离允许集合即拒绝（BENCH-02）。
- 停止/删除/重建/故障注入/trap 清理前，同时校验 `com.docker.compose.project`
  与 `p0bench.run_id` 两个标签；禁止全局 prune；证据目录保留。
- 密码由运行器生成并写入本 run 的 0600 环境文件，运行结束删除；
  输出不含环境变量全集、原始 Authorization 或完整 docker inspect 数据。

## BLOCKED 状态含义

机器可读验收记录统一为 `status=BLOCKED`、`reason=ENVIRONMENT_UNAVAILABLE`
（对应文档中的 BLOCKED_ENV 写法）。含义：**环境不可用导致该项未执行**，
不是通过、不是失败、更不是 SKIP——报告总判定中强制项 BLOCKED 一律记为
NOT_PASSED。当前本机无专用基准硬件，matrix/soak/recovery 正式测量即处此状态。

## 语料说明

- 全部样本 `source=self_synthetic`（自研合成），不含第三方攻击语料。
- 每条含 case_id、类别、请求模板、生成种子、标签、期望识别模块、九模式期望
  动作（七模式主基线 + jwt_off/jwt_protect 配对）、源站期望、期望事件；
  攻击样本带 `request_override` 字面量供确定性回放。
- `deferred=true` 样本（A-EXC-01 依赖 S4 决策域例外）不计入任何指标分母。
  JWT 语料（N-JWT-01/A-JWT-01）随 S3 交付已解除 deferred：`expected_detection_module`
  指向 `jwt_trust` 真实语义——jwt_protect 下篡改签名 Token INVALID → `BLOCK_401`
  （事件 JWT_AUTH_FAILED 落 access_control_events），jwt_off 与七模式基线（JWT 关闭）
  下原样放行，能力关闭的放行如实记录、不构成漏报。
- 语料不含任何 Token 材料：声明 `jwt_inject`（valid/tampered）的样本由运行器
  现场签发并注入（见下节）；`request_override.headers` 禁止静态写 Authorization。
- 修改语料后必须重算哈希并生成新 run-plan（旧计划哈希即失效，这是预期行为）。

## JWT 配对实验（JWT-18，S3 起接线）

**状态：工具已就绪，测量待专用隔离环境（BLOCKED_ENV）。** 本节只说明已接线的
用法；在共享开发机上不得执行正式测量或宣称性能结论。

计划声明 `config.jwt_pair`（见 run-plan.example.json）后，`correctness` /
`matrix` / `soak` 在七模式主基线之外追加配对 profile：

| Profile | WAF | API 动态防护 | JWT 信任链 |
|---|---|---|---|
| jwt_off | Off | OFF | OFF |
| jwt_protect | Off | OFF | PROTECT（静态 JWKS，RS256） |

运行机制（全部作用本 run 资源）：

1. `switch_profile` 扩展：配对 profile 先现场生成 RSA-2048 测试密钥
   （`openssl genpkey`，写入 `$RUN_DIR/jwt/key.pem`，0600；不入库不入 git），
   导出公钥 JWKS（`p0b jwt-jwks`，公钥非秘密，保留供审计），并用测试私钥
   现场签发有效/篡改签名两份 Bearer Token 到头文件（0600）。
2. 策略切换：按 `config.jwt_pair.app_code` 解析基准应用 ID（应用须已在基准栈
   接入，找不到即该轮 `BLOCKED`，不伪造结果）→ GET 当前草稿版本 →
   `PUT /api/v1/applications/{id}/jwt-trust-policy`（expected_version 乐观锁；
   PROTECT 携带 selector + STATIC_JWKS issuer）→ 既有发布通道发布 →
   GET 核对生效，策略文本哈希快照存证。
3. 回放注入：回放器对声明 `jwt_inject` 的语料样本以 `curl -H @<头文件>` 注入
   `Authorization: Bearer <token>`（Token 不上命令行、不入任何输出）；
   七模式基线回放不注入（JWT 关闭语义）。基线切换时 JWT 同步压回 OFF，
   防止配对 PROTECT 残留污染主基线。
4. 运行结束删除 `key.pem` 与 Token 头文件（trap 清理；证据不含密钥材料）。

期望真值（correctness 配对轮次）：A-JWT-01 在 jwt_protect 下 `BLOCK_401`、
jwt_off 下 `PASS`；N-JWT-01 两种 profile 均 `PASS`（VERIFIED 继续后续检测，
不产生事件）；其余样本两 profile 均与 proxy 基线一致（`PASS`）。

注意：matrix 配对负载沿用 ab 闭环并发且**不携带 Token**，测得的是选择器评估
与 NOT_PRESENT 路径开销；带 Token 的逐请求延迟由 correctness 回放的
truth-raw 提供。需要带 Token 的吞吐测量时改用 wrk/k6 并在 run-plan 登记。

## 已知限制

- 压测器默认 ab（闭环并发），报告如实标注协调遗漏限制，不伪称固定到达率；
  需要开放模型时在 run-plan 登记 wrk/k6（版本随运行采集入 manifest）。
- macOS/Windows 下 `docker stats` 为 Docker Desktop 虚拟机口径，资源时序
  仅作参考；正式测量应在 Linux 目标硬件上进行并以 /proc 补充。
-  correctness 的检测证据关联（truthbuild `--detected`）依赖事件日志
  request_id 对账，首次真实运行时需按网关节点日志格式核对。
- 运行器尚未实现：多节点矩阵、磁盘空间受限故障、队列背压注入的自动化
  （recovery 当前覆盖网关重启场景），对应 BENCH-09/10 的完整场景属 S5。
