# 安全与 APM 标准演示环境（P1-01 A1+A4）

> 状态：A1（独立演示夹具）+ A4（真实产品栈网关联动）交付物。
> 依据：docs/tasks/wdsp-p1/P1-01_SECURITY_APM_DEMO.md §3（演示环境组成与八个必备真实场景）、
> §6（实施拆分）、§8（发布/回退与证据）；docs/tasks/wdsp-p1/WORKLOG.md「S0 记录」P1-01 节。
> 本文是演示环境的唯一操作手册；产品侧 APM 事实以 docs/APM_ONBOARDING_GUIDE.md 为准
> （本文不重复定义产品行为，仅引用）。

## 1. 这是什么 / 不是什么

是一套**独立于既有部署**的演示夹具：合成业务（服务 A → 服务 B → 独立测试库）+ 演示专用
OTel Collector + 演示专用 ClickHouse，用于在真实数据面上演练「安全事件 → 关联请求 →
Trace → 服务调用 → 慢 SQL / 异常」调查流程。

A4 起新增 `--with-product` 形态：在同一 compose project 内叠加**本 run 自建的真实产品栈**
（管理 server + 防护网关 + 管理 PostgreSQL + Valkey，源码现建镜像，APM 数据面指向本 run
演示 ClickHouse），并全部经**真实管理 API** 完成接入（授权导入 → 全量访问日志开启 →
建安全管理员 → 建应用 → 配置发布 → 网关 traceparent 注入显式开启）。网关联动场景
（§7 场景 2/3/6/7）以管理 API 断言（trace-search 的 availability/correlation、安全事件、
access_logs）取证，证据落 `runs/<run_id>/evidence-a4/`。

它**不是**：

- 第二套随产品交付的管理面：产品栈编排（docker-compose.product-stack.yml）复刻
  deployment/docker-compose.stage5.yml 的服务组成与环境变量口径，镜像从仓库源码现建，
  随产品代码升级而升级；演示结束后 cleanup 整栈销毁；
- 对既有部署的任何修改：--with-product 的管理面操作对象仅限本 run 自建实例；
  把演示应用接入**既有部署**仍是操作员手动步骤（§4-B），脚本不代劳；
- 产品默认配置的副本：演示采样配置独立于产品默认值（collector/demo-*.yaml，§6）；
- 生产故障注入入口：场景开关只存在于本测试业务，不进入产品镜像或客户安装包。

## 2. 组成与选型理由

```text
造流/浏览器 ──► 既有部署网关（可选，手动接入，§4）──► 服务 A ──► 服务 B ──► 测试库(postgres)
                  │                                   │           │
                  │（网关 traceparent 注入现状见 §8）   │ OTLP      │ OTLP
                  ▼                                   ▼           ▼
              既有部署事件/日志                      演示 Collector ──► 演示 ClickHouse
                                                  （独立采样配置）   （apm.otel_traces 等）
```

| 组件 | 来源 | 版本与锁定 | 许可证 |
|---|---|---|---|
| 服务 A / B | 本目录 services/（Go，OTel SDK 显式埋点） | otel v1.44.0 / otelhttp v0.69.0 / pgx v5.7.2（go.sum 锁定，与 server/go.mod 同基线） | Apache-2.0 / MIT |
| 测试库 | postgres:16.4-alpine（与 P0 基准编排同一锁定值） | tag + index digest 双锁（compose 内） | PostgreSQL License（宽松，BSD 类） |
| 演示 Collector | otel/opentelemetry-collector-contrib（引用 deployment/docker-compose.apm.yml 锁定值） | 0.154.0 + index digest | Apache-2.0 |
| 演示 ClickHouse | clickhouse/clickhouse-server（同上引用） | 25.8-alpine + index digest | Apache-2.0 |
| 业务镜像基础 | golang:1.25-alpine / alpine:3.24（与 server/Dockerfile 同一锁定基线） | tag + digest ARG | BSD-3 / MIT 等 |

**测试库选型（PostgreSQL vs SQLite）**：选 PostgreSQL。理由：① 与产品主线数据库同族
（管理面 PostgreSQL 16+），镜像锁定值已在仓库内经评审复用；② 服务 B → 数据库是真实网络
跃点，DB Span 的 Client 语义与生产拓扑一致（SQLite 为进程内嵌入式，演示不出跨服务数据库
调用）；③ 慢查询延迟由**库内预定义函数** `demo_sleep_bounded` 执行（clamp 上限 3 秒），
满足「测试库中预先定义的有界延迟操作」；④ 驱动 pgx（MIT）与 server 同版本。SQLite 许可证
（公有领域）虽更宽，但拓扑真实性不满足演示目标。

**为什么不复制管理面**：任务书 §3.1 明确「复用现有网关、管理服务、PostgreSQL、Valkey、
Collector 与 ClickHouse 配置，禁止复制一套不随产品升级的管理面」。本目录的 Collector 与
ClickHouse 是**演示数据面实例**（复用 deployment/apm 的锁定镜像与 schema SQL，引用而非
复制），其采样配置独立；控制面（应用接入、策略发布、事件查询）一律使用既有部署。

## 3. 前置条件

- Docker（compose v2）可用，daemon 可达；curl、python3；本机 Go 1.24+ 可选（仅静态自检用，
  起栈构建在容器内进行）；
- 端口：全部对外端口绑定 127.0.0.1。startup 时由 run.sh 显式分配（缺省取回环空闲端口）；
  如需固定，设置 `DEMO_SERVICE_A_PORT` / `DEMO_SERVICE_B_PORT` / `DEMO_DB_PORT` /
  `DEMO_CH_HTTP_PORT` / `DEMO_COLLECTOR_METRICS_PORT` / `DEMO_COLLECTOR_HEALTH_PORT`
  （preflight 会校验占用）。注意：Docker Desktop 对「空宿主端口」**不会**分配随机端口
  （实测 compose v2.38 渲染为不发布），因此本夹具不沿用 P0 的「留空随机」写法；
- 网关联调（场景 2/3/6）另需：一套运行中的九章既有部署（管理面 + 网关），并完成 §4 接入；
- **管理凭据一律运行时产生**：每个 run 的全部密码由 run.sh 现场生成（/dev/urandom，写入
  `runs/<run_id>/env`，0600，cleanup 时删除）；脚本内不含任何凭据。

## 4. 产品栈接入

### 4-A. A4 自动接入（推荐，`startup --with-product`）

一条命令完成：本 run 产品栈起栈 + 真实管理 API 接入序列。接入序列全部走 HTTP 管理
API（与控制台同一路径），**不用 SQL 直接插库**：

1. 起栈：mgmt-postgres / mgmt-valkey / gateway / api（api 首启执行全部迁移）；
   api 的 `APM_CLICKHOUSE_DSN` 指向本 run 演示 ClickHouse（apm_writer 最小授权账号）；
2. 系统管理员登录（验证码从本 run Valkey 读取；首登强制改密为随机口令）；
3. 签发并导入本 run 临时 wdsp 授权（每轮随机 Ed25519 密钥对；api 镜像以
   `WDSP_LICENSE_TEST_KEYS=1` 测试构建，与 deployment/docker-compose.test-license.yml
   同一口径，仅本地/CI，不用于交付）；
4. `PUT /api/v1/system-settings` 开启 `logging.access_log_enabled`（request_id→trace_id
   关联链的 PG 证据来源）；
5. 创建 SECURITY_ADMIN 用户（临时口令→随机口令）；
6. 创建演示应用（OBSERVE，域名 `apmdemo-<run_id>.test`，上游 `service-a:8080`）并启用；
7. `POST /api/v1/gateway-config/publish` 发布并等待 SUCCESS（节点生效以发布任务终态为准）；
8. adminpatch：经 Caddy Admin Unix Socket 把活跃配置中全部 jiuzhang_guard 处理器的
   `trace_inject_upstream` 显式置 true（网关侧既有能力，ADR D6；发布侧管理面取值接线
   尚未落地，见 §8-2）。**每次重新发布都会覆盖该补丁**，`run.sh mode` 会在发布后自动重打；
9. 网关自检：经网关访问演示应用须 200。

模式切换与遥测开关（场景 3/7 用）：

```bash
bash test/security-apm-demo/run.sh mode protect           # OBSERVE→PROTECT（API 更新+发布+adminpatch）
bash test/security-apm-demo/run.sh instrumentation off    # 重建 service-a/b 关闭应用遥测
bash test/security-apm-demo/run.sh instrumentation on     # 恢复
```

### 4-B. 接入既有部署（手动步骤，脚本不代劳）

> 纪律：A1 口径（不带 --with-product）的 run.sh 从不调用管理面 API，启动失败不可能
> 修改客户站点配置。以下步骤由操作员在既有部署控制台上完成；演示结束后按相反顺序撤销
> （删除应用即停止关联，演示事件由产品保留期自然清理，本夹具不删除产品数据）。

1. 完成 §5 startup（不带 --with-product），取得服务 A 直连地址
   （`cat runs/<run_id>/ports.env` 中 SERVICE_A_ADDR）；
2. 既有部署管理面：新增应用，上游地址指向服务 A——
   - 网关与演示栈同机（Docker Desktop）：`http://host.docker.internal:<SERVICE_A_ADDR 端口>`；
   - 网关为 Linux 裸机/其他主机：`http://<演示机内网 IP>:<端口>`（compose 发布端口绑定
     127.0.0.1，跨机接入时需先用 `DEMO_SERVICE_A_PORT` 固定端口并自行放宽绑定——
     此为手动变更，非脚本默认行为）；
3. 应用域名任选（如 `apmdemo-<run_id>.test`）；防护模式按场景选择 OBSERVE（检测）或
   PROTECT（阻断）；
4. APM 总开关：产品默认关闭；如需在控制台查看演示 Trace，在「系统设置 → APM 性能监控」
   开启并按 §8 限制 3 知晓 ClickHouse 指向的含义；
5. 记录网关地址，造流时经环境变量传入（覆盖自动指向）：
   `GATEWAY_BASE_URL=http://<网关地址>:<端口> GATEWAY_HOST=apmdemo-<run_id>.test`。

## 5. 操作命令（实际入口）

全部命令从仓库根目录执行；`run.sh -h` 有完整用法。

```bash
# 0. 预检（不起栈）：工具链 / 引用资产 / 镜像锁定 / 端口 / compose 静态校验
bash test/security-apm-demo/run.sh preflight

# 1. 启动（每次运行唯一 run_id / compose project apmdemo-<run_id> / 独立数据卷）
#    内含写入通路 canary 自检：一条慢场景请求（keep-all/sampled 两形态均被 slow-keep-all
#    保留），有界等待其入库且 exporter 零失败重试；失败即中止并按归属校验回滚本 run。
bash test/security-apm-demo/run.sh startup                      # A1 形态（默认采样 keep-all）
bash test/security-apm-demo/run.sh startup --sampling sampled   # 对照形态：正常基线 0%（场景 8）
bash test/security-apm-demo/run.sh startup --with-product       # A4 形态：叠加本 run 真实产品栈
                                                                # + 管理 API 自动接入（§4-A）

# 2. 造流（正常×N / 慢查询×1 / 异常×1 / 脱敏护栏×1；产品栈存在时网关类自动指向本 run 网关）
bash test/security-apm-demo/run.sh traffic                                # 主波次（OBSERVE）
bash test/security-apm-demo/run.sh mode protect                           # 切阻断模式（§4-A）
bash test/security-apm-demo/run.sh traffic --wave protect                 # 阻断波次（场景 3）
bash test/security-apm-demo/run.sh instrumentation off                    # 关应用遥测（场景 7）
bash test/security-apm-demo/run.sh traffic --wave gwonly                  # 仅网关观测波次
bash test/security-apm-demo/run.sh instrumentation on                     # 恢复应用遥测
bash test/security-apm-demo/run.sh mode observe                           # 切回观测模式
# 接入既有部署（§4-B）时改用手动网关地址：
GATEWAY_BASE_URL=http://127.0.0.1:8081 GATEWAY_HOST=apmdemo-<run_id>.test \
  bash test/security-apm-demo/run.sh traffic

# 3. 验证（证据断言 A1-01~07 + A4-01~04 + 尾声护栏 A1-export-health；有界等待：
#    关联类 ≤45s/项，A4-04 按产品 PENDING 余量（5min）随波次时刻等待、封顶 6.5min，
#    不永久轮询；退出码 0/1/3 见下；自动识别采样形态——sampled 形态下 A1-02/A1-05 判
#    SKIP，见 §7 表注；A4 断言在无产品栈或无对应波次时判 SKIP）
bash test/security-apm-demo/run.sh verify

# 4. 清理（双标签归属校验后仅删本 run 容器/网络/卷；证据目录保留，
#    密码 env / 授权私钥 / 会话 Cookie 删除）
bash test/security-apm-demo/run.sh cleanup
```

- 多 run 并存时，`traffic/verify/cleanup` 用 `--run-id <run_id>` 指定；缺省取最近一次
  （`runs/latest`）；
- 退出码：0 = 全部执行项 PASS；1 = 存在 FAIL；2 = 用法/预检拒绝；3 = 存在 BLOCKED/SKIP。
  **没有数据就是 FAIL/BLOCKED，脚本不会伪造通过。**

## 6. 演示采样配置（独立于产品默认值）

| 配置 | tail_sampling 基线 | 用途 |
|---|---|---|
| `collector/demo-keep-all.yaml`（默认） | 错误/慢≥2s/WAF 高风险全留 + 正常 100% | 场景 1-7：每条 Trace 确定性可见 |
| `collector/demo-sampled.yaml` | 错误/慢≥2s/WAF 高风险全留 + 正常 0% | 场景 8：「显式不采样」决策证据 |

与产品基线（central-gateway.yaml：正常 5%）的差异是**演示确定性**选择：0% 让「不采样」
在少量请求下必然发生。NOT_SAMPLED_CONFIRMED 的证据链（任务书 §4.3：未采样需采样决策证据）：
① Collector 自监控 `otelcol_processor_tail_sampling_new_trace_id_received` > 0
   （trace 已进入决策管线）；
② 决策计数 `otelcol_processor_tail_sampling_global_count_traces_sampled` 的
   `decision="not_sampled"` 与 `decision="sampled"` 均 > 0（丢弃与保留两条路径都真实
   发生，互相印证配置生效）；
③ 演示 ClickHouse 中按正常流量的 trace_id 在决策窗口后查无（地面真值）。
三者齐备 verify 才报 PASS，正常 trace 若入库直接 FAIL，其余缺口如实 BLOCKED/UNKNOWN
（原始指标快照存 `runs/<run_id>/collector-metrics-snapshot.txt`）。
实测备注（v0.154.0）：`otelcol_exporter_sent_spans/send_failed_spans` 对 clickhouse
exporter 的重试语义不完整（失败按 span 计数、重试成功不计 sent），故 exporter 计数
只作诊断字段，不作 PASS 判据；contrib 尾采样不输出逐 trace 决策日志。

## 7. 八个必备场景：操作、观察点与预期事实

A1 交付**数据面真实证据层**（Trace/DB Span/异常/采样决策，经演示 ClickHouse 直查核对，
断言 A1-01~07）；A4 交付**产品栈管理 API 对账层**（断言 A4-01~04：trace-search 的
availability/correlation、安全事件、access_logs，原始响应落 `runs/<run_id>/evidence-a4/`）。
页面 UX 属 A3 子阶段（组件测试层），下表「页面观察点」为控制台最终形态。

| # | 场景 | 操作 | 可验证事实（断言 ID） | 页面观察点 |
|---|---|---|---|---|
| 1 | 正常调用 | `traffic`（normal 类，直连 A） | A1-02：每条 Trace 含 a Server→a Client→b Server→b DB 四层 Span 且父子链正确（spans-*.jsonl 原始证据） | 调用链检索按 trace_id 可见瀑布 |
| 2 | 命中但观察 | `--with-product` 启动（应用 OBSERVE）后 `traffic`（attack 类） | A1-07 透传分支 + **A4-01**：每条攻击的安全事件（action≠BLOCK）与同 request_id 的上游 Trace 经管理 API 相互定位（trace-search correlation=MATCHED、trace_id 与造流记录一致、详情含 demo-service-a/b 且 observed_sources 含 GATEWAY+OTEL）；命中不等于阻断 | 事件详情「查看关联调用链」直达目标 Trace |
| 3 | 网关阻断 | `mode protect` → `traffic --wave protect` | A1-07 阻断分支 + **A4-02**：攻击全部 403；源站（服务 A）`/demo/stats` 计数 delta 仅含透传请求（攻击未到达源站）；CH 无应用 Span；安全事件/访问记录 action/waf_action=BLOCK；trace-search correlation=**NOT_EXPECTED**（无应用 Span 是预期结果） | 事件展示最终执行模块与阻断证据链 |
| 4 | 慢 SQL | `traffic`（slow 类，场景头 slow-sql） | A1-03：目标 Trace 内 `demo_sleep_bounded` DB Span 时长 ∈ [2s,4s]，db.statement 为常量语句（SQL 指纹 = hex(MD5(该常量))）；A4-03 复核慢 Trace 经管理 API 可定位 | SQL 诊断页指纹与该 Trace 一致 |
| 5 | 应用异常 | `traffic`（exception 类） | A1-04：响应 500 且 Trace 含 Error Span + exception 事件；403 不能冒充应用异常 | 异常分析页出现对应指纹 |
| 6 | 同时但无关 | 主波次内 attack（经网关）与 slow 并存 | **A4-03**：攻击 request_id/trace_id 与慢查询 trace_id 互不交叉；攻击 Trace 的 SQL 指纹列表（/apm/sql?trace_id=）无慢 SQL 指纹、慢 Trace 有（瀑布属性按产品数据最小化口径不含原始 db.statement，交叉判定用 hex(MD5(常量语句)) 指纹）；本断言只证「按 ID 可区分」，**不断言因果**（因果纪律属 A3 页面层） | 界面仅说明时间关联 |
| 7 | 仅网关观测 | `instrumentation off` → `traffic --wave gwonly` | **A4-04**：业务照常 200（遥测关闭不影响业务）；access_logs 网关记录可用；trace-search 无 MATCHED（PENDING 有界等待后落 NOT_FOUND/UNKNOWN；产品 PENDING 余量=发生时刻起 5min，availability.go correlationPendingMargin，verify 自动按波次时刻等待）；trace 详情 observed_sources 仅 GATEWAY、无 Span；`/apm/sql?trace_id=` 空列表不伪造；CH 地面真值零 Span | 仅入口延迟/TTFB；SQL/代码级耗时不可用如实标注 |
| 8 | 数据面异常-停采样 | `startup --sampling sampled` → `traffic` → `verify` | A1-06：§6 三件套证据链（决策计数 not_sampled>0 且 sampled>0 / 正常 trace CH 查无）；证据不足如实 BLOCKED | availability 返回 NOT_SAMPLED_CONFIRMED（A2 接线） |

> sampled 形态下 A1-02（正常链路）与 A1-05（脱敏核对）判 **SKIP 而非 FAIL**：正常流量
> （含脱敏护栏请求）按 tail_sampling 设计被丢弃，CH 查无是预期而非缺陷，丢弃事实本身由
> A1-06 断言；链路层次与脱敏核对以 keep-all 形态为准。verify 自动识别形态，无需手工选择。

场景 8 的另外两个子场景（停止 Collector、阻断 CH 查询）为**手动故障注入**：
`docker compose -p apmdemo-<run_id> --env-file runs/<run_id>/env -f test/security-apm-demo/docker-compose.security-apm-demo.yml stop collector`
（仅本 project），观察业务无影响（fail-open）、遥测有界丢弃计数；恢复后遥测继续。
阻断 CH 查询对应的管理台展示（UNAVAILABLE/PARTIAL 而非健康空图）属 A2 验收（APMD-009）。

## 8. 已知限制（如实声明）

1. **APM 总开关默认关闭**：演示栈自身不依赖总开关（直查演示 ClickHouse），但控制台
   查看需开启（§4-4）；总开关关闭时 APM 接口整体 503 是产品既定语义，演示不得绕过。
2. **网关 → 上游 traceparent 注入的开启方式（A4 实测路径）**：网关侧开关
   `trace_inject_upstream` 已实现（gateway/modules/jiuzhang_guard/apiprotect.go serveNext），
   但发布侧管理面取值接线未落地（server/internal/gatewayconfig/guard.go 字段注释：
   恒 false 不下发）。A4 演示由 adminpatch 一次性容器在每次发布后，经 Caddy Admin
   Unix Socket 把活跃配置中的 jiuzhang_guard 处理器显式置 true（运行态补丁，不改产品
   代码、不改发布侧行为；重新发布即被覆盖，`run.sh mode` 自动重打）。因此网关联动断言
   （A1-07 / A4-01~04）具备完整的「网关 access_logs.trace_id ↔ 业务 Span 同 trace 续接」
   证据链；管理面开关接线属后续工作包（docs/APM_ONBOARDING_GUIDE.md §6 同一事实）。
   服务 A → B 之间的 W3C Trace Context 续接不依赖该开关（otelhttp 自动透传）。
3. **内部 request_id 不可由外部伪造**：发布侧 Caddy headers handler 覆盖写入
   X-Request-Id（server/internal/gatewayconfig/headers.go buildChainHandles），外部同名头
   不污染内部关联；造流记录网关响应头 X-Jiuzhang-Request-ID 作为内部请求 ID 证据。
4. **演示 Collector 为明文 OTLP**（compose 内网、4317/4318 不发布宿主机）：生产中央网关
   强制 mTLS（central-gateway.yaml receiver client_ca_file）；演示不签发私有 CA 证书，
   遥测内容全为合成数据。
5. **采样证据口径**：A1-06 用 tail_sampling 决策计数器（v0.154.0 实测输出，Development
   稳定性指标）+ CH 地面真值构成证据链；contrib 尾采样不输出逐 trace 决策日志，单条
   trace 的「未采样」判定以计数器 + 入库缺失联合成立，证据不足时如实 UNKNOWN（不凭
   「没查到」下结论——与任务书 §4.3 reason 纪律一致）。exporter 发送计数器仅作诊断
   （§6 实测备注）。
6. **演示 ClickHouse 的指向（A4 已自动化）**：`startup --with-product` 在本 run 的
   管理 server 环境注入 `APM_CLICKHOUSE_DSN` 指向演示 ClickHouse（run 级随机口令，
   不入证据），控制台/管理 API 因此可直接查询演示 Trace 与关联结果。接入**既有部署**
   （§4-B）时仍需手动把既有部署的 APM ClickHouse 连接指向演示实例（可回退；操作员
   决策）。A1 验证始终不依赖该指向——直查演示实例即可。
7. **场景开关仅存在于测试业务**（DEMO_SCENARIOS_ENABLED，代码默认关）：只接受
   slow-sql / exception 白名单；慢延迟由库内函数 clamp ≤3s；**不接受任意 SQL、命令或
   外部 URL**；服务 B 地址来自 compose 固定环境变量，不取自请求。
8. **清理边界**：cleanup 只删本 run 的 compose project 资源（容器/网络/卷），
   构建镜像（固定 tag `jiuzhang-apmdemo-service-{a,b}:a1`）保留作缓存，可按需手工
   `docker image rm`；既有部署中的应用与安全事件属产品数据，由操作员按 §4 逆序撤销。
9. **ClickHouse 25.8 物化视图 INVOKER 权限链（实测）**：向 `apm.otel_traces` INSERT 时，
   其物化视图以**写入者身份** SELECT 源表，且 002_aggregates.sql 的聚合链是两级级联
   （otel_traces→分钟表→小时/天表，中间表均为下游 MV 的源表）。缺 SELECT 授权时的实测
   表现是：基表插入成功、MV 推送报 code 497、exporter 重试叠加重复行后丢弃（基表可见
   重复数据，极具迷惑性）。因此 demo 的 apm_writer 授权为
   `INSERT ON apm.otel_traces` + `SELECT ON apm.*`（独立实例、随机密码、用完即毁，
   授权面可控）；startup 的 canary 自检会把该类故障在起栈阶段拦下。注意：
   `deployment/apm/clickhouse/README.md` 的「仅 INSERT」授权建议在同版本 CH + 本 schema
   下会遇到同类报错，其修复口径属生产工作包，本夹具不改动 deployment/（已在 WORKLOG
   记录，供 P1 后续阶段复核）。

## 9. 目录与文件

```text
test/security-apm-demo/
├── README.md                              # 本文（唯一操作手册）
├── docker-compose.security-apm-demo.yml   # 数据面编排（无 name/container_name，标签+端口按 run 参数化）
├── docker-compose.product-stack.yml       # A4 产品栈叠加（mgmt PG/Valkey + gateway + api + adminpatch[profile=tool]）
├── run.sh                                 # preflight/startup/traffic/verify/cleanup/mode/instrumentation
├── collector/
│   ├── demo-keep-all.yaml                 # 演示采样配置（默认：正常全保留）
│   └── demo-sampled.yaml                  # 演示采样配置（对照：正常基线 0%）
├── db-init/001_demo_schema.sql            # 测试库 schema + 有界延迟/合成错误函数
├── services/                              # 合成业务（独立 Go 模块，锁定版本）
│   ├── Dockerfile                         # 多阶段构建（tag+digest 双锁基础镜像）
│   ├── go.mod / go.sum
│   ├── cmd/service-a/                     # HTTP 入口 → 调用 B；/demo/stats 源站计数
│   ├── cmd/service-b/                     # → 独立测试库（DB Span 显式埋点）
│   ├── cmd/adminpatch/                    # A4 运行态补丁：经 Caddy Admin Socket 开 trace_inject_upstream
│   └── internal/                          # demootel（OTel 初始化/OTEL_SDK_DISABLED）/ democommon（白名单校验）
└── runs/                                  # 运行产物（gitignore）：env(0600)/ports/traffic/verify/evidence-a4 证据
```

## 10. 静态验证（CI/复核可直接重跑）

```bash
docker compose -f test/security-apm-demo/docker-compose.security-apm-demo.yml config --quiet
cd test/security-apm-demo/services && go build ./... && go vet ./... && go test ./...
bash -n test/security-apm-demo/run.sh
bash test/security-apm-demo/run.sh preflight   # 含镜像锁定与引用资产复核
```

## 11. 客户调查任务脚本（冻结文本，供 APMD-017）

> **APMD-017 状态：BLOCKED（未执行）**。该验收要求「≥3 名未参与开发的人员」在不知情
> 前提下计时完成调查，当前不具备人员条件，本子阶段不执行、不伪造计时数据。以下为
> 冻结的任务脚本与评分口径，人员条件具备后照此执行即可，无需再改脚本。

**任务背景（发给参与者的唯一说明）**：

> 你是一名安全运营人员。昨晚演示应用 `apmdemo-<run_id>.test` 触发了多条安全事件，
> 其中一条的**请求 ID** 为 `<从主波次 traffic.jsonl 取一条 attack-sqli 记录的
> jiuzhang_request_id>`。请使用控制台回答下列问题，并给出你下结论的依据（截图或
> 页面路径均可）：
>
> 1. 这次请求最终**有没有到达业务源站**？
> 2. 如果是 OBSERVE 透传：这次请求在上游业务里**做了什么**（调用了哪些服务、执行了
>    哪条 SQL、耗时多少）？
> 3. 同一时段还有一条约 2~3 秒的慢查询，它和这次攻击**是不是同一次请求**？
> 4. 你认为这个事件**该怎么处置**（放行观察 / 转阻断 / 误报），为什么？

**正确回答标准（评分员用，参与者不可见）**：

| 问题 | 正确回答 | 判错情形 |
|---|---|---|
| 1 | OBSERVE 波次：已到达源站（事件 action≠BLOCK，且网关 access_logs 显示透传）；PROTECT 波次：未到达（403，源站计数不变） | 只凭「有安全事件」断言已被阻断，或反之 |
| 2 | 经事件详情/关联检索定位到同 request_id 的调用链，答出 demo-service-a → demo-service-b → `demo_sleep_bounded` 常量 SQL（或该 trace 实际 SQL 指纹），耗时与瀑布一致 | 编造链路内容；把别条 trace 的 SQL 安到本 trace |
| 3 | **不是同一次请求**：两者 request_id/trace_id 不同，仅时间相近（攻击 trace 内无慢 SQL Span） | 凭时间相近断言因果/同一请求 |
| 4 | OBSERVE 下「继续观察、评估是否转 PROTECT」或给出等价合理处置，且能指出事件上的最终执行模块证据 | 无依据拍脑袋；声称已被阻断（与实际 action 矛盾） |

**操作动线（脚本化步骤，供计时与观察记录）**：

1. 事件中心 → 安全事件列表 → 按请求 ID 检索（`GET /api/v1/security-events?request_id=`）。
   预期：事件存在，action 字段为最终执行结果（OBSERVE 波次非 BLOCK）。
2. 事件详情 → 「查看关联调用链」（关联检索 `GET /api/v1/apm/trace-search?request_id=`）。
   预期：correlation.state=MATCHED，候选 trace_id 唯一且可点击跳转。
3. 调用链详情（`GET /api/v1/apm/traces/{trace_id}`）。
   预期：瀑布含 demo-service-a/b 双层服务；availability.observed_sources 含 GATEWAY+OTEL。
4. SQL 诊断页按 trace 过滤（`GET /api/v1/apm/sql?trace_id=`）/异常分析页。
   预期：trace 级定位到该请求真实执行的 SQL 指纹/异常指纹；对「仅网关观测」形态
   必须如实显示不可用而非空图假数据。
5. 回到事件详情，给出处置结论。
   预期：参与者能指出事件 action 与是否到达源站之间的关系。

**执行纪律**：参与者 ≥3 人且均未参与本子阶段开发；逐人独立计时（从发题到交出
4 题答案）；记录每步用时、走错的页面、最终答案对错；结果连同原始操作记录归档到
`runs/<run_id>/apmd-017/`（若执行）。任何人代答、提示答案或预先培训动线，该人次
作废并如实记 BLOCKED。

---

Copyright © 聚信得仁
All Rights Reserved.
