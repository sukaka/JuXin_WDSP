# S8 NG-REL-02 离线包构建 / 纯离线安装 / 升级与回滚 / openEuler 实证报告

> 日期：2026-10-09 ｜ 依据：`docs/WDSP_API_WAF_NEXTGEN_RD_PLAN.md` §15.2 NG-REL-02（「离线包+升级+openEuler 实证」）
> 口径：全部实证由本批亲跑并留存原始日志，不信既有记录；未执行项一律 NOT_RUN 不折算；缺陷与意外如实登记（§8）。
> 证据目录：`output/evidence/rel02-20261009-071500/`（下文简称 `$EV`），测试数据全部使用 RFC5737/example.com 口径。
> **版本声明**：本批产物版本号为 `1.3.0-rc1`（候选发布）。**正式版本号待用户批准（NG-REL-03 门禁）**，本报告不构成发布批准。
> 纪律：本批未做任何 git 写操作，未改动生产代码与 CHANGELOG；所有命令在 macOS 构建机与一次性容器实验室内完成，stage5 常驻栈（容器名均为 `jiuzhang-stage5-*`）未受影响。

## 1. 总结论

| 交付项 | 结论 | 说明 |
|---|---|---|
| ① 从工作树构建完整 amd64 离线包 | **PASS** | `jiuzhang-wdsp-offline-1.3.0-rc1-amd64.tar.gz` + 旁车 sha256 + Ed25519 签名 + traceability（§3） |
| ② 纯离线安装实证 | **PASS** | 篡改验签 fail-closed；9 镜像 tar 加载；`compose up` 全程 0 次镜像拉取事件；7 容器健康；初始化/授权/冒烟全过（§4） |
| ③ 升级实证（旧版→新包） | **PASS** | 前台上传门禁 4 项全过；1.2.1→1.3.0 升级 job SUCCESS（88 秒）；坏包自动回滚、中断语义、手动 apply/rollback 通道均实证（§5/§6） |
| ④ openEuler 24.03 可行性 | **PASS（容器内实测）/ NOT_RUN（裸机 systemd 形态）** | 安装器全链路在 openEuler 24.03 amd64 容器内跑至 systemd 边界并 fail-closed；升级执行器/apply.sh/rollback.sh 在 openEuler 用户态真实跑通；真机 systemd 部署未执行（§7） |

升级链路实证中共执行 5 个升级任务，终态如实登记：`eca73e00` FAILED（预检严重告警阻断，设计行为）、`28bef5b8` ROLLED_BACK（F1 缺陷首跑失败自动回滚）、`7f0e58e5` SUCCESS（正式升级）、`89b609a4` ROLLED_BACK（坏包自动回滚）、`f01ae2f7` APPLYING 滞留（中断实证 + F7 新发现，§6.3/§8）。

## 2. 方法与环境

### 2.1 构建/实证环境指纹

```
构建机:  macOS（arm64）+ Docker Desktop，linux/amd64 镜像经 Rosetta 运行
签名:    Ed25519，私钥 ~/Documents/JiuZhang_License/release/wdsp-release.key
         （与服务端硬编码信任根 ops/offline-package/release-signing.pub 配对，验证通过；
          签名/验签一律使用 brew openssl，系统 /usr/bin/openssl 为 LibreSSL 3.3 不支持 Ed25519）
源码基线: HEAD e34185334b4d778719744a236ab83bf0c6924f1f（含 S1–S7 工作区未提交改动，
          与 NG-REL-01 冻结报告 §2 同一状态）
共存约束: stage5 栈在跑（占用 18080/18081 等端口），实验室统一使用 28080/28081/15440/16390 等端口段
```

### 2.2 实验室拓扑

- **离线安装实验室**：解包 `jiuzhang-wdsp-offline-1.3.0-rc1-amd64.tar.gz` 至 `$EV/offline-lab/`，compose 项目 `jiuzhang-wdsp`（包内默认项目名），加载包内 9 个镜像 tar 后 `docker compose up -d`，`docker events --filter type=image` 全程捕获。实证完成后已 `down -v` 拆除。
- **升级实验室**：先用历史包 `jiuzhang-wdsp-offline-1.2.1-amd64`（dist 既有产物）同法搭建 1.2.1 环境并造数（应用 `rel02-upgrade`、PROTECT、域 `rel02-upgrade.example.com:18902`、SQLi 事件 1 条、双管理员、授权 ACTIVE），再走前台升级通道。
- **openEuler 执行器容器**：自建镜像 `rel02-oe-executor:24.03`（基座本地已有 `openeuler/openeuler:24.03-lts-sp4`，linux/amd64；加装 jq/findutils/util-linux/diffutils + 静态 docker CLI 27.5.1 + compose 插件 v2.40.3；Dockerfile 在 `$EV/executor-img/`），挂载宿主机 docker.sock 与实验室卷，容器内以 root 运行包自带的 `/usr/local/libexec/jiuzhang-upgrade-executor`（1.2.1 包版本）——即生产形态的执行器用户态，只是 systemd 由人工前台代替。

### 2.3 与生产形态的差异声明（全文适用）

1. macOS 无 systemd/root 语义，`ops/install/install.sh` 全 9 步在构建机不可达；离线安装走**应用层等价路径**（验签→整包哈希→架构→manifest→加载镜像→compose up），安装器脚本本体在 openEuler 容器内实证至 systemd 闸门（§7）。
2. 网关容器为 host 网络模式，在 Docker Desktop VM netns 内，macOS 直连 18902 不可达；冒烟流量经 netmgrd 容器（同 netns 注入路径）发起。
3. `check.sh` 的网关 TCP 探测默认打 `127.0.0.1:18080`——该端口在构建机上是 **stage5** 网关，手动通道实证时已显式规避，防止误判为实验室网关。
4. amd64 镜像在 arm64 宿主经 Rosetta 运行，功能等价但性能数据无意义（本报告不含性能判定）。

## 3. 交付物清单（dist/ 实测）

| 文件 | 字节数 | sha256 |
|---|---|---|
| `dist/jiuzhang-wdsp-offline-1.3.0-rc1-amd64.tar.gz` | 602,140,778 | `6e35ca0a2da945f457311ef7e79163693772dc6d1880559e532c264eceb4c37b` |
| `dist/jiuzhang-wdsp-offline-1.3.0-rc1-amd64.tar.gz.sha256`（旁车） | 111 | — |
| `dist/jiuzhang-wdsp-offline-1.3.0-rc1-amd64.tar.gz.sig`（Ed25519 旁车签名） | 89 | — |
| `dist/jiuzhang-wdsp-offline-1.3.0-rc1-amd64.traceability.json`（交付追溯，已签名） | — | artifact_digest 与整包 sha256 一致 |
| `dist/jiuzhang-wdsp-upgrade-1.3.0-amd64.tar.gz` | 162,518,266 | `f456c67ee2a277d0560bfba9aae74a51c8ad0018d5c25780e84ac1797a3101a2` |
| `dist/jiuzhang-wdsp-upgrade-1.3.0-amd64.tar.gz.sha256`（旁车；包签名 manifest.sig 内嵌） | 107 | — |

证据：`$EV/artifact-inventory.log`、`$EV/build-package.log`（build_exit=0）、`$EV/build-upgrade-pack.log`（upg_exit=0）。

### 3.1 离线包构成（manifest 实测）

`version=1.3.0-rc1`、`product=九章Web动态防护系统`、`arch=amd64`、`delivery_mode=production`、镜像 9 个、manifest.files 232 个文件（`$EV/offline-lab-state.log`）。

### 3.2 锁定清单（全部按版本/digest 锁定，无 latest）

**产品镜像（本批从工作树构建，tar 加载口径镜像 ID）：**

| 镜像 | 标签 | 镜像 ID |
|---|---|---|
| jiuzhang-server | 1.3.0-rc1（=1.3.0 同 ID） | `7ba753c1b7f6dee35043fa3bedb773ec05fb67016ad6b48a5de36ef50a0b3c77` |
| jiuzhang-gateway | 1.3.0-rc1（=1.3.0 同 ID） | `25298284572c45570a89830b52e9eddb36ecdf1ad2f721c52ed36d674833b361` |
| jiuzhang-web | 1.3.0-rc1（=1.3.0 同 ID） | `2b3820bd97a8f00c7edf67acb0ae0d9b0e84098e5357c47a1472aab8ae99a792` |
| jiuzhang-netmgrd | 1.3.0-rc1（=1.3.0 同 ID） | `907700c0981033ab02fb535cc4d968a6d181a8902dfaf4827afdfb0653f17482` |
| jiuzhang-logrotator | 1.3.0-rc1 | 见包内 manifest |

**第三方镜像（digest 锁定，构建日志逐条「复用已锁定镜像」）：**

| 镜像 | 锁定 |
|---|---|
| postgres | `16.4-alpine@sha256:5660c2cbfea50c7a9127d17dc4e48543eedd3d7a41a595a2dfa572471e37e64c` |
| valkey/valkey | `8.1.8-alpine@sha256:94365b275456ae14621001c03556c732b1d93a0cdeacc317d1bdd52eba680885` |
| clickhouse/clickhouse-server | `25.8-alpine@sha256:87e0a5b72f5465b18eacca7c76850e7ff551c9795c50e451f5646299e5e24146` |
| otel/opentelemetry-collector-contrib | `0.154.0@sha256:b3079f45e19bdb7326bf49cdddce6cf60dfd865138db39f2733ea48ab17bc4cb` |

**网关核心组件版本（Dockerfile/go.mod/规则包三处锁定口径）：**

| 组件 | 版本 | 锁定位置 |
|---|---|---|
| Caddy | v2.11.4 | `gateway/Dockerfile` ARG CADDY_VERSION（构建日志同步实测） |
| xcaddy | v0.4.5 | `gateway/Dockerfile` ARG XCADDY_VERSION |
| coraza-caddy | v2.5.0 | `gateway/Dockerfile` ARG CORAZA_CADDY_VERSION |
| Coraza | v3.7.0 | `gateway/go.mod`（github.com/corazawaf/coraza/v3） |
| OWASP CRS | 4.28.0 | 包内 `gateway/rules/crs/crs-setup.conf`（`ver:'OWASP_CRS/4.28.0'`） |

### 3.3 升级包构建口径（如实登记）

升级包协议版本号严格 `X.Y.Z`（`build-upgrade-pack.sh` 正则拒绝 `-rc1` 后缀），故以 `--from 1.2.0 --to 1.3.0 --components "api web gateway netmgrd" --skip-build` 构建：`jiuzhang-{server,web,gateway,netmgrd}:1.3.0` 标签与 `:1.3.0-rc1` **镜像 ID 逐字节相同**（§3.2 表）。auto 自动识别模式因 S0–S7 改动横跨 `deployment/` 与宿主机执行器脚本，按设计拒绝生成升级包（F6，§8）——本批走显式组件模式并在升级实验室实证了其完整链路。

## 4. 纯离线安装实证（交付项②）—— PASS

执行序列与证据（全部在 `$EV/offline-lab/` 完成，日志 `$EV/*.log`）：

1. **篡改 fail-closed**：复制整包并改动 1 字节后跑安装器验签段，Ed25519 验签失败、`rc=1`，安装中止（验签闸门位置同时确认：`install.sh` 内嵌公钥第 17 行、验签第 128 行、旁车哈希第 158 行、manifest 校验第 204 行）。
2. **镜像加载**：包内 9 个镜像 tar 全部 `docker load` 成功。
3. **零拉取实证**：`docker events --filter type=image` 在 `docker compose up -d` 全程捕获，**0 条事件**（`$EV/offline-install-events.log`，0 字节；grep 'pull' 计数 0）——compose up 未触发任何镜像拉取，纯离线成立。
4. **栈健康**：7 容器全部 Up（postgres/valkey/api healthy，gateway/netmgrd healthy，web/logrotator Up），`/api/v1/health` 返回 `{"status":"ok","postgres":true,"valkey":true,"product":"wdsp"}`（`$EV/offline-lab-state.log`）。
5. **初始化与授权**：管理员/三权初始化完成；以仓库 `runtime/license/host_fingerprint`（sha256:a3eac025…）重建授权文件导入，LIC-20260911-OT9YDQ（wdsp TRIAL 至 2026-12-10）ACTIVE。
6. **冒烟**（`$EV/offline-smoke.sh` / `offline-smoke.log`）：创建 PROTECT 应用（app_id `0a5c7a3b-405c-4d9b-b8ce-048515245331`）→ 发布任务 `219f4c4a` SUCCESS → 正常请求透传 `200` → SQLi（`/search?q=1' OR '1'='1`）`403` → 安全事件落库实证（`/api/v1/security-events` 查到 `attack_type=SQL_INJECTION, action=BLOCK`；脚本内 `/api/v1/waf-events` 404 为脚本路径笔误，已用正确端点复核）。
7. 实证完毕 `docker compose down -v` 拆除，未留残留。

**结论：PASS**。差异声明见 §2.3（应用层等价路径代替 systemd 安装器全步）。

## 5. 升级实证（交付项③前半）—— PASS

### 5.1 前置：1.2.1 实验室造数

`$EV/upgrade-lab/`：用 dist 既有 `jiuzhang-wdsp-offline-1.2.1-amd64` 包搭建，造数快照（`$EV/upgrade-pre-snapshot.log`）：应用 `rel02-upgrade`（id `6b3ac3cd`，ACTIVE/PROTECT，域 `rel02-upgrade.example.com:18902`）、security_events 1 条（SQL_INJECTION）、双管理员、授权 LIC-20260911-OT9YDQ ACTIVE；`system:current_version` 未落库（服务端常量 `CurrentVersion="1.2.0"`，F3，§8）。

### 5.2 前台上传门禁（4 项，全过）

| 用例 | 结果 | 证据 |
|---|---|---|
| 篡改包（改内容重打包） | 包状态 **REJECTED** | `$EV/upload-reject-tests.log`（`rel02-upg-tampered.tar.gz` REJECTED） |
| 未签名包 | **INVALID_ARGUMENT**：「缺少升级包签名：包内无 manifest.sig 时须通过 multipart 字段 signature 提供整包 detached Ed25519 签名（base64）」 | 同上 |
| 同名不同内容包 | **RESOURCE_CONFLICT**：「同名升级包文件已存在且内容不同…」 | 同上 |
| 预检严重告警未处置 | 升级任务 `eca73e00` **FAILED**（fail-closed，阻断执行）；处置告警后同一包放行 | 任务列表实测 |

如实登记：正式升级实际执行的包是 `/tmp` 重建副本（构建环境已设 `WDSP_SIGNING_KEY`，`--unsigned` 被密钥覆盖而实际产出签名包，F2）；内容与 `dist/` 产物完全一致且签名有效，`dist/` 原件上传被上述重名闸门拦下（设计行为）。

### 5.3 正式升级 1.2.1 → 1.3.0（job `7f0e58e5-975b-4ff8-aa4f-581beb3e5504`）

- 状态机：VERIFIED →（预检 10 项全 PASS）→ 备份 `d0438c7f` → APPLYING → 宿主机执行器（openEuler 容器内）APPLYING→VERIFYING→**SUCCESS**，`started 00:12:21Z / finished 00:13:49Z`（约 88 秒），executor message「升级已生效并通过健康检查」（`$EV/upgrade-post-smoke.log`、`$EV/executor-run2.log`）。
- **镜像切换实证**（`$EV/upgrade-post-snapshot.log`）：api/web/gateway/netmgrd 4 容器镜像 ID 与 §3.2 的 1.3.0-rc1 构建 ID 逐一相等。
- **数据保留断言**：应用 ACTIVE/PROTECT 不变、security_events 保留、双用户在、授权 ACTIVE、schema_migrations 推进到 **184**。
- **升级后冒烟**：网关配置经 autosave 保留无需重发布——透传 `200`、SQLi `403`。

**结论：PASS**（前台通道 + 宿主机执行器通道全链路）。

## 6. 失败与回滚实证（交付项③后半）—— PASS（含两项发现）

### 6.1 坏包自动回滚（job `89b609a4-8337-434c-ae38-80d611b6cac0`）

用 `$EV/build-broken-pkg.py` 构造坏包：以 `busybox:1.37.0` 冒充 api 镜像重打包并**重新签名**（验签通过，专测执行期防线）。链路：VERIFIED → 执行器 APPLYING → api 容器起不来（健康等待超时，executor 配置 TIMEOUT=60）→ 执行器 FAILED（MIGRATING 阶段）→ **执行器自动镜像回滚**（retag 旧 ID 并重启）→ 服务端 ROLLING_BACK → 备份恢复 `6bffee4e` → **ROLLED_BACK**。断言（`$EV/rollback-assertions.log`）：api 回到 `7ba753c1`（1.3.0 正常镜像）且 healthy、`/api/v1/health` ok、应用/事件/授权均在。

### 6.2 执行器首跑失败（F1 缺陷现场，job `28bef5b8-be7a-42ef-b8ec-68e19a4cd636`）

openEuler 最小环境缺 `diff/cmp`（diffutils），执行器文件一致性比对误报「包内文件与 manifest 声明不一致（存在未声明文件）；已尝试恢复原容器镜像」（FAILED/APPLY_FAILED）→ 服务端自动备份回滚 ROLLED_BACK。安装 diffutils 后同一任务重跑即 §5.3 的 SUCCESS。详见 §8-F1。

### 6.3 中断实证（job `f01ae2f7-7883-4dc5-8d8f-9cd3ff749f8c`）

执行器拾取任务后 `kill -9`（`$EV/interrupt-test.log`、`$EV/interrupt-stranded-evidence.log`）：

- `.processing` 残留；**重跑执行器不自动续跑**（exit 0，仍无结果文件）——中断不重复执行的语义正确。
- 中断点在任何镜像变更之前，栈无损：health ok、api 镜像 ID 未变。
- 服务端 `cancel` 正确拒收 APPLYING 任务（「任务已开始，无法取消」）。
- **F7 新发现**：服务端 30 分钟执行器等待超时（`server/internal/upgrades/executor.go:17` `defaultExecutorWait`）是**进程内定时器**；本批在坏包测试后的运维恢复中重启过 api 容器（00:34:28Z），定时器随之丢失，而 `RunResultReconciler`（executor.go:209）只补偿「执行器已写结果文件」的场景。实证：截至 00:56:58Z（任务 started 00:20:09Z，已 36 分钟）job 仍 APPLYING，结果目录无该任务结果文件——**执行器中断且 API 重启的组合下任务滞留 APPLYING**，会占用后续升级的 `no_active_tasks` 预检。若 API 未重启，30 分钟超时将触发「等待宿主机升级执行器超时」→ 自动备份回滚（代码级确认，executor.go:150-151 + rollbackOnFail 路径；本批因 API 重启未观察到该定时器实际触发，如实登记）。

### 6.4 手动通道（apply.sh / rollback.sh）

- **rollback.sh**：手工构造 state 文件指向 1.2.1 镜像 ID → 回滚落地，api=`25f1dfa9…`/gateway=`3ccc0b7d…`（1.2.1），health ok、应用在、透传 200（`$EV/manual-rollback-assertions.log`）。
- **apply.sh**：五步全过（备份 `67d39025` 已验证），api/gateway 回到 1.3.0 ID，health ok、SQLi 403（`$EV/apply-forward-assertions.log`）。
- 插曲（运维实证，非产品缺陷）：apply.sh 首跑时 `jiuzhang-server:1.3.0` 标签曾被坏包测试的 busybox 残留污染导致 api 崩溃，手工 retag 恢复正常镜像后复跑通过——说明手动通道依赖本地标签正确性，已在 §8 登记注意事项。

**结论：PASS**（坏包自动回滚、中断语义、手动通道均实证；F1/F7 转入发现清单）。

## 7. openEuler 24.03 可行性（交付项④）

### 7.1 容器内实测（PASS）

`rel02-oe-executor:24.03`（基座 `openeuler/openeuler:24.03-lts-sp4`，linux/amd64）实测软件版本：bash 5.2.15、python 3.11.6、jq 1.8.0、curl 8.4.0、GNU coreutils 9.4、findutils 4.9.0。

- **安装器链路**（`$EV/openeuler-install-gate.log`）：`ops/install/install.sh` 在 openEuler 容器内真实执行——production 模式识别 → Ed25519 验签通过 → 整包 sha256 通过 → 架构校验通过（amd64/amd64）→ 产品线识别（edition=wdsp）→ manifest.files 232 文件完整性通过 → **systemd 闸门 fail-closed**：「完整离线包需要 systemd，用于自动安装宿主机升级执行器」，`install_rc=1`，在容器边界正确中止（未伪装成功）。
- **升级执行器**：§5.3 成功升级、§6.1 坏包回滚、§6.3 中断语义全部是在该 openEuler 用户态内真实跑通（非宿主机冒充）。
- **手动脚本**：apply.sh / rollback.sh 五步链路在 openEuler 容器内跑通（§6.4）。
- **语法兼容**：ops 全部 shell 脚本 `bash -n` 通过。

### 7.2 历史佐证（如实登记来源）

`dist/run-20260923-182724/BUILD_VERIFICATION.md`：60 项打包单测 + 31 项欧拉安装器 harness 通过、RUN 签名验证通过——该次同样未在真实欧拉主机部署。

### 7.3 NOT_RUN 声明

**openEuler 裸机/VM  systemd 形态安装与升级未执行**（本环境无欧拉真机/VM）。systemd 单元安装、`install-executor.sh` 的宿主机落位、reboot 持久化等只能登记 NOT_RUN，不折算为通过。

**结论：容器内实证 PASS + 裸机形态 NOT_RUN**。F1（diffutils 缺失）即为 openEuler 最小化实景下暴露的真实缺陷，佐证该实证路径的有效性。

## 8. 发现与缺陷登记

| 编号 | 级别 | 发现 | 证据/位置 | 处置建议 |
|---|---|---|---|---|
| F1 | **缺陷** | `upgrade-executor.sh` / `install-executor.sh` 依赖核查漏 `diffutils`（diff/cmp）；openEuler 最小环境缺 diff 时升级失败且**报错误导**（「存在未声明文件」实为 diff 缺失） | job 28bef5b8 executor result；§6.2 | 执行器依赖清单补 diffutils；比对失败时区分「命令缺失」与「内容不一致」 |
| F2 | 注意 | 构建机已设 `WDSP_SIGNING_KEY` 时 `--unsigned` 被静默覆盖，仍产出签名包 | §5.2 | 文档注明优先级或加显式告警 |
| F3 | **门禁注意** | 服务端 `CurrentVersion = "1.2.0"`（`server/internal/upgrades/upgrades.go:53`）未随版本递增，`system:current_version` 不落库 → 升级后版本基线仍锚 1.2.0 | `upgrade-pre-snapshot.log` | **NG-REL-03 需定策略**：版本基线来源（常量/落库/包自报） |
| F4 | 备注 | 预检严重告警 fail-closed 实证通过（job eca73e00 FAILED） | §5.2 | 无需处置 |
| F5 | 备注 | 同名不同内容包 RESOURCE_CONFLICT 闸门有效；正式包上传需先清理或换名 | §5.2 | 运维手册注明 |
| F6 | 设计确认 | 升级包 auto 模式拒绝含宿主机变更（deployment/、执行器脚本）的发布，**设计正确**；正式节奏应先以完整离线包落地基线再启用 auto | §3.3 | 发布流程文档化 |
| F7 | **缺陷（新）** | 执行器中断（无结果文件）+ API 重启 → 升级任务**滞留 APPLYING** 无超时兜底：30min 等待为进程内定时器，`RunResultReconciler` 只补偿已写结果的任务；滞留任务占用 `no_active_tasks` 预检阻塞后续升级 | §6.3，`executor.go:17/131/209` | 建议：APPLYING 任务持久化 deadline，启动时对超期无结果任务兜底回滚/标记失败 |
| F8 | 注意 | 手动通道（apply.sh/rollback.sh）依赖本地镜像标签正确性；标签被污染时无前置校验 | §6.4 插曲 | apply.sh 增加镜像 ID 与期望值比对的前置断言 |

## 9. 结论汇总

| 验收点 | 结论 |
|---|---|
| 完整 amd64 离线包构建（签名+digest 锁定+traceability） | PASS |
| 篡改包验签 fail-closed | PASS |
| 纯离线安装（0 拉取、7 容器健康、初始化、授权、WAF 冒烟、事件落库） | PASS |
| 前台上传门禁（篡改/未签名/重名/预检告警） | PASS |
| 升级 1.2.1→1.3.0 全链路（镜像切换、迁移 184、数据保留、升级后防护） | PASS |
| 坏包执行期防线 + 自动回滚（镜像+数据库） | PASS |
| 中断语义（不续跑、栈无损、cancel 拒收） | PASS（另发现 F7 滞留缺陷） |
| 手动 apply.sh/rollback.sh 通道 | PASS |
| openEuler 24.03 容器内安装器/执行器/手动脚本 | PASS |
| openEuler 裸机/VM systemd 形态 | **NOT_RUN** |
| 性能判定 | NOT_RUN（Rosetta 环境无意义） |

## 10. 证据索引（`output/evidence/rel02-20261009-071500/`）

| 文件 | 内容 |
|---|---|
| `artifact-inventory.log` | 交付物清单、sha256、traceability 摘要 |
| `build-package.log` / `build-upgrade-pack.log` / `image-build.log` / `build-unsigned-pack.log` | 构建全过程（exit=0） |
| `offline-install-events.log`（0 字节） | compose up 全程镜像事件捕获——0 拉取 |
| `offline-lab-state.log` / `offline-smoke.log` / `offline-smoke.sh` | 离线栈状态与冒烟 |
| `upgrade-lab-setup.sh` / `upgrade-lab-setup.log` / `upgrade-pre-snapshot.log` | 1.2.1 实验室与造数快照 |
| `upload-reject-tests.log` | 上传门禁 4 用例 |
| `executor-run1.log` ~ `executor-run4-interrupt.log` | 执行器各次运行输出 |
| `upgrade-post-snapshot.log` / `upgrade-post-smoke.log` | 升级后镜像 ID/数据/冒烟 |
| `rollback-assertions.log` / `manual-rollback-assertions.log` / `apply-forward-assertions.log` | 回滚与手动通道断言 |
| `interrupt-test.log` / `interrupt-stranded-evidence.log` | 中断实证与 F7 滞留证据 |
| `openeuler-install-gate.log` | openEuler 安装器至 systemd 闸门 |
| `build-broken-pkg.py` / `executor-img/` / `assets/` | 坏包构造器、执行器镜像 Dockerfile、静态二进制 |
| `upgrade-lab/` / `offline-lab/` | 实验室解包目录（报告定稿后清理，日志保留） |

## 11. 缺陷修复闭环（2026-10-09 批次 C 续；F1/F7 已修并实证，F3 留 NG-REL-03 决策）

> 口径：修复面最小、对齐既有代码风格；两处均补单测并在实验室活体闭环。证据续存 `output/evidence/rel02-20261009-071500/`。CHANGELOG 归批次 D 统一登记，本次不动。

### 11.1 F1 执行器/安装器依赖核查漏 diffutils —— 已修复（PASS）

- **现象**（批次 C §6.2，job 28bef5b8）：openEuler 24.03 最小化环境缺 `diff`/`cmp`（diffutils），执行器在 manifest 文件比对处报「包内文件与 manifest 声明不一致（存在未声明文件）」——真实原因是比对命令缺失，报错误导排障方向。
- **修复点**：
  - `ops/upgrade/upgrade-executor.sh:43-50`：依赖核查清单补 `diff cmp`；缺失时报准确错误「缺少命令： diff（diffutils 包；manifest 文件比对与 compose 覆盖判异必需）」，fail-closed `rc=1`。
  - `ops/upgrade/install-executor.sh:43-50`：同口径补 `diff cmp`（安装期一并核查被安装执行器的运行期依赖）。
- **单测**：新增 `ops/upgrade/tests/test_executor_dependencies.py`（5 用例 × 两脚本：清单必含 diff/cmp、依赖齐全 rc=0、缺 diff/缺 cmp 点名 diffutils、缺其他命令维持原文案）；并接入 `ops/upgrade/tests/upgrade-pack-harness.sh:75-80`。
- **实测**：`test_executor_dependencies.py` 5/5 OK（证据 `f1-unit-test-dependencies.log`）；upgrade-pack-harness **PASS=58 FAIL=0**（证据 `f1-upgrade-pack-harness.log`，含签名链路需 `WDSP_SIGNING_KEY`）；活体实证 `f1-fix-live-evidence.log`：openEuler 24.03 无 diffutils 容器内执行器报「缺少命令： diff（diffutils 包；…）」rc=1，`dnf install diffutils` 后 rc=0。
- **结论：PASS**。

### 11.2 F7 执行器中断 + API 重启 → 升级任务滞留 APPLYING 无兜底 —— 已修复（PASS）

- **现象**（批次 C §6.3，job f01ae2f7）：执行器被 kill -9（无结果文件）后 API 重启，进程内 30min 等待定时器（`executor.go` 旧 `defaultExecutorWait`）随进程丢失，`RunResultReconciler` 只补偿「已写结果文件」的任务，滞留 APPLYING 超 36 分钟无终结，阻塞后续升级 `no_active_tasks` 预检。
- **根因**：等待截止是进程内存态，无可持久查询的事实来源。
- **修复点**：
  - `server/migrations/000185_upgrade_executor_deadline.{up,down}.sql`：`upgrade_jobs` 新增 `executor_deadline TIMESTAMPTZ` 列（APPLYING 持久化 deadline；旧行 NULL 时清扫查询退化为 `started_at + 等待上限`）。
  - `server/internal/upgrades/service.go:349`：进入 APPLYING 即写 `executor_deadline = now + executorWait`；`:66/:84` 新增 `executorWait` 字段（默认 30min）；`:41-46` 新增 `strandedStore` 接口（测试可注入内存实现，同 `scheduleStore` 模式）。
  - `server/internal/upgrades/store.go:386` `SetExecutorDeadline` / `:393` `ListExpiredApplyingJobs`（`COALESCE(executor_deadline, started_at + make_interval(...))`）/ `:416` `MarkFailedIfStatus`（乐观守卫，与执行器结果处理竞争时恰好一方生效）。
  - `server/internal/upgrades/executor.go:250` `reconcileExpiredApplying`：挂接 `RunResultReconciler` 循环（`:219`，与 `reconcileResults` 同周期 3s）；超期且**无结果文件**的 APPLYING 任务标记 `FAILED`/`EXECUTOR_TIMEOUT`（`upgrades.go:52`），留审计（`executor.go:279` `recordStrandedAudit`：action=`executor_timeout_close`、HIGH、操作人取任务创建人）并 Raise 已注册告警 `UPGRADE_FAILED`；**不自动重跑、不假装成功**，任务可经既有 `FAILED → ROLLING_BACK` 手动回滚入口处置；有结果文件的任务跳过（交给 `reconcileResults`，防 SUCCESS 误判）。
- **单测**：新增 `server/internal/upgrades/stranded_test.go` 5 用例（滞留终结+审计+告警、有结果文件跳过、空列表零动作、竞争失败不审计不告警、查询错误不误标）；`go test ./internal/upgrades/ -count=1` **67 PASS / 0 FAIL / exit=0**（证据 `f7-unit-test-upgrades.log`）；server 全量 **103 包 ok、零 FAIL、exit=0**（证据 `f7-server-full-test.log`）；reconcile **727 双向零差集不回退**（证据 `f7-reconcile-check.log`）。
- **活体闭环证据**（`f7-fix-evidence.log`，fix-lab：1.2.1 包基线 + api 跑修复镜像 `jiuzhang-server:1.3.0-fix`=9cf3bec76300，schema=185）：
  1. 升级任务 66c72855 进入 APPLYING，`executor_deadline` 落库（started_at+1807s≈30min，持久化事实达成）；
  2. openEuler 执行器拾取任务（`.processing`）后 `kill -9`，无结果文件——中断场景复现；
  3. 将 deadline 平移至过去（仅时钟平移，免等 30min，清扫逻辑路径一致），重启 API；
  4. 修复版 API 启动 **1.2 秒**后日志 `stranded applying upgrade job closed id=66c72855 code=EXECUTOR_TIMEOUT`，任务 `FAILED/EXECUTOR_TIMEOUT`，failure_message 明示「不自动重跑，请人工核查后可手动回滚」；
  5. 审计在册（`operation_audits`：action=executor_timeout_close / module=upgrades / HIGH）；告警在册（`UPGRADE_FAILED`「升级执行器超时，滞留任务已终结」HIGH/OPEN）；
  6. 不重跑不装成功：重跑执行器 rc=0、结果目录仍无该任务文件、任务维持 FAILED；栈 health ok，`active_jobs=0`（后续升级预检不再被阻塞）。
- **插曲如实登记**：① 首次试跑 job 0095ccb7 因实验室 `upgrade-executor/jobs` 目录被先行的 root 执行器创建、api（uid 1000）写任务文件 permission denied 而 fail-closed 回滚（ROLLBACK 路径正确性顺带实证），chown 后重跑；② 本次执行器被杀前已把 api 容器替换为未修复 1.3.0 镜像（比批次 C 中断点更靠后的真实中断），第一次重启未触发清扫（运行的是旧代码），compose 重建回修复镜像后闭环触发——佐证「兜底能力取决于管理面版本」的部署前提。
- **结论：PASS**。
- **漏检补记（2026-10-09 续：000185 栈顶后契约测试 down 序列未 prepend）**：F7 把 `000185_upgrade_executor_deadline` 加到迁移栈顶后，各包 PG 契约测试的「down N 步」序列未机械补第一步（回滚 185），落点全部偏移一步；且本批此前跑的 server 全量测试**未设 `AUTHZ_TEST_PG_DSN`**，这些 Opt-in 契约测试静默 skip——§11.2 上文所引「103 包 ok 零 FAIL」（`f7-server-full-test.log`）对 PG 契约测试而言是**假绿**，如实更正。用户在干净 PG（容器 `s8fix-pg`）亲跑实证 9 个失败后发现。修复=逐文件机械 prepend（注释版本链同步更新）：
  - `server/internal/apiauthz/migration_integration_test.go:553-561`：Enforcement174 down 十一步→十二步（`[]int` 链首补 185）；
  - `server/internal/apiauthzwizard/wizard_integration_test.go:151-153`：Wizard175 down 十步→十一步；
  - `server/internal/strongflow/resolve_integration_test.go:62-66`：StrongFlow178 down 七步→八步；
  - `server/internal/strongflow/strongflow_integration_test.go:81-86`：StrongFlow176 down 九步→十步；
  - `server/internal/apigrpcdesc/bindings_pg_test.go:109-114` 与 `:299-304`：Grpc179 down 六步→七步、Grpc180 down 五步→六步；
  - `server/internal/apimcp/apimcp_pg_test.go:166-171`（头注 :3-5 同步）：MCP181/182 down×4→×5；
  - `server/internal/apimachineid/apimachineid_pg_test.go:178-182`（头注 :3 同步）：MachineId183/184 down 两步→三步——**用户 9 项清单之外由 grep 全扫补上的第 7 个文件**（同样假设栈顶=184，修复前必红，用户清单未覆盖）。
  - `vulnrefs/store_integration_test.go` 的 000167 陈旧断言（S6 前登记遗留）**未动**。A/B 实证：栈顶=184 与栈顶=185 各跑一次 `TestMigrationDownRollback`，失败签名逐字节一致（`store_integration_test.go:87 vuln_refs should be dropped after rollback`、`:98` 四列、`:106 permission seed` 共 6 条断言，无迁移报错行；证据 `185-vulnrefs-signature-pre185.log` / `185-vulnrefs-signature-with185.log`）——单步 down 只回滚栈顶一个迁移，无论栈顶是 184 还是 185 都轮不到 167，与 000185 无关、未因 185 恶化。
  - 复跑口径与全绿证据：每包前 drop/recreate `jiuzhang_waf` 库（s8fix-pg，postgres:16-alpine@127.0.0.1:55432），`AUTHZ_TEST_PG_DSN` 逐包串行 `-count=1`：apiauthz/apimcp/apigrpcdesc/strongflow/apiauthzwizard/apimachineid 六包 ok（`185-prepend-verify-serial.log`）；`-v` 复核 **119 PASS / 0 FAIL / 0 SKIP**，用户点名的 9 个测试 + apimachineid 迁移契约全部单独 `--- PASS`（`185-prepend-verify-verbose.log`）；upgrades 包复跑 ok（67 PASS 口径不破）。用户清单中两个无 down 序列的测试（CandidateSweep、GrpcBindingsCRUD）修复后同绿——其失败为级联：先行失败测试 t.Fatal 跳过「复 up」把库留在半栈，或共享库并发干扰所致，非自身断言缺陷。
  - 附带实证约束：这类 Opt-in 契约**不可多包并行共享同一 DSN 库**——并发 `Migrate up` 撞 `schema_migrations_pkey` 唯一键全灭（证据 `185-prepend-repro-parallel.log`），正确用法是串行 + 一次性库（vulnrefs 不受影响：`CNNVD_TEST_PG_DSN` 每测试自建一次性库）。此为契约测试既有运行前提，非本次新引入。
  - 扩大补扫（其余 13 个 DSN-gated 包，同口径逐包串行，证据 `185-prepend-verify-others.log`）：guardconfig/metrics/apisecurity/customrules/securityevents/apiauthzauthority/apiauthzacks/apinodes/threatintel/apigql/netdiag/apiruntime **12 包 ok**；**新发现 1 项与本次无关的陈旧失败**——`accesscontrolversions.TestPersistedSnapshotSelectionAfterProcessRestart`（`recovery_integration_test.go:97`）：把 DB 读回的 `config` 文本与内存回显字节做字符串相等断言，而 `access_control_versions.config` 自 000008 起即 JSONB，PG jsonb 规范化必加重量空白（psql 直证：输入紧凑串输出 `{"api_authz_models": [{"endpoint_key": ...}]}`），该断言对真实 PG 不可能通过——属未登记的陈旧脆弱断言（包自 wdsp 1.1.4 起无工作区改动，与 000185 不同表不同域），**未动**，建议登记入 `docs/tasks/STAGE_4_8_PENDING_ITEMS.md` 并另行决策（断言改为 JSON 语义相等，或列改回文本型）。

### 11.3 不修声明

- **F3**（`server/internal/upgrades/upgrades.go:53` `CurrentVersion = "1.2.0"` 未随版本递增，版本基线策略）**不修**，留 NG-REL-03 用户决策，仅在批次 D 材料呈现。
