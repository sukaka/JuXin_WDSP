# S8 阶段出口小结（NG-REL-01/02/03 发布线 —— 批次 D 交付）

日期：2026-10-09 ｜ 依据：`docs/WDSP_API_WAF_NEXTGEN_RD_PLAN.md` §15.2（NG-REL-01/02/03）+ §15.3（阶段出口口径）+ §14.2（性能门槛纪律）
状态词表：**PASS**（有实证证据）｜**PARTIAL**（部分实证，缺口注明）｜**NOT_RUN**（未执行或口径不可达，不折算为通过）｜**NOT_APPLICABLE**（范围明示未激活）。
纪律声明：本批全程无 git 写操作、不打 tag、不推送；版本号与发布动作留用户批准（§6）。NOT_RUN/PARTIAL 无一粉饰（§3/§4）。

## 1. NG-REL-01/02/03 逐项结论

| 任务 | 结论 | 关键数字与证据 |
|---|---|---|
| NG-REL-01 回归与验收对账 | **PASS**（强制项全绿） | 回归套件 **10/10 全绿**：server 103 包 / gateway 7+23+17 包 / web 139 文件 1070 用例 / stage5 40+13+契约门 / stage8 15+10+23 / reconcile **727 双向零差集**，全部直捕退出码原样记录。首轮三红灯根因=JWT PROTECT 防静默降级拒发（设计行为）+ stage8 脚本缺 Bot 墓碑前置（脚本缺口），处置后复跑全绿、**零生产代码改动**。交付物：`S8-ACCEPTANCE-MATRIX.md`（§15.2 逐行：PASS 30 / PARTIAL 2 / NOT_RUN 2；§16 逐条：PASS 50 / PARTIAL 2 / NOT_APPLICABLE 1 / NOT_RUN 8）、`S8-REL01-REGRESSION-REPORT.md` |
| NG-REL-02 完整包与前台升级兼容 | **PASS**（四项交付全实证；openEuler 裸机 systemd 形态 NOT_RUN 如实保留） | 产物 `dist/jiuzhang-wdsp-offline-1.3.0-rc1-amd64.tar.gz`（602,140,778 B，sha256=6e35ca0a…）与 `jiuzhang-wdsp-upgrade-1.3.0-amd64.tar.gz`（162,518,266 B，sha256=f456c67e…）；纯离线安装 0 拉取 7 容器健康；**1.2.1→1.3.0 前台升级 88 秒 SUCCESS**（镜像 ID 逐一相等、迁移推进至 184、数据保留、升级后 SQLi 照拦）；篡改包验签 fail-closed、坏包执行期自动回滚 ROLLED_BACK、中断不续跑语义、手动 apply.sh/rollback.sh 通道全实证；openEuler 24.03 容器内 PASS。缺陷 F1/F7 已修复并闭环（报告 §11），F3 留本批决策（§5）。交付物：`S8-REL02-PACKAGE-REPORT.md` |
| NG-REL-03 运维/限制/版本与交付清单 | **本批交付**（「需用户批准发布」门禁如实挂起） | 交付物=本文档 + 运维/限制文档最小更新（§7）+ CHANGELOG Unreleased 补登 + THIRD_PARTY_NOTICES 核对（§7）；F3 版本基线三选项呈现（§5）；版本建议候选 1.3.0（§6）。**版本号与 tag 由用户批准后再定，本批不打 tag 不推送、不改 VERSION.md 版本行、不做 CHANGELOG 版本节归并** |

配套批次 B 交付物：`S8-PERFORMANCE-REPORT.md`（候选门槛对照：门槛 2 参考 PASS + 队列有界实证成立；门槛 1 口径不可达、门槛 3 本环境不可判定、24h/兆芯 NOT_RUN——§3 汇总）。

## 2. RD 计划 §15.3 阶段出口逐条核对

§15.3 原文：「实现与设计对应、数据库迁移与 OpenAPI 同步、单元/接口/E2E 按风险完成、权限与审计验证、失败与回滚验证、证据可复现、限制已披露。仅页面可操作、单测全绿或开发者自述，均不足以判定阶段完成。」

| §15.3 出口项 | 结论 | 证据指针 |
|---|---|---|
| 实现与设计对应 | PASS | S1~S7 各冻结设计文档「实现状态」节与出口记录（`docs/nextgen/s1`~`s7/`）逐字对照；验收矩阵 §15.2 按「完成证据」列逐行对账 34 项（PASS 30，PARTIAL/NOT_RUN 缺口逐项注明无一冒充） |
| 数据库迁移与 OpenAPI 同步 | PASS | S1~S8 迁移 000168~000185 全链；`tools/check-api-reconcile.py` 代码注册路由 727 = OpenAPI 片段收录 727，双向零差集（REL-01 §3，与 S7 出口持平）；000185 登栈顶后 7 个 PG 契约测试 down 序列 prepend 修复，干净 PG 逐包串行复跑 119 PASS/0 FAIL/0 SKIP（REL-02 §11.2 补记） |
| 单元/接口/E2E 按风险完成 | PASS | REL-01 十套件全绿（上表数字）；§16 验收矩阵 61 用例逐条对账（PASS 50 / PARTIAL 2 / NOT_APPLICABLE 1 / NOT_RUN 8，§3 汇总）；DSN-gated PG 契约测试须逐包串行+一次性库的运行前提已实证登记（并发 Migrate 撞 `schema_migrations_pkey`，REL-02 §11.2） |
| 权限与审计验证 | PASS | 各阶段越权用例在册（S7 C09 未认证 401/AUDIT_ADMIN 写 403、I05、S6 M06、S3 四要素八负向 400 等）；机器身份/MCP/gRPC 权限复用既有读/管理点零新增；写操作 HIGH 审计逐批读回（S7 audits.json ≥50 条）；授权恢复 manage+乐观锁 409+HIGH 审计 after 全值（S4 FLOW-03） |
| 失败与回滚验证 | PASS | REL-01 §7 容量与恢复汇总表（Valkey 故障 UNKNOWN 放行、水位回滚拒载 fail-closed、能力门六组三态、发布冒烟失败 VERIFY_FAILED_ROLLED_BACK 真实触发等）；REL-02 §5/§6（篡改/未签名/重名/预检告警四闸门、坏包自动回滚、中断语义、手动通道）；F7 滞留兜底修复活体闭环（REL-02 §11.2：API 重启 1.2 秒兜底终结 EXECUTOR_TIMEOUT+审计+告警） |
| 证据可复现 | PASS | 三批报告命令原样+退出码直捕；证据根目录 `output/evidence/rel02-20261009-071500/`（批次 C/D 全量）及各阶段证据目录在册；性能报告方法先于测量冻结（§1） |
| 限制已披露 | PASS | 验收矩阵 §3 十四项移交全量登记；本小结 §3（NOT_RUN/PARTIAL 汇总）与 §4（遗留登记全表）无折算无隐藏 |

## 3. NOT_RUN 与 PARTIAL 汇总表（全量，逐条注明原因与顺延去向）

| # | 项 | 状态 | 原因 | 顺延去向 |
|---|---|---|---|---|
| 1 | NG-COV-04 灰度生命周期（SHADOW/CANARY）+远端次要节点 manifest 通道 | PARTIAL | 能力门第一批已交付（fail-closed 三态实证），灰度生命周期与远端 manifest 通道未交付 | 后续批（矩阵 §3 项 10） |
| 2 | NG-GQL-03 性能分档 | PARTIAL | 功能链全绿，性能分档并入性能专项 | 批次 B 性能报告（已出参考读数，正式判定留专用环境） |
| 3 | §16 H02 h2→h1.1 链路 | PARTIAL | httpchain 三链路 pass；h2/path-rewrite 拓扑未建（topology.yaml untested） | 后续批（矩阵 §3 项 11） |
| 4 | §16 A07 分区演练 | PARTIAL | ha-lab S1-S5 已实证；AZ-02/03 与 FLOW 合并分区演练矩阵未编排 | 后续批（矩阵 §3 项 12） |
| 5 | §16 M07 审批闭环 | NOT_APPLICABLE | 完整审批闭环属后续子阶段（RD_PLAN §11.3 明文）；首期高风险默认拒绝已实断 | 审批子阶段 |
| 6 | §16 D01~D08 发布与运行矩阵 | NOT_RUN | 性能/发布矩阵属性能专项与专用环境 | 性能专项（批次 B 报告部分覆盖口径验证，正式判定留专用环境） |
| 7 | 性能门槛 1（新能力全 OFF 同源码基线成对对照） | NOT_RUN | 「加入新能力前的同源码网关」历史二进制未留存，口径不可达 | 性能报告 §5 给绝对读数替代画像；正式判定留专用环境 |
| 8 | 24h 稳定性 | NOT_RUN | 专用环境移交项；短时 smoke 不算通过（§14.2 原文） | 性能专项/移交（矩阵 §3 项 1） |
| 9 | 兆芯/openEuler 性能双报告 | NOT_RUN | 无硬件，如实标注 | 性能专项/移交（矩阵 §3 项 1） |
| 10 | 授权 AZ 臂性能读数 | NOT_RUN | 批次 B 未单列授权臂；架构证据在册（本地快照零网络 IO） | 性能专项 |
| 11 | openEuler 裸机/VM systemd 形态安装与升级 | NOT_RUN | 本环境无欧拉真机/VM；容器内实证不折算 | REL-02 §7.3 登记，移交真机环境 |
| 12 | 快照体积基准（200000 relations/10000 冲突上限形态） | NOT_RUN | S3-AZ02 遗留 5 | 后续批（REL-01 §8） |
| 13 | go-ftw 10014xx 簇整改后复跑 | NOT_RUN | 用例设计问题定责在册（S1 §5.3），整改未执行 | 后续批（矩阵 §3 项 11） |
| 14 | MCP 调用预算 stage5 联调证据 | NOT_RUN | S6 已知限制；单测承载 | 后续批（矩阵 §3 项 6） |
| 15 | AZ CLOCK_SKEW 负向漂移 stage5 实证 | NOT_RUN | 需节点时钟注入设施（S3-AZ03 遗留 1） | 后续批（矩阵 §3 项 8） |

## 4. 遗留登记全表

| # | 遗留项 | 位置/现象 | 定性与实证 | 修复选项/去向 |
|---|---|---|---|---|
| 1 | vulnrefs 000167 陈旧断言 | `server/internal/vulnrefs/store_integration_test.go`（S6 前登记遗留） | A/B 实证与 000185 无关：栈顶 184 与 185 各跑一次失败签名逐字节一致（6 条断言，无迁移报错行；证据 `185-vulnrefs-signature-pre185.log`/`185-vulnrefs-signature-with185.log`） | 未动；既有遗留登记，另行决策 |
| 2 | accesscontrolversions JSONB 断言陈旧 | `server/internal/accesscontrolversions/recovery_integration_test.go:97`：DB 读回 jsonb 规范化文本与内存紧凑回显做字符串相等断言；`access_control_versions.config` 自迁移 000008 起即 JSONB（psql 直证输出带空格），该断言对真实 PG 不可能通过；包自 wdsp 1.1.4 起无工作区改动 | 000185 修复批扩大补扫新发现，与 185 不同表不同域 | 未动；选项：断言改 JSON 语义相等 / 列改回文本型；建议登记 `docs/tasks/STAGE_4_8_PENDING_ITEMS.md` 另行决策 |
| 3 | 登录限流键 PTTL=-1 永久 429 | `server/internal/middleware/ratelimit.go:40-58`：Incr 成功而 Expire 未执行的崩溃窗口留下无 TTL 键，无自清机制（Expire 失败时已删键+503 兜底在位，缺口仅是崩溃窗口残留） | S4 三处笔记已载（NG-FLOW-strong-flow.md:294、S4-FLOW04/03 出口记录）；定性=测试环境治理坑+潜在运维坑 | 遗留登记；候选修复：读侧校验无 TTL 键自清或 Lua 原子 Incr+Expire |
| 4 | 强流程：多 ACTIVE 绑定同端点 finalize 只消费首个预留 | NG-FLOW 设计 §9.2 联调新发现 | 多绑定 CONFIRMED 语义待设计明确 | 设计明确后处理（矩阵 §3 项 9） |
| 5 | 强流程：实例键 HMAC 输入不含 definition_id | NG-FLOW 设计 §9.2；同版本号不同名定义同 ref 撞键缝隙 | CHANGELOG FLOW-04 条目已登记 | 后续批（矩阵 §3 项 9：实例键加 definition_id 分量） |
| 6 | gRPC >1MiB 无压缩大体 h2c 转发挂起 | S5 遗留，未定性 | 矩阵 §3 项 5 登记 | 后续批排查 |
| 7 | tproxyd flaky（2/3） | gateway 根模块；高负载并行资源竞争型，未抓到失败用例名 | REL-01 §5：单跑与根模块全量复跑均 PASS | 建议 `go test ./tproxyd/ -count=20` 定位；登记观察 |
| 8 | protocol-tests.py 2/5 断言失败 | 阶段1 POC 适配差异（头部上限 1MB vs POC 64KB、宿主 WAF Off 前提），非产品缺陷；正向对照 WAF-On 403/400 实证 | REL-01 §6 | 是否纳入 stage5 常规回归待编排者裁决（矩阵 §3 项 13） |
| 9 | F1 执行器/安装器依赖核查漏 diffutils | `ops/upgrade/upgrade-executor.sh:43-50`、`install-executor.sh:43-50` | **已修复闭环**：REL-02 §11.1（单测 5/5、harness 58/58、openEuler 活体 rc=1→rc=0）；CHANGELOG 已登记；HOST_UPGRADE_EXECUTOR.md 依赖清单本批已补 | 闭环 |
| 10 | F2 `--unsigned` 被 WDSP_SIGNING_KEY 覆盖 | `ops/upgrade/build-upgrade-pack.sh:223` 密钥优先 | 注意项；UPGRADE_PACKAGE_POLICY.md 本批已注明优先级 | 闭环（文档口径） |
| 11 | F3 版本基线 `CurrentVersion="1.2.0"` 未递增 | `server/internal/upgrades/upgrades.go:53` | 门禁注意：**本批 §5 三选项呈现，留用户决策** | 用户决策 |
| 12 | F5 同名不同内容包 RESOURCE_CONFLICT 闸门 | REL-02 §8 | 备注：闸门有效属设计行为 | 运维手册注明（移交项） |
| 13 | F6 auto 模式拒宿主机变更 | REL-02 §8 | 设计正确确认；UPGRADE_PACKAGE_POLICY.md 本批已补批次 C 实证现状 | 闭环（文档口径） |
| 14 | F7 升级任务滞留 APPLYING 无兜底 | 迁移 000185 + `reconcileExpiredApplying` | **已修复闭环**：REL-02 §11.2（5 单测+fix-lab 活体：兜底终结 EXECUTOR_TIMEOUT+审计+告警、不重跑不装成功）；CHANGELOG 已登记；HOST_UPGRADE_EXECUTOR.md 本批补「中断与超时语义」节 | 闭环 |
| 15 | F8 手动通道依赖本地镜像标签正确性无前置校验 | apply.sh/rollback.sh（承载文档 OFFLINE_DEPLOYMENT_GUIDE.md:145-148、OPERATIONS_MANUAL.md:138-139、SYSTEM_ADMIN_MANUAL.md:98,133） | 注意项；处置建议（镜像 ID 前置断言）属代码改动，本批不硬改 | 登记移交 |
| 16 | 000185 栈顶后契约测试 down 序列漏 prepend | 7 个测试文件（apiauthz/apiauthzwizard/strongflow×2/apigrpcdesc×2 处/apimcp/apimachineid） | **已修复闭环**：REL-02 §11.2 补记（含「103 包 ok」对 PG 契约测试为假绿的口径更正）；119 PASS/0 FAIL/0 SKIP；CHANGELOG 已登记 | 闭环 |
| 17 | DEPLOYMENT.md 结构性陈旧 | 快速部署节引用的根目录 compose 不存在（编排在 deployment/）、占位节残留 | 本批已最小更新三处（产物名笔误、占位节改事实指针、备份/升级指针）；整体结构重写超出「最小更新」口径 | 登记移交（编排者决策是否重写） |
| 18 | 源码未提交状态 | S1~S8 全部交付物为工作区未提交改动（384 M + 305 ??，HEAD e341853，分支 main） | REL-01 §2/矩阵 §3 项 14 已登记；提交与推送属编排者职责（AGENTS.md 协作纪律） | 编排者 |

## 5. F3 版本基线问题（三选项呈现，留用户决策）

现象（REL-02 §8-F3，证据 `upgrade-pre-snapshot.log`）：服务端 `CurrentVersion = "1.2.0"`（`server/internal/upgrades/upgrades.go:53`）未随版本递增，`system:current_version` 不落库——1.2.1→1.3.0 升级实证完成后版本基线仍锚定 1.2.0，后续升级包预检的 `version_from` 比对以该常量为准。版本基线来源策略需定案，三选项利弊：

| 选项 | 做法 | 利 | 弊 |
|---|---|---|---|
| A. 保持手动维护（现状） | 发布流程把「递增 `CurrentVersion` 常量」列为发布清单强制步骤（VERSION.md「发布时必须同步更新」第 4 条已含「代码中的版本常量」） | 零代码改动；行为可预测；不引入新失败面 | 已实证会忘：常量锚定 1.2.0 经历了 1.2.1 实验室包与 1.3.0-rc1 产物两轮仍未递增；纯靠纪律兜底 |
| B. 构建期注入 | 构建脚本/Dockerfile 以 `-ldflags -X`（或构建期生成常量文件）把版本注入二进制，单一事实来源=构建输入（构建链版本本已锁定） | 消灭人工遗漏；产物与代码常量天然一致 | 需改 server 构建链（Dockerfile、CI、本地 `go run` 开发态缺省值策略）；偏离「go build 直构建」现状，调试态版本语义需定义 |
| C. 从迁移表推导 | 启动时读 `schema_migrations` max(version) 映射产品版本 | 免维护；随升级自动推进 | 迁移号≠产品版本需维护映射表；首次启动空库无行无定义；回滚/补迁移场景语义复杂；把数据库状态变成版本事实源引入新耦合 |

本批不定案、不改代码；决策后按所选选项另行立项实施。

## 6. 版本建议与发布门禁

- 当前基线（VERSION.md，2026-09-12 确认）：已发布 `1.2.0`（tag `wdsp-v1.2.0`），下一候选 `1.2.1`（Bug 修复，未发布）。
- 改动性质：S1~S7 全部为新功能（执行覆盖账本与能力门、GraphQL 成本、授权 AZ-01~04、强流程 FLOW-01~04、gRPC G1、MCP G1、机器身份 G1），S8 为发布工程与缺陷修复（F1/F7/prepend）。按版本号规则「新功能 → 第二位 +1、第三位归零」，**建议候选版本 `1.3.0`**。批次 C 产物文件名（`jiuzhang-wdsp-offline-1.3.0-rc1-amd64.tar.gz`、`jiuzhang-wdsp-upgrade-1.3.0-amd64.tar.gz`）与升级实证（1.2.1→1.3.0）已按此候选构建——但产物文件名不构成版本批准。
- 张力如实呈现：VERSION.md 下一候选 `1.2.1`（Bug 修复口径）与 S1~S8 新功能量不匹配；若批准 `1.3.0`，需同步更新 VERSION.md 当前/候选行、CHANGELOG Unreleased 归并版本节、并按 §5 决策处理 F3 常量——这些均为发布动作。
- **门禁声明：版本号与 tag 由用户批准后再定。本批不打 tag、不推送、不改 VERSION.md 版本行、不做 CHANGELOG 版本节归并。**

## 7. 批次 D 交付物清单

| # | 交付物 | 说明 |
|---|---|---|
| 1 | 本文档 `docs/nextgen/s8/S8-EXIT-SUMMARY.md` | NG-REL-03 主交付物（§1~§6） |
| 2 | `docs/HOST_UPGRADE_EXECUTOR.md` | 最小更新：依赖清单补 `realpath`/`diff`/`cmp`（diffutils）；新增「中断与超时语义」节（F7 修复后行为） |
| 3 | `docs/UPGRADE_PACKAGE_POLICY.md` | 最小更新：`--unsigned` 与 `WDSP_SIGNING_KEY` 优先级注记（F2）；「当前开发基线限制」节补批次 C 实证现状（auto 拒绝结论不变） |
| 4 | `docs/DEPLOYMENT.md` | 最小更新：多架构表产物名笔误（补 `-wdsp`）；三处「待阶段X」占位节改事实指针；备份/升级两占位节改 `ops/backup`、`ops/restore` 与升级文档指针 |
| 5 | `docs/OPENEULER_ZHAOXIN_INSTALLATION.md` | 审计结论：**无脱节，不改**（其依赖清单属安装器 install.sh 口径，F1 在执行器侧；install.sh 已在 openEuler 容器实证至 systemd 闸门 fail-closed） |
| 6 | `CHANGELOG.md` | Unreleased「安全与质量」节补三条：F1 diffutils 依赖核查、F7 滞留兜底（迁移 000185）、000185 prepend 修复（含假绿口径更正）；不做版本节归并 |
| 7 | `THIRD_PARTY_NOTICES.md` | 「阶段8 新增与关键间接依赖补登」表补两行测试期对测组件：modelcontextprotocol/go-sdk v1.8.0（Apache-2.0/MIT 过渡态）、google.golang.org/grpc v1.76.0（Apache-2.0），均注明「仅测试期，不入产物」；生产 go.mod 全量核对无其他遗漏，许可证均为 Apache-2.0/MIT/BSD 族 |
| 8 | `VERSION.md` | 核对结论：与工作区现状一致（1.2.0 已发布、候选 1.2.1 未发布）；**本批不改**（版本待用户批准，§6） |

源码状态登记：工作区未提交改动 384 M + 305 ??（HEAD e341853，分支 main），提交与推送属编排者职责（AGENTS.md 协作纪律；矩阵 §3 项 14 同口径）。
