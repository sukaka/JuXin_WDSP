# WDSP P1 交付证据汇总与客户说明（S6）

日期：2026-09-09。范围：docs/tasks/wdsp-p1/ 下四项任务（P1-01 安全+APM 演示、P1-02 Bot 挑战、P1-03 Agent 网关协议、P1-04 规则与模型持续回归）。本文是交付证据总索引；逐项证据以被引用文档与 run 目录为准，过程记录见同目录 WORKLOG.md。

## 1. 强制验收总表

| 任务 | 验收清单 | 状态 | 权威证据 |
|---|---|---|---|
| P1-01 安全+APM 演示 | APMD-001～018 | 17 项 PASS；**APMD-017 BLOCKED**（用户任务耗时验证需未参与开发的人员，条件不具备；任务脚本已固化待执行） | WORKLOG S2 四条记录；A4 真实产品栈联调四场景 PASS |
| P1-02 Bot 挑战 | BOT-001～024 | **PASS 20 / PARTIAL 4 / FAIL 0** | docs/WDSP_BOT_CHALLENGE_ACCEPTANCE_MATRIX.md（逐项证据映射） |
| P1-03 Agent 网关协议 | AGT-001～028 | **26 项 PASS；AGT-021/022 BLOCKED_ENV**（无真实 K8s 集群；组件级等价断言已由 11 个单测覆盖） | docs/agents/WDSP_AGENT_P1_SUPPORT_MATRIX.md |
| P1-04 规则模型回归 | REG-001～026 | 工具层/后端/门禁/回退全部实证通过；真实环境项均在 stage5 真实栈执行 | docs/evidence/regressions/P1-04-R2-FINAL-REPORT.md、P1-04-R4B-DRILL-REPORT.md |

## 2. 关键实证 run_id 索引

| 内容 | run_id / 路径 | 结果 |
|---|---|---|
| Bot 浏览器与自动化基准（BOT-004/005/021） | test/e2e/bot-challenge/runs/20260908T184056-940230 | 27/27 PASS |
| Bot 升级/关闭/回退演练（BOT-024） | test/e2e/bot-challenge/runs/20260908T185148-7b707a | 23/23 PASS |
| Agent Nginx mirror E2E | test/wdsp-agent-e2e/mirror/runs/20260908T151957-2396b3 | 11/11 PASS |
| Agent Envoy tap E2E（h2/gRPC/WS） | test/wdsp-agent-e2e/envoy-tap/runs/20260908T152129-c4a655 | 11/11 PASS |
| 回归全量回放 基线/候选对比 | docs/evidence/regressions/compare-20260908T222932-46b792 | 基线 48/48；候选精准捕获唯一预期内丢失检测，如实 FAIL |
| ENFORCE 门禁 + 误报/故障回退演练 | docs/evidence/regressions/r4b-20260909T0015（55 文件） | 全相位 PASS |
| 安全回归管理界面 E2E | test/e2e/security-regression/runs/20260909T003233-d76e86 | 11/11 PASS |

## 3. 已知限制与未覆盖项（如实披露）

- **APMD-017**（用户任务耗时验证）：BLOCKED，需未参与开发人员执行，脚本已固化。
- **AGT-021/022**（真实 K8s Pod 变更与 RBAC 最小权限实证）：BLOCKED_ENV，需具备真实集群的环境补做；组件级断言已覆盖。
- **BOT-004**：仅 Chromium 通道实测；Firefox/Safari/移动浏览器 NOT_RUN（Playwright spec 可扩展复用）。
- **BOT-006**：慢设备节流、读屏与键盘导航实测 NOT_RUN（设计已防主线程长阻塞，无辅助技术环境证据）。
- **BOT-013**：移动网络 IP 变化实测 BLOCKED_ENV。
- **BOT-018**：签发/验证洪峰压测 NOT_RUN。
- 范围外能力（NOT_SUPPORTED，不得以转码/镜像冒充）：原生旁路 HTTP/2 HPACK 帧解析、WebSocket 帧正文解析、HTTP/3/QUIC、gRPC Protobuf 正文解码、AF_XDP、Agent 在线阻断。
- Bot 信号：method_ratio 恒 UNAVAILABLE（无每方法计数源）；identity_behavior 未启用时行为组不可用、PROTECT 不挑战（部署配套要求见运维手册）。
- 回归语料：JWT/Agent/APM 类用例仍缺口（manifest 已标注）；WAF-BEN-EDGE-001 关联 CUSTOM_PACK 1001012 存在非确定命中 flake（10 轮 2 轮），已如实披露。
- APM：trace_inject_upstream 网关侧已实现但管理面发布接线未落地（guard.go 恒 false），列入后续工作包。

## 4. 过程中发现并修复的真实缺陷（均有证据链）

1. server 证书查询 SQL 歧义（certColumns 未限定别名与 application_certificates JOIN，SQLSTATE 42702）——任何「HTTPS 域名+绑定证书」应用发布必失败；已修（certColumnsC）。
2. docker stage5 栈证书下发通道未接线（裸机设计为宿主机共享目录）；已修（stage5-gateway-certs 卷 + 两 Dockerfile 预建目录，uid 1000 数值权属一致）。
3. botchallenge Store.Read 真实 Valkey 下 HGETALL 数字型 bulk string 解析失败导致 verify 恒 503；已修（luaFieldString 两型兼容）。注意：counters.Eval 数字串→int64 共享语义未改，其他 Lua HGETALL 数字字段消费者存在同类潜在风险，待排查。
4. web 回归详情页 gate_assessment.reasons null 白屏；已修（归一化+守护测试）。
5. s5_publish 发布锁 LOCK_BUSY 无重试（自动发布与显式发布竞争）；已修（退避重试）。

## 5. 产品发现（待修复排期，未改产品代码）

R2 七条（详见 P1-04-R2-FINAL-REPORT.md「产品发现」节）：escapeSecLangArg 转义 bug、CRS 949110 相位抢占、Coraza 无 XML 体处理器、apigeo nil panic、事件关联键口径、族映射、OBSERVE offer 语义。
R4b 六条（详见 P1-04-R4B-DRILL-REPORT.md）：**回滚草稿孤儿化（优先级最高：门禁拒绝路径不回写 runtime 策略，rollback 502 后策略滞留 DRAFT，下一次无关发布会静默带生效）**、学习态指纹漂移×3、GuardOverride 恢复不清 DB 规则本体、config-versions 回滚不经回归门禁、EDGE 事件 client_ip 恒为网关出口、公钥登记无 settings API。

## 6. 客户部署与升级说明

- 所有 P1 新能力默认关闭：bot_policy=OFF、jwt_trust=关、identity_behavior=关、risk_policy=关、regression-policy=OFF（门禁三态 OFF/OBSERVE/ENFORCE）。
- Bot 挑战启用配套：Valkey 共享态 + identity_behavior 启用 + 签名密钥登记（步骤见 docs/BOT_CHALLENGE_OPERATIONS.md）。
- 回归门禁启用配套：受信验签公钥登记（system_settings）、tools/regsign 签名工具（私钥不入库不入仓）、证据有效期默认 7 天；详见 docs/evidence/regressions/README.md 与 R3 记录。
- 升级/回退：配置版本回退与 GuardOverride 已知良好快照恢复均经实证（BOT-024 演练、R4b 相位②③）；Agent v1→v2 升级与能力收回降级实证见支持矩阵 AGT-023/024/028；迁移 000128/129/131-135 均经真实 PG up/down 演练。
- 运维文档：docs/BOT_CHALLENGE_OPERATIONS.md（Bot）、docs/agents/WDSP_AGENT_P1_SUPPORT_MATRIX.md §4（Agent 回退纪律）、docs/evidence/regressions/（回归证据）。

## 7. 最终构建验证（S6 扫尾）

以 WORKLOG S6 记录为准：gateway（根+jiuzhang_guard 子模块）、server（build+vet+internal 全包）、wdsp-agent 22 包、web（typecheck/lint/vitest 113 文件/858 用例）、p1reg 201 单测——全绿（2026-09-09 主代理实跑，exit 0）；全部 e2e 证据 run 不可变归档于上表路径。
