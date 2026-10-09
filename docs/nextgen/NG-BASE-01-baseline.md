# NG-BASE-01 基线冻结清单（S0）

> 任务来源：docs/WDSP_API_WAF_NEXTGEN_RD_PLAN.md §15.2 NG-BASE-01。
> 冻结时间：2026-10-03。冻结人：Kimi（研发助理执行）。本清单不含任何口令、密钥或敏感值。
> 用途：后续所有 NG 阶段以本清单为事实起点；发现与本清单冲突的事实，以更新本清单的方式修正，不口头漂移。

## 1. 源码基线

| 项 | 值 |
|---|---|
| 仓库 | JiuZhang_WAF（本地工作副本） |
| HEAD | `e34185334b4d778719744a236ab83bf0c6924f1f`（main） |
| HEAD 提交 | 2026-09-13 16:55:28 +0800 `feat(network-tools): add network diagnostics and NTP/DNS settings` |
| 未提交改动 | **276 条**（M/?? 合计），分布：server 77、test 38、output 47、gateway 33、web 31、ops 17、docs 10、wdsp-agent 9、tools 4、licenses 3、scripts 2、其余单文件 5 |
| 已发布版本 | `1.2.0`（VERSION.md）；候选 `1.2.1`（未发布） |

### 1.1 未提交改动按功能线归组（会话记录口径，供 S0 各阶段读码索引）

| # | 功能线 | 主要范围 | 状态 |
|---|--------|----------|------|
| 1 | 授权信任根 TRIAL 轮换登记 + 门控放行升级通道 | `server/internal/license/`（vendor_pubkey.hex、gate.go、测试） | 代码完成，license 包测试绿 |
| 2 | 管理控制台 HTTPS（100 年自签证书）+ Cookie Secure 按协议动态下发 | `ops/install/console-cert.sh`、`web/`（Caddyfile.docker、entrypoint、Dockerfile）、`server/internal/auth/handler.go`、`ops/offline-package/build.sh`、`ops/install/install.sh` | 完成并经 stage5 双栈实测 |
| 3 | WAF 安全事件真实 IP / connection_ip 修复 | `gateway/modules/jiuzhang_guard/module.go`、`server/internal/securityevents/`、`gateway/internal/eventparser/` | 完成并实测；~~遗留：stage5-gateway-tests 有 3 个相关失败待查~~ **已结案（2026-10-03）**：三失败为环境残留非代码回归，详见 §6.1 附记 |
| 4 | WDSP 免 Docker 裸机交付包 | `ops/baremetal/`（build-runtimes/build-binaries/assemble + package/）、`dist/jiuzhang-wdsp-baremetal-linux-amd64.tar.gz` | 完成并容器彩排通过（未在 openEuler 实机验收） |
| 5 | WAF 规则体系增强（开源策略引入） | `gateway/rules/`（4 排除插件、scanner-fingerprints-ext 1501、ai-crawler 180、fake-bot-claims 13、auto-decoding 默认禁用）、`tools/rulegen/{crawler-ua,ai-crawler}`、`licenses/` 三目录 | 完成，stage5 探针命中实测通过 |
| 6 | 威胁情报导入（Feodo 对账） | `server/internal/threatintel/`、`server/internal/app/app.go`（装配/路由）、openapi 片段 | 完成，stage5 全链路实测通过 |
| 7 | NVD 策展队列生成器 | `tools/rulegen/cve-draft/`、`output/cve-review/` | 完成，实跑产出 50 条评审队列 |
| 8 | 更早任务线（HEAD 后、本会话前段） | 升级包制作/签名/上传升级、站点流量分析、API 准入防护（迁移 000166）、攻击会话关联、CNNVD 兼容 P1（迁移 000167）、rule_source/attack_type/phase 修复、网络工具与 NTP/DNS（已入 HEAD）、软著文档 | 见 CHANGELOG Unreleased 与各自设计文档 |

**重要认知**：当前工作区 = 1.2.0 + 上述 8 条未发布功能线。NG 各阶段读取「现状」时必须以工作区为准，不能以 1.2.0 tag 为准；也不得把未提交功能当成已发布能力对外宣称。

## 2. 构建与依赖基线

| 项 | 锁定值 | 来源 |
|---|---|---|
| Go | 1.25.6（三个 module 一致：server / gateway / wdsp-agent；构建指令 GOAMD64=v1） | 各 go.mod |
| Node | v24.13.0（构建机）；web package.json `1.0.1` | web/ |
| Caddy | v2.11.4（xcaddy v0.4.5 构建，含 jiuzhang_guard） | gateway/Dockerfile |
| coraza-caddy | v2.5.0 / Coraza v3.7.0 | gateway/Dockerfile、go.mod |
| OWASP CRS | 4.28.0（commit 55b09f5acfd1，tarball sha256 d8acc96f…） | gateway/rules/crs/VERSION.txt |
| CRS 插件 | auto-decoding 1.0.0@6885a972（默认禁用、修适）；排除插件 6 个（PINNED 见 licenses/crs-plugins/README.md） | gateway/rules/ |
| PostgreSQL | 镜像 16.4-alpine@sha256:5660c2cb…（离线包）；裸机包内嵌 16.14-bookworm 提取运行时 | ops/offline-package/build.sh、ops/baremetal |
| Valkey | 8.1.8-alpine@sha256:94365b27… | 同上 |
| 前端栈 | React 18 + TS + Vite + AntD 5 + ECharts + TanStack Query + Zustand（精确版本见 web/package.json） | web/ |
| 规则数据 | monperrus/crawler-user-agents@9345a7ad（MIT）、ai.robots.txt@987266f3（MIT）、NVD API 2.0（公共领域，在线拉取不锁定） | tools/rulegen/ PINNED |

构建验证（2026-10-03）：`go build ./...` 三个 module **全部通过**（server / gateway / wdsp-agent）。

## 3. 测试基线（2026-10-03 全量补跑登记；此前为本会话局部运行记录）

| 套件 | 结果 | 说明 |
|---|---|---|
| `server` 全量 `go test ./...` | **94 包 ok，0 FAIL** | apiscan `TestWorkerUnresolvableHostFails` 环境性失败已修（本机/上游 DNS 把 RFC2606 保留域解析为真实 IP 198.20.1.144——utun6 VPN 隧道所致，test 加环境探测跳过） |
| `gateway` 全量 `go test ./...` | **7 包 ok，0 FAIL** | — |
| `wdsp-agent` 全量 `go test ./...` | **22 包 ok，0 FAIL** | netif `TestDiscover` 环境性失败已修（macOS pktap0/utun 伪接口无 L2/L3 字段，test 跳过伪接口） |
| `web` Vitest | **127 文件 / 993 用例全过** | `npm test`（vitest run），121s |
| go-ftw v2.4.0（自建 linux 静态二进制，与 docs/DEPENDENCIES.md 锁定一致） | **harness 路径已建立；首轮结果混合** | 见 §3.1 |
| `server` license 包 | PASS | 2026-09-29 |
| `tools/check-api-reconcile.py` 路由对账 | 671/671 零差集 | 2026-10-02 |
| `scripts/license-audit.sh` | OK（预存 `licenses/yaml/` 未登记 FAIL 一项，非本次引入） | 2026-10-02 |
| stage5 `custom-pack-blocking-tests.sh` | 13/13 PASS | 2026-10-02 |
| stage5 `stage5-gateway-tests.sh` | **40/40 PASS（连续两轮幂等）** | 2026-10-03（定责修复后，见 §6.1） |
| stage5 栈运行态 | 8 容器 Up | 2026-10-03 核对 |

### 3.1 go-ftw 补跑记录（2026-10-03）

- **可复用执行路径**（首次建立）：ftw 在 **linux/amd64 容器内**运行，直挂 `jiuzhang-stage5_stage5-gateway-logs` 卷读审计日志（**不经宿主机 tail 流**，消除标记竞态），请求经 `host.docker.internal:18080` 发往 stage5 网关；配置 `test/waf/ftw/ftw.stage5.yaml`（`virtual_host_mode: true` + `headers.Host: shop.example.com`——标记探针默认 `Host: localhost` 会落到无 WAF 默认路由，这是 stage5 适配的关键改动；40 条用例 yaml 的 Host 已同步改为 shop.example.com）。
- **结果**：10006xx/10013xx 系列基本通过（如 1000631 双例全过）；**1001408~1001417 簇失败**；1001314/1001324 两文件存在预存 yaml 构造错误（`seq into int`，ftw 跳过）；偶发标记检索抖动。
- **失败簇定责（重要，非规则缺陷）**：该簇 payload（如 `java.lang.ProcessImpl`）在到达 CUSTOM_PACK 之前已被 CRS 934200/944130 计分，**CRS 评分先过阈值 → REQUEST-949110 在阶段 2 内先于 contrib 中断** → contrib/CUSTOM_PACK 的 phase-2 规则不再求值（已在隔离 harness 用变体规则双向证实：同一 payload 阈值下变体规则不命中，CRS 无感的探针变体规则正常命中）。**防护结果无缺口**（请求仍被 949110 阻断，只是规则归因不是我们的包）；属 ftw 用例设计问题（`expect_ids` 断言特定包规则 ID，未考虑 CRS 先行中断），整改方向：换「CRS 低分但本包命中」的 payload，或放宽期望为「被阻断即可」。webshell-content 包在 CRS 未中断路径上工作正常。
- 遗留：ftw 全量绿需要按上述方向修订该簇用例（约 8 文件）+ 修 2 个 yaml 格式错误，列入 S1 语料扩编项（与 NG-BASE-04 §3 语料库合并管理）。

**未做**：Playwright E2E、性能回归（列入 S1 任务书前置项）。

## 4. 现状差异清单（文档描述 vs 当前实现，S0 校正）

| # | 差异 | 事实（已核对） | 影响 |
|---|------|---------------|------|
| D1 | 统一决策优先级 | 实际为 `BLOCK > TEMP_BLOCK > RATE_LIMIT > MASK_RESPONSE > OBSERVE > ALLOW`（RD_PLAN §3.2 已注明，S0 复核一致） | NG 契约按此设计 |
| D2 | 规则双轨生命周期（DRAFT→OBSERVE→TP/FP→READY_FOR_BLOCK→BLOCK + EMERGENCY 轨） | **未实现为产品功能**；当前只有「新检测规则默认 OBSERVE（pass+log）」的编写约定与 waf_rules 按条启停 | NG-AZ/REL 阶段若要正式生命周期需单独立项；NG-BASE-02 契约不得引用不存在的双轨状态机 |
| D3 | 业务流程状态 | 现有流程检测为观察型（观察请求推进），无面向阻断的事务状态机 | 方向四（强流程）按 RD_PLAN §9 新建独立命名空间 |
| D4 | gRPC 深检 | 当前仅首个完整未压缩帧的结构检查 | G1 按 §10 实施 |
| D5 | GraphQL | 基础操作识别+变量信息，无 AST 成本预算 | 方向二按 §7 实施 |
| D6 | MCP | JSON-RPC 方法与敏感参数观察线索，无工具目录/ACL | 方向六按 §11 实施 |
| D7 | 机器身份（DPoP/HTTP 签名） | 不存在；TLS 版本/密码套件弱指纹已有 | 方向七按 §12 实施 |
| D8 | 执行覆盖账本（FULL/PARTIAL/SKIPPED/ERROR/NOT_APPLICABLE 五态） | 不存在；现有「授权覆盖」「准入覆盖」为局部统计 | 方向一按 §5 实施 |
| D9 | 授权关系撤销/快照 | 已有撤销、重新授权、签名快照、PreviousValid 回退（RD_PLAN §3.2 注明，S0 静态复核接口存在） | 撤销水位/租约在 NG-AZ 阶段验证与扩展 |
| D10 | 授权门控白名单 | 已含 `/api/v1/upgrades/`（9-29 修复「锁定态无法升级」死锁） | NG 新接口默认不在白名单（业务接口口径） |

## 5. 环境基线

| 项 | 值 |
|---|---|
| 构建机 | macOS（arm64），Docker Desktop 运行中，可 linux/amd64 交叉构建与容器彩排 |
| stage5 本地栈 | API `http://127.0.0.1:18081`、网关 `http://127.0.0.1:18080`、测试宿主 `waf-s5.local`（当前 SecRuleEngine Off）、`shop.example.com`（On） |
| openEuler 测试机 | `192.168.3.201`（兆芯 x86_64）：当前运行 WDSP 1.2.1 docker 部署 + 手工替换的 api 镜像（含 9-29 三项修复）；**未装宿主机升级执行器**；裸机包未实机安装 |
| 授权中心 | 本机 `~/Documents/JiuZhang_License`（api 经 run-api-local.sh 运行，密钥库已迁至 `~/jiuzhang-license-data/` 并有基线备份） |

## 6. 基线结论与 S0 后续任务衔接

### 6.1 附记：stage5 真实 IP 三失败定责与结案（2026-10-03）

`stage5-gateway-tests.sh` 的 forge-xff-ignored / cc-forge-rotation / deny-conn-ip-forge-bypass 三失败经逐层定责，**全部为环境残留与套件自身脆弱性，非 9-29 真实 IP 代码回归**：

1. **残留可信代理**：9-20 手工验收遗留 `验收-网关前置测试跳板 172.19.0.0/16 ENABLED`（不在任何脚本的按名清理名单内）→ XFF 被信任 → 伪造防护用例全面反转。
2. **CC_AUTO 封禁残留**：cc-temp 用例在可信代理缺失时对 docker 网桥 IP 产生 300s CC_AUTO 临时封禁 → 下一轮 setup 读取连接源 IP 得空 → deny-conn 规则地址为空 → 级联误判（套件此前解封后立即读 /echo，未等轮询生效，存在竞态）。
3. **CIDR 唯一索引占用**：跳板被 DISABLED 后仍占 `ux_trusted_proxies_cidr`（部分唯一索引，仅排除 deleted_at）→ 套件 docker-bridge 重建被 409 静默拒绝 → 正向真实 IP 用例失败。

权限模型核实（非缺陷）：`trusted_proxies.*`、`temporary_blocks.manage` 按 000100 迁移属 SECURITY_ADMIN，SYSTEM_ADMIN 调用 403 系设计使然；测试框架的 `sec_admin_s5`（SECURITY_ADMIN）为正确操作账户。

修复（test/waf/scripts/stage5-gateway-tests.sh，已三轮实测）：setup 解封后**轮询等待 /echo 可读（15s）再取 CONN_IP，取不到立即中止**；残留清理改为**按 CIDR 包含关系删除（非禁用）覆盖连接源的可信代理**；docker-bridge 创建后**显式校验存在、失败即中止**。结果：连续两轮 **40/40 PASS**（此前 37/40 与 32/40）。

## 6.2 基线结论与 S0 后续任务衔接

1. 源码/依赖/测试事实已冻结如上；S0 其余任务（NG-BASE-02 契约、03 威胁模型、04 隔离语料）以本清单为输入。
2. 两项已知风险带入 S1 评估：openEuler 未实机验收裸机包、全量回归未跑（stage5 真实 IP 三失败已于 2026-10-03 结案，见 §6.1）。
3. 待用户/业务确认项（不阻塞 S0 文档工作，进入 S1 前必须闭环）：第一批业务范围（REST/GraphQL/gRPC/MCP 优先级）、权威关系来源系统、可承受严格失败策略的端点清单、隔离测试资源（openEuler/兆芯双节点）。详见 NG-BASE-03 待决策清单。
