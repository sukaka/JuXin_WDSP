# WDSP IP 保护验收台账

> 依据：[WDSP_IP_PROTECTION_DESIGN.md](/Users/zhanglei/Documents/JiuZhang_WAF/docs/WDSP_IP_PROTECTION_DESIGN.md)  
> 首次建立：2026-09-07  
> 规则：没有命令输出、产物摘要或真实设备记录，不得将 `NOT_RUN` 改为 `PASS`。

## 1. 状态与证据规则

允许的验收状态：

- `NOT_RUN`：尚未执行，或只有静态阅读/单元测试不足以覆盖验收条件。
- `PASS`：测试输入、平台、产物摘要和结果完整，且没有未说明的覆盖缺口。
- `FAIL`：验收条件未满足。
- `BLOCKED`：依赖真实硬件、合法授权、生产签名或外部受控材料，当前无法安全伪造；必须写明解除条件。
- `NOT_APPLICABLE`：经评审确认该产品形态不适用，并记录替代控制；不能用资源不足代替该状态。

每条证据应包含：执行日期、提交/工作树状态、命令或测试入口、输入摘要、平台/架构、扫描器/策略版本、结果摘要和报告路径。敏感值只记录规则编号、脱敏摘要和位置，不记录秘密正文。

### 1.1 当前验收范围

2026-09-08，用户明确暂缓所有必须依赖真实部署环境、正式厂商签名材料或批准硬件/TEE 的验证，待环境部署完成后继续。本轮不执行这些外部验收，也不因此改变其 `NOT_RUN` 或 `BLOCKED` 状态；暂缓不等同于通过或不适用。

## 2. IP 项目进度（2026-09-08）

| 项目 | 阶段 | 状态 | 当前证据/下一步 |
|---|---|---|---|
| IP-00 基线与决策 | S0 | PASS | 基线、硬件边界、追溯和本台账已建立；不授予发行资格 |
| IP-01 交付白名单 | S1 | PASS | `ops/offline-package/allowlist.v1` 和构建复制范围已通过本地测试；完整产品矩阵待验收 |
| IP-02 递归扫描 | S1 | NOT_RUN | 扫描器已升至 `wdsp-offline-scan/1.9`，48 项回归通过；2026-09-08 已构建含完整镜像的 WDSP 1.0.0 amd64/arm64 开发离线包，并完成两次最终归档递归扫描（均 `PASS`、`coverage.complete=true`）。但两包均未正式签名，且未覆盖全部产品线、正式发布环境与大容器边界，不能将全项验收标为 PASS。完整证据见第 7 节。 |
| IP-03 固定生产信任根 | S2 | PASS | 正式构建内嵌根不受运行时环境变量覆盖；生产公钥为空时明确 fail-closed |
| IP-04 签名原文/迁移 | S2 | PASS | 原文事实源、异常状态、DB 篡改复核有 Go 测试；合法历史迁移/根轮换尚无受控材料 |
| IP-05 强制签名交付 | S1/S2 | PASS | 缺签名密钥拒绝、临时签名链、安装/升级前置验签和 TOCTOU 复核通过 |
| IP-06 Go/Web 加固 | S3 | NOT_RUN | 后端 stripped build、Web sourcemap 门禁已落地；完整网关/多架构客户产物待验收 |
| IP-07 诊断与私有归档 | S3 | PASS | 诊断脱敏、支持包清单、发布标识和私有调试归档边界有回归脚本 |
| IP-08 状态与审计 | S3 | NOT_RUN | Go 状态模型、OpenAPI/TypeScript 状态契约和 Web 全量回归已通过；2026-09-08 已补完整性依赖短暂故障时的状态与配置发布隔离回归；完整 API/UI/权限审计 E2E 未完成 |
| IP-09 交付追溯 | S3 | PASS | traceability sidecar 和 release/build/package/scan 字段已落地；正式 tag/签名流程待验收 |
| IP-10 硬件绑定 | S4 | BLOCKED | 标准离线版不宣称强硬件保护；当前主机无批准硬件证据 |
| IP-11 机密计算最小 PoC | S5 | BLOCKED | 无真实 TEE、远程证明和密钥释放环境 |
| IP-12 离线机密计算 PoC | S5 | BLOCKED | 无批准设备执行离线生命周期验证 |
| IP-13 机密计算产品化 | S6 | BLOCKED | 依赖真实 S5、HA、升级和性能门禁 |

## 3. AT-01～AT-15：交付与构建

| 编号 | 状态 | 证据/备注 |
|---|---|---|
| AT-01 | NOT_RUN | 2026-09-08 已对含完整镜像的 WDSP 1.0.0 amd64/arm64 开发包分别完成最终递归扫描：amd64 扫描 117 个归档、10,774 个成员、4,752,666,821 字节；arm64 扫描 117 个归档、10,762 个成员、4,538,016,799 字节；两者 `coverage.complete=true`。但它们是未签名开发包，且“各产品正式包”条件未满足。 |
| AT-02 | NOT_RUN | 本机缓存 linux/arm64 Docker 历史删除层样本已由 `test/wdsp-ip/docker-history-scan.py` 扫描并检出删除源码（扫描器拒绝）；未驱动正式签名/发布，且非平台矩阵，仍不满足全项 PASS |
| AT-03 | PASS | `test/offline-package` 覆盖嵌套归档和 source map 拒绝 |
| AT-04 | NOT_RUN | Source map 规则和 Web sourcemap 关闭已具备；结构化交付 tar 样本已覆盖独立 `.map`、hidden `.map` 和 inline `sourceMappingURL` 三种形态并拒绝，且报告不回显内容；实际 amd64/arm64 WDSP 开发包最终扫描也通过，但尚未对正式签名发布包执行本用例。 |
| AT-05 | NOT_RUN | JSON/base64 假凭据与不回显值测试通过；结构化 Docker save 样本已覆盖 history、RepoTags 与 config 三处假凭据并拒绝、报告不回显标记；实际 amd64/arm64 WDSP 开发包最终扫描也通过，但未在正式发布镜像中植入并验证人工测试标记，局部测试不足以证明全项通过。 |
| AT-06 | NOT_RUN | 路径/链接逃逸、FIFO/输入根软链接/不可读目录拒绝、ZIP 链接 CRC 与大小限制、压缩炸弹、空成员数量和累计预算回归通过；ZIP 中央目录与 tar PAX 解析元数据预算已覆盖；完整产品包仍待验收 |
| AT-07 | NOT_RUN | 已验证格式解析失败、超时、预算不足拒绝，且扫描与摘要共用超时/不可读目录策略；Docker 配置、OCI 索引声明及 OCI 配置的平台不明或不匹配均拒绝，OCI descriptor 指向缺失或摘要不匹配 blob 也拒绝；实际 WDSP amd64/arm64 开发包扫描均完整通过，但全部产品、正式发布流水线和资源上限压力矩阵仍未闭环。 |
| AT-08 | NOT_RUN | `bash test/wdsp-ip/upgrade-executor-gates.sh` 覆盖缩减后升级执行器的实际内嵌安全解压逻辑：正常包可解压，路径穿越、链接和超过 20 个成员的归档均在写入前拒绝；仍待完整离线包安装、升级及恢复回归 |
| AT-09 | PASS | `offline-delivery-gates.sh` 验证正式模式缺少 `WDSP_SIGNING_KEY` 时拒绝 |
| AT-10 | PASS | 构建顺序、最终归档重扫、manifest/scan/artifact 摘要绑定和签名后摘要复核已通过门禁 |
| AT-11 | NOT_RUN | Go artifact verifier 测试覆盖签名、manifest 内容、归档布局、路径穿越和执行前复核；`bash test/wdsp-ip/upgrade-executor-gates.sh` 另确认安全解压拒绝危险归档，且架构检查位于 `docker load` 前。尚未在隔离主机执行已签包篡改、内部脚本替换和错误架构完整升级/配置不变性回归，不能标为 PASS |
| AT-12 | PASS | `bash test/wdsp-ip/attacker-package-gate.sh`：官方安装器从攻击者自制生产包目录执行时，包内伪造验签脚本/公钥与攻击者签名均不能自证；生产环境变量根覆盖及 `--allow-unsigned` 降级也被拒绝，且在任何安装前终止 |
| AT-13 | NOT_RUN | 后端 stripped build 已验证；实际网关 ELF、最终 Web 客户包和产物报告未齐备 |
| AT-14 | NOT_RUN | 待 amd64/arm64 和声明 CPU 基线回归 |
| AT-15 | PASS | `test/wdsp-ip/diagnostics-collect.sh` 通过：发布标识、清单、摘要和脱敏边界可复现 |

## 4. AT-16～AT-32：授权、迁移与业务安全

| 编号 | 状态 | 证据/备注 |
|---|---|---|
| AT-16 | PASS | 正式构建测试验证 `LICENSE_VENDOR_PUBLIC_KEY` 环境变量不能覆盖内嵌根；攻击者自签授权仍需真实生产根材料做端到端验收 |
| AT-17 | NOT_RUN | 已关闭运行时根覆盖；正式二进制在生产环境修改 `APP_ENV` 的黑盒尝试未执行 |
| AT-18 | PASS | Dockerfile 默认不启用 `wdsp_testkeys`，测试根只在显式测试构建/注入路径；正式发布包门禁仍需 CI 实跑 |
| AT-19 | BLOCKED | 当前没有合法既有生产根和 `.lic`，不能伪造“合法授权继续有效”证据 |
| AT-20 | NOT_RUN | 需要经批准的根轮换材料和兼容窗口 |
| AT-21 | PASS | `server/internal/license` 服务测试覆盖 DB 派生字段与签名原文不一致时的篡改状态 |
| AT-22 | PASS | 服务测试覆盖 raw 原文缺失、加密器未装配/失败和解密失败的区分；接口 E2E 待完成 |
| AT-23 | NOT_RUN | 需要合法原始 `.lic` 的历史迁移与备份恢复 |
| AT-24 | PASS | 导入要求可复核的加密原始文件，DB-only 历史行不会被当作完整授权事实源 |
| AT-25 | PASS | 授权签名/载荷篡改及原文复核测试通过；完整字段矩阵仍需生产样本 |
| AT-26 | PASS | `GOCACHE=/private/tmp/jiuzhang-waf-go-cache go test ./internal/license -count=1` 通过：`TestServiceIntegrityDependencyFailurePreservesGatewayConfiguration` 覆盖候选授权记录与加密原文两类临时读取故障；状态明确为 `UNKNOWN/PRESERVE_EXISTING`，不误报 `LICENSE_INVALID`、不重发布，恢复后重新验签并恢复发布。 |
| AT-27 | PASS | `go test ./internal/license -count=1`、`go test ./internal/gatewayconfig -count=1`、`go test ./internal/app -count=1` 均通过：完整性无法验证时服务禁止发布，发布器在读取/生成配置前以 `LICENSE_INTEGRITY_UNAVAILABLE` 停止任务，应用启动路径不生成无效授权旁路配置；确定的授权失效仍保留既有旁路策略。 |
| AT-28 | NOT_RUN | 待主备、授权恢复和合法换机回归 |
| AT-29 | NOT_RUN | 待权限、审计、敏感字段脱敏 E2E |
| AT-30 | NOT_RUN | 待软件指纹复制、时间回退、快照的边界记录 |
| AT-31 | NOT_RUN | 待 WAF/WDSP/API/APM/Agent 组合回归 |
| AT-32 | NOT_RUN | 待网关白名单、JWT、WAF、API 动态防护顺序回归 |

## 5. AT-33～AT-50：硬件与机密计算

| 编号 | 状态 | 证据/备注 |
|---|---|---|
| AT-33 | BLOCKED | 当前无批准硬件；软件指纹复制不能替代设备持有证明 |
| AT-34 | BLOCKED | 当前无 TEE 平台；解除条件是“不支持”路径的实机证据且不得交付明文密钥 |
| AT-35 | BLOCKED | 无真实证明服务和批准安全版本 |
| AT-36 | BLOCKED | 无真实证明协议、会话密钥和新鲜性测试环境 |
| AT-37 | BLOCKED | 无机密计算 PoC 密文/清单/版本输入产物 |
| AT-38 | BLOCKED | 无受保护来宾和真实宿主机导出测试环境 |
| AT-39 | BLOCKED | 当前主机没有批准 TEE/远程证明环境 |
| AT-40 | BLOCKED | 无受保护来宾生命周期和维护面测试环境 |
| AT-41 | BLOCKED | 无可信启动/度量链实机证据 |
| AT-42 | BLOCKED | 无机密计算 PoC 运行、崩溃和诊断证据 |
| AT-43 | BLOCKED | 无批准离线 TEE 激活与恢复设备 |
| AT-44 | BLOCKED | 无批准快照/代理密钥服务测试环境 |
| AT-45 | BLOCKED | 无证明服务、HA 和故障切换部署 |
| AT-46 | BLOCKED | 无机密计算版本撤销与解密授权服务 |
| AT-47 | BLOCKED | 无批准固件、安全基线和证明策略更新链 |
| AT-48 | BLOCKED | 无机密计算密钥释放业务接口；普通 API 测试不能替代本项 |
| AT-49 | BLOCKED | 无受保护运维、备份和排障环境 |
| AT-50 | BLOCKED | 无真实 TEE 工作负载、性能基线和故障切换环境 |

## 6. 证据记录模板

后续每次验收在对应章节追加记录，至少使用以下字段：

```text
编号：AT-XX
状态：PASS | FAIL | BLOCKED | NOT_APPLICABLE
执行时间：YYYY-MM-DDThh:mm:ss+08:00
提交/工作树：<commit>；clean/dirty；说明既有改动边界
输入产物：<产品>/<版本>/<架构>；SHA-256=<digest>
策略/工具：<策略版本>/<扫描器或测试版本>
命令或入口：<可复现命令>
结果摘要：<不含秘密正文>
证据路径：<报告/日志/产物相对路径>
限制与后续：<未覆盖平台、外部依赖或整改项>
```

`BLOCKED` 必须给出解除条件；`NOT_APPLICABLE` 必须给出产品形态、替代控制和评审依据。没有真实生产公钥、合法授权或批准硬件时，不得用自造材料把对应条目改为 `PASS`。
