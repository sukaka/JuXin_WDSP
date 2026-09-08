# WDSP IP 保护开发记忆

## 2026-09-07 基线

- 本轮按 `docs/WDSP_IP_PROTECTION_DESIGN.md` 从 IP-03 开始，仅处理“生产授权验签信任根不可被运行时环境变量替换”。
- 当前工作树已有大量用户未提交修改；本轮只修改与 IP-03 直接相关的授权装配、测试注入、Compose/环境说明和测试脚本。
- `server/internal/license/vendor_pubkey.hex` 当前没有真实生产公钥。实现必须保持 fail-closed，不能写入测试公钥或虚构厂商密钥。
- 生产路径使用 Go 内嵌公钥表；集成测试通过应用装配层的显式依赖注入传入测试公钥，不再依赖 `LICENSE_VENDOR_PUBLIC_KEY`。
- 本轮不处理离线发布包签名公钥 `WDSP_PACKAGE_PUBLIC_KEY` / `WDSP_RELEASE_PUBKEY_PEM`，它属于发布包验签信任根的后续 IP 任务。

## 待验证

- 授权集成测试与 WDSP E2E 已迁移到显式 `wdsp_testkeys` 构建或应用装配层注入；后续新增测试不得恢复生产环境变量覆盖。
- 真实生产公钥需由授权中心/发布流程提供并经正式构建嵌入，不能由本轮生成。

## 2026-09-07 继续开发

- 已建立 IP-00/S0 基线和验收矩阵：`docs/WDSP_IP_PROTECTION_BASELINE.md`、`docs/WDSP_IP_PROTECTION_ACCEPTANCE.md`；矩阵使用 `NOT_RUN/PASS/FAIL/BLOCKED/NOT_APPLICABLE`，未用已有代码冒充验收证据。
- 已明确关闭前端生产 source map：`web/vite.config.ts` 设置 `build.sourcemap=false`。
- 已增强 `ops/diagnostics/collect.sh`：环境、Compose 日志和健康响应统一脱敏；默认不采集私钥、会话、请求/响应正文、内存转储；诊断包带清单与 SHA-256；回归脚本为 `test/wdsp-ip/diagnostics-collect.sh`。
- 当前验收主机为 Apple Silicon macOS；没有 `/dev/tpmrm0`、TPM 工具链或已配置的 TDX/SEV-SNP 证据。边界已记录在 `docs/WDSP_IP_PROTECTION_HARDWARE_EVIDENCE.md`，IP-10～IP-13 的硬件/TEE项不能标记为通过。

## 当前并行工作

- IP-01～IP-09 已有部分实现和本地回归，不等于模块全部完成。2026-09-08 继续核查发现扫描器漏检与资源限制缺口，仍需修改软件并补充真实产物验收；不能把工作限制为补证据。

## 2026-09-07 全量实施快照

- IP-01/IP-02 已落地：`ops/offline-package/allowlist.v1`、`scan.py` 和 `build.sh` 现在按 allowlist 复制运行时文件，递归扫描目录、tar/zip/嵌套归档，拒绝源码、source map、疑似秘密、路径穿越、符号链接逃逸、未知格式和预算超限，并绑定 allowlist/manifest/扫描报告/归档摘要。
- IP-05 已接入正式构建门禁：构建脚本只有显式 `--development` 才允许无签名密钥；正式模式缺少 `WDSP_SIGNING_KEY` 直接失败。安装、升级预检和执行前均复核固定发布公钥、`.sig`、manifest 内容和归档布局；新增 `test/wdsp-ip/signed-delivery-gates.sh` 使用临时 Ed25519 密钥验证机制，但该密钥不构成生产证据。
- IP-04 已补齐原始 `.lic` 的加密保存、复核和保护状态语义：原文缺失、加密材料不可用、解密失败、签名/字段不一致、过期和设备不匹配分别处理。合法历史迁移、根轮换和恢复仍需要真实授权材料。
- IP-06～IP-09 已补齐一部分：后端生产构建使用 `-trimpath -ldflags='-s -w'`，Web sourcemap 关闭；诊断默认脱敏；授权状态拆分商业授权、产物完整性、网关防护、机密计算和恢复；构建生成 traceability sidecar；OpenAPI/Go/TypeScript 状态契约已对齐。前端全量 Vitest（107 个文件、816 个测试）、类型检查和生产构建已通过；完整网关/多架构产物、API/UI/权限 E2E 仍待验收。
- IP-10～IP-13 保持阻断：当前 Apple Silicon macOS 没有 `/dev/tpmrm0`、TPM 工具链、TDX/SEV-SNP 或批准的证明服务，不能用软件指纹、Docker 或临时 Mock 代替。

本轮已通过的代表性命令：

```text
GOCACHE=/tmp/jz-waf-go-cache go test ./internal/license ./internal/app ./tests ./internal/upgrades -count=1
python3 -m unittest discover -s test/offline-package -p 'test_*.py' -v
bash test/wdsp-ip/offline-delivery-gates.sh
bash test/wdsp-ip/signed-delivery-gates.sh
bash test/wdsp-ip/diagnostics-collect.sh
npm run typecheck --prefix web
NODE_OPTIONS=--no-experimental-webstorage npm test --prefix web -- --run
npm run build --prefix web
```

前端回归在 Apple Silicon 的 arm64 Node 上执行，并使用 `NODE_OPTIONS=--no-experimental-webstorage` 避免 Node 25 实验性 Web Storage 与 jsdom 的既有冲突；测试、类型检查和构建均通过。没有生产签名私钥、公钥授权材料和批准硬件前，不要把相关验收条目改为 `PASS`，也不要生成版本 tag 或 push。

## 2026-09-07 前端与接口契约回归

- `server/openapi/fragments/06-ops.yaml` 新增 `LicenseProtectionState`，并为 `LicenseState.integrity_status` 与 `protection_state` 补齐枚举和结构；已运行 `python3 server/openapi/merge.py` 生成 `server/openapi/wdsp-api.yaml`。
- `server/internal/license/handler_test.go` 增加状态接口序列化断言，确保未导入授权时的商业授权、产物完整性、网关防护、机密计算和标准离线形态不会被 UI 误读。
- `web/src/types/index.ts` 增加 `LicenseIntegrityStatus` 联合类型，和 Go/OpenAPI 的状态码保持一致。
- `npm run typecheck`、`NODE_OPTIONS=--no-experimental-webstorage npm test -- --run`、`npm run build` 均通过；全量 Vitest 为 107 个测试文件、816 个测试。
- `check-api-reconcile.py` 可执行并报告现有 36 条未收录路由；这些路由属于既有 WDSP Agent、流量和 APM 文档缺口，本轮没有扩大范围伪装为 IP-08 已完成。

## 2026-09-08 扫描器修复与接续点

- 用户目标仍是完整设计全部实现与验收，不缩减为标准离线版本地单测；硬件和正式授权材料缺失不妨碍继续修复软件。
- 上一开发轮修复无扩展名/伪装 AppleDouble 镜像层漏扫、嵌套 Docker manifest 被误认成交付 manifest、JSON 凭据及 base64 尾部等号漏检；12 项扫描器测试和开发打包门禁通过。仅豁免已确认的两条 WAF 规则文档示例，不恢复通用等号豁免。
- 本轮先运行新增失败测试：17 个方法中 15 个失败断言/子用例，复现单文件压缩误判、ZIP 链接大小限制旁路及 CRC 异常被吞、累计预算超限后继续读取、空成员数量无限制、普通成员误占归档深度。
- `ops/offline-package/scan.py` 版本 1.2：共用归档读取流程，支持 gzip/bzip2/xz 单文件解压后扫描，tar 逐成员遍历，ZIP 链接和文件统一受限读取及 CRC 校验，新增全局 `--max-archive-members`（默认 100000），累计字节超限后停止；不完整扫描不再二次全量摘要读取。
- `test/offline-package/test_offline_package_scan.py` 现有 18 个测试方法（含多格式/嵌套子用例）；2026-09-08 执行 `python3 -m unittest discover -s test/offline-package -p 'test_*.py' -v`：18 项通过，2.395 秒。新增加压缩炸弹和截断流验证，ZIP 嵌套预算样本使用压缩后的小容器，避免只测到外层大小限制。
- 打包门禁 `bash test/wdsp-ip/offline-delivery-gates.sh` 已完成，exit 0：正式模式缺签名密钥拒绝、开发包追溯通过。开发模式 skip-images 门禁不等于完整正式包验收。
- 两个已启动子代理 Godel（AT-26/27）与 Sartre（AT-12）在先前轮次均因用量限制终止，没有交付可验收结果；不得把任务分配记录作为完成证据。
- 剩余软件重点：真实 Docker 删除历史层样本；Docker/OCI 描述符、摘要和实际平台覆盖；超过 256MiB 的合法嵌套镜像容器的有界流式扫描；ZIP 中央目录、tar PAX 元数据解析预算；扫描/摘要全流程超时、特殊文件和不可读目录；AT-12、AT-26/27 以及完整 API/UI/安装/升级回归。
- 不覆盖用户无关修改，不提交/推送/打 tag；生产根仍需受控输入，禁止以测试根替代。IP-10～13 无真实设备/证明环境的条目继续保持未完成。
