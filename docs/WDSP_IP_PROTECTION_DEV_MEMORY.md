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
- `ops/offline-package/scan.py` 版本 1.6：在既有归档预算与 CRC 校验基础上，目录遍历、扫描和摘要均拒绝 FIFO、输入根软链接、不可读路径及扫描期叶文件替换；摘要与扫描共用截止时间，不完整扫描不再二次全量摘要读取。ZIP 中央目录、ZIP 本地成员头和 tar/PAX 解析元数据另计入全局 `--max-archive-metadata-bytes`（默认 32 MiB），超限 fail-closed，成员内容仍由既有解压后字节预算计量。Docker `manifest.json` 指向的配置、OCI 索引的 `platform` 声明及 OCI 镜像配置的 `os/architecture` 还必须分别确认并精确匹配目标 `linux/<平台>`；所有 OCI index/manifest descriptor 还必须绑定同路径实际 blob 的 SHA-256，缺失、损坏或不一致均拒绝。
- `test/offline-package/test_offline_package_scan.py` 已扩展至 32 个测试方法（含多格式/嵌套子用例）；2026-09-08 执行 `python3 -m unittest discover -s test/offline-package -p 'test_*.py' -v`：32 项通过，4.779 秒。新增 FIFO、根软链接、不可读目录、摘要截止时间、叶路径竞态，容器根文件系统绝对软链接与普通归档绝对软链接的边界测试，ZIP 中央目录与 tar PAX 元数据预算测试，Docker/OCI 配置和 OCI 索引平台绑定，OCI descriptor 摘要绑定，以及独立/hidden/inline Source Map、Docker history/RepoTags/config 凭据与报告脱敏的结构化交付样本测试。
- `test/wdsp-ip/docker-history-scan.py` 在本机缓存 linux/arm64 Docker 镜像构建“先复制源码、后在下一层删除”的真实历史层样本；2026-09-08 执行后，扫描器检出历史层源码并拒绝，证据为 `/private/tmp/wdsp-ip-history-20260908-c/evidence.json`。该脚本不签名、不发布，不能替代正式产物/平台矩阵验收。
- `test/wdsp-ip/attacker-package-gate.sh` 已覆盖 AT-12：临时生成攻击者 Ed25519 密钥、自制生产包、包内伪造验签脚本和公钥；从该目录启动仓库内官方安装器时，固定根验签失败，生产环境变量根覆盖与 `--allow-unsigned` 也分别被拒绝。2026-09-08 以 `bash test/wdsp-ip/attacker-package-gate.sh` 通过；全程在验签闸门退出，不执行安装或产生持久配置。
- AT-26/27 已修复并回归：完整性事实源的候选记录或加密原文临时不可读时，授权服务将状态如实置为 `IntegrityDatabaseUnavailable`（商业授权/产物完整性 `UNKNOWN`、网关 `PRESERVE_EXISTING`），既不误报 `LICENSE_INVALID`，也不触发旁路重发布。`gatewayconfig.Publisher` 在读取快照和生成配置前检查该发布门禁，以 `LICENSE_INTEGRITY_UNAVAILABLE` 结束任务并保留正在运行的网关配置；应用启动时同样不会因这类不确定故障首发旁路。故障恢复后重新验签并恢复正常发布。2026-09-08 已执行 `GOCACHE=/private/tmp/jiuzhang-waf-go-cache go test ./internal/license -count=1`、`go test ./internal/app -count=1` 通过；`go test ./internal/gatewayconfig -count=1` 需允许本地 IPv6 监听，复跑通过。
- 打包门禁 `bash test/wdsp-ip/offline-delivery-gates.sh` 已完成，exit 0：正式模式缺签名密钥拒绝、开发包追溯通过。开发模式 skip-images 门禁不等于完整正式包验收。
- 两个已启动子代理 Godel（AT-26/27）与 Sartre（AT-12）在先前轮次均因用量限制终止，没有交付可验收结果；不得把任务分配记录作为完成证据。
- 升级执行器的内嵌安全解压已补 8 GiB 总展开上限；`test/wdsp-ip/upgrade-executor-gates.sh` 从执行器提取并直接运行同一段 Python 逻辑，验证正常包可解压、路径穿越/符号链接/超过 20 个成员包均在写入前拒绝，并校验架构拒绝位于 `docker load` 前。该回归不触发 Docker、systemd 或真实升级，AT-08/AT-11 仍需隔离主机端到端安装、错误架构和回滚验证。
- 剩余软件重点：正式 Docker/OCI 多架构产品包的实际覆盖；超过 256MiB 的合法嵌套镜像容器的有界流式扫描；完整 API/UI/安装/升级回归。
- 不覆盖用户无关修改，不提交/推送/打 tag；生产根仍需受控输入，禁止以测试根替代。IP-10～13 无真实设备/证明环境的条目继续保持未完成。

## 2026-09-08 本轮补充回归

- 工作区默认 Node 25 不符合 `web/package.json` 的 Node 版本约束，已使用锁定的 Node 24.13.0 执行 `npm ci --include=optional` 恢复可选 Rollup 平台包；`npm run typecheck` 通过。
- 本轮曾启动的全量 Vitest、授权页面定向 Vitest 与生产构建被首个 30 秒命令窗口截断；随后保持同一全量 Vitest 进程短轮询，使用 Node 24.13.0 和 `NODE_OPTIONS=--no-experimental-webstorage` 取得最终退出码 0：108 个测试文件、824 个测试全部通过（99.62 秒）。stderr 仍有 jsdom 对伪元素 `getComputedStyle` 的既有实现提示和 Ant Design 弃用提示，但无测试失败。生产构建仍待本轮取得明确退出码。
- `GOCACHE=/private/tmp/jiuzhang-waf-go-cache go test . -count=1` 已在 `gateway/modules/jiuzhang_guard` 完成且无失败输出。完整网关 `./...`、服务端集成环境及端到端门禁仍不因此视为完成。

## 2026-09-08 流式扫描器与交付闸门复验

- `ops/offline-package/scan.py` 升至 `wdsp-offline-scan/1.7`：归档成员不再聚合为内存 `bytes`，改为受 `--max-in-memory-bytes`（默认 1 MiB）限制的临时文件流；内容规则以有限重叠窗口流式扫描，OCI Blob 摘要同时流式计算，受限结构化元数据才进入 JSON 解析。成员、总量、深度、数量、元数据和截止时间预算仍是 fail-closed，包内 `manifest.json` 超过结构化元数据上限会拒绝。
- `test/offline-package/test_offline_package_scan.py` 增加“大型嵌套成员在 1 KiB 内存阈值下可扫描”的回归；2026-09-08 执行 `python3 -m py_compile ops/offline-package/scan.py && python3 -m unittest discover -s test/offline-package -p 'test_*.py' -v && git diff --check`，33 个测试方法全部通过（4.022 秒）。该验证覆盖流式扫描行为，不代表已生成正式签名多架构产品包。
- 2026-09-08 再次执行 `bash test/wdsp-ip/offline-delivery-gates.sh`、`bash test/wdsp-ip/signed-delivery-gates.sh`、`bash test/wdsp-ip/attacker-package-gate.sh`、`bash test/wdsp-ip/upgrade-executor-gates.sh` 和 `git diff --check`，均通过。签名闸门仍仅使用临时测试密钥，正式厂商信任根、正式制品、隔离安装升级回滚及硬件/TEE验收仍不得标记为通过。
- 使用 Node 24.13.0 的 `PATH=... NODE_OPTIONS=--no-experimental-webstorage npm test --prefix web -- --run` 已在同一测试进程中取得 exit 0：108 个测试文件、824 个测试通过（99.62 秒）；`npm run build --prefix web` 同样 exit 0（Vite 6.4.3、6103 个模块）。
- `GOCACHE=/private/tmp/jiuzhang-waf-go-cache go test ./...` 在默认沙箱因禁止回环监听而退出 1；以允许本地回环临时 TCP/UDP 监听的同一命令复跑，所有 server 包 exit 0。前者是执行环境限制，不是业务测试失败。

## 2026-09-08 完整镜像离线包双架构复验

- `ops/offline-package/scan.py` 当前版本为 `wdsp-offline-scan/1.9`，策略版本为 `WDSP_IP-01/IP-02.v1`。私钥检测已收紧为完整 PEM 结构，OCI 裸 blob 的通用内容规则延后至层摘要校验完成后执行，避免同一层的重复发现；PostgreSQL 测试二进制源码命中仅通过路径、精确 SHA-256、例外编号和到期日共同约束，例外适用于 amd64 与 arm64 各自已审查摘要。
- `python3 test/offline-package/test_offline_package_scan.py` 已通过 48 项测试；覆盖 OCI 层不重复凭据、OCI 裸 blob 延后凭据、完整 PEM 检测和 PostgreSQL 双架构精确摘要例外。`bash -n ops/offline-package/build.sh` 与 `git diff --check` 同时通过。
- 2026-09-08 使用 `bash ops/offline-package/build.sh --product wdsp --version 1.0.0 --arch amd64 --development --output /private/tmp/wdsp-ip-amd64-development-tty5` 构建并最终重扫成功。报告 `/private/tmp/wdsp-ip-amd64-development-tty5/jiuzhang-wdsp-offline-1.0.0-amd64.scan.json` 为 `PASS`，`coverage.complete=true`，扫描 117 个归档、10,774 个成员、5,614,592 字节归档元数据、4,752,666,821 字节内容；产物 SHA-256 为 `fa6b2c120805050baa1fde9dd2333f487614e1d158c4e8c3bc7db7a31081857e`。
- 同日使用 `bash ops/offline-package/build.sh --product wdsp --version 1.0.0 --arch arm64 --development --output /private/tmp/wdsp-ip-arm64-development-tty2` 构建并最终重扫成功。报告 `/private/tmp/wdsp-ip-arm64-development-tty2/jiuzhang-wdsp-offline-1.0.0-arm64.scan.json` 为 `PASS`，`coverage.complete=true`，扫描 117 个归档、10,762 个成员、5,374,464 字节归档元数据、4,538,016,799 字节内容；产物 SHA-256 为 `45a1ac59319e2bed43662e63ffab4ea78b7a5202c2ef02d477a121b57ede4f98`。
- 两份 traceability sidecar 都绑定提交 `621d2e4a542ae8e78fa18b7fdc4067d5353d7832`、WDSP 1.0.0、策略 `WDSP_IP-01/IP-02.v1`、产物和扫描报告摘要。它们均为 `signed=false` 的开发包；没有 `WDSP_SIGNING_KEY` 时不得把这些结果升级为正式发行资格或 AT-01 PASS。
