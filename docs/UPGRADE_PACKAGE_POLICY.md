# 补丁包与升级包规则

本文约束 WDSP 的版本交付物类型。生成发布文件前必须先读取根目录 `VERSION.md`，以其中的当前已发布版本为基线。

## 一、交付物分类

| 场景 | 版本变化 | 交付物 | 内容 |
|---|---|---|---|
| 单个或少量 Bug 修复 | 第三位递增 | 统一签名升级包 | 自动识别需要更新的应用镜像，附清单与校验值 |
| 多个功能更新或功能优化 | 第二位递增、第三位归零 | 统一签名升级包 | 自动识别需要更新的应用镜像，附清单与校验值 |
| 大改版、全新安装、基础设施整体变更 | 第一位递增或新安装 | 完整离线安装包 | 应用、基础设施镜像、部署配置和安装工具 |

小补丁包不得捎带未变化的网关、PostgreSQL、Valkey、日志轮转或 APM 镜像，也不得使用源码补丁冒充部署补丁。

## 二、命名规则

- 历史小补丁包：`jiuzhang-wdsp-patch-X.Y.Z-to-X.Y.N-ARCH.tar.gz`（旧格式，仅保留历史说明，不再生成）
- 升级包：`jiuzhang-wdsp-upgrade-X.Y.Z-ARCH.tar.gz`
- 完整离线安装包：`jiuzhang-wdsp-offline-X.Y.Z-ARCH.tar.gz`

`ARCH` 目前为 `amd64` 或 `arm64`。每个交付物必须同时提供同名 `.sha256` 文件。

## 三、1.0.1 的明确口径

`1.0.0` → `1.0.1` 是审计管理员权限收敛的 Bug 修复，只制作小补丁包。补丁只包含：

- `jiuzhang-server:1.0.1`
- `jiuzhang-web:1.0.1`
- `manifest.json`
- `SHA256SUMS`
- `installer/install-executor.sh`
- `installer/upgrade-executor.sh`

不包含网关、数据库、缓存、日志轮转和 APM 镜像。

## 四、Web 升级兼容性

当前 `1.0.0` 的 Web 升级后台能上传、保存和校验文件，但执行阶段不会解包或切换上传包中的 Docker 镜像。API 容器也是只读运行且未挂载 Docker Socket，因此不能在容器内直接完成镜像切换。

`1.0.1` 已提供宿主机升级执行器及安装脚本。首次从 `1.0.0` 升级时，需要在宿主机用 root 权限安装一次执行器；安装脚本可同时投递 `1.0.1` 补丁。此后 Web 升级由 API 写入任务、宿主机执行器切换镜像，API 收到执行结果后才显示成功。

## 五、升级包（upgrade）构建与上传

Bug 修复与功能更新都使用 `ops/upgrade/build-upgrade-pack.sh`，默认自动检测组件。旧 `build-patch.sh` 仅转发到统一入口，不再维护另一套包格式：

```bash
# 只预览变化，不需要 Docker 或私钥，不生成文件：
bash ops/upgrade/build-upgrade-pack.sh --to 1.3.0 --arch amd64 --plan

# 自动识别 → 构建变化组件 → 结合基准归档生成层差量 → 签名 → 打包 → 自检：
WDSP_SIGNING_KEY=/path/to/ed25519-private.pem \
  bash ops/upgrade/build-upgrade-pack.sh --from 1.11.1 --to 1.11.2 --arch amd64 \
  --base-archive dist/update-full-1.11.1-amd64/jiuzhang-wdsp-update-full-1.11.1-amd64.tar.gz

# 连续链式 Web 差量升级（如 1.11.1 完整包 → 1.11.2 差量包 → 1.11.3 差量包），按从旧到新顺序传入多个 --base-archive：
WDSP_SIGNING_KEY=/path/to/ed25519-private.pem \
  bash ops/upgrade/build-upgrade-pack.sh --from 1.11.2 --to 1.11.3 --arch amd64 \
  --base-archive dist/update-full-1.11.1-amd64/jiuzhang-wdsp-update-full-1.11.1-amd64.tar.gz \
  --base-archive dist/jiuzhang-wdsp-upgrade-1.11.2-amd64.tar.gz

# 本机已有 jiuzhang-<名>:<to> 镜像时跳过 docker build（若需关闭层差量可追加 --no-layer-delta）：
WDSP_SIGNING_KEY=/path/to/ed25519-private.pem \
  bash ops/upgrade/build-upgrade-pack.sh --to 1.11.2 --arch amd64 --skip-build
```

- `--from` 缺省读取根目录 `VERSION.md` 的「当前已发布版本」；`--to` 必填且必须高于 `--from`。
- `--components` 默认 `auto`，无需填写。支持全 9 个自研容器组件：`api`、`web`、`gateway`、`netmgrd`、`mirrorcap`、`tproxyd`、`logrotator`、`containerops`、`pcapd`（其中 `pcapd` 按 `request-pcap` profile 守卫：宿主机未运行 `pcapd` 时仅更新镜像标签，绝不擅自启动抓包）。显式清单仅作为已有基线经人工验证的兼容入口，不执行 Git 自动检测，不能证明变更已完整覆盖；日常发布不要使用。
- **精确 `from → to` 镜像层差量（`layer-delta`）**：
  - 指定 `--base-archive <基准离线包或历史升级包>`（或由构建脚本自动探测 `dist/` 下对应 `--from` 的基准归档，亦可本地联调用 `--base-from-docker`）后，构建脚本调用 `ops/upgrade/image-delta.py` 仅导出相对 `--from` 变化的新增层，未变的基础层（Alpine、Caddy、GeoIP、运行库等）仅以未压缩层摘要 `diff_id` 记录于 `manifest.json` 的 `images[].base_layers`。
  - 若基准归档经 `no-docs-tests-v1` 裁剪（完整离线包/`update-full`），构建脚本自动同步裁剪新镜像层，保证跨版本未变层 `diff_id` 精确匹配；若未复用任何层或节省不足 1 MiB，自动回退为完整组件镜像导出（`delivery_mode: "full"`）。
  - 宿主机执行器（`upgrade-executor.sh` + `/usr/local/libexec/jiuzhang-image-delta.py`）在加载/切换任何镜像前先对当前运行镜像做 `check-base` 预检，任一基础层缺失立即 fail-closed 中止且不触碰容器；校验通过后本地拼装并逐层校验 SHA-256 后 `docker load`。
  - 后端升级成功后自动把 `version_to` 持久化到 `system_settings`（`system:current_version`），确保纯前端/网关/sidecar 等未替换 `api` 镜像的差量升级完成后，下一次 `from → to` 精确预检版本连续。
- “上次”指 `VERSION.md` 当前已发布版本对应的 tag，不是上次执行打包的时间。打包不会改写版本、提交、打 tag 或推送；实际部署版本不同时须传 `--from`，缺少对应 tag 则拒绝自动打包。
- 镜像内使用运行时构建产物，包不复制仓库、测试目录或产品文档。同名产物已存在时拒绝覆盖。跨主版本以及镜像无法交付的宿主机变更不属于此升级格式。
- 产物在 `dist/`：`jiuzhang-wdsp-upgrade-<to>-<arch>.tar.gz` + 旁车 `.sha256`（单文件格式：签名内嵌包内根目录 `manifest.sig`，不再产独立 `.sig` 与 manifest 副本；上传只需传文件本身）。
- 正式包必须签名：`WDSP_SIGNING_KEY` 必须对应 `ops/offline-package/release-signing.pub` 的已有发布私钥；不能生成随机密钥替代。缺少或不匹配时拒绝正式打包；`--unsigned` 仅限本地开发自测，不能用于前台升级。优先级注意：构建机已设置 `WDSP_SIGNING_KEY` 时密钥优先于 `--unsigned`，仍会产出签名包（S8 批次 C 实证，REL-02 报告 F2）；确需未签名产物须先清空该环境变量。

### `--components auto` 自动识别

`--components auto` 以 `wdsp-v<--from>` tag 为基准，用 `git diff --name-only <tag>..HEAD` 加工作区未提交改动（含未跟踪；存在时打印警告，正式包建议先提交）自动判定该升级哪些组件。脚本只读仓库：tag 缺失时报错并提示先 `git fetch --tags`，绝不自行 fetch 或做任何 git 写操作。纯测试文件（`*_test.go`、`*/__tests__/*`、`web/e2e/*`、`*.test.ts(x)`、`*.spec.ts(x)`）自动跳过，不触发无意义镜像重建。

路径 → 组件映射：

| 变更路径 | 组件 |
|---|---|
| `server/cmd/containeropsd/`、`server/internal/containeropsd/`、`deployment/containerops/Dockerfile` | `containerops` |
| `server/go.mod`、`server/go.sum`、根 `.dockerignore` | `api` + `containerops` |
| `server/` 其余（含 migrations/openapi） | `api` |
| `web/` | `web` |
| `gateway/netmgrd/`、`gateway/cmd/netmgrd/`、`gateway/images/netmgrd/` | `netmgrd` |
| `gateway/mirrorcap/` | `mirrorcap` + `pcapd` |
| `gateway/cmd/mirrorcap/`、`gateway/images/mirrorcap/` | `mirrorcap` |
| `gateway/tproxyd/`、`gateway/cmd/tproxyd/`、`gateway/images/tproxyd/` | `tproxyd` |
| `gateway/pcapcapture/`、`gateway/cmd/pcapd/`、`gateway/images/pcapd/` | `pcapd` |
| `gateway/images/logrotator/` | `logrotator` |
| `gateway/dynamic_security/`、`gateway/pcapevidence/`、`gateway/go.mod`/`go.sum`、`gateway/modules/jiuzhang_guard/` 共享包 | 按 Dockerfile 实际 `COPY` 依赖图自动映射到受影响组件集合 |
| `gateway/rules/` | `api` + `gateway` |
| `gateway/` 其余（`gateway/havipd/` 为裸机专用跳过） | `gateway` |
| `deployment/`（除 `containerops/Dockerfile`）、根 Compose、`ops/upgrade/upgrade-executor.sh`、`install-executor.sh`、`image-delta.py`、`wdsp-agent/`、`packaging/` | 拒绝自动打包：宿主机/Agent 变更不能靠应用镜像替换落地 |
| `ops/` 其余、`docs/`、`test/`、`tools/`、`scripts/`、测试文件等 | 非应用运行时变更，提示跳过 |
| 未命中任何映射的路径 | 报错并列出，需补充映射 |

判定证据逐组件打印（`auto 证据: <组件> ← 命中 N 条路径；示例: <前 5 条>`）后继续构建（非交互）。变更使用 NUL 分隔读取，跨目录重命名同时检查来源与目标组件；合并冲突、非祖先基准、无应用更新时拒绝打包。

通常只需指定 `--to` 和目标 `--arch`；可先使用 `--plan` 查看证据，但无需手工将结果抄回组件列表。

### manifest.json 双口径

包内单一 `manifest.json` 同时满足两套消费者，字段不冲突：

| 字段 | 服务端（artifact.go） | 宿主机执行器（upgrade-executor.sh） |
|---|---|---|
| `version` / `arch` | 必须与升级目标版本一致 / 与服务器 `runtime.GOARCH` 一致（读自包内 manifest.json，不再依赖上传表单字段） | `arch` 必须与宿主机架构一致 |
| `files` / `files_manifest_sha256` | 与归档常规文件精确一一对应（**`files` 不得收录 `manifest.json`/`manifest.sig`**，两者为保留根文件，否则按保留路径拒绝）；摘要 == sha256(Go `json.Marshal` 紧凑序列化的 files 数组） | 逐一校验存在性/大小/SHA-256，并反查除 `manifest.json`/`manifest.sig` 外无未声明文件（同口径） |
| `package_type: "upgrade"` / `components` / `images[]` | 忽略（多余字段不校验） | 协议主字段：`components` 白名单校验、`images[]` 逐组件 docker load → retag → `compose up -d` |
| `target_schema_version` | 预检从包内 manifest.json 读取（≤ 本地最大迁移号 +1） | 不使用 |

包内路径强制白名单 `^[A-Za-z0-9._/-]+$`（排除 `<>&` 与非 ASCII），保证 python3 紧凑序列化与 Go `json.Marshal`（HTML 转义）字节一致；该一致性由 `ops/upgrade/tests/upgrade-pack-harness.sh` 内置的 Go 同口径校验器回归验证。

### 签名与上传

- 单文件格式：签名内嵌包内根目录 `manifest.sig`（base64 单行文本），内容 = 对 `manifest.json` 在归档内原始字节的 Ed25519 签名（`openssl pkeyutl -sign -rawin`，与 `ops/lib/signing.sh` 同算法，仅输入从整包变为 manifest.json）；不再产出独立 `.sig` 旁车。构建顺序固定为：先生成 manifest.json（含 files 清单）→ 对其字节签名产 manifest.sig → 再打出同时含两个文件的归档；`manifest.sig` 不进 `files` 清单、不参与 `files_manifest_sha256`。
- 链式信任：`manifest.sig` 锁定 `manifest.json`，`manifest.files` / `files_manifest_sha256` 再逐文件锁定包内全部内容（镜像、安装器、compose 片段）。
- 正式上传与升级只可通过 Web 管理端的“系统升级”页面完成：选择单个 `.tar.gz` 后，系统会从包内 `manifest.json` / `manifest.sig` 读取并校验版本区间与签名；不提供命令行、脚本或直接接口上传/执行流程。构建脚本仅生成并自检交付物，不会上传、部署或触发升级。
- 预检要求包内 `version_from` == 当前系统版本（`system:current_version`），`version_to` 更高（均读自包内 manifest.json）。

### 含新组件（netmgrd 首次部署）的升级流程

升级包可携带全新组件（如网络诊断功能引入的 `netmgrd`）：

1. 包内 `installer/` 随附当版 `install-executor.sh` / `upgrade-executor.sh`，`compose/upgrade-services.yml` 携带新组件编排片段。
2. 初始完整安装必须已安装支持 `package_type=upgrade` 的宿主机执行器及内嵌签名上传的管理后端。包内附带执行器文件不代表会自动更新执行器；不支持此协议的旧环境不能直接使用此包，本流程不提供手工 SSH 升级旁路。
3. 再在 Web 系统升级页面上传执行。执行器发现宿主 compose 缺失的服务时，校验包内片段「新增服务集合恰好等于缺失服务集合、不改写既有服务镜像、镜像与 manifest 声明一致」后，将片段并入 `<DataDir>/upgrade-executor/compose-overrides.d/` 并创建新服务。失败回滚会一并摘除片段、移除新容器与新镜像标签。

### 完整升级介质（宿主/Compose/基础设施变更）

只要变更涉及 Compose、宿主单元、防火墙通道、网关启动契约或新增数据面，就不使用上述应用镜像包。
用 `ops/offline-package/build-update-full.sh --version X.Y.Z --signing-key <受信任发布私钥>` 从已提交且已打版本标签的干净工作区构建：

- `jiuzhang-wdsp-update-full-X.Y.Z-amd64.tar.gz` 及 `.sha256`、`.sig`；
- 同名 `.sh` 独立启动脚本及旁车，内含固定发布公钥，先验签再安全解压；
- `jiuzhang-wdsp-install-X.Y.Z-amd64.run` 由完整安装构建入口提供。

现场只需执行 `sudo bash <update-full脚本> --package <原始update-full归档> --current-release <旧release目录>`。
脚本自动从旧 Compose 读取 API 地址、验证 FULL 备份、更新全部变更组件与 hostctl，失败恢复旧镜像和新增迁移，全部健康后切换 current。
保留原 `.env` 与 runtime，PCAP 默认关闭；已显式启用时才更新对应数据面。详细操作与回滚语义见 `docs/DEPLOYMENT.md`。

### 当前开发基线限制（2026-09-17）

以 `wdsp-v1.2.0` 对比当前开发工作区，自动预览发现 `deployment/docker-compose.stage5.yml` 和 `ops/upgrade/upgrade-executor.sh` 存在变更，因此拒绝自动生成完整升级包。必须先建立包含新协议执行器的完整安装发布基线，并让 VERSION/tag 与实际安装版本一致，后续应用更新才能直接通过此脚本打包、前台升级。不能通过改写 `--from` 或手填组件清单伪装兼容。

（2026-10-09 现状补记：S8 批次 C 已在实验室以显式 `--components "api web gateway netmgrd" --skip-build`（`--from 1.2.0 --to 1.3.0`）构建签名升级包，并完成 1.2.1→1.3.0 前台升级实证（约 88 秒 SUCCESS，另实证坏包自动回滚与执行器中断语义，见 `nextgen/s8/S8-REL02-PACKAGE-REPORT.md`）。上述 auto 拒绝结论不变——该实证属「已有基线经人工验证的兼容入口」，正式节奏仍应先以完整离线包落地含新协议执行器的基线，再启用 auto 通道。）
