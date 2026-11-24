# 九章 WDSP 分布式流量采集 Agent — 跨平台安装、服务化与原生抓包实施契约

**版本：V1.0（已批准冻结契约，2026-11-24）**
**适用平台**：CentOS / RHEL 系（Linux RPM）、Debian / Ubuntu 系（Linux DEB）、macOS（Darwin）、Windows
**上游设计**：`docs/agents/WDSP_DISTRIBUTED_AGENT_DESIGN.md`、`docs/agents/WDSP_AGENT_PHASE1_CONTRACT.md`、`docs/agents/WDSP_AGENT_PHASE2_CONTRACT.md`

本文件是 `wdsp-agent`、打包脚本（`packaging/wdsp-agent/` 与 `ops/offline-package/`）、管理后端（`server/internal/agents/`）和管理前端（`web/src/pages/traffic-agents/`）共同遵守的跨平台实施契约。任何路径、接口、枚举或打包格式变更须四方同步。

---

## 1. 红线与合规边界

1. **纯旁路只读**：所有抓包后端（Linux `ebpf`/`afpacket`、macOS `bpf`、Windows `npcap`/`rawsocket`）不得包含任何向网卡回写、注入或改包的代码路径（macOS `/dev/bpf*` 强制 `O_RDONLY` 打开；Windows `npcap` 仅绑定只读符号，刻意不绑定 `pcap_sendpacket`/`pcap_inject`）；全部 goroutine 必须 `recover()` 保护，失败仅 Fail-Open 降级，绝不退出进程或影响业务。
2. **许可证与零新增第三方 Go 依赖**：
   - `wdsp-agent/go.mod` 维持既有宽松许可依赖（`gopacket v1.1.19`、`cilium/ebpf v0.22.0`、`golang.org/x/sys v0.45.0`），全平台保持 `CGO_ENABLED=0` 纯静态编译。
   - **Windows Npcap 合规红线**：Npcap 驱动属专有许可，**严禁**将 Npcap 安装器或 `wpcap.dll` 随 WDSP 发行介质分发。Agent 仅在运行期从 `%SystemRoot%\System32\Npcap\wpcap.dll` 动态加载（强制 `LOAD_LIBRARY_SEARCH_SYSTEM32`，防止 DLL 劫持）；未安装时自动回退至 Windows 原生 IPv4 Raw Socket 或仅控制通道。
   - 打包容器镜像须在 `docs/DEPENDENCIES.md` 锁定版本与 digest，禁止 `latest`。
3. **鉴权与零明文泄露**：
   - 机器引导分发端点（`/api/v1/agents/bootstrap/*`）禁止匿名开放，强制要求 `Authorization: Bearer wdt_<64hex>` 指向 `ACTIVE` 状态的一次性 Enrollment Token；**只读校验不消耗 Token**，直到 `POST /api/v1/agents/enroll` 成功才原子置为 `USED`。
   - **严禁**将 Enrollment Token 放进 URL Query String 或静态写死在下载脚本正文内；所有一键安装命令均经环境变量 `WDSP_ENROLL_TOKEN` + HTTP Header 传递。
   - 所有在线/离线安装流程在安装前**强制校验 SHA-256**，不匹配立即中止。
4. **诚实验收**：不得用 mock 或单测替代目标系统实测；受环境限制未在真实 OS 上执行的验收项须显式标 `NOT_RUN` 并附复现步骤。

---

## 2. 跨平台目录、权限与服务契约（阶段 1）

| 项目 | Linux（CentOS / Debian） | macOS（Darwin） | Windows |
|---|---|---|---|
| **服务名** | `wdsp-agent`（systemd） | `com.jiuzhang.wdsp-agent`（LaunchDaemon） | `WDSPAgent`（Windows SCM） |
| **服务定义位置** | `/etc/systemd/system/wdsp-agent.service` | `/Library/LaunchDaemons/com.jiuzhang.wdsp-agent.plist` | Windows SCM 注册表 |
| **默认配置文件** | `/etc/wdsp-agent/agent.json` | `/Library/Application Support/WDSPAgent/agent.json` | `%ProgramData%\JiuZhang\WDSPAgent\agent.json` |
| **默认状态目录** | `/var/lib/wdsp-agent` | `/Library/Application Support/WDSPAgent/state` | `%ProgramData%\JiuZhang\WDSPAgent\state` |
| **默认日志目录** | systemd journal（stderr） | `/Library/Logs/WDSPAgent` | `%ProgramData%\JiuZhang\WDSPAgent\logs` |
| **凭据权限隔离** | 目录 `0700`、文件 `0600` | 目录 `0700`、文件 `0600` | 受限 NTFS DACL（禁用继承，仅 `SYSTEM` 与 `Administrators` 完全控制） |

### 2.1 CLI 子命令契约

保持既有 `enroll` / `run` / `version` 100% 向后兼容，新增：

- `wdsp-agent install --server <url> (--token-file <path> | --token <wdt_...> | WDSP_ENROLL_TOKEN) [--config <path>] [--state-dir <dir>] [--backend auto|...] [--insecure-skip-verify] [--force-reenroll] [--no-start]`
  - 校验管理员/root 权限 → 创建受限目录 → 执行 `enroll`（已存在合法 `agent.json` 时默认拒绝覆盖，除非显式传 `--force-reenroll`；若传入 `--backend` 写入 `agent.json` 的 `capture_backend`）→ 注册平台原生服务 → 启动服务（除非 `--no-start`）→ 校验服务存活。
- `wdsp-agent uninstall [--config <path>] [--state-dir <dir>] [--purge]`
  - 停止并注销平台原生服务；默认保留配置文件与状态目录，`--purge` 才清理配置、证书、缓存与日志目录。
- `wdsp-agent status [--config <path>] [--state-dir <dir>]`
  - 打印服务状态、配置/状态路径、Agent ID、认证模式（PoP/Bearer）、证书到期时间、平台及后端配置摘要。
- `wdsp-agent service <start|stop|restart|status>`
  - 调用平台原生服务控制命令。
- `wdsp-agent run`
  - 在 Windows 上自动检测 `svc.IsWindowsService()`：由 SCM 拉起时走原生 Windows Service 生命周期（并把日志落入日志目录），前台运行时响应 Ctrl+C 输出至 stderr。

### 2.2 系统信息与自我保护采样

- **OS/Kernel 上报**：
  - Linux：`/etc/os-release` `PRETTY_NAME` + `uname -r`；
  - macOS：`/System/Library/CoreServices/SystemVersion.plist`（或 `sysctl kern.osproductversion`）+ `sysctl kern.osrelease`；
  - Windows：`RtlGetNtVersionNumbers` + `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`（含 build ≥ 22000 的 Windows 11 修正）。
- **自我保护采样（`selfmon.Sampler`）**：
  - Linux：`/proc/self/stat` + `/proc/self/status`（`VmRSS`）；
  - macOS：`unix.Getrusage(RUSAGE_SELF)` 计算进程 CPU% + Go `runtime.MemStats`（`Sys - HeapReleased`）作为常驻内存近似值（零 CGO，如实标注口径）；
  - Windows：`GetProcessTimes` 计算进程 CPU% + `K32GetProcessMemoryInfo` 读取 `WorkingSetSize`（MB）。

---

## 3. 跨平台抓包后端契约（阶段 2）

### 3.1 合法后端枚举与平台回退链

- 合法后端枚举：`auto`、`ebpf`、`afpacket`、`bpf`、`npcap`、`rawsocket`（服务端 `PolicyCapture.Backend` 同步放行上述枚举及空串）。
- 平台默认 `auto` 优先级链：
  - Linux：`ebpf` → `afpacket` → 仅控制通道；
  - macOS：`bpf`（`/dev/bpf*`，只读 `O_RDONLY`）→ 仅控制通道；
  - Windows：`npcap`（`%SystemRoot%\System32\Npcap\wpcap.dll` 动态只读加载）→ `rawsocket`（IPv4 `SIO_RCVALL`）→ 仅控制通道。
- 策略下发与当前 OS 不匹配的显式后端（如 Windows 收到 `ebpf`）：Fail-Open 记 `Warn` 并按当前平台 `auto` 链回退，且通过心跳 `metrics.capture_backend` 与 `metrics.backend_fallback_reason` 如实上报。

### 3.2 各平台边界声明

- **macOS `bpf`**：支持 `DLT_EN10MB`（以太网）与 `DLT_NULL`（回环），需 `root` 或 `access_bpf` 权限；内核统计经 `BIOCGSTATS` 差分后符合统一差值语义。
- **Windows `npcap`**：要求目标机已安装 Npcap；通过 `GetAdaptersAddresses` 精确映射友好网卡名与 `\Device\NPF_{GUID}`；`pcap_stats` 内部差分对齐统一语义；`Close()` 调用 `pcap_breakloop` 唤醒。
- **Windows `rawsocket`**：无需驱动但仅覆盖 IPv4、无二层以太网头（直接 `LayerTypeIPv4` 进 `DecodePacket`）、依赖宿主机防火墙策略放行接收、无内核丢包计数（`KernelStats` 返回不可用）。RAW 通道（`WDP1`）遇非以太网帧时跳过不伪造假以太网头。

---

## 4. 四平台安装包与一键脚本契约（阶段 3）

### 4.1 产物目录与命名（`dist/agent-packages/<version>/`）

| 平台 | 架构 | 格式标识（`format`） | 文件名 |
|---|---|---|---|
| CentOS / RHEL 系（`os=linux, distro=rpm`） | `amd64` / `arm64` | `rpm` | `wdsp-agent-<version>-1.x86_64.rpm` / `wdsp-agent-<version>-1.aarch64.rpm` |
| Debian / Ubuntu 系（`os=linux, distro=deb`） | `amd64` / `arm64` | `deb` | `wdsp-agent_<version>_amd64.deb` / `wdsp-agent_<version>_arm64.deb` |
| macOS（`os=darwin, distro=darwin`） | `arm64` / `amd64` | `pkg` / `targz` | `wdsp-agent-<version>-darwin-<arch>.pkg` / `.tar.gz` |
| Windows（`os=windows, distro=windows`） | `amd64` / `arm64` | `zip` | `wdsp-agent-<version>-windows-<arch>.zip` |

同时产出 `SHA256SUMS` 与 `manifest.json`（字段：`version`、`built_at`、`packages[{os, distro, arch, format, filename, size, sha256}]`）。

### 4.2 一键安装脚本

- `packaging/wdsp-agent/scripts/install-agent.sh`：兼容 CentOS/RHEL/Rocky/Alma/openEuler/Debian/Ubuntu 与 macOS，支持在线（`WDSP_ENROLL_TOKEN` Header 拉取 + SHA-256 强制校验）与 `--local-package` 离线安装。
- `packaging/wdsp-agent/scripts/install-agent.ps1` 与 `uninstall-agent.ps1`：支持 PowerShell 5.1+，强制管理员校验、Header 鉴权下载、`Get-FileHash -Algorithm SHA256` 校验、Npcap 状态检测与提示、调用 `wdsp-agent.exe install` 注册启动服务。

---

## 5. 管理面分发接口与前端安装向导契约（阶段 4）

### 5.1 配置与存储

- 管理后端环境变量：
  - `TRAFFIC_AGENT_PACKAGES_DIR`（默认 `/app/runtime/agent-packages`）：多平台安装包目录；
  - `WEB_HTTPS_PORT`（默认 `8443`）、`WDSP_HOST_IPS`（安装期写入 `.env` 的宿主机非回环 IP 列表）、`TRAFFIC_AGENT_PUBLIC_URL`（可选显式覆盖地址）、`CONSOLE_CERT_FILE`（可选控制台公开证书路径，仅读 SAN IP 与自签标记）。
- 加载 `manifest.json` 时必须逐项复核磁盘文件真实存在、为常规文件（拒绝符号链接）且位于配置根目录内（防止路径穿越）；目录不存在或为空时如实返回 `available: false, packages: []`。

### 5.2 管理端接口（会话 + RBAC，统一 `response.Body` 信封）

- `GET /api/v1/traffic/agents/packages`（权限 `traffic.agents.view`）
  - 响应 `data`：`{ "available": bool, "version": string, "packages": [...] }`。
- `GET /api/v1/traffic/agents/packages/{os}/{arch}/{format}`（权限 `traffic.agents.view`）
  - 响应：二进制流 + `Content-Disposition: attachment; filename="..."`、`X-WDSP-SHA256: <hex>`、`X-Content-Type-Options: nosniff`、`Cache-Control: no-store`，记录审计日志。
- `GET /api/v1/traffic/agents/install-endpoint`（权限 `traffic.agents.view`）
  - 响应 `data`：`{ "recommended_url", "saved_url", "source", "https_port", "self_signed_tls", "candidate_ips", "candidate_urls" }`。按「已保存默认地址 → 环境变量 → 控制台访问 IP（HTTP 自动升 HTTPS）→ 宿主机 IP → 证书 SAN IP → 本机网卡 IP」优先级自动推导客户端可直接经 IP 访问的 WDSP HTTPS 地址。
- `PUT /api/v1/traffic/agents/install-endpoint`（权限 `traffic.agents.manage` + 审计日志）
  - 请求体：`{ "server_url": "<IP 或 https://地址[:端口]，空串表示清空恢复自动探测>" }`；非回环地址严禁明文 `http://`。

### 5.3 机器引导端点（强制 `ACTIVE` Enrollment Token Header 鉴权，裸 JSON 错误信封）

认证要求：`Authorization: Bearer wdt_<64hex>`（只读校验 Token 存在、未过期、未撤销、未使用；**不消耗 Token**；失败统一返回 `401 UNAUTHENTICATED`）。

- `GET /api/v1/agents/bootstrap/manifest`：返回 `manifest.json`（无可用包时返回 `404 NOT_FOUND`）。
- `GET /api/v1/agents/bootstrap/script/{os}`（`os ∈ {linux, darwin, windows}`）：返回静态内嵌安装脚本，附带 `X-WDSP-SHA256` 与 `Cache-Control: no-store`。
- `GET /api/v1/agents/bootstrap/packages/{os}/{arch}/{format}`：返回安装包二进制流，附带 `X-WDSP-SHA256`、`X-Content-Type-Options: nosniff`、`Cache-Control: no-store`。

### 5.4 前端页面要求

- 「流量采集 Agent 管理」提供 **「一键部署 Agent」** 入口与「安装向导与离线包」面板：
  - 自动调用 `/api/v1/traffic/agents/install-endpoint` 填入客户端可达的 WDSP HTTPS IP 地址，支持点击宿主机候选 IP 快捷切换与保存默认对接地址，并在自签证书/IP 直连时自动勾选自签 HTTPS 兼容开关；
  - 默认展示**单行全自动一键安装命令**（`Linux / macOS` 自动识别发行版/包管理器/架构与 root/sudo，`Windows` 自动识别架构并启用 TLS 1.2）；支持一键签发一次性令牌并直接嵌入命令（仅通过环境变量与 Authorization Header 传递，绝不拼进 URL）；
  - 提供「按平台指定 / 离线包下载」Tab（CentOS/Debian/macOS/Windows），展示离线下载按钮、文件大小、SHA-256 与离线安装命令；缺失安装包时如实禁用在线一键命令并提示；
- 「Agent 详情」抽屉展示实时生效的 `capture_backend` 与 `backend_fallback_reason`（如有）。
