# 生产裸机网关部署设计（systemd 网关 + 容器化管理面）

> 本文档已经过一轮评审（评审意见 75/100，方向认可、P0 需修复），当前为修订版。
> 相对初版的实质变化：新增运行配置持久化与重启恢复（4.1）、发布事务模型（4.6）、
> 端口策略与防火墙语义（4.7）、共享 GID 权限模型（4.3）、升级自动回滚（4.9）；
> 修正 SELinux `:z`/`:Z` 表述、证书目录权限、日志轮转策略。

## 一、需求与范围

### 1.1 背景

开发/演示环境（`deployment/docker-compose.stage5.yml`）中网关以容器运行，站点监听端口
依赖 Docker 静态端口映射（创建容器时确定，运行中不可新增）。这导致两个问题：

1. 管理界面配置的站点端口若未预先映射，发布后无法访问（容器内监听无法透出宿主机）；
2. 客户生产环境（openEuler / 统信 UOS Linux 服务器）端口需求不可预知，且运行期可能
   新增，"改 compose + 重建网关容器"会造成代理流量秒级中断，不可接受。

### 1.2 目标

生产环境网关（定制 Caddy）以 **systemd 裸机服务**运行，管理面（管理后端、PostgreSQL、
Valkey、管理前端）继续 Docker Compose 部署。产品语义明确为：

> 网关支持动态绑定任意**端口策略允许**的业务端口，无需重启或重建网关；
> 宿主机边界防火墙策略由独立运维策略控制，发布结果区分「配置发布 / 本机监听 /
> 外部可达」三种状态（见 4.7），不以「配置发布成功」冒充「外部可访问」。

### 1.3 范围

**纳入**：

- 反向代理形态的裸机网关（定制 Caddy 二进制 + CRS 规则 + systemd 单元）；
- 运行配置持久化与重启恢复（4.1）、发布事务（4.6）、端口策略（4.7）；
- 安装、升级（含自动回滚）、巡检、日志轮转等配套运维能力；
- 证书交付通道闭环（4.5，该缺陷容器形态下已存在，本方案一并修复）；
- `docs/GATEWAY_SECURITY.md` 安全基线的宿主机加固映射。

**不纳入**（后续阶段单独设计）：

- netmgrd / tproxyd / mirrorcap 三个宿主机守护进程的裸机化（透明/路由/镜像模式）；
- 网关与管理面**跨机部署**（本方案以同机为前提，见 1.4）；
- HA 多网关节点与配置分布式同步（沿用现有扇出机制，不在本文展开）。

### 1.4 已确认的决策

| 决策点 | 结论 | 理由 |
|--------|------|------|
| Admin 通道 | 坚持 **Unix Socket**，不引入 TCP Admin | 守住「Admin API 不上 TCP」安全底线；主发布链路（`NewPublisher`）仅支持 socket，改动最小 |
| 部署拓扑 | 网关与管理面**同机部署** | socket 与日志目录通过宿主机 bind mount 共享给后端容器，跨机必须改 TCP Admin + 日志回传，复杂度和攻击面都不可接受 |
| 阶段8 宿主机组件 | 本次**不纳入** | 先让基础反代形态闭环，降低单阶段风险 |
| 权限模型 | **共享 GID**，不强绑 UID=1000（4.3） | 客户已有 OS 上 UID 1000 常被占用，强绑定会导致安装失败 |
| 配置恢复 | **autosave/resume + current.json 双保险**（4.1） | 杜绝「重启后站点全部消失」 |
| 产品交付形态 | 支持安装到客户已有 openEuler/UOS | 因此 UID/GID、SELinux、防火墙均按「不可控环境」设计 |

## 二、现状与关键事实（已核实）

- **网关二进制可直接复用**：`gateway/Dockerfile` 使用 xcaddy 构建定制 Caddy
  （`CADDY_VERSION=v2.11.4`、`CORAZA_CADDY_VERSION=v2.5.0`，注入 `dynamic_security`
  与 `modules/jiuzhang_guard` 两个自主模块），`CGO_ENABLED=0` 静态编译，已支持
  linux/amd64 + linux/arm64。从镜像中抽取 `/usr/bin/caddy` 即为裸机产物，构建流程
  零改动。注意：仓库根的 `bin/jiuzhang-gateway` 是 macOS 占位 stub，非交付物。
- **路径契约天然兼容**：配置生成器硬编码网关侧路径 `/etc/caddy/rules`、
  `/srv/jiuzhang/blockpage.html`、`/var/log/caddy/*`（`server/internal/gatewayconfig/
  generator.go`），符合 Linux FHS，宿主机沿用相同路径则生成器零改动。
- **发布链路**：管理后端经 `CADDY_ADMIN_SOCKET`（默认 `/var/run/caddy/admin.sock`）
  发布配置（`publisher.go` `executePublish` → `CaddyClient.LoadConfig` → Ping +
  规范化哈希校验，失败自动回滚）。生成的配置始终显式携带 `admin unix/...` 段。
- **日志采集**：后端容器只读挂载网关日志目录，采集 `coraza-audit.log`、
  `guard-events.log`、`access.log`、`node-interfaces.jsonl`、`site-discovery.jsonl`、
  `api-runtime-events.log`、`access-full.jsonl` 共 7 类文件；网关侧写入路径与后端侧
  采集路径是**成对独立的环境变量**（`server/internal/config/config.go`），两侧路径
  可不同，天然适配混合形态。
- **健康检查**：GATEWAY 组件健康 = 对 admin socket 执行 Ping
  （`server/internal/runtimehealth/collector.go`），socket 共享后不受影响。
- **systemd 单元为零起点**：`deployment/systemd/` 目录当前为空。
- **安装/升级脚本仅有 Docker 分支**：`ops/install/install.sh` 为纯 Compose 向导；
  `ops/upgrade/apply.sh` 为镜像 retag + `compose up -d`；均无裸机路径，无
  SELinux/firewalld 处理。裸机安装写法可参考 `ops/console/install-console.sh`
  （运维控制台，建用户 + sudoers + 二进制安装）。
- **既有缺陷——证书通道未闭环**：publisher 将证书/私钥写入后端侧
  `dataDir/certificates`（`server/internal/gatewayconfig/files.go`），生成的配置使用
  `certificate_selection any_tag`，而网关侧（含现有容器形态）无任何机制获取这些
  证书文件；`generator.go` 中 `CertFileDir` 定义后未被使用。本方案必须一并闭环。
- **既有缺陷——离线包生产 compose 模板缺挂载**：`ops/offline-package/build.sh`
  生成的生产 compose 模板缺少 rules/Caddyfile/blockpage 挂载（与 stage5 不一致），
  裸机打包时一并核对修复。
- **Caddy 原生能力（容器内已实测，目标 systemd 环境由 verify 脚本复核）**：
  - Admin API `/load` 加载的配置会 autosave 到 `autosave.json`，`caddy run --resume`
    可恢复——**已用 `jiuzhang-gateway:stage5`（v2.11.4）实测通过**（`/load` 站点后
    重启，配置与监听自动恢复）。**实测发现关键坑：任何一次不带 `--resume` 的启动
    都会用当前初始配置覆盖 autosave.json**，站点配置即丢失；因此 unit 的 ExecStart
    恒定带 `--resume`，运维文档禁止手工 `caddy run` 不带 `--resume`；
  - Caddy 官方 systemd unit 采用 `Type=notify`（core 内置 sd_notify）——容器内无法
    验证 sd_notify，期1 由 `verify-gateway-baremetal.sh` 在目标环境实测定稿，
    不通过则降级 `Type=simple`；
  - Caddy file writer 自带日志 rolling——**已实测 `/load` 接受**
    `{"output":"file","roll":true,"roll_size_mb":100,"roll_keep":30,
    "roll_keep_days":90}`。注意单位：`roll_size_mb` 为 MiB 语义，Caddyfile 写
    `roll_size 100mb` 实测只得 96，应写 `roll_size 100mib`；
  - TLS 证书 JSON 结构——**已用 `caddy adapt` 实测**（v2.11.4）：
    `apps.tls.certificates.load_files: [{certificate, key, tags}]` +
    server `tls_connection_policies: [{match:{sni:[host]}},
    {certificate_selection:{any_tag:["certN"]}}]`，4.5 按此结构实现。

## 三、总体架构

```
┌─────────────────────────── Linux 宿主机（openEuler / UOS）──────────────────────────┐
│                                                                                      │
│  ┌─ systemd ─────────────────────┐   ┌─ Docker Compose（管理面，内部 bridge）──────┐ │
│  │ jiuzhang-gateway.service      │   │                                              │ │
│  │  caddy（定制，静态二进制）    │   │  api（管理后端）  postgres  valkey  frontend   │ │
│  │  用户 jiuzhang-gw（非 root）  │   │    │                                         │ │
│  └───────┬──────────────────────┘   │    │ bind mount（共享 GID 授权）              │ │
│          │ 写                       │    ▼                                         │ │
│  /var/log/caddy/ ───────────────────┼─▶ /var/log/caddy-audit（只读，日志采集）       │ │
│  /var/run/caddy/ ───────────────────┼─▶ /var/run/caddy（admin.sock，配置发布）       │ │
│  /etc/caddy/certificates/ ◀─────────┼── 由后端 publisher 原子写入（证书下发，4.5）   │ │
│  /var/lib/caddy/config/ ◀───────────┼── current.json/previous.json（发布存档，4.1）  │ │
│                                                                                      │
│  站点流量：0.0.0.0:端口策略允许的任意端口（systemd 直绑宿主机网卡，无 NAT）            │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

共享边界共四个宿主机目录，职责单一：

| 宿主机目录 | 网关（caddy） | 后端容器 | 用途 |
|-----------|--------------|---------|------|
| `/var/run/caddy/` | 创建 socket | socket 客户端 | admin socket（0660，共享 GID） |
| `/var/log/caddy/` | RW | RO | 7 类审计/事件日志采集 |
| `/etc/caddy/certificates/` | RO | RW | 证书/私钥下发（4.5，原子写） |
| `/var/lib/caddy/config/` | RO（恢复时读） | RW | 发布存档 current/previous.json（4.1） |

socket 路径沿用 `/var/run/caddy/admin.sock`（与生成器、边车契约一致，不引入路径变更）。

## 四、详细设计

### 4.1 运行配置持久化与重启恢复（P0）

**问题**：bootstrap Caddyfile 仅含 admin socket，站点配置全在 Admin API `/load` 的
运行态中。若无持久化机制，`systemctl restart` / 服务器重启 / 网关升级后所有站点
配置消失。

**双保险设计**：

1. **主机制——Caddy autosave + `--resume`**：

   ```ini
   ExecStart=/opt/jiuzhang-gateway/current/caddy run \
       --config /etc/caddy/Caddyfile.bootstrap \
       --resume
   ```

   Admin API `/load` 的每次配置 Caddy 都会 autosave；`--resume` 使进程启动时
   优先恢复最近一次运行配置，不存在时回退 bootstrap。`XDG_CONFIG_HOME` 在 unit
   中显式指向 `/var/lib/caddy`（`Environment=XDG_CONFIG_HOME=/var/lib/caddy`），
   使 autosave 落点可预期、可备份。
   **期1 必须对定制构建实测** autosave/resume 全场景（首启、发布后重启、升级后
   重启、异常退出后重启），验证不通过则以下述 current.json 为主机制、包装脚本
   选择启动配置。

2. **兜底与回滚源——发布存档**：

   ```
   /var/lib/caddy/config/
   ├── current.json      # 最近一次验证成功的配置
   ├── previous.json     # 上一次验证成功的配置（回滚源）
   └── versions/<seq>.json
   ```

   发布流程在 Verify 通过（4.6）后，将候选配置**原子替换**（写 tmp + fsync +
   rename）为 current.json，原 current 轮转为 previous。该目录同时作为：
   灾难恢复来源（autosave 损坏时人工/脚本恢复）、发布回滚的内容基准、
   升级前配置兼容性校验的输入（4.9）。

3. **管理后端恢复兜底**：GATEWAY 健康检查（现有 socket Ping）之外增加
   「运行配置哈希与库内激活版本一致性」校验；检测到网关以空配置/bootstrap
   运行时，管理界面给出「配置未恢复」告警并支持一键重发（数据在库，可重建）。

### 4.2 交付物与宿主机布局

- 离线包（`ops/offline-package/build.sh`）新增 `gateway-linux-<arch>.tar.gz`：
  从现有多架构网关镜像抽取 `/usr/bin/caddy`，附 SHA256 校验和与版本清单；
  构建流程沿用现有 Dockerfile，不新增构建链。包内同步携带：`gateway/rules/`、
  `gateway/configs/blockpage.html`、bootstrap Caddyfile、systemd unit、
  安装/升级脚本。顺带修复离线包生产 compose 模板缺挂载的既有缺陷。
- 版本化布局（支撑 4.9 的软链切换与回滚）：

  ```
  /opt/jiuzhang-gateway/
  ├── current -> releases/2.x.x/
  └── releases/<version>/caddy
  ```

- 目录与权限（网关进程视角的最小权限；UID/GID 取值由安装脚本分配，见 4.3）：

| 路径 | 属主 | 权限 | 网关进程权限 |
|------|------|------|-------------|
| `/opt/jiuzhang-gateway/` | root | 0755 | RO（防篡改） |
| `/etc/caddy/`（含 rules、Caddyfile.bootstrap） | root:jiuzhang-waf | 0750 | RO |
| `/etc/caddy/certificates/` | root:jiuzhang-waf | 0750 | **RO** |
| `/srv/jiuzhang/blockpage.html` | root:jiuzhang-waf | 0640 | RO |
| `/var/log/caddy/` | jiuzhang-gw:jiuzhang-waf | 0750 | RW |
| `/var/lib/caddy/` | jiuzhang-gw:jiuzhang-waf | 0750 | RW（autosave/data） |
| `/var/lib/caddy/config/` | root:jiuzhang-waf | 0750 | RO（恢复时读） |
| `/var/run/caddy/`（RuntimeDirectory） | jiuzhang-gw:jiuzhang-waf | 0750 | RW |

私钥文件 0640、属组 jiuzhang-waf，网关凭组成员身份只读打开。

### 4.3 权限模型：共享 GID，不强绑 UID（P0）

初版「宿主机 UID 与容器 UID 均固定 1000」在客户已有 OS 上过脆弱（UID 1000 常被
admin/deploy/桌面用户占用）。改为：

- 安装脚本创建**专用组** `jiuzhang-waf`（GID 默认取系统段空闲值，可
  `--gid` 参数指定），创建**专用用户** `jiuzhang-gw`（UID 取系统段空闲值，
  主组 jiuzhang-waf）；
- admin socket 权限 `0660`、属主 `jiuzhang-gw:jiuzhang-waf`；
- 管理后端容器经 `group_add: ["${JIUZHANG_WAF_GID}"]` 追加补充组获得 socket
  读写权与日志/证书目录的组权限，**容器内运行 UID 与宿主机 UID 不再要求相等**；
- 安装脚本在 `.env` 中输出实际分配的 UID/GID，compose 模板引用；
- 一体机/自有镜像交付可继续使用默认值；客户已有 OS 安装时自动避让已占用值。

### 4.4 systemd 单元

`deployment/systemd/jiuzhang-gateway.service`（已落地，期1 产物为**模板**，含
`__GW_USER__`/`__WAF_GROUP__` 占位符，由安装脚本按 4.3 实际分配值 sed 渲染，
并带管理标记防止覆盖客户手工文件；另含 `StateDirectory=caddy` 建
`/var/lib/caddy`，systemd 不递归改属主，与 root 所有的 `config/` 子目录并存）：

```ini
[Unit]
Description=JiuZhang WAF Gateway (Caddy + Coraza)
After=network-online.target docker.service
Wants=network-online.target

[Service]
# 期1 对定制构建验证 sd_notify 后定稿；不通过则改 Type=simple
Type=notify
User=jiuzhang-gw
Group=jiuzhang-waf
Environment=XDG_CONFIG_HOME=/var/lib/caddy
ExecStart=/opt/jiuzhang-gateway/current/caddy run --config /etc/caddy/Caddyfile.bootstrap --resume
ExecReload=/opt/jiuzhang-gateway/current/caddy reload --config /etc/caddy/Caddyfile.bootstrap
UMask=0077
RuntimeDirectory=caddy
RuntimeDirectoryMode=0750
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/log/caddy /var/lib/caddy /var/run/caddy
ReadOnlyPaths=/etc/caddy /srv/jiuzhang
ProtectHome=true
PrivateTmp=true
LimitNOFILE=1048576
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30s

[Install]
WantedBy=multi-user.target
```

要点：

- 证书目录对网关进程为**只读**（`ReadOnlyPaths=/etc/caddy` 覆盖），写证书是
  后端容器经 bind mount 的行为，与网关进程无关（修正初版把证书目录放进
  网关 `ReadWritePaths` 的过宽授权）；
- `ProtectSystem=strict` + `ReadOnlyPaths`/`ReadWritePaths` 等价替代容器
  `read_only` rootfs；`CAP_NET_BIND_SERVICE` 为 80/443 的必要最小授权；
- **sandbox 增强候选**（`PrivateDevices`、`ProtectKernelTunables`、
  `ProtectKernelModules`、`ProtectKernelLogs`、`ProtectControlGroups`、
  `ProtectClock`、`RestrictSUIDSGID`、`LockPersonality`、`RestrictRealtime`、
  `SystemCallArchitectures=native`）：期1 逐项对 Caddy + Go runtime 做兼容性
  测试后分批开启，不一次性全开；`MemoryDenyWriteExecute`、`SystemCallFilter`、
  `RestrictAddressFamilies` 三项需重点验证（Go runtime 对 W^X 与 syscall 的
  使用较敏感），验证记录留档。

### 4.5 证书交付通道闭环（P0，修复既有缺陷）

1. 生产 compose 将宿主机 `/etc/caddy/certificates/` bind mount 为后端
   `dataDir/certificates`，publisher 写文件即落到网关（组只读）可见位置；
2. **原子写入**（P1 评审意见，前置实现）：publisher 写证书一律
   「写 `<name>.tmp` → fsync → rename」，且私钥先于证书完成 rename，
   杜绝「半份 PEM」与「新证书配旧私钥」的中间态；`files.go` 补齐
   chown（root 不可用时退化为属组 jiuzhang-waf + 0640）；
3. `generator.go` 启用已定义的 `CertFileDir`，按**当前定制 Caddy 版本的真实
   JSON Schema** 生成证书加载结构（P0 验证项：期2 用 `caddy adapt` 对
   `tls /path/cert /path/key` 的 Caddyfile 采样，以 Caddy 自己生成的 JSON
   为准实现「文件加载（tls app certificates.load_files）」与「连接策略选择」
   两层结构，替代 `any_tag` 隐式选择），并以 generator 单元测试锁定语义；
4. 证书轮换并入发布事务（4.6）：证书文件先原子落盘，再 `/load`，Verify 含
   证书加载状态检查，失败连同配置一起回滚。

### 4.6 发布事务（P0）

裸机形态下一次发布涉及配置、证书、端口、辅助文件，统一为五阶段事务
（在现有 `publisher.go` `executePublish` 基础上扩展，不另起链路）：

1. **Prepare**：配置生成 → Caddy Schema 校验（现有 `caddy validate` 或等效）→
   证书格式与证书/私钥匹配检查 → 规则文件存在性检查 → **端口策略检查（4.7）**
   → 权限预检；
2. **Stage**：写出 candidate.json、临时证书/私钥文件（`.tmp`）；
3. **Commit**：证书原子 rename → Admin API `/load`；
4. **Verify**：socket Ping → 规范化配置哈希比对（现有）→ **监听端口本地探测**
   （对新端口 TCP connect）→ 证书加载状态 → **外部可达性评估（4.7）**；
5. **Commit 存档**：Verify 全过后原子更新 `current.json`（4.1）；
   **Rollback**：任一阶段失败，恢复 previous 配置与 previous 证书并重新 `/load`
   （现有回滚扩至证书维度），事务状态与失败阶段写入发布记录，界面可见。

杜绝「库中成功、Caddy 成功、证书还是上一版」这类半成功状态。

### 4.7 端口策略与防火墙语义（P0）

**Reserved Port Policy**（前后端共同校验，库表存策略，默认规则内置）：

- 合法范围 1–65535，但默认保留：22（SSH）、53、管理面组件端口（管理前端 80、
  API、PostgreSQL 5432、Valkey 6379）、后续透明代理组件端口段；
- `IP:Port` 唯一性校验；IPv4/IPv6 分别检测；
- 发布 Prepare 阶段执行本机端口占用检查（被非本网关进程占用则拒绝发布并
  指明占用者）；
- 保留端口支持管理员显式解除（二次确认 + 审计日志）。

**防火墙语义闭环**：

- 安装器只放行 80/443 与管理员显式声明的初始站点端口，不开放整个高位端口段。
- Web 发布在加载候选网关配置前，按本次实际监听站点生成排序去重的 TCP 端口清单，经带 HMAC、时效和属主校验的 hostctl 通道提交 `firewall_ensure`；宿主侧在 firewalld 默认 zone 同时确保 runtime 与 permanent 精确放行，API 容器不直接获得宿主 root 权限。
- 首版只增不删：不自动移除历史端口，避免多站点共享端口或管理员既有规则被误删；宿主通道写入失败时发布在候选加载前以 `FIREWALL_ENSURE_FAILED` 中止。
- 发布结果明确区分「配置发布」「本机监听」「防火墙指令已提交」「外部可达」。摘要显示已提交端口，不把它冒充外部可达证明；云安全组、上游 ACL 与运营商网络仍需按部署环境核验。
- 巡检与发布验证继续报告真实数据面结果，外部不可达不得改写为验证通过。

### 4.8 日志轮转

- **安全审计类日志**（coraza-audit、guard-events、api-runtime-events、
  access-full 等）**禁止 copytruncate**（copy→写→truncate 竞争窗口会丢/重日志）：
  优先采用 Caddy file writer 原生 rolling（`roll_size`/`roll_keep`/
  `roll_keep_for`，生成器在下发日志配置时携带），系统侧只做容量监控与
  归档清理（find -mtime 删除过期已滚动文件）；
- caddy.log 等运行日志同样走 Caddy rolling；
- logrotate 仅作为兜底安全网部署（对陈旧的已滚动文件 compress + 定期清理），
  不 touch 活动日志文件；是否启用 postrotate/reload 视期1 实测。

### 4.9 安装 / 升级 / 巡检

- **安装**（`ops/install/` 新增裸机路径，主向导按部署形态调用）：检测 OS/架构
  （openEuler/UOS/通用 systemd 发行版）→ 分配 UID/GID（4.3）→ 建目录 →
  安装 releases + 规则 + blockpage + bootstrap + unit → SELinux 处理（4.10）→
  firewalld 仅放行 80/443 与显式初始站点端口并输出运维约定；后续发布经 hostctl 自动提交精确端口 → `systemctl enable --now` →
  冒烟检查（socket 存在 + Ping）。
- **升级**（`ops/upgrade/`）健康门禁 + 自动回滚：

  ```
  安装 releases/<new> → SHA256 校验 → caddy version
    → 用 current.json 做配置兼容性校验（caddy validate）
    → 切换 current 软链 → systemctl restart
    → 等待 admin socket 就绪 → 关键监听端口探测 → HTTP/TCP smoke
    → 成功：记档；previous.json 保持
  任一步失败或 60s 内未通过：自动恢复旧软链 → restart → 复检 → 告警
  ```

  人工 `rollback.sh` 保留作为第二通道；升级前自动备份 `/etc/caddy` 与
  `/var/lib/caddy/config`。
- **巡检/诊断**（`ops/healthcheck/check.sh`、`ops/diagnostics/collect.sh`）：
  增加 systemd 分支（`systemctl is-active`、journalctl、站点端口探测、
  外部可达性探测），Docker 分支保留用于管理面组件。

### 4.10 SELinux 处理

- 修正术语：`:z` 为**共享**卷标签、`:Z` 为**私有**卷标签（初版写反）；
- 本方案是「宿主机 systemd 进程 + Docker 容器共同访问宿主机目录」，不能简单
  自动追加 `:z`：安装脚本检测 `getenforce`，Enforcing 时针对目标
  openEuler/UOS + Docker 组合提供**经验证的标签方案**（候选：为共享目录设置
  `container_file_t` 类型或定制 CIL 策略模块），期1 在目标环境实测后定稿；
- 任何情况下**不得引导用户关停 SELinux**（沿用 `docs/OFFLINE_DEPLOYMENT_GUIDE.md`
  纪律）。

## 五、安全基线映射（GATEWAY_SECURITY.md 修订）

| 容器基线（现状） | 宿主机等价物 | 落实位置 |
|------------------|-------------|---------|
| `read_only: true` rootfs | `ProtectSystem=strict` + `ReadOnlyPaths`/`ReadWritePaths` | unit |
| `cap_drop: ALL` | `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` | unit |
| uid 1000 非 root 运行 | 专用系统用户 `jiuzhang-gw`（系统段 UID） | 安装脚本 + unit |
| `no-new-privileges` | `NoNewPrivileges=true` + `RestrictSUIDSGID`（候选） | unit |
| bridge 网络 + 显式端口映射 | 无（裸机直绑，监听面由发布配置与端口策略控制） | — |
| tmpfs `/tmp` | `PrivateTmp=true` | unit |
| Admin 仅 Unix Socket | 不变（socket 0660 + 共享 GID 授权） | bootstrap + unit |
| 容器卷日志隔离 | 目录 0750 + Caddy 原生 rolling | 安装脚本 + 生成器 |

基线条目「无 `network_mode: host`」修订为：「管理面组件禁止 host 网络；生产离线包
的网关容器为实现业务端口直绑，例外采用 `network_mode: host` 并仅增加
`CAP_NET_BIND_SERVICE`；裸机网关同样由发布配置与端口策略控制」。开发/演示环境
维持 bridge + 端口段约定不变。

## 六、开发/演示环境的端口段约定（不变）

开发环境继续走容器桥接，一次性映射端口段避免反复重建：

```yaml
# deployment/docker-compose.stage5.yml gateway 服务
ports:
  - "127.0.0.1:${GATEWAY_PORT:-18080}:8080"
  - "${GATEWAY_SITE_HTTP_PORT:-81}:81"        # 演示站点端口，按需扩展段
```

站点端口校验按部署形态分支：容器形态提示「端口须已映射」；裸机形态执行
4.7 的端口策略校验，放开为任意未被保留的合法端口。

## 七、分期与实施步骤

| 期 | 内容 | 验收 |
|----|------|------|
| 1 | unit（含 sd_notify、sandbox 候选逐项实测）、bootstrap Caddyfile、宿主机布局、共享 GID 安装脚本、**autosave/resume 与 Caddy rolling 实测**、SELinux 方案目标环境实测 | openEuler 虚拟机全新安装，服务 active，发布站点后 `systemctl restart` + 整机重启配置自动恢复 |
| 2 | 生产 compose 共享挂载、发布事务（Prepare/Stage/Commit/Verify/Rollback）、端口策略、证书通道闭环（atomic write + `caddy adapt` 验证的 generator 改造 + 单测） | 端到端：前台建 HTTPS 站点（任意非保留端口）→ 发布三态正确 → 外部访问通；故障注入各阶段回滚正确 |
| 3 | 升级/自动回滚脚本、日志轮转、sysctl（已落地：ops/install/tune-gateway-baremetal.sh，见 docs/BARE_METAL_PERFORMANCE_TUNING.md）、巡检/诊断 systemd 分支 | 升级失败 60s 内自动回滚还原；轮转无日志丢失；巡检报告含外部可达性 |
| 4 | 文档与基线修订（GATEWAY_SECURITY.md、INSTALLATION_GUIDE.md、OFFLINE_DEPLOYMENT_GUIDE.md、AGENTS.md 索引） | 评审通过；交付检查脚本绿 |

每期附单元测试与集成测试（遵循 AGENTS.md「测试先行」）；unit 文件与脚本变更
附 shellcheck/bats 或等效校验。

## 八、风险与未决问题

- **autosave/resume 实测不通过**：降级为包装脚本按 current.json 存在性选择启动
  配置（设计已预留，4.1），不阻塞主线；
- **欧拉 iSulad 变量**：若客户环境以 iSulad 替代 Docker，管理面 compose 行为需
  实测；裸机网关本身不依赖容器引擎，风险仅限管理面；
- **证书 JSON 结构**：已用 `caddy adapt` 完成采样（见第二节实测结论），期2 按该
  结构实现并以 generator 单测锁定；
- **跨机部署**：如未来出现网关与管理面分机需求，需另起设计（TCP Admin 通道 +
  鉴权 + 日志回传），不在本方案承诺范围内。
