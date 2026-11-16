# 部署文档

## 环境要求

- Docker 24+
- Docker Compose v2+
- Linux（推荐 Ubuntu 22.04+ / CentOS 8+）
- 4 核 CPU、8GB 内存、本地 SSD（最低要求）

## 部署方式

V2.0 使用 Docker Compose 部署，不使用 Kubernetes。

## 快速部署

### 1. 准备环境变量

```bash
cp .env.example .env
# 编辑 .env，修改数据库密码、Valkey 密码、会话密钥等
```

### 2. 启动基础服务

```bash
docker compose up -d postgres valkey
```

### 3. 初始化数据库

数据库迁移由管理后端内置执行（`server/cmd/api` 的 `migrate` 子命令，迁移目录 `server/migrations/`），离线包安装与容器启动链路自动完成，无需手工初始化。

### 4. 启动管理服务

生产部署使用完整离线包一键安装（见下文「离线交付包」节与 [docs/OFFLINE_DEPLOYMENT_GUIDE.md](OFFLINE_DEPLOYMENT_GUIDE.md)）；实验/开发场景编排见 `deployment/` 目录各 `docker-compose.*.yml`。

### 5. 启动防护网关

网关随同一 compose 栈或离线包一并启动；裸机 systemd 形态见 [docs/BARE_METAL_GATEWAY_DESIGN.md](BARE_METAL_GATEWAY_DESIGN.md) 与 `ops/baremetal/`。

## 多架构部署（x86/C86/兆芯/ARM）

系统提供 linux/amd64 与 linux/arm64 两套离线交付包，按目标主机架构选择：

| 目标架构 | 使用产物 | 说明 |
|----------|----------|------|
| x86_64（Intel/AMD） | jiuzhang-wdsp-offline-{version}-amd64.tar.gz | 标准路径 |
| 海光 C86 | jiuzhang-wdsp-offline-{version}-amd64.tar.gz | C86 为 x86-64 兼容，直接使用 amd64 产物，不单独出包 |
| 兆芯 KX/KH（含 KH-40000） | jiuzhang-wdsp-offline-{version}-amd64.tar.gz | 兆芯为 x86-64 兼容，直接使用 amd64 产物，不单独出包 |
| ARM64（鲲鹏/飞腾等） | jiuzhang-wdsp-offline-{version}-arm64.tar.gz | 镜像与自研二进制均为 arm64 构建 |

- **架构自动校验**：离线包内 manifest.json 记录 arch 字段，安装脚本执行时先与主机架构（`uname -m`）比对，不一致则中止安装并提示应使用的包，避免误装异架构镜像。
- **第三方镜像 digest**：compose 文件中 postgres/valkey 的 digest 为 amd64 子摘要；arm64 部署需替换为对应 arm64 子摘要（获取方式见 docs/DEPENDENCIES.md「多架构镜像锁定」）。
- **海光 C86 实测注意**：C86 虽兼容 x86-64，但指令集实现存在差异，TLS 加解密（AES-NI 等加密指令路径）与 WAF 正则检测性能可能与 Intel/AMD 平台不同。上线前建议在 C86 环境单独做一次性能基线测试（HTTPS 吞吐、TLS 握手速率、CRS 全规则检测时延），确认满足容量规划后再投产。
- **兆芯 KH-40000 实测注意**：KH-40000（陆家嘴架构）无 AVX2 指令，本项目交付物已锁定 `GOAMD64=v1` 基线编译，功能兼容性不受影响；但其单核主频与向量指令吞吐低于主流 Intel/AMD 服务器 CPU，TLS 加解密与 CRS 全规则正则检测性能可能有明显差距。上线前建议在 KH-40000 实机做性能基线测试（HTTPS 吞吐、TLS 握手速率、CRS 全规则检测时延），确认满足容量规划后再投产。
- **裸机网关性能调优**：裸机（systemd 形态）网关主机安装后可执行 `bash ops/install/tune-gateway-baremetal.sh --target 6|8|10 --apply`（安装时加 `--tune N` 可一并完成），按 6/8/10 Gbps HTTP 吞吐目标档应用 sysctl、网卡 ring/offload/队列、IRQ 绑核与 CPU governor 调优；目标档定义、硬件前提与验收方法见 [docs/BARE_METAL_PERFORMANCE_TUNING.md](BARE_METAL_PERFORMANCE_TUNING.md)。

## 离线交付包签名与验签（Ed25519）

离线交付包采用「发布私钥签名 + 安装端内置可信公钥」的真实性验签体系（OpenSSL 3.x
Ed25519，无新增依赖）。旁车 `.sha256` 哈希校验只防偶发损坏，真实性由签名锚定：

- **发布侧签名**：`ops/offline-package/build.sh` / `build-all.sh` 在设置环境变量
  `WDSP_SIGNING_KEY`（Ed25519 私钥路径）后，对整包 `jiuzhang-{product}-offline-{version}-{arch}.tar.gz`
  与包内裸机网关包 `gateway-linux-<arch>.tar.gz` 各产出旁车 `.sig`（base64 编码签名），
  并在 manifest.json 记录 `signed: true` 与 `delivery_mode: production`。正式构建未配置
  私钥时直接失败；仅显式传入 `--development` 才允许生成 `delivery_mode: development`
  的本地自验包。
- **安装侧验签**：`ops/install/install.sh` 与 `ops/install/install-gateway-baremetal.sh`
  内置同一把可信公钥（与仓库 `ops/offline-package/release-signing.pub` 同源），
  在解压/执行任何包内容之前对整包验签；验签失败或未签名**默认中止安装**
  （fail-closed）。安装器同时要求 manifest 明确 `delivery_mode`；验签通过后旁车
  `.sha256` 与 manifest.files 校验保留为纵深。
- **开发例外**：`--allow-unsigned` 默认关闭，且只接受
  `manifest.delivery_mode=development` 的包；使用时输出醒目安全警告，生产包即使
  传入该参数也会拒绝。正式环境不得使用该开关。
- **公钥覆盖**：生产安装永远使用脚本内置发布根。测试场景可将
  `WDSP_PACKAGE_PUBLIC_KEY` 指向 PEM 公钥，但必须同时显式使用开发模式（安装器的
  `--allow-unsigned` 会开启该模式）；该环境变量不得用于生产密钥轮换或正式交付。

### 密钥生成与保管

```bash
# 生成发布签名密钥对（OpenSSL 3.x）
openssl genpkey -algorithm ED25519 -out offline-package-signing.key
openssl pkey -in offline-package-signing.key -pubout -out release-signing.pub
# 公钥指纹（DER 的 SHA-256，用于公示与轮换核对）
openssl pkey -pubin -in release-signing.pub -outform DER | sha256sum
```

保管纪律：

1. 私钥**绝不入库、不进入离线包**，仅由发布负责人离线保管（建议硬件密钥介质或加密保险库）；
   构建机上仅以 `WDSP_SIGNING_KEY` 指向的路径临时引用，构建后清除副本。
2. 公钥随仓库分发（`ops/offline-package/release-signing.pub`）并内嵌于两个安装脚本；
   当前公钥指纹（SHA-256）为
   `0db8c1fc0fe556fd1236a2da0bcedf2d56a82fca322e63ee6da42ba77a69567d`。
3. 验签命令示例（手工复核包的真实性）：
   `base64 -d < jiuzhang-wdsp-offline-X.Y.Z-amd64.tar.gz.sig > /tmp/pkg.sig &&
    openssl pkeyutl -verify -pubin -inkey release-signing.pub -rawin \
      -in jiuzhang-wdsp-offline-X.Y.Z-amd64.tar.gz -sigfile /tmp/pkg.sig`
4. **密钥轮换**：生成新密钥对 → 更新 `release-signing.pub` 与两个安装脚本内嵌 PEM
   及本节指纹 → 用新私钥签名后续版本。轮换必须由发布流程完成并同步更新安装端，
   不得通过 `WDSP_PACKAGE_PUBLIC_KEY` 绕过生产信任根。

## 端口规划

| 服务 | 端口 | 说明 |
|------|------|------|
| 管理后端 | 8080 | 管理 API |
| 管理前端 | 5173 | 开发环境，生产环境由 Nginx/Caddy 托管 |
| 管理控制台（离线包） | 8080（HTTP）/ 8443（HTTPS，可用 `WEB_HTTPS_PORT` 改宿主机侧端口） | web 容器双栈托管；HTTPS 证书由安装期 `ops/install/console-cert.sh` 生成（自签、100 年有效期，SAN 覆盖宿主机全部 IPv4 与 hostname），落 `runtime/certificates/console.{crt,key}`，只读挂载进容器；证书缺失时自动退化为仅 HTTP。用户可替换为内网 CA 签发的同名文件后 `docker compose up -d web` 生效 |
| PostgreSQL | 5432 | 仅绑定 127.0.0.1 |
| Valkey | 6379 | 仅绑定 127.0.0.1 |
| Caddy Admin | Unix Socket | /var/run/caddy/admin.sock |
| 容器运维 sidecar | Unix Socket | containeropsd 仅监听共享卷内 `/run/containerops/containerops.sock`（API 侧经卷挂载为 `/app/runtime/containerops/containerops.sock`），不暴露 TCP；docker.sock 仅该组件挂载 |
| 业务代理 | 默认 80/443，站点端口按发布结果精确放行 | 生产离线包网关直绑宿主机端口；安装时用 `--site-ports` 显式指定站点端口（ops/install 不再默认放行 1024-65535 全高位端口） |

## 数据目录

```text
runtime/
├── configs/       # 配置文件
├── certificates/  # 证书文件
├── logs/          # 日志文件
├── reports/       # 报表文件
└── backups/       # 备份文件
```

## 安全要求

1. PostgreSQL 和 Valkey 仅绑定 127.0.0.1；
2. Caddy Admin API 仅通过 Unix Socket 访问；
3. 管理端默认只监听内网；
4. 生产环境必须使用 HTTPS；
5. 定期备份 `runtime/` 目录和数据库；
6. `/var/run/docker.sock` 仅允许 containerops sidecar 挂载，严禁挂进 api/web/gateway 等任何其他容器。

## 容器运维通道（containerops sidecar）

管理面的容器级运维能力（组件状态/日志查看、白名单内服务重启、锁定镜像更新）经独立
sidecar 提供，**API 容器不直接持有 docker.sock**：

- **拓扑**：API → 共享 Unix Socket 卷（stage5 为 `stage5-containerops`，离线生产包为
  `containerops-data`，API 侧挂载点 `/app/runtime/containerops`）→ containerops sidecar →
  `/var/run/docker.sock`。sidecar 为全栈唯一挂载 docker.sock 的组件，以
  `network_mode: none` 运行、不暴露任何 TCP 端口；详见
  [docs/CONTAINER_OPS_DESIGN.md](CONTAINER_OPS_DESIGN.md)。
- **白名单**：sidecar 只运维 `CONTAINEROPS_PROJECT` 指定的 compose 项目内、且命中
  `CONTAINEROPS_ALLOWED_SERVICES` 的服务（双重校验，fail-closed）；sidecar 自身
  永远不可经通道操作。
- **docker 组 gid**：sidecar 镜像以非 root（uid 1000）运行，访问 docker.sock 的属组
  gid 由 compose `group_add: ${CONTAINEROPS_DOCKER_GID}` 注入；安装期执行
  `bash ops/install/prepare-containerops.sh -e .env` 自动探测写入（缺省 0 适配
  Docker Desktop/root-owned 场景）。
- **镜像更新纪律**：update 只接受显式锁定镜像引用，拒绝 `latest` 与任意 tag；
  数据类容器仅允许同大版本补丁更新；API 自身不允许经本通道 stop/update
  （其版本升级走宿主机升级执行器）。
- **不可用口径**：裸机 systemd 形态无 docker.sock，容器运维不可用，管理面接口返回
  503 降级并隐藏入口，不伪造容器状态。

## 授权导入与管理

系统采用厂家离线签发的授权文件（`.lic`）门控，机制详见
[docs/LICENSE_DESIGN.md](LICENSE_DESIGN.md)。**无有效授权时全系统锁定**（仅登录与授权管理可用），
网关进入数据透传（不检测不防护）。操作流程：

1. **安装期自动采集指纹**：`ops/install/install.sh` 在启动服务前自动执行
   `ops/lib/fingerprint.sh`，将宿主机指纹写入 `<安装根>/runtime/license/host_fingerprint`
   并只读挂载进 api 容器；采集失败仅告警不中断，可事后执行
   `bash ops/lib/fingerprint.sh` 核对（`--json` 查看采集明细）后手动补齐该文件。
2. **查看本机指纹**：登录管理界面 →「授权管理」页查看并复制本机指纹
   （或调用 `GET /api/v1/license/status`）。
3. **报厂家签发**：将指纹串（含 `sha256:` 前缀）与客户信息提供给厂家，
   厂家授权中心离线签发 `.lic` 文件回传。
4. **导入授权**：「授权管理」页上传 `.lic` 完成导入。导入即时生效：
   字段校验失败返回 400、验签失败 422、指纹不匹配 409；
   导入新授权自动取代旧授权（旧记录置 SUPERSEDED，历史可查）。
5. **到期/失配行为与恢复**：
   - 授权到期（服务端每 60 秒复核，按日判定含当天）或宿主机指纹失配（换机/换网卡/重装系统）
     → 系统回到锁定态，网关自动切换为透传（guard 事件/全量访问日志停止、真实 IP 头消失，
     Caddy access.log 照常）；管理面提示授权无效并产生 `LICENSE_INVALID` 告警（CRITICAL），
     到期前 7 天另有 `LICENSE_EXPIRING_SOON`（HIGH）预警；
   - 恢复方式：续期或换机重签后导入新 `.lic`，授权恢复有效即自动重新发布正常防护配置，
     无需重启服务。
   - 注意：离线场景产品侧无法感知厂家吊销，已签发授权在到期前持续有效（见设计文档声明）。

## 运维控制台（设备本地/SSH 受限后台）

硬件服务器交付形态提供定制运维后台：专用账号登录后进入**白名单命令界面**，只能执行预设运维命令，
不暴露系统 shell。

**安装**（需 root，推荐 Ubuntu 22.04+，RHEL 系经 nmcli 支持）：

```bash
sudo ops/console/install-console.sh
# 输出一次初始口令（仅打印一次，请立即记录）
```

安装后：`jiuzhang-ops` 用户的登录 shell 即控制台（SSH/TTY 登录 → 输入控制台账号口令 → 进入 REPL）。

**命令集**：

| 命令 | 说明 |
|------|------|
| `show sysinfo` | CPU / 内存 / 磁盘信息 |
| `show network` | 网口、地址、路由、DNS |
| `set mgmt-ip <网口> <IP/前缀> [网关]` | 设置管理地址 |
| `set route add <目的/前缀> via <网关> [dev <网口>]` / `set route del <目的/前缀>` | 静态路由增删 |
| `set dns <IP1> [IP2]` | 设置 DNS |
| `ping <主机>` | 连通性诊断 |
| `passwd` | 重置控制台密码 |
| `help` / `exit` | 帮助 / 退出 |

**安全设计**：客户只持有专用账户 `jiuzhang-ops`（SSH/TTY 登录），**root 口令无需交付**；
SSH 侧对该账户强制 `ForceCommand` 进控制台并禁用转发/sftp（任何会话通道都落进白名单 REPL）；
账号口令 bcrypt 存于 `/etc/jiuzhang/console.yaml`（0600，无默认口令）；连续 5 次认证失败退出；
所有命令参数白名单校验（IP/CIDR/网口名/主机名严格解析），输入绝不交 shell 执行；
网络变更经 sudoers 精确放行的唯一 root 入口 `ops/console/netapply.sh`（netplan 落地、先备份原配置）；
登录与每条命令写审计（优先 syslog tag `jiuzhang-console`，客户无权清除；兜底 `/var/log/jiuzhang-console.log`）。

## 系统控制（重启/关机/恢复出厂）

管理控制台「系统运维 → 系统控制」支持重启、关机、恢复出厂三个动作。API 容器为
`read_only` + `cap_drop ALL`，不能执行主机命令，因此采用**标志文件执行通道**：
API 校验通过后仅往 `runtime/hostctl/` 写入 `<action>-<unixts>-<requestid>.json`
标志文件（含操作人、requestID、延迟秒数），实际执行由宿主机完成。

**执行依赖**：宿主机 systemd path 单元 `jiuzhang-hostctl.path` 监视
`<安装根>/runtime/hostctl/*.json`，命中即触发 `jiuzhang-hostctl.service`
（`Type=oneshot`，调用 `ops/system/hostctl-exec.sh`）。单元由 `ops/install/install.sh`
自动安装（systemd 可用且 root 时；单元模板在 `deployment/systemd/`，安装时渲染安装根路径）。
执行脚本先将标志文件改名为 `.done` 防重复触发，再写 syslog（tag `jiuzhang-hostctl`）、
按 `delaySeconds`（默认 3s，上限 60s）延迟后执行。

**无 systemd 环境**（容器、macOS 开发机等）：可手工执行处理标志文件：

```bash
# 试跑（只打印将执行的动作，不真正执行）
ops/system/hostctl-exec.sh --dry-run
# 实际执行
sudo ops/system/hostctl-exec.sh
```

**恢复出厂 = 清空全部数据**：删除 compose 命名卷（postgres-data/valkey-data/runtime 等）、
清空 `<安装根>/runtime/` 数据子目录（含**授权 license**），随后 `compose up -d` 并等待
API 健康；执行后系统回到首次安装完成前的状态，需重新初始化三权账号。
实现为 `ops/system/factory-reset.sh`，执行前请确认已备份。

## 备份与恢复

备份与恢复脚本及流程见 `ops/backup/create.sh`、`ops/restore/restore.sh`；恢复演练编排见 `deployment/docker-compose.restore-test.yml`。

## 升级

升级交付物口径与前台升级流程见 [docs/UPGRADE_PACKAGE_POLICY.md](UPGRADE_PACKAGE_POLICY.md)；宿主机升级执行器的安装、就绪标准与中断/超时语义见 [docs/HOST_UPGRADE_EXECUTOR.md](HOST_UPGRADE_EXECUTOR.md)。

## 附录：双节点高可用（HA）部署与验证

双节点 Active-Active 方案设计见 [docs/HA_TWO_NODE_DESIGN.md](HA_TWO_NODE_DESIGN.md)
（拓扑/数据同步矩阵/脑裂处理/风险边界）。其最小落地形态已提供可运行的 lab 编排：

- 编排：`deployment/ha-lab/docker-compose.ha-lab.yml`（Caddy 前置 LB `least_conn`+被动健康检查、
  双网关节点 gw-a/gw-b、共享 PostgreSQL/Valkey、单管理面、testorigin 源站；
  端口与卷约定见文件头注释，生产主从/哨兵形态见设计文档 §3）；
- 验证：`test/ha/ha-lab-verify.sh`（方案 §6 的 S1-S5 场景自动化：配置一致性、
  跨节点共享计数、故障摘除与恢复、发布中故障、管理面中断）。

```bash
# 启动（仓库根目录）
docker compose -f deployment/ha-lab/docker-compose.ha-lab.yml up -d --build
# 全量验证（约 15-20 分钟；可 --scenario S2 单跑）
bash test/ha/ha-lab-verify.sh
# 清理
docker compose -f deployment/ha-lab/docker-compose.ha-lab.yml down -v
```

生产部署差异（lab 简化项与发布通道缺口）如实记录在编排文件头注释与设计文档 §5 实测注记，
其中关键一项：节点唯一 `gateway_node`/心跳周期当前由 lab 的 nodepatch 工具在每次发布后
逐节点补丁（发布扇出为同构配置，按节点注入属后续工程）。

### 次要节点 Caddy Admin API 暴露面与加固

发布扇出（`PATCH /api-security/nodes/{id}` 登记 `admin_addr` 后）经次要节点 Caddy Admin API
`/load` 下发配置，部署时须遵守：

- **风险认知**：Caddy Admin API **无鉴权**；`admin_addr` 为 `http://` 时发布载荷明文过网，
  载荷含身份盐、文件签名/扫描验证密钥、站点证书私钥等密钥材料，同网段监听者可窃取密钥
  并获得配置面写入能力。
- **已有校验**：登记仅接受 unix socket 或内网地址（主机名全量解析、任一公网/保留地址即拒绝），
  拨号时 DNS 重解析复检防重绑定（`server/internal/gatewayconfig/caddyclient.go`）。
- **生产纪律**：主节点本机 Admin API 保持 Unix Socket、不暴露 TCP（项目红线；次要节点 http(s)
  管理地址为发布扇出的受控例外）；生产应使用 `https://`（内部 PKI 证书）；次要节点 Admin 端口
  绑定管理网卡、不随业务网卡暴露；防火墙白名单仅放行管理面主机到该端口，默认全拒；
  ha-lab 形态（admin_addr 登记为共享卷 unix socket 路径、业务端口一律绑 127.0.0.1）仅限单机实验，
  跨机生产部署才涉及 http(s) 管理地址、必须按本条纪律收敛暴露面。
  风险分析与设计依据见 [docs/HA_TWO_NODE_DESIGN.md](HA_TWO_NODE_DESIGN.md) §8.1。
