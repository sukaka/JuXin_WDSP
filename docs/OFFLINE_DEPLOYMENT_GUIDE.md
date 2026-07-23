# 离线部署指南

本文档适用于无法访问公网的环境：在联网机构建离线交付包，拷贝到目标主机后完成安装、验证与卸载。相关脚本：`ops/offline-package/build.sh`、`ops/install/install.sh`、`ops/healthcheck/check.sh`。

## 1. 离线包内容与构建

### 1.1 构建

在已构建好镜像的联网/构建机上执行（仓库根目录）：

```bash
# 前置：已构建 jiuzhang-server:<version> 与 jiuzhang-gateway:<version> 镜像
# 建议先生成 SBOM：scripts/generate-sbom.sh
ops/offline-package/build.sh --version 2.0.1
# 无 docker 环境仅打包文件清单验证时：--skip-images；输出目录可用 -o 指定
```

产物：`dist/jiuzhang-offline-<version>.tar.gz`，解包后目录结构：

```text
jiuzhang-offline-<version>/
├── images/                  # docker save 的 4 个锁定镜像
│   ├── jiuzhang-server.tar  # jiuzhang-server:<version>
│   ├── jiuzhang-gateway.tar # jiuzhang-gateway:<version>
│   ├── postgres.tar         # postgres:16.4-alpine@sha256:5660c2cb…（摘要锁定）
│   └── valkey.tar           # valkey/valkey:8.1.8-alpine@sha256:94365b27…（摘要锁定）
├── docker-compose.yml       # 生产编排模板（口令经 .env 注入；name: jiuzhang-waf）
├── .env.example             # 配置模板
├── ops/                     # 运维脚本（install/upgrade/backup/restore/healthcheck/diagnostics/lib）
├── licenses/                # 第三方许可证归档
├── docs/                    # SBOM.spdx.json / SBOM.cyclonedx.json（若已生成）、
│                            # THIRD_PARTY_NOTICES.md、DEPENDENCIES.md（若存在）
└── manifest.json            # 版本、镜像 digest、全部文件 sha256/size、文件清单总哈希
```

安全约束：构建脚本会强制检查打包目录中**不得混入 `.env`**（发现即失败）；绝不打包真实口令；全部镜像使用 tag + digest 锁定，禁止 `latest`。版本号须为 `X.Y.Z`（可带 prerelease 后缀），且与 server/gateway 镜像 tag 一致。

### 1.2 完整性核对（目标机上）

```bash
tar -xzf jiuzhang-offline-<version>.tar.gz
cd jiuzhang-offline-<version>
# 逐文件核对 manifest.json 中的 sha256
jq -r '.files[] | "\(.sha256)  \(.path)"' manifest.json | shasum -a 256 -c -
# 核对文件清单总哈希
jq -r '.files_manifest_sha256' manifest.json
```

任一文件 `FAILED` 即说明包在传输中损坏或被篡改，禁止继续安装。

## 2. 安装检查清单（对应任务书 §15.2 全项）

安装前逐项确认（install.sh 会自动覆盖其中 docker/compose/端口/内存/磁盘/时间同步六项，其余为人工核对）：

| # | 检查项 | 检查方法与要求 |
|---|--------|----------------|
| 1 | CPU 架构 | `uname -m`：与镜像构建架构一致（如 `x86_64`/`aarch64`） |
| 2 | 操作系统 | `cat /etc/os-release`：推荐 Ubuntu 22.04+ / CentOS 8+ 等主流 Linux |
| 3 | Docker 和 Compose | `docker --version`（24+）、`docker compose version`（v2 插件） |
| 4 | CPU、内存和磁盘 | 建议 4 核/8GB/SSD；install.sh 硬性要求内存 ≥4GB、当前目录磁盘可用 ≥20GB（`df -P -k .`） |
| 5 | 端口 | 网关 80、管理 API 18081（可用 `--gateway-port/--api-port` 调整）未被占用：`lsof -nP -iTCP:80 -sTCP:LISTEN` |
| 6 | 时间同步 | `timedatectl` 确认 NTP；install.sh 对比网络时间源，偏移 >60s 阻断（离线环境自行确认 NTP 正常） |
| 7 | 文件权限 | 部署目录可写；`.env` 由 install.sh 生成并 `chmod 600`（`umask 077`） |
| 8 | 主机名和 DNS | `hostname` 合法；需经域名访问管理面/业务时，内网 DNS 或 `/etc/hosts` 已配置 |
| 9 | 网络和防火墙 | PostgreSQL/Valkey/管理 API 仅绑定 `127.0.0.1`；防火墙仅放行网关 80/443 与管理面需要的入口 |
| 10 | SELinux 或安全策略 | `getenforce`：Enforcing 时确认卷挂载与端口策略放行（必要时配置适当上下文，不得直接关停安全子系统了事） |
| 11 | 已存在容器 | `docker ps -a`：无同名残留容器（`jiuzhang-postgres`/`jiuzhang-valkey`/`jiuzhang-api`/`jiuzhang-gateway`），有则先清理旧部署 |
| 12 | 证书目录权限 | 证书数据存于数据库 CERTIFICATE 分组；运行期证书文件目录（`runtime/certificates`，容器卷 `runtime-data`）属主与权限仅服务账号可读写 |
| 13 | 随机数来源 | `ls -l /dev/urandom` 存在可读；口令/主密钥由 `openssl rand -hex` 生成（install.sh 前置检查 `openssl`） |

## 3. 安装步骤

```bash
# 1. 解包并核对完整性（见 §1.2）
tar -xzf jiuzhang-offline-<version>.tar.gz && cd jiuzhang-offline-<version>

# 2. 加载离线镜像（4 个，可能需要数分钟）
for f in images/*.tar; do docker load -i "$f"; done
docker images | grep -E 'jiuzhang|postgres|valkey'   # 确认 4 个镜像在位

# 3. 运行安装向导（环境检查 → 生成 .env → 启动 → 三权账号引导）
ops/install/install.sh
# 端口/compose 文件非默认时：--gateway-port/--api-port/-c/-e；
# .env 已存在需覆盖时加 --force（覆盖前自行备份）；仅装环境不建账号用 --skip-accounts
```

install.sh 自动完成：

1. 环境检查（docker/compose/openssl/curl、端口、内存 ≥4GB、磁盘 ≥20GB、时间同步）；
2. 生成 `.env`（随机 `POSTGRES_PASSWORD`、`VALKEY_PASSWORD`、`JIUZHANG_MASTER_KEY`、`INITIAL_ADMIN_PASSWORD`，文件权限 600）；
3. `docker compose up -d` 启动并等待管理 API 健康（最长 180s）；
4. 初始化三权账号：系统管理员 `jiuzhang_admin`（初始口令来自 .env）、安全管理员 `jiuzhang_secadmin`、审计管理员 `jiuzhang_auditadmin`（经 `POST /api/v1/users` 创建并返回临时口令）。

**初始/临时口令仅在终端打印一次，不写入任何日志文件**，请立即记录并妥善保管；首次登录后必须修改。

## 4. 验证步骤

```bash
# 1. 组件健康检查（容器/管理 API/网关/PostgreSQL/Valkey），全部 [OK]
ops/healthcheck/check.sh

# 2. 管理 API 健康
curl -fsS http://127.0.0.1:18081/api/v1/health     # 期望 {"status":"ok"}

# 3. 确认无敏感端口暴露（仅 127.0.0.1）
docker compose ps --format '{{.Name}} {{.Ports}}'

# 4. 登录管理面，修改全部初始/临时口令
# 5. 创建首次 FULL 备份并下载，验证备份链路
ops/backup/create.sh -t FULL -o .

# 6. 留档诊断信息（配置自动脱敏）
ops/diagnostics/collect.sh
```

确认账号可用后，从 `.env` 中删除 `INITIAL_ADMIN_PASSWORD` 行并 `docker compose up -d --no-deps api` 重启生效。

## 5. 卸载说明

```bash
cd jiuzhang-offline-<version>

# 1. 停止并删除容器（保留数据卷，可再次启动）
docker compose -f docker-compose.yml --env-file .env down

# 2. 如需彻底清除数据（数据库、Valkey、运行期数据、网关日志，不可恢复）：
docker compose -f docker-compose.yml --env-file .env down -v

# 3. 删除镜像（按 manifest.json 中记录的镜像名/digest）
docker rmi jiuzhang-server:<version> jiuzhang-gateway:<version>
docker rmi postgres:16.4-alpine valkey/valkey:8.1.8-alpine

# 4. 删除安装目录（.env 含敏感信息，建议先 shred 或安全擦除）
cd .. && rm -rf jiuzhang-offline-<version>
```

卸载前如需保留数据：先 `ops/backup/create.sh -t FULL -o <安全目录>` 下载加密备份，并单独保管 `.env` 中的 `JIUZHANG_MASTER_KEY`（二者缺一无法恢复，详见《备份恢复设计》《灾难恢复手册》）。

## 6. 离线环境的升级

离线包同样作为升级介质：在新包目录加载镜像后，于**部署目录**执行：

```bash
ops/upgrade/apply.sh --server-image jiuzhang-server:<新版本> \
  --gateway-image jiuzhang-gateway:<新版本> --images-tar <新包镜像tar>
# 失败回滚：
ops/upgrade/rollback.sh [--restore-backup]
```

升级前脚本会强制创建并等待 FULL 加密备份验证通过，详见《升级与回滚设计》。
