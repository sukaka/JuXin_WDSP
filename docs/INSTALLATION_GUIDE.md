# 安装向导

本文档指导完成九章 WAF V2.0 的全新安装：环境要求、两条安装路径（在线 compose / 离线包）、初始化、安装后检查与初始口令的安全处理。安装入口脚本：`ops/install/install.sh`。

## 1. 环境要求

| 项目 | 要求 |
|------|------|
| 操作系统 | Linux（推荐 Ubuntu 22.04+ / CentOS 8+） |
| 容器运行时 | Docker 24+ 与 Docker Compose v2 插件 |
| 硬件 | 建议 4 核 CPU、8GB 内存、本地 SSD；安装脚本硬性要求内存 ≥4GB、部署目录磁盘可用 ≥20GB |
| 端口 | 网关 80、管理 API 18081 未被占用（可用 `--gateway-port/--api-port` 调整） |
| 依赖命令 | `docker`、`openssl`、`curl`、`jq`、`python3`、`flock`、`install`、`sha256sum`、`realpath` |
| 服务管理 | systemd（完整安装包用于自动启用宿主机升级执行器） |
| 时间 | 系统时间与网络时间源偏差 ≤60s（离线环境自行确认 NTP 正常） |

## 2. 快速开始

### 路径 A：在线 compose（可拉取/构建镜像）

```bash
# 1. 获取仓库并进入根目录，直接运行安装向导（推荐）
sudo bash ops/install/install.sh

# 2. 或手工方式：准备环境变量后启动
cp .env.example .env        # 然后编辑 .env，替换所有 CHANGE_ME 项
docker compose up -d
```

手工方式必须自行保证：所有 `CHANGE_ME` 口令已替换为强随机值，并补充 `JIUZHANG_MASTER_KEY`（备份/证书加密必需）。推荐使用 `install.sh`，由脚本生成全部随机值。

### 路径 B：离线包（无公网环境）

```bash
# 构建机：ops/offline-package/build.sh --version <版本>
# 目标机：
tar -xzf jiuzhang-offline-<版本>.tar.gz && cd jiuzhang-offline-<版本>
for f in images/*.tar; do docker load -i "$f"; done
sudo bash ops/install/install.sh
```

完整流程（含完整性核对、检查清单、卸载）见《离线部署指南》。

## 3. 初始化向导（install.sh 八步）

`ops/install/install.sh [选项]`（`-c` compose 文件、`-e` env 文件、`--api-url`、`--gateway-port`、`--api-port`、`--force`、`--skip-accounts`）依次执行：

**步骤 1/8 环境检查**：docker/compose/openssl/curl 可用；网关与 API 端口空闲；内存 ≥4GB；磁盘 ≥20GB；时间偏移 ≤60s（可判定时）。完整包还会预检 root、systemd 及升级执行器依赖，不满足时在改变系统前终止。

**步骤 2/8 生成 .env**（已存在则拒绝覆盖，`--force` 除外；文件权限 600，`umask 077`）：

- `POSTGRES_PASSWORD`、`VALKEY_PASSWORD`：`openssl rand -hex 24`；
- `JIUZHANG_MASTER_KEY`：`openssl rand -hex 32`，**主密钥**——备份与证书私钥加密的根，生成后不回显；
- `INITIAL_ADMIN_PASSWORD`：`openssl rand -hex 12`，系统管理员初始口令；
- 固定项：`APP_ENV=prod`、`COOKIE_SECURE=true`、`INITIAL_ADMIN_USERNAME=jiuzhang_admin`、端口配置。

**步骤 3—6/8**：采集授权指纹、配置防火墙、安装宿主机系统控制单元，再执行 `docker compose up -d` 并等待管理 API 就绪（最长 180s）。

**步骤 7/8 安装升级执行器**：自动安装并启用 `jiuzhang-upgrade-executor.path`/`.service`，建立 API 容器与宿主机的安全任务通道，并验证监听单元处于启用且运行状态。完整包不允许跳过此步。

**步骤 8/8 三权账号初始化**（可用 `--skip-accounts` 跳过）：

- 系统管理员 `jiuzhang_admin`：由 api 服务首次启动时按 `INITIAL_ADMIN_PASSWORD` 创建；
- 安全管理员 `jiuzhang_secadmin`（角色 `SECURITY_ADMIN`）、审计管理员 `jiuzhang_auditadmin`（角色 `AUDIT_ADMIN`）：脚本以系统管理员登录后调用 `POST /api/v1/users` 创建，各返回一次性临时口令；
- 已存在的账号跳过创建（幂等）。

其余初始化项在安装后通过管理面完成：

- **系统名称、时区**：登录管理面「系统设置」配置；当前版本号记录于 `system_settings` 的 `system:current_version`（升级预检读取，缺省回退常量 `2.5.4`）；
- **密码策略**：口令以 argon2id 散列；登录验证码等安全开关在「系统设置」中调整（如 `login:captcha_enabled`）；
- **主密钥**：由 .env 的 `JIUZHANG_MASTER_KEY` 提供，仅驻留 api 进程内存，任何日志/备份文件中不出现；
- **HTTPS**：管理 API 容器仅绑定 `127.0.0.1:18081`，生产环境必须在其前以反向代理终结 HTTPS（`COOKIE_SECURE=true` 已默认开启，要求经 HTTPS 访问）；网关业务侧 80/443 按接入应用配置证书。

## 4. 初始化后检查

```bash
# 1. 组件健康（容器/管理 API/网关/PostgreSQL/Valkey），全部 [OK]
ops/healthcheck/check.sh

# 2. 管理 API 健康
curl -fsS http://127.0.0.1:18081/api/v1/health     # 期望 {"status":"ok"}

# 3. 敏感端口未对外（postgres/valkey/api 均仅 127.0.0.1）
docker compose ps --format '{{.Name}} {{.Ports}}'

# 4. 三权账号均可登录管理面，并立即修改全部初始/临时口令

# 5. 备份链路自检：创建并下载首个 FULL 加密备份
ops/backup/create.sh -t FULL -o .

# 6. 留档诊断信息（PASSWORD/SECRET/KEY/TOKEN 自动脱敏为 ********）
ops/diagnostics/collect.sh
```

## 5. 初始密码安全处理

1. **仅打印一次**：`jiuzhang_admin` 初始口令与 secadmin/auditadmin 临时口令只在 install.sh 终端输出打印一次，不写入任何日志文件，也无法再次查询（用户创建接口不返回已有账号口令）。若 `.env` 未注入 `INITIAL_ADMIN_PASSWORD`，api 首次启动时会生成一次性随机口令并**仅打印一次到容器 stdout**（可用 `docker compose logs api` 查看一次），账号均带 `MustChangePassword` 标记；
2. 立即用纸笔/密码管理器记录，**首次登录后必须修改**；
3. 确认三权账号均可用后，从 `.env` 删除 `INITIAL_ADMIN_PASSWORD` 行并重启：

```bash
# 编辑 .env 删除 INITIAL_ADMIN_PASSWORD=... 行，然后
docker compose up -d --no-deps api
```

4. `.env` 权限保持 600，禁止提交 Git、禁止写入工单/文档；`ops/diagnostics/collect.sh` 收集时会自动脱敏；
5. 若初始口令在未修改前泄露：立即用系统管理员登录修改，并检查操作审计中是否有异常登录。

## 6. 常见问题

- **端口被占用**：install.sh 报“端口 80/18081 已被占用”——释放占用或用 `--gateway-port/--api-port` 换端口后重跑；
- **API 启动超时**：执行 `docker compose logs --tail=200 api` 与 `ops/diagnostics/collect.sh` 定位（常见为数据库未就绪或主密钥缺失）；
- **登录要求图形验证码**：脚本提示先在系统设置中临时关闭 `login:captcha_enabled` 后重试；
- **.env 已存在**：install.sh 拒绝覆盖；确认旧文件已备份后加 `--force`；
- **重新初始化**：`docker compose down -v` 清除数据卷后重跑 install.sh（数据不可恢复，先备份）。
