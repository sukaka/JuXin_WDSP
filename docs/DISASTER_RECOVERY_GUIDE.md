# 灾难恢复手册

本手册面向运维值班人员，给出八类故障场景的命令级恢复步骤。所有命令均来自仓库内真实脚本与管理 API，执行前请确认：

- 在部署目录（含 `docker-compose.yml` 与 `.env`）下执行，或用 `-c/-e` 显式指定；
- 管理 API 默认 `http://127.0.0.1:18081`，脚本均支持 `--api-url` 覆盖；
- 管理员口令经环境变量 `JZ_ADMIN_PASSWORD` 提供（未设置时脚本交互读取，不回显）；
- 恢复类操作默认逐步交互确认，`-y/--yes` 仅用于自动化场景。

通用定位手段（各场景均可先执行）：

```bash
ops/healthcheck/check.sh                     # 组件健康检查（容器/API/网关/PostgreSQL/Valkey）
ops/diagnostics/collect.sh                   # 打包诊断信息到 dist/diagnostics-*.tar.gz（配置自动脱敏）
docker compose ps                            # 容器状态
docker compose logs --tail=200 api           # 管理后端日志
```

## 场景 1：单机损坏（宿主机故障后数据卷完好）

适用：宿主机重启/异常后，Docker 数据卷（`postgres-data`、`runtime-data` 等）仍在。

```bash
# 1. 确认 Docker 可用并拉起全部服务
docker compose up -d
# 2. 等待管理 API 健康（最长约 180s）
curl -fsS http://127.0.0.1:18081/api/v1/health
# 3. 全量健康检查
ops/healthcheck/check.sh
# 4. 仍有异常项时收集诊断并排查
ops/diagnostics/collect.sh
```

`restart: unless-stopped` 策略下容器通常已自动拉起；`check.sh` 全部 OK 即恢复完成。若某容器反复退出，用 `docker compose logs --tail=500 <服务>` 定位。

## 场景 2：数据库损坏

适用：PostgreSQL 可启动但数据异常（误删、表损坏），或实例无法启动。

1. 实例异常但数据目录完好：

```bash
docker compose restart postgres
docker compose logs --tail=200 postgres
ops/healthcheck/check.sh
```

2. 数据内容损坏（备份系统的 `backup_jobs` 元数据仍可读）：用最近一次**已验证**的 FULL 备份做隔离恢复：

```bash
# 找到最近 SUCCESS 且 verified=true 的备份任务ID（管理面「备份」列表，或 API）
curl -fsS -b <会话> http://127.0.0.1:18081/api/v1/backups
# 引导式恢复（validate → create → AWAITING_CONFIRM → 人工确认 confirm）
ops/restore/restore.sh --backup-id <备份任务ID> --scope FULL
```

3. 整库不可恢复（数据目录损毁）：按「场景 7：系统重装后恢复」处理。

注意：恢复任务以 `backup_jobs` 记录为入口，该记录与业务数据同库。只要库可启动且备份记录可读，即可走隔离恢复；正式恢复会自动进入维护模式并整组替换范围内表。

## 场景 3：配置误发布

适用：错误的网关配置/策略被发布到 Caddy。

优先使用配置版本回滚（无需恢复整库）：

```bash
# 1. 查询配置版本，找到误发布前的版本ID
curl -fsS -b <会话> http://127.0.0.1:18081/api/v1/config-versions
# 2. 查看差异确认目标版本
curl -fsS -b <会话> http://127.0.0.1:18081/api/v1/config-versions/{id}/diff
# 3. 回滚到指定版本（权限 gateway_configs.rollback）
curl -fsS -b <会话> -X POST -H "X-CSRF-Token: <token>" \
  http://127.0.0.1:18081/api/v1/config-versions/{id}/rollback
```

访问控制类配置（IP 黑白名单/CC 策略）另有独立版本回滚：`POST /api/v1/access-control/versions/{id}/rollback`。

若配置版本不可用或损坏面更大，再按场景 2 用 `ops/restore/restore.sh --backup-id <ID> --scope CONFIG` 仅恢复配置分组。

## 场景 4：证书目录损坏

适用：证书文件/私钥异常，或 `certificates` 表数据损坏。

证书数据（含加密私钥字段）属于 CERTIFICATE 分组，可独立恢复：

```bash
ops/restore/restore.sh --backup-id <备份任务ID> --scope CERTIFICATE
```

恢复后验证：

```bash
ops/healthcheck/check.sh                 # 网关/API 恢复正常
# 管理面「证书管理」核对证书列表与有效期；恢复后验证会自动核对 certificates 表行数
```

注意：解密证书私钥字段依赖当前 `JIUZHANG_MASTER_KEY` 与备份时一致；主密钥变更后旧备份的证书段无法使用（见场景 8）。

## 场景 5：Valkey 数据丢失

Valkey 中存放的是会话、CSRF Token、CC 计数、维护模式标志等**易失数据**，不是持久化真相来源（配置与数据均在 PostgreSQL）。丢失后无需数据恢复：

```bash
# 1. 重启 Valkey（compose 配置已启用 --appendonly yes，AOF 完好时会自动重放）
docker compose restart valkey
# 2. 验证（check.sh 会从 .env 读取 VALKEY_PASSWORD 执行 ping，不回显）
ops/healthcheck/check.sh
# 3. 所有在线会话失效，通知管理员重新登录；CC 计数从零重建，属预期行为
```

若 AOF 也损坏，删除 `valkey-data` 卷后 `docker compose up -d valkey` 重建即可，影响同上新会话重建。

## 场景 6：采集积压（安全事件/访问日志采集落后）

采集器按 `event_collector_checkpoints`（文件 offset + inode）断点续采：API 停机期间网关持续写审计/事件日志，API 恢复后从断点继续，不会丢当前日志文件内的数据。

```bash
# 1. 确认 API 与网关容器正常
ops/healthcheck/check.sh
# 2. 观察采集恢复：安全事件列表按时间回升；查看 api 日志中 collector 相关输出
docker compose logs --tail=200 api
```

边界情况：停机期间日志发生轮转（inode 变化或文件变小）时，采集器检测到后轮转到 offset=0 重采当前文件；已被轮转移除的旧文件内容无法补采。因此网关日志卷应保证足够容量，长时间停机后应在管理面核对事件时间线是否连续。

## 场景 7：系统重装后恢复

适用：整机重装/迁移到新主机，持有离线包或镜像、`.env`（含主密钥）、以及数据卷或备份。

1. 数据卷完好（推荐路径）：将 `postgres-data`、`valkey-data`、`runtime-data`（含 `backups/`）、`gateway-logs` 等卷迁移到新机同名卷，部署同版本后 `docker compose up -d`，系统整体回到故障前状态，备份记录与 `.jzbk` 文件同时可用。

2. 仅有备份文件时的完整流程：

```bash
# 1. 新主机完成安装（见 INSTALLATION_GUIDE.md；离线环境用离线包）
tar -xzf jiuzhang-offline-<版本>.tar.gz && cd jiuzhang-offline-<版本>
for f in images/*.tar; do docker load -i "$f"; done
ops/install/install.sh            # 生成 .env 时务必将 JIUZHANG_MASTER_KEY 替换为原主密钥
# 2. 将原 .env 中的主密钥写回新 .env，并重启 api
#    （主密钥不一致则无法解密旧备份）
docker compose up -d --no-deps api
# 3. 健康检查
ops/healthcheck/check.sh
```

3. 已知限制（务必纳入运维规程）：当前版本恢复入口基于数据库中的 `backup_jobs` 记录，全新数据库中没有历史备份记录，单独的 `.jzbk` 文件无法直接经 API 恢复。因此生产环境必须双轨保管：

- 定期用 `ops/backup/create.sh -o <安全目录>` 下载 `.jzbk` 文件并记录任务ID与 verified 状态；
- 同时对 `postgres-data` 与 `runtime-data` 卷做快照/异地副本，保证备份元数据与备份文件可一起找回；
- `JIUZHANG_MASTER_KEY` 与备份文件分开保管，二者缺一无法恢复。

## 场景 8：主密钥丢失风险

主密钥（`JIUZHANG_MASTER_KEY`）是备份/证书私钥加密的根：

- 主密钥丢失 = 全部既有 `.jzbk` 备份无法解密、证书私钥字段无法解密，**不可恢复**；
- 主密钥变更后，变更前创建的备份同样无法使用。

处置与预防：

1. 发现主密钥泄露风险时：先在低峰期变更 `.env` 中 `JIUZHANG_MASTER_KEY` 并重启 api，随后**立即创建新的 FULL 备份**（`ops/backup/create.sh -t FULL`），旧备份按失效处理；证书需重新上传/签发；
2. 主密钥只出现在 `.env`（权限 600）与进程内存，禁止写入日志、文档、工单；`ops/diagnostics/collect.sh` 会自动将 KEY/PASSWORD/SECRET/TOKEN 类值脱敏为 `********`；
3. 保管要求：主密钥与备份文件异地、分人保管；升级前预检会检查主密钥已配置（缺失则 FAIL，阻断升级）。

## 恢复后通用验证清单

```bash
ops/healthcheck/check.sh                     # 全部 [OK]
curl -fsS http://127.0.0.1:18081/api/v1/health   # {"status":"ok"}
```

- 管理面可登录，应用/策略/证书列表数据完整；
- 恢复任务状态为 `SUCCESS`，`post_verify` 行数核对无异常；
- 防护链路抽测：经网关访问一个已接入应用，确认正常代理与拦截页面可用；
- 必要时执行 `ops/diagnostics/collect.sh` 留档。
