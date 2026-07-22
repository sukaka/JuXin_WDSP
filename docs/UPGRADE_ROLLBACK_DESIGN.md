# 升级与回滚设计

本文档描述九章 WAF V2.0 的升级与回滚设计，与实现严格一致：

- 管理面升级服务：`server/internal/upgrades/`（service.go / precheck.go / store.go / handler.go / upgrades.go）
- 数据库迁移：`server/internal/database`（`Migrate`，迁移目录 `server/migrations/`，容器内 `/app/migrations`）
- 运维脚本：`ops/upgrade/apply.sh`、`ops/upgrade/rollback.sh`

## 1. 职责划分

升级由「管理 API 升级任务」与「运维脚本」两部分协作完成：

- **API 侧**：升级包登记/校验、升级前检查（9 项）、升级前强制 FULL 备份、迁移文件成对校验、执行数据库迁移（up）、升级后验证、失败自动回滚（恢复升级前备份）；
- **脚本侧**：组件健康预检、调用 API 备份、**容器镜像切换（retag）**、重启 api/gateway、等待健康、失败时按状态文件回滚镜像（可选同时恢复数据）。

镜像切换属运维脚本职责（`applyDryRun` 注释明确：API 侧完成迁移文件校验与目标版本记录）。

## 2. 升级包结构

升级包登记信息（`upgrade_packages` 表 / `Package`）：

| 字段 | 说明 |
|------|------|
| `file_name` | 包文件名（仅纯文件名，拒绝路径分隔符，≤255 字符） |
| `version_from` / `version_to` | 起始/目标版本，语义化版本号 `v?MAJOR.MINOR.PATCH`（可带 prerelease 后缀，比较时忽略），且 `version_to > version_from` |
| `file_hash` | 包文件 SHA-256（64 位小写十六进制） |
| `file_size` | 包文件字节数（>0） |
| `manifest` | 包清单 JSON（可选；`target_schema_version` 声明目标迁移号，供预检核对） |
| `status` | `REGISTERED` / `VERIFIED` / `REJECTED` |

登记（`POST /api/v1/upgrade-packages`，权限 `upgrades.execute`）时逐项校验：全部通过置 `VERIFIED`；任一不通过仍以 `REJECTED` 状态登记留证并返回失败原因。哈希/镜像摘要用于交付侧核对（离线包 `manifest.json` 记录每个镜像 digest 与全部文件 SHA-256，见《离线部署指南》）。

## 3. 升级前检查（9 项）

`precheck.go` 的 `Evaluate` 为纯函数，输入采集到的事实，输出 9 个检查项（`PASS` / `WARNING` / `FAIL`）：

| # | 检查项 | 判定 |
|---|--------|------|
| 1 | `version_match` | 当前版本 == 包 `version_from` 且 `version_to` 更高，否则 FAIL |
| 2 | `disk_space` | 数据目录所在磁盘 <2GiB FAIL；<4GiB WARNING |
| 3 | `postgres_reachable` | 不可达 FAIL |
| 4 | `valkey_reachable` | 不可达 FAIL |
| 5 | `no_active_tasks` | 存在进行中的发布/备份/恢复/报告任务 FAIL |
| 6 | `migration_compat` | 本地迁移目录可读，且包声明的目标迁移号 ≤ 本地最大号+1，否则 FAIL |
| 7 | `master_key` | `JIUZHANG_MASTER_KEY` 已配置，否则 FAIL（无法创建加密备份） |
| 8 | `recent_backup` | 最近 24h 无已验证 FULL 备份为 WARNING（BACKUP 步骤会自动新建） |
| 9 | `no_critical_alerts` | 存在未处置 CRITICAL 告警 FAIL；查询失败按存在告警保守阻断 |

存在任一 FAIL 即阻断升级。预检结果落 `upgrade_jobs.precheck`，可单独预检：`POST /api/v1/upgrade-packages/{id}/precheck`（权限 `upgrades.precheck`）。

## 4. 升级状态机

```text
PENDING → PRECHECK → BACKUP → APPLYING → MIGRATING → VERIFYING → SUCCESS
            │          │          │           │           │
            ▼          ▼          ▼           ▼           ▼
          FAILED     FAILED   ROLLING_BACK ←────┘（自动回滚）
                                 │
                    SUCCESS/FAILED（显式回滚）→ ROLLING_BACK
                                 ▼
                     ROLLED_BACK（回滚成功）/ FAILED（回滚失败）
```

状态迁移由白名单约束（`transitions`），非法迁移拒绝。终态：`SUCCESS` / `FAILED` / `ROLLED_BACK`。失败码：`PRECHECK_FAILED`、`BACKUP_FAILED`、`APPLY_FAILED`、`MIGRATE_FAILED`、`VERIFY_FAILED`、`ROLLBACK_FAILED`。任一失败落库并产生系统告警（`UPGRADE_FAILED` / `UPGRADE_ROLLED_BACK` / `UPGRADE_ROLLBACK_FAILED`）。

## 5. 升级前强制备份

进入 `BACKUP` 阶段后，系统自动创建 `FULL` 加密备份（请求来源标记 `upgrade-{升级任务ID}`）并等待其到达终态：

- 仅当备份 `SUCCESS` 且 `verified=true` 才继续；`FAILED`/`CANCELLED`/超时（默认等待上限 30 分钟）即升级失败；
- 备份任务ID 记录于 `upgrade_jobs.backup_job_id`，作为后续回滚的恢复点；
- 备份成功之后的任何失败（APPLYING/MIGRATING/VERIFYING）都会触发自动回滚。

## 6. 数据库迁移

- 迁移文件命名 `NNNNNN_name.up.sql` / `NNNNNN_name.down.sql`，**up/down 必须成对**：APPLYING 阶段执行 dry-run 校验，任一 up 缺少对应 down 即失败（迁移必须具备回滚能力）；
- MIGRATING 阶段执行 `database.Migrate(ctx, db, migrationsDir, "up")`（容器内目录 `/app/migrations`）；
- VERIFYING 阶段核对：PostgreSQL/Valkey 可达，且 `schema_migrations` 当前最大版本 == 本地迁移文件最大版本，不一致即失败；
- 脚本路径下，迁移随 api 服务启动自动执行（`apply.sh` 重启后等待 `/api/v1/health`）。

## 7. 失败自动回滚

`BACKUP` 之后任一阶段失败，进入 `ROLLING_BACK`，使用升级前备份自动恢复：

```text
validate 备份 → 创建恢复任务（scope=FULL，来源 upgrade-rollback）
→ 等待 AWAITING_CONFIRM（默认上限 60 分钟）→ 自动 confirm（维护模式 + 事务整组替换）
```

- 回滚成功：任务置 `ROLLED_BACK`，告警 `UPGRADE_ROLLED_BACK`；
- 回滚失败：任务置 `FAILED`（`ROLLBACK_FAILED`），告警 `UPGRADE_ROLLBACK_FAILED`，需人工介入（可用 `ops/restore/restore.sh` 手动恢复升级前备份）；
- 显式回滚：仅 `SUCCESS`/`FAILED` 状态的任务允许 `POST /api/v1/upgrades/{id}/rollback`（权限 `upgrades.rollback`），异步执行同一恢复流程；
- 注意：API 侧回滚恢复的是**数据**；镜像回退由 `ops/upgrade/rollback.sh` 完成。

## 8. ops/upgrade 脚本

### 8.1 apply.sh（升级执行）

```bash
ops/upgrade/apply.sh \
  --server-image jiuzhang-server:2.1.0 \
  --gateway-image jiuzhang-gateway:2.1.0 \
  [--images-tar images.tar] \     # 离线场景先 docker load
  [-c docker-compose.yml] [-e .env] [--timeout 600]
```

执行流程（与脚本步骤一致）：

1. 预检：调用 `ops/healthcheck/check.sh`，未通过即中止；
2. 备份：调用管理 API 创建 `FULL` 备份并等待 `SUCCESS + verified`，失败即中止升级；
3. 镜像切换：`--images-tar` 存在则先 `docker load`；从 compose 配置解析 api/gateway 当前镜像名，记录**旧镜像 ID** 与备份任务ID 到 `ops/upgrade/.upgrade-state.env`（权限 600，不含敏感信息），然后 `docker tag` 将新镜像标记为 compose 使用的镜像名（retag）；
4. `docker compose up -d --no-deps api gateway` 重启，等待管理 API 健康（默认 600s），数据库迁移随服务启动执行；
5. 升级后再次 `check.sh`；失败时提示执行 `rollback.sh`。

### 8.2 rollback.sh（升级回滚）

```bash
ops/upgrade/rollback.sh [--restore-backup] [-y] [--timeout 600]
```

1. 读取 `.upgrade-state.env`（无升级记录则退出）；
2. 校验旧镜像 ID 仍在本机（被清理则报错并提示重新加载旧镜像），`docker tag <旧镜像ID> <compose镜像名>` retag 回旧镜像，重启 api/gateway 并等待健康；
3. `--restore-backup` 时追加数据回滚：调用 `ops/restore/restore.sh --backup-id <升级前备份ID> --scope FULL`（validate → create → 人工确认 → confirm），不加该选项则只回退镜像。

### 8.3 脚本与 API 的关系

- 纯容器升级（同库结构或仅脚本侧）：`apply.sh` 一条命令完成预检→备份→切换→验证；
- 管理面升级任务（`POST /api/v1/upgrades`，权限 `upgrades.execute`）提供 9 项预检、强制备份、迁移 up/down 成对校验与失败自动数据回滚，二者共用同一备份/恢复底座；
- 生产变更窗口推荐：先 `POST /api/v1/upgrade-packages/{id}/precheck` 独立预检，再执行 `apply.sh`；异常时 `rollback.sh --restore-backup`。

## 9. 安全要求

1. 升级前必须备份且验证通过，禁止跳过；
2. 迁移必须具备回滚能力（up/down 成对），禁止只更新数据库而没有回滚方案；
3. 失败必须可查询原因（`failure_code`/`failure_message`）并告警，不静默吞错；
4. 存在未处置严重告警、进行中任务、主密钥缺失时阻断升级；
5. 升级/预检/回滚全部记录操作审计；回滚状态文件不含敏感信息（仅镜像名/ID、备份任务ID）。
