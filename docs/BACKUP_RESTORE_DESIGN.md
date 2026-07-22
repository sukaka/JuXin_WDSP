# 备份恢复设计

本文档描述九章 WAF V2.0 的备份与恢复设计，与实现代码严格一致：

- 备份：`server/internal/backups/`（format.go / export.go / worker.go / tables.go / manifest.go / store.go / handler.go）
- 恢复：`server/internal/restores/`（service.go / restores.go / store.go / handler.go）
- 运维脚本：`ops/backup/create.sh`、`ops/restore/restore.sh`

## 1. 设计目标与安全底线

1. 备份文件必须加密（AES-256-GCM），主密钥只存在于服务端进程内，不落备份目录、不进备份文件；
2. 必须先验证再显示成功：`SUCCESS` 仅当导出后验证通过（`verified=true`）；
3. 恢复绝不未经确认覆盖生产：`Create` 只写入隔离 schema，`Confirm` 才触碰正式表；
4. 审计归档段（`operation_audits`）仅导出查阅，永不恢复写回；
5. 失败必须可查询原因（`failure_code` / `failure_message`）并产生系统告警，不静默吞错。

## 2. 备份范围（21 表分组）

备份范围为 `tables.go` 中声明的 21 张表，按四个分组决定备份/恢复范围：

| 分组 | 表 | 说明 |
|------|----|------|
| DATABASE（8） | roles、permissions、users、user_roles、role_permissions、applications、application_domains、upstreams | 账号体系与应用拓扑 |
| CONFIG（11） | system_settings、protection_policies、rule_overrides、custom_rules、exception_policies、trusted_proxies、protected_addresses、ip_access_rules、rate_limit_policies、temporary_blocks、report_templates | 策略与配置 |
| CERTIFICATE（1） | certificates | 证书（含加密私钥字段） |
| AUDIT（1） | operation_audits | 审计归档：仅导出最近 100 万行（`ORDER BY occurred_at DESC LIMIT 1000000`），`archive=true`，永不恢复 |

备份类型（`backups.TypeFull` / `TypeConfigOnly`）：

- `FULL`：全部 21 表（含审计归档段）；
- `CONFIG_ONLY`：仅前 20 表，排除 AUDIT 归档段。

表间硬外键依赖登记于 `tableDeps`（如 `user_roles → users, roles`、`upstreams → applications`），恢复顺序由 Kahn 拓扑排序计算（parent → child，同层按声明顺序，结果确定）。

## 3. .jzbk 文件格式

备份文件扩展名 `.jzbk`，文件名固定为 `backup-{任务UUID}.jzbk`（仅由 UUID 派生，防路径穿越），存放在 `GATEWAY_DATA_DIR/backups/`（容器内 `/app/runtime/backups/`）。单文件上限 2GB。

```text
┌─────────────────────────────────────────────┐
│ 8B  magic "JZBK0001"                        │
├─────────────────────────────────────────────┤
│ 加密数据段（重复 N 块）：                     │
│   ┌──────────────┬────────────────────────┐ │
│   │ 4B 大端长度  │ 密文块（base64 解码后） │ │
│   └──────────────┴────────────────────────┘ │
│   明文 = gzip(tar)，按 4MB 分块，             │
│   每块独立随机 nonce 做 AES-256-GCM 加密      │
├─────────────────────────────────────────────┤
│ manifest.json（清单，尾部存储）               │
├─────────────────────────────────────────────┤
│ 4B 大端 manifest 长度                        │
└─────────────────────────────────────────────┘
```

清单置于尾部，导出可单遍流式写入，无需预知数据段统计。tar 内部每表一个条目 `tables/{表名}.jsonl`（JSON Lines，每行一个 `to_jsonb` 对象）；读取时条目名必须匹配白名单 `^tables/([a-z0-9_]+)\.jsonl$` 且属于备份范围表，否则拒绝（防 zip-slip）。

## 4. 加密设计

- 算法：`AES-256-GCM`（与 `encryption.Service` 一致）；分块大小 `ChunkSize = 4MiB`，控制内存占用；
- 每块使用独立随机 nonce，nonce 随密文存储（`encryption.Service.Encrypt` 输出 base64，Writer 解码后按 `[4B 长度][密文]` 落盘）；
- 主密钥来自环境变量 `JIUZHANG_MASTER_KEY`，仅驻留服务端进程内存；未配置时加密服务不可用，备份直接失败（`ENCRYPTION_UNAVAILABLE`）；
- 清单记录加密元信息：`{algorithm, chunk_size, chunk_count}`，读取时逐项校验，不匹配即拒绝。

## 5. 清单（manifest）

尾部 manifest.json 字段（`manifest.go`）：`format="jzbk"`、`format_version=1`、`backup_id`、`backup_type`、`created_at`、`created_by`、`schema_version`（备份时 `schema_migrations` 最大版本）、`app_component="jiuzhang-waf-server"`、`compression="gzip"`、`archive_format="tar"`、`encryption{...}`、`data{sha256_encrypted, size_encrypted, sha256_plain, size_plain}`、`tables[]{name, group, columns, row_count, byte_count, sha256, archive, truncated}`、`total_rows`。

`Manifest.Validate()` 校验格式版本、加密参数、压缩/归档标识、数据哈希存在性、表名白名单、行数非负、`total_rows` 与分表行之和一致。清单上限 4MB（防御畸形文件）。

## 6. 备份执行与验证

Worker（`worker.go`）每 5s 认领一个待处理任务，单任务超时 30 分钟：

```text
PENDING → RUNNING（导出）→ VERIFYING（验证）→ SUCCESS（verified=true）
                    ↘ 任一步失败 → FAILED（failure_code + failure_message + 告警）
```

导出：SELECT → JSONL → tar/gzip → 分块加密，大表经数据目录下的临时卷文件（`.spool-*.jsonl`）中转，避免整表驻留内存；先写 `.backup-{id}.tmp`，验证通过后原子改名为 `backup-{id}.jzbk`。

验证（`Exporter.Verify`，任一步失败即整体失败，绝不部分通过）：

1. 全文件 SHA-256 与 DB 记录比对（`file_hash`）；
2. 清单结构与自洽性校验；
3. schema 兼容：备份 `schema_version` 高于当前库时拒绝；
4. 解密 → 解压 → 逐表重算行数/字节数/段哈希，与清单逐项比对；
5. 明文整体 SHA-256 比对（排空 tee 流后）。

**未验证不显示成功**：Worker 导出后自动执行验证，仅验证通过才 `MarkSuccess`；手动验证（`POST /api/v1/backups/{id}/verify`，权限 `backups.verify`）重算文件哈希对照 DB 记录，验证失败的备份被直接置为 `FAILED`（`failure_code=VERIFY_FAILED`，不得保持"成功"外观）并产生告警（`BACKUP_VERIFY_FAILED`）。

## 7. 保留策略

Worker 每小时执行一次保留清理（`CleanupRetention`）：

- 保留最近成功备份 10 份（`RetainRecentSuccess = 10`）；
- 保留最长时间 30 天（`RetainMaxAge = 30 * 24h`）；
- 超额/过期任务删除备份文件并删除 DB 记录；文件删除失败保留记录下轮重试，不静默；
- 被恢复任务引用的备份不可删除（`ErrReferenced`）。

## 8. 恢复设计

### 8.1 恢复范围

| scope | 覆盖分组 |
|-------|----------|
| `FULL` | DATABASE + CERTIFICATE + CONFIG（不含 AUDIT 归档段） |
| `CONFIG` | CONFIG |
| `DATABASE` | DATABASE |
| `CERTIFICATE` | CERTIFICATE |

范围内表按拓扑序（parent → child）恢复；备份中不存在的表自动跳过（如 `CONFIG_ONLY` 备份无审计段）。范围为空报 `EMPTY_SCOPE`。

### 8.2 状态机与隔离恢复流程

```text
PENDING → VALIDATING → ISOLATED_RESTORE → VERIFYING → AWAITING_CONFIRM
        →（管理员确认）→ RESTORING → SUCCESS
   任意阶段失败 → FAILED；AWAITING_CONFIRM 可 Cancel → CANCELLED
```

前提：备份任务必须 `SUCCESS` 且 `verified=true`，文件存在；同一时刻只允许一个活动恢复任务。

隔离恢复（异步，超时 60 分钟，绝不触碰正式表）：

1. **VALIDATING**：重新全量验证备份（哈希+清单+解密+逐表行数），解包到 `GATEWAY_DATA_DIR/restore-tmp/{id}/`（权限 0700），校验 schema 兼容；
2. **ISOLATED_RESTORE**：创建隔离 schema `jzrestore_{任务ID前8位hex}`（先 DROP 再 CREATE，重复执行安全），按当前库信息模式 `CREATE TABLE ... (LIKE ...)` 克隆表结构（仅列与类型），从 JSONL 按 200 行/批经 `jsonb_populate_recordset` 插入，列集取备份列 ∩ 当前列；
3. **VERIFYING**：逐表核对 `隔离表行数 = 清单行数 = 已插入行数`，不一致即失败；
4. 生成预览（每表备份行数/恢复行数/是否匹配/是否在范围内），进入 `AWAITING_CONFIRM`；解包明文立即清理，隔离 schema 保留至确认或取消。

正式恢复（`Confirm`，超时 30 分钟，关键段使用独立超时上下文）：

1. 设置维护模式标志（见 §9）；
2. 单事务内：`SET LOCAL session_replication_role = 'replica'` 关闭触发器（需超级用户或等效权限，失败即报 `PRIVILEGE_REQUIRED`，绝不降级继续）；
3. 按 child → parent 顺序 `DELETE FROM` 范围内正式表，再按 parent → child 从隔离 schema 整组 `INSERT INTO ... SELECT`（保留原主键，关联关系不失），插入行数与隔离表行数不一致即回滚；
4. 同事务 `DROP SCHEMA jzrestore_xxx CASCADE`，提交；
5. 恢复后验证：核心表可读且计数合理（`users`、`applications`、`system_settings`；CERTIFICATE 范围为 `certificates`），随后 `MarkSuccess`；
6. 取消（`Cancel`）：标记 `CANCELLED` 并删除隔离 schema。

任一阶段失败：标记 `FAILED`（失败码可查）、清理隔离 schema 与解包目录、产生系统告警（`RESTORE_FAILED`）；隔离环境清理失败单独告警（`RESTORE_CLEANUP_FAILED`）。

## 9. 维护模式

正式恢复前置入维护模式：向 Valkey 写入 `jiuzhang:maintenance = "1"`，TTL 30 分钟（兜底过期，防进程崩溃后无法退出维护）；恢复结束（成功或失败）后删除标志。本阶段实现标志的设置与清除，网关/管理面中间件对该标志的读取在后续阶段接入。

## 10. 安全要求

1. 备份文件权限 0600，备份目录 0750，解包临时目录 0700；
2. 文件名仅由 UUID 派生，所有路径拼接经 `SafeJoin` 白名单校验（拒绝穿越/绝对路径/嵌套路径）；
3. 主密钥只存进程内；备份文件不含密钥；
4. 全部写操作（创建/验证/下载/删除/恢复各阶段）记录操作审计；
5. 备份、验证、恢复失败均产生系统告警并可查询失败码；
6. 审计归档段永不写回生产库，恢复预览中明确标注"仅用于查阅"。

## 11. API 与脚本

| 能力 | API | 权限 |
|------|-----|------|
| 创建备份 | `POST /api/v1/backups`（`{"backup_type":"FULL"|"CONFIG_ONLY"}`） | `backups.create` |
| 列表/详情 | `GET /api/v1/backups`、`GET /api/v1/backups/{id}` | `backups.read` |
| 手动验证 | `POST /api/v1/backups/{id}/verify` | `backups.verify` |
| 下载 | `GET /api/v1/backups/{id}/download` | `backups.read` |
| 删除 | `DELETE /api/v1/backups/{id}` | `backups.delete` |
| 校验并预览 | `POST /api/v1/restores/validate` | `backups.restore` |
| 创建恢复 | `POST /api/v1/restores`（`{"backup_job_id","scope"}`） | `backups.restore` |
| 详情/确认/取消 | `GET /api/v1/restores/{id}`、`POST .../confirm`、`POST .../cancel` | `backups.restore` |

运维脚本：

```bash
# 创建 FULL 备份、等待 SUCCESS 且 verified=true 并下载 .jzbk
ops/backup/create.sh -t FULL -o /safe/dir
# 隔离恢复引导（validate → create → 等待 AWAITING_CONFIRM → 人工确认 confirm）
ops/restore/restore.sh --backup-id <备份任务ID> --scope FULL
```
