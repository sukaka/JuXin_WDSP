# APM 数据面备份与恢复（阶段5）

> 范围：ClickHouse 数据面（apm 库）、PostgreSQL 控制面 apm_* 表、Collector 配置与 mTLS 证书。
> 依据：`docs/BUSINESS_PERFORMANCE_APM_DESIGN.md` §14/§19.4；schema 见 `deployment/apm/clickhouse/`。
> 下列命令样例均已在锁定镜像 `clickhouse/clickhouse-server:25.8-alpine@sha256:87e0a5b7…`（25.8.33）
> 上实测通过（2026-08-31）。

## 1. 备份范围与优先级

| 数据 | 位置 | 备份方式 | 优先级 |
|---|---|---|---|
| 原始 span / 检索表 | ClickHouse `apm.otel_traces`、`apm.otel_traces_trace_id_ts` | 原生 `BACKUP`（Disk/File/S3） | 高（不可重建） |
| 聚合表 / 指标表 | ClickHouse `apm.apm_*` 聚合、`apm.otel_metrics_*` | 可由原始表重建（重放物化视图逻辑） | 低（可不备份） |
| APM 控制面元数据 | PostgreSQL `apm_services` 等 7 张 `apm_*` 表 | 见 §3（**当前不随 .jzbk 既有备份**，临时 pg_dump 纪律） | 高 |
| Collector 配置 | `deployment/apm/collector/*.yaml` | Git 受控，无需单独备份 | — |
| mTLS 证书/私钥 | `deployment/apm/pki/`（占位，部署侧签发） | 私有 CA 可重签；在签发侧按 CA 制度保管 | 中 |

保留与备份窗口的关系（设计 §14.2）：原始正常 trace TTL 仅 7 天（错误/慢/高风险 14 天），
备份超过 TTL 窗口的数据恢复后会被 TTL 立即清除——**APM 备份的意义是灾难恢复
（实例/磁盘损毁），不是长期归档**；长期留存诉求应走延长 TTL 的容量评审，而非堆备份。

## 2. ClickHouse 备份

### 2.1 一次性准备：备份磁盘配置

官方镜像默认只开放 `<backups><allowed_path>backups</allowed_path>`（支持 `TO File(...)`
单文件归档，开箱即用）；`TO Disk(...)`（目录形态、支持增量 `base_backup`）需要追加
`/etc/clickhouse-server/config.d/backups.xml`（已实测）：

```xml
<clickhouse>
  <storage_configuration>
    <disks>
      <backups>
        <type>local</type>
        <path>/var/lib/clickhouse/backups/</path>
      </backups>
    </disks>
  </storage_configuration>
  <backups>
    <allowed_disk>backups</allowed_disk>
  </backups>
</clickhouse>
```

compose 形态注意把 `/var/lib/clickhouse/backups` 挂到持久卷或宿主机目录，
否则备份随容器删除而丢失。

### 2.2 备份命令样例

```sql
-- A. 磁盘目录形态（推荐；支持增量）：
BACKUP DATABASE apm TO Disk('backups', 'apm-full-20260831');
-- 增量（基于上一次全量）：
BACKUP DATABASE apm TO Disk('backups', 'apm-inc-20260901')
  SETTINGS base_backup = Disk('backups', 'apm-full-20260831');

-- B. 单文件归档（默认配置即可用，便于离线搬运）：
BACKUP DATABASE apm TO File('backups/apm-full-20260831.zip');

-- C. 直传对象存储（S3 兼容；凭据用命名集合或环境注入，勿写入脚本/命令历史）：
BACKUP DATABASE apm TO S3('https://<endpoint>/<bucket>/apm/apm-full-20260831/', '<ak>', '<sk>');

-- D. 双副本（ReplicatedMergeTree）形态：任选一个健康副本执行即可（副本间数据等价）；
--    或对全部副本一致性备份加 ON CLUSTER：
BACKUP DATABASE apm ON CLUSTER apm_ha TO Disk('backups', 'apm-full-20260831');
```

监控备份进度/结果：

```sql
SELECT id, name, status, error, start_time, end_time, num_files, total_size
FROM system.backups ORDER BY start_time DESC LIMIT 5;
```

### 2.3 恢复命令样例

```sql
-- 目标实例为空（灾难恢复常态）时直接恢复（备份内含建表元数据）：
RESTORE DATABASE apm FROM Disk('backups', 'apm-full-20260831');
-- 增量链恢复：先全量再增量（RESTORE 指定 base_backup 顺序还原）；
-- 从单文件/对象存储恢复：
RESTORE DATABASE apm FROM File('backups/apm-full-20260831.zip');
RESTORE DATABASE apm FROM S3('https://<endpoint>/<bucket>/apm/apm-full-20260831/', '<ak>', '<sk>');
-- 目标表已存在且非空时须显式允许合入（谨慎，先确认目标为空或评估冲突）：
RESTORE TABLE apm.otel_traces FROM Disk('backups', 'apm-full-20260831')
  SETTINGS allow_non_empty_tables = true;
```

恢复后校验：`SELECT count() FROM apm.otel_traces`、抽查时间范围、
双副本形态核对 `system.replicas`（`is_readonly=0`、`absolute_delay` 收敛）。

### 2.4 可选工具说明（未引入）

Altinity `clickhouse-backup`（MIT）可提供远端存储上传、调度与 API 化管理。**本交付物
未引入该工具**；如部署侧选用，须先按 AGENTS.md 开源合规纪律登记（版本锁定、
`docs/DEPENDENCIES.md` 与 `THIRD_PARTY_NOTICES.md`），再纳入运维流程。

## 3. PostgreSQL 控制面 apm_* 表

**现状（如实）**：管理面既有 `.jzbk` 备份（`ops/backup/create.sh` → `POST /api/v1/backups`）
的表清单登记在 `server/internal/backups/tables.go`，当前**不含** APM 控制面 7 张表
（`apm_services`、`apm_agents`、`apm_enrollment_tokens`、`apm_agent_policies`、
`apm_agent_cert_revocations`、`apm_slos`、`apm_diagnostic_sessions`）。
在这些表登记进备份清单之前（server 侧工作，列入遗留项），采用以下临时纪律：

```bash
# 随既有备份调度（每次 .jzbk FULL 备份后）追加导出 apm_* 表：
pg_dump -h <pg-host> -U <备份账号> -d <控制面库名> \
  -t apm_services -t apm_agents -t apm_enrollment_tokens -t apm_agent_policies \
  -t apm_agent_cert_revocations -t apm_slos -t apm_diagnostic_sessions \
  --format=custom --file=apm-control-plane-"$(date +%F)".pgdump
```

恢复顺序：`apm_services` 等表存在指向 `applications` 等主表的外键，必须先完成
`.jzbk` 主恢复（`ops/restore/` 流程），再 `pg_restore` 上述归档：

```bash
pg_restore -h <pg-host> -U <恢复账号> -d <控制面库名> --clean --if-exists \
  apm-control-plane-<日期>.pgdump
```

注意：`apm_enrollment_tokens` 仅存不可逆摘要、`apm_agent_cert_revocations` 为吊销清单，
恢复后需触发 Agent 心跳核对（Agent 状态以心跳为准重建）。

## 4. Collector 配置与证书

- `deployment/apm/collector/*.yaml`、`deployment/apm/docker-compose.ha.yml`、
  `deployment/apm/k8s/*` 均在 Git 受控，随仓库恢复，不做运行时备份；
- `deployment/apm/pki/` 为占位目录且**严禁入 Git**（AGENTS.md 安全底线）：证书私钥由
  部署侧私有 CA 保管并可重签，备份对象是 CA 自身（不在本交付物范围）；节点证书丢失
  时按 CA 流程重签下发即可，无需从备份恢复。

## 5. 恢复演练步骤清单

频率建议：上线前必做一次全链路演练，其后每季度一次（与既有备份制度对齐）。

1. **准备**：隔离演练环境（不与生产共用 ClickHouse/PostgreSQL）；准备最近一次的
   ClickHouse 备份、`apm-control-plane-*.pgdump`、`.jzbk` 主备份与主密钥；
2. **恢复控制面**：按 `ops/restore/` 恢复 `.jzbk` → `pg_restore` apm_* 归档 →
   核对表行数与抽样记录；
3. **恢复数据面**：起空 ClickHouse（单副本或双副本）→ 执行对应 `RESTORE` →
   核对 `count()`、`min/max(Timestamp)`、`system.replicas`（双副本）；
4. **恢复采集链路**：启动 Collector（compose HA 或 K8s 清单）→ 发送测试 span →
   确认 `otelcol_exporter_sent_spans` 增长且 ClickHouse 可见；
5. **验证查询**：trace 检索/瀑布、聚合曲线、`GET /api/v1/apm/runtime` 抽查；
6. **记录**：实测 RTO（恢复耗时）与数据完整性结论写入演练报告；RPO 由备份调度周期
   决定（建议每日增量 + 每周全量，按 §2.2 命令纳入既有调度）；
7. **清理**：销毁演练环境，演练数据不回流生产。

## 6. 遗留项

- `apm_*` 7 张表登记进 `server/internal/backups/tables.go` 备份清单（含依赖拓扑
  `tableDeps`），消除 §3 的 pg_dump 临时纪律（server 侧工作包，本任务范围外）；
- ClickHouse 备份的调度化（cron/systemd timer + 对象存储生命周期）由部署侧落地；
- 双副本形态下 `ON CLUSTER` 一致性备份的演练（当前仅单副本实测）。
