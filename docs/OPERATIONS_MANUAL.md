# 九章WAF 运维手册

适用版本：九章WEB应用智能防护系统 V2.0（阶段6 交付版）
适用对象：驻场/远程运维工程师。系统内操作按三权分工执行，详见《系统管理员手册》《安全管理员手册》《审计管理员手册》。

## 1. 系统组件与运行基线

| 组件 | 标识 | 说明 | 默认端口 |
|------|------|------|---------|
| 防护网关 | GATEWAY（含 CORAZA、GUARD） | Caddy 2.11.x + Coraza + CRS + jiuzhang_guard | 18080（生产 80/443） |
| 管理后端 | API | jiuzhang-server REST API | 18081 |
| 数据库 | POSTGRES | PostgreSQL 16 | 127.0.0.1:5432 |
| 缓存 | VALKEY | Valkey 8（会话/CC计数/临时封禁） | 127.0.0.1:6379 |
| 事件采集 | EVENT_COLLECTOR | 安全事件/访问控制事件采集器（进程内 goroutine） | - |
| 存储探针 | DISK | 数据目录磁盘占用 | - |

运行健康快照每 30 秒采集一次，告警评估每 30 秒执行一次（`App.StartStage6Workers`）。状态取值：UP / DEGRADED / DOWN / UNKNOWN。

## 2. 日常巡检清单

### 2.1 每班（或每日开市前）巡检

- [ ] 运行监控：系统管理员登录 → 「系统运维 → 运行监控」（`/system-monitoring`，API `GET /api/v1/system-health`），全组件 UP；整体状态非 UP 时按第 4 节处置。
- [ ] 系统告警：「安全态势 → 系统告警」（`/system-alerts`，API `GET /api/v1/system-alerts`），无未处置的 CRITICAL/HIGH 告警。
- [ ] 安全态势：安全管理员查看「安全态势 → 安全总览」（`/security-overview`，API `GET /api/v1/dashboard/security-overview`），关注今日攻击数、阻断数、未处置事件数突变。
- [ ] 采集延迟：运行监控中 EVENT_COLLECTOR 组件 `max_lag_seconds` 指标 < 60 秒；超限会产生 EVENT_COLLECTOR_LAG 告警。
- [ ] 存储容量：「系统运维 → 存储容量」（`/storage`，API `GET /api/v1/system-health/storage`），磁盘占用率与数据库容量无 HIGH 水位。

### 2.2 每日巡检

- [ ] 备份任务：「系统运维 → 备份恢复」（`/backup-restore`，API `GET /api/v1/backups`），最近一次备份 SUCCESS 且已验证（verified）。
- [ ] 报告任务：「报表中心 → 报告任务」（`/reports`），无 FAILED 状态的定时报告；失败会产生 REPORT_FAILED 告警。
- [ ] 未处置安全事件：「事件中心 → 安全事件」（`/security-events`）按"未处置"筛选，清零或转交研判。
- [ ] 临时封禁：「访问控制 → 临时封禁」（`/temporary-blocks`），确认活跃封禁均为预期。

### 2.3 每周巡检

- [ ] 交付检查抽查：「系统运维 → 交付检查」（`/delivery-check`，API `POST /api/v1/delivery-checks/run`）执行一次，整体结果保持 PASS。
- [ ] 审计哈希链：审计管理员在「操作审计」（`/audits`）执行"验证哈希链"（API `POST /api/v1/audits/verify-chain`），不一致数必须为 0。
- [ ] 证书到期：「应用防护 → HTTPS证书」（`/certificates`），剩余天数 ≤30 天的证书列入更新计划（CERTIFICATE_EXPIRING 告警同步出现）。
- [ ] 磁盘增长趋势：对比存储容量页历史快照，评估增长斜率（见第 8 节）。

## 3. 告警处置流程

### 3.1 标准流程

1. **发现**：「系统告警」页或巡检发现告警（去重合并，同一类型+组件只保留一条 open 记录）。
2. **确认**：点击"确认"（`POST /api/v1/system-alerts/{id}/acknowledge`），表明已有人接手，避免多人重复处理。
3. **处置**：按 3.2 对照表定位根因并修复；过程记录写入"备注"（`POST /api/v1/system-alerts/{id}/notes`）。
4. **关闭**：根因消除后点"解决"（`POST /api/v1/system-alerts/{id}/resolve`）；确认为噪声的用"忽略"（`POST /api/v1/system-alerts/{id}/ignore`）并备注理由。
5. **复盘**：CRITICAL 告警关闭后 24 小时内补记处置经过，纳入周巡检复盘。

### 3.2 告警类型与处置指引

| 告警类型 | 默认级别 | 首要处置 |
|---------|---------|---------|
| GATEWAY_DOWN | CRITICAL | `docker compose ps` 查网关容器；查 `docker logs`；必要时 `docker compose up -d gateway` |
| DATABASE_UNAVAILABLE | CRITICAL | 查 postgres 容器与磁盘；恢复后确认 API 自动重连 |
| MANAGEMENT_API_DOWN | HIGH | 查 API 容器日志；确认 18081 端口与迁移是否卡住 |
| VALKEY_UNAVAILABLE | HIGH | 查 valkey 容器；CC 计数按 GUARD_FAIL_OPEN 策略 Fail-open/Fail-closed，期间网关产生 RATE_LIMIT_ENGINE_ERROR 访问控制事件（`/access-control-events` 可查） |
| CONFIG_PUBLISH_FAILED | HIGH | 「应用防护 → 配置发布」（`/config-publish`）查失败任务详情，修复后重新发布或回滚 |
| CERTIFICATE_EXPIRED | HIGH | 立即按第 7 节更换证书 |
| DISK_SPACE_LOW | HIGH | 按第 8 节清理/扩容 |
| AUDIT_INTEGRITY_FAILED | CRITICAL | 哈希链不一致，立即保全现场并上报安全负责人，禁止删改审计表 |
| EVENT_COLLECTOR_LAG | MEDIUM | 查采集器指标与错误队列；确认网关日志卷可读写 |
| EVENT_PARSE_FAILURE_RATE_HIGH | MEDIUM | 查解析失败样本；确认网关日志格式未被改动 |
| SOURCE_UNHEALTHY | MEDIUM | 在应用详情"源站"Tab 执行连通性测试（`POST /api/v1/upstreams/test`） |
| CERTIFICATE_EXPIRING | LOW（≤7 天升 MEDIUM） | 纳入证书更新计划 |
| CONFIG_HASH_MISMATCH | MEDIUM | 比对「网关状态」（`/gateway-status`）哈希与当前版本，必要时重新发布 |
| DATABASE_CAPACITY_HIGH | MEDIUM | 按第 8 节评估分区清理与扩容 |
| BACKUP_FAILED / REPORT_FAILED / UPGRADE_FAILED / RESTORE_VALIDATION_FAILED | 按级别 | 查对应任务详情页错误信息，重跑或回滚 |

## 4. 备份策略建议

- **周期**：每日 1 次 FULL 全量备份（低峰时段）；配置频繁变更期加做 CONFIG_ONLY 配置备份（变更发布前必做）。
- **操作**：页面「系统运维 → 备份恢复」→ 新建备份（`POST /api/v1/backups`，type=FULL|CONFIG_ONLY）；或命令行 `ops/backup/create.sh -t FULL -o /backup/dir`（生成加密 `.jzbk` 文件）。
- **验证**：创建后执行"验证"（`POST /api/v1/backups/{id}/verify`），交付检查要求最近已验证备份 <7 天（backup_available 关键项）。
- **保留**：本地保留最近 14 天 + 每周 1 份保留 3 个月；每月 1 份保留 1 年。过期备份用页面删除（`DELETE /api/v1/backups/{id}`）。
- **异地**：`.jzbk` 为加密备份（AES-256-GCM，主密钥 `JIUZHANG_MASTER_KEY`），每日同步至异地存储；主密钥独立于备份保管，丢失则全部备份不可恢复。
- **失败兜底**：备份失败自动产生 BACKUP_FAILED 告警，当日必须补跑成功。

## 5. 恢复演练制度

- **频次**：每季度至少 1 次隔离恢复演练；重大升级前必须演练。
- **方式**：使用隔离恢复流程（不触碰正式表）：`ops/restore/restore.sh -b <backup-id> -s FULL`，或在「备份恢复」页按 validate → create → AWAITING_CONFIRM → confirm 操作（`POST /api/v1/restores/validate`、`POST /api/v1/restores`、`POST /api/v1/restores/{id}/confirm`）。
- **验收**：恢复后抽查应用、策略、用户、证书可用；记录演练结果（restore_jobs SUCCESS 记录即交付检查 restore_drill 项依据）。
- **注意**：confirm 为正式恢复，进入维护模式整组替换，必须人工确认，禁止 `-y` 跳过确认用于生产。

## 6. 发布变更流程

1. **变更申请**：明确变更内容（应用接入/策略/黑白名单/CC/证书），评估影响面。
2. **变更前备份**：CONFIG_ONLY 备份；重大变更 FULL 备份。
3. **预览与校验**：「配置发布」页先"预览"（`POST /api/v1/gateway-config/preview`）再"校验"（`POST /api/v1/gateway-config/validate`）。
4. **发布**：确认后发布（`POST /api/v1/gateway-config/publish`），页面轮询任务进度（`GET /api/v1/publish-tasks/{id}`）。发布具备失败保护：新配置加载失败自动保持旧配置。
5. **验证**：发布后经网关发测试请求确认转发与防护正常；查「网关状态」哈希一致。
6. **回滚**：异常时在「配置版本」（`/config-versions`）选择上一版本回滚（`POST /api/v1/config-versions/{id}/rollback`）；访问控制类配置另走 `POST /api/v1/access-control/versions/{id}/rollback`。
7. **记录**：发布操作自动写入操作审计，变更单号填入发布备注。

## 7. 证书更新

1. 在「应用防护 → HTTPS证书」上传新证书 PEM（`POST /api/v1/certificates`），系统自动解析域名匹配、到期时间、密钥强度。
2. 在应用详情"证书"Tab 绑定新证书（`POST /api/v1/certificates/{id}/bind`），解绑旧证书（`POST /api/v1/certificates/{id}/unbind`）。
3. 按第 6 节发布配置并验证 HTTPS 访问。
4. 确认无绑定关系后删除旧证书（使用中证书禁止删除）。
5. 私钥以 AES-256-GCM 加密存储，页面与接口均不回显私钥。

## 8. 容量管理

- **监控入口**：「系统运维 → 存储容量」（`GET /api/v1/system-health/storage`）：数据目录、`runtime/reports`、`runtime/backups`、数据库容量。
- **阈值**：磁盘不足触发 DISK_SPACE_LOW（HIGH），数据库容量高水位触发 DATABASE_CAPACITY_HIGH（MEDIUM）。
- **治理手段**：按第 4 节清理过期备份与报告归档；security_events / access_control_events 按月分区，可按分区归档历史月份；清理 gateway 日志轮转产物。
- **扩容原则**：容量周增长率 >10% 或预计 30 天内写满时启动扩容；扩容操作记录在变更单。

## 9. 日志管理

- **访问/审计日志**：网关访问日志、Coraza 审计日志、guard 事件 JSONL 位于网关数据目录（`runtime/logs` 及数据卷），由采集器断点续传入库，文件按大小轮转。
- **业务日志**：安全事件（`/security-events`）、访问控制事件（`/access-control-events`）支持页面筛选与 CSV 导出；登录日志、操作审计见《审计管理员手册》。
- **API 访问日志**：管理后端 AccessLog 中间件记录全部 API 请求（含 Request ID）。
- **脱敏要求**：日志与导出不含密码、验证码、私钥、完整会话；诊断收集脚本自动脱敏（`ops/diagnostics/collect.sh`）。

## 10. 故障应急

重大故障（网关中断、数据损坏、全组件 DOWN、安全事件导致业务不可用）按《灾难恢复指南》（`docs/DISASTER_RECOVERY_GUIDE.md`）执行，要点：

1. **定级与通报**：按影响面定级，10 分钟内通报负责人。
2. **保全现场**：收集诊断包 `ops/diagnostics/collect.sh`（含版本/脱敏配置/容器状态/最近日志/磁盘），禁止直接重启销毁证据。
3. **快速恢复**：优先恢复流量（网关容器重启 → 配置回滚 → 备份恢复逐级升级）。
4. **根因分析**：恢复后 48 小时内完成根因报告，整改项纳入变更管理。
5. 详细 RTO/RPO 指标、分场景恢复步骤以《灾难恢复指南》为准。

## 11. 常用命令速查

| 场景 | 命令 |
|------|------|
| 组件健康检查 | `ops/healthcheck/check.sh`（退出码 0=全部健康） |
| 创建备份 | `ops/backup/create.sh -t FULL -o /backup/dir` |
| 隔离恢复 | `ops/restore/restore.sh -b <backup-id> -s FULL` |
| 系统升级 | `ops/upgrade/apply.sh --server-image <img> --gateway-image <img>` |
| 升级回滚 | `ops/upgrade/rollback.sh`（可加 `--restore-backup`） |
| 诊断收集 | `ops/diagnostics/collect.sh -o dist` |
| 离线包构建 | `ops/offline-package/build.sh` |
| 构建前后端 | `make build` |
| 全量测试 | `make test`（后端 `go test -race` + 前端 vitest） |
| 网关单测 | `make guard-test` |
| 阶段5环境 | `make stage5-up / stage5-status / stage5-down` |
| 阶段5全量测试 | `make stage5-test-all` |

关键 API：`GET /api/v1/health`（无需认证，含 postgres/valkey 依赖状态）；`GET /api/v1/system-health`、`GET /api/v1/system-health/components`、`GET /api/v1/system-health/storage`（运行监控）；`GET /api/v1/gateway/status`（网关状态）；`POST /api/v1/delivery-checks/run`（交付检查）。
