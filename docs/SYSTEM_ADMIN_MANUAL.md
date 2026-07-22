# 九章WAF 系统管理员手册

适用角色：系统管理员（SYSTEM_ADMIN）
版本：九章WEB应用智能防护系统 V2.0（阶段6 交付版）

## 1. 职责边界

系统管理员负责平台自身的稳定运行与账号体系，**不负责 WAF 业务防护策略**。

**职责范围内**：

- 用户账号与角色管理、密码策略与会话管理；
- 系统设置（密码/登录/会话/展示四组参数）；
- 运行监控、存储容量管理、系统告警处置；
- 备份与恢复、系统升级与回滚、交付检查；
- 可信代理与保护地址维护（网络拓扑类配置）；
- 网关状态、配置版本查看（只读）。

**职责范围外**（属安全管理员）：Web 应用接入与发布、防护策略、WAF 规则、例外策略、IP 黑白名单、CC 防护、临时封禁、安全事件处置、安全报告。这些菜单对系统管理员不可见，API 调用返回 403。

**三权互斥**：一个账号只能持有一种角色；系统内置保护最后一个系统管理员账号，禁止停用或删除。

## 2. 登录与菜单视图

登录页输入账号密码与图形验证码；首次使用初始账号须先完成强制改密。登录失败 5 次锁定 15 分钟。

登录后可见菜单：工作台（`/dashboard`）、应用防护 → 配置版本（`/config-versions`）与网关状态（`/gateway-status`）、访问控制 → 可信代理（`/trusted-proxies`）、安全态势 → 系统告警（`/system-alerts`）、系统运维（运行监控 `/system-monitoring`、存储容量 `/storage`、备份恢复 `/backup-restore`、系统升级 `/system-upgrade`、交付检查 `/delivery-check`）、用户管理（`/users`）、角色权限（`/roles`）、系统设置（`/system-settings`）、个人中心（`/profile`）。

## 3. 账号管理

### 3.1 用户管理（`/users`）

| 操作 | 入口 | API |
|------|------|-----|
| 查看用户列表/详情 | 用户管理页 | `GET /api/v1/users`、`GET /api/v1/users/{id}` |
| 创建用户 | 新建用户（指定角色，三权互斥） | `POST /api/v1/users` |
| 编辑用户 | 编辑（乐观锁，回传 version） | `PUT /api/v1/users/{id}` |
| 启用/停用 | 列表操作列 | `POST /api/v1/users/{id}/enable`、`POST /api/v1/users/{id}/disable` |
| 解锁 | 锁定用户操作列 | `POST /api/v1/users/{id}/unlock` |
| 重置密码 | 生成一次性临时密码，仅显示一次 | `POST /api/v1/users/{id}/reset-password` |
| 强制下线 | 结束该用户全部会话 | `DELETE /api/v1/users/{id}/sessions` |
| 删除用户 | 二次确认 | `DELETE /api/v1/users/{id}` |

角色与权限查看：`/roles` 页查看三权角色及权限清单（`GET /api/v1/roles`、`GET /api/v1/roles/{id}/permissions`、`GET /api/v1/permissions`）。角色为内置三权，不可自定义。

### 3.2 密码策略（`/system-settings` 密码组）

- 最小长度（合规要求 ≥12，交付检查 password_policy 关键项）、复杂度、历史不重复次数、有效期、弱口令字典。
- 修改入口：`PUT /api/v1/system-settings`（乐观锁；敏感值脱敏显示，仅白名单字段可改）。
- 用户改密走 `POST /api/v1/auth/change-password`，首次登录/重置后强制改密。

### 3.3 会话管理

- 会话策略在系统设置"会话组"：空闲超时（默认 30 分钟）、绝对时长（默认 8 小时）。
- 个人会话：「个人中心」查看并下线自己的其他会话（`GET /api/v1/auth/sessions`、`DELETE /api/v1/auth/sessions/{id}`）。
- 全员强制下线：用户管理页"强制下线"操作。
- 登录安全：登录失败锁定策略（5 次/15 分钟）、图形验证码、登录接口限速（每分钟次数，热更新）在"登录组"配置。

## 4. 系统设置

「系统设置」（`/system-settings`）四组参数：密码、登录、会话、展示。修改即时生效（登录限速等支持热更新），全部变更写入操作审计。查看 `GET /api/v1/system-settings`，修改 `PUT /api/v1/system-settings`。

## 5. 运行监控与存储

- **运行监控**（`/system-monitoring`）：组件健康总览（`GET /api/v1/system-health`）、分组件快照（`GET /api/v1/system-health/components`），组件含 GATEWAY/CORAZA/GUARD/API/POSTGRES/VALKEY/EVENT_COLLECTOR/UPSTREAM/CERTIFICATE/DISK，每 30 秒刷新。
- **存储容量**（`/storage`）：`GET /api/v1/system-health/storage`，数据目录、报告/备份目录与数据库容量，超阈值联动 DISK_SPACE_LOW / DATABASE_CAPACITY_HIGH 告警。
- **网关状态**（`/gateway-status`）：网关在线状态、当前版本/哈希、应用/域名/源站计数、最后发布结果（`GET /api/v1/gateway/status`）。系统管理员只读，发布操作属安全管理员。
- **系统告警**（`/system-alerts`）：系统管理员可查看全部告警并处置（确认 `POST /api/v1/system-alerts/{id}/acknowledge`、解决 `/resolve`、忽略 `/ignore`、备注 `/notes`）。处置流程见《运维手册》第 3 节。

## 6. 备份与恢复操作（`/backup-restore`）

### 6.1 备份

1. 新建备份：选择 FULL（全量）或 CONFIG_ONLY（仅配置），提交 `POST /api/v1/backups`。
2. 等待任务完成（后台 Worker 执行，列表轮询 `GET /api/v1/backups`）。
3. 执行验证：`POST /api/v1/backups/{id}/verify`，状态为已验证方可作为恢复依据。
4. 下载异地保管：`GET /api/v1/backups/{id}/download`（`.jzbk` 加密文件）。
5. 删除过期备份：`DELETE /api/v1/backups/{id}`。

命令行等价：`ops/backup/create.sh -t FULL -o /backup/dir`。

### 6.2 恢复（隔离恢复，人工确认）

1. 校验备份：`POST /api/v1/restores/validate`，确认备份完整与内容预览。
2. 创建隔离恢复：`POST /api/v1/restores`（scope：FULL/CONFIG/DATABASE/CERTIFICATE），系统在隔离区恢复，不触碰正式表。
3. 任务进入 AWAITING_CONFIRM 后人工核对，执行 `POST /api/v1/restores/{id}/confirm` 进入正式恢复（维护模式整组替换）；放弃则用 `POST /api/v1/restores/{id}/cancel`。
4. 恢复记录可在列表查询（`GET /api/v1/restores`）。

命令行引导：`ops/restore/restore.sh -b <backup-id> -s FULL`（逐步交互确认）。

## 7. 系统升级操作（`/system-upgrade`）

1. **升级前检查**：注册升级包后执行预检（`POST /api/v1/upgrade-packages/{id}/precheck`，检查数据库/Valkey 连通、数据目录、迁移文件）。
2. **执行升级**：`POST /api/v1/upgrades`。升级流程强制"先备份"：自动创建 FULL 备份并验证通过后切换镜像，数据库迁移随服务启动自动执行。
3. **验证**：升级后查运行监控全组件 UP、交付检查 PASS。
4. **回滚**：升级失败或验证不通过，`POST /api/v1/upgrades/{id}/rollback` 恢复旧镜像；必要时再恢复升级前备份。

命令行：`ops/upgrade/apply.sh --server-image jiuzhang-server:<新版本> --gateway-image jiuzhang-gateway:<新版本>`（自动预检+备份+切换+验证）；回滚用 `ops/upgrade/rollback.sh`（可选 `--restore-backup` 数据回滚，高风险需确认）。

升级记录（`GET /api/v1/upgrades`）与升级包列表（`GET /api/v1/upgrade-packages`）全程留痕，审计管理员只读可查。

## 8. 交付检查操作（`/delivery-check`）

1. 点击"执行检查"（`POST /api/v1/delivery-checks/run`），系统执行 22 项检查（运行状态/安全配置/账号权限/防护能力/合规交付/质量保障六类）。
2. 查看结果：整体 PASS / WARNING / FAIL。任一关键项 FAIL 即整体 FAIL，不得交付。
3. 历史记录 `GET /api/v1/delivery-checks`，详情 `GET /api/v1/delivery-checks/{id}`，导出 `GET /api/v1/delivery-checks/{id}/export`。
4. 逐项说明与 FAIL/WARNING 处置规则见《交付验收指南》。

## 9. 可信代理与保护地址（`/trusted-proxies`）

- 可信代理：新增 `POST /api/v1/trusted-proxies`，编辑 `PUT /api/v1/trusted-proxies/{id}`，删除 `DELETE /api/v1/trusted-proxies/{id}`，启停 `POST /api/v1/trusted-proxies/{id}/enable|disable`；配置代理地址与头类型（XFF/X-Real-IP/Forwarded/自定义头）；"命中测试"（`POST /api/v1/trusted-proxies/test`）验证链路真实 IP 识别。
- 保护地址 Tab：系统地址自动登记，手动刷新 `POST /api/v1/protected-addresses/refresh`；保护地址永不封禁（网关强制），删除仅允许非系统地址。
- 修改后由安全管理员发布生效（发布操作不在系统管理员权限内）。

## 10. 常见场景操作步骤

**场景 A：新员工入职开通安全管理员账号**
1. `/users` → 新建用户 → 角色选"安全管理员" → 保存。
2. 将系统生成的一次性密码线下告知本人；本人首次登录强制改密。

**场景 B：磁盘空间告警（DISK_SPACE_LOW）**
1. `/storage` 查看各目录占用 → 定位增长源（备份/报告/日志）。
2. `/backup-restore` 删除过期备份（确认异地已留存）。
3. 处理后到 `/system-alerts` 将该告警标记"解决"并备注处置动作。

**场景 C：季度恢复演练**
1. `ops/backup/create.sh -t FULL` 创建并验证备份。
2. `ops/restore/restore.sh -b <id> -s FULL` 按引导完成隔离恢复与确认。
3. 抽查业务数据；`/backup-restore` 恢复记录应出现 SUCCESS（支撑交付检查 restore_drill 项）。

**场景 D：版本升级**
1. 按第 7 节执行预检 → 升级 → 验证。
2. 升级失败执行 `ops/upgrade/rollback.sh`，再到 `/system-alerts` 处置 UPGRADE_FAILED 告警。

**场景 E：交付前自检**
1. `/delivery-check` 执行检查，逐项核对 FAIL/WARNING。
2. 处置后重跑至整体 PASS，导出结果归档（详见《交付验收指南》）。
