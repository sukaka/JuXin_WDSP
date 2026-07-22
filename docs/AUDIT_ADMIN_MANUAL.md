# 九章WAF 审计管理员手册

适用角色：审计管理员（AUDIT_ADMIN）
版本：九章WEB应用智能防护系统 V2.0（阶段6 交付版）

## 1. 职责定位

审计管理员是独立监督角色：**全局只读 + 处置类统计**，不修改任何业务配置与防护策略。核心职责：

- 审查登录行为与账号安全（登录日志）；
- 审查全部操作审计，定期验证审计哈希链完整性；
- 查看角色权限配置，核对三权分立执行情况；
- 查看处置统计态势，监督事件与告警处置闭环；
- 只读查看安全事件、访问控制事件、防护策略与配置版本；
- 只读查看并下载安全报告；
- 只读查看系统告警、备份/恢复/升级记录、交付检查结果；
- 导出审计数据用于合规留档。

**不可做**：创建/修改/删除任何业务对象；处置安全事件与系统告警；管理用户；执行发布、备份、升级、交付检查。对应写操作 API 一律返回 403。

登录后可见菜单：工作台、应用防护 → 配置版本（`/config-versions`）、WAF 策略（防护策略 `/protection-policies`、WAF 规则 `/waf-rules`、例外策略 `/exceptions`）、访问控制（可信代理 `/trusted-proxies`、IP 黑白名单 `/access-rules`、CC 防护 `/rate-limit`、临时封禁 `/temporary-blocks`、访问控制事件 `/access-control-events`）、事件中心（安全事件 `/security-events`、事件统计 `/event-statistics`）、安全态势（统计分析 `/analytics`、系统告警 `/system-alerts`）、报表中心（报告任务 `/reports`、报告归档 `/report-archives`）、系统运维 → 交付检查（`/delivery-check`）、角色权限（`/roles`）、登录日志（`/login-logs`）、操作审计（`/audits`）、个人中心。上述业务菜单均为只读视图。

## 2. 登录日志（`/login-logs`）

- 查看全部登录日志：`GET /api/v1/login-logs`，覆盖 16 类事件（登录成功/失败、锁定、改密、会话下线等），支持按用户/时间/结果筛选。
- 导出：`GET /api/v1/login-logs/export`（限速 5 次/分钟）。
- 日志不记录密码、验证码与完整会话标识，仅记录脱敏信息。
- 审查要点：频繁失败/锁定（暴力破解迹象）、非常用来源 IP、非工作时间登录、被强制下线账号的后续行为。

## 3. 操作审计（`/audits`）

### 3.1 审计查看

- 列表：`GET /api/v1/audits`，按操作人/模块/动作/风险等级/时间筛选；详情 `GET /api/v1/audits/{id}`。
- 审计记录含：操作人、角色、动作、对象、风险分级、来源 IP、Request ID；敏感字段（密码、私钥等）已脱敏。
- 导出：`GET /api/v1/audits/export`。

### 3.2 哈希链验证

- 操作：审计页"验证哈希链"按钮，或 `POST /api/v1/audits/verify-chain`。
- 机制：每条审计记录包含前序哈希，数据库 RULE 禁止 UPDATE/DELETE，形成防篡改链。
- 频次：每周至少 1 次，交付前必做（交付检查 audit_chain 为关键项，不一致即 FAIL 且产生 AUDIT_INTEGRITY_FAILED 告警）。
- 处置：验证不一致时**立即保全现场**，禁止任何删表尝试，通报安全负责人与系统管理员取证；不一致记录 ID 会在结果中返回。

### 3.3 审查要点

- 高风险操作：用户删除、重置密码、强制下线、备份删除、正式恢复 confirm、升级执行/回滚、宽泛例外创建、保护地址变更。
- 越权迹象：某角色频繁出现 403 记录；非工作时段的发布/导出操作。
- 配置轨迹：策略、黑白名单、CC 策略的增删改与发布记录是否一一对应变更单。

## 4. 角色权限查看（`/roles`）

- 查看三权角色及权限映射：`GET /api/v1/roles`、`GET /api/v1/roles/{id}/permissions`；权限清单 `GET /api/v1/permissions`。
- 核对内容：三权互斥（一账号一角色）是否保持；是否存在越权赋权；系统管理员账号是否仅限运维权限。
- 角色为内置三权（SYSTEM_ADMIN/SECURITY_ADMIN/AUDIT_ADMIN），不可自定义；审计管理员仅能查看，不能调整。

## 5. 处置统计态势

- **工作台**（`/dashboard`）：审计视角态势 `GET /api/v1/dashboard/audit-overview`，展示事件处置与审计相关统计。
- **统计分析 → 处置统计**（`/analytics`）：`GET /api/v1/analytics/disposition-overview`，事件确认攻击/误报/忽略/解决的数量与时效分布。
- 监督要点：未处置事件积压、误报率异常（提示策略质量问题）、处置时长超 SLA。

## 6. 事件与报告只读

### 6.1 安全事件与访问控制事件（只读）

- 安全事件：`GET /api/v1/security-events`、`GET /api/v1/security-events/{id}`、`GET /api/v1/security-events/{id}/related`、导出 `GET /api/v1/security-events/export`；事件统计见 `/event-statistics`。
- 访问控制事件：`GET /api/v1/access-control-events`、`GET /api/v1/access-control-events/{id}`、导出 `GET /api/v1/access-control-events/export`。
- 审计管理员不能执行处置动作（确认/忽略/解决等接口返回 403），通过处置统计监督处置质量。

### 6.2 报告只读与下载（`/reports`、`/report-archives`）

- 报告任务列表 `GET /api/v1/reports`、详情 `GET /api/v1/reports/{id}`、预览 `GET /api/v1/reports/{id}/preview`。
- 下载：`GET /api/v1/reports/{id}/download`（审计专用下载权限，与安全管理员下载通道并列）。
- 归档检索：`GET /api/v1/report-archives`。
- 不能创建/重试/删除报告，不能管理模板。

## 7. 系统告警与运维记录只读

- **系统告警**（`/system-alerts`）：`GET /api/v1/system-alerts`、`GET /api/v1/system-alerts/{id}`。只读查看，确认/解决/忽略操作不可用；通过告警备注与状态变化监督处置时效。
- **备份/恢复记录**：`GET /api/v1/backups`、`GET /api/v1/restores` 只读（核对备份是否按策略执行、验证是否通过、恢复演练是否开展）。
- **升级记录**：`GET /api/v1/upgrades`、`GET /api/v1/upgrade-packages` 只读（核对升级是否先备份、失败是否回滚）。
- **交付检查**（`/delivery-check`）：`GET /api/v1/delivery-checks`、`GET /api/v1/delivery-checks/{id}`、导出 `GET /api/v1/delivery-checks/{id}/export`。只读查看，不能执行检查（`delivery_checks.run` 属系统管理员）。

## 8. 审计导出与留档

| 数据 | API | 说明 |
|------|-----|------|
| 登录日志 | `GET /api/v1/login-logs/export` | CSV，限速 5 次/分钟 |
| 操作审计 | `GET /api/v1/audits/export` | CSV，限速 5 次/分钟 |
| 安全事件 | `GET /api/v1/security-events/export` | CSV，敏感参数已遮蔽 |
| 访问控制事件 | `GET /api/v1/access-control-events/export` | CSV |
| 交付检查结果 | `GET /api/v1/delivery-checks/{id}/export` | 检查报告 |
| 安全报告 | `GET /api/v1/reports/{id}/download` | PDF |

留档建议：每月导出一次登录日志与操作审计，与哈希链验证结果一并归档；导出文件按内部密级管理，禁止外传。

## 9. 例行审计计划（建议）

- **每日**：登录日志异常筛查；系统告警未处置项复核。
- **每周**：哈希链验证；高风险操作审计复核；事件处置时效统计核对。
- **每月**：角色权限配置核对；审计数据导出归档；备份/演练/升级记录合规核对。
- **交付/大版本前**：全程监督交付检查执行，核对 22 项结果与整改闭环（见《交付验收指南》）。
