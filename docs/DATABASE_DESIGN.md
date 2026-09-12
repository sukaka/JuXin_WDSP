# 数据库设计文档

## 设计原则

1. PostgreSQL 作为主数据库；
2. 所有核心表使用 UUID 作为主键；
3. 时间统一使用 UTC 存储，前端按用户时区展示；
4. 所有业务表包含 `created_at` 和 `updated_at`；
5. 重要配置表保留版本；
6. 安全事件按月分区；
7. 不在数据库中保存明文私钥；
8. 不在普通字段保存完整敏感请求体；
9. 删除操作优先使用逻辑删除；
10. 审计日志不允许普通删除。

## 表结构

### 用户与权限

#### users

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID | 主键 |
| username | VARCHAR(64) | 用户名，唯一 |
| password_hash | VARCHAR(255) | 密码哈希 |
| display_name | VARCHAR(128) | 显示名称 |
| email | VARCHAR(255) | 邮箱 |
| status | VARCHAR(32) | 状态：active/disabled/locked |
| password_changed_at | TIMESTAMPTZ | 密码修改时间 |
| password_expires_at | TIMESTAMPTZ | 密码过期时间 |
| failed_login_count | INT | 连续失败次数 |
| locked_until | TIMESTAMPTZ | 锁定截止时间 |
| last_login_at | TIMESTAMPTZ | 最后登录时间 |
| created_at | TIMESTAMPTZ | 创建时间 |
| updated_at | TIMESTAMPTZ | 更新时间 |
| deleted_at | TIMESTAMPTZ | 删除时间（逻辑删除） |

#### roles

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID | 主键 |
| code | VARCHAR(64) | 角色编码，唯一 |
| name | VARCHAR(128) | 角色名称 |
| description | TEXT | 描述 |
| is_builtin | BOOLEAN | 是否内置 |
| created_at | TIMESTAMPTZ | 创建时间 |
| updated_at | TIMESTAMPTZ | 更新时间 |

#### permissions

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID | 主键 |
| code | VARCHAR(128) | 权限编码，唯一 |
| name | VARCHAR(128) | 权限名称 |
| module | VARCHAR(64) | 所属模块 |
| description | TEXT | 描述 |

#### user_roles

| 字段 | 类型 | 说明 |
|------|------|------|
| user_id | UUID | 用户 ID |
| role_id | UUID | 角色 ID |
| created_at | TIMESTAMPTZ | 创建时间 |

#### role_permissions

| 字段 | 类型 | 说明 |
|------|------|------|
| role_id | UUID | 角色 ID |
| permission_id | UUID | 权限 ID |
| created_at | TIMESTAMPTZ | 创建时间 |

#### login_sessions

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID | 主键 |
| user_id | UUID | 用户 ID |
| token_hash | VARCHAR(255) | 令牌哈希 |
| source_ip | INET | 来源 IP |
| user_agent | TEXT | 用户代理 |
| expires_at | TIMESTAMPTZ | 过期时间 |
| created_at | TIMESTAMPTZ | 创建时间 |
| revoked_at | TIMESTAMPTZ | 注销时间 |

#### login_logs

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID | 主键 |
| username | VARCHAR(64) | 用户名 |
| source_ip | INET | 来源 IP |
| user_agent | TEXT | 用户代理 |
| result | VARCHAR(32) | 结果：success/failure |
| failure_reason | VARCHAR(255) | 失败原因 |
| created_at | TIMESTAMPTZ | 创建时间 |

### 应用与源站

#### applications

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID | 主键 |
| code | VARCHAR(64) | 应用编码，唯一 |
| name | VARCHAR(128) | 应用名称 |
| description | TEXT | 业务描述 |
| listen_protocol | VARCHAR(16) | 监听协议：http/https |
| listen_port | INT | 监听端口 |
| status | VARCHAR(32) | 状态：enabled/disabled |
| protection_mode | VARCHAR(32) | 防护模式：off/detection_only/on |
| policy_id | UUID | 防护策略 ID |
| owner | VARCHAR(128) | 应用负责人 |
| tags | JSONB | 标签 |
| created_by | UUID | 创建人 |
| created_at | TIMESTAMPTZ | 创建时间 |
| updated_at | TIMESTAMPTZ | 更新时间 |
| deleted_at | TIMESTAMPTZ | 删除时间 |

#### application_domains

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID | 主键 |
| application_id | UUID | 应用 ID |
| domain | VARCHAR(255) | 域名 |
| is_primary | BOOLEAN | 是否主域名 |
| created_at | TIMESTAMPTZ | 创建时间 |

#### upstreams

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID | 主键 |
| application_id | UUID | 应用 ID |
| name | VARCHAR(128) | 源站名称 |
| scheme | VARCHAR(16) | 协议：http/https |
| host | VARCHAR(255) | 地址 |
| port | INT | 端口 |
| weight | INT | 权重 |
| health_check_path | VARCHAR(255) | 健康检查路径 |
| connect_timeout_ms | INT | 连接超时 |
| response_timeout_ms | INT | 响应超时 |
| tls_verify | BOOLEAN | 是否校验 HTTPS 证书 |
| sni | VARCHAR(255) | SNI 名称 |
| status | VARCHAR(32) | 状态：enabled/disabled |
| created_at | TIMESTAMPTZ | 创建时间 |
| updated_at | TIMESTAMPTZ | 更新时间 |

#### certificates

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID | 主键 |
| name | VARCHAR(128) | 证书名称 |
| cert_pem_encrypted | TEXT | 证书 PEM（加密存储） |
| key_pem_encrypted | TEXT | 私钥 PEM（加密存储） |
| subject | VARCHAR(255) | 主体 |
| issuer | VARCHAR(255) | 颁发者 |
| not_before | TIMESTAMPTZ | 生效时间 |
| not_after | TIMESTAMPTZ | 过期时间 |
| serial_number | VARCHAR(128) | 序列号 |
| created_at | TIMESTAMPTZ | 创建时间 |
| updated_at | TIMESTAMPTZ | 更新时间 |
| deleted_at | TIMESTAMPTZ | 删除时间 |

#### application_certificates

| 字段 | 类型 | 说明 |
|------|------|------|
| application_id | UUID | 应用 ID |
| certificate_id | UUID | 证书 ID |
| created_at | TIMESTAMPTZ | 创建时间 |

### 防护策略

#### protection_policies

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID | 主键 |
| name | VARCHAR(128) | 策略名称 |
| description | TEXT | 描述 |
| mode | VARCHAR(32) | 防护模式 |
| inbound_anomaly_threshold | INT | 入站异常阈值 |
| outbound_anomaly_threshold | INT | 出站异常阈值 |
| paranoia_level | INT | CRS 执行等级 |
| inspect_request_body | BOOLEAN | 请求体检查 |
| inspect_response_body | BOOLEAN | 响应体检查 |
| max_request_body_size | BIGINT | 最大请求体 |
| allowed_file_extensions | JSONB | 允许的文件扩展名 |
| enable_xml | BOOLEAN | XML 解析 |
| enable_json | BOOLEAN | JSON 解析 |
| block_status_code | INT | 阻断状态码 |
| block_page_html | TEXT | 阻断页面 |
| rule_category_switches | JSONB | 规则分类开关 |
| log_matched_data | BOOLEAN | 记录匹配数据 |
| enable_custom_rules | BOOLEAN | 启用自定义规则 |
| enable_exceptions | BOOLEAN | 启用例外策略 |
| is_builtin | BOOLEAN | 是否内置 |
| created_at | TIMESTAMPTZ | 创建时间 |
| updated_at | TIMESTAMPTZ | 更新时间 |

#### waf_rules

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID | 主键 |
| rule_id | INT | 规则 ID |
| name | VARCHAR(255) | 规则名称 |
| source | VARCHAR(32) | 来源：crs/jiuzhang/custom |
| attack_type | VARCHAR(64) | 攻击类型 |
| severity | VARCHAR(32) | 风险等级 |
| phase | INT | 执行阶段 |
| tags | JSONB | 标签 |
| default_enabled | BOOLEAN | 默认状态 |
| current_enabled | BOOLEAN | 当前状态 |
| version | VARCHAR(32) | 规则版本 |
| description | TEXT | 规则说明 |
| created_at | TIMESTAMPTZ | 创建时间 |
| updated_at | TIMESTAMPTZ | 更新时间 |

#### rule_overrides

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID | 主键 |
| rule_id | INT | 规则 ID |
| application_id | UUID | 应用 ID（NULL 表示全局） |
| enabled | BOOLEAN | 是否启用 |
| severity_override | VARCHAR(32) | 风险等级覆盖 |
| created_at | TIMESTAMPTZ | 创建时间 |
| updated_at | TIMESTAMPTZ | 更新时间 |

#### custom_rules

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID | 主键 |
| name | VARCHAR(128) | 规则名称 |
| rule_text | TEXT | SecLang 规则文本 |
| enabled | BOOLEAN | 是否启用 |
| created_by | UUID | 创建人 |
| created_at | TIMESTAMPTZ | 创建时间 |
| updated_at | TIMESTAMPTZ | 更新时间 |

#### exception_policies

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID | 主键 |
| name | VARCHAR(128) | 例外名称 |
| application_id | UUID | 应用 ID |
| domain | VARCHAR(255) | 域名 |
| uri | VARCHAR(512) | URI |
| uri_prefix | VARCHAR(512) | URI 前缀 |
| method | VARCHAR(16) | 请求方法 |
| param_name | VARCHAR(128) | 参数名称 |
| cookie_name | VARCHAR(128) | Cookie 名称 |
| header_name | VARCHAR(128) | 请求头名称 |
| rule_id | INT | 规则 ID |
| rule_tag | VARCHAR(128) | 规则标签 |
| source_ip | INET | 来源 IP |
| effective_at | TIMESTAMPTZ | 生效时间 |
| expires_at | TIMESTAMPTZ | 失效时间 |
| status | VARCHAR(32) | 状态 |
| reason | TEXT | 申请原因 |
| risk_note | TEXT | 风险说明 |
| created_by | UUID | 创建人 |
| approved_by | UUID | 审核人 |
| created_at | TIMESTAMPTZ | 创建时间 |
| updated_at | TIMESTAMPTZ | 更新时间 |

#### ip_access_rules

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID | 主键 |
| rule_type | VARCHAR(32) | 类型：whitelist/blacklist |
| scope | VARCHAR(32) | 范围：global/application |
| application_id | UUID | 应用 ID |
| ip_address | INET | IP 地址 |
| cidr | CIDR | CIDR 网段 |
| expires_at | TIMESTAMPTZ | 失效时间 |
| note | TEXT | 备注 |
| source | VARCHAR(64) | 来源 |
| created_by | UUID | 创建人 |
| created_at | TIMESTAMPTZ | 创建时间 |
| updated_at | TIMESTAMPTZ | 更新时间 |

#### rate_limit_policies

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID | 主键 |
| name | VARCHAR(128) | 策略名称 |
| application_id | UUID | 应用 ID |
| target_type | VARCHAR(32) | 目标类型：ip/application/uri |
| target_value | VARCHAR(512) | 目标值 |
| requests_per_second | INT | 每秒请求数 |
| window_seconds | INT | 时间窗口 |
| window_requests | INT | 窗口请求数 |
| burst_capacity | INT | 突发容量 |
| block_duration_seconds | INT | 临时封禁时间 |
| whitelist_ips | JSONB | 白名单 |
| mode | VARCHAR(32) | 模式：detection_only/on |
| status_code | INT | 响应状态码 |
| block_page_html | TEXT | 阻断页面 |
| enabled | BOOLEAN | 是否启用 |
| created_at | TIMESTAMPTZ | 创建时间 |
| updated_at | TIMESTAMPTZ | 更新时间 |

### 安全事件

#### security_events（按月分区）

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID | 主键 |
| request_id | VARCHAR(64) | 请求 ID |
| occurred_at | TIMESTAMPTZ | 发生时间 |
| application_id | UUID | 应用 ID |
| domain | VARCHAR(255) | 域名 |
| client_ip | INET | 客户端 IP |
| client_port | INT | 客户端端口 |
| method | VARCHAR(16) | 请求方法 |
| uri | VARCHAR(2048) | URI |
| query_summary | TEXT | 查询参数摘要 |
| user_agent | TEXT | User-Agent |
| referer | TEXT | Referer |
| http_version | VARCHAR(16) | HTTP 版本 |
| attack_type | VARCHAR(64) | 攻击类型 |
| rule_id | INT | 规则 ID |
| rule_name | VARCHAR(255) | 规则名称 |
| rule_tags | JSONB | 规则标签 |
| severity | VARCHAR(32) | 风险等级 |
| anomaly_score | INT | 异常评分 |
| action | VARCHAR(32) | 防护动作 |
| status_code | INT | 响应状态码 |
| gateway_node_id | UUID | 网关节点 ID |
| disposition_status | VARCHAR(32) | 处置状态 |
| disposition_by | UUID | 处置人 |
| disposition_note | TEXT | 处置说明 |
| raw_log_reference | TEXT | 原始日志引用 |
| created_at | TIMESTAMPTZ | 创建时间 |

#### security_event_matches

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID | 主键 |
| event_id | UUID | 事件 ID |
| rule_id | INT | 规则 ID |
| rule_name | VARCHAR(255) | 规则名称 |
| severity | VARCHAR(32) | 风险等级 |
| message | TEXT | 匹配消息 |
| matched_variable | VARCHAR(255) | 匹配变量 |
| matched_data_masked | TEXT | 匹配数据（脱敏） |
| tags | JSONB | 标签 |
| created_at | TIMESTAMPTZ | 创建时间 |

#### security_event_actions

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID | 主键 |
| event_id | UUID | 事件 ID |
| action_type | VARCHAR(64) | 动作类型 |
| operator_id | UUID | 操作人 |
| note | TEXT | 说明 |
| created_at | TIMESTAMPTZ | 创建时间 |

#### security_event_notes

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID | 主键 |
| event_id | UUID | 事件 ID |
| user_id | UUID | 用户 ID |
| note | TEXT | 备注 |
| created_at | TIMESTAMPTZ | 创建时间 |

#### event_daily_statistics

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID | 主键 |
| stat_date | DATE | 统计日期 |
| application_id | UUID | 应用 ID |
| total_requests | BIGINT | 总请求数 |
| attack_events | BIGINT | 攻击事件数 |
| blocked_events | BIGINT | 阻断事件数 |
| detected_events | BIGINT | 观察事件数 |
| high_risk_events | BIGINT | 高危事件数 |
| attack_type_stats | JSONB | 攻击类型统计 |
| source_ip_stats | JSONB | 攻击源统计 |
| created_at | TIMESTAMPTZ | 创建时间 |

### 配置管理

#### gateway_nodes

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID | 主键 |
| name | VARCHAR(128) | 节点名称 |
| address | VARCHAR(255) | 节点地址 |
| status | VARCHAR(32) | 状态 |
| version | VARCHAR(64) | 版本 |
| last_seen_at | TIMESTAMPTZ | 最后在线时间 |
| created_at | TIMESTAMPTZ | 创建时间 |
| updated_at | TIMESTAMPTZ | 更新时间 |

#### gateway_config_versions

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID | 主键 |
| version | VARCHAR(64) | 版本号 |
| config_hash | VARCHAR(128) | 配置哈希 |
| summary | TEXT | 配置摘要 |
| created_by | UUID | 创建人 |
| created_at | TIMESTAMPTZ | 创建时间 |
| published_by | UUID | 发布人 |
| published_at | TIMESTAMPTZ | 发布时间 |
| publish_result | VARCHAR(32) | 发布结果 |
| applications | JSONB | 关联应用 |
| change_note | TEXT | 变更说明 |
| raw_config | TEXT | 原始配置 |
| structured_config | JSONB | 结构化配置 |
| previous_version_id | UUID | 上一版本 ID |
| is_current | BOOLEAN | 是否当前生效 |

#### gateway_publish_tasks

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID | 主键 |
| version_id | UUID | 版本 ID |
| status | VARCHAR(32) | 状态 |
| stage | VARCHAR(64) | 当前阶段 |
| error_message | TEXT | 错误信息 |
| started_at | TIMESTAMPTZ | 开始时间 |
| finished_at | TIMESTAMPTZ | 完成时间 |
| created_at | TIMESTAMPTZ | 创建时间 |

#### gateway_health_records

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID | 主键 |
| node_id | UUID | 节点 ID |
| status | VARCHAR(32) | 状态 |
| details | JSONB | 详情 |
| checked_at | TIMESTAMPTZ | 检查时间 |

#### system_settings

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID | 主键 |
| key | VARCHAR(128) | 配置键 |
| value | JSONB | 配置值 |
| description | TEXT | 描述 |
| updated_by | UUID | 更新人 |
| updated_at | TIMESTAMPTZ | 更新时间 |

### 审计和报告

#### operation_audits

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID | 主键 |
| occurred_at | TIMESTAMPTZ | 发生时间 |
| user_id | UUID | 用户 ID |
| username | VARCHAR(64) | 用户名 |
| source_ip | INET | 来源 IP |
| user_agent | TEXT | 用户代理 |
| module | VARCHAR(64) | 操作模块 |
| action | VARCHAR(64) | 操作类型 |
| object_type | VARCHAR(64) | 对象类型 |
| object_id | VARCHAR(64) | 对象 ID |
| before_summary | TEXT | 操作前摘要 |
| after_summary | TEXT | 操作后摘要 |
| result | VARCHAR(32) | 操作结果 |
| failure_reason | TEXT | 失败原因 |
| request_id | VARCHAR(64) | 请求 ID |

#### report_tasks

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID | 主键 |
| name | VARCHAR(128) | 报表名称 |
| report_type | VARCHAR(32) | 类型：daily/weekly/monthly/custom |
| application_id | UUID | 应用 ID（NULL 表示全局） |
| start_time | TIMESTAMPTZ | 开始时间 |
| end_time | TIMESTAMPTZ | 结束时间 |
| status | VARCHAR(32) | 状态 |
| created_by | UUID | 创建人 |
| created_at | TIMESTAMPTZ | 创建时间 |
| finished_at | TIMESTAMPTZ | 完成时间 |

#### report_files

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID | 主键 |
| task_id | UUID | 任务 ID |
| file_name | VARCHAR(255) | 文件名 |
| file_path | VARCHAR(512) | 文件路径 |
| file_size | BIGINT | 文件大小 |
| format | VARCHAR(16) | 格式：html/pdf |
| created_at | TIMESTAMPTZ | 创建时间 |

#### backup_records

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID | 主键 |
| file_name | VARCHAR(255) | 文件名 |
| file_path | VARCHAR(512) | 文件路径 |
| file_size | BIGINT | 文件大小 |
| backup_type | VARCHAR(32) | 备份类型 |
| status | VARCHAR(32) | 状态 |
| created_by | UUID | 创建人 |
| created_at | TIMESTAMPTZ | 创建时间 |

## 索引设计

待阶段2补充详细索引。

## 分区策略

`security_events` 表按 `occurred_at` 字段进行月分区，分区命名格式：`security_events_YYYYMM`。

## 数据保留

- 安全事件：180 天
- 操作审计：365 天
- 登录日志：180 天
- 配置版本：永久保留或管理员归档
- 报表文件：365 天
