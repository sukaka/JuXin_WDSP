# 九章WEB应用智能防护系统V2.0
## 阶段6：安全态势、统计报表、运行监控与正式交付任务书

## 一、阶段目标

阶段6将阶段1至阶段5形成的网关、身份认证、应用接入、WAF、事件中心、访问控制和CC能力整合为可正式交付、可持续运维的产品版本。

本阶段完成后，系统应能够：

1. 提供统一安全态势首页；
2. 对访问流量、WAF事件、CC事件和访问控制事件进行统计分析；
3. 展示攻击趋势、风险等级、攻击类型、来源IP、应用风险和规则命中；
4. 提供日报、周报、月报和自定义报告；
5. 支持报告预览、生成、下载和归档；
6. 监控网关、管理API、数据库、Valkey、采集器、解析器和报告服务；
7. 监控应用、源站、证书、策略、日志和存储容量；
8. 提供系统告警、确认、处置和恢复；
9. 提供配置、数据库、证书、策略和审计数据备份；
10. 提供备份校验、隔离恢复和灾难恢复流程；
11. 提供系统升级、升级前检查、数据库迁移和失败回滚；
12. 提供离线部署包、安装向导和正式交付检查；
13. 生成第三方组件清单、许可证归档和SBOM；
14. 完成稳定性、容量、故障恢复、安全和交付验收测试；
15. 形成九章WEB应用智能防护系统V2.0首个正式交付版本。

完整闭环：

```text
阶段1至阶段5安全能力
  ↓
统一指标采集和数据聚合
  ↓
安全态势首页
  ↓
趋势、排行和风险分析
  ↓
日报、周报和月报
  ↓
系统运行监控和告警
  ↓
管理员处置异常
  ↓
备份、恢复和升级
  ↓
离线安装和正式交付
```

---

## 二、阶段边界

### 2.1 必须开发

- 安全态势首页；
- 统一指标模型；
- 请求趋势；
- 攻击趋势；
- 风险等级统计；
- 攻击类型统计；
- 应用风险排行；
- 攻击源IP排行；
- 规则命中排行；
- URI排行；
- CC排行；
- 黑名单命中排行；
- 事件处置统计；
- 策略运行状态；
- 网关运行状态；
- 源站健康状态；
- 证书到期状态；
- 事件采集延迟；
- 事件解析失败统计；
- PostgreSQL和Valkey状态；
- 磁盘和存储容量；
- 系统告警；
- 告警确认和关闭；
- 日报；
- 周报；
- 月报；
- 自定义时间报告；
- 报告模板；
- 报告任务；
- 报告预览和归档；
- HTML和PDF导出；
- 配置备份；
- 数据库备份；
- 证书和私钥加密备份；
- 策略和审计备份；
- 备份验证；
- 隔离恢复；
- 全系统恢复；
- 灾难恢复文档；
- 系统升级包；
- 升级前检查；
- 数据库迁移检查；
- 升级失败回滚；
- 离线安装包；
- 初始化向导；
- 正式交付检查；
- 运维手册；
- 三权管理员手册；
- 第三方许可证；
- SBOM；
- 稳定性、容量、恢复、安全和交付验收测试。

### 2.2 暂不开发

- AI自动研判；
- AI自动生成报告结论；
- AI自动修改策略；
- 多Agent协同；
- Bot挑战；
- 云威胁情报；
- SaaS多租户；
- 云端统一管理；
- 多网关集群控制平面；
- 跨地域容灾；
- 全局流量调度；
- 商业计费；
- 手机App。

这些能力建议进入后续V3.0或更高版本。

---

## 三、前置条件

开始阶段6前必须确认：

1. 阶段1网关构建、Coraza和CRS稳定；
2. 阶段2身份认证、会话、三权和审计稳定；
3. 阶段3应用、源站、证书、发布和回滚稳定；
4. 阶段4WAF策略、事件采集、解析和处置稳定；
5. 阶段5真实IP、黑白名单、CC和临时封禁稳定；
6. 所有阶段测试报告已归档；
7. 所有重大和高危遗留问题已关闭；
8. 数据库迁移可重复执行和回滚；
9. 配置版本、策略版本和访问控制版本可查询；
10. 所有关键操作均有审计；
11. Docker Compose可一键启动和停止；
12. 第三方组件版本和许可证已锁定。

不得通过阶段6页面掩盖前面阶段未完成功能。

---

## 四、总体架构

```text
网关、管理API、事件采集器、事件解析器
    │
    ├── 访问指标
    ├── WAF事件
    ├── CC事件
    ├── 访问控制事件
    ├── 运行指标
    ├── 健康检查
    └── 审计记录
            │
            ▼
       指标聚合服务
            │
            ├── PostgreSQL
            ├── Valkey
            └── 报告文件存储
            │
            ▼
    安全态势与报告服务
    ├── 态势首页
    ├── 统计分析
    ├── 报告生成
    ├── 系统告警
    ├── 备份恢复
    ├── 系统升级
    └── 正式交付检查
```

建议目录：

```text
server/internal/
├── dashboards/
├── metrics/
├── aggregations/
├── reports/
├── reporttemplates/
├── reportjobs/
├── systemalerts/
├── runtimehealth/
├── backups/
├── restores/
├── upgrades/
├── delivery/
└── compliance/

web/src/pages/
├── security-overview/
├── analytics/
├── reports/
├── system-monitoring/
├── system-alerts/
├── backup-restore/
├── system-upgrade/
└── delivery-check/

ops/
├── install/
├── upgrade/
├── backup/
├── restore/
├── healthcheck/
├── diagnostics/
└── offline-package/
```

---

## 五、统一指标模型

### 5.1 指标来源

至少采集：

- Caddy访问日志；
- Coraza安全事件；
- 访问控制事件；
- CC事件；
- 网关运行指标；
- 管理API运行指标；
- PostgreSQL健康和容量；
- Valkey健康和容量；
- 事件采集器；
- 事件解析器；
- 源站健康检查；
- 证书状态；
- 配置发布任务；
- 报告任务；
- 备份任务；
- 升级任务；
- 系统审计。

### 5.2 指标原则

- UTC存储，按系统时区展示；
- 指标名称固定；
- 标签维度受控；
- 不允许完整URI参数作为标签；
- 不允许用户输入直接作为指标名称；
- 指标中不得保存密码、Token、Cookie或攻击载荷；
- 原始事件与聚合指标分离；
- 聚合指标可重新生成；
- 不以管理前端统计结果作为可信数据源。

### 5.3 时间粒度

支持：

```text
1分钟
5分钟
1小时
1天
```

短期页面可查询分钟聚合，长期趋势使用小时和天聚合，避免每次扫描全部原始事件。

### 5.4 指标命名示例

```text
http_requests_total
http_request_duration_ms
waf_events_total
waf_blocks_total
cc_threshold_exceeded_total
ip_deny_matches_total
security_events_unprocessed
event_collector_lag_seconds
event_parse_failures_total
gateway_up
upstream_healthy
certificate_days_remaining
database_size_bytes
disk_free_bytes
```

---

## 六、安全态势首页

### 6.1 总览卡片

至少展示：

- 今日请求总数；
- 今日安全事件；
- 今日阻断；
- 今日观察事件；
- 今日CC超限；
- 今日黑名单命中；
- 当前临时封禁IP；
- 未处置高危事件；
- 受保护应用数；
- 异常应用数；
- 异常源站数；
- 即将到期证书数。

### 6.2 趋势

- 请求趋势；
- 安全事件趋势；
- 阻断趋势；
- 风险等级趋势；
- CC趋势；
- 黑名单命中趋势；
- 事件处置趋势。

时间范围：

```text
最近1小时
最近24小时
最近7天
最近30天
自定义
```

### 6.3 排行

- 攻击类型排行；
- 攻击源IP排行；
- 被攻击应用排行；
- 被攻击URI排行；
- 命中规则排行；
- CC触发IP排行；
- CC触发URI排行；
- 黑名单命中排行；
- 误报规则排行；
- 未处置事件排行。

### 6.4 风险提示

展示：

- 高危未处置事件；
- 策略发布失败；
- 网关异常；
- 采集器积压；
- 解析失败；
- 源站不可用；
- 证书即将到期；
- 数据库容量高；
- Valkey异常；
- 备份失败；
- 升级失败；
- 审计完整性失败。

### 6.5 权限差异

安全管理员查看完整安全态势；系统管理员查看运行和容量；审计管理员查看审计、处置和变更统计。

不得让系统管理员默认查看完整攻击载荷，也不得让安全管理员执行系统升级。

---

## 七、统计分析

### 7.1 请求统计

- 请求总量；
- 成功率；
- 4xx和5xx；
- 平均响应时间；
- P50、P95、P99；
- 应用请求排行；
- 域名请求排行；
- 源站状态；
- 请求方法分布；
- Content-Type分布。

### 7.2 WAF统计

- 安全事件数；
- 阻断数；
- 观察数；
- 风险等级；
- 攻击类型；
- 规则命中；
- 异常评分；
- 应用风险；
- 误报数和误报率；
- 事件平均处置时长。

### 7.3 CC和访问控制统计

- CC触发；
- 429；
- 临时封禁；
- 自动解封；
- 白名单命中；
- 黑名单命中；
- 全局和应用规则分布；
- 可信代理IP来源；
- 非法代理头；
- 保护地址拦截。

### 7.4 运行统计

- 网关运行时间；
- 管理API可用性；
- PostgreSQL连接和容量；
- Valkey连接和内存；
- 采集延迟；
- 解析失败率；
- 发布成功率；
- 发布耗时；
- 报告成功率；
- 备份成功率；
- 升级成功率。

---

## 八、数据聚合任务

### 8.1 周期

- 每分钟聚合实时指标；
- 每5分钟聚合短期趋势；
- 每小时聚合长期趋势；
- 每天生成日统计。

### 8.2 幂等和修正

聚合任务必须：

- 使用明确时间窗口；
- 支持重复执行；
- 不产生重复数据；
- 支持迟到事件修正；
- 记录任务状态；
- 失败可重试；
- 单应用异常不阻塞全部任务；
- 有最大重试次数和错误队列。

### 8.3 数据表

建议新增：

```text
metric_minute_aggregates
metric_hour_aggregates
metric_daily_aggregates
application_security_summaries
rule_hit_summaries
source_ip_summaries
uri_security_summaries
system_health_snapshots
aggregation_jobs
```

---

## 九、报告系统

### 9.1 报告类型

```text
DAILY
WEEKLY
MONTHLY
CUSTOM
INCIDENT
```

阶段6必须完成日报、周报、月报和自定义时间报告。

### 9.2 报告结构

至少包括：

1. 封面；
2. 报告周期；
3. 应用范围；
4. 管理摘要；
5. 请求流量；
6. 安全事件总览；
7. 风险等级；
8. 攻击类型；
9. 攻击趋势；
10. 攻击源IP；
11. 被攻击应用；
12. 命中规则；
13. CC防护；
14. 黑白名单；
15. 事件处置；
16. 误报和例外；
17. 源站健康；
18. 证书状态；
19. 策略发布；
20. 系统运行；
21. 结论和建议。

结论和建议使用确定性模板和规则生成，不使用AI自动判断。

### 9.3 报告模板

支持：

- 企业名称；
- 产品名称；
- Logo；
- 页眉页脚；
- 报告编号；
- 编制人；
- 审核人；
- 日期；
- 报告说明；
- 章节显示或隐藏。

模板不得执行任意代码、脚本和外部请求。

### 9.4 报告任务

状态：

```text
PENDING
COLLECTING
AGGREGATING
RENDERING
SUCCESS
FAILED
CANCELLED
```

字段：

```text
id
report_type
time_range_start
time_range_end
application_ids
template_id
status
progress
requested_by
requested_at
started_at
finished_at
file_reference
file_hash
failure_code
failure_message
request_id
```

### 9.5 导出

至少支持HTML和PDF。DOCX可作为增强项。

报告文件必须：

- 有权限；
- 有下载审计；
- 有哈希；
- 有保留期限；
- 不包含未脱敏攻击载荷；
- 防路径穿越；
- 防任意文件下载；
- 防HTML和PDF渲染SSRF；
- 限制文件大小和生成时长。

---

## 十、系统运行监控

### 10.1 组件

监控：

- Caddy网关；
- Coraza；
- jiuzhang_guard；
- 管理API；
- 管理前端；
- PostgreSQL；
- Valkey；
- 事件采集器；
- 事件解析器；
- 报告服务；
- 备份服务；
- 配置发布控制器。

### 10.2 指标

- 进程状态；
- 启动时间；
- CPU；
- 内存；
- 磁盘；
- 文件句柄；
- 请求数；
- 错误率；
- 响应时间；
- 数据库连接池；
- Valkey连接；
- 事件队列长度；
- 采集延迟；
- 解析失败；
- 配置版本；
- 最后成功任务时间。

### 10.3 应用和源站

- 应用可访问性；
- HTTP状态；
- TLS握手；
- 证书剩余天数；
- 源站健康；
- 源站响应时间；
- 连续失败；
- 域名监听；
- 配置哈希一致性。

### 10.4 存储

- PostgreSQL容量；
- 事件分区大小；
- 报告大小；
- 原始日志大小；
- 配置版本大小；
- 备份大小；
- 磁盘剩余；
- 数据保留清理任务。

---

## 十一、系统告警

### 11.1 类型

```text
GATEWAY_DOWN
MANAGEMENT_API_DOWN
DATABASE_UNAVAILABLE
VALKEY_UNAVAILABLE
EVENT_COLLECTOR_LAG
EVENT_PARSE_FAILURE_RATE_HIGH
SOURCE_UNHEALTHY
CERTIFICATE_EXPIRING
CERTIFICATE_EXPIRED
CONFIG_PUBLISH_FAILED
CONFIG_HASH_MISMATCH
DISK_SPACE_LOW
DATABASE_CAPACITY_HIGH
BACKUP_FAILED
RESTORE_VALIDATION_FAILED
REPORT_FAILED
UPGRADE_FAILED
AUDIT_INTEGRITY_FAILED
```

### 11.2 等级

```text
CRITICAL
HIGH
MEDIUM
LOW
INFO
```

### 11.3 状态

```text
OPEN
ACKNOWLEDGED
RESOLVED
IGNORED
```

### 11.4 操作

- 查看；
- 确认；
- 添加备注；
- 标记已解决；
- 忽略；
- 查看关联组件；
- 查看关联事件；
- 查看关联审计；
- 导出。

阶段6至少完成平台内告警。外部邮件、短信或企业微信作为增强项。

### 11.5 告警抑制

支持：

- 相同组件同类告警合并；
- 抖动抑制；
- 恢复通知；
- 维护窗口；
- 重复告警冷却；
- 最大未关闭告警数量保护。

---

## 十二、备份设计

### 12.1 备份范围

必须覆盖：

- PostgreSQL业务数据；
- 用户、权限和系统设置；
- 应用、域名和源站；
- 证书元数据；
- 加密后的证书和私钥；
- WAF策略；
- 规则覆盖；
- 自定义规则；
- 例外；
- 黑白名单；
- CC策略；
- 配置版本；
- 审计记录；
- 报告模板；
- 当前有效网关配置。

原始访问日志和全部报告文件是否备份可配置。

### 12.2 类型

```text
FULL
INCREMENTAL
CONFIG_ONLY
DATABASE_ONLY
CERTIFICATE_ONLY
```

阶段6至少实现全量备份和配置备份。

### 12.3 安全要求

- 备份加密；
- 生成清单；
- 文件哈希；
- 最小访问权限；
- 主密钥和加密数据不得放在同一未保护位置；
- 日志不打印备份密码；
- 防路径穿越；
- 防任意目录备份；
- 设置保留策略；
- 支持手动和计划备份；
- 失败产生告警；
- 成功后执行完整性验证。

### 12.4 任务状态

```text
PENDING
RUNNING
VERIFYING
SUCCESS
FAILED
CANCELLED
```

记录类型、范围、文件、大小、哈希、开始和结束时间、操作人、结果、错误和Request ID。

---

## 十三、恢复和灾难恢复

### 13.1 恢复原则

必须先在隔离环境或临时目录验证，不得直接覆盖生产。

流程：

```text
选择备份
  ↓
校验哈希
  ↓
校验版本
  ↓
解密
  ↓
检查数据库迁移兼容性
  ↓
隔离环境恢复
  ↓
完整性检查
  ↓
生成恢复预览
  ↓
管理员确认
  ↓
进入维护模式
  ↓
正式恢复
  ↓
验证组件、配置和应用
  ↓
退出维护模式
```

### 13.2 恢复范围

支持：

- 全系统恢复；
- 配置恢复；
- 数据库恢复；
- 证书恢复；
- 指定配置版本恢复。

### 13.3 灾难恢复文档

必须覆盖：

- 单机损坏；
- 数据库损坏；
- 配置误发布；
- 证书目录损坏；
- Valkey数据丢失；
- 采集积压；
- 系统重装后恢复；
- 主密钥丢失风险。

### 13.4 真实恢复测试

必须在全新环境验证：

- 用户登录；
- 三权权限；
- 应用访问；
- 证书加载；
- WAF策略；
- 黑白名单和CC；
- 历史版本；
- 审计；
- 事件查询；
- 配置发布。

没有真实恢复测试不得标记备份恢复完成。

---

## 十四、系统升级和回滚

### 14.1 升级包

包含：

- 版本清单；
- 镜像或二进制；
- 数据库迁移；
- 配置迁移；
- 前端静态文件；
- 组件版本；
- 校验和；
- 签名或完整性文件；
- 升级说明；
- 回滚说明。

### 14.2 升级前检查

检查：

- 当前和目标版本；
- 磁盘空间；
- PostgreSQL和Valkey；
- 当前发布和备份任务；
- 数据库迁移兼容性；
- 配置兼容性；
- Caddy模块兼容性；
- 证书文件；
- 主密钥；
- 最近全量备份；
- 未处理高危系统告警。

### 14.3 升级流程

```text
加载升级包
  ↓
校验哈希和签名
  ↓
升级前检查
  ↓
升级前全量备份
  ↓
进入维护窗口
  ↓
更新组件
  ↓
执行数据库和配置迁移
  ↓
启动服务
  ↓
健康检查
  ↓
应用访问验证
  ↓
退出维护窗口
```

### 14.4 失败回滚

必须支持：

- 恢复旧镜像或二进制；
- 回滚数据库迁移；
- 恢复配置；
- 恢复前端；
- 验证旧版本；
- 记录升级和回滚审计。

禁止只更新数据库而没有回滚方案。

---

## 十五、离线部署和初始化向导

### 15.1 离线包内容

- Docker镜像离线包；
- Docker Compose；
- 配置模板；
- 安装脚本；
- 初始化脚本；
- 健康检查脚本；
- 诊断脚本；
- 备份恢复脚本；
- 升级脚本；
- 卸载说明；
- 第三方许可证；
- SBOM；
- 管理和运维手册；
- 验收测试清单。

### 15.2 安装检查

- CPU架构；
- 操作系统；
- Docker和Compose；
- CPU、内存和磁盘；
- 端口；
- 时间同步；
- 文件权限；
- 主机名和DNS；
- 网络和防火墙；
- SELinux或安全策略；
- 已存在容器；
- 证书目录权限；
- 随机数来源。

### 15.3 初始化向导

完成：

- 系统名称和时区；
- 初始化系统管理员；
- 初始化安全管理员；
- 初始化审计管理员；
- 密码策略；
- 生成或导入主密钥；
- PostgreSQL和Valkey；
- 网关监听；
- 管理平台HTTPS证书；
- 健康检查；
- 一次性初始化结果。

不得在安装日志中长期保存初始密码。

---

## 十六、正式交付检查

自动检查：

- 组件状态；
- 管理平台HTTPS；
- 三权账号；
- 密码策略；
- Caddy管理接口未暴露；
- PostgreSQL未暴露；
- Valkey未暴露；
- 当前配置版本；
- WAF检测；
- 黑白名单；
- CC；
- 事件采集；
- 报告生成；
- 备份；
- 恢复；
- 审计；
- 第三方许可证；
- SBOM；
- 文档；
- 高危漏洞扫描；
- 默认密码；
- 调试接口；
- Mock数据；
- 测试报告。

结果：

```text
PASS
WARNING
FAIL
NOT_APPLICABLE
```

关键项为FAIL时不得标记正式交付。

---

## 十七、开源合规和软件著作权材料

必须维护：

```text
THIRD_PARTY_NOTICES.md
OPEN_SOURCE_COMPLIANCE.md
DEPENDENCY_LICENSES.md
SBOM.spdx.json
SBOM.cyclonedx.json
LICENSES/
```

记录：

- Caddy；
- Coraza；
- OWASP CRS；
- Valkey；
- PostgreSQL；
- 前端依赖；
- Go依赖；
- Node依赖；
- 基础镜像；
- 字体、图标和图片；
- 自主开发模块。

软件著作权基础材料：

- 产品功能说明；
- 系统架构；
- 模块清单；
- 自主代码目录；
- 第三方边界；
- 数据库结构；
- 界面截图清单；
- 版本信息；
- 源代码导出规范。

---

## 十八、数据库设计

至少新增：

```text
metric_minute_aggregates
metric_hour_aggregates
metric_daily_aggregates
application_security_summaries
rule_hit_summaries
source_ip_summaries
uri_security_summaries
system_health_snapshots
aggregation_jobs
report_templates
report_jobs
report_archives
system_alerts
system_alert_notes
backup_jobs
backup_files
restore_jobs
upgrade_packages
upgrade_jobs
delivery_checks
delivery_check_results
```

所有报告、备份、恢复和升级任务必须有不可变记录和明确状态流转。

---

## 十九、接口设计

### 19.1 态势和统计

```text
GET /api/v1/dashboard/security-overview
GET /api/v1/dashboard/runtime-overview
GET /api/v1/analytics/request-trend
GET /api/v1/analytics/security-event-trend
GET /api/v1/analytics/risk-levels
GET /api/v1/analytics/attack-types
GET /api/v1/analytics/top-source-ips
GET /api/v1/analytics/top-applications
GET /api/v1/analytics/top-rules
GET /api/v1/analytics/top-uris
GET /api/v1/analytics/cc-overview
GET /api/v1/analytics/access-control-overview
GET /api/v1/analytics/disposition-overview
```

### 19.2 报告

```text
GET    /api/v1/report-templates
POST   /api/v1/report-templates
GET    /api/v1/report-templates/{id}
PUT    /api/v1/report-templates/{id}
DELETE /api/v1/report-templates/{id}

GET    /api/v1/reports
POST   /api/v1/reports
GET    /api/v1/reports/{id}
POST   /api/v1/reports/{id}/retry
GET    /api/v1/reports/{id}/preview
GET    /api/v1/reports/{id}/download
DELETE /api/v1/reports/{id}
```

### 19.3 监控和告警

```text
GET  /api/v1/system-health
GET  /api/v1/system-health/components
GET  /api/v1/system-health/storage
GET  /api/v1/system-alerts
GET  /api/v1/system-alerts/{id}
POST /api/v1/system-alerts/{id}/acknowledge
POST /api/v1/system-alerts/{id}/resolve
POST /api/v1/system-alerts/{id}/ignore
POST /api/v1/system-alerts/{id}/notes
```

### 19.4 备份和恢复

```text
GET  /api/v1/backups
POST /api/v1/backups
GET  /api/v1/backups/{id}
POST /api/v1/backups/{id}/verify
GET  /api/v1/backups/{id}/download
DELETE /api/v1/backups/{id}

GET  /api/v1/restores
POST /api/v1/restores/validate
POST /api/v1/restores
GET  /api/v1/restores/{id}
```

### 19.5 升级和交付

```text
GET  /api/v1/upgrades
POST /api/v1/upgrades/packages
POST /api/v1/upgrades/precheck
POST /api/v1/upgrades
GET  /api/v1/upgrades/{id}
POST /api/v1/upgrades/{id}/rollback

GET  /api/v1/delivery-checks
POST /api/v1/delivery-checks/run
GET  /api/v1/delivery-checks/{id}
GET  /api/v1/delivery-checks/{id}/export
```

---

## 二十、权限设计

### 安全管理员

```text
dashboard.security.read
analytics.security.read
reports.read
reports.create
reports.download
reports.delete_own
system_alerts.read_security
system_alerts.acknowledge_security
```

### 系统管理员

```text
dashboard.runtime.read
system_health.read
system_alerts.read
system_alerts.acknowledge
system_alerts.resolve
backups.read
backups.create
backups.verify
backups.restore
upgrades.read
upgrades.precheck
upgrades.execute
upgrades.rollback
delivery_checks.read
delivery_checks.run
```

### 审计管理员

```text
dashboard.audit.read
analytics.disposition.read
reports.read_audit
reports.download_audit
system_alerts.read_audit
backup_records.read
restore_records.read
upgrade_records.read
delivery_checks.read
```

恢复、升级和删除备份属于高风险操作，必须二次确认并记录审计。

---

## 二十一、前端菜单

```text
安全态势
├── 安全总览
├── 统计分析
└── 系统告警

报表中心
├── 报告任务
├── 报告模板
└── 报告归档

系统运维
├── 运行监控
├── 存储容量
├── 备份恢复
├── 系统升级
└── 交付检查
```

根据三权角色动态展示。

---

## 二十二、稳定性和容量测试

### 22.1 稳定性

至少执行72小时连续运行，期间包含：

- 持续访问流量；
- 持续安全事件写入；
- 定时聚合；
- 定时报告；
- 定时备份；
- 日志轮转；
- 临时封禁到期；
- 证书状态检查；
- 组件重启；
- 无持续内存增长；
- 无任务无限积压；
- 无数据库连接泄露。

### 22.2 容量

至少测试：

- 100个应用；
- 500个域名；
- 500个源站；
- 1000万安全事件模拟数据；
- 1000万访问控制事件模拟数据；
- 100个并发统计查询；
- 30天趋势；
- 180天事件查询；
- 大型PDF报告；
- 并发备份任务串行或拒绝控制。

### 22.3 参考目标

- 态势首页P95低于2秒；
- 24小时趋势P95低于1秒；
- 30天趋势P95低于2秒；
- 报告异步执行，不阻塞API；
- 健康页面P95低于1秒；
- 1000万事件下分页查询可用；
- 备份期间网关请求无明显中断；
- 报告生成期间管理API可用。

目标值不得冒充实际结果。

---

## 二十三、故障恢复测试

真实执行：

- 管理API重启；
- 网关重启；
- PostgreSQL短暂中断；
- Valkey短暂中断；
- 采集器重启；
- 解析器重启；
- 报告服务失败；
- 备份失败；
- 磁盘空间不足；
- 配置哈希不一致；
- 源站全部异常；
- 证书过期；
- 升级失败回滚；
- 全新环境恢复备份。

验证告警、恢复、数据丢失、重复事件、当前网关配置和审计记录。

---

## 二十四、安全测试

至少执行：

- 统计接口越权；
- 报告跨用户下载；
- 报告路径穿越；
- 任意文件下载；
- 模板存储型XSS；
- 报告HTML注入；
- PDF渲染SSRF；
- 报告任务资源耗尽；
- 聚合参数注入；
- 指标高基数攻击；
- 告警备注XSS；
- 备份路径穿越；
- 备份未加密；
- 备份密码泄露；
- 恢复包篡改；
- 恢复覆盖生产；
- 升级包篡改；
- 升级命令注入；
- 数据库迁移注入；
- 升级越权；
- 回滚越权；
- 离线包恶意文件；
- 安装脚本命令注入；
- 默认账号和密码；
- 调试接口暴露；
- 敏感环境变量泄露；
- SBOM或许可证缺失；
- 管理HTTPS错误；
- 备份和主密钥同目录风险。

高危问题未修复不得交付。

---

## 二十五、自动化命令

```bash
make stage6-up
make stage6-status
make metrics-aggregate
make reports-test
make monitoring-test
make alerts-test
make backup-create
make backup-verify
make restore-test
make upgrade-precheck
make upgrade-test
make delivery-check
make sbom-generate
make license-audit
make stage6-test-unit
make stage6-test-api
make stage6-test-e2e
make stage6-test-performance
make stage6-test-stability
make stage6-test-recovery
make stage6-test-security
make stage6-test-all
make stage6-down
```

---

## 二十六、文档要求

```text
docs/SECURITY_DASHBOARD_DESIGN.md
docs/METRICS_DATA_DICTIONARY.md
docs/REPORTING_DESIGN.md
docs/REPORT_TEMPLATE_GUIDE.md
docs/MONITORING_ALERTING_DESIGN.md
docs/BACKUP_RESTORE_DESIGN.md
docs/DISASTER_RECOVERY_GUIDE.md
docs/UPGRADE_ROLLBACK_DESIGN.md
docs/OFFLINE_DEPLOYMENT_GUIDE.md
docs/INSTALLATION_GUIDE.md
docs/OPERATIONS_MANUAL.md
docs/SYSTEM_ADMIN_MANUAL.md
docs/SECURITY_ADMIN_MANUAL.md
docs/AUDIT_ADMIN_MANUAL.md
docs/DELIVERY_ACCEPTANCE_GUIDE.md
docs/STAGE6_TEST_REPORT.md
THIRD_PARTY_NOTICES.md
docs/OPEN_SOURCE_COMPLIANCE.md
docs/DEVELOPMENT_STATUS.md
```

---

## 二十七、阶段退出条件

以下条件全部满足才允许“阶段6通过”：

1. 态势首页使用真实数据；
2. 请求、攻击、CC和访问控制趋势可用；
3. 风险、类型、IP、应用、规则和URI排行可用；
4. 未处置事件和运行风险可展示；
5. 聚合任务幂等；
6. 迟到数据可修正；
7. 高基数标签受限；
8. 日报、周报、月报和自定义报告可生成；
9. 报告任务真实异步；
10. 报告预览和下载可用；
11. 报告有权限、哈希和审计；
12. 报告无未脱敏攻击载荷；
13. 网关、API、数据库、Valkey、采集器和解析器监控可用；
14. 应用、源站、证书和存储监控可用；
15. 系统告警可产生、确认和关闭；
16. 告警合并和抖动抑制可用；
17. 全量备份可用；
18. 配置备份可用；
19. 备份加密并有哈希；
20. 备份失败有告警；
21. 已在全新环境完成真实恢复；
22. 恢复后用户、应用、证书、策略、审计和事件可用；
23. 升级包完整性校验可用；
24. 升级前检查可用；
25. 升级前自动备份可用；
26. 数据库迁移可执行；
27. 升级失败可回滚；
28. 离线包可在干净环境安装；
29. 初始化向导可用；
30. 初始密码不长期保留在日志；
31. 交付检查可执行；
32. 关键检查失败会阻止交付；
33. THIRD_PARTY_NOTICES完整；
34. OPEN_SOURCE_COMPLIANCE完整；
35. SBOM可生成；
36. 自主模块清单完整；
37. 72小时稳定性测试通过；
38. 容量测试完成；
39. 故障恢复测试完成；
40. E2E测试通过；
41. 安全测试无未修复高危；
42. Docker Compose可一键启动和停止；
43. 离线部署文档与实际一致；
44. 三权管理员手册完整；
45. 交付验收文档完整；
46. 未使用Mock统计；
47. 未将目标指标冒充结果；
48. 重大遗留问题已记录；
49. `docs/DEVELOPMENT_STATUS.md`已更新；
50. 系统具备正式交付条件。

---

## 二十八、执行顺序

```text
检查阶段1至阶段5
  ↓
统一指标模型
  ↓
聚合任务和统计表
  ↓
安全态势首页
  ↓
统计分析
  ↓
报告模板和任务
  ↓
运行监控
  ↓
系统告警
  ↓
备份
  ↓
隔离恢复验证
  ↓
正式恢复流程
  ↓
升级包和升级前检查
  ↓
升级失败回滚
  ↓
离线安装和初始化向导
  ↓
交付检查
  ↓
开源合规和SBOM
  ↓
前端
  ↓
全部测试
  ↓
正式交付验收
```

完成后停止，不得自行开发AI、Bot、多节点集群或SaaS。

---

## 二十九、禁止事项

1. 使用Mock数据冒充态势数据；
2. 首页每次扫描全部原始事件；
3. 完整URI参数作为指标标签；
4. 报告输出未脱敏攻击载荷；
5. 报告模板执行代码；
6. PDF渲染器任意访问网络；
7. 报告下载路径穿越；
8. 前端定时器模拟报告完成；
9. 备份明文保存；
10. 主密钥和备份放同一未保护目录；
11. 未验证备份就显示成功；
12. 未真实恢复就标记完成；
13. 直接覆盖生产恢复；
14. 升级前不备份；
15. 数据库迁移无回滚；
16. 升级失败留下半升级状态；
17. 安装脚本执行未转义输入；
18. 离线包包含固定默认密码；
19. 暴露调试接口；
20. 暴露PostgreSQL、Valkey或Caddy管理接口；
21. 删除失败测试；
22. 将性能目标写成结果；
23. 安全管理员执行系统升级；
24. 系统管理员修改WAF业务策略；
25. 审计管理员删除审计或证据；
26. 提前开发AI、多节点集群和SaaS。

---

## 三十、Agent最终输出格式

必须输出：

1. 阶段结论；
2. 实际完成项；
3. 未完成项；
4. 新增和修改文件；
5. 数据库迁移；
6. 指标模型和聚合任务；
7. 态势首页真实数据验证；
8. 报告类型、生成数、成功数、失败数和耗时；
9. 组件监控和告警验证；
10. 备份文件、大小、哈希和验证；
11. 全新环境恢复结果；
12. 升级和失败回滚结果；
13. 离线安装环境和结果；
14. 交付检查结果；
15. SBOM、许可证和第三方组件清单；
16. 单元、接口、E2E、性能、容量、稳定性、恢复和安全测试结果；
17. 72小时稳定性数据；
18. CPU、内存、磁盘、数据库容量和事件积压；
19. 安全检查；
20. 遗留问题；
21. 未满足退出条件；
22. 是否具备正式交付条件。

执行指令：

```text
请严格按照 docs/tasks/STAGE_6_SECURITY_OPERATIONS_DELIVERY.md 执行阶段6。
先检查阶段1至阶段5真实交付结果。
不得使用Mock统计和Mock报告数据。
必须完成真实备份和全新环境恢复。
必须完成升级失败回滚验证。
必须完成离线安装和交付检查。
必须生成开源合规文件和SBOM。
完成全部测试后停止，不得自行开发AI、多节点集群或SaaS。
```
