# 九章WEB应用智能防护系统V2.0
## 阶段7：AI智能安全运营中心（AI SOC）开发任务书

## 一、阶段定位

阶段7在阶段1至阶段6已经完成的网关、身份认证、应用接入、WAF策略、安全事件、访问控制、CC防护、统计报表、运行监控、备份恢复和正式交付能力之上，建设九章AI智能安全运营中心。

本阶段不是让AI直接代替安全管理员，也不是让AI绕过现有权限和发布流程，而是构建一个具备安全分析、日志问答、攻击画像、攻击链关联、误报研判、策略建议、运维诊断、报告总结和受控草稿生成能力的企业级AI安全助手。

阶段7完成后，系统定位升级为：

```text
企业级WAF
+
安全事件运营平台
+
AI安全分析助手
+
受控多Agent协同平台
```

完整闭环：

```text
WAF、CC、访问控制和运行监控产生真实数据
    ↓
AI Orchestrator识别用户意图
    ↓
任务规划器拆解任务
    ↓
调用受控安全Tool
    ↓
专业Agent执行分析
    ↓
证据聚合和冲突校验
    ↓
生成带引用的结论和建议
    ↓
管理员确认
    ↓
生成例外、黑名单、CC、规则或报告草稿
    ↓
进入既有校验、发布和审计流程
    ↓
验证处置结果并形成闭环
```

---

## 二、阶段目标

本阶段完成后，系统应具备：

1. AI安全助手多轮对话；
2. 会话、项目和长期记忆；
3. 上下文预算、使用量展示和自动压缩；
4. 任务分类和结构化任务规划；
5. 多Agent协同；
6. 受控Tool工具体系；
7. 安全事件AI分析；
8. 误报AI分析；
9. WAF规则AI解释；
10. 攻击源、URI和应用画像；
11. 攻击链关联；
12. 运行异常根因分析；
13. 日志和安全统计自然语言问答；
14. 策略优化建议；
15. What-If策略模拟；
16. 例外、黑名单、CC和自定义规则草稿生成；
17. 日报、周报和月报AI总结；
18. 模型网关和模型路由；
19. Prompt版本管理；
20. Agent、Tool、Memory和模型管理；
21. AI调用成本和配额控制；
22. AI输出证据引用；
23. AI调用、Tool调用和草稿操作审计；
24. Prompt Injection、幻觉和越权防护；
25. AI故障降级和熔断；
26. AI质量评估和回归测试。

---

## 三、阶段边界

### 3.1 本阶段必须开发

- AI模型网关；
- 模型供应商抽象；
- 主模型、备用模型、本地模型和嵌入模型配置；
- 模型连通性和能力测试；
- AI Orchestrator；
- Intent Classifier；
- Task Planner；
- Context Manager；
- Memory Manager；
- Agent Registry；
- Tool Registry；
- Tool Router；
- Evidence Collector；
- Risk Guard；
- Response Composer；
- AI安全助手Chat；
- 会话和消息管理；
- 流式输出、停止、重试和继续输出；
- 会话级上下文；
- 应用或项目级上下文；
- 用户长期记忆；
- 记忆查看、修改、禁用和删除；
- 上下文预算；
- 自动压缩；
- 历史摘要；
- 证据引用；
- 安全事件Agent；
- 日志分析Agent；
- WAF策略Agent；
- 资产Agent；
- 运维诊断Agent；
- 报告Agent；
- 知识库Agent；
- 总调度Agent；
- 安全事件、日志、统计、资产、策略、规则、例外、访问控制、CC和系统状态查询Tool；
- 例外、黑名单、CC、自定义规则和报告总结草稿Tool；
- 攻击画像；
- 攻击链分析；
- 根因分析；
- 误报分析；
- 规则解释；
- 策略建议；
- What-If模拟；
- AI报告总结；
- Prompt管理和不可变版本；
- Agent和Tool配置管理；
- AI审计；
- 成本和配额；
- AI质量评估；
- 幻觉、注入、长上下文、多Agent、性能、成本和安全测试。

### 3.2 本阶段暂不开发

- AI自动发布WAF策略；
- AI自动启停规则；
- AI自动创建永久例外；
- AI自动创建永久黑名单；
- AI自动封禁或解封IP；
- AI自动执行系统升级；
- AI自动执行备份恢复；
- AI直接访问数据库；
- AI直接执行原始SQL；
- AI执行宿主机Shell；
- AI访问Docker Socket；
- AI访问Caddy管理Socket；
- AI直接修改配置文件；
- AI自动删除事件或审计；
- AI自主联网搜索；
- 未经批准的外部威胁情报查询；
- 多租户AI计费；
- 云端集中AI运营；
- 自动工单；
- 语音助手；
- 自动微调、自训练和未受控代码执行。

所有生产变更必须经过阶段3至阶段6已有的草稿、校验、发布、回滚和审计流程，并由具备权限的管理员明确确认。

---

## 四、阶段前置条件

开始阶段7前必须确认：

1. 阶段1网关、Coraza和OWASP CRS稳定运行；
2. 阶段2身份认证、服务端会话、三权权限和操作审计稳定；
3. 阶段3应用、源站、证书、配置发布和回滚稳定；
4. 阶段4WAF策略、事件采集、事件解析和事件处置稳定；
5. 阶段5真实IP、黑白名单、CC和临时封禁稳定；
6. 阶段6安全态势、报表、监控、告警和备份恢复稳定；
7. 安全事件数据已经标准化；
8. 事件、规则、策略、应用和Request ID可以关联；
9. 数据保留和脱敏策略已经生效；
10. 当前系统不存在未关闭的高危问题；
11. 阶段1至阶段6测试报告已经归档；
12. AI模块可以作为独立模块启停；
13. AI模块关闭时不影响WAF核心防护；
14. 所有关键业务接口已经具备后端权限校验；
15. 报表和统计数据可以重复验证。

如果前序阶段真实数据链路存在问题，不得使用AI生成内容掩盖。

---

## 五、AI设计原则

### 5.1 AI只做辅助决策

AI可以执行查询、分析、解释、汇总、比较、推荐、模拟和生成草稿。

AI不得直接执行发布、删除、封禁、解封、修改生产配置、修改数据库、Shell、升级和恢复。

### 5.2 所有事实必须有证据

AI回答涉及当前系统事实时必须附带：

- 安全事件ID；
- Request ID；
- 规则ID；
- 应用ID；
- 策略或配置版本；
- 统计时间范围；
- Tool结果引用；
- 日志时间范围。

无法获得足够证据时必须明确说明：

```text
当前数据不足，无法确认。
```

不得将推测写成已经确认的事实。

### 5.3 AI与防护内核解耦

AI模块异常时：

- WAF继续运行；
- CC继续运行；
- 黑白名单继续生效；
- 配置发布继续可用；
- 安全事件继续采集；
- 固定模板报告继续生成；
- AI入口显示降级状态。

### 5.4 最小权限

每个Agent和Tool只拥有完成职责所需的最低权限。

### 5.5 全程可审计

所有模型调用、Agent调用、Tool调用、草稿生成、人工确认和最终执行结果必须可追溯。

### 5.6 不保存私有思维链

系统不得要求、存储或展示模型内部私有思维链。审计只记录任务计划摘要、Agent、Tool、证据、回答、风险检查、Token、成本和人工操作。

---

## 六、总体架构

```text
九章AI安全助手前端
        │
        ▼
AI API Gateway
        ├── 身份认证
        ├── 权限校验
        ├── 会话管理
        ├── 限流
        └── 审计
        │
        ▼
AI Orchestrator
        ├── Intent Classifier
        ├── Task Planner
        ├── Context Manager
        ├── Memory Manager
        ├── Agent Router
        ├── Tool Router
        ├── Evidence Collector
        ├── Risk Guard
        └── Response Composer
        │
        ├──────── Model Gateway
        ├──────── Agent Registry
        ├──────── Tool Registry
        ├──────── PostgreSQL
        ├──────── Valkey
        ├──────── Knowledge Index
        └──────── Audit Storage
```

建议目录：

```text
ai-service/
├── cmd/
├── internal/
│   ├── orchestrator/
│   ├── planner/
│   ├── context/
│   ├── memory/
│   ├── agents/
│   ├── tools/
│   ├── modelgateway/
│   ├── prompts/
│   ├── evidence/
│   ├── guardrails/
│   ├── evaluation/
│   ├── audit/
│   ├── cost/
│   └── streaming/
├── migrations/
├── tests/
└── Dockerfile

web/src/pages/
├── ai-assistant/
├── ai-analysis/
├── ai-recommendations/
├── ai-reports/
├── ai-prompts/
├── ai-agents/
├── ai-tools/
├── ai-memory/
├── ai-models/
└── ai-audits/
```

---

## 七、AI模型网关

### 7.1 统一模型接口

AI业务不得直接绑定单一供应商。统一接口至少支持：

```text
chat
stream
tool_call
structured_output
embedding
health_check
usage
```

模型字段：

```text
provider
model
base_url
api_key_reference
context_window
max_output_tokens
supports_tools
supports_structured_output
supports_streaming
supports_embeddings
status
priority
timeout_seconds
retry_policy
cost_input_unit
cost_output_unit
```

### 7.2 模型类型

- 主模型；
- 备用模型；
- 本地模型；
- 嵌入模型；
- 低成本分类模型。

### 7.3 模型路由

- 简单分类使用低成本模型；
- 单事件分析使用标准模型；
- 攻击链和复杂根因分析使用高能力模型；
- 敏感数据场景可以强制使用本地模型；
- 主模型故障时切换备用模型。

### 7.4 模型健康检查

验证连通性、鉴权、流式响应、Tool调用、结构化输出、上下文长度、最大输出、超时和错误率。

### 7.5 密钥安全

模型API密钥必须加密保存，不返回前端、不写入日志、不进入Prompt、不进入AI审计正文，并支持轮换、禁用和最小权限账户。

---

## 八、AI Orchestrator

### 8.1 职责

- 意图识别；
- 任务分类；
- 任务拆解；
- Agent和Tool选择；
- 上下文构建；
- 记忆加载；
- 证据收集；
- 结果冲突校验；
- 风险检查；
- 最终回答生成；
- 成本控制；
- 失败降级。

### 8.2 任务类型

```text
EVENT_ANALYSIS
FALSE_POSITIVE_ANALYSIS
RULE_EXPLANATION
ATTACK_PROFILE
ATTACK_CHAIN
ROOT_CAUSE_ANALYSIS
LOG_QUERY
STATISTICS_QUERY
POLICY_RECOMMENDATION
WHAT_IF_ANALYSIS
DRAFT_EXCEPTION
DRAFT_BLACKLIST
DRAFT_CC_POLICY
DRAFT_CUSTOM_RULE
REPORT_SUMMARY
GENERAL_SECURITY_QA
```

### 8.3 结构化计划摘要

复杂任务必须生成任务类型、步骤、所需Tool、风险等级和预计范围。前端可以展示计划摘要，但不得展示模型私有思维链。

### 8.4 执行限制

每次任务设置：

- 最大Agent调用数；
- 最大Tool调用数；
- 最大总耗时；
- 最大输入Token；
- 最大输出Token；
- 最大重试次数；
- 最大查询时间范围；
- 最大返回事件数；
- 最大并发子任务数。

超过限制时停止并返回已经完成的结果。

---

## 九、多Agent设计

### 9.1 总调度Agent

负责任务拆解、专业Agent调度、证据检查、结果合并和最终回答。

### 9.2 安全事件Agent

负责单事件分析、批量事件归纳、攻击类型、影响范围、关联事件、攻击确认建议和误报初判。

### 9.3 日志分析Agent

负责访问日志、WAF日志、CC日志、访问控制日志、审计日志、系统日志和Request ID链路追踪。

### 9.4 WAF策略Agent

负责策略、规则、覆盖、例外、误报、策略建议、What-If和变更草稿。

### 9.5 资产Agent

负责应用、域名、源站、证书、策略、配置版本和发布状态。

### 9.6 运维诊断Agent

负责网关、API、PostgreSQL、Valkey、采集器、解析器、CPU、内存、磁盘、报告、备份和发布故障。

### 9.7 报告Agent

负责日报、周报、月报、事件专题和运营建议摘要。

### 9.8 知识库Agent

负责OWASP CRS、Coraza、九章文档、管理员手册、运维手册和企业审核文档。知识库说明不得冒充当前运行事实。

---

## 十、Tool工具体系

### 10.1 Tool统一契约

每个Tool必须定义：

- Tool名称和版本；
- 功能说明；
- 输入和输出JSON Schema；
- 所需权限；
- 风险等级；
- 超时时间；
- 最大返回数量；
- 分页能力；
- 是否只读；
- 是否只生成草稿；
- 审计策略；
- 脱敏策略；
- 错误码。

风险等级：

```text
READ_ONLY
DRAFT_ONLY
REQUIRES_CONFIRMATION
PROHIBITED
```

阶段7只允许READ_ONLY和DRAFT_ONLY。最终生产操作必须进入人工确认流程。

### 10.2 安全事件Tool

```text
security_event.search
security_event.get
security_event.related
security_event.statistics
security_event.disposition_summary
```

### 10.3 日志Tool

```text
access_log.search
waf_log.search
cc_log.search
access_control_log.search
audit_log.search
system_log.search
request_trace.get
```

必须限制时间范围、返回数量、字段、脱敏、超时和高成本查询。

### 10.4 资产和策略Tool

```text
application.search
application.get
domain.get
upstream.get
certificate.get_metadata
gateway.get_status
policy.get
policy.diff
policy.version
rule.search
rule.get
rule.hit_statistics
exception.search
exception.get
```

证书Tool只能返回元数据，禁止返回私钥。

### 10.5 访问控制和统计Tool

```text
access_rule.search
temporary_block.search
rate_limit_policy.search
rate_limit_statistics.get
trusted_proxy.get_summary
statistics.security_overview
statistics.attack_trend
statistics.top_source_ips
statistics.top_applications
statistics.top_rules
statistics.top_uris
statistics.false_positive
statistics.runtime
```

### 10.6 草稿Tool

```text
draft.exception.create
draft.blacklist.create
draft.cc_policy.create
draft.custom_rule.create
draft.report_summary.create
```

所有草稿必须标记AI生成、记录来源会话和证据、默认状态DRAFT，并进入既有人工校验和发布流程。

### 10.7 禁止提供的Tool

```text
shell.execute
database.raw_query
database.write
docker.execute
gateway.publish_direct
policy.publish_direct
firewall.block_direct
system.upgrade_direct
backup.restore_direct
audit.delete
```

---

## 十一、AI安全助手Chat

### 11.1 支持问题

示例：

```text
今天为什么攻击增多？
最近谁在攻击ERP？
942100为什么一直命中？
哪些规则误报率最高？
哪些IP建议封禁？
哪些URI风险最高？
为什么事件采集延迟升高？
为什么报告生成失败？
当前哪些证书即将过期？
最近一次发布为什么失败？
```

### 11.2 回答结构

事实型回答默认包含：

1. 结论；
2. 时间范围；
3. 关键数据；
4. 证据引用；
5. 风险判断；
6. 建议；
7. 不确定性说明；
8. 可以生成的草稿操作。

### 11.3 流式输出

必须支持：

- 流式回答；
- 用户主动停止；
- 网络断开恢复；
- Tool调用中断；
- 重试；
- 继续输出；
- 防止内容重复；
- 保存已经生成的有效内容。

### 11.4 输出长度中断处理

当模型因输出长度停止时：

- 识别`finish_reason=length`或等价状态；
- 保存已完成内容；
- 生成压缩续写上下文；
- 从未完成章节继续；
- 不重复前文；
- 最多自动续写指定次数；
- 超过限制后提供继续按钮。

---

## 十二、安全事件AI分析

### 12.1 输入范围

支持：

- 单个事件；
- 多个事件；
- 指定时间范围；
- 指定应用；
- 指定IP；
- 指定URI；
- 指定规则；
- 指定Request ID。

### 12.2 输出内容

至少包括：

- 攻击类型；
- 命中规则；
- 风险等级；
- 攻击载荷脱敏摘要；
- 是否已阻断；
- 是否到达源站；
- 关联请求；
- 可能影响；
- 是否建议进一步排查；
- 是否建议封禁；
- 是否可能误报；
- 证据引用；
- 不确定性。

### 12.3 结论等级

```text
CONFIRMED
LIKELY
POSSIBLE
INSUFFICIENT_EVIDENCE
```

证据不足时不得输出“已经成功入侵”。

### 12.4 到达源站判断

必须综合：

- WAF动作；
- 网关访问日志；
- 源站状态；
- Request ID链路；
- 响应状态；
- 上游连接记录。

不能只根据WAF事件中的攻击类型判断攻击成功与否。

---

## 十三、AI误报分析

### 13.1 分析维度

- 命中规则；
- 匹配变量；
- 匹配内容；
- URI；
- 请求方法；
- Content-Type；
- 应用业务场景；
- 同类合法请求；
- 同类攻击请求；
- 历史误报记录；
- 已有例外；
- 规则命中统计。

### 13.2 输出内容

- 是否可能误报；
- 误报原因；
- 推荐例外范围；
- 预计影响；
- 风险；
- 建议有效期；
- 测试方法；
- 例外草稿。

### 13.3 例外草稿约束

优先生成：

```text
应用
+
URI
+
规则ID
+
变量名
```

禁止默认生成：

- 全局永久例外；
- 关闭全部SQL注入规则；
- 关闭全部XSS规则；
- 关闭整个WAF；
- 无有效期的宽泛例外。

草稿必须附带风险说明、影响范围、验证用例和来源事件。

---

## 十四、AI规则解释

点击规则后，AI应输出：

- 规则用途；
- 攻击类型；
- 检测变量；
- 检测逻辑摘要；
- 常见攻击样例说明；
- 常见误报场景；
- 推荐适用范围；
- 不推荐场景；
- 关联事件数；
- 误报数；
- 当前启用状态；
- 当前覆盖；
- CRS版本；
- 调整建议。

不得大段复制上游规则源代码，也不得把规则解释写成当前系统攻击事实。

---

## 十五、攻击画像

### 15.1 IP画像

至少包含：

- 首次出现；
- 最后出现；
- 请求次数；
- 攻击事件次数；
- 攻击应用；
- 攻击URI；
- 攻击类型；
- 风险等级；
- 命中规则；
- 时间分布；
- User-Agent摘要；
- 阻断情况；
- 封禁情况；
- 共享出口风险；
- 建议。

### 15.2 URI画像

- 请求量；
- 事件量；
- 攻击类型；
- 风险等级；
- 来源IP；
- 误报率；
- 命中规则；
- 当前例外；
- 当前CC策略；
- 建议。

### 15.3 应用画像

- 请求量；
- 事件量；
- 阻断率；
- 误报率；
- 高危事件；
- 主要攻击类型；
- 主要来源IP；
- 高风险URI；
- 当前策略；
- 证书状态；
- 源站状态；
- 建议。

### 15.4 画像时间范围

默认支持24小时、7天、30天和自定义时间。所有指标必须显示统计区间。

---

## 十六、攻击链分析

### 16.1 关联条件

可以依据：

- 客户端IP；
- Request ID；
- Session标识摘要；
- Cookie摘要；
- User-Agent；
- 应用；
- URI；
- 时间窗口；
- 规则；
- 攻击类型；
- 请求顺序；
- 源站响应状态。

### 16.2 输出内容

- 攻击时间线；
- 攻击阶段；
- 每一步关联事件；
- 证据；
- 是否被阻断；
- 是否存在成功迹象；
- 受影响应用；
- IOC脱敏摘要；
- 风险等级；
- 建议排查项；
- 建议处置项。

### 16.3 关联置信度

```text
HIGH_CONFIDENCE
MEDIUM_CONFIDENCE
LOW_CONFIDENCE
```

每条攻击链必须说明关联理由和置信度。

### 16.4 MITRE ATT&CK映射

可以提供参考映射，但必须明确标注为“参考映射”，不得将不确定映射写成确认事实。

---

## 十七、AI根因分析

支持分析：

- CPU升高；
- 内存升高；
- 磁盘不足；
- 事件积压；
- 解析失败；
- 报告失败；
- 备份失败；
- 发布失败；
- 网关重启；
- Valkey异常；
- PostgreSQL连接异常；
- 源站大量失败；
- 证书加载失败；
- 模型调用失败；
- Tool调用超时。

分析流程：

```text
读取运行状态
    ↓
读取系统告警
    ↓
读取相关日志
    ↓
读取最近配置变更
    ↓
读取发布、升级和备份记录
    ↓
建立时间线
    ↓
输出最可能原因
    ↓
输出证据和排查步骤
```

输出必须区分：

- 已确认原因；
- 高概率原因；
- 待验证原因。

不得自动执行重启、升级、恢复或配置修改。

---

## 十八、AI策略推荐

### 18.1 推荐维度

- CRS执行等级；
- 入站和出站阈值；
- 规则启停；
- 规则覆盖；
- 例外收敛；
- CC阈值；
- 临时封禁时长；
- 应用防护模式；
- 请求体和响应体检查。

### 18.2 推荐依据

- 最近7天、30天和90天事件；
- 误报率；
- 阻断率；
- 规则命中；
- 应用类型；
- 业务时间；
- 历史处置；
- 当前例外；
- 当前发布版本；
- 历史策略变更效果。

### 18.3 输出内容

- 建议项；
- 当前配置；
- 推荐配置；
- 原因；
- 影响范围；
- 风险；
- 预期收益；
- 验证方法；
- 是否生成草稿。

不得仅因为规则从未命中就建议关闭高风险规则。

---

## 十九、What-If策略模拟

### 19.1 支持模拟

- 停用指定规则；
- 启用指定规则；
- 修改异常阈值；
- PL1切换PL2；
- 删除例外；
- 新增例外；
- 修改CC阈值；
- 修改临时封禁时间。

### 19.2 模拟方式

使用历史事件离线回放或统计模拟，不直接修改生产策略。

### 19.3 输出内容

- 受影响历史请求数；
- 可能减少的误报数；
- 可能增加的漏拦数；
- 受影响应用；
- 受影响URI；
- 风险等级；
- 建议测试范围；
- 模拟时间范围；
- 模拟局限性。

所有结果必须标注：

```text
基于历史数据估算，不代表未来确定结果。
```

---

## 二十、AI报告总结

### 20.1 数据来源

AI只能使用阶段6已生成的确定性报告数据和统计结果，不允许自行编造数字。

### 20.2 输出内容

- 本期安全态势摘要；
- 同比或环比变化；
- 主要攻击类型；
- 高风险应用；
- 主要攻击源；
- CC和访问控制情况；
- 误报和例外情况；
- 事件处置情况；
- 运行健康情况；
- 建议。

### 20.3 约束

- 每个数字必须来自报告数据；
- 每个趋势必须注明时间范围；
- 数据不足时不得生成趋势；
- AI总结与固定模板报告分开保存；
- 管理员可以编辑；
- 最终报告标记“AI辅助生成”。

---

## 二十一、Memory记忆体系

### 21.1 会话记忆

保存当前会话的用户问题、回答、Tool引用、已确认范围和当前任务状态。

### 21.2 项目记忆

按应用或项目保存：

- 业务说明；
- 约定时间范围；
- 已确认误报；
- 已批准策略偏好；
- 项目术语；
- 已确认资产关系。

### 21.3 长期记忆

只保存长期有价值并且经过确认的信息。

不得自动保存：

- 密码；
- Token；
- 私钥；
- 完整攻击载荷；
- 未确认的AI推测；
- 临时故障状态；
- 无长期价值的临时查询。

### 21.4 记忆操作

用户可以查看、新增、修改、禁用、删除、查看来源和最后使用时间。

### 21.5 记忆置信度

```text
USER_CONFIRMED
SYSTEM_CONFIRMED
AI_INFERRED
```

`AI_INFERRED`默认不得进入长期记忆，必须经过用户确认。

---

## 二十二、上下文管理与自动压缩

### 22.1 上下文组成

```text
系统Prompt
+
角色Prompt
+
任务Prompt
+
会话摘要
+
最近消息
+
用户记忆
+
项目记忆
+
Tool结果
+
知识引用
```

### 22.2 Token预算

分别设置系统安全规则、最近消息、历史摘要、Tool结果、知识库和输出预留预算。

### 22.3 自动压缩触发

参考阈值：

```text
70%：预警
80%：自动压缩
90%：强制裁剪和重新规划
```

阈值必须可配置，并根据模型上下文窗口自动计算。

### 22.4 优先压缩内容

- 已完成任务；
- 重复Tool结果；
- 过长日志；
- 已归纳事件；
- 旧的中间回答；
- 重复知识片段。

不得丢失：

- 用户明确要求；
- 权限和安全约束；
- 当前任务目标；
- 时间范围；
- 已确认事实；
- 未完成步骤；
- 关键证据引用。

### 22.5 压缩审计

记录压缩前后Token、摘要版本、保留引用、压缩原因和是否强制裁剪。

---

## 二十三、知识库与RAG

### 23.1 知识来源

- OWASP CRS文档；
- Coraza文档；
- 九章产品文档；
- 管理员手册；
- 运维手册；
- 安全事件处置指南；
- 企业审核通过的文档。

### 23.2 文档分级

```text
SYSTEM_OFFICIAL
ENTERPRISE_APPROVED
USER_PRIVATE
UNVERIFIED
```

正式回答优先使用SYSTEM_OFFICIAL和ENTERPRISE_APPROVED。

### 23.3 引用

引用应包含文档名、章节、版本和片段引用ID。

### 23.4 Prompt Injection防护

知识文档中的“忽略之前规则”“执行工具”“泄露密钥”“直接发布”等内容只能作为数据，不得覆盖系统和安全Prompt。

### 23.5 用户私人文档

用户私人文档只能作为该用户的个人参考资料，不自动进入企业正式知识库。进入企业知识库必须经过管理员审核。

---

## 二十四、Prompt管理

### 24.1 Prompt类型

```text
SYSTEM
ORCHESTRATOR
AGENT
TOOL
TASK
SAFETY
EVALUATION
```

### 24.2 Prompt状态

```text
DRAFT
TESTING
ACTIVE
DISABLED
ARCHIVED
```

### 24.3 Prompt版本

每次修改生成不可变版本，至少记录内容、哈希、变更摘要、测试结果、创建人、发布人和当前版本标记。

### 24.4 发布流程

```text
创建草稿
    ↓
静态安全检查
    ↓
测试集回归
    ↓
对抗测试
    ↓
结果对比
    ↓
人工审核
    ↓
发布
```

支持差异查看和回滚。

### 24.5 禁止内容

Prompt不得包含明文模型密钥、数据库密码、Shell、绕过权限、要求输出私有思维链、忽略Tool权限和未脱敏客户数据。

---

## 二十五、AI权限模型

### 25.1 安全管理员

可以：

- 使用AI安全助手；
- 分析事件和误报；
- 查询安全日志和策略；
- 生成例外、黑名单、CC和自定义规则草稿；
- 查看安全类AI审计；
- 生成AI报告总结。

不得执行系统升级和恢复。

### 25.2 系统管理员

可以：

- 使用运维诊断；
- 查询系统状态；
- 分析发布、备份、升级和组件故障；
- 查看运行类AI审计。

不得默认生成WAF业务策略草稿，除非另有明确授权。

### 25.3 审计管理员

可以：

- 查看AI调用记录；
- 查看Tool调用记录；
- 查看草稿来源；
- 查看人工确认链路；
- 导出AI审计。

不得使用AI生成生产变更草稿。

### 25.4 普通只读用户

如后续开放，只能执行授权范围内的只读查询，不能生成变更草稿。

---

## 二十六、AI审计

### 26.1 审计字段

记录：

- 会话ID；
- 用户；
- 角色；
- 用户请求；
- 任务类型；
- 任务计划摘要；
- Agent调用；
- Tool调用；
- Tool参数摘要；
- Tool结果引用；
- 模型供应商；
- 模型；
- Prompt版本；
- 输入Token；
- 输出Token；
- 总耗时；
- 成本；
- 最终回答；
- 风险检查；
- 草稿ID；
- 人工确认结果；
- 最终发布或处置结果。

### 26.2 脱敏

不得保存：

- 模型密钥；
- 数据库密码；
- 私钥；
- 完整Cookie；
- 完整Token；
- 未脱敏攻击载荷；
- 模型私有思维链。

### 26.3 完整性

AI审计应复用系统既有哈希链或完整性校验机制，防止记录被静默篡改。

### 26.4 保留期限

AI会话、Tool调用、草稿、模型用量和审计记录应分别配置保留期限。被安全事件、报告或审计调查引用的记录不得提前清理。

---

## 二十七、成本和配额控制

### 27.1 配额维度

- 用户每日配额；
- 角色每日配额；
- 单次Token限制；
- 单次Tool调用数；
- 并发会话数；
- 高成本任务次数；
- 报告总结次数；
- 攻击链分析次数。

### 27.2 成本统计

展示：

- 今日输入Token；
- 今日输出Token；
- 模型调用次数；
- Tool调用次数；
- 用户成本；
- Agent成本；
- 任务类型成本；
- 失败调用成本。

### 27.3 预算保护

达到预算时：

- 降级到低成本模型；
- 缩小查询范围；
- 禁止高成本任务；
- 提示管理员；
- 不影响WAF核心功能。

### 27.4 防止配额绕过

配额必须在服务端按真实用户、角色、会话和任务统计，不能依赖前端计数。

---

## 二十八、前端页面

阶段7新增：

```text
AI安全运营
├── AI安全助手
├── AI事件分析
├── AI攻击画像
├── AI攻击链
├── AI策略建议
├── AI报告总结
└── AI任务记录

AI管理
├── 模型管理
├── Agent管理
├── Tool管理
├── Prompt管理
├── Memory管理
├── 配额与成本
└── AI审计
```

### 28.1 AI安全助手

支持：

- 新建会话；
- 会话历史；
- 流式回答；
- 停止生成；
- 继续生成；
- 重试；
- 复制；
- 导出；
- 证据引用；
- Tool调用步骤摘要；
- 草稿生成；
- 用户反馈；
- 上下文使用量；
- 自动压缩提示；
- 当前模型和降级状态。

### 28.2 AI事件分析页

从安全事件详情一键发起分析，自动带入事件ID、Request ID、应用和时间范围。

### 28.3 AI策略建议页

展示建议类型、当前配置、推荐配置、证据、风险、影响范围、模拟结果、草稿状态和审核状态。

### 28.4 模型管理页

展示供应商、模型、能力、上下文、最大输出、Tool支持、状态、优先级、成本和最近测试。密钥只允许设置和轮换，不显示明文。

### 28.5 Agent和Tool管理页

展示名称、版本、状态、Prompt版本、允许Tool、权限、风险等级、最近调用、错误率和平均耗时。

### 28.6 Prompt管理页

支持草稿、版本、Diff、测试结果、对抗测试、发布、回滚和历史记录。

### 28.7 Memory管理页

支持按会话、项目、用户、来源、置信度和状态查询，并允许用户管理自己的长期记忆。

### 28.8 AI审计页

支持按用户、会话、Agent、Tool、任务类型、模型、Prompt版本、时间和草稿查询。

---

## 二十九、数据库设计

至少新增以下表。

### 29.1 ai_model_providers

```text
id
name
provider_type
base_url
api_key_reference
status
created_at
updated_at
```

### 29.2 ai_models

```text
id
provider_id
model_code
display_name
context_window
max_output_tokens
supports_tools
supports_streaming
supports_structured_output
supports_embeddings
priority
timeout_seconds
cost_input_unit
cost_output_unit
status
created_at
updated_at
```

### 29.3 ai_sessions

```text
id
user_id
title
status
project_scope
application_ids
context_summary
context_token_count
created_at
updated_at
archived_at
```

### 29.4 ai_messages

```text
id
session_id
role
content
content_masked
model_id
prompt_version_id
input_tokens
output_tokens
finish_reason
created_at
```

### 29.5 ai_tasks

```text
id
session_id
task_type
status
risk_level
plan_summary
started_at
finished_at
failure_code
failure_message
created_at
```

任务状态：

```text
PENDING
PLANNING
RUNNING
WAITING_TOOL
COMPOSING
SUCCESS
PARTIAL_SUCCESS
FAILED
CANCELLED
```

### 29.6 ai_agent_runs

```text
id
task_id
agent_id
status
input_summary
output_summary
started_at
finished_at
model_id
input_tokens
output_tokens
error_code
created_at
```

### 29.7 ai_tool_calls

```text
id
task_id
agent_run_id
tool_id
tool_version
risk_level
input_summary
output_reference
status
duration_ms
error_code
created_at
```

### 29.8 ai_agents

```text
id
code
name
description
prompt_id
allowed_tool_ids
status
version
created_at
updated_at
```

### 29.9 ai_tools

```text
id
code
name
description
version
risk_level
required_permission
input_schema
output_schema
timeout_seconds
max_results
status
created_at
updated_at
```

### 29.10 ai_prompts

```text
id
code
name
prompt_type
status
current_version_id
created_by
created_at
updated_by
updated_at
```

### 29.11 ai_prompt_versions

```text
id
prompt_id
version_number
content
content_hash
change_summary
test_result
created_by
created_at
published_by
published_at
is_current
```

### 29.12 ai_memories

```text
id
user_id
memory_scope
scope_reference
content
confidence_type
source_type
source_reference
status
last_used_at
created_at
updated_at
```

### 29.13 ai_recommendations

```text
id
task_id
recommendation_type
target_type
target_id
summary
evidence_references
risk_level
status
draft_reference
created_by_ai
reviewed_by
reviewed_at
created_at
```

推荐状态：

```text
DRAFT
PENDING_REVIEW
ACCEPTED
REJECTED
EXPIRED
```

### 29.14 ai_context_compressions

```text
id
session_id
before_tokens
after_tokens
summary
preserved_references
compression_reason
created_at
```

### 29.15 ai_feedback

```text
id
session_id
message_id
user_id
rating
feedback_type
comment
created_at
```

### 29.16 ai_evaluation_runs

```text
id
evaluation_set_id
model_id
prompt_version_id
status
score
details
started_at
finished_at
created_at
```

### 29.17 ai_usage_records

```text
id
user_id
session_id
task_id
model_id
input_tokens
output_tokens
tool_calls
estimated_cost
created_at
```

### 29.18 索引要求

至少为用户、会话、任务状态、任务类型、Agent、Tool、Prompt版本、创建时间、草稿引用和审计查询建立索引。

---

## 三十、接口设计

### 30.1 会话和消息

```text
GET    /api/v1/ai/sessions
POST   /api/v1/ai/sessions
GET    /api/v1/ai/sessions/{id}
PATCH  /api/v1/ai/sessions/{id}
DELETE /api/v1/ai/sessions/{id}
POST   /api/v1/ai/sessions/{id}/archive
POST   /api/v1/ai/sessions/{id}/messages
POST   /api/v1/ai/sessions/{id}/stop
POST   /api/v1/ai/sessions/{id}/continue
POST   /api/v1/ai/messages/{id}/retry
POST   /api/v1/ai/messages/{id}/feedback
```

### 30.2 AI分析

```text
POST /api/v1/ai/analyze/security-event
POST /api/v1/ai/analyze/false-positive
POST /api/v1/ai/analyze/attack-profile
POST /api/v1/ai/analyze/attack-chain
POST /api/v1/ai/analyze/root-cause
POST /api/v1/ai/analyze/policy
POST /api/v1/ai/analyze/what-if
POST /api/v1/ai/analyze/report-summary
```

### 30.3 草稿和推荐

```text
POST /api/v1/ai/drafts/exception
POST /api/v1/ai/drafts/blacklist
POST /api/v1/ai/drafts/cc-policy
POST /api/v1/ai/drafts/custom-rule
GET  /api/v1/ai/recommendations
GET  /api/v1/ai/recommendations/{id}
POST /api/v1/ai/recommendations/{id}/accept
POST /api/v1/ai/recommendations/{id}/reject
```

接受推荐仅代表进入人工草稿流程，不代表发布。

### 30.4 模型管理

```text
GET    /api/v1/ai/models
POST   /api/v1/ai/models
GET    /api/v1/ai/models/{id}
PUT    /api/v1/ai/models/{id}
DELETE /api/v1/ai/models/{id}
POST   /api/v1/ai/models/{id}/test
POST   /api/v1/ai/models/{id}/enable
POST   /api/v1/ai/models/{id}/disable
POST   /api/v1/ai/models/{id}/rotate-key
```

### 30.5 Agent和Tool

```text
GET  /api/v1/ai/agents
GET  /api/v1/ai/agents/{id}
PUT  /api/v1/ai/agents/{id}
POST /api/v1/ai/agents/{id}/test

GET  /api/v1/ai/tools
GET  /api/v1/ai/tools/{id}
PUT  /api/v1/ai/tools/{id}
POST /api/v1/ai/tools/{id}/test
```

### 30.6 Prompt

```text
GET    /api/v1/ai/prompts
POST   /api/v1/ai/prompts
GET    /api/v1/ai/prompts/{id}
PUT    /api/v1/ai/prompts/{id}
POST   /api/v1/ai/prompts/{id}/versions
GET    /api/v1/ai/prompts/{id}/versions
GET    /api/v1/ai/prompts/{id}/diff
POST   /api/v1/ai/prompts/{id}/test
POST   /api/v1/ai/prompts/{id}/publish
POST   /api/v1/ai/prompts/{id}/rollback
```

### 30.7 Memory

```text
GET    /api/v1/ai/memories
POST   /api/v1/ai/memories
PATCH  /api/v1/ai/memories/{id}
DELETE /api/v1/ai/memories/{id}
POST   /api/v1/ai/memories/{id}/disable
```

### 30.8 审计、用量和评估

```text
GET /api/v1/ai/audits
GET /api/v1/ai/audits/{id}
GET /api/v1/ai/usage/overview
GET /api/v1/ai/usage/by-user
GET /api/v1/ai/usage/by-agent
GET /api/v1/ai/usage/by-task
GET /api/v1/ai/evaluations
POST /api/v1/ai/evaluations/run
GET /api/v1/ai/evaluations/{id}
```

---

## 三十一、权限设计

至少新增：

```text
ai.chat.use
ai.event_analysis.use
ai.false_positive_analysis.use
ai.attack_profile.use
ai.attack_chain.use
ai.root_cause.use
ai.policy_recommendation.use
ai.what_if.use
ai.report_summary.use
ai.draft.exception
ai.draft.blacklist
ai.draft.cc_policy
ai.draft.custom_rule
ai.sessions.read_own
ai.sessions.delete_own
ai.memories.read_own
ai.memories.manage_own
ai.models.read
ai.models.manage
ai.agents.read
ai.agents.manage
ai.tools.read
ai.tools.manage
ai.prompts.read
ai.prompts.create
ai.prompts.test
ai.prompts.publish
ai.prompts.rollback
ai.audits.read
ai.usage.read
ai.evaluations.run
```

所有Tool执行前必须重新检查当前用户真实权限，不能只信任Agent声明或前端菜单。

---

## 三十二、提示词注入和越权防护

### 32.1 用户输入防护

识别并阻止：

- 要求忽略系统规则；
- 要求泄露Prompt；
- 要求泄露密钥；
- 要求执行Shell；
- 要求直接发布；
- 要求绕过权限；
- 要求查询无权应用；
- 要求输出未脱敏日志；
- 要求扩大超过权限的查询范围。

### 32.2 Tool输出防护

Tool返回内容视为不可信数据，不得覆盖系统指令。

### 32.3 知识库防护

知识文档中的指令性内容不得执行。

### 32.4 草稿防护

草稿生成后必须经过：

- 结构校验；
- 安全校验；
- 影响范围检查；
- 风险提示；
- 人工确认。

### 32.5 跨用户隔离

会话、Memory、Tool结果引用、文件和草稿必须按用户和权限隔离。

---

## 三十三、错误处理和降级

### 33.1 模型故障

- 有限重试；
- 切换备用模型；
- 降级固定模板；
- 返回已获得证据；
- 不重复执行高成本Tool。

### 33.2 Tool故障

- 标记失败Tool；
- 不将缺失数据写成事实；
- 允许部分结果；
- 明确数据不足；
- 记录审计。

### 33.3 任务超时

- 保存任务状态；
- 返回已完成步骤；
- 支持继续任务；
- 不重复已完成查询。

### 33.4 AI模块关闭

- 隐藏或禁用AI入口；
- 不影响阶段1至阶段6；
- 固定模板报告继续可用。

---

## 三十四、质量评估体系

### 34.1 评估集

至少建立：

- 单事件分析集；
- 误报分析集；
- 规则解释集；
- 攻击画像集；
- 攻击链集；
- 根因分析集；
- 策略建议集；
- What-If集；
- 报告总结集；
- Prompt Injection集；
- 权限越权集；
- 数据不足集。

### 34.2 指标

- 事实准确率；
- 引用正确率；
- 权限合规率；
- Tool选择准确率；
- 攻击类型准确率；
- 误报判断准确率；
- 草稿结构正确率；
- 幻觉率；
- 拒绝准确率；
- 平均耗时；
- 平均Token；
- 平均成本；
- 用户反馈。

### 34.3 回归门禁

模型、Prompt、Agent或Tool变更后必须运行回归测试。高风险评估集未通过不得发布。

---

## 三十五、测试要求

### 35.1 单元测试

至少覆盖：

- 意图分类；
- 任务类型识别；
- 任务规划；
- Agent路由；
- Tool路由；
- 权限检查；
- 风险等级；
- 结构化输出；
- 引用格式；
- Memory写入规则；
- 上下文预算；
- 自动压缩；
- 继续输出；
- 模型降级；
- Tool重试；
- 草稿标记；
- 成本计算；
- 审计脱敏；
- 任务状态流转；
- 并发任务限制。

### 35.2 接口测试

覆盖：

- 新建、查询、归档和删除会话；
- 多轮消息；
- 停止、继续和重试；
- 反馈；
- 事件分析；
- 误报分析；
- 攻击画像；
- 攻击链；
- 根因分析；
- 策略建议；
- What-If；
- 报告总结；
- 草稿生成；
- 模型管理；
- Agent和Tool管理；
- Prompt版本和回滚；
- Memory管理；
- AI审计；
- 配额和越权。

### 35.3 Tool测试

每个Tool必须测试：

- 正常查询；
- 空结果；
- 大结果；
- 分页；
- 超时；
- 权限不足；
- 非法参数；
- 时间范围过大；
- 返回脱敏；
- 审计记录；
- 重试；
- 服务不可用；
- 结果引用。

### 35.4 Agent测试

每个Agent至少测试：

- 正常任务；
- 模糊任务；
- 数据不足；
- Tool失败；
- 权限不足；
- 多Agent协同；
- 结果冲突；
- 任务中断；
- 继续执行；
- 模型降级。

### 35.5 幻觉测试

验证AI不得编造：

- 不存在的事件；
- 不存在的规则；
- 不存在的应用；
- 不存在的配置版本；
- 不存在的攻击成功；
- 不存在的统计数字；
- 不存在的发布结果；
- 不存在的威胁情报；
- 不存在的证书状态；
- 不存在的系统告警。

### 35.6 Prompt Injection测试

至少包括：

- 用户直接注入；
- 日志内容注入；
- URI参数注入；
- User-Agent注入；
- 知识库文档注入；
- Tool输出注入；
- 报告内容注入；
- 事件备注注入；
- 文件名和文档元数据注入。

### 35.7 长上下文测试

至少测试：

- 50轮会话；
- 100轮会话；
- 大量Tool结果；
- 自动压缩；
- 压缩后继续任务；
- 压缩后权限、目标和时间范围不丢失；
- 长报告续写；
- 输出长度中断后继续；
- 多次压缩后的引用完整性。

### 35.8 多Agent协同测试

覆盖：

- 事件Agent和日志Agent；
- 策略Agent和知识库Agent；
- 运维Agent和日志Agent；
- 报告Agent和统计Tool；
- 多Agent结果冲突；
- 子任务失败；
- 并发限制；
- 总调度结果合并；
- 重复Tool调用抑制。

### 35.9 性能和成本测试

至少测试：

- 100并发AI会话；
- 20并发复杂分析；
- 10并发攻击链任务；
- Tool查询大数据集；
- 流式首Token时间；
- 完整回答时间；
- 平均输入Token；
- 平均输出Token；
- 单任务成本；
- 模型故障切换；
- Valkey会话缓存异常；
- 配额达到后的降级。

### 35.10 安全测试

至少执行：

- Prompt Injection；
- Tool越权；
- 水平越权；
- 垂直越权；
- SQL注入；
- 日志查询注入；
- SSRF；
- 模型密钥泄露；
- Prompt泄露；
- 私钥泄露；
- 未脱敏日志泄露；
- 任意文件读取；
- Shell执行；
- Docker Socket访问；
- Caddy Socket访问；
- 草稿直接生效；
- 审计删除；
- 配额绕过；
- 会话跨用户读取；
- Memory跨用户读取；
- 存储型XSS；
- Markdown链接注入；
- Tool结果注入；
- Token耗尽；
- 超长输入；
- 恶意知识库文件；
- 模型故障时权限降级错误。

高危问题未修复不得通过阶段7。

---

## 三十六、Playwright E2E场景

### 场景一：事件AI分析

1. 安全管理员登录；
2. 打开真实安全事件；
3. 点击AI分析；
4. 查看攻击类型、证据和建议；
5. 打开引用事件和规则；
6. 确认回答与真实数据一致。

### 场景二：误报和例外草稿

1. 打开已确认误报事件；
2. 发起AI误报分析；
3. 查看推荐例外范围；
4. 生成例外草稿；
5. 验证草稿为DRAFT；
6. 验证未自动发布；
7. 进入阶段4测试和发布流程。

### 场景三：攻击画像和黑名单草稿

1. 选择攻击源IP；
2. 生成7天画像；
3. 查看攻击类型、应用、URI和趋势；
4. 生成黑名单草稿；
5. 验证未自动封禁。

### 场景四：攻击链

1. 选择时间范围和应用；
2. 发起攻击链分析；
3. 查看时间线和置信度；
4. 打开关联事件；
5. 验证每一步证据引用。

### 场景五：根因分析

1. 制造测试采集器积压；
2. 发起“为什么事件延迟”；
3. 验证AI读取状态、告警、日志和配置变更；
4. 验证输出已确认、高概率和待验证原因；
5. 验证未自动重启服务。

### 场景六：上下文压缩

1. 连续执行多轮分析；
2. 达到压缩阈值；
3. 验证自动压缩；
4. 验证任务目标、权限、时间范围和证据未丢失；
5. 验证继续输出不重复。

### 场景七：Prompt Injection

1. 在事件备注中写入恶意指令；
2. 发起AI分析；
3. 验证AI将其视为数据；
4. 验证未泄露Prompt；
5. 验证未调用越权Tool。

### 场景八：模型故障降级

1. 禁用主模型；
2. 发起事件分析；
3. 验证切换备用模型；
4. 查看降级提示；
5. 验证WAF核心功能不受影响。

### 场景九：审计管理员

1. 审计管理员登录；
2. 查看AI会话审计；
3. 查看Tool调用；
4. 查看草稿来源；
5. 尝试使用变更草稿Tool；
6. 验证被拒绝。

---

## 三十七、自动化命令

```bash
make ai-build
make ai-migrate
make ai-seed
make ai-model-test
make ai-tool-test
make ai-agent-test
make ai-prompt-test
make ai-evaluation
make stage7-up
make stage7-status
make stage7-test-unit
make stage7-test-api
make stage7-test-tools
make stage7-test-agents
make stage7-test-rag
make stage7-test-memory
make stage7-test-context
make stage7-test-injection
make stage7-test-hallucination
make stage7-test-e2e
make stage7-test-performance
make stage7-test-cost
make stage7-test-security
make stage7-test-all
make stage7-down
```

要求：

- 可重复执行；
- 失败返回非零状态；
- 显示总数、通过、失败和跳过；
- 显示平均Token、成本和耗时；
- 不依赖手工进入容器修改；
- 不使用Mock结果冒充真实模型和Tool测试。

---

## 三十八、文档要求

必须完成：

```text
docs/AI_SOC_ARCHITECTURE.md
docs/AI_ORCHESTRATOR_DESIGN.md
docs/AI_AGENT_DESIGN.md
docs/AI_TOOL_DESIGN.md
docs/AI_TOOL_SECURITY.md
docs/AI_MODEL_GATEWAY.md
docs/AI_MEMORY_DESIGN.md
docs/AI_CONTEXT_COMPRESSION.md
docs/AI_PROMPT_MANAGEMENT.md
docs/AI_RAG_SECURITY.md
docs/AI_AUDIT_DESIGN.md
docs/AI_COST_CONTROL.md
docs/AI_EVALUATION_GUIDE.md
docs/AI_SECURITY_TEST_GUIDE.md
docs/STAGE7_TEST_REPORT.md
docs/API_DESIGN.md
docs/SECURITY_DESIGN.md
docs/DEVELOPMENT_STATUS.md
```

---

## 三十九、阶段退出条件

以下条件全部满足才允许标记“阶段7通过”：

1. AI模块可以独立启停；
2. AI模块关闭不影响WAF核心功能；
3. 模型网关支持主模型和备用模型；
4. 支持按任务路由模型；
5. 模型密钥加密且不返回前端；
6. 模型健康检查可用；
7. AI安全助手支持多轮会话；
8. 流式输出、停止、重试和继续可用；
9. 输出长度中断后可从断点继续；
10. 会话历史可查询、归档和删除；
11. 上下文使用量可以统计；
12. 自动压缩可以触发；
13. 压缩后任务目标和安全约束不丢失；
14. 会话记忆可用；
15. 项目记忆可用；
16. 长期记忆可查看、修改、禁用和删除；
17. AI推测不会自动写入长期记忆；
18. 敏感信息不会写入长期记忆；
19. AI Orchestrator可识别任务类型；
20. 复杂任务可生成计划摘要；
21. 多Agent调度可用；
22. Agent调用有状态和错误记录；
23. 每个Agent只能调用允许的Tool；
24. Tool具有输入输出Schema；
25. Tool具有超时、返回数量和审计限制；
26. 所有Tool执行前重新检查用户权限；
27. AI不能直接访问数据库；
28. AI不能执行原始SQL；
29. AI不能执行Shell；
30. AI不能访问Docker Socket；
31. AI不能访问Caddy管理Socket；
32. 安全事件AI分析可用；
33. 事件分析包含真实证据引用；
34. 数据不足时不会编造结论；
35. 攻击是否成功不会仅根据规则命中判断；
36. AI误报分析可用；
37. 例外草稿默认范围精确；
38. AI规则解释可用；
39. IP画像可用；
40. URI画像可用；
41. 应用画像可用；
42. 攻击链分析可用；
43. 攻击链每一步有证据和置信度；
44. 根因分析可用；
45. 根因分析区分确认、高概率和待验证原因；
46. 策略推荐可用；
47. 策略建议显示当前值、建议值、依据、风险和验证方法；
48. What-If模拟基于历史数据；
49. 模拟结果明确标注估算性质；
50. AI报告总结基于阶段6真实统计；
51. 报告数字均可追溯；
52. 例外、黑名单、CC和自定义规则只能生成草稿；
53. AI草稿不会自动发布；
54. 草稿带来源会话、任务和证据；
55. Prompt可以版本化；
56. Prompt可以测试、发布和回滚；
57. Prompt变更经过回归和对抗测试；
58. 知识库内容不能覆盖系统指令；
59. Tool输出不能覆盖系统指令；
60. Prompt Injection测试通过；
61. 知识库注入测试通过；
62. Tool输出注入测试通过；
63. 幻觉测试通过；
64. 水平和垂直越权测试通过；
65. 会话和Memory跨用户隔离；
66. AI审计记录用户、任务、Agent、Tool、模型、Prompt版本、Token、成本和结果；
67. AI审计不保存私有思维链；
68. AI审计敏感信息已经脱敏；
69. AI审计完整性校验可用；
70. 成本和配额控制可用；
71. 配额不能通过前端绕过；
72. 模型故障可以降级；
73. Tool故障不会生成虚假事实；
74. 长上下文测试通过；
75. 多Agent协同测试通过；
76. 单元测试通过；
77. 接口测试通过；
78. Tool测试通过；
79. Agent测试通过；
80. E2E测试通过；
81. 性能和成本测试完成；
82. 安全测试无未修复高危问题；
83. Docker Compose可以一键启动和停止；
84. 文档与实际功能一致；
85. 未使用Mock数据冒充真实分析；
86. 未实现AI自动发布、自动封禁和自动恢复；
87. 未提前开发阶段8功能；
88. `docs/DEVELOPMENT_STATUS.md`已经更新。

任何一项未满足，不得标记“阶段7通过”。

---

## 四十、执行顺序

```text
检查阶段1至阶段6真实状态
    ↓
设计AI安全边界和权限模型
    ↓
设计数据库和迁移
    ↓
开发模型网关
    ↓
开发会话、消息和流式输出
    ↓
开发上下文管理和自动压缩
    ↓
开发Memory
    ↓
开发Tool Registry和权限校验
    ↓
开发只读Tool
    ↓
开发草稿Tool
    ↓
开发Agent Registry
    ↓
开发专业Agent
    ↓
开发AI Orchestrator和任务规划
    ↓
开发证据引用和Risk Guard
    ↓
开发事件分析和误报分析
    ↓
开发规则解释和攻击画像
    ↓
开发攻击链和根因分析
    ↓
开发策略推荐和What-If
    ↓
开发AI报告总结
    ↓
开发Prompt管理
    ↓
开发模型、Agent、Tool和Memory管理页面
    ↓
开发AI审计和成本控制
    ↓
开发评估集和回归门禁
    ↓
执行单元、接口、Tool和Agent测试
    ↓
执行长上下文和压缩测试
    ↓
执行Prompt Injection和幻觉测试
    ↓
执行E2E、性能、成本和安全测试
    ↓
编写测试报告
```

完成阶段7后立即停止，不得自行进入阶段8。

---

## 四十一、禁止事项

1. AI直接访问数据库；
2. AI执行原始SQL；
3. AI执行Shell；
4. AI访问Docker Socket；
5. AI访问Caddy管理Socket；
6. AI直接写配置文件；
7. AI直接发布策略；
8. AI直接封禁或解封IP；
9. AI直接关闭规则；
10. AI直接创建永久例外；
11. AI直接执行升级或恢复；
12. AI删除事件或审计；
13. Tool输出覆盖系统指令；
14. 知识库内容覆盖系统指令；
15. 模型密钥进入Prompt或日志；
16. 保存模型私有思维链；
17. 编造不存在的数据；
18. 无证据确认攻击成功；
19. 无证据确认系统被入侵；
20. 自动保存AI推测为长期记忆；
21. 保存完整攻击载荷到长期记忆；
22. 不同用户读取彼此会话和Memory；
23. 审计管理员生成生产变更草稿；
24. 系统管理员默认生成WAF策略草稿；
25. 前端直接调用模型供应商；
26. 前端直接调用内部Tool；
27. 未经权限检查调用Tool；
28. Tool返回密码、Token、Cookie或私钥；
29. 草稿生成后自动发布；
30. Prompt修改后跳过回归测试；
31. 删除失败用例使测试通过；
32. 使用Mock数据冒充真实事件分析；
33. 将性能目标写成实际结果；
34. 提前开发阶段8的API安全、Bot、威胁情报和集群功能。

---

## 四十二、Agent最终输出格式

### 1. 阶段结论

只能选择：

```text
阶段7通过
阶段7有条件通过
阶段7未通过
```

### 2. 实际完成项

逐项列出真实完成的功能。

### 3. 未完成项

列出全部未完成内容，不得隐瞒。

### 4. 新增和修改文件

按以下模块列出：

- AI服务；
- 模型网关；
- Orchestrator；
- Agent；
- Tool；
- Memory；
- Prompt；
- 前端；
- 数据库迁移；
- 测试；
- 部署；
- 文档。

### 5. 数据库迁移

列出迁移版本、新增表、索引、外键、唯一约束、初始化数据和回滚验证。

### 6. 模型配置

列出供应商、模型、上下文长度、最大输出、Tool支持、结构化输出、主模型、备用模型、本地模型和健康检查结果。不得输出密钥。

### 7. Agent和Tool

列出Agent总数、名称、Tool总数、名称、风险等级、所需权限、平均耗时和错误率。

### 8. AI功能验证

至少列出：

- 安全事件分析；
- 误报分析；
- 规则解释；
- IP画像；
- URI画像；
- 应用画像；
- 攻击链；
- 根因分析；
- 策略推荐；
- What-If；
- 例外草稿；
- 黑名单草稿；
- CC草稿；
- 自定义规则草稿；
- 日报、周报和月报AI总结。

### 9. 测试结果

必须列出：

```text
单元测试总数和通过数
接口测试总数和通过数
Tool测试总数和通过数
Agent测试总数和通过数
Memory测试总数和通过数
Context测试总数和通过数
Prompt Injection测试总数和通过数
幻觉测试总数和通过数
权限测试总数和通过数
E2E测试总数和通过数
性能测试场景数和通过数
安全测试总数和通过数
失败数
跳过数
```

### 10. 性能和成本

列出测试环境、并发会话、首Token时间、完整回答P50和P95、Tool平均耗时、平均输入输出Token、单任务平均成本、单用户每日成本、模型故障切换时间、CPU和内存。

### 11. 安全检查

说明：

- AI是否直接访问数据库；
- 是否可执行Shell；
- 是否可直接发布；
- Tool权限是否后端校验；
- 模型密钥是否安全；
- Prompt Injection是否通过；
- 知识库和Tool输出注入是否通过；
- 会话和Memory是否隔离；
- AI审计是否脱敏；
- 是否保存私有思维链；
- 是否存在未修复高危问题。

### 12. 遗留问题

每个问题包含问题描述、影响范围、风险等级、当前处理、后续建议和是否影响阶段8。

### 13. 退出条件

逐项列出未满足的阶段退出条件。

完成阶段7后停止，不得自行进入阶段8。

---

## 四十三、交给Agent的执行指令

请严格按照：

```text
docs/tasks/STAGE_7_AI_SECURITY_OPERATIONS.md
```

执行阶段7。

执行要求：

1. 先检查阶段1至阶段6真实交付结果；
2. AI模块必须与核心WAF防护解耦；
3. AI不得直接访问数据库、Shell、Docker Socket和Caddy管理Socket；
4. AI只允许只读查询和草稿生成；
5. 所有Tool必须执行后端权限校验；
6. 所有AI事实结论必须引用真实证据；
7. 数据不足时必须明确说明，不得编造；
8. 所有草稿默认DRAFT，不得自动发布；
9. 不得保存模型私有思维链；
10. 所有模型、Agent、Tool、Prompt和草稿操作必须记录审计；
11. 必须完成Prompt Injection、幻觉、权限、长上下文、多Agent、性能、成本和安全测试；
12. 完成全部测试后再判断阶段结论；
13. 阶段7完成后停止；
14. 不得提前开发阶段8。
