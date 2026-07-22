# 九章WEB应用智能防护系统V2.0
## 阶段5：IP访问控制、真实客户端IP识别与CC防护任务书

## 一、阶段目标

阶段5建设九章WEB应用智能防护系统的访问控制和流量防护能力。本阶段完成后，系统应能够准确识别真实客户端IP，安全处理可信代理头，管理全局和应用级IP黑白名单，支持IPv4、IPv6和CIDR，配置应用级与URI级CC防护，并完成临时封禁、自动解封、访问控制事件、策略发布和回滚。

完整链路：

```text
客户端请求
  ↓
九章防护网关
  ↓
提取TCP连接源IP
  ↓
判断连接源是否为可信代理
  ↓
安全解析真实客户端IP
  ↓
保护地址检查
  ↓
全局和应用白名单
  ↓
全局和应用黑名单
  ↓
CC频率检测
  ↓
Coraza WAF检测
  ↓
允许、观察、429拒绝或临时封禁
  ↓
生成访问控制事件
  ↓
管理员解封或调整策略
```

---

## 二、阶段边界

### 2.1 必须开发

- 自主`jiuzhang_guard` Caddy模块；
- 真实客户端IP识别；
- 可信代理管理；
- X-Forwarded-For解析；
- X-Real-IP解析；
- Forwarded解析；
- 一个可配置的自定义真实IP头；
- IPv4和IPv6；
- 代理链长度限制；
- 保护地址；
- 全局白名单；
- 应用白名单；
- 全局黑名单；
- 应用黑名单；
- CIDR匹配；
- 临时和永久访问控制；
- 到期自动失效；
- 批量导入和导出；
- 从安全事件创建黑名单；
- CC策略；
- 按IP、应用、IP+URI限速；
- 令牌桶或滑动窗口；
- 突发容量；
- 观察、429拒绝和临时封禁；
- 自动封禁和自动解封；
- Valkey计数器；
- 内存计数器保护；
- 访问控制事件和CC事件；
- 配置预览、校验、发布、版本和回滚；
- 三权权限和审计；
- 单元、接口、真实网关、性能、E2E和安全测试。

### 2.2 暂不开发

- Bot管理；
- 浏览器挑战；
- JavaScript挑战；
- 验证码挑战；
- 设备指纹和行为分析；
- 机器学习识别；
- 云端威胁情报；
- 地理位置和ASN控制；
- 多节点分布式CC全局一致性；
- DDoS清洗和四层抗D；
- CDN；
- AI自动封禁；
- 多租户限流；
- 安全态势大屏和正式报告。

---

## 三、前置条件

1. 阶段1网关稳定运行；
2. 阶段2身份认证、三权和审计正常；
3. 阶段3应用接入和配置发布正常；
4. 阶段4WAF策略和统一事件中心正常；
5. Request ID可关联访问日志和事件；
6. Valkey稳定运行；
7. 网关能够加载自主Caddy模块；
8. 阶段4已有黑名单草稿入口；
9. Caddy管理接口只通过Unix Socket访问；
10. 发布失败不破坏当前有效配置。

---

## 四、总体架构

```text
九章管理前端
    │
    ▼
九章管理API
    ├── 可信代理服务
    ├── IP访问控制服务
    ├── CC策略服务
    ├── 临时封禁服务
    ├── 访问控制事件服务
    └── 配置发布服务
    │
    ├── PostgreSQL
    ├── Valkey
    └── 网关配置控制器
            │
            ▼
      jiuzhang_guard模块
      ├── 真实IP识别
      ├── 保护地址
      ├── 黑白名单
      ├── CC限速
      ├── 临时封禁
      └── 事件输出
            │
            ▼
      Coraza + OWASP CRS
            │
            ▼
           源站
```

建议目录：

```text
gateway/modules/jiuzhang_guard/
├── clientip/
├── trustedproxy/
├── accesscontrol/
├── cidr/
├── ratelimit/
├── counters/
├── temporaryblock/
├── events/
├── config/
└── tests/

server/internal/
├── trustedproxies/
├── protectedaddresses/
├── accessrules/
├── ratelimitpolicies/
├── temporaryblocks/
├── accesscontrolevents/
└── accesscontrolversions/

web/src/pages/
├── trusted-proxies/
├── access-rules/
├── rate-limit/
├── temporary-blocks/
└── access-control-events/
```

---

## 五、jiuzhang_guard模块

### 5.1 定位

`jiuzhang_guard`为九章自主开发的Caddy模块，负责：

- 真实IP识别；
- 可信代理判断；
- 保护地址；
- 黑白名单；
- CIDR匹配；
- CC计数；
- 限速和临时封禁；
- 自定义429或阻断响应；
- 访问控制事件输出；
- 运行指标。

模块必须代码独立、测试完整、配置结构稳定，不复制商业WAF代码，不引入GPL或AGPL组件。

### 5.2 请求处理顺序

```text
生成Request ID
  ↓
提取连接源IP
  ↓
判断可信代理
  ↓
解析真实客户端IP
  ↓
保护地址检查
  ↓
白名单
  ↓
黑名单
  ↓
CC策略
  ↓
Coraza WAF
  ↓
反向代理
```

白名单默认绕过黑名单和CC，但不绕过基础协议校验，也默认不绕过WAF检测。

---

## 六、真实客户端IP识别

### 6.1 核心原则

只有TCP连接来源属于可信代理时，才能信任代理头；否则必须使用连接源IP。

不得无条件读取：

- `X-Forwarded-For`；
- `X-Real-IP`；
- `Forwarded`；
- CDN自定义头。

### 6.2 支持头

- X-Forwarded-For；
- X-Real-IP；
- Forwarded；
- 一个可配置的自定义真实IP头。

### 6.3 可信代理字段

```text
id
name
cidr
ip_version
header_type
custom_header_name
priority
status
description
created_by
created_at
updated_by
updated_at
deleted_at
version
```

支持单个IPv4、IPv4 CIDR、单个IPv6、IPv6 CIDR、全局可信代理和节点级可信代理。

### 6.4 X-Forwarded-For解析

对于：

```text
client, proxy1, proxy2
```

从右向左连续跳过可信代理，第一个非可信地址作为客户端IP。

要求：

- 最大代理链默认16；
- 非法地址回退连接源IP；
- 重复头和多值头按固定规则处理；
- IPv4映射IPv6规范化；
- 禁止控制字符和换行；
- 自定义头只对指定可信代理生效。

### 6.5 日志字段

```text
client_ip
connection_ip
forwarded_chain_summary
trusted_proxy_used
client_ip_source
```

来源：

```text
CONNECTION
X_FORWARDED_FOR
X_REAL_IP
FORWARDED
CUSTOM_HEADER
```

### 6.6 必须测试

- 直接访问；
- 非可信来源伪造XFF；
- 单级可信代理；
- 多级可信代理；
- 混合可信和非可信代理；
- IPv6；
- IPv4映射IPv6；
- 非法IP；
- 超长代理链；
- 重复代理头；
- 自定义真实IP头。

---

## 七、保护地址

系统自动维护不可封禁或高风险地址：

- 网关节点；
- 管理平台；
- PostgreSQL；
- Valkey；
- 源站；
- 可信代理；
- 回环地址；
- 链路本地地址；
- Docker关键网络；
- 自定义保护地址。

字段：

```text
id
name
address
cidr
address_type
source_type
description
status
created_at
updated_at
```

地址类型：

```text
GATEWAY
MANAGEMENT
UPSTREAM
DATABASE
CACHE
TRUSTED_PROXY
LOOPBACK
LINK_LOCAL
CUSTOM
```

普通接口必须拒绝封禁保护地址并记录高风险审计。

---

## 八、IP访问控制

### 8.1 类型和范围

规则类型：

```text
ALLOW
DENY
```

范围：

```text
GLOBAL
APPLICATION
```

有效期：

```text
PERMANENT
TEMPORARY
```

状态：

```text
DRAFT
ACTIVE
DISABLED
EXPIRED
DELETED
```

### 8.2 支持地址

- 单个IPv4；
- IPv4 CIDR；
- 单个IPv6；
- IPv6 CIDR。

禁止域名、带协议地址、带端口地址、通配字符串和非法掩码。

### 8.3 优先级

```text
全局白名单
  >
应用白名单
  >
全局黑名单
  >
应用黑名单
  >
CC防护
  >
WAF检测
```

同层规则按显式优先级排序。可以记录全部匹配规则，但只执行最终动作。

### 8.4 规则字段

```text
id
name
rule_type
scope_type
application_id
address
cidr
ip_version
priority
status
effective_from
effective_until
reason
source_type
source_event_id
hit_count
last_hit_at
created_by
created_at
updated_by
updated_at
deleted_at
version
```

来源：

```text
MANUAL
SECURITY_EVENT
IMPORT
AUTO_BLOCK
SYSTEM
```

### 8.5 操作

支持新增、编辑、启停、删除、复制、批量导入、批量导出、临时封禁、延期、立即解封、查看命中、查看关联事件、配置预览、发布和回滚。

---

## 九、临时规则和自动失效

支持：

- 15分钟；
- 1小时；
- 4小时；
- 1天；
- 7天；
- 30天；
- 自定义时间；
- 永久。

到期后：

- 标记`EXPIRED`；
- 网关停止执行；
- 清理缓存；
- 记录系统审计；
- 保留历史记录。

数据库使用UTC，前端按系统时区显示。

---

## 十、批量导入和导出

支持CSV和纯文本。

CSV字段：

```text
address
rule_type
scope_type
application_code
effective_until
reason
```

导入前检查：

- IP和CIDR；
- 重复；
- 应用；
- 类型；
- 时间；
- 文件大小；
- 最大行数；
- 保护地址；
- 错误行；
- 导入预览。

支持“全部成功才提交”或“跳过错误行导入有效行”，必须由管理员明确选择。

导出必须防CSV公式注入，对`= + - @`开头内容做安全处理。

---

## 十一、从安全事件加入黑名单

从阶段4事件自动填充：

- 客户端IP；
- 应用；
- 来源事件；
- 攻击类型；
- 封禁原因；
- 建议时长；
- 相关事件数；
- 最近攻击时间。

管理员必须确认：

- 全局或应用级；
- 时长；
- 是否立即发布；
- 是否为共享出口或代理；
- 是否命中保护地址。

不得未经确认自动永久封禁。

---

## 十二、CC防护

### 12.1 策略范围

```text
GLOBAL
APPLICATION
URI
```

重点实现应用级和应用+URI级。

### 12.2 限制维度

```text
CLIENT_IP
APPLICATION
CLIENT_IP_AND_URI
CLIENT_IP_AND_APPLICATION
```

### 12.3 算法

支持令牌桶和滑动窗口中的一种或两种。

推荐：

- 实时限速使用令牌桶；
- 封禁判断使用滑动窗口。

必须在设计文档中说明算法、复杂度、时间精度和故障策略。

### 12.4 字段

```text
id
name
description
scope_type
application_id
uri_match_type
uri_pattern
dimension
algorithm
requests_limit
window_seconds
burst_capacity
action
block_duration_seconds
status
observe_only
priority
effective_from
effective_until
created_by
created_at
updated_by
updated_at
deleted_at
version
```

### 12.5 URI匹配

```text
ALL
EXACT
PREFIX
REGEX
```

正则必须有长度限制、安全校验和执行超时，优先推荐精确和前缀匹配。

---

## 十三、CC动作和响应

动作：

```text
LOG
OBSERVE
REJECT
TEMP_BLOCK
```

### 13.1 观察

只记录，不阻断，生成CC事件。

### 13.2 拒绝

返回：

```text
HTTP 429 Too Many Requests
```

响应头：

```text
Retry-After
X-Jiuzhang-Request-ID
```

不得返回内部阈值、当前计数、算法和节点信息。

### 13.3 临时封禁

- 创建临时封禁记录；
- 后续请求直接拒绝；
- 到期自动解除；
- 支持人工提前解封；
- 记录自动封禁和解封审计。

API应用返回JSON，浏览器应用可返回HTML。响应不得反射未转义用户输入。

---

## 十四、计数器设计

### 14.1 内存计数器

单节点模式可使用内存计数器，但必须：

- 并发安全；
- 自动过期；
- 最大键数量；
- 定期清理；
- 防随机IP和URI无限建键；
- 提供键数量和内存指标。

### 14.2 Valkey计数器

用于：

- 多进程共享；
- 临时封禁；
- 限流窗口；
- 自动解封；
- 管理平台实时查询。

键示例：

```text
cc:{policy_id}:{client_ip_hash}:{uri_hash}
```

不得直接拼接完整URI和未经处理的用户输入。

### 14.3 故障策略

支持：

- Fail-open；
- Fail-closed。

普通业务默认Fail-open，高安全应用可选Fail-closed。无论哪种都必须产生系统告警，不得静默失效。

---

## 十五、自动封禁

触发条件：

- CC连续超限；
- 短时间多次WAF阻断；
- 同一IP命中多个高危规则；
- 管理员手动触发。

阶段5重点实现CC自动封禁。

字段：

```text
id
client_ip
application_id
trigger_type
trigger_policy_id
trigger_event_ids
block_started_at
block_expires_at
status
hit_count
release_type
released_by
released_at
created_at
```

状态：

```text
ACTIVE
EXPIRED
MANUALLY_RELEASED
CANCELLED
```

自动封禁前必须检查白名单、保护地址、可信代理、网关、源站、管理平台和共享NAT风险。

---

## 十六、访问控制事件

事件类型：

```text
IP_ALLOW_MATCH
IP_DENY_MATCH
CC_THRESHOLD_EXCEEDED
CC_REQUEST_REJECTED
CC_TEMP_BLOCK_CREATED
CC_TEMP_BLOCK_EXPIRED
CC_TEMP_BLOCK_RELEASED
TRUSTED_PROXY_INVALID
FORWARDED_HEADER_INVALID
FORWARDED_CHAIN_TOO_LONG
RATE_LIMIT_ENGINE_ERROR
```

字段：

```text
id
request_id
occurred_at
application_id
client_ip
connection_ip
domain
request_method
request_path
event_type
action
policy_id
access_rule_id
current_count
limit_value
window_seconds
block_expires_at
response_status
gateway_node_id
created_at
```

接入阶段4统一事件中心，事件来源增加：

```text
WAF
ACCESS_CONTROL
CC_PROTECTION
SYSTEM
```

不得建立割裂的第二套事件中心。

---

## 十七、配置发布和版本

发布内容：

- 可信代理；
- 真实IP头；
- 保护地址；
- 全局和应用黑白名单；
- CC策略；
- 临时封禁；
- 429页面；
- JSON错误响应。

流程：

```text
保存草稿
  ↓
校验IP和CIDR
  ↓
检查冲突和保护地址
  ↓
检查可信代理
  ↓
校验CC参数
  ↓
校验URI匹配
  ↓
生成jiuzhang_guard配置
  ↓
生成差异和版本
  ↓
网关配置校验
  ↓
发布
  ↓
真实IP测试
  ↓
黑白名单测试
  ↓
CC测试
  ↓
标记生效
```

发布失败时：

- 当前名单和CC继续生效；
- 不清空名单；
- 不关闭CC；
- 不自动切换观察模式；
- 保存错误；
- 支持重试和回滚；
- 记录审计。

版本记录至少包含可信代理配置、访问控制配置、CC配置、保护地址配置、配置哈希、变更摘要、上一版本和发布结果。

---

## 十八、数据库设计

至少新增：

```text
trusted_proxies
protected_addresses
ip_access_rules
rate_limit_policies
temporary_blocks
access_control_events
access_control_versions
rate_limit_runtime_summaries
```

`access_control_events`建议按月分区。

关键索引包括时间、应用、IP、事件类型、动作、策略、规则和Request ID。

---

## 十九、接口设计

### 可信代理

```text
GET    /api/v1/trusted-proxies
POST   /api/v1/trusted-proxies
GET    /api/v1/trusted-proxies/{id}
PUT    /api/v1/trusted-proxies/{id}
DELETE /api/v1/trusted-proxies/{id}
POST   /api/v1/trusted-proxies/{id}/enable
POST   /api/v1/trusted-proxies/{id}/disable
POST   /api/v1/trusted-proxies/test
```

### 保护地址

```text
GET  /api/v1/protected-addresses
POST /api/v1/protected-addresses/refresh
```

### IP访问控制

```text
GET    /api/v1/access-rules
POST   /api/v1/access-rules
GET    /api/v1/access-rules/{id}
PUT    /api/v1/access-rules/{id}
DELETE /api/v1/access-rules/{id}
POST   /api/v1/access-rules/{id}/enable
POST   /api/v1/access-rules/{id}/disable
POST   /api/v1/access-rules/{id}/extend
POST   /api/v1/access-rules/{id}/release
POST   /api/v1/access-rules/import
GET    /api/v1/access-rules/export
POST   /api/v1/access-rules/validate
POST   /api/v1/access-rules/publish
```

### CC策略

```text
GET    /api/v1/rate-limit-policies
POST   /api/v1/rate-limit-policies
GET    /api/v1/rate-limit-policies/{id}
PUT    /api/v1/rate-limit-policies/{id}
DELETE /api/v1/rate-limit-policies/{id}
POST   /api/v1/rate-limit-policies/{id}/enable
POST   /api/v1/rate-limit-policies/{id}/disable
POST   /api/v1/rate-limit-policies/{id}/validate
POST   /api/v1/rate-limit-policies/{id}/test
POST   /api/v1/rate-limit-policies/publish
```

### 临时封禁和事件

```text
GET  /api/v1/temporary-blocks
GET  /api/v1/temporary-blocks/{id}
POST /api/v1/temporary-blocks/{id}/release
POST /api/v1/temporary-blocks/{id}/extend
POST /api/v1/temporary-blocks/{id}/convert-to-permanent

GET /api/v1/access-control-events
GET /api/v1/access-control-events/{id}
GET /api/v1/access-control-events/export
```

### 版本

```text
GET  /api/v1/access-control/versions
GET  /api/v1/access-control/versions/{id}
GET  /api/v1/access-control/versions/{id}/diff
POST /api/v1/access-control/versions/{id}/rollback
```

---

## 二十、权限设计

安全管理员拥有可信代理、访问规则、CC、临时封禁、事件和发布权限。

系统管理员只负责组件状态、系统可信代理和保护地址维护，不得默认创建业务黑名单和CC策略。

审计管理员只读规则、版本、事件和审计记录。

所有权限必须后端校验。

---

## 二十一、前端菜单

```text
访问控制
├── 可信代理
├── IP黑白名单
├── CC防护
├── 临时封禁
└── 访问控制事件
```

页面支持可信代理测试、规则筛选和导入导出、CC分步配置、临时封禁解封和延期、事件查询、配置差异、版本和回滚。

---

## 二十二、性能目标

必须测试：

- 1000条黑名单；
- 10000条黑名单；
- 1000条CIDR；
- 100条CC策略；
- 500 RPS；
- 200并发；
- 随机IP键攻击；
- 随机URI键攻击；
- 长时间内存变化。

初始目标：

- 访问控制新增P95延迟低于5毫秒；
- CC计数新增P95低于10毫秒；
- 500 RPS无持续错误；
- 随机键攻击不无限增长内存；
- 发布期间旧策略持续可用。

必须记录真实环境和结果。

---

## 二十三、测试要求

### 单元测试

覆盖IPv4、IPv6、CIDR、可信代理、XFF、X-Real-IP、Forwarded、超长链、重复头、优先级、保护地址、临时到期、令牌桶、滑动窗口、突发容量、TTL、URI匹配、正则安全、自动封禁、自动解封、Valkey故障、配置生成、哈希和脱敏。

### 接口测试

覆盖可信代理、黑白名单、临时规则、批量导入、保护地址、CC策略、封禁、解封、版本、发布、回滚和越权。

### 真实网关测试

真实IP：

1. 直接请求；
2. 伪造XFF；
3. 可信代理；
4. 多级代理；
5. IPv6；
6. 超长代理链；
7. 非法头。

黑白名单：

1. 应用黑名单；
2. 全局黑名单；
3. 应用白名单；
4. 全局白名单；
5. 冲突优先级；
6. CIDR；
7. IPv6；
8. 临时过期；
9. 被阻断请求未到源站。

CC：

1. 阈值以下；
2. 达阈值429；
3. 突发容量；
4. 不同IP独立计数；
5. 不同URI独立计数；
6. 观察模式；
7. 临时封禁；
8. 自动解封；
9. 白名单绕过；
10. 伪造IP头不能绕过；
11. Valkey中断。

### E2E

至少覆盖：

- 新增可信代理；
- 从事件创建黑名单；
- 白名单优先级；
- CC策略发布；
- 临时封禁和解封；
- 审计管理员只读。

### 安全测试

至少包括XFF伪造、多重代理头绕过、重复头污染、IPv4映射IPv6绕过、CIDR边界绕过、超长链、超大导入、CSV公式注入、正则拒绝服务、随机键耗尽、Valkey键注入、保护地址封禁、白名单越权、CC越权、配置竞争、时间溢出、负数阈值、零窗口、日志注入、存储型XSS和429反射型XSS。

高危问题未修复不得通过。

---

## 二十四、自动化命令

```bash
make guard-build
make guard-test
make trusted-proxy-test
make access-control-test
make rate-limit-test
make stage5-up
make stage5-status
make stage5-test-unit
make stage5-test-api
make stage5-test-gateway
make stage5-test-performance
make stage5-test-e2e
make stage5-test-security
make stage5-test-all
make stage5-down
```

---

## 二十五、文档要求

```text
docs/TRUSTED_PROXY_DESIGN.md
docs/REAL_CLIENT_IP_DESIGN.md
docs/IP_ACCESS_CONTROL_DESIGN.md
docs/RATE_LIMIT_DESIGN.md
docs/JIUZHANG_GUARD_MODULE.md
docs/ACCESS_CONTROL_EVENT_DESIGN.md
docs/STAGE5_TEST_REPORT.md
docs/SECURITY_DESIGN.md
docs/API_DESIGN.md
docs/DEVELOPMENT_STATUS.md
```

---

## 二十六、阶段退出条件

以下条件全部满足才允许“阶段5通过”：

1. jiuzhang_guard可重复构建和真实加载；
2. 真实客户端IP识别可用；
3. 非可信来源伪造代理头无效；
4. 可信代理链解析正确；
5. IPv4和IPv6正确；
6. 超长代理链受限；
7. 可信代理可管理、测试和发布；
8. 保护地址自动生成并受保护；
9. 全局和应用白名单生效；
10. 全局和应用黑名单生效；
11. 优先级正确；
12. IPv4和IPv6 CIDR生效；
13. 临时规则自动过期；
14. 黑名单可人工解封；
15. 可从事件创建并发布黑名单；
16. 导入导出可用；
17. 错误可定位到行；
18. CSV公式注入已防护；
19. CC策略可新增、编辑、测试和发布；
20. 按IP、应用、IP+URI限速生效；
21. 突发容量生效；
22. 观察模式不阻断；
23. 429和Retry-After正确；
24. 临时封禁和自动解封生效；
25. 白名单按设计绕过CC；
26. 伪造IP头不能绕过CC；
27. 随机键攻击不会无限耗尽内存；
28. Valkey故障行为符合配置；
29. 访问控制和CC事件入库；
30. Request ID可关联；
31. 发布失败不影响当前配置；
32. 黑白名单和CC可回滚；
33. 所有策略、封禁和解封有审计；
34. 三权权限正确；
35. 单元、接口、真实网关、E2E、性能和安全测试通过；
36. Docker Compose可一键启动和停止；
37. 文档与实际一致；
38. 未使用Mock结果；
39. 未提前开发阶段6；
40. `docs/DEVELOPMENT_STATUS.md`已更新。

---

## 二十七、执行顺序

```text
检查阶段1至阶段4
  ↓
设计jiuzhang_guard
  ↓
真实客户端IP和可信代理
  ↓
保护地址
  ↓
黑白名单和CIDR
  ↓
临时规则和导入导出
  ↓
从事件加入黑名单
  ↓
CC算法和计数器
  ↓
Valkey支持
  ↓
观察、拒绝和临时封禁
  ↓
自动解封
  ↓
访问控制事件
  ↓
发布、版本和回滚
  ↓
前端
  ↓
全部测试和报告
```

完成后停止，不得进入阶段6。

---

## 二十八、禁止事项

1. 无条件信任代理头；
2. 根据前端传入IP直接封禁；
3. 使用字符串前缀判断CIDR；
4. 使用域名作为IP黑名单；
5. 封禁网关、管理平台、源站或可信代理；
6. 默认白名单绕过全部WAF；
7. 未经确认自动永久封禁；
8. 使用无上限内存Map；
9. 允许随机URI无限建键；
10. Valkey键直接拼接用户输入；
11. Valkey故障时静默关闭防护；
12. 使用危险正则；
13. 返回内部CC阈值；
14. 429页面反射用户输入；
15. 前端直接修改网关配置；
16. 使用Mock请求冒充CC测试；
17. 删除失败用例；
18. 破坏三权边界；
19. 提前开发Bot、挑战、AI封禁和态势大屏。

---

## 二十九、Agent最终输出格式

必须输出：

1. 阶段结论；
2. 实际完成项；
3. 未完成项；
4. 新增和修改文件；
5. 数据库迁移；
6. Guard模块构建方式和Caddy兼容版本；
7. 真实IP识别方式；
8. 限流算法、计数存储和故障策略；
9. 单元、接口、真实IP、黑白名单、CC、性能、前端、E2E和安全测试数据；
10. 性能环境、RPS、并发、P50、P95、P99、错误率、CPU和内存；
11. 伪造XFF、可信代理、IPv6、黑白名单、CIDR、429、临时封禁、自动解封和Valkey故障真实验证；
12. 安全检查；
13. 遗留问题；
14. 未满足退出条件。

执行指令：

```text
请严格按照 docs/tasks/STAGE_5_ACCESS_CONTROL_CC.md 执行阶段5。
先检查阶段1至阶段4真实交付结果。
必须开发并真实加载jiuzhang_guard模块。
不得无条件信任代理请求头。
不得使用Mock数据代替黑名单和CC测试。
所有策略必须后端校验并经过发布验证。
完成全部测试后停止，不得进入阶段6。
```
