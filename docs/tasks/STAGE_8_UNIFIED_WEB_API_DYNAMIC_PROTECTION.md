# 九章WEB应用智能防护系统V2.0
## 阶段8：统一Web与API动态防护、持续发现与运行时安全开发任务书

---

## 一、阶段定位

阶段8在阶段1至阶段7已经完成的网关、身份认证、三权管理、应用接入、WAF策略、安全事件、访问控制、CC防护、运行监控、备份恢复、报表和AI智能安全运营能力之上，建设统一的Web与API动态防护能力。

本阶段不是在现有WAF后面串联一个独立API安全系统，也不是将WAF和API防护作为两个相互独立的流量处理链。

本阶段必须实现：

```text
一套产品
+
一条流量处理链
+
一次协议解析
+
一个统一请求上下文
+
多个检测器共享分析结果
+
一个统一风险决策
+
一个统一事件中心
```

同一份HTTP请求和响应经过一次解析后，同时完成：

- Web攻击检测；
- API自动识别；
- API归一化；
- API用途识别；
- 请求参数动态学习；
- 响应字段动态学习；
- API认证与身份提取；
- API Schema偏离检测；
- API资源消耗检测；
- API敏感数据检测；
- API对象、功能和字段权限风险分析；
- API业务流程和行为异常分析；
- 统一风险计算；
- 统一放行、观察、限流、临时封禁或阻断。

阶段8完成后，产品正式定位为：

> 九章Web动态防护系统：面向Web页面、Web应用接口和互联网API的一体化动态安全防护系统。

同时，阶段8必须为后续独立发布“九章API安全系统”预留清晰的能力边界。未来独立API产品应复用现有底座，包括用户管理、三权管理、安全设置、审计管理、配置发布、版本管理、报表、AI安全运营和统一流量引擎，而不是重新开发一套平台。

---

## 二、最高优先级架构原则

本阶段必须遵守以下原则。

### 2.1 同一请求只解析一次

HTTP头、Cookie、Query、表单、JSON、XML、Multipart、文件元数据、GraphQL参数和响应体不得由WAF、API发现、日志和敏感数据模块重复解析。

### 2.2 Web与API共享统一请求上下文

所有检测器读取同一个`RequestContext`，并将检测结果写回同一上下文。

### 2.3 Web与API不采用互斥分类

一个请求可以同时是：

```text
Web请求
API请求
登录接口
文件上传接口
敏感接口
GraphQL接口
管理接口
```

不得先将请求硬分为“网站流量”或“API流量”，再选择不同系统。

### 2.4 统一决策

所有检测器只输出检测结论，不得各自直接返回阻断响应。最终动作必须由统一决策引擎确定。

### 2.5 统一事件

同一个Request ID下的Web攻击、Schema偏离、认证异常、权限风险、敏感数据和CC命中应归并到一个主事件中，并保留多条检测明细。

### 2.6 动态学习不等于自动放宽

学习模型可以持续变化；正式模型经人工确认后必须冻结。偏离正式模型的请求不得自动反向扩大正式模型。

### 2.7 字段名只是数据

不得针对`username`、`password`、`amount`、`orderId`或任何具体字段名编写固定业务策略。

系统必须对任意字段使用通用学习与检测机制。

### 2.8 运行时一体化，能力域可拆分

当前产品中Web与API能力运行在一条链路内；代码、数据表、服务接口和前端模块必须允许未来将API能力独立打包为“九章API安全系统”。

能力域目录边界与跨域依赖规则按《产品线与分支策略》（docs/BRANCHING_AND_PRODUCT_LINES.md）§5.1 执行：共享底座不得import任一能力域；Web防护域与API能力域不得互相import；API能力域新增代码必须落在 `gateway/modules/api_*`、`server/internal/api_*`、`web/src/pages/api-*` 等对应域目录下，评审时按目录核对归属。

---

## 三、阶段目标

阶段8完成后，系统应具备以下能力：

1. 统一Web与API流量处理链；
2. 统一请求和响应上下文；
3. API流量自动识别；
4. API识别置信度；
5. API自动发现；
6. 动态路径参数识别；
7. API路径归一化；
8. API合并和拆分；
9. REST、JSON、XML、SOAP、GraphQL、Webhook等协议识别；
10. 请求参数提取；
11. 响应字段提取；
12. 参数位置识别；
13. 参数基础类型识别；
14. 参数语义类型推荐；
15. 字符串长度和字符集学习；
16. 数值范围和精度学习；
17. 数组元素和数量学习；
18. 对象字段和嵌套结构学习；
19. 文件类型和大小学习；
20. 条件参数关系学习；
21. 字段间关联关系学习；
22. 请求Schema动态学习；
23. 响应Schema动态学习；
24. 参数和Schema学习版本；
25. 版本差异对比；
26. 模型人工确认；
27. 正式模型冻结；
28. 重新学习分支；
29. 学习样本污染防护；
30. API用途多维识别；
31. API主分类；
32. API操作动作识别；
33. API业务对象识别；
34. API身份要求识别；
35. API敏感度识别；
36. API风险标签；
37. 人工分类；
38. 企业自定义分类；
39. OpenAPI和Swagger导入；
40. 导入规范与流量学习模型对比；
41. Schema偏离检测；
42. 未定义参数检测；
43. 参数类型异常检测；
44. 参数长度异常检测；
45. 参数数值异常检测；
46. 参数枚举异常检测；
47. JSON和XML结构异常检测；
48. 请求体和响应体资源限制；
49. JWT、API Key和Token识别；
50. 身份指纹提取；
51. 按IP、身份、Token、租户和API限流；
52. API敏感数据发现；
53. 响应敏感数据泄露检测；
54. Shadow API发现；
55. Zombie API发现；
56. Deprecated API识别；
57. Debug和测试API识别；
58. API生命周期管理；
59. API安全图谱；
60. API调用拓扑；
61. 用户、身份、API和对象关系；
62. API风险评分；
63. BOLA辅助检测；
64. BFLA辅助检测；
65. 字段级越权辅助检测；
66. Mass Assignment检测；
67. 业务流程偏离检测；
68. 批量抓取和资源滥用检测；
69. 统一风险决策；
70. 统一安全事件；
71. 统一策略发布和版本；
72. 与阶段7 AI安全运营打通；
73. 独立API产品打包边界；
74. 完整数据库、接口、权限和前端；
75. 完整单元、接口、性能和安全测试。

---

## 四、阶段边界

### 4.1 本阶段必须开发

- 统一动态防护引擎；
- 统一`RequestContext`；
- 请求和响应一次解析；
- API自动发现；
- API路径模板化；
- API管理；
- API动态参数微模型；
- 请求和响应Schema；
- 学习任务；
- 候选模型版本；
- 模型差异；
- 人工确认；
- 模型冻结；
- 重新学习；
- API用途识别；
- API多维标签；
- API安全图谱基础版；
- API身份和Token指纹；
- API维度限流；
- 敏感数据发现；
- Schema偏离检测；
- Shadow、Zombie和Deprecated API识别；
- API运行时风险事件；
- BOLA、BFLA和字段权限的规则化基础能力；
- 业务行为基线基础能力；
- 统一策略、决策和事件；
- AI分析工具；
- 未来独立API产品的模块化边界；
- 数据库、API、RBAC、前端、测试和文档。

### 4.2 本阶段暂不开发

- 完整API开发门户；
- API开发者自助注册；
- 完整API网关计费；
- API商业化套餐；
- 服务网格；
- gRPC原生代理；
- Kafka协议安全；
- MQTT协议安全；
- 自动生成SDK；
- 自动生成客户端代码；
- API全生命周期CI/CD平台；
- DAST全量主动扫描；
- API模糊测试平台；
- 自动渗透攻击；
- AI自动修改正式模型；
- AI自动发布模型；
- AI自动关闭API；
- AI自动封禁用户；
- AI自动认定所有BOLA和BFLA；
- 无人工确认的自动字段权限推断；
- 多节点集群；
- SaaS多租户；
- 云端集中管理；
- 完整Bot挑战平台；
- 完整威胁情报平台。

---

## 五、阶段前置条件

阶段8开始前必须确认：

1. 阶段1网关和Coraza运行稳定；
2. 阶段2三权、用户、会话和审计稳定；
3. 阶段3应用、域名、源站、证书和发布回滚稳定；
4. 阶段4WAF策略、规则和事件稳定；
5. 阶段5真实IP、访问控制和CC稳定；
6. 阶段6监控、报表、备份和交付稳定；
7. 阶段7 AI Tool和证据引用机制稳定；
8. Request ID贯穿请求、响应、日志和事件；
9. 网关可获得请求和响应必要数据；
10. 敏感字段和认证凭据具备脱敏机制；
11. 大请求体和大响应体有明确采样和截断策略；
12. 当前系统无未修复高危安全问题；
13. API能力可以独立启停；
14. API能力关闭时不影响WAF核心防护。

---

## 六、总体架构

```text
客户端请求
    ↓
连接与TLS
    ↓
Request ID
    ↓
真实客户端IP
    ↓
HTTP协议解析
    ↓
请求标准化
    ↓
统一RequestContext
    ├── Web/API识别
    ├── 访问控制
    ├── CC与资源保护
    ├── Coraza WAF检测
    ├── API匹配
    ├── API Schema检测
    ├── 身份与Token检测
    ├── 敏感数据检测
    ├── 对象与功能权限检测
    ├── 业务行为检测
    └── 风险聚合
    ↓
统一决策引擎
    ↓
ALLOW / OBSERVE / BLOCK / RATE_LIMIT / TEMP_BLOCK / MASK_RESPONSE
    ↓
源站
    ↓
响应解析
    ↓
响应Schema与敏感数据检测
    ↓
统一事件与API学习
```

建议代码结构：

```text
gateway/
├── dynamic_security/
│   ├── context/
│   ├── parser/
│   ├── normalizer/
│   ├── classifier/
│   ├── detectors/
│   │   ├── waf/
│   │   ├── api_discovery/
│   │   ├── api_schema/
│   │   ├── authentication/
│   │   ├── authorization/
│   │   ├── sensitive_data/
│   │   ├── behavior/
│   │   ├── resource/
│   │   └── lifecycle/
│   ├── decision/
│   ├── events/
│   ├── learning/
│   ├── versioning/
│   └── telemetry/
├── coraza_adapter/
└── caddy_adapter/

api-service/
├── discovery/
├── endpoint/
├── model/
├── learning/
├── version/
├── classification/
├── graph/
├── posture/
├── runtime/
└── export/
```

---

## 七、统一RequestContext

每个请求必须只创建一个上下文，至少包含：

```text
request_id
trace_id
connection_id
connection_ip
client_ip
trusted_proxy_chain
application_id
domain_id
domain
scheme
protocol_version
http_method
raw_path
normalized_path
api_endpoint_id
api_candidate_id
api_confidence
request_content_type
response_content_type
request_headers
request_cookies
query_parameters
path_parameters
form_parameters
json_document
xml_document
multipart_parts
uploaded_files
graphql_operation
graphql_variables
request_body_size
request_body_hash
response_status
response_headers
response_body_size
response_body_hash
authentication_type
identity_fingerprint
token_fingerprint
api_key_fingerprint
session_fingerprint
tenant_fingerprint
device_fingerprint
object_identifiers
waf_matches
api_schema_matches
auth_matches
authorization_matches
sensitive_data_matches
behavior_matches
rate_limit_matches
lifecycle_matches
risk_score
risk_level
final_action
event_id
```

### 7.1 数据最小化

上下文不得长期保存完整密码、Token、Cookie和高敏感数据。

### 7.2 大报文处理

设置：

- 最大完整解析大小；
- 最大采样大小；
- 最大JSON深度；
- 最大XML深度；
- 最大字段数；
- 最大文件元数据数量；
- 响应体采样比例。

### 7.3 上下文扩展

检测器可以写入扩展字段，但必须注册Schema，禁止任意动态字段造成内存失控。

---

## 八、API流量识别

### 8.1 识别原则

不得仅依赖URL包含`/api/`。

综合使用：

- 请求Content-Type；
- 响应Content-Type；
- 请求和响应是否为结构化数据；
- HTTP方法；
- Token、API Key、签名；
- 路径结构；
- 调用客户端；
- User-Agent类型；
- 返回状态码；
- 字段结构稳定性；
- 重复API模式；
- GraphQL特征；
- SOAP特征；
- Webhook特征。

### 8.2 识别结果

```text
CONFIRMED_API
PROBABLE_API
POSSIBLE_API
NON_API
```

同时保存0至100置信度。

### 8.3 人工操作

管理员可以：

- 确认为API；
- 标记非API；
- 忽略；
- 合并；
- 拆分；
- 修改路径模板；
- 修改协议类型；
- 修改所属应用；
- 锁定识别结果。

人工锁定后，自动识别不得覆盖。

---

## 九、API协议类型

至少支持识别：

```text
REST_JSON
REST_XML
FORM_API
SOAP
GRAPHQL
JSON_RPC
XML_RPC
WEBHOOK
FILE_UPLOAD
FILE_DOWNLOAD
WEBSOCKET_HANDSHAKE
SERVER_SENT_EVENTS
UNKNOWN_HTTP_API
```

每个API必须记录：

- 协议类型；
- 请求格式；
- 响应格式；
- 认证方式；
- 是否双向数据；
- 是否文件接口；
- 是否长连接入口。

---

## 十、API唯一标识和路径归一化

### 10.1 唯一键

```text
application_id
+
domain_id
+
http_method
+
normalized_path
+
protocol_type
```

### 10.2 动态路径识别

识别：

- 整数；
- 长整数；
- UUID；
- 雪花ID；
- 日期；
- 时间；
- 时间戳；
- 哈希；
- 文件名；
- 业务编号；
- 随机字符串；
- 枚举路径；
- 自定义模式。

### 10.3 归一化示例

```text
/api/users/10001
/api/users/10002
```

归一化为：

```text
/api/users/{integer}
```

管理员可将`{integer}`改名为`{userId}`。

### 10.4 合并安全

不得仅因为路径位置均为数字就自动合并。必须结合：

- 前后路径段；
- HTTP方法；
- 请求和响应结构；
- 参数类型；
- 用途分类；
- 状态码；
- 人工规则。

### 10.5 API拆分

同一路径在以下情况下可以拆分：

- Content-Type不同；
- GraphQL operation不同；
- 认证方式不同；
- 请求Schema完全不同；
- 响应Schema完全不同；
- 管理员明确拆分。

---

## 十一、API资产状态

```text
DISCOVERED
LEARNING
ACTIVE
SHADOW
ZOMBIE
DEPRECATED
DEBUG
TEST
INTERNAL
EXTERNAL
OFFLINE
IGNORED
ARCHIVED
```

### 11.1 Shadow API

符合以下条件之一：

- 流量发现但未登记；
- 不在导入规范；
- 不在资产清单；
- 无负责人；
- 无正式版本；
- 无策略绑定。

### 11.2 Zombie API

符合以下条件之一：

- 标记下线但仍有流量；
- 旧版本仍在被调用；
- 长期无维护但仍暴露；
- 已替代API仍可访问。

### 11.3 Deprecated API

由管理员或导入规范明确标记弃用。

### 11.4 状态变化审计

所有状态变化必须记录原状态、新状态、原因、操作者和时间。

---

## 十二、API学习状态

资产状态与模型状态分离。

```text
NOT_STARTED
LEARNING
CANDIDATE
REVIEW_PENDING
CONFIRMED
PROTECTING
RELEARNING
REJECTED
SUPERSEDED
ARCHIVED
```

推荐流程：

```text
发现API
  ↓
开始学习
  ↓
生成候选版本
  ↓
待人工确认
  ↓
确认正式模型
  ↓
观察或防护
```

---

## 十三、通用参数标识

任何字段均按以下组合识别：

```text
api_endpoint_id
+
direction
+
parameter_location
+
structured_path
+
parameter_name
```

其中：

```text
direction = REQUEST | RESPONSE
```

参数位置：

```text
PATH
QUERY
HEADER
COOKIE
FORM
JSON_BODY
XML_BODY
SOAP_HEADER
SOAP_BODY
MULTIPART
FILE_METADATA
GRAPHQL_ARGUMENT
GRAPHQL_VARIABLE
RESPONSE_HEADER
RESPONSE_BODY
```

禁止将相同字段名跨API直接合并学习。

---

## 十四、参数基础类型

```text
STRING
INTEGER
LONG
FLOAT
DECIMAL
BOOLEAN
NULL
OBJECT
ARRAY
FILE
BINARY
MIXED
UNKNOWN
```

系统必须记录：

- 观察类型；
- 推荐类型；
- 人工确认类型；
- 类型置信度；
- 类型冲突次数。

人工确认后，类型异常只生成风险，不自动改变正式类型。

---

## 十五、参数语义类型

系统可以推荐但不得强制：

```text
IDENTIFIER
USERNAME_LIKE
PASSWORD_LIKE
EMAIL
PHONE
PERSON_NAME
ID_NUMBER
BANK_CARD
AMOUNT
CURRENCY
PERCENTAGE
DATE
TIME
DATETIME
TIMESTAMP
DURATION
UUID
IP_ADDRESS
DOMAIN
URL
URI
JWT
TOKEN
API_KEY
HASH
BASE64
HEX
ENUM
COUNTRY_CODE
LANGUAGE_CODE
COORDINATE
FILE_NAME
MIME_TYPE
BUSINESS_NUMBER
ORDER_NUMBER
SERIAL_NUMBER
CUSTOM
```

语义类型来源：

- 字段名；
- 路径；
- 值格式；
- 上下文；
- 请求和响应关系；
- 人工标注。

任何语义类型均允许管理员修改或创建企业自定义类型。

---

## 十六、字符串参数微模型

对所有字符串字段统一学习：

- 样本数量；
- 非空样本数量；
- 观察最小长度；
- 观察最大长度；
- 平均长度；
- P50；
- P90；
- P95；
- P99；
- 标准差；
- 字符类别；
- Unicode脚本；
- 是否允许中文；
- 是否允许空白；
- 是否允许控制字符；
- 常见前缀；
- 常见后缀；
- 固定格式候选；
- 正则候选；
- 枚举候选；
- 唯一值比例；
- 高基数或低基数；
- 熵区间；
- 敏感程度。

正式约束必须区分：

```text
observed
recommended
confirmed
```

不得直接把观察最大值作为阻断上限。

---

## 十七、数字参数微模型

学习：

- 最小值；
- 最大值；
- P50；
- P90；
- P95；
- P99；
- 是否允许负数；
- 是否允许零；
- 小数位数；
- 数值精度；
- 常见区间；
- 枚举候选；
- 离群值；
- 单调性；
- 单位候选。

正式模型使用人工确认范围。

---

## 十八、布尔、枚举与低基数字段

### 18.1 布尔

识别：

```text
true/false
0/1
yes/no
on/off
```

不得自动将任意两个值都识别为布尔。

### 18.2 枚举

枚举候选需满足：

- 样本数量；
- 多来源；
- 稳定时间；
- 低基数；
- 不包含敏感随机值。

新增枚举值在正式模型中应形成偏离事件，不自动加入正式枚举。

---

## 十九、数组模型

学习：

- 最小元素数；
- 最大元素数；
- P95元素数；
- 元素类型；
- 元素Schema；
- 是否允许重复；
- 是否允许空数组；
- 最大嵌套深度；
- 单元素长度；
- 数组总大小；
- 固定顺序或无序；
- 混合类型风险。

---

## 二十、对象模型

学习：

- 字段集合；
- 必填字段；
- 可选字段；
- 条件字段；
- 未定义字段是否允许；
- 最大字段数；
- 最大嵌套深度；
- 动态Key；
- 子对象Schema；
- 字段出现率；
- 字段顺序是否有意义；
- 对象总大小。

---

## 二十一、文件参数模型

学习：

- 文件数量；
- 文件名长度；
- 文件扩展名；
- MIME类型；
- Magic Header；
- 最小和最大大小；
- P95大小；
- 是否允许空文件；
- 是否压缩包；
- 压缩层级；
- 图片尺寸；
- 文件内容类别；
- 文件名字符集。

正式检测应支持：

- 扩展名和MIME不一致；
- Magic Header不一致；
- 超大文件；
- 超数量；
- 压缩炸弹风险；
- 双扩展名；
- 可执行内容；
- 脚本文件；
- 非法文件名。

---

## 二十二、存在性与条件关系模型

学习：

- 参数出现率；
- 是否必填；
- 是否允许缺失；
- 是否允许NULL；
- 是否允许空字符串；
- 条件出现关系。

例如：

```text
字段A=true时字段B通常出现
字段C出现时字段D必须出现
字段E和字段F互斥
```

系统只能生成候选关系，人工确认后才用于正式检测。

---

## 二十三、字段间关联关系

支持人工确认以下关系：

- 等值；
- 不等值；
- 大于小于；
- 时间先后；
- 同时出现；
- 互斥；
- 条件依赖；
- 数量一致；
- 汇总关系；
- 父子对象关系；
- 租户关系；
- 所有者关系。

例如：

```text
start_time <= end_time
min_value <= max_value
currency与amount同时出现
item_count等于items数组长度
```

第一版可由系统推荐，人工确认后启用。

---

## 二十四、请求Schema与响应Schema

每个API模型必须分别保存：

```text
request_schema
response_schema_by_status
```

响应Schema按状态码或状态码组管理。

支持检测：

- 新增字段；
- 缺失字段；
- 类型变化；
- 未定义字段；
- 嵌套变化；
- 数组元素变化；
- 响应状态码异常；
- 响应Content-Type变化；
- 响应体异常增大；
- 敏感字段新增。

---

## 二十五、学习样本过滤

默认不得进入学习：

- 命中WAF高风险规则；
- 命中API偏离规则；
- 黑名单流量；
- CC超限流量；
- 认证失败；
- 401、403、429；
- 500及以上响应；
- 请求或响应解析失败；
- 扫描器流量；
- 高频随机参数；
- 已确认攻击；
- 已确认异常；
- 超出正式模型；
- 单一来源大量重复样本；
- 请求体超出解析限制；
- 响应体不完整。

优先学习：

- 成功响应；
- 已认证身份；
- 多IP；
- 多身份；
- 多时间段；
- 未命中安全规则；
- 管理员指定可信来源；
- 业务正常时段。

---

## 二十六、防学习污染机制

必须具备：

- 单IP样本占比上限；
- 单身份样本占比上限；
- 单Token样本占比上限；
- 单User-Agent样本占比上限；
- 新结构最小独立来源数量；
- 新范围最小有效样本数；
- 离群值排除；
- 高风险样本排除；
- 样本去重；
- 样本时间衰减；
- 人工可信来源；
- 学习审计。

不得因攻击者持续发送异常请求而扩大模型。

---

## 二十七、模型版本机制

每个API拥有独立模型版本。

版本状态：

```text
LEARNING
CANDIDATE
REVIEW_PENDING
CONFIRMED
ACTIVE
REJECTED
SUPERSEDED
ARCHIVED
```

每个版本保存：

- 版本号；
- 父版本；
- API；
- 学习开始和结束；
- 样本总数；
- 有效样本；
- 排除样本；
- 请求Schema；
- 响应Schema；
- 参数模型；
- 用途模型；
- 身份模型；
- 行为模型；
- 风险标签；
- 置信度；
- 变更摘要；
- 创建原因；
- 创建方式；
- 创建人；
- 确认人；
- 确认时间；
- 内容哈希。

---

## 二十八、版本生成条件

不得每个请求生成一个版本。

满足以下条件之一生成候选版本：

- 新API；
- 新参数；
- 参数删除；
- 参数位置变化；
- 参数类型变化；
- 必填属性变化；
- 长度范围有效变化；
- 数值范围有效变化；
- 枚举集合变化；
- 请求结构变化；
- 响应结构变化；
- 新状态码；
- 认证方式变化；
- API用途变化；
- 敏感数据变化；
- 达到学习周期；
- 管理员手动保存快照。

---

## 二十九、版本差异对比

必须显示：

### 29.1 基本信息

- 方法；
- 路径；
- 协议；
- Content-Type；
- 认证；
- 用途；
- 风险等级。

### 29.2 请求参数

- 新增；
- 删除；
- 位置变化；
- 类型变化；
- 必填变化；
- NULL变化；
- 长度变化；
- 数值变化；
- 枚举变化；
- 格式变化；
- 敏感度变化；
- 条件关系变化。

### 29.3 响应

- 状态码变化；
- 字段新增；
- 字段删除；
- 类型变化；
- 敏感数据变化；
- 响应大小变化。

### 29.4 行为

- 调用频率；
- 身份类型；
- 对象访问数量；
- 调用顺序；
- 业务时段。

---

## 三十、人工确认与冻结

人工确认后：

- 正式模型不可自动变化；
- 新异常不得进入正式模型；
- 新参数不得自动加入；
- 新范围不得自动扩大；
- 新枚举不得自动加入；
- 新响应字段不得自动加入；
- 用途分类不得自动覆盖；
- 正式版本用于观察或阻断；
- 变更只能通过重新学习或人工编辑。

确认操作必须记录：

- 确认人；
- 确认时间；
- 确认前后差异；
- 风险提示；
- 是否立即启用；
- 是否仅观察；
- 是否进入防护。

---

## 三十一、重新学习分支

正式模型V3启用时，管理员可以创建：

```text
V4-LEARNING
```

规则：

- V3继续正式检测；
- V4独立收集可信样本；
- V4不得影响V3；
- V4可与V3对比；
- V4确认后成为新正式版本；
- V4拒绝后归档；
- V3偏离流量默认不进入V4，除非满足可信样本规则；
- 重新学习过程必须审计。

---

## 三十二、Schema偏离检测

检测：

- 未定义参数；
- 缺失必填参数；
- 参数位置错误；
- 参数类型错误；
- 字符串超长或过短；
- 数值越界；
- 非法枚举；
- 非法格式；
- 不允许NULL；
- 不允许空值；
- 数组数量异常；
- 对象字段过多；
- 嵌套过深；
- 动态Key异常；
- 文件类型异常；
- 请求Content-Type异常；
- 响应Schema异常；
- 响应敏感字段新增；
- 未定义状态码。

动作：

```text
OBSERVE
BLOCK
RATE_LIMIT
MASK_RESPONSE
```

---

## 三十三、OpenAPI与规范导入

支持：

- OpenAPI 3.x；
- Swagger 2.0；
- JSON Schema；
- Postman Collection；
- GraphQL Schema。

导入后不得直接覆盖流量学习模型。

必须生成三方对比：

```text
导入规范
流量观察模型
人工确认模型
```

识别：

- 规范有但流量无；
- 流量有但规范无；
- 类型冲突；
- 必填冲突；
- 长度冲突；
- 认证冲突；
- 响应冲突；
- Shadow API；
- Zombie API。

---

## 三十四、API用途多维识别

每个API用途由多个维度组成：

```text
业务领域
业务对象
操作动作
交互模式
身份要求
数据敏感等级
业务流程阶段
技术协议
风险标签
```

不得仅保存单一分类。

### 34.1 业务领域

内置通用领域：

- 身份认证；
- 用户账户；
- 权限组织；
- 通用数据资源；
- 流程审批；
- 文件内容；
- 查询分析；
- 导入导出；
- 交易资金；
- 消息通知；
- 外部集成；
- 配置管理；
- 系统运维；
- 设备物联网；
- 人工智能；
- 隐私合规；
- 企业自定义。

### 34.2 操作动作

```text
CREATE
READ_LIST
READ_DETAIL
SEARCH
COUNT
UPDATE
PATCH
DELETE
BATCH_CREATE
BATCH_UPDATE
BATCH_DELETE
REGISTER
LOGIN
LOGOUT
TOKEN_ISSUE
TOKEN_REFRESH
TOKEN_REVOKE
VERIFY
SUBMIT
APPROVE
REJECT
WITHDRAW
ASSIGN
TRANSFER
PUBLISH
UNPUBLISH
ENABLE
DISABLE
LOCK
UNLOCK
IMPORT
EXPORT
UPLOAD
DOWNLOAD
PREVIEW
SYNC
CALLBACK
START
STOP
RETRY
BACKUP
RESTORE
EXECUTE
CUSTOM
```

### 34.3 识别证据

- 方法；
- 路径词；
- 参数；
- 响应；
- 认证；
- 调用顺序；
- 相邻API；
- 人工标注；
- 语义模型。

### 34.4 人工管理

支持：

- 修改推荐；
- 新增分类；
- 新增对象；
- 新增动作；
- 新增风险标签；
- 批量调整；
- 锁定分类；
- 企业分类树。

---

## 三十五、API身份与凭据模型

识别：

- 匿名；
- Cookie Session；
- Bearer Token；
- JWT；
- API Key；
- Basic Auth；
- OAuth Token；
- HMAC签名；
- 自定义Header；
- mTLS元数据；
- 未知认证。

保存指纹，不保存完整凭据。

检测：

- 凭据缺失；
- 凭据位置异常；
- Token过期；
- JWT算法风险；
- Token跨应用；
- Token跨IP异常；
- API Key出现在URL；
- 同一凭据高并发；
- 同一凭据多设备异常；
- 已吊销凭据继续访问。

---

## 三十六、API维度资源保护

阶段5已有IP和URI限流，本阶段扩展：

- 按API；
- 按身份；
- 按Token；
- 按API Key；
- 按租户；
- 按设备；
- 按业务对象；
- 按接口组；
- 按操作动作；
- 按请求成本；
- 按并发；
- 按日配额；
- 按小时配额；
- 按批量数量；
- 按分页大小；
- 按GraphQL深度；
- 按GraphQL复杂度。

动作：

```text
OBSERVE
RATE_LIMIT
TEMP_BLOCK
BLOCK
```

---

## 三十七、敏感数据识别

请求和响应均支持：

- 认证凭据；
- Token；
- API Key；
- Cookie；
- 身份证件；
- 银行卡；
- 手机号；
- 邮箱；
- 地址；
- 财务数据；
- 医疗数据；
- 企业自定义敏感字段。

支持：

- 敏感级别；
- 数据类别；
- 字段路径；
- 脱敏预览；
- 响应泄露事件；
- 未授权身份访问敏感数据；
- 新增敏感字段；
- 单次返回量异常；
- 批量导出风险。

不得在事件中保存完整高敏感值。

---

## 三十八、API安全图谱

建立以下实体：

```text
应用
域名
API
API模型版本
参数
响应字段
身份
Token指纹
角色
租户
设备
业务对象
敏感数据
调用关系
安全事件
```

建立关系：

```text
应用包含API
API包含参数
身份调用API
身份访问对象
API返回敏感数据
API前置调用API
API后续调用API
事件命中API
模型版本属于API
```

第一版可以使用关系表实现，不强制引入图数据库。

---

## 三十九、API调用拓扑

根据流量建立：

- 前后调用顺序；
- 高频调用链；
- 登录后常见链；
- 业务流程链；
- 外部回调链；
- API到源站服务关系；
- 身份到API关系。

支持按：

- 应用；
- 身份；
-时间；
- 业务领域；
- 风险；
- 事件；

查看拓扑。

---

## 四十、对象标识与BOLA辅助检测

系统通过以下信息识别对象标识候选：

- 路径变量；
- Query参数；
- JSON字段；
- 响应字段；
- 业务对象分类；
- 高唯一值字段；
- 前后API关系；
- 人工配置。

BOLA第一版采用：

```text
对象字段识别
+
身份字段识别
+
所有者关系配置
+
历史访问基线
+
异常对象遍历检测
```

输出：

- 疑似对象越权；
- 证据；
- 身份；
- 对象；
- 历史基线；
- 请求序列；
- 风险等级。

不得仅因访问不同对象ID就直接确认BOLA。

---

## 四十一、BFLA辅助检测

识别：

- 低权限身份调用管理动作；
- 匿名调用需认证动作；
- 普通用户调用审批、删除、导出、授权等高风险动作；
- 角色与API历史关系偏离；
- 人工配置的角色到API权限矩阵。

输出：

```text
CONFIRMED_BY_POLICY
LIKELY
POSSIBLE
INSUFFICIENT_EVIDENCE
```

---

## 四十二、字段级越权和Mass Assignment

支持管理员将字段标记为：

- 普通可写；
- 只读；
- 管理员可写；
- 服务端生成；
- 敏感；
- 禁止外部提交。

检测：

- 客户端提交只读字段；
- 普通身份提交管理字段；
- 新增未定义高风险字段；
- 请求字段与响应内部字段重合；
- 批量修改权限字段；
- 角色、权限、状态、余额等关键字段异常提交。

不得仅依赖字段名称，必须结合人工确认和模型。

---

## 四十三、业务行为学习

在结构模型之外学习：

- 调用频率；
- 调用时段；
- 调用顺序；
- 成功失败比；
- 单次对象数量；
- 单身份对象遍历范围；
- 单次数据量；
- 批量操作规模；
- 登录后行为；
- 设备和地域变化；
- Token使用模式。

正式行为基线同样需要确认或明确策略阈值，不能无限自适应。

---

## 四十四、业务流程偏离

支持识别候选流程：

```text
登录 → 查询 → 提交 → 审批 → 完成
```

检测：

- 跳过前置步骤；
- 重复提交；
- 逆序调用；
- 未授权状态转换；
- 短时间批量执行；
- 取消后继续操作；
- 未登录直接调用后置API。

第一版作为观察和高风险提示，不默认阻断复杂业务流程。

---

## 四十五、统一风险决策

每个检测器输出：

```text
detector
rule_or_model
risk_score
risk_level
confidence
evidence
recommended_action
```

决策引擎综合：

- WAF命中；
- API Schema偏离；
- 认证异常；
- 权限风险；
- 敏感数据；
- 行为异常；
- 访问控制；
- CC；
- 白名单和例外；
- 策略模式；
- 应用风险级别。

最终动作：

```text
ALLOW
OBSERVE
BLOCK
RATE_LIMIT
TEMP_BLOCK
MASK_RESPONSE
CHALLENGE_RESERVED
```

---

## 四十六、统一事件中心

主事件：

```text
security_event
```

检测来源：

```text
WEB_ATTACK
API_DISCOVERY
API_SCHEMA
API_AUTHENTICATION
API_AUTHORIZATION
API_SENSITIVE_DATA
API_BEHAVIOR
API_LIFECYCLE
ACCESS_CONTROL
CC_PROTECTION
SYSTEM
```

同一Request ID只生成一个主事件，可挂接多条检测明细。

事件详情至少显示：

- 请求；
- API；
- 正式模型版本；
- 实际参数；
- 期望范围；
- WAF命中；
- 身份；
- 对象；
- 敏感数据；
- 风险计算；
- 最终动作；
- 证据；
- 处置。

---

## 四十七、统一策略模型

每个应用绑定一套动态防护策略：

```text
基础访问控制
CC与资源保护
Web攻击防护
API发现
API学习
API Schema
认证安全
对象和功能权限
敏感数据
业务行为
响应检测
```

发布时形成统一不可变版本。

回滚必须同时回滚相关策略引用，防止WAF和API模型版本不一致。

---

## 四十八、与阶段7 AI打通

阶段7新增Tool：

```text
api_asset.search
api_asset.get
api_model.get
api_model.diff
api_parameter.get
api_graph.query
api_runtime.statistics
api_risk.search
api_learning.status
api_classification.explain
```

AI可以：

- 解释API用途；
- 解释模型差异；
- 总结Shadow和Zombie API；
- 分析参数偏离；
- 分析疑似BOLA和BFLA；
- 生成模型确认建议；
- 生成策略草稿。

AI不得：

- 自动确认模型；
- 自动发布；
- 自动修改用途；
- 自动关闭API；
- 自动封禁身份。

---

## 四十九、未来独立九章API安全系统

必须以可拆分能力域开发。

公共底座复用：

- 用户管理；
- 三权管理；
- 安全设置；
- 审计管理；
- 登录认证；
- 配置发布；
- 版本管理；
- 事件中心；
- 报表；
- AI安全运营；
- 统一流量引擎。

独立API产品启用：

- API发现；
- 动态微模型；
- Schema；
- 用途识别；
- 身份和权限；
- 敏感数据；
- 安全图谱；
- 业务行为；
- 生命周期；
- API专项报表。

禁止在当前代码中把API逻辑写死到WAF规则页面或Coraza适配器内部。

---

## 五十、数据库设计

至少新增以下表：

```text
api_endpoints
api_endpoint_aliases
api_endpoint_path_segments
api_assets
api_learning_jobs
api_learning_samples
api_model_versions
api_parameter_models
api_parameter_statistics
api_parameter_relations
api_request_schemas
api_response_schemas
api_classifications
api_classification_dimensions
api_custom_taxonomies
api_identity_profiles
api_object_models
api_behavior_profiles
api_call_edges
api_sensitive_fields
api_runtime_findings
api_schema_violations
api_lifecycle_events
api_model_reviews
api_model_diffs
api_import_specs
api_spec_diffs
```

### 50.1 api_endpoints

```text
id
application_id
domain_id
http_method
raw_path_example
normalized_path
protocol_type
api_confidence
asset_status
learning_status
current_model_version_id
classification_locked
created_at
last_seen_at
updated_at
```

### 50.2 api_model_versions

```text
id
api_endpoint_id
version_number
parent_version_id
status
request_schema_id
response_schema_set_id
sample_count
valid_sample_count
excluded_sample_count
confidence
change_summary
content_hash
created_reason
created_by
created_at
confirmed_by
confirmed_at
activated_at
```

### 50.3 api_parameter_models

```text
id
model_version_id
direction
location
structured_path
parameter_name
base_type
semantic_type
required
nullable
empty_allowed
observed_constraints
recommended_constraints
confirmed_constraints
sensitivity_level
confidence
created_at
```

### 50.4 api_learning_samples

不得默认保存完整敏感值，至少保存：

```text
id
api_endpoint_id
request_id
sample_hash
source_fingerprint
identity_fingerprint
response_status
accepted
exclude_reason
collected_at
```

---

## 五十一、接口设计

### 51.1 API资产

```text
GET    /api/v1/api-security/endpoints
POST   /api/v1/api-security/endpoints/confirm
GET    /api/v1/api-security/endpoints/{id}
PATCH  /api/v1/api-security/endpoints/{id}
POST   /api/v1/api-security/endpoints/{id}/merge
POST   /api/v1/api-security/endpoints/{id}/split
POST   /api/v1/api-security/endpoints/{id}/ignore
POST   /api/v1/api-security/endpoints/{id}/classify
```

### 51.2 学习和模型

```text
POST /api/v1/api-security/endpoints/{id}/learning/start
POST /api/v1/api-security/endpoints/{id}/learning/stop
GET  /api/v1/api-security/endpoints/{id}/learning/status
GET  /api/v1/api-security/endpoints/{id}/models
GET  /api/v1/api-security/models/{id}
GET  /api/v1/api-security/models/{id}/diff/{other_id}
POST /api/v1/api-security/models/{id}/submit-review
POST /api/v1/api-security/models/{id}/confirm
POST /api/v1/api-security/models/{id}/reject
POST /api/v1/api-security/models/{id}/activate
POST /api/v1/api-security/models/{id}/archive
```

### 51.3 参数

```text
GET   /api/v1/api-security/models/{id}/parameters
GET   /api/v1/api-security/parameters/{id}
PATCH /api/v1/api-security/parameters/{id}
POST  /api/v1/api-security/parameters/{id}/confirm
```

### 51.4 分类和图谱

```text
GET  /api/v1/api-security/classifications
POST /api/v1/api-security/classifications
PUT  /api/v1/api-security/endpoints/{id}/classification
GET  /api/v1/api-security/graph
GET  /api/v1/api-security/topology
```

### 51.5 规范导入

```text
POST /api/v1/api-security/specs/import
GET  /api/v1/api-security/specs
GET  /api/v1/api-security/specs/{id}/diff
```

### 51.6 风险和运行时

```text
GET /api/v1/api-security/findings
GET /api/v1/api-security/violations
GET /api/v1/api-security/posture
GET /api/v1/api-security/runtime/statistics
```

---

## 五十二、权限设计

至少新增：

```text
api_asset.read
api_asset.confirm
api_asset.edit
api_asset.merge
api_asset.split
api_asset.ignore
api_learning.read
api_learning.start
api_learning.stop
api_model.read
api_model.edit
api_model.review
api_model.confirm
api_model.activate
api_model.archive
api_parameter.read
api_parameter.edit
api_classification.read
api_classification.manage
api_spec.read
api_spec.import
api_graph.read
api_runtime.read
api_policy.read
api_policy.edit
api_policy.publish
api_audit.read
```

三权边界必须与现有系统一致。

---

## 五十三、前端页面

建议新增：

```text
API动态防护
├── API资产
├── API学习中心
├── 模型版本
├── 参数模型
├── 用途分类
├── API安全图谱
├── API调用拓扑
├── API风险
├── Shadow与Zombie API
├── 敏感数据
├── 规范对比
└── API策略
```

### 53.1 API资产页

显示：

- 方法；
- 规范化路径；
- 用途；
- 协议；
- 状态；
- 学习状态；
- 当前版本；
- 最近访问；
- 请求量；
- 风险；
- 是否Shadow或Zombie。

### 53.2 模型版本页

显示：

- 时间线；
- 版本状态；
- 样本数；
- 参数变化；
- 请求和响应变化；
- 分类变化；
- 风险变化；
- 确认人；
- 对比；
- 确认；
- 拒绝；
- 重新学习。

### 53.3 参数模型页

支持树形展示：

```text
请求
├── PATH
├── QUERY
├── HEADER
└── BODY
    └── JSON字段树

响应
└── 状态码
    └── 字段树
```

显示观察值、推荐值和确认值。

---

## 五十四、可观测性

新增指标：

- 每秒API识别量；
- API总数；
- 新API数；
- Shadow数量；
- Zombie数量；
- 学习任务数；
- 学习延迟；
- 模型版本生成数；
- Schema偏离数；
- 参数异常数；
- 响应异常数；
- API检测耗时；
- 请求解析耗时；
- 响应解析耗时；
- 内存占用；
- 样本排除率；
- 事件积压；
- 图谱边数量；
- AI Tool调用量。

---

## 五十五、性能要求

基准目标应在测试报告中以实际结果为准。

至少验证：

- 一次解析相较重复解析的性能收益；
- 无API功能时的WAF基线；
- 开启API发现后的延迟；
- 开启Schema检测后的延迟；
- 开启响应检测后的延迟；
- 大JSON；
- 深嵌套JSON；
- 大数组；
- Multipart；
- 文件上传；
- 高并发；
- API数量10万级；
- 参数模型百万级；
- 学习任务并发；
- 版本对比性能；
- 图谱查询性能。

不得将目标值写成已完成结果。

---

## 五十六、单元测试

至少覆盖：

- API识别；
- 路径归一化；
- 动态段识别；
- API合并；
- API拆分；
- 参数提取；
- 类型识别；
- 字符串统计；
- 数值统计；
- 数组和对象Schema；
- 文件模型；
- 条件关系；
- 样本过滤；
- 防污染；
- 版本触发；
- 版本差异；
- 模型冻结；
- 重新学习；
- 用途分类；
- 身份提取；
- Schema偏离；
- 风险聚合；
- 统一事件；
- 敏感数据脱敏；
- API Tool权限。

---

## 五十七、接口测试

覆盖：

- API资产分页；
- API确认；
- 合并和拆分；
- 学习启动和停止；
- 候选版本；
- 版本对比；
- 模型确认；
- 模型激活；
- 重新学习；
- 参数修改；
- 用途分类；
- 自定义分类；
- 规范导入；
- Shadow和Zombie查询；
- 图谱；
- 风险；
- 权限越权；
- 审计。

---

## 五十八、流量回放测试

必须使用真实协议样例覆盖：

- 页面请求；
- JSON API；
- XML API；
- SOAP；
- GraphQL；
- 文件上传；
- 文件下载；
- Webhook；
- 登录；
- 列表；
- 详情；
- 更新；
- 删除；
- 批量导出；
- 大分页；
- Token异常；
- Schema异常；
- 响应敏感数据；
- 业务流程偏离。

回放后验证Web和API检测共用同一个Request ID。

---

## 五十九、学习测试

至少验证：

1. 正常样本形成稳定模型；
2. 单IP大量样本不能控制模型；
3. 攻击样本被排除；
4. 401、403、429和500样本被排除；
5. 新字段生成候选版本；
6. 小量离群值不扩大范围；
7. 达到阈值后生成版本；
8. 人工确认后模型冻结；
9. 偏离请求产生事件；
10. 偏离请求不进入学习；
11. 重新学习分支不影响正式版本；
12. 拒绝候选后正式版本不变。

---

## 六十、API用途识别测试

至少覆盖：

- URL含明确动作；
- URL不含动作但参数和响应可判断；
- 同一路径不同方法；
- 同一路径不同Schema；
- 登录；
- 注册；
- 登出；
- Token刷新；
- 查询；
- 更新；
- 删除；
- 审批；
- 导入；
- 导出；
- 上传；
- 下载；
- Webhook；
- 系统健康；
- 企业自定义用途；
- 低置信度；
- 人工修正和锁定。

---

## 六十一、安全测试

必须执行：

- 路径归一化绕过；
- 双重编码；
- 参数污染；
- 重复JSON Key；
- JSON深度攻击；
- XML实体攻击；
- 超大数组；
- 超大请求；
- 超大响应；
- Multipart边界攻击；
- 压缩炸弹；
- Schema绕过；
- 学习污染；
- 模型投毒；
- 版本越权；
- 模型确认越权；
- 跨应用读取模型；
- 跨用户审计读取；
- Token泄露；
- 敏感数据泄露；
- SQL注入；
- XSS；
- SSRF特征；
- NoSQL注入；
- Mass Assignment；
- BOLA辅助检测；
- BFLA辅助检测；
- 业务流程绕过；
- 图谱查询注入；
- OpenAPI恶意文件；
- SSRF式规范导入；
- 任意文件读取；
- 审计删除；
- 绕过统一决策；
- 检测器直接返回响应；
- AI自动确认模型。

高危问题未修复不得通过。

---

## 六十二、Playwright E2E场景

### 场景一：自动发现API

1. 创建应用；
2. 发送JSON接口流量；
3. 验证API被发现；
4. 验证方法、路径、协议和置信度；
5. 确认为API。

### 场景二：动态参数学习

1. 发送多组不同参数；
2. 查看字符串、数值、数组和对象模型；
3. 查看样本数和置信度；
4. 验证不针对具体字段名。

### 场景三：版本生成与对比

1. 增加新字段；
2. 生成候选版本；
3. 对比新旧版本；
4. 确认正式版本。

### 场景四：模型冻结

1. 确认参数范围；
2. 发送超出范围请求；
3. 验证生成风险事件；
4. 验证正式模型未变化；
5. 验证异常请求未进入学习。

### 场景五：重新学习

1. 从正式版本启动重新学习；
2. 产生新业务流量；
3. 验证正式版本继续检测；
4. 对比学习分支；
5. 确认新版本并激活。

### 场景六：统一事件

1. 构造同时命中WAF和Schema偏离的请求；
2. 验证只生成一个主事件；
3. 验证包含多条检测明细。

### 场景七：未来独立API权限

1. 验证API功能权限独立；
2. 验证公共底座权限复用；
3. 验证API管理员无法越权系统管理。

---

## 六十三、自动化命令

```bash
make stage8-build
make stage8-migrate
make stage8-seed
make stage8-up
make stage8-status
make stage8-test-unit
make stage8-test-api
make stage8-test-discovery
make stage8-test-learning
make stage8-test-versioning
make stage8-test-schema
make stage8-test-classification
make stage8-test-identity
make stage8-test-authorization
make stage8-test-sensitive-data
make stage8-test-behavior
make stage8-test-graph
make stage8-test-replay
make stage8-test-e2e
make stage8-test-performance
make stage8-test-security
make stage8-test-all
make stage8-down
```

命令必须可重复执行，失败返回非零状态，不依赖人工进入容器修改。

---

## 六十四、文档要求

必须完成：

```text
docs/UNIFIED_DYNAMIC_SECURITY_ARCHITECTURE.md
docs/REQUEST_CONTEXT_DESIGN.md
docs/API_DISCOVERY_DESIGN.md
docs/API_PATH_NORMALIZATION.md
docs/API_PARAMETER_MODEL.md
docs/API_LEARNING_SECURITY.md
docs/API_MODEL_VERSIONING.md
docs/API_CLASSIFICATION_DESIGN.md
docs/API_SCHEMA_PROTECTION.md
docs/API_IDENTITY_SECURITY.md
docs/API_AUTHORIZATION_ANALYSIS.md
docs/API_SENSITIVE_DATA.md
docs/API_BEHAVIOR_ANALYSIS.md
docs/API_SECURITY_GRAPH.md
docs/API_PRODUCT_SEPARATION.md
docs/STAGE8_TEST_REPORT.md
docs/API_DESIGN.md
docs/SECURITY_DESIGN.md
docs/DEVELOPMENT_STATUS.md
```

---

## 六十五、阶段退出条件

以下全部满足才允许标记阶段8通过：

1. 产品中Web和API使用同一流量链；
2. 同一请求只解析一次；
3. 存在统一RequestContext；
4. Coraza只是统一检测器之一；
5. API功能关闭不影响WAF；
6. API可自动识别；
7. API识别不依赖`/api/`；
8. API置信度可见；
9. API可人工确认；
10. 路径可归一化；
11. API可合并和拆分；
12. 不同HTTP方法为不同操作；
13. 参数覆盖请求和响应；
14. 参数覆盖所有主要位置；
15. 参数模型不针对具体字段名；
16. 字符串模型可学习长度和字符集；
17. 数值模型可学习范围和精度；
18. 数组和对象模型可用；
19. 文件模型可用；
20. 条件关系可建模；
21. 观察、推荐和确认值分离；
22. 观察范围不直接作为正式范围；
23. 学习样本过滤可用；
24. 攻击流量不进入学习；
25. 单一来源不能控制模型；
26. 候选版本按有效变化生成；
27. 版本不可变；
28. 版本可对比；
29. 人工可确认模型；
30. 确认后模型冻结；
31. 偏离请求生成事件；
32. 偏离请求不扩大模型；
33. 重新学习分支可用；
34. 重新学习不影响正式版本；
35. 用途采用多维模型；
36. 用途可人工修改；
37. 企业可自定义分类；
38. 人工分类可锁定；
39. OpenAPI导入可用；
40. 导入规范与流量模型可对比；
41. Shadow API可识别；
42. Zombie API可识别；
43. Deprecated API可管理；
44. 请求Schema检测可用；
45. 响应Schema检测可用；
46. 未定义字段检测可用；
47. 参数类型检测可用；
48. 参数长度检测可用；
49. 参数数值检测可用；
50. 枚举检测可用；
51. API身份识别可用；
52. 凭据只保存指纹；
53. API维度限流可用；
54. 敏感数据发现可用；
55. 响应泄露检测可用；
56. API安全图谱可用；
57. API调用拓扑可用；
58. 对象标识候选可识别；
59. BOLA辅助检测可用；
60. BFLA辅助检测可用；
61. 字段级越权检测可用；
62. Mass Assignment检测可用；
63. 业务行为基线可用；
64. 业务流程偏离可观察；
65. 多检测器使用统一决策；
66. 检测器不能直接返回阻断；
67. 同一Request ID生成一个主事件；
68. 主事件支持多检测明细；
69. 动态防护策略统一发布；
70. 策略版本不可变；
71. 回滚保持Web和API策略一致；
72. 阶段7 AI Tool已接入；
73. AI不能自动确认模型；
74. AI不能自动发布；
75. API能力域可独立打包；
76. 公共底座可复用；
77. API逻辑未写死在Coraza适配器；
78. 数据库迁移通过；
79. 回滚验证通过；
80. 单元测试通过；
81. 接口测试通过；
82. 流量回放测试通过；
83. 学习污染测试通过；
84. E2E测试通过；
85. 性能测试完成；
86. 安全测试无未修复高危；
87. 文档与实际一致；
88. 未使用Mock数据冒充真实结果；
89. 未提前开发阶段9；
90. `docs/DEVELOPMENT_STATUS.md`已更新；
91. 能力域目录边界符合《产品线与分支策略》§5.1：底座未import能力域、Web防护域与API能力域未互相import；
92. CI edition矩阵中 `smoke-waf`（API关闭态）与 `smoke-wdsp`（API开启态）全绿。

任何一项未满足，不得标记阶段8通过。

---

## 六十六、执行顺序

```text
检查阶段1至阶段7真实状态
    ↓
设计统一RequestContext
    ↓
改造一次解析链路
    ↓
接入Coraza检测适配器
    ↓
开发API识别与路径归一化
    ↓
开发API资产管理
    ↓
开发参数和Schema提取
    ↓
开发动态学习与样本过滤
    ↓
开发防污染机制
    ↓
开发模型版本和差异
    ↓
开发人工确认和冻结
    ↓
开发重新学习分支
    ↓
开发用途多维识别
    ↓
开发OpenAPI导入和差异
    ↓
开发身份与凭据模型
    ↓
开发API资源保护
    ↓
开发敏感数据检测
    ↓
开发安全图谱和调用拓扑
    ↓
开发BOLA、BFLA和字段权限基础能力
    ↓
开发业务行为基线
    ↓
开发统一风险决策
    ↓
开发统一事件
    ↓
开发统一策略发布
    ↓
接入阶段7 AI
    ↓
完成前端、权限、审计和报表
    ↓
执行全部测试
    ↓
编写测试报告
```

阶段8完成后立即停止，不得自行进入阶段9。

---

## 六十七、禁止事项

1. 禁止建设WAF和API两条独立流量链；
2. 禁止重复解析请求和响应；
3. 禁止WAF服务串联调用API安全服务；
4. 禁止API模块自行直接返回阻断；
5. 禁止将Coraza作为整个统一引擎；
6. 禁止只根据URL包含`/api/`识别API；
7. 禁止针对具体字段名写死学习策略；
8. 禁止把观察最大值直接当正式最大值；
9. 禁止攻击流量进入学习；
10. 禁止单一IP控制模型；
11. 禁止正式模型自动变化；
12. 禁止偏离流量自动扩大范围；
13. 禁止每个请求生成版本；
14. 禁止人工确认后继续后台静默学习；
15. 禁止重新学习直接覆盖正式模型；
16. 禁止用途只使用单一分类；
17. 禁止系统自动覆盖人工分类；
18. 禁止保存完整Token、密码和Cookie；
19. 禁止API事件与WAF事件完全割裂；
20. 禁止同一Request ID生成多个互相独立主事件；
21. 禁止AI自动确认模型；
22. 禁止AI自动发布策略；
23. 禁止AI自动认定入侵成功；
24. 禁止未经证据确认BOLA或BFLA；
25. 禁止API逻辑写死在WAF页面；
26. 禁止未来独立API产品重新开发公共底座；
27. 禁止使用Mock数据冒充真实测试；
28. 禁止将性能目标写成实际结果；
29. 禁止通过删除失败用例使测试通过；
30. 禁止提前开发阶段9。

---

## 六十八、Agent最终输出格式

阶段8完成后必须输出：

### 1. 阶段结论

```text
阶段8通过
阶段8有条件通过
阶段8未通过
```

### 2. 实际完成项

逐项列出真实完成能力。

### 3. 未完成项

不得隐瞒。

### 4. 新增和修改文件

按：

- 网关；
- 统一上下文；
- API发现；
- 学习；
- 模型；
- 版本；
- 分类；
- 图谱；
- 决策；
- 事件；
- 前端；
- 数据库；
- 测试；
- 文档；

分类列出。

### 5. 数据库迁移

列出版本、表、索引、约束、初始化数据和回滚结果。

### 6. API发现结果

列出测试环境中：

- 发现API数；
- 确认API数；
- Shadow数；
- Zombie数；
- 协议分布；
- 归一化结果。

### 7. 学习和版本结果

列出：

- 学习任务数；
- 样本总数；
- 有效样本；
- 排除样本；
- 候选版本；
- 确认版本；
- 冻结验证；
- 重新学习验证；
- 污染测试。

### 8. API用途识别

列出：

- 测试API；
- 推荐用途；
- 人工确认；
- 置信度；
- 错误案例；
- 自定义分类验证。

### 9. 运行时防护

列出：

- Schema偏离；
- 参数类型；
- 参数长度；
- 数值；
- 枚举；
- 身份；
- 资源保护；
- 敏感数据；
- BOLA；
- BFLA；
- Mass Assignment；
- 业务行为。

### 10. 统一架构验证

说明：

- 是否一次解析；
- 是否统一上下文；
- 是否统一决策；
- 是否统一事件；
- 是否存在重复链路；
- API关闭是否影响WAF；
- 未来是否可独立打包。

### 11. 测试结果

列出全部测试总数、通过数、失败数和跳过数。

### 12. 性能

列出测试环境、并发、延迟、吞吐、CPU、内存、API规模、参数规模和学习耗时。

### 13. 安全检查

说明学习污染、敏感数据、越权、模型确认权限、统一决策绕过和高危问题。

### 14. 遗留问题

每项包含影响、风险、处理和后续建议。

### 15. 未满足退出条件

逐项列出。

---

## 六十九、交给Agent的执行指令

请严格按照：

```text
docs/tasks/STAGE_8_UNIFIED_WEB_API_DYNAMIC_PROTECTION.md
```

执行阶段8。

执行要求：

1. 先检查阶段1至阶段7真实交付结果；
2. 同一请求只允许解析一次；
3. Web和API必须共享统一RequestContext；
4. 不得建设串联式双系统；
5. 不得针对任何具体字段名写死策略；
6. 学习必须通用、动态、版本化和可审计；
7. 正式模型经人工确认后必须冻结；
8. 偏离请求必须形成风险且不得污染模型；
9. 重新学习必须使用独立分支；
10. API用途必须采用多维模型并支持人工自定义；
11. 所有检测器必须经过统一决策；
12. 同一Request ID只生成一个主事件；
13. API能力必须为未来独立产品预留可拆分边界；
14. 必须完成学习污染、版本冻结、统一事件、性能和安全测试；
15. 完成全部测试后再判断阶段结论；
16. 阶段8完成后停止；
17. 不得提前开发阶段9。
