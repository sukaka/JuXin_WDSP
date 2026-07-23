# API 敏感数据识别设计（阶段8 / WDSP）

## 一、目的与范围

本文档描述阶段8 敏感数据识别能力：网关侧基于**字段名模式**的敏感字段检测、
Query 明文外泄的升级规则、管理面 `api_sensitive_fields` 表与查询接口。

两条底线贯穿全文（对应任务书第三十七章"不得在事件中保存完整高敏感值"）：

1. **只匹配字段名，不触碰字段值**——检测输入是解析层产出的字段名集合，
   值从未进入匹配逻辑；
2. **Evidence 不记值**——事件证据只含字段路径、数据类型标签与位置三类信息。

覆盖代码：`gateway/dynamic_security/detectors/sensitive.go`（检测器）、
`server/internal/apisecurity/sensitive.go`（查询仓储）、迁移 000018
`api_sensitive_fields`。

## 二、架构与数据流

```text
parser.ParseRequest
  │  产出字段名集合：Query 键、JSONFields 路径、FormFields 键、XMLFields 路径
  ▼
pipeline.Process（pipeline.go:91-95）
  │  CompileSensitivePatterns(cfg.SensitivePatterns)（nil → 内置表；编译失败 = 配置错误）
  ▼
detectors.CheckSensitiveData(ctx, parsed, patterns)   （sensitive.go:60）
  ├─ Query 键名命中     → sensitive.in_query（BLOCK 类 / HIGH / +40）
  ├─ JSON 字段名命中    → sensitive.field（OBSERVE / MEDIUM / +10）
  ├─ Form 字段名命中    → sensitive.field（OBSERVE / MEDIUM / +10）
  └─ XML 字段名命中     → sensitive.field（OBSERVE / MEDIUM / +10）
  （单请求 match 上限 20，Query 优先）
  ▼
decision.Decide：BLOCK 类在 PROTECT 模式 → ActionBlock（engine.go:62-83）
  ▼
管理面：api_sensitive_fields（画像表，当前无写入方）＋ 只读查询接口
```

## 三、字段名模式表

内置模式表 `defaultSensitivePatterns`（sensitive.go:28-34），覆盖中英常见命名，
编译期正则（Go RE2，线性时间，与阶段5 防 ReDoS 纪律一致）：

| 数据类型标签 | 模式要点 |
|--------------|----------|
| `phone` | `phone`、`mobile`、`telephone`、拼音 `shouji`；短词 `tel` 带非字母边界 |
| `email` | `email`/`mail`（可选下划线）、拼音 `youxiang` |
| `id_card` | `id_card`/`idcard`、`identity`、拼音 `shenfenzheng`；短词 `sfz` 带边界 |
| `bank_card` | `bank_card`、`card_number`/`card_no`、拼音 `yinhangka`；短词 `pan` 带边界 |
| `credential` | `password`、`passwd`、`pwd`、`secret`、`token`、`api_key`/`apikey`、`access_key`、`private_key`、拼音 `mima` |

**短词边界防误伤**：`tel`、`sfz`、`pan` 三个短关键字写作
`(^|[^a-z])tel([^a-z]|$)` 形态（sensitive.go:29-33），要求两侧为非字母字符，
避免 `hotel`、`company` 等常见词误命中（代码注释明确此意图，sensitive.go:27）。
匹配整体大小写不敏感（`(?i)`）。

模式表可经 `pipeline.Config.SensitivePatterns` 整体替换（pipeline.go:29）；
`CompileSensitivePatterns` 对空 `data_type`/`pattern` 或正则编译失败返回错误，
管线启动即报配置错误，不静默降级（sensitive.go:40-56、pipeline.go:91-94）。

## 四、检测规则与升级

`CheckSensitiveData`（sensitive.go:60-96）：

| 规则 ID | 位置 | 类别 / 严重度 | ScoreDelta | 含义 |
|---------|------|---------------|------------|------|
| `sensitive.in_query` | Query 键名 | BLOCK / HIGH | 40 | 敏感字段出现在 URL，明文外泄（日志、历史记录、Referer 均会留存） |
| `sensitive.field` | JSON / Form / XML 字段名 | OBSERVE / MEDIUM | 10 | 请求体携带敏感字段，观察记录 |

- **扫描顺序与预算**：Query 优先（高危），随后 JSON、Form、XML；
  单请求 match 总量上限 `maxSensitiveMatches = 20`（sensitive.go:37），
  防超大报文撑爆事件（sensitive.go:36 注释）。
- **Query 升级即 BLOCK 类**：URL 中的敏感字段视为高危信号，
  PROTECT 模式下经统一决策可阻断；请求体内的命中只观察不阻断——体内携带
  敏感字段是 API 常态（登录、开户），阻断会造成大面积误伤。
- **Evidence 三要素**：`field`（字段名/路径）、`data_type`（上表标签）、
  `location`（query / json / form / xml），无值、无值长度、无值哈希。

## 五、api_sensitive_fields 与查询接口

### 5.1 表结构

迁移 000018 第 282-293 行：

| 列 | 说明 |
|----|------|
| `endpoint_id` | 端点，FK 级联删除 |
| `direction` | `REQUEST` / `RESPONSE`，默认 `REQUEST` |
| `structured_path` | 字段结构化路径 |
| `data_type` | 数据类型标签（phone / id_card / bank_card / email / credential / …） |
| `confidence` | 置信度 |
| `detection_source` | `AUTO` / `MANUAL`，默认 `AUTO` |
| `created_at` / `updated_at` | 时间戳 |

约束：`UNIQUE (endpoint_id, direction, structured_path)`——同端点同方向同路径
唯一行，重复识别自然去重。

### 5.2 查询接口

`GET /api/v1/api-security/sensitive-fields`（`apisecurity/routes.go:43-44`，
权限 `api_runtime.read`）：

- 过滤：`endpoint_id`（非法 UUID 返回 400）、`direction`（仅 REQUEST/RESPONSE，
  其他返回 400）、`data_type`、分页（handler.go:420-443）；
- 仓储 `ListSensitiveFields`（sensitive.go:28-80）按白名单字段拼接 WHERE、
  值一律参数化，`updated_at DESC` 排序分页；过滤条件不含任何用户输入拼接；
- 前端页面 `web/src/pages/api-sensitive-fields/ApiSensitiveFieldsPage.tsx`。

## 六、关键设计决策

1. **字段名即信号，值永不入场**。检测器签名只接收解析层的字段名集合
   （`p.Query`、`p.JSONFields`、`p.FormFields`、`p.XMLFields`），从函数签名层面
   排除接触值的可能；这与任务书 2.7"字段名只是数据"一体两面——不针对具体
   字段名写业务策略，但字段名本身是通用的敏感度信号。
2. **URL 与体内分级处置**。同一命中在 Query 是 BLOCK 类、在体内是 OBSERVE，
   差异来自外泄面：URL 会进入访问日志、浏览器历史与代理日志，体内不会。
3. **中文命名一等支持**。拼音命名（shouji/shenfenzheng/yinhangka/mima）与英文
   并列在内置表中，匹配国内业务真实命名习惯。
4. **短词必须带边界**。宁可漏报 `telephone` 缩写变体，也不可让 `hotel` 之类
   常见词污染事件中心——误报成本高于漏报成本时选择保守。
5. **match 预算上限**。20 条/请求硬上限，恶意构造的超大报文无法制造事件风暴。
6. **模式表启动期编译**。正则编译失败视为配置错误并终止管线调用链
   （返回 error），不在运行中吞错降级。

## 七、当前实现范围与限制

- **画像表仅建表**。`api_sensitive_fields` 无 Go 写入方——检测命中只进入
  运行时事件明细，不落敏感字段画像；查询接口当前读到的是空表。画像回填
  （从事件聚合 upsert）是后续工作。
- **仅请求方向**。检测器只扫描请求（Query/JSON/Form/XML）；`direction=RESPONSE`
  列与查询过滤已预留，但响应敏感数据泄露检测（任务书 53 项目标）未实现，
  响应侧无解析与扫描路径。
- **字段名模式是唯一的检测手段**。无值格式校验（Luhn、身份证号校验位）、
  无数据类别内容识别；命中精度完全取决于命名规范度，混淆命名
  （`f1`、`col_a`）识别不到。
- **无脱敏预览与单次返回量异常**。任务书三十七章的脱敏预览、新增敏感字段
  管理、单次返回量异常、批量导出风险均未实现；`detection_source=MANUAL`
  已预留但无管理面写入接口。
- **自定义模式为整体替换**。`Config.SensitivePatterns` 非 nil 时整体替换内置表，
  无增量合并；模式内容不进入管理面数据库，当前由网关配置下发。

## 八、与任务书对应章节

- 第三十七章（敏感数据识别）：请求侧敏感字段识别、凭据类字段、"不得在事件中
  保存完整高敏感值"的落地；响应泄露检测见第七节；
- 7.1（数据最小化）：Evidence 不记值原则；
- 2.4（统一决策）：Query 命中仅输出 BLOCK 类信号，动作由决策引擎定案；
- 第五十章：`api_sensitive_fields` 表结构；51.6 / 五十二章：
  `api_runtime.read` 权限点（迁移 000019 种子）。

Copyright © 聚信得仁
All Rights Reserved.
