# API 敏感数据识别设计（阶段8 / WDSP）

## 一、目的与范围

本文档描述阶段8 敏感数据识别能力：网关侧基于**字段名模式**的敏感字段检测、
Query 明文外泄的升级规则、管理面 `api_sensitive_fields` 表与查询接口。

两条底线贯穿全文（对应任务书第三十七章"不得在事件中保存完整高敏感值"）：

1. **字段名匹配不触碰字段值；值级匹配只在值级规则下发时开启**——字段名检测输入是
   解析层产出的字段名集合；值级检测（`api_sensitive_value_rules` 下发）对留存值做
   RE2 匹配（单值 4096 字符截断），证据同样不落值；
2. **Evidence 不记值**——事件证据只含字段路径、数据类型标签、位置与敏感等级四类信息。

覆盖代码：`gateway/dynamic_security/detectors/sensitive.go`（检测器）、
`server/internal/apisecurity/sensitive.go`（查询仓储）、迁移 000018
`api_sensitive_fields`。

## 二、架构与数据流

```text
parser.ParseRequest
  │  产出字段名集合：Query 键、JSONFields 路径、FormFields 键、XMLFields 路径
  ▼
pipeline.Process（pipeline.go:145-154）
  │  CompileSensitivePatterns(cfg.SensitivePatterns)（nil → 内置表；编译失败 = 配置错误）
  │  CompileSensitiveValueRules(cfg.SensitiveValueRules)（值级规则；编译失败 = 配置错误）
  ▼
detectors.CheckSensitiveData(ctx, parsed, patterns, valueRules)   （sensitive.go:140）
  ├─ Query 键名命中     → sensitive.in_query（BLOCK 类 / HIGH / +40）
  ├─ JSON 字段名命中    → sensitive.field（OBSERVE / MEDIUM / +10）
  ├─ Form 字段名命中    → sensitive.field（OBSERVE / MEDIUM / +10）
  ├─ XML 字段名命中     → sensitive.field（OBSERVE / MEDIUM / +10）
  └─ 值级规则命中（valueRules 非空时追加；sensitive.go:186 scanValueLevel）
       ├─ Query 值命中   → sensitive.value_in_query（BLOCK 类 / HIGH / +40）
       └─ JSON/Form/HEADER/PATH 值命中 → sensitive.value（OBSERVE / MEDIUM / +15）
  （单请求 match 上限 20，Query 优先；值级单值 4096 字符截断、单请求 512 次求值预算）
  ▼
decision.Decide：BLOCK 类在 PROTECT 模式 → ActionBlock（engine.go:62-83）
  ▼
管理面：api_sensitive_fields（apidata SweepOnce 水位幂等写入，detection_source=RUNTIME）＋ 只读查询接口
```

## 三、字段名模式表

内置模式表 `defaultSensitivePatterns`（sensitive.go:30-36），覆盖中英常见命名，
编译期正则（Go RE2，线性时间，与阶段5 防 ReDoS 纪律一致）：

| 数据类型标签 | 模式要点 |
|--------------|----------|
| `phone` | `phone`（含 `cell/tele/mobile` 前缀）、`mobile`、`tel`（分隔符/驼峰边界防 `microphone`/`automobile`/`hotel` 误伤）、拼音 `shouji` |
| `email` | `email`/`e_mail`/`mail`（分隔符/驼峰边界防 `mailer`/`mailinglist`/`pipermail`/`blackmail` 误伤）、拼音 `youxiang` |
| `id_card` | `id_card`/`idcard`、`identity`、拼音 `shenfenzheng`；短词 `sfz` 带边界 |
| `bank_card` | `bank_card`、`card_number`/`card_no`、拼音 `yinhangka`；短词 `pan` 带边界 |
| `credential` | `password`、`passwd`、`pwd`、`secret`、`token`、`api_key`/`apikey`、`access_key`、`private_key`、拼音 `mima` |

**词根边界防误伤**：`phone`/`mobile`/`tel`/`email`/`mail` 采用分隔符与驼峰边界，
`sfz`/`pan` 采用非字母边界（sensitive.go），兼容 `userPhone`/`emailAddress`/`USER_EMAIL` 等命名，
同时避免 `hotel`、`company`、`mailer`、`mailinglist`、`pipermail`、`microphone`、`automobile` 等非敏感词误命中。

模式表可经 `pipeline.Config.SensitivePatterns` 整体替换（pipeline.go:36-37）；
`CompileSensitivePatterns` 对空 `data_type`/`pattern` 或正则编译失败返回错误，
管线启动即报配置错误，不静默降级（sensitive.go:118-134、pipeline.go:145-148）。

## 四、检测规则与升级

`CheckSensitiveData`（sensitive.go:140-180）：

| 规则 ID | 位置 | 类别 / 严重度 | ScoreDelta | 含义 |
|---------|------|---------------|------------|------|
| `sensitive.in_query` | Query 键名 | BLOCK / HIGH | 40 | 敏感字段出现在 URL，明文外泄（日志、历史记录、Referer 均会留存） |
| `sensitive.field` | JSON / Form / XML 字段名；值级规则开启时扩展非标准协议 HEADER 名（跳过标准浏览器/HTTP 头，不做 URL 路径字面段匹配） | OBSERVE / MEDIUM | 10 | 请求载荷/业务头携带敏感字段，观察记录 |
| `sensitive.value_in_query` | Query 值（值级 regex） | BLOCK / HIGH | 40 | 敏感值出现在 URL，与键名命中同一升级语义（值级规则下发才启用） |
| `sensitive.value` | JSON / Form 留存值、HEADER 非脱敏头值、PATH 原始段值（值级 regex） | OBSERVE / MEDIUM | 15 | 值级命中观察记录（证据不落值，PATH 证据用段序号/占位名） |

- **扫描顺序与预算**：Query 优先（高危），随后 JSON、Form、XML；
  单请求 match 总量上限 `maxSensitiveMatches = 20`（sensitive.go:39），
  防超大报文撑爆事件（sensitive.go:38 注释）；值级扫描另有单值 4096 字符截断
  （`maxSensitiveValueInputLen`）与单请求 512 次求值上限（`maxSensitiveValueScans`），
  规则条数 ≤256、单条正则 ≤512 字符（启动期编译，非法拒绝加载不静默）。
- **Query 升级即 BLOCK 类**：URL 中的敏感字段（键名或值）视为高危信号，
  PROTECT 模式下经统一决策可阻断；请求体内的命中只观察不阻断——体内携带
  敏感字段是 API 常态（登录、开户），阻断会造成大面积误伤。
- **Evidence 要素**：`field`（字段名/路径；PATH 值级命中用段序号/占位名）、
  `data_type`（上表标签或值级规则类型）、`location`（query / json / form / xml /
  header / path），值级命中另携 `level`（五级敏感等级透传）；无值、无值长度、无值哈希。

## 五、api_sensitive_fields 与查询接口

### 5.1 表结构

迁移 000018 第 282-293 行；迁移 000040 追加运行时统计列：

| 列 | 说明 |
|----|------|
| `endpoint_id` | API，FK 级联删除 |
| `direction` | `REQUEST` / `RESPONSE`，默认 `REQUEST` |
| `structured_path` | 字段结构化路径 |
| `data_type` | 数据类型标签（phone / id_card / bank_card / email / credential / …） |
| `confidence` | 置信度 |
| `detection_source` | `AUTO` / `MANUAL`（000018 注释口径），默认 `AUTO`；运行时写入方为 `RUNTIME`（000040 Sweep） |
| `created_at` / `updated_at` | 时间戳 |
| `first_seen` / `last_seen` / `occurrence_count` / `source_detail` | 000040 追加：首/末次发现时间、出现次数、最近命中摘要（SweepOnce upsert 维护） |

约束：`UNIQUE (endpoint_id, direction, structured_path)`——同API同方向同路径
唯一行，重复识别自然去重。

### 5.2 查询接口

`GET /api/v1/api-security/sensitive-fields`（`apisecurity/routes.go:76-77`，
权限 `api_runtime.read`）：

- 过滤：`endpoint_id`（非法 UUID 返回 400）、`direction`（仅 REQUEST/RESPONSE，
  其他返回 400）、`data_type`、分页（handler.go:657-680）；
- 仓储 `ListSensitiveFields`（sensitive.go:28-80）按白名单字段拼接 WHERE、
  值一律参数化，`updated_at DESC` 排序分页；过滤条件不含任何用户输入拼接；
- 前端页面 `web/src/pages/api-sensitive-fields/ApiSensitiveFieldsPage.tsx`。

## 六、关键设计决策

1. **字段名即信号；值只在值级规则下发时入场、且只进证据安全通道**。字段名检测输入
   是解析层的字段名集合（`p.Query`、`p.JSONFields`、`p.FormFields`、`p.XMLFields`）；
   值级检测（第三波起）仅对留存值做 RE2 匹配（单值 4096 字符截断、求值预算封顶），
   证据仍只含字段名/类型/位置/等级，**任何路径都不落值**；这与任务书 2.7"字段名只是
   数据"一体两面——不针对具体字段名写业务策略，但字段名本身是通用的敏感度信号。
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

- **画像表已有写入方（000040）**。`api_sensitive_fields` 由 apidata SweepOnce
  水位幂等 upsert（occurrence_count++/last_seen，detection_source=RUNTIME，
  MANUAL 行来源不被改写）；查询接口读到真实台账。台账已与参数模型联动：
  学习调度 Sweep 在参数统计画像刷新后调用 `PropagateSensitivityLevels`
  （`server/internal/apimodels/sensitivity_propagate.go`），按「参数名 = 台账
  structured_path 末段 + 位置由首段映射」把台账命中回写为参数模型
  `sensitivity_level`（credential/bank_card/id_card→HIGH，phone/email→MEDIUM，
  其他非空→LOW；只补 UNKNOWN 不覆盖人工已定级别，映射细则见
  docs/API_PARAMETER_MODEL.md 第三节）。
- **响应侧字段名级检测已落地（第一波）**：响应相位 `ProcessResponse` 复用同一词表
  检测响应 JSON 字段路径（`sensitive.response_field`，不落值），字段级脱敏与
  值级响应检测的剩余缺口见 docs/API_RESPONSE_SECURITY.md；值级检测当前仅请求侧。
- **字段名模式 + 值级 regex 双手段（第三波起）**。值级规则（`api_sensitive_value_rules`
  发布下发，管理面 `api_sensitive_data_types.regex`）对留存值做 RE2 匹配；
  仍无校验器（Luhn、身份证号校验位）类 validator；混淆命名（`f1`、`col_a`）
  字段名级识别不到（值级可部分弥补）。
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
