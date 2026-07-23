# 统一 RequestContext 设计（阶段8 / WDSP）

## 一、目的与范围

`RequestContext` 是阶段8 统一引擎的数据中枢：**同一 HTTP 请求只创建一份上下文**，
一次解析产物写入其中，所有检测器从中读取并把结论写回，决策引擎据其定案
（任务书 §2.1、§2.2、§七）。本文定义其字段分组、一次解析流程、扩展机制与
解析限制/截断语义。

核心实现：`gateway/dynamic_security/context/context.go`（上下文本体）、
`gateway/dynamic_security/parser/`（一次解析器，填充上下文）。

## 二、字段分组

`RequestContext`（`context.go:72-130`）按用途分组，互斥锁保护并发读写：

| 分组 | 字段 | 说明 |
|------|------|------|
| 关联与连接 | `RequestID` `TraceID` `ConnectionID` `ConnectionIP` `ClientIP` `TrustedProxyChain` `OccurredAt` | 全链路关联；IP 用 `netip.Addr` 规范化 |
| 应用与请求线 | `ApplicationID` `DomainID` `Domain` `Scheme` `ProtocolVer` `HTTPMethod` `RawPath` `NormalizedPath` | 应用归属与请求行 |
| API 识别 | `APIEndpointID` `APICandidateID` `APIConfidence` | 置信度 0..1 |
| 内容类型与体量 | `RequestContentType` `ResponseContentType` `RequestBodySize` `RequestBodyHash` `ResponseStatus` `ResponseBodySize` `ResponseBodyHash` | 体只存哈希不存明文 |
| 身份指纹 | `AuthenticationType` `IdentityFingerprint` `TokenFingerprint` `APIKeyFingerprint` `SessionFingerprint` `TenantFingerprint` | **只存指纹/存在性标记**，不存明文凭据 |
| 解析限制与截断 | `Limits` `BodyTruncated` `FieldCountCapped` | 截断标记随上下文传递 |
| 检测与决策 | `Matches` `RiskScore` `RiskLevel` `FinalAction` `EventID` | `Matches` 为 `[]DetectorMatch` |
| 受控扩展 | `Extensions map[string]any` | 键集合固定（见第四节） |

`DetectorMatch`（`context.go:60-68`）是各检测器统一的结论结构：
`detector / rule_id / category / severity / message / evidence（已脱敏键值）/
score_delta`。`AddMatch` 追加明细的同时累加 `RiskScore` 并按阈值映射
`RiskLevel`（1-24 LOW、25-49 MEDIUM、50-79 HIGH、≥80 CRITICAL，`context.go:218-230`）。
`FinalAction` 只允许经 `SetFinalAction` 写入，约定仅决策引擎调用
（`context.go:185-193`）。

任务书 §7 的全量字段清单（70+ 项）在本实现中**裁剪为上述核心可序列化集合**；
其余载体（解析产物明细）经 Extensions 传入，见第四节。

## 三、一次解析

`parser.ParseRequest`（`parser/parse.go:58`）是唯一的协议解析入口，
管线、分类器、各检测器共享其产物，不做二次解析：

```text
*http.Request
  ├─ Query：首值留存，字段数计入 MaxFieldCount，超限置 FieldCapped（parse.go:78-87）
  ├─ Headers：authorization / cookie / x-api-key 一律写 [redacted] 标记，
  │            其余仅首值小写键留存（parse.go:89-98）
  └─ Body（非 GET/HEAD）：
       ├─ multipart/form-data：流式解析，文件内容经 io.Discard 丢弃不落内存，
       │    仅记 PartMeta（字段名/文件名/Content-Type/大小），TeeReader 同步
       │    累计 BodySize/BodyHash（parse_multipart.go:21-57）
       └─ 其余：LimitReader 读 MaxBodyParseBytes+1；
            ├─ 超限 → BodyTruncated，仅保留 MaxBodySampleBytes 采样，
            │    不再做字段级遍历（防截断样本污染 Schema，parse.go:116-137）
            ├─ application/graphql → 操作类型/命名操作（parse_graphql.go:10）
            ├─ JSON（含 { / [ 嗅探）→ JSONFields（路径→粗类型）；
            │    /graphql 路径附带提取 operation/operationName/variables 键名
            ├─ x-www-form-urlencoded → FormFields（字段名→推断粗类型，不落值）
            └─ xml / +xml → XMLFields（流式 token 解析，不建树）
```

JSON 遍历规则（`parse.go:218-265`）：嵌套对象路径以 `.` 连接、数组元素统一为
`path[]` 并只取首元素形态、叶子粗类型词表为
`string|number|bool|object|array|null|unknown`；深度超 `MaxJSONDepth` 即停，
字段数超 `MaxFieldCount` 置 `FieldCapped`。

XML 防御（`parse_xml.go:17-61`）：遇 `DOCTYPE` 立即停止并置 `XMLDTDBlocked`
（XXE 防御：禁止 DTD/实体展开）；嵌套超 `MaxXMLDepth` 置 `XMLTruncated`；
重复兄弟元素共享路径只记一次。

GraphQL 识别（`parse_graphql.go`）：`application/graphql` 原始查询优先于 JSON
嗅探；操作类型识别 query/mutation/subscription/unknown（关键字边界匹配防
`mutationFoo` 误判）；variables 只存顶层键名（排序，不存值）。

体指纹 `BodyHash` 为 FNV-1a 64（`parse.go:267-275`），轻量、非加密用途，
与身份指纹同族（`detectors/authentication.go:184`）。

## 四、扩展机制

任务书 §7.3 要求「检测器写入扩展字段必须注册 Schema，禁止任意动态字段造成内存
失控」。本实现以**固定键常量**方式落实：所有由解析器写入的扩展键在
`parser/parse.go:16-27` 集中声明，管线/检测器使用的键在各自源码中固定：

```text
parser 写入（req.*）：
  req.form_fields  req.xml_fields  req.multipart_parts  req.has_files
  req.graphql_operation  req.graphql_operation_name  req.graphql_variables
  req.multipart_capped  req.xml_truncated  req.xml_dtd_blocked
pipeline 写入（api.*）：
  api.is_api  api.signals  api.endpoint_key        （pipeline.go:70-74）
resource 检测器写入：
  api.object_id_type（numeric/uuid/hex）            （detectors/resource.go:50）
```

写入统一经 `SetExtension(key, value)`（`context.go:206-216`）：空键拒绝、
nil map 惰性初始化；值由调用方保证可序列化且已脱敏。新增扩展键的纪律是：
在写入方包内声明常量并写明脱敏语义，不允许以请求输入拼键。

## 五、解析限制与截断语义

`ParseLimits`（`context.go:38-45`）与默认值（`context.go:48-57`）：

| 限制 | 默认 | 超限行为 |
|------|------|----------|
| `MaxBodyParseBytes` | 1 MiB | 置 `BodyTruncated`，仅保留采样，**跳过字段级遍历** |
| `MaxBodySampleBytes` | 64 KiB | 截断后用于类型嗅探的采样长度 |
| `MaxJSONDepth` | 32 | 停止深入（已解析部分保留） |
| `MaxXMLDepth` | 32 | 置 `XMLTruncated` 并停止解析 |
| `MaxFieldCount` | 2048 | 置 `FieldCapped`，Query/JSON/Form/XML 共用同一计数 |
| `MaxFileMetaCount` | 64 | 置 `MultipartCapped`，不再记录 part 元数据 |

设计要点：

- **截断即标记**：所有截断都有对应布尔标记随上下文与 `Parsed` 传递，
  检测器与事件可感知「这是不完整解析」，不得把截断产物当完整 Schema 使用；
- **截断不做字段遍历**：超大 JSON 只嗅探不展开，防止「半个 Schema」进入学习/偏离
  比对（`parse.go:133-137`）；
- **内存有界**：multipart 文件内容不落内存、XML 不建树、字段数与深度双上限，
  任意畸形/超大报文不能撑爆网关内存；
- 管理面持有同组限制配置（`server/internal/product/edition.go:28-33`），
  经策略接口展示（`apisecurity/policy.go:78-93`），当前下发链路以网关默认值为准。

## 六、数据最小化

- 敏感请求头（authorization/cookie/x-api-key）解析期即脱敏为 `[redacted]`
  （`parse.go:89-98`）；检测器证据只允许记录 scheme、长度分档
  （`detectors/authentication.go:143-159`），凭据值永不进 Evidence；
- 身份维度一律使用 FNV-1a 指纹或「present」存在性标记（`detectors/schema.go:59-79`）；
- 表单字段只存字段名与粗类型，不落明文值（`parse_form.go:11-36`）；
- 上下文对象随请求生命周期存活，不做跨请求持久化。

## 七、关键设计决策

1. **结构体字段 + 受控 Extensions 两层**。高频判定字段（方法/路径/置信度/风险）
   落结构体字段，类型安全；协议相关的解析产物（表单/XML/GraphQL）落
   Extensions，键集合固定。既满足任务书「注册 Schema」的约束，又避免上下文
   结构无限膨胀。
2. **AddMatch 顺带累计风险分**。检测器写结论时同步完成分值聚合，决策引擎只需
   读快照定案，不需要理解各检测器的计分细节（`context.go:147-158`）。
3. **互斥锁内聚在上下文**。检测器在管线内当前是顺序执行，但上下文按并发安全
   设计（`sync.RWMutex`），为后续并行检测留出余地，且成本可忽略。
4. **上下文随请求传递**。管线结果写回 `http.Request.Context()`
   （`apiprotect.go:87`），下游处理器可经 `RequestContextFrom` 复用一次解析
   结果（`apiprotect.go:31-34`），把「一次解析」的收益延伸到引擎之外。
5. **截断优先于检测完整性**。宁可在超大报文上放弃字段级检测，也不做无界解析；
   这与阶段5「URI 正则限长、RE2 线性时间」一脉相承（`docs/SECURITY_DESIGN.md`）。

## 八、当前实现范围与限制

1. **响应侧字段未填充**：`ResponseStatus`/`ResponseBodyHash` 等响应字段已定义，
   但管线当前不解析响应（无响应挂点），均为零值。
2. **连接与身份字段部分未填充**：`ConnectionIP`/`ClientIP`/`TrustedProxyChain`/
   `TraceID`/`ConnectionID` 由 guard 真实 IP 模块掌握，当前未写入统一上下文；
   `ApplicationID`/`Domain` 由 guard 配置掌握，主事件构建时经 guard 侧补齐
   （`apiprotect.go:131-133`），上下文本体未填。
3. **扩展键无运行时注册表**：键集合以源码常量约束（编译期纪律），没有独立的
   Schema 注册数据结构；新键需改代码并评审，符合「禁止任意动态字段」的目标。
4. **解析限制下发未接线**：管理面 `API_MAX_*` 环境变量与策略接口只读展示，
   网关实际使用 `DefaultParseLimits()`（`apiprotect.go:72`），按环境变量定制
   下发尚未实现。
5. **GetExtension 读取 API 未导出**：当前检测器不读取彼此的扩展（资源检测器只写
   `api.object_id_type`），读取走 `Extensions` map 直接访问（同包/测试）。

## 九、与任务书章节对应

| 本文章节 | 任务书 |
|----------|--------|
| 二、字段分组 | §七 统一RequestContext（字段清单的裁剪实现） |
| 三、一次解析 | §2.1 同一请求只解析一次 |
| 四、扩展机制 | §7.3 上下文扩展 |
| 五、解析限制 | §7.2 大报文处理 |
| 六、数据最小化 | §7.1 数据最小化 |
| 八、限制 | §65 退出条件相关项的如实披露 |

---

Copyright © 聚信得仁
All Rights Reserved.
