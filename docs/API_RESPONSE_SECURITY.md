# API 响应侧安全设计（ResponseContext / 响应相位 / Response Transformer）

> 对应任务书 §226（P0-05 ResponseContext、P0-07 MASK_RESPONSE）。本文以当前代码为准，
> 覆盖响应捕获、JSON/XML/文本/SSE 值级检测、gzip/br 解压与重编码、五类脱敏算法及密钥管理。

## 一、目的与范围

API 响应在返回客户端前进入统一捕获与响应相位，完成敏感检测、错误签名提取、字段级脱敏和事件输出。
核心实现：

- `ResponseContext`：`gateway/dynamic_security/context/context.go`；
- 捕获与压缩：`gateway/modules/jiuzhang_guard/apiresponse.go`、`apiresponsecompression.go`；
- 响应相位：`gateway/dynamic_security/pipeline/response.go`；
- 值级检测：`dynamic_security/detectors/response_sensitive_value*.go`；
- SSE 单事件检查：`gateway/modules/jiuzhang_guard/apiresponsesse.go`；
- 脱敏：`dynamic_security/response/rule.go`、`transform.go`、`mask_crypto.go`。

数据最小化不变：ResponseContext 不保存明文体；解码树和标量只在当前请求内存中使用。
事件和证据只含字段路径、类型、等级、方向、规则标识及值级命中时的网关内存脱敏样本（`masked_sample`，凭据类固定 `******`），绝不含敏感原值或密钥。

## 二、ResponseContext

响应相位写入以下元数据：

```text
status / content_type / headers（脱敏快照）
body_size / body_hash（sha256 前 8 字节 hex）
truncated / streamed
is_json / parsed_body（JSON 字段路径 → 类型）
sensitive_fields[]（字段路径与类型标签）
error_signatures[]
transform_plan[]（字段路径、算法、参数及 key_id/map_id，不含密钥）
```

流式响应此前已积累的 `SensitiveFields` 在最终响应相位继续保留。BodyHash 是实际用于分析的捕获体哈希；
压缩响应分析体为解压后的内容，BodySize 仍表示源站实际传输字节数。

## 三、捕获策略

仅 API 流量包装捕获，非 API 不增加响应包装。主要分支如下：

| 条件 | 行为 |
|---|---|
| JSON 族或缺失 Content-Type | 完整缓冲，响应相位后写回 |
| XML / `text/plain` 且配置了 `response_body` 值级规则 | 完整缓冲并检测；无规则时维持原直通行为 |
| gzip / br 且非 SSE、非升级 | 保留原始压缩字节，解压后供检测/改写；未改写时原字节交付 |
| SSE `text/event-stream` | 单事件缓冲、即检即放，不整流缓存；MCP 活跃时由 MCP 专用 writer 独占避免重复检测 |
| 其他显式非 JSON / 二进制 | 原路径直通，不伪造结构化解析 |
| 101 / Upgrade / Hijack | 直通或脱离捕获，不能改写 |
| 超过捕获上限或解压上限 | FAIL_OPEN 原样直通并 Warn；FAIL_CLOSED 且存在脱敏规则则抑制 |

默认捕获上限 1 MiB，配置硬上限 16 MiB。压缩解压只允许单一 `gzip` 或 `br`，多重编码和未知编码不处理；
解压读取严格限制为当前捕获上限 + 1，防压缩炸弹。Range/206 不做字段脱敏、水印或签名改写。

## 四、响应相位与值级检测

`ProcessResponse` 复用已解码内容执行：

1. JSON 解析和结构观测，`UseNumber` 保留数字字面量；
2. JSON 字段名敏感检测 `sensitive.response_field`；
3. `response_body` 值级检测 `sensitive.response_value`；
4. 错误签名与服务器信息泄露检测；
5. 响应偏离、字段权限和脱敏计划；
6. 统一决策，计划非空且 PROTECT 时执行 `MASK_RESPONSE`。

### 支持的值级输入

- **JSON**：复用首次解析根值，排序遍历对象并扫描全部数组元素；
- **XML**：元素文本和属性，拒绝 DTD，限制深度、节点/路径、字段和扫描次数；
- **`text/plain`**：按完整行扫描，证据位置使用 `text.line[N]` 等安全标签；
- **SSE data**：JSON data 复用 JSON 树扫描，文本 data 按行扫描，keepalive 原样透传。

所有上述命中均为 `sensitive_data / sensitive.response_value`（OBSERVE/MEDIUM）。
证据只含安全字段位置、data_type、level、location=response_body、direction=RESPONSE 与网关内存脱敏后的 `masked_sample`（中间位打码，凭据类固定 `******`）。
敏感原值不会写入事件。新检测不单独新增阻断或响应改写。

非法 UTF-8、DTD、超深、超预算、未完结 SSE 尾块等产生零分值的
`sensitive.response_body_unchecked`（带 `completion=partial` 和明确 `skip_reason`），不能把未检查当成安全。

## 五、Response Transformer

### 5.1 规则与计划

规则来自 `api_masking_rules` enabled 行，经 `api_mask_rules` 发布到网关。
点路径支持对象嵌套和 `[]` 数组通配，同路径首条规则生效；object/array 目标仅 REMOVE 可执行。
字段路径最长 256，规则最多 512，JSON 重编码使用 `UseNumber` 和 `SetEscapeHTML(false)`。

### 5.2 五类算法

| 算法 | 参数 | 语义 |
|---|---|---|
| MASK | `keep_head` / `keep_tail` | 保留前后字符，中间按原长度替换 `*`；短值整体为 `****` |
| HASH | 无 | 标量字符串形式取 sha256 hex，不可逆 |
| REMOVE | 无 | 删除对象成员或数组元素 |
| ENCRYPT | `key_id` | AES-256-GCM，输出 `enc_<kid>_<base64(nonce|ciphertext)>` |
| MAP | `map_id` | 同密钥 HMAC-SHA256 按域、mapID 和值映射，输出 `map_<mapID>_<前8字节hex>` |

`key_id/map_id` 均为 1–64 位 `[A-Za-z0-9_-]`，必须且只能单独出现在对应算法参数中。
MAP 同值同结果、不可逆，不保存原值映射表；它不是可逆字典加密。ENCRYPT 的 nonce 随机生成，授权恢复必须重新解密。

### 5.3 密钥与恢复审计

- 运行时设置：`gateway_runtime.api_mask_encryption_kid` 与 `api_mask_encryption_key`（密文）；
- 发布时解密并校验 32 字节 hex，向网关下发 `api_mask_crypto:{kid,key_hex}`；
- 仅存在 ENCRYPT/MAP 规则时强制加载密钥，缺失、格式错误、解密失败或 kid 不匹配均拒绝发布/加载；
- 密钥和 AEAD 不导出，规则、事件、计划只带 kid/mapID；快照和整站配置 JSON 脱敏，回滚按当前密钥重注入；
- 密钥不进入 `api_policy_version`，不记录到日志。

授权恢复接口：`POST /api/v1/api-security/masking-rules/decrypt`，权限 `api_data.manage`。
请求只含 `ciphertext`（最长 4096），成功返回 plaintext 并记录不含明文、密文和密钥的 HIGH 审计。
错误 kid、格式或解密失败返回不泄密的 400，未配置或不可用返回 503。MAP 不支持恢复。

## 六、压缩与流式处理

### gzip / br

- 捕获器始终保留源站原始压缩字节；
- 解压后供 ProcessResponse、ApplyJSON、水印和签名使用；
- 未发生修改时原始压缩流逐字节交付；
- 发生脱敏、水印或签名修改时按原编码重新压缩，保留 Content-Encoding 并修正 Content-Length；
- 解压失败、超限、多重编码：FAIL_OPEN 返回原压缩字节并 Warn，不将残片当完整 JSON；FAIL_CLOSED 且有脱敏规则时抑制。

Brotli 使用 `github.com/andybalholm/brotli v1.3.0`（MIT，已锁定并归档许可证）；gzip 使用 Go 标准库。

### SSE

- 单事件上限 1 MiB、单流事件数上限 4096、流字节上限 16 MiB；
- 支持分片写入、多行 data 和 keepalive；事件检查通过即放行并 flush；
- 预算耗尽或流尾未完结，余量原样直通并披露 partial；不整流缓存；
- 当前仅做敏感观测，不新增中途阻断或已外发内容撤回，不承诺流式脱敏。

## 七、失败策略与事件

| 场景 | FAIL_OPEN（默认） | FAIL_CLOSED |
|---|---|---|
| 捕获/解压超限 | 原响应完整交付 + Warn | 有脱敏规则时 500 空明细抑制 |
| 多重/未知编码或压缩数据损坏 | 原压缩字节交付 + Warn | 同上抑制 |
| Transformer/密钥执行失败 | 原响应交付 + `response.mask_failed` + Warn | 抑制并记录失败 |
| Hijack / 已外发内容 | 直通，不撤回 | 不能用于已外发内容 |

API 放行事件在响应完成后输出，带真实 response_status 和 latency_ms。
`response.mask_applied` 记录应用/跳过字段数，`response.mask_failed` 记录失败，均不包含密钥或原敏感值。

## 八、性能保护

- 捕获与解压均有上限，禁止无限整流缓存；
- JSON 深度/字段数受 ParseLimits 约束；
- 值级规则求值上限 512、单值输入上限 4096 rune、字段名与值级命中各上限 20；
- XML 另有深度、节点、路径和扫描预算；
- SSE 单事件/事件数/流字节均有上限，预算耗尽明确披露；
- 事件字段继续执行截断、控制字符清理和脱敏；
- 响应采样比例沿用 `api_response_sample_ratio`：0 不解析，中间比例只处理可解析的采样内容。

## 九、当前限制

1. 多重编码、deflate 等不在当前支持范围；
2. 压缩 SSE 不承诺检测或脱敏，SSE 只支持明文流式观测；
3. 普通文本扩展范围为 `text/plain`，其他 `text/*`、表单和二进制不新增结构化解析；
4. XML 必须完整可解析，非法 XML/DTD 不扫描；表单和二进制脱敏仍未实现；
5. MAP 是确定性 HMAC 映射，不支持恢复；ENCRYPT 恢复依赖当前密钥，轮换后旧密文能否恢复取决于旧密钥是否保留；
6. 点路径 DSL 无法寻址键名含 `.` 的字段；
7. 当前验证以真实 serveNext、writer 边界和单元/集成测试为主，尚未完成真实 Caddy 反代、长连接浏览器互操作、压缩性能基准及实库发布验收。

## 十、测试证据

- `response/mask_crypto_test.go`：AES-GCM 可恢复、MAP 确定性、缺密钥和 kid 不匹配；
- `apimaskcrypto_test.go`：Guard ENCRYPT/MAP 完整改写及事件无密钥/明文泄漏；
- `apiresponsecompression_test.go`：gzip/br 检测、脱敏、重压缩、原字节保持、损坏/超限/失败策略；
- `detectors/response_sensitive_value_text_test.go`、`pipeline/response_text_value_test.go`：XML/文本、DTD、UTF-8、深度和预算；
- `apiresponsesse_test.go`：SSE 分片、后续事件、keepalive、预算和未完结尾块；
- `apiresponsetextvalue_test.go`：普通 XML/文本真实 serveNext 与压缩组合；
- 管理面 000213 静态测试及 OpenAPI 双向对账；实库密钥发布、解密和浏览器验收仍需真实环境执行。
