# API 路径归一化设计（阶段8 / WDSP）

## 一、目的与范围

路径归一化把 `/api/users/10001`、`/api/users/10002` 这类带动态段的 URL 折叠为稳定
的路径模板 `/api/users/{id}`，使API获得**稳定身份**：发现登记、命中计数、冻结模型
下发、生命周期基线比对全部以归一化产物为键。本文覆盖：

- 归一化规则（`gateway/dynamic_security/normalizer/path.go`）；
- `endpoint_key` 规范与全体使用方；
- 合并兼容判定与API别名表（`api_endpoint_aliases`）。

## 二、归一化规则

`NormalizePath`（`normalizer/path.go:17-56`）分两步：先净化、后逐段替换。

**净化**：

1. 剥离 query/fragment（`?`、`#` 起截断）；
2. 补前导 `/`；
3. 折叠连续 `/`；
4. 去尾部 `/`（根路径 `/` 除外）；
5. 空输入归一为 `/`。

**段级替换**（按序匹配，先 UUID 再整数再长十六进制）：

| 规则 | 正则 | 替换为 | 示例 |
|------|------|--------|------|
| UUID（大小写不敏感） | `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$` | `{uuid}` | `/o/550e8400-e29b-41d4-a716-446655440000` → `/o/{uuid}` |
| 纯数字 | `^\d+$` | `{id}` | `/users/10001` → `/users/{id}` |
| 长十六进制（≥16 位） | `^[0-9a-f]{16,}$`（i） | `{hex}` | `/t/9f2c…ab01` → `/t/{hex}` |
| 其余段 | — | 保留字面量 | `/api/orders` 不变 |

替换不改变段的数量与顺序；字面量段（含短十六进制、含字母数字混合的标识、
日期型 `2024-01-01`、带点文件名 `a.json` 等）**保持原样**。

**归一化示例（单测锁定，`normalizer/path_test.go:5-45`）**：

| 原始路径 | 归一化结果 |
|----------|------------|
| `/users/123` | `/users/{id}` |
| `/users/550e8400-e29b-41d4-a716-446655440000` | `/users/{uuid}` |
| `/v1/orders/99/items/7` | `/v1/orders/{id}/items/{id}` |
| `/static/app.js` | `/static/app.js`（文件名段保留） |
| `users/1?x=1` | `/users/{id}`（补前导斜杠、剥离 query） |
| `//a//b//` | `/a/b`（折叠斜杠、去尾斜杠） |

`EndpointKey("get", "/users/1")` 与 `EndpointKey("GET", "/users/99")` 产出同一键
`GET /users/{id}`；`POST /users/{id}` 与之不同键（方法区分API）。
`MergeCompatible("/users/1", "/users/2")` 为真、
`MergeCompatible("/users/1", "/orders/1")` 为假。

## 三、endpoint_key 规范

`EndpointKey(method, rawPath)`（`path.go:59-65`）：

```text
endpoint_key = 大写HTTP方法 + 单个空格 + NormalizePath(rawPath)
```

- 方法去空白并大写，空方法按 `GET`；
- 不同方法是不同API（`GET /users/{id}` ≠ `POST /users/{id}`，任务书 §65 第12条）；
- 键长上限 560（`VARCHAR(560)`，迁移 000016；事件日志同长截断，`apievents.go:37`）。

**全体使用方（同一算法、同一键空间）**：

| 使用方 | 位置 | 用途 |
|--------|------|------|
| 管线 | `pipeline/pipeline.go:73-74` | 写扩展 `api.endpoint_key`，供生命周期/限速检测 |
| guard 挂点 | `apiprotect.go:68` | 按键查 `api_formal_schemas` 选冻结模型 |
| 发现入库 | `apiassets/store.go:204-212` | `ON CONFLICT (endpoint_key)` 幂等 upsert |
| 基线下发 | `apiassets/store.go:272`（`ListKeyStatus`） | `endpoint_key → asset_status`，生命周期检测 |
| 模型下发 | `apimodels/store.go:497`（`ListFormalSchemas`） | `endpoint_key → 字段类型表` |
| 模型版本 | `apimodels/store.go:130` | 内容哈希输入之一（endpoint+schema） |
| 事件 | `apievents/apievents.go:23` | 主事件与发现的关联键 |

网关与管理面共享同一份 Go 源码（`gateway/dynamic_security/normalizer`），
管理面直接 import（如 `apiassets/handler.go:13` 拆分路径归一化），
**不存在两份实现漂移的风险**。

## 四、合并兼容与拆分

`MergeCompatible(a, b)`（`path.go:68-70`）：两条原始路径归一化结果相等即可合并为
同一API。这是**模板一致性**判定，是合并的必要条件而非充分条件——任务书 §10.4
要求结合方法、结构、用途、人工确认，本实现中「是否合并」始终由管理员在管理面
显式执行（`POST .../endpoints/{id}/merge`），系统不自动合并。

**合并时的别名归档**（`apiassets/store.go:312-383`）：

```text
api_endpoint_aliases(endpoint_id, alias_key, created_reason='merge')
  - other API的历史 endpoint_key 归档到 primary；
  - alias_key 全局唯一（迁移 000018 唯一索引），重复归档幂等（ON CONFLICT DO NOTHING）；
  - other 删除，hit_count 与 last_seen_at 并入 primary，写 MERGED 生命周期事件。
```

别名表的用途：历史事件/旧配置中的API键仍可追溯到存续API，为后续按别名归并
统计、重归一化迁移保留映射。当前实现中别名在合并时写入，查询侧尚无独立接口
（经API生命周期事件可见合并轨迹）。

**拆分**（`store.go:387-436`）：管理员指定若干新路径（先经 `NormalizePath`，
`handler.go:304-311`），按 `方法 + 新路径` 生成新API（继承 application/domain/
置信度/协议/is_api，初始 DISCOVERED）；键已存在返回 409 冲突；原API写 SPLIT
生命周期事件。拆分不删除原API、不写别名。

## 五、关键设计决策

1. **只替换三类高置信动态段**。数字 ID、UUID、长十六进制几乎必然是对象标识；
   其余段保守保留字面量。误合并的代价（两个不同API共享一个模型/基线）远大于
   多登记几个API的代价，规则从简从严（任务书 §10.4「不得仅因为路径位置均为
   数字就自动合并」——本实现连「自动合并」本身都不做，合并一律人工）。
2. **方法进入API键**。同一模板的不同 HTTP 方法语义不同、Schema 不同，
   拆为独立API才能独立学习与防护。
3. **键即算法产物，不含随机成分**。任何节点、任何时刻对同一请求算出的键一致，
   采集重放与多节点上报天然幂等；键可复算也意味着别名表只用于「历史键 →
   存续键」的演化映射，而非身份本体。
4. **归一化前置到解析器**。`parser.ParseRequest` 同时产出 `RawPath` 与
   `NormalizedPath`（`parse.go:69`），后续分类、检测、发现、事件全部使用同一对
   路径，避免「检测用一套模板、入库用另一套」。
5. **对象段类型复用归一化产物**。BOLA 辅助检测按 `{id}/{uuid}/{hex}` 段识别
   对象标识形态（`detectors/resource.go:83-105`），归一化一处定义、多处消费。

## 六、当前实现范围与限制

对照任务书 §10.2 的 12 类动态段（整数/长整数/UUID/雪花ID/日期/时间/时间戳/
哈希/文件名/业务编号/随机字符串/枚举路径/自定义模式）：

1. **当前实现三类**：纯数字、UUID、长十六进制。日期/时间戳/雪花 ID 若由纯数字
   构成会被 `{id}` 覆盖（如 `/o/20240101`）；含分隔符的日期（`2024-01-01`）、
   短哈希、随机字符串、文件名、业务编号**不归一**，各流量会形成独立API键，
   需人工合并收敛。
2. **占位符不可改名**：模板固定为 `{id}/{uuid}/{hex}`，任务书 §10.3「管理员将
   `{integer}` 改名为 `{userId}`」未实现；`api_endpoint_path_segments` 表
   （段级样本与变量名）已建但无写入方。
3. **无自定义模式**：不支持管理员配置段级正则；`MergeCompatible` 只做模板相等
   判定，不做模糊相似度。
4. **拆分以路径为粒度**：任务书 §10.5 的按 Content-Type/GraphQL operation/认证
   方式拆分未实现；拆分入口只接受路径列表。
5. **归一化不影响转发**：模板只用于身份与检测，转发给源站的始终是原始路径
   （`RawPath`），归一化不改变业务流量。

## 七、与任务书章节对应

| 本文章节 | 任务书 |
|----------|--------|
| 二、归一化规则 | §10.2 动态路径识别（裁剪子集）、§10.3 归一化示例 |
| 三、endpoint_key | §10.1 唯一键（application/domain 维度的当前取舍见下） |
| 四、合并与拆分 | §10.4 合并安全、§10.5 API拆分 |
| 五、决策 1/2 | §10.4「不得仅因数字段自动合并」 |

说明：任务书 §10.1 的唯一键含 `application_id + domain_id + http_method +
normalized_path + protocol_type` 五元组；当前 `endpoint_key` 为「方法+模板」
二元组，应用归属经 `api_endpoints.application_id` 列独立承载（发现 upsert 暂不
回填，见 `docs/API_DISCOVERY_DESIGN.md` 七.6），同键跨应用共享模型与基线的
隔离问题在产品分离边界内按单网关单租户语义接受，后续独立 API 产品时扩展。

---

Copyright © 聚信得仁
All Rights Reserved.
