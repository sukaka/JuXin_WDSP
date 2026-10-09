# NG-AZ-01 权威关系接入（authorities & imports）冻结设计（S3 阶段 0，2026-10-04）

> 依据：RD_PLAN §8.2（权威关系输入）+ NG-BASE-02 §4.2/§4.5 + NG-BASE-03 §3（T5/T6/T7 滥用场景）。
> 目标：对象授权关系的两条可信入口——**离线签名导入**与**业务系统主动推送**；自动拉取仅在用户明确配置授权后另行建设，不在请求热路径访问业务系统。
> 前置事实（NG-BASE-01 D9 / inventory）：现有 `apiauthz` 已有候选确认/手工关系/撤销/重新授权/有效期/覆盖/决策查询与签名快照发布（`guardconfig/authz_decision.go`：ModelVersion/SnapshotExpiresAt/PreviousValid）。**本批不重建关系 CRUD**，只新增「权威来源 → 关系与撤销」的可信输入通道与版本水位语义。

## 1. 输入契约（冻结）

每条权威变更事件：

| 字段 | 类型 | 约束 |
|---|---|---|
| `source_id` | string | 已登记来源 ID（未登记来源一律拒收，不自动登记） |
| `event_id` | string | 来源侧全局唯一事件 ID（幂等键：重复 event_id 按已消费跳过并如实计数） |
| `sequence` | uint64 | 来源侧单调递增序列（缺口/乱序检测依据；来源须保证单调，管理面校验） |
| `object_type` | string | 白名单（首批与现有关系对象类型词表一致，不在词表拒收） |
| `tenant_domain` | string | 租户域（与现有关系租户语义一致；跨域事件须来源范围授权覆盖） |
| `principal_ref` | string | 主体引用（HMAC 域隔离后的受控引用，不存明文身份） |
| `object_ref` | string | 对象引用（HMAC 域隔离，不存明文对象标识） |
| `relation` | enum | `OWNER`（首批唯一排他关系词；共享/委托/组继承不支持——见 §5） |
| `change_type` | enum | `GRANT` / `REVOKE` |
| `valid_from` / `valid_until` | RFC3339 | valid_until 可空=不限；valid_from 不得晚于 valid_until |
| `issued_at` | RFC3339 | 签发时间（陈旧事件按来源声明的最大可接受年龄单独配置，不全局拍死） |
| `source_signature` | string(hex) | 对上述全部字段的规范化字节（键序字典序紧凑 JSON）Ed25519 签名 |

批次契约：`{batch_id, source_id, mode: "snapshot" | "delta", items[], batch_signature}`。
- **snapshot（全量快照）**：暂存区整体校验（条数上限、完整性、对象域一致性）后**原子切换**；导入中断**绝不把未导入对象当作撤销**（全量语义只在切换成功时成立）。
- **delta（增量）**：按 sequence 顺序应用；缺口未补齐时标记数据不完整（`AUTHZ_SOURCE_GAP`），不伪造最新状态；重复/乱序如实计数。

## 2. 校验链（冻结，按序执行，任一失败整批拒绝并展示原因）

1. 来源身份：source_id 已登记且 ACTIVE；签名按来源登记的公钥验签（多公钥按 key_id 轮换，与发布签名密钥**不混用**）。
2. 范围权限：事件的 tenant_domain/object_type 必须落在来源被批准的范围（来源登记时的 scope 白名单）。
3. 重放：event_id 幂等（已消费跳过）；sequence 必须 > 已应用水位（snapshot 模式下按批次序列整体推进）。
4. 大小与字段白名单：批次条数/单条字段长度/未知字段（严格白名单，未知字段拒收不忽略）。
5. 字段语义：词表（relation/change_type/object_type）、时间关系、引用形态。

## 3. 冲突与水位（冻结）

- **冲突状态**：同一 (object_type, tenant_domain, object_ref) 出现两个不同 `principal_ref` 的有效 OWNER → 进入**冲突状态**（不可信），**不按「最后到达者」覆盖**；冲突中的对象不参与 VERIFIED_VIOLATION 判定（NG-T-A03/A04）。
- **撤销水位**：REVOKE 事件推进单调撤销水位（SnapshotWatermark.revocation_watermark）；普通策略回滚不得使其下降；PreviousValid 仅允许回退到不越过该水位的有效快照。
- **快照有效期**：沿用现有 24h 快照（签名+PreviousValid 回退）；权威通道只改变关系来源，不改变既有快照发布机制。

## 4. 密钥与隔离（冻结）

- 来源验签公钥、发布签名密钥、对象 HMAC 密钥**三把钥匙不混用**；私钥不下发流量网关、不进升级包。
- principal_ref/object_ref 沿用现有 HMAC 域隔离机制；**密钥轮换期双版本匹配与清退必须明确**（轮换窗口内新旧两版并存匹配，窗口外只认新——窗口长度随轮换事件登记）。
- 日志/事件不落原始 Token、Cookie、私钥、完整对象标识、主体明文（NG-BASE-02 §4.2-8；低熵值不做普通 SHA-256 冒充匿名）。

## 5. 首批不支持（如实标注，不静默扩展语义）

共享对象、委托、复杂组继承、嵌套租户、批量对象、复合 ID、对象字段级授权——事件中出现一律按不支持拒收并展示原因，不降级猜义。历史访问推断关系**只能进候选待确认**，不具备阻断资格（EnforcementEvidence.evidence_source=HISTORY_INFERRED 恒 NOT_ELIGIBLE）。

## 6. 接口与权限（冻结候选名，实现时按现有权限模型注册）

- `GET/POST /api/v1/api-security/authz/authorities` + `/{id}`（来源登记/启停/范围；候选权限 `api_authorization.authority_manage`，建议双人复核——阶段 0 待定）；
- `POST /api/v1/api-security/authz/authorities/{id}/imports`（离线批次导入；候选权限 `api_authorization.authority_import`；与来源管理分权）；
- 业务推送通道与离线导入走**同一校验链与同一事件模型**（推送仅为在线形态的 delta 批次，不混用管理员登录凭据）；
- 读取（来源列表/状态/缺口/冲突/最近同步）沿用 `api_authorization.read`。

## 7. 测试锚点（NG-T-A01~A06 映射）

有效本人/他人 OWNER（A01）、历史推断不阻断（A02）、跨租户同名/共享/冲突（A03）、关系过期/签名错误（A04）、撤销水位不下降（A05）、重复/乱序/缺口可见无静默覆盖（A06）。

## 实现状态（2026-10-04，NG-AZ-01 第一批已上线）

### 文件清单

- 迁移 `server/migrations/000172_authz_authorities.{up,down}.sql`（六表 + 关系表溯源列/词表 + 权限种子）。
- `server/internal/apiauthzauthority/`：`types.go`（契约类型与登记校验）、`canonical.go`
  （规范化签名输入与 Ed25519 验签/轮换窗口）、`store.go`（六表存储 + 权威关系写入）、
  `service.go`（五步校验链 + 来源管理）、`apply.go`（snapshot 原子切换 / delta 应用 / 水位 / 缺口 / 冲突编排）、
  `handler.go`（六端点）；测试：canonical/service_unit/handler/service_integration 四层
  （真实 PG 门控 `AUTHORITY_TEST_PG_DSN`）。
- 装配：`server/internal/app/app.go`（WDSP 块注册 + 导入成功触发整站发布）；
  OpenAPI `server/openapi/fragments/07-api-security.yaml`（6 操作 + 12 schema，对账 684 零差集）。

### 契约偏差与实现决策（如实登记）

- **D1（补充字段）**：事件携带 `key_id`（§2 第 1 步「按 key_id 选公钥」需要落点；纳入签名输入防替换）；
  批次携带 `key_id`（batch_signature 验签键选择）。
- **D2（snapshot 词表收窄）**：snapshot 批次仅接受 GRANT 项——全量状态语义（不在集合即撤销），
  REVOKE 在 snapshot 中无意义，第 5 步拒收展示。
- **D3（第 3 步序号的缺口补齐解读）**：§2 第 3 步字面「sequence 必须 > 已应用水位」与 §1 delta
  「缺口补齐自动消除」存在张力。实现按后者收口：event_id 未消费且序号落在缺口内的补隙事件属
  合法新事实照常应用；**同序号不同 event_id（重放攻击面）整批拒收**；delta 批内非升序拒收展示；
  snapshot 批次最大 sequence 不大于水位按陈旧快照拒收。E2E/集成双重锚定。
- **D4（tenant_domain → application_id）**：关系表 `application_id NOT NULL FK` 需要应用落点——
  按管理面 ACTIVE 应用域（application_domains.normalized_hostname）解析；解析不到/多义即第 5 步
  语义失败展示。relation.tenant_id 落 tenant_domain 原值。
- **D5（REVOKE 作用域）**：仅撤销本来源（source_id 相同）AUTHORITY_SYNC 有效行——来源只管自己
  签发的事实，不撤销 MANUAL/其他来源关系；对不存在的关系 REVOKE 照常记账并推进撤销水位
  （「确保撤销」幂等语义）。
- **D6（批次留痕 FK）**：api_authority_import_batches.source_id 有 FK——未登记来源的导入拒收
  批次无法落库（跳过留痕，响应照常返回 REJECTED 与原因）；登记在册来源的拒绝批次全量留痕。
- **D7（冲突 GRANT 不落行）**：冲突拒绝的 GRANT 不落关系行（仅 ConflictRecord + 幂等账本）——
  与「不按最后到达者覆盖」一致；冲突解除（REVOKE/切换收敛 ≤1 有效 OWNER 自动 RESOLVED）后，
  来源须重新签发新 event_id 事件方可落关系（被冲突拒绝的事件已消费，重发按重复跳过）。
- **D8（对象类型词表）**：现有关系模型 object_type 无冻结枚举（自由文本）——第 5 步按标识符
  形态 + 来源 scopes 白名单双重约束；「与现有关系对象类型词表一致」在本批即 scopes 显式授权。
- **D9（issued_at 时钟漂移）**：超前当前时间 >5 分钟按语义失败拒收（时钟漂移容忍）。
- 本批不改 authzdecide / 快照发布侧（guardconfig/authz_decision.go）——权威 CONFIRMED 行随既有
  发布链自然下发；冲突对象不参与 VERIFIED_VIOLATION 的决策侧排除、PreviousValid 回退不越过
  撤销水位的发布侧约束、节点 ACK 与租约，移交 NG-AZ-02。

### E2E 证据摘录（stage5，2026-10-04）

1. 未登记来源导入：`status: REJECTED`（来源未登记，不自动登记；FK 下留痕跳过）。
2. 登记来源（测试 Ed25519 公钥）→ 签名 delta GRANT：`status: APPLIED counts.grants=1`；
   `GET /api/v1/api-security/authz/relations` 可见 `source: AUTHORITY_SYNC status: CONFIRMED`；
   库内 `source_id`/`source_event_id=e2e-evt-1` 溯源齐全。
3. 重发同批：`APPLIED applied=0 skipped_duplicate=1`。
4. sequence 1→3 跳号：`gap_status: AUTHZ_SOURCE_GAP last_sequence: 3 gap_from: 2`。
5. 第二来源对同对象签不同 OWNER：`grants: 0 conflicts: 1`；conflict 列表
   `principals: ['subj:alice','subj:bob'] status: OPEN`（既有 alice 不被覆盖）。
6. snapshot 中途坏行：`REJECTED 校验链第 5 步失败 relation="SHARED_WITH" 首批不支持`；
   relations 前后计数 2=2（原子切换零变更）。
7. jiuzhang_admin（SYSTEM_ADMIN）POST/PATCH/imports 写端点全部 403。
8. 清理：测试关系/冲突/来源删除，发布恢复 SUCCESS；stage5-gateway-tests 40/40、
   custom-pack-blocking 13/13 不回退。
