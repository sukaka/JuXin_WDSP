# P0-04 契约冻结与设计补充（S4 实施基线）

日期：2026-09-07。状态：S4 实施基线（随实施记录偏差）。上位文档：[P0-04 任务书](P0-04_DECISION_SCOPED_EXCEPTIONS.md)；本文档只冻结任务书未尽的接口/字段细节，不改动任务书语义。

## 1. 迁移

| 迁移 | 内容 |
|---|---|
| 000130 | `exception_policies` 增列：target_engine(WAF/API)、api_rule_refs、resolved_rule_ids（标签冻结集）、source_event_id、validation_status(VALID/NEEDS_REVIEW)、compiled_fingerprint、unsupported_reasons；历史危险/失效配置标记 NEEDS_REVIEW（只标记，不改 status、不重新解释范围） |
| 000131 | `api_runtime_events.final_decision JSONB`（可空，历史不回填） |
| 000132 | `security_events.final_decision JSONB`（可空，分区表级联，历史不回填） |

guard 直拦事件的 final_decision 落 `access_control_events.details`（既有 JSONB 列，迁移 000101 先例），不新增表。

## 2. final_decision JSON 契约（网关/server 共用，schema_version=1）

```json
{
  "schema_version": 1,
  "request_id": "网关生成，不信外部同名头",
  "application_id": "uuid 或空",
  "gateway_node": "节点 ID",
  "completion_status": "COMPLETED | ABORTED | ERROR | PENDING_CORRELATION | UNKNOWN",
  "security_action": "NONE | BLOCK | TEMP_BLOCK | RATE_LIMIT | MASK_RESPONSE",
  "executor_module": "PROTECTED_ADDRESS | MANUAL_BAN | IP_BLACKLIST | L7_ACL | AUTO_BAN | RISK_POLICY | LICENSE_QUOTA | CC | JWT | API | WAF | NONE | UNKNOWN",
  "response_source": "GATEWAY | ORIGIN | UNKNOWN",
  "http_status": 403,
  "response_committed": true,
  "reason_codes": ["固定词表，如 IP_IN_BLACKLIST"],
  "rule_refs": [{"module": "WAF|API|...", "rule_id": "942100", "version": "可空"}],
  "effective_config": {"config_fingerprint": "可空", "api_policy_version": "可空", "exception_versions": {"<uuid>": 2}},
  "findings": {"observed": 0, "enforced": 0, "excepted": 0, "skipped": 0},
  "steps": [{"module": "CC", "result": "EXECUTED | OBSERVED | EXCEPTED | SKIPPED", "detail": "可空"}],
  "matched_exceptions": [{"exception_id": "uuid", "version": 2, "target": "WAF|API", "rule_refs": ["942100"], "scope_summary": "脱敏摘要", "effective_from": "RFC3339 可空", "effective_until": "RFC3339 可空"}],
  "identity_verification": {"status": "VERIFIED 等", "verified_principal_id": "指纹"} ,
  "evidence_refs": ["关联事件/事务标识"],
  "finalized_at": "RFC3339"
}
```

纪律：
- steps ≤ 32、rule_refs ≤ 64；截断时 steps 追加 `{"module":"TRUNCATED","result":"SKIPPED","detail":"dropped=N"}`；最终动作与关键规则引用不可被截断丢弃。
- 只记录已执行事实；观察命中不进 security_action。上游断连/超时/流中断不硬映射 BLOCK。
- 终止分支之后的模块标 SKIPPED；白名单只记录实际绕过的步骤（SKIPPED + detail）。
- 写入口径：先到先得 + 终止动作优先——已确认 BLOCK 不被晚到观察覆盖；PENDING_CORRELATION 允许被真实证据幂等更新（去重键 request_id+application_id+gateway_node）。
- identity_verification 引用 P0-03 状态与指纹，历史可空；不落原始 Token/明文声明。

## 3. 例外动作矩阵（新启用门禁）

| target_engine | action | 新启用 | 编译/执行 |
|---|---|---|---|
| WAF | REMOVE_RULE | 允许（rule_ids 非空） | 无目标名 → `ctl:ruleRemoveById`；有目标名 → 每个 规则×目标 `ctl:ruleRemoveTargetById` |
| WAF | REMOVE_VAR_DETECTION | 允许（rule_ids 与目标名同时非空，缺一字段级错误） | 同上目标排除 |
| WAF | REMOVE_RULE_TAG | 允许（启用时经规则目录展开冻结进 resolved_rule_ids；解析不出 → 拒绝启用） | 冻结集逐 ID `ctl:ruleRemoveById`；范围链不变 |
| WAF | LOG_ONLY / ADJUST_SCORE | **拒绝**（400 UNSUPPORTED_ACTION，返回迁移预览说明） | 历史记录 NEEDS_REVIEW，发布侧不再下发 |
| API | OBSERVE_RULE（新增） | 允许（api_rule_refs 非空且 detector_id ∈ 受支持注册表） | 决策引擎 Finding 级豁免+重算 |
| API | 其他任意动作 | 拒绝 | — |

目标名映射：ParamNames→`ARGS:<名>`、CookieNames→`REQUEST_COOKIES:<名>`、HeaderNames→`REQUEST_HEADERS:<名>`（Header 名大小写不敏感，统一大写）。

受支持 API detector 注册表（首批，Finding.RuleID 稳定）：`api_schema`（schema 违例）、`api_parser`（参数/解析观测）。其余检测器一律拒绝为例外目标（EXC-11）。

## 4. 范围校验（保存校验 + 启用门禁双层）

- 保存（Create/Update）：字段格式校验（现状保留）+ 不支持字段组合给字段级错误，不静默舍弃。
- 启用（Enable，及 Create 直接 ENABLED）追加门禁：
  - ScopeType=APPLICATION 且 application_id 非空且应用存在（服务端查库）；GLOBAL 禁止新建/启用；
  - Methods 非空（标准化大写，∈GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS，≤10）；
  - URIExact XOR URIPrefix（URIRegex 仅历史/高级：需 risk_acknowledged + RE2 可编译 + 长度 ≤512，且记录 unsupported_reasons 提示）；prefix 必须以 `/` 开头，禁止裸 `/` 作为唯一范围（任务书 §5.2 默认值）；
  - 目标规则非空（WAF：rule_ids 或 resolved_rule_ids；API：api_rule_refs）；
  - 临时例外必须 effective_until；from<until（相等非法）；UTC 秒精度；
  - validation_status=NEEDS_REVIEW 的禁止启用，须先修改达标（Update 重算 validation_status）。
- 攻击类型 attack_types 仅作事件分类筛选，不参与运行时范围，也不得仅凭它授权启用。
- ActionTarget 禁止自由文本拼 SecLang：仅允许作为 REMOVE_VAR_DETECTION 的目标集合别名校验，否则拒绝。

## 5. WAF SecLang 编译模板（两规则标记法；Coraza 3.7.0 实测锁定）

**实测发现（gateway/corazasemantics/exception_seclang_test.go，仓库锁定 Coraza v3.7.0）**：Coraza 对「自身已匹配」的规则立即执行非中断动作（internal/corazawaf/rule.go 原文注释 "We run non-disruptive actions even if there is no chain match"；multiphaseEvaluation 编译期常量默认 false）。链首直挂 ctl 时，只要链首条件（如 Host）匹配，后续链环（路径/方法/IP/时间）失败**仍摘除规则且无审计记录**。因此禁止链首挂 ctl，采用两规则标记法：

```
# jiuzhang-exc-map: <effect_rule_id> <exception_uuid> <exception_version>
SecRule REQUEST_HEADERS:Host "@rx (?i)^<domain>(?::\d+)?$" "id:<marker_id>,phase:1,pass,nolog,chain"
    SecRule REQUEST_FILENAME "@streq <uri_exact>" "chain"
    SecRule REQUEST_FILENAME "@rx ^<uri_prefix_escaped>(?:/|$)" "chain"   （与上行互斥，按配置择一）
    SecRule REQUEST_METHOD "@pm <m1> <m2>" "chain"
    SecRule REMOTE_ADDR "@ipMatch <ip1>,<cidr2>" "chain"
    SecRule REQUEST_HEADERS:Content-Type "@rx ^<ct_main>(?:[;]|$)" "chain"
    SecRule TIME_EPOCH "@ge <from_epoch>" "chain"
    SecRule TIME_EPOCH "@lt <until_epoch>" "setvar:tx.jz_exc_<marker_id>=1"
SecRule TX:jz_exc_<marker_id> "@eq 1" "id:<effect_id>,phase:1,pass,log,tag:'jiuzhang-exception',tag:'exc:<uuid>',tag:'excv:<version>',<ctl 动作...>"
```

- 标记规则（marker）：仅条件链，nolog；`setvar` 必须且只能写在**末环**（末环仅在前序链环全部匹配后才求值——这是 Coraza 链语义中唯一安全的条件挂点）。无任何条件维度的例外拒绝编译（启用门禁已保证至少 应用+方法+路径 三维）。
- 效果规则（effect）：`TX:jz_exc_<marker_id> @eq 1` 单条件，携带全部 ctl 与 exc/excv 审计 tag；仅当标记被设置才触发，天然满足「条件全部成立才生效」。
- 每条例外占两个规则 ID：marker=8000001+2i、effect=8000002+2i（i 为按 exception_id 字典序排序后的序号）；映射注释写 effect 行；反查锚点为 effect 规则的 exc:/excv: tag。容量上限 2000 条例外（规则 ID 8000001-8004000 段）。
- `REQUEST_FILENAME` 不含 query（EXC-08）；Host 允许带端口、大小写不敏感；REMOTE_ADDR 为 guard 可信代理改写后的客户端 IP（经 XFF 伪造用例实测）。
- 时间链用 TIME_EPOCH（UTC 秒，半开区间 from≤now<until）；到期无需再发布。未来生效规则照常下发，由运行时时间链控制生效起点。
- 效果规则用 `log`、标记规则一律 `nolog`：例外命中在 Coraza 审计留下匹配记录，eventparser 经 `exc:` tag 反查 exception_id/version 写入 final_decision.matched_exceptions——例外命中可审计是契约要求，接受其审计量（范围越窄量越小）。
- 取时点：请求进入 Coraza 事务时一次取值（Coraza 内部变量求值），同一请求一致。
- 规则 ID 分配：发布侧对待下发例外按 exception_id 字典序排序，每条占 marker/effect 两个连续 ID（8000001+2i/8000002+2i）；映射注释+tag 双锚点；版本内稳定无碰撞；例外数超容量上限（2000）发布明确失败。
- 实测基线（锁版引擎内执行，非字符串比对）：条件逐维翻折、目标级/规则级排除边界、时间窗三态、段前缀边界、query 剔除、tag 可见性全部绿（gateway/corazasemantics/exception_seclang_test.go）。

## 6. API 例外下发契约（guard 配置 `api_exceptions` 段）

`gatewayconfig.GuardAPIException` / `GuardAPIRuleRef`（server/internal/gatewayconfig/guard.go，本提交冻结）；随 WDSP API 动态防护门控下发，key=应用编码，纳入 api_policy_version 版本戳；读取失败 fail-hard 中止发布。网关装配期严格解码，schema_version 不支持 → 拒绝加载（旧节点不忽略新强制语义）。

网关侧范围筛选（纯函数，guard 新增 `apiexceptions.go`）：输入请求事实（domain/路径/method/可信 IP/当前 UTC 秒）+ 该应用例外集 → 输出适用 `[]decision.ExceptionRef`。决策引擎只做 Finding↔rule_ref 匹配与重算，不感知 HTTP。

`decision.Input.Exceptions` 类型由 `[]string` 改为 `[]ExceptionRef{ExceptionID, Version, DetectorID, RuleID, ModelVersion}`（该字段此前预留未生效、无调用方传值，直接改型）。

决策重算：命中 Finding 保留于 Matches 并标记（ctx 侧记录 exception_id/version、OBSERVED），其 ScoreDelta 与执法类别从定案排除；按既有优先级对剩余 Finding 重算 FinalAction。PROTECT 下降级语义不变。

## 7. 处置上下文采集点（网关 jiuzhang_guard）

- ServeHTTP 入口创建 disposition（不依赖访问日志开关），defer finalize。
- 各终止分支写入 executor/action/status/reason：MANUAL_BAN(403)、IP_BLACKLIST(403)、L7_ACL(403)、AUTO_BAN(403)、RISK_POLICY(403/429)、LICENSE_QUOTA(429)、CC(429)、JWT(401/503)、API（决策结果）、WAF（经 apicoraza 中断归因，同步仅知 executor+status，规则明细由 eventparser 异步补）。
- 终止后模块标 SKIPPED；白名单/L7 allow 记录实际绕过步骤。
- 源站完成：response_source=ORIGIN、security_action=NONE（仅响应脱敏时 MASK_RESPONSE 且注明 ORIGIN 来源）、http_status 取实际写出码。
- ResponseWriter 包装沿用 captureResponseWriter/apiResponseCapture（已实现 Flusher/Hijacker/Unwrap），不新增缓存响应体的包装。
- 落库：guard 事件 → access_control_events.details.final_decision；API 事件 → api_runtime_events.final_decision（迁移 000131）；WAF 事件 → eventparser 构建 + normalize 落 security_events.final_decision（迁移 000132）。三侧经 request_id 关联；事件详情 API 合并展示时按「已确认拦截优先」去重。

## 8. 预览接口契约（新增 POST /api/v1/exceptions/{id}/preview）

权限 exceptions.manage；请求 `{expected_version}`；响应：

```json
{
  "validation_status": "VALID | NEEDS_REVIEW",
  "field_errors": [{"field": "methods", "message": "..."}],
  "normalized_scope": {"domain": "...", "uri_exact": "...", "methods": ["POST"], "source_ips": [...], "content_types": [...], "effective_from": "...", "effective_until": "..."},
  "resolved_rule_refs": [{"engine": "WAF", "rule_id": 942100} 或 {"engine": "API", "detector_id": "api_schema", "rule_id": "..."}],
  "effective_window": {"from": "...", "until": "...", "half_open": true},
  "unsupported": [{"field_or_action": "LOG_ONLY", "migration_preview": "改为 REMOVE_VAR_DETECTION ..."}],
  "protected_modules_unchanged": ["JWT", "ACCESS_CONTROL", "CC", "RATE_LIMIT_QUOTA", "MANUAL_BAN", "PROTOCOL_LIMITS", "RISK_POLICY"],
  "compiled_fingerprint": "sha256 hex",
  "required_publish_targets": ["应用编码..."],
  "historical_sample_coverage": null,
  "estimated_match_count": null
}
```

- expected_version 与当前版本不符 → 409；预览后草稿被改 → 指纹变化，发布前重验。
- 历史日志字段不足时估计值恒 null 并显示「无法估算」，不显示零影响（本阶段不做日志回放估算）。
- 预览不启用、不发布、不回放真实请求；操作写审计。

## 9. 事件→例外草稿修复

- CreateFromEventInput 增 ApplicationID/Method/Path（不含 query）/RuleIDs/SourceEventID；服务端从事件记录取 application_id 与 matches 的规则 ID（可信源，客户端入参不能覆盖）。
- 缺应用或规则证据 → validation_status=NEEDS_REVIEW 草稿，禁止启用，预览列出缺失项；补齐走服务端规则目录+有权限应用选择。
- 宽泛判定不再被单字段绕过：IsBroad 保持，但启用门禁独立于风险勾选（结构化范围校验为准）。

## 10. 跨实施者函数签名冻结（A=server 例外包 / B=网关决策+筛选 / C=处置上下文）

```go
// ---- B 交付：gateway/dynamic_security/decision ----
type ExceptionRef struct {
    ExceptionID  string `json:"exception_id"`
    Version      int    `json:"version"`
    DetectorID   string `json:"detector_id"`
    RuleID       string `json:"rule_id"`
    ModelVersion string `json:"model_version,omitempty"`
}
// Input.Exceptions 类型改为 []ExceptionRef（原 []string 预留字段无调用方传值）

// ---- B 交付：gateway/dynamic_security/context ----
// DetectorMatch 增列：
//   Excepted         bool   `json:"excepted,omitempty"`           // 被例外命中，取消本次执法贡献
//   ExceptionID      string `json:"exception_id,omitempty"`
//   ExceptionVersion int    `json:"exception_version,omitempty"`
// 豁免由 decision.Decide 在打标后经 SnapshotMatches 体现；apievents 输出自然携带。

// ---- B 交付：gateway/modules/jiuzhang_guard/apiexceptions.go（纯函数，不碰 module.go/apiprotect.go）----
type APIExceptionRuleRef = 与 gatewayconfig.GuardAPIRuleRef 同构的网关侧类型（含 json tag 一致）
type APIException struct { SchemaVersion int; ExceptionID string; Version int;
    Domain, URIExact, URIPrefix string; Methods, SourceIPs []string;
    EffectiveFrom, EffectiveUntil *int64; RuleRefs []APIExceptionRuleRef }
func ParseAPIExceptionsSection(raw json.RawMessage) (map[string][]APIException, error) // 严格解码+校验，schema_version!=1 拒绝
func FilterAPIExceptions(list []APIException, domain, path, method, clientIP string, nowUnix int64) []decision.ExceptionRef
// 范围 AND：domain 大小写不敏感/可带端口；path 精确或按段前缀；method 大写集合；
// clientIP 为可信 IP（netip 解析，CIDR 支持）；时间半开 [from,until)。任一维度不满足即不适用。

// ---- C 交付：处置上下文 ----
// gateway/modules/jiuzhang_guard/disposition.go：
type Disposition struct { /* 与 final_decision JSON 同构（设计文档 §2） */ }
func WithDisposition(ctx context.Context, node string) (context.Context, *Disposition)
func DispositionFrom(ctx context.Context) *Disposition
func (d *Disposition) RecordTerminal(module, action string, status int, committed bool, reasons, ruleRefs []string)
func (d *Disposition) RecordStep(module, result, detail string) // result ∈ EXECUTED/OBSERVED/EXCEPTED/SKIPPED
func (d *Disposition) RecordMatchedException(id string, version int, target string, ruleRefs []string, scopeSummary string, from, until *time.Time)
func (d *Disposition) RecordOrigin(status int, committed bool)  // response_source=ORIGIN
func (d *Disposition) Finalize() // 补 completion_status/SKIPPED/findings 计数/finalized_at，幂等
```

接线分工：B 不动 module.go/apiprotect.go/apicoraza.go；C 负责 Provision 装配调用 `ParseAPIExceptionsSection`（仿 assembleJWTTrust fail-closed）、serveNext 内调用 `FilterAPIExceptions` 并把结果传入决策、将 Excepted Finding 写入 disposition.matched_exceptions。A 负责 server 侧 `loadAPIExceptions`（guardconfig/provider.go + apiruntime.go 段组装，仿 loadJWTTrust fail-hard）。

## 11. 偏差记录

- 2026-09-07：§5 模板由「链首挂 ctl」改为「两规则标记法」。原因：Coraza v3.7.0（仓库锁定版）实测——链首条件一旦匹配，非中断动作（ctl/setvar）立即执行，不等待后续链环（internal/corazawaf/rule.go 注释 "We run non-disruptive actions even if there is no chain match"，multiphaseEvaluation 编译期常量默认 false）。链首挂 ctl 会在路径/方法/IP/时间任一不满足时仍摘除规则且无审计。实测证据：gateway/corazasemantics/exception_seclang_test.go（先以链首方案红测复现，改两规则后全绿）。
- 2026-09-07：每条例外占用 marker/effect 两个连续规则 ID（8000001+2i/8000002+2i），映射注释锚定 effect 行；容量 2000 条例外。
- 2026-09-07（工作流 A，P0-04 server 侧）：Create/Update 默认落 DRAFT（保存不再直接 ENABLED），启用走单独 Enable 门禁；宽泛例外风险确认保留在保存层（update 的 ack 分支），Enable 不重复确认。
- 2026-09-07（A）：app.go 接线限任务书两处（eventExceptionCreator 经 events.GetByID 取 matches；preview 路由注册），`guardProvider.SetAPIExceptionsLister(exceptionStore)` 一行装配未接，遗留主代理/装配方补齐。
- 2026-09-07（A）：required_publish_targets 不存快照，发布时经 applications 表按 application_id 反查 code；rule_tags 走 waf_rules 目录展开冻结分支（冻结规则 ID 集于创建时）。
- 2026-09-07（A）：ReviewException 返回 (status, reasons, error) 三值——启用门禁的 hook 查库失败经 FieldError.infra 上抛为 error（500），不伪装成校验失败。
- 2026-09-07（A）：URIRegex 的审查提示只追加 reason，不翻转 VALID→NEEDS_REVIEW（否则启用门禁中「NEEDS_REVIEW 须 ack」分支永远不可达）。
- 2026-09-07（A）：@pm 目标方法列表排序后参与编译与指纹，保证同输入指纹稳定；新增 escapeRegexArg 专供 @rx 语境（不双写反斜杠），因 Coraza 3.7.0 utils.UnescapeQuotedString 只还原 `\"` 不折叠 `\\`；@streq 语境保留旧 escapeArg。
- 2026-09-07（A）：Enable 指纹在版本推进后由 storeFingerprint 重算回写（修复启用后指纹仍等于创建指纹的缺陷）；upsert 接受 policy_id（修复 PUT 整列更新丢字段缺陷）；buildException 补 effective_from/until 解析（修复旧代码静默丢弃时间窗缺陷）。
- 2026-09-07（A，清单外）：openapi/merge.py 增补 `'bot-policy': 'Bot 挑战策略（WDSP P1-02）'` 一行——P1-02 作者引入 fragment 后未登记，导致 make openapi-reconcile 预存阻塞，不修则无法重生成。
- 2026-09-07（A，既有缺口）：make openapi-reconcile 仍有 36 条代码已注册但文档缺失路由，全部属 wdsp-agent/traffic/APM 轨道，无一条与 exceptions 相关，属其他工作流既有缺口。
