# AUTHZ-01：对象授权关系确认与 BOLA/BFLA 网关 OBSERVE 决策开发任务书

日期：2026-09-08。状态：本地实现与可复现验收完成；正式环境验收后置。优先级：产品 P1（独立任务线，不属于 wdsp-p0/p1 竞品任务包）。

前置：设计基线 [../API_BOLA_BFLA_MULTI_TENANT_AUTHORIZATION_DESIGN.md](../API_BOLA_BFLA_MULTI_TENANT_AUTHORIZATION_DESIGN.md)（下称"设计文档"，章节引用如"设计 §15"）；[P0-03 JWT 信任链](wdsp-p0/P0-03_JWT_TRUST_CHAIN.md)已落地，提供 `verified_principal_id` / `verified_tenant_id`；P0-15/16/17 的 `server/internal/apiauthz` 角色基线、对象权属、字段权限已存在。

编写标记沿用 wdsp-p1 总纲：**现有** / **新增约定** / **建议默认值** / **待复现**。

## 实施进展（2026-09-10）

已完成的核心接线：

- 迁移 `000136` 新增对象关系、关系候选、迁移回执、对象引用专用密钥与授权决策存储；历史 ownership 以 legacy 候选迁移，保留独立旧指纹且不可直接确认。
- 新候选采集仅接受 `VERIFIED` 且主体非空的 HUMAN 身份；单一来源不抬高 `source_count`，同一对象 10 分钟内超过 8 个不同主体时冻结自动浮现。管理接口已覆盖候选确认/拒绝、手工关系、决策与覆盖率查询，并接入权限和操作审计。
- 可发布对象模型、CONFIRMED OWNER 关系和 VERIFIED 角色基线已进入现有配置发布链；授权快照使用独立 HMAC 密钥签名，带策略版本和有效期，配置回读时密钥保持脱敏。
- 发布链补充了仅 BFLA 角色基线场景：即使当前没有可发布的 BOLA 对象模型，也会下发 VERIFIED 角色基线，不生成空对象模型或空 HMAC 密钥要求。
- 网关已接入可信身份、可信角色和对象关系的 BOLA/BFLA OBSERVE 决策，覆盖应用隔离、单层租户、关系生效时间、请求级 `decision_id`、聚合原因码与脱敏事件；所有结果均放行。
- 管理端“对象授权”面板已提供覆盖率、候选、关系和决策视图；OpenAPI 片段与生成文件 `server/openapi/wdsp-api.yaml` 已同步。

已完成的验证：

- server：`go test ./internal/apiauthz ./internal/guardconfig ./internal/apiruntime ./internal/app ./cmd/api`。
- server 授权快照契约：`server/internal/guardconfig/authz_decision_test.go` 已覆盖对象模型存在时关系/角色/HMAC 输入不完整即拒绝发布、策略版本生成、快照过期时间传递和对象段编译。
- gateway：授权决策器、事件、管线及 JWT 信任链相关 Go 测试通过。
- 网关关系索引微基准：`BenchmarkEvaluateAuthorizationWithRelationIndex` 使用 200,000 条关系；本机 darwin/amd64 以 `-benchtime=100x` 运行约 `6.2 µs/op`、`2,010 B/op`、`26 allocs/op`。该结果仅证明索引路径的局部开销，不代表 P0-02 的开关配对 P95、端到端吞吐或内存上限验收。
- 网关授权索引/线性扫描配对微基准：`BenchmarkEvaluateAuthorizationPaired` 在相同 200,000 条关系、相同请求和决策输入下，以 `-benchtime=30x` 测得索引路径约 `7.6 µs/op`、`2,008 B/op`、`26 allocs/op`，线性扫描约 `2.25 ms/op`、`1,912 B/op`、`25 allocs/op`。该结果用于证明大关系集下索引路径的局部收益，仍不替代 P0-02 的多轮 P95、端到端吞吐和内存上限验收。
- gateway 组合验收：`gateway/modules/jiuzhang_guard/apiprotect_test.go` 的 `TestServeNext_AuthzBOLAObserveRecordsHMACAndPassthrough` 已验证 Guard → API 动态防护管线 → API 事件出口；BOLA 命中保持 OBSERVE 放行，事件含 `AUTHZ-BOLA-001`、策略/模型版本和 HMAC 对象引用，原始对象 ID 不落决策。
- web：`npm run test -- --run src/pages/api-authz/__tests__/ApiAuthzPage.test.tsx`（8/8）与 `npm run typecheck` 通过。
- OpenAPI：`make openapi-reconcile` 通过，生成契约与片段一致。
- P0-02 工具层：`python3 -m pytest -q test/performance/p0/tests` 在具备 loopback 监听权限的环境中 147 项通过，覆盖计划校验、隔离、语料、指标、报告与 JWT 工具；该结果只证明基准运行器工具层可用，尚未替代真实基准环境中的七模式配对 P95、吞吐、内存、`-race`、长稳和故障恢复验收。
- PostgreSQL：使用仓库锁定的 `postgres:16.4-alpine@sha256:5660c2cbfea50c7a9127d17dc4e48543eedd3d7a41a595a2dfa572471e37e64c` 一次性实例运行 `AUTHZ_TEST_PG_DSN=... go test -mod=readonly ./internal/apiauthz -run 'TestAuthz(MigrationPostgres(LegacyOwnershipContract|Contract|ConcurrentContract)|CandidateSweepPostgresConcurrentContract)$' -count=1`；全量迁移、000136 幂等重放、AZ-01 legacy 业务迁移、迁移级并发锁和候选 sweep 业务级并发均通过。
- Luna 复核 AZ-15/AZ-16/AZ-18：`server/internal/apiauthz` 定向测试通过；权限分离、详情证据脱敏、跨应用隔离及候选→确认→关系→网关 OBSERVE 链路均有本地证据，未新增未冻结的主体或对象引用格式约束。
- AUTHZ 迁移契约测试：新增可选真实 PostgreSQL 测试 `server/internal/apiauthz/migration_integration_test.go`；使用仓库已锁定的 PostgreSQL 16.4 镜像设置 `AUTHZ_TEST_PG_DSN` 运行 `TestAuthzMigrationPostgresContract`，全量 `000001→000136` 迁移、重复迁移，以及 000136 的表、字段、约束和权限断言均通过。
- AZ-01 遗留 ownership 迁移契约测试：同一测试文件新增 `TestAuthzMigrationPostgresLegacyOwnershipContract`，覆盖 `principal_id=NULL`、独立 legacy 指纹、`FROZEN`/`LEGACY_UNVERIFIED`/不可确认标记、专用 HMAC `object_ref`、不生成可信关系和幂等重跑；已在仓库锁定的 `postgres:16.4-alpine@sha256:5660c2cbfea50c7a9127d17dc4e48543eedd3d7a41a595a2dfa572471e37e64c` 一次性实例中通过真实业务数据断言。
- 迁移执行器已补充按版本隔离的 PostgreSQL 事务级 advisory lock，并在加锁后重新检查 `schema_migrations`；`TestAuthzMigrationPostgresConcurrentContract` 已在同一真实 PostgreSQL 实例上由两个独立 runner 并发执行，迁移记录恰好一次且探针表存在，验证通过。
- 候选 sweep 真实并发契约已通过：`TestAuthzCandidateSweepPostgresConcurrentContract` 使用两个独立 worker 同时领取同一 runtime event，最终断言事件只扫描 1 次、候选只 upsert 1 行、receipt 只写 1 行且 `observation_count=1`；验证了 `FOR UPDATE OF e SKIP LOCKED` 与 receipt 去重在真实 PostgreSQL 中的恰好一次消费语义。
- 迁移事务失败恢复契约已通过：`TestAuthzMigrationPostgresFailureRetryContract` 在真实 PostgreSQL 中先执行必然失败的迁移，断言 DDL 与 `schema_migrations` 完整回滚；随后替换为修复迁移成功执行，并再次重放确认幂等。该测试覆盖数据库事务失败后的重试，不等同于进程被杀、机器故障或网络断连恢复。
- 候选确认发布接线已通过：`ConfirmRelationCandidate` 在关系事务提交并写入审计后调用注入的既有 `publisher.Publish` 回调；`TestTrustedRelationConfirmationTriggersConfiguredPublish` 验证 VERIFIED 候选确认恰好触发一次，legacy/不可确认候选不触发。发布任务创建失败时保留已确认关系，后续整站发布可重试带上最新授权快照。
- 手工关系发布接线已通过：`CreateObjectRelation` 对成功创建的 CONFIRMED 关系复用同一发布回调；`TestManualRelationCreationTriggersConfiguredPublish` 验证成功请求恰好触发一次，原始对象引用校验失败不触发。候选拒绝不改变 confirmed 快照。
- 节点发布故障注入已通过：`TestFanoutTransientFailureCanRetryExactAuthzSnapshot` 通过真实 HTTP `/load` 链路注入第一次 500，发布器自动等待后以同一版本重试成功；两次请求中的 `api_authz_models` 与 `api_authz_previous_valid` 逐字一致，节点水位由 `FAILED` 转为 `SUCCESS`，恢复成功不重复告警。自动重试仅执行一次且可被上下文取消，仍不代表跨主机网络、机器故障或完整发布编排验收。
- 多节点发布故障注入已通过：`TestFanoutMultiNodeRetryKeepsAuthzRollbackSnapshot` 使用两个真实 HTTP 节点，验证节点 A 的瞬时失败会在单次自动重试后保留失败事实，节点 B 同批成功；随后显式恢复只重试 A，仍逐字发送同一授权回滚快照并记录 A 的 `SUCCESS` 水位。该测试覆盖部分节点失败/恢复契约，不代表跨主机网络、进程重启后的状态持久化或完整多节点编排。
- Guard PreviousValid 运行时 E2E 已通过：`TestProvisionedGuard_AuthzPreviousValidFallbackE2E` 模拟 Provider JSON 序列化/反序列化、Guard `Provision` 和真实 API 管线，验证当前快照过期时产生 `AUTHZ-POLICY-002`，仍以历史模型/关系完成 BOLA `ALLOW`，请求到达源站且事件可见。
- 跨 module 故障恢复契约已补充：`gateway/modules/jiuzhang_guard/authz_cross_module_contract_test.go` 的 `TestTransientPublishRetryLoadsSameSnapshotIntoGuardAndDecides` 通过 live HTTP `/load` 注入第一次 500，第二次以逐字节相同 JSON 重试成功，再由 Guard 恢复 `PreviousValid`、HMAC 和关系，接收真实 API 请求并产出 `AUTHZ-BOLA-001` OBSERVE 事件且放行到源站；`go test . -run 'TestTransientPublishRetryLoadsSameSnapshotIntoGuardAndDecides|TestConsumeAuthzCrossModuleContract' -count=1` 与 Guard 模块全量 `go test . -count=1` 均通过。该测试锁定 server/gateway 的 JSON 交接边界，Provider 真实进程、数据库事务和多节点编排仍需集成环境验收。
- 跨 module 契约脚本 `bash test/waf/scripts/authz-cross-module-contract.sh` 已通过：脚本先运行 `apiauthz` 管理层候选确认、发布回调和 owner/other 主体决策回归，再由 `guardconfig` Provider 测试生成临时 JSON，最后由 gateway Guard 消费同一 JSON，覆盖对象模型唯一模板、PreviousValid/HMAC、BOLA OBSERVE 脱敏、BFLA VERIFIED 角色放行和事件落盘。该脚本是两个 module 测试的可复现串联，仍不等同于 Provider 真实进程、数据库事务或多节点编排验收。
- AUTHZ 开关配对基准已补充：`BenchmarkEvaluateAuthorizationAuthzPair` 在相同 parsed request 与 VERIFIED JWT 下分别运行 `authz_disabled` 和同时启用 BFLA+BOLA 的 `authz_enabled`，循环内校验禁用路径无授权组、启用路径仍为 ALLOW 且包含两类检查；短测使用 `-benchmem -benchtime=100ms -count=3` 已通过。该基准只提供 Go 请求本地原始耗时/分配对照，不能替代 P0-02 要求的 P95/P99、端到端吞吐、RSS、`-race`、长稳和故障恢复数据。
- 覆盖率存储语义已对齐：`MemStore.GetAuthorizationCoverage` 统计当前时间窗内的 `CONFIRMED` 关系及 `ConfirmedRelationRate`，并按 `application_id` 统计 `Decisions`、`UNKNOWN`、`OBSERVE_VIOLATION` 与 `UnknownRate`，与 PostgreSQL 实现保持一致；`TestMemStoreCoverageExcludesInactiveRelations` 覆盖有效、过期、未来生效和 revoked 关系，`TestMemStoreCoverageIncludesDecisionMetricsAndApplicationIsolation` 覆盖决策指标与应用隔离。
- 关系生命周期已接线：`POST /api/v1/api-security/authz/relations/{id}/revoke` 仅允许撤销 `CONFIRMED` 关系，强制记录原因和操作审计；服务启动时及每 5 分钟自动将到期关系标记为 `EXPIRED`，状态发生变化时复用既有发布回调。重复撤销/过期保持幂等，发布任务创建失败不回滚已提交的关系状态；`handler_test.go` 已覆盖权限、状态、审计、发布和重复执行路径。

2026-09-10 继续收口：

- 发布编译器现在会按 `application_id + endpoint_key + method + role + action` 检测 VERIFIED BFLA 基线的相互冲突行；同一键同时出现允许与拒绝时直接拒绝生成快照，避免依赖数据库返回顺序产生不确定决策。相同语义的重复允许或拒绝行仍可幂等下发。
- 新增 `TestLoadAPIAuthzSnapshotRejectsConflictingVerifiedRoleBaselines`，覆盖仅有 BFLA 基线、没有 BOLA 对象模型时的冲突拒绝路径；`go test ./internal/guardconfig ./internal/apiauthz ./internal/apiruntime ./internal/app ./cmd/api -count=1` 通过。
- 网关决策器增加运行时兜底：旧节点或手工构造的快照若仍含同一角色基线键的相反允许值，直接输出 `UNKNOWN/AUTHZ-POLICY-001`，不按数组顺序首条生效；由于网关无法观测业务 action，跨 action 的相反决策也按同一角色冲突处理。`TestEvaluateAuthorizationRejectsConflictingBFLABaselines`、`TestEvaluateAuthorizationRejectsUnobservableActionConflict` 与完整 detectors、`jiuzhang_guard` 测试通过。
- 网关对象模型匹配补充严格应用隔离与 HTTP method 约束：无应用上下文的请求不消费应用级快照，显式 method 不再被其他 method 的同路径模型误匹配；新增跨应用、跨 method 用例并通过 detectors 全量测试。
- 配置渲染修复仅含 BFLA 角色基线的快照被静默丢弃问题：此类快照会下发角色基线，但不会伪造空 BOLA 模型或对象 HMAC key；`TestBuildGuardHandlerAuthzBFLAOnly` 与相关 `gatewayconfig` 定向测试通过。
- 发布器新增统一的失败码归一化：验证失败或当前版本切换失败在回滚成功时分别保留原失败原因并追加 `_ROLLED_BACK`，回滚本身失败统一输出 `ROLLBACK_FAILED`；表驱动测试 `TestPublishRollbackFailureCode` 已覆盖两类可回滚失败和回滚失败路径，定向 `gatewayconfig` 测试通过。该证据仅覆盖失败码映射，部分节点发布、完整状态机和 AZ-13 集成验收仍待补齐。
- 决策器支持调用方显式提供 `PreviousValid` 快照：当前快照过期时先记录 `AUTHZ-POLICY-002`，再使用仍有效的上一快照执行 BOLA/BFLA；关系仍按自身 `valid_from` / `valid_until` 过滤。`TestEvaluateAuthorizationFallsBackToPreviousValidSnapshot`、无回退时 UNKNOWN、以及回退后过期关系过滤用例已通过 detectors 全量测试。Guard 与 Provider 现已具备上一快照契约和最近一次 `SUCCESS` 快照选择；配置注入边界已覆盖当前进程的回放与脱敏，真实 Provider→Guard→网关跨进程链路仍需 AZ-14 集成验收。
- Guard 配置契约已补齐 `api_authz_previous_valid`：Provision 会校验上一快照的模型、关系、角色基线和对象引用 HMAC，并传递快照有效期后显式注入决策器；配置渲染及版本回读会对嵌套 HMAC 脱敏，并按当前运行时密钥重注入。`TestBuildGuardHandlerAuthzPreviousValidSnapshot`、`TestReinjectConfigSecretsRedactedSnapshot` 及对应 `gatewayconfig` 普通/`-race` 定向测试通过。
- Provider 生命周期已接入授权快照：`BuildGuardConfig` 与 `SaveVersionSnapshot` 仅从版本表选择最近一次 `SUCCESS`，`PENDING/FAILED` 不得成为 `PreviousValid` 或 `PreviousVersionID`；历史快照深拷贝授权事实、保留原有效期且不携带 HMAC，回放时使用当前运行时密钥。发布结果状态机限制为 `PENDING → SUCCESS/FAILED`，终态回调仅允许幂等重试；`accesscontrolversions`、`guardconfig` 普通/`-race` 测试覆盖成功、失败、错误和脱敏路径。跨进程配置注入边界已有回放契约测试，旧版本节点组合与真实 Provider→Guard→网关链路仍待 AZ-13/AZ-14 集成验收。
- AZ-13/AZ-14 的持久化恢复边界已增加 PostgreSQL 集成测试 `TestPersistedSnapshotSelectionAfterProcessRestart`：写入 `SUCCESS`、`FAILED`、`PENDING` 三类版本后以新的 `Store` 实例模拟进程重启，只恢复最近持久化的 `SUCCESS` 快照；将原 `PENDING` 推进为 `SUCCESS` 后，新实例可读取该快照且配置/UUID 保持不变。测试通过 `AUTHZ_TEST_PG_DSN` 显式启用，未配置 DSN 时按设计跳过；该证据不覆盖真实进程强杀、机器/网络故障、Provider 常驻服务或多节点编排。
- 事件存储中断路径已收口：API 事件日志保持 4096 条有界队列，后台写失败和队列丢弃均进入限量账本；`Close` 会聚合文件关闭、后台写入和丢弃错误，并保证并发/重复关闭复用同一结果，不静默吞错。新增后台写失败、队列满、关闭汇总和重复 `Close` 用例；`apievents` 普通测试与 `-race` 均通过。
- 候选 sweep 的事件领取已收口：未处理 runtime event 查询、候选 upsert 与 receipt 写入统一在同一事务中，使用 `FOR UPDATE OF e SKIP LOCKED` 让并发 worker 跳过已领取事件；SQL 契约测试和真实 PostgreSQL 两 worker 业务契约均覆盖行锁、跳过锁、receipt 去重及恰好一次消费。跨进程连续事件流仍待 AZ-01/AZ-02 集成验收。
- 权限矩阵测试已补齐：`relation_manage` 不得被 `api_authorization.read/manage` 替代，`evidence_read` 不能绕过决策详情的通用读取权限；决策详情继续执行应用隔离和证据脱敏。`TestAuthorizationPermissionMatrix`、`TestAuthorizationDecisionDetailPermissionAndApplicationIsolation` 与无权限全路由测试通过。
- 管理接口真实 HTTP 边界验收已补充：`TestAuthorizationHTTPPermissionAndApplicationIsolation` 通过 `httptest.NewServer` 与 HTTP 客户端串联候选列表、候选确认、关系列表、决策详情和证据脱敏，验证跨应用决策详情按 404 隔离，并在真实请求边界复核 `relation_manage` 与 `api_authorization.read/manage` 的权限分离。该测试补齐的是接口层边界证据，尚不等同于完整的 Provider→发布器→真实网关流量 E2E。
- 应用隔离测试已覆盖 candidates、relations、coverage 三类查询：不同 `application_id` 只能读取各自范围，覆盖率统计不会串应用。`TestAuthorizationApplicationFiltersCoverRelationsCandidatesAndCoverage` 与授权接口定向测试通过。
- AZ-08 租户完整性矩阵已补齐：双方租户均为空时不启用租户维度，任一侧为空输出 `UNKNOWN/AUTHZ-TENANT-002`，双方非空不一致输出 `OBSERVE/AUTHZ-TENANT-001`，一致时允许；请求参数不参与身份租户判定。`TestEvaluateAuthorizationTenantCompletenessMatrix` 与 detectors 测试通过。
- AZ-14 PreviousValid 配置下发验收已补强：Guard 渲染保留历史快照的模型、标识符、关系、角色基线、策略版本、过期时间和 stale 标记；历史 HMAC 不透传，统一替换为当前运行时密钥，配置脱敏同时覆盖当前与历史密钥。`TestBuildGuardHandlerAuthzPreviousValidSnapshot`、`TestReinjectConfigSecretsRedactedSnapshot` 及对应 `-race` 定向测试通过；事件存储中断与真实跨进程流仍待集成补齐。
- PreviousValid 的 HMAC 边界已补齐：Guard `Provision` 对历史快照在配置了对象模型但缺少 HMAC、或 HMAC 不是 32 字节十六进制时 fail-closed；Provider 在当前仅 BFLA 或回放上一快照场景下会补注入当前运行时密钥，避免错误配置进入回退链路。`TestProvisionAuthzPreviousValidRejectsMissingOrInvalidHMAC`、`TestReinjectConfigSecretsRedactedSnapshot` 与回放契约测试通过；真实跨进程发布注入仍需集成环境验收。
- 关系创建的默认 `valid_from` 已在 PostgreSQL Store 与 MemStore 统一为“先补齐、后校验”，避免带 `valid_until` 的关系在不同存储实现下出现不一致；新增 `TestMemStoreRelationDefaultsValidFromBeforeValidityCheck` 回归测试。
- 发布器加载候选配置失败时保留网关当前完整配置作为回退值，包含 AUTHZ 当前模型、当前对象 HMAC 和 `api_authz_previous_valid` 历史快照；`TestLoadGatewayConfigReturnsPreviousConfigWhenLoadFails` 已覆盖该配置保真边界。该测试证明的是进程内回退契约，部分节点失败与真实跨进程发布仍待集成验收。
- 显式回滚在主节点恢复旧版本后会继续以恢复后的完整 JSON 扇出到次节点，并使用独立后台上下文完成节点水位记录；`TestRollbackFanoutPreservesRestoredConfig` 验证包含授权模型与 `api_authz_previous_valid` 的配置逐字下发且记录 `SUCCESS`。该证据仍属于进程内节点同步测试，真实多节点网络故障注入仍待集成环境验收。
- 旧版本节点组合兼容边界已补充：`TestFanoutLegacyNodeRejectsUnknownAuthzShardsKeepsExactSnapshot` 用真实 HTTP Admin `/load` 返回 400 模拟旧节点拒绝未知 `api_authz_models`/`api_authz_previous_valid` 分片，验证失败水位与告警包含节点、版本和拒绝原因，当前节点继续接收完整 JSON，兼容后仅重试失败节点且授权快照逐字一致。该测试只锁定发布器 HTTP 错误与快照保真契约，不伪造或宣称覆盖真实旧二进制解析行为。
- 版本级节点恢复已支持失败目标定向查询：`apinodes.Store.ListFailedSyncTargets` 仅返回指定版本最近一次 `FAILED` 或 `HASH_MISMATCH` 且仍启用的节点，`Publisher.RetryNodeSyncForVersion` 对实现该扩展的仓储只重试这些节点；旧版 `NodeSyncStore` 仍回退到全量目标以保持兼容。`TestRetryNodeSyncVersionUsesFailedTargetQuery` 与 `TestRetryNodeSyncVersionPropagatesFailedTargetQueryError` 已覆盖定向筛选和查询失败透传。该机制是显式恢复入口，叠加发布器单次瞬时错误自动重试，仍不覆盖未持久化版本水位、Provider 常驻进程或机器/网络故障。
- AZ-11 防投毒回归已补齐：`TestFrozenFanoutCandidatesCannotPolluteConfirmedRelations` 模拟同一对象在短窗口内出现 `candidateFreezeLimit+1` 个不同主体，验证候选进入 `FROZEN` 后确认统一返回 `ErrCandidateNotConfirmable`，冻结候选保持不变且 confirmed 关系数量为零；真实 PostgreSQL 并发锁时序、跨进程连续事件流仍待集成验收。
- AZ-18 本地证据链已补齐：`TestRelationCandidateConfirmationGatewayAuthorization` 覆盖观察候选创建、管理确认生成 `CONFIRMED/OWNER` 关系、HMAC 对象引用进入网关授权评估，以及 owner `ALLOW/EFFECTIVE_OWNER`、其他主体 `OBSERVE_VIOLATION/AUTHZ-BOLA-001` 和请求上下文记录。该测试不依赖 PostgreSQL 或运行中的网关；真实 Guard HTTP 流量、跨进程快照发布和事件落库仍待集成验收。
- AZ-18 管理接口接线已补强：同一测试通过现有管理 mux 的 `POST /api/v1/api-security/authz/relations/candidates/{id}/confirm` 路由完成候选确认，断言 `CONFIRMED/OWNER`、发布回调恰好一次，并将确认关系送入 owner/other 主体的网关评估；这仍是可运行的管理层链路，不等同于独立管理服务进程。
- 跨 module 契约脚本 `bash test/waf/scripts/authz-cross-module-contract.sh` 已复跑通过：Provider 测试生成的单份 JSON 经反序列化校验当前模型、对象引用 HMAC 与 `PreviousValid`，再由 gateway Guard 消费并验证 BOLA/BFLA 决策、事件脱敏和源站放行；Provider 写入、Guard 消费以及第二个 Gateway `PreviousValid` 恢复校验分别运行在独立 `go test` 子进程，中间只通过临时 JSON 文件交接。`AUTHZ_PROVIDER_CONTROL_TEST=1 bash test/waf/scripts/authz-cross-module-contract.sh` 另有控制协议兼容回归；两者仍不覆盖正式 Provider 常驻服务、多节点编排、机器故障或跨主机网络中断。
- 候选→确认→发布→真实 Guard/API 流量的本地连续契约已补齐：`authz_cross_module_contract_test.go` 将 `apiauthz` 确认后的候选发布摘要随 Provider JSON 经 gatewayconfig `CaddyClient` HTTP 边界原样转交，Guard 消费端校验 `CONFIRMED/OWNER`、发布回调元数据、运行时 HMAC 与已加载关系一致，再通过真实 `net/http` 客户端请求 owner/BOLA/BFLA 并核对放行和事件；默认使用 `net.Pipe` 隔离边界，设置 `AUTHZ_GATEWAY_REAL_HTTP=1` 时切换到 OS TCP HTTP listener。`bash test/waf/scripts/authz-cross-module-contract.sh` 已通过，真实 Provider 模式会同时启用该 OS TCP 分支；上述证据仍使用测试 Provider/独立测试进程，不替代正式 Provider、多节点或跨主机连续流量验收。
- 版本级节点恢复入口已补充：`Publisher.RetryNodeSyncForVersion` 仅读取持久化 `SUCCESS` 版本，先用当前运行时密钥重注入脱敏快照；持久化仓储支持失败目标查询时只重试该版本最近一次 `FAILED`/`HASH_MISMATCH` 节点，否则兼容回退到全部启用节点，再复用既有逐节点同步、水位记录和告警路径。`TestRetryNodeSyncVersionRehydratesPersistedSnapshot`、`TestRetryNodeSyncVersionUsesFailedTargetQuery` 与 `TestRetryNodeSyncVersionRejectsUnpublishedVersion` 已通过。该入口是可调用的恢复契约，与发布器单次瞬时错误自动重试互补，仍不覆盖真实 Provider 常驻进程、机器/网络故障或多节点编排。
- P0-02 最小验收 runner `test/performance/p0/run-authz-01.sh` 已接线并以 `AUTHZ_BENCHTIME=100ms AUTHZ_BENCHCOUNT=3 AUTHZ_RACE=1` 运行通过；`test/performance/p0/p0bench/go_bench.py` 会保留 Go `-benchmem -count` 原始样本并计算 P50/P95/P99、吞吐、B/op、allocs/op，正式环境标识或计划缺失时输出明确 `BLOCKED` 报告。本机配对样本约为 disabled `1.409–1.417 µs/op, 192 B/op, 4 allocs/op`，enabled `5.115–5.279 µs/op, 2,392 B/op, 27 allocs/op`，并通过授权矩阵与 `-race`；该结果仍是本机 Go 微基准，不能替代正式网关容量、RSS、长稳或故障恢复验收。
- 发布回滚状态机与节点水位已补强：显式回滚只有在恢复配置完整扇出到所有目标节点后才记为成功；部分节点失败持久化为 `ROLLBACK_NODE_SYNC_FAILED`，回滚结果记录失败时为 `ROLLBACK_NODE_SYNC_STATE_PERSIST_FAILED`，并可通过 `RetryNodeSyncForVersion` 只重试该版本最近失败的节点。`TestRollbackFanoutPartialFailureIsPersistedAsIncomplete`、`TestRollbackFanoutRecordFailureIsPersistedAsIncomplete`、`TestRetryNodeSyncVersionRehydratesPersistedSnapshot` 已通过；发布器对可识别的瞬时节点错误另有一次自动重试，但该证据仍不覆盖跨主机故障或真实多节点编排。
- Provider→gatewayconfig→Guard 的 HTTP 边界已增加独立进程契约：`server/internal/gatewayconfig/authz_http_boundary_test.go` 启动真实 `net/http` 服务，经生产 `CaddyClient` 完成 `/config/` 与 `/load` 交接，校验 JSON、哈希和 Content-Type，并由 `test/waf/scripts/authz-cross-module-contract.sh` 串联 Provider 生成、Guard 消费及上一有效快照恢复；脚本输出 `AUTHZ-01 cross-module contract: PASS` 与 `AUTHZ-01 process recovery contract: PASS`。这仍是测试进程边界，不等同 Provider 常驻服务、机器/网络故障或跨主机流量验收。
- 节点进程重启恢复契约已补充：`TestRetryNodeSyncVersionRecoversAfterNodeProcessRestart` 使用同一 loopback Admin 地址模拟节点停止、连接拒绝、重新绑定和新 Publisher 进程恢复，验证失败水位持久化、同版本完整授权快照重放及 `SUCCESS` 更新；该证据仍不等同真实多主机网络故障，自动重试也只覆盖单次瞬时错误。
- P0-02 正式环境门禁已落地：`test/performance/p0/p0bench/formal_gate.py` 要求 `P0B_FORMAL_ENVIRONMENT_READY=1` 且环境标识与计划一致；缺失时 `matrix`/`soak`/`recovery` 在启动 Docker 前写出 `BLOCKED`、原因 `ENVIRONMENT_UNAVAILABLE` 并返回退出码 3。门禁单测和 P0 工具回归在具备 loopback 监听权限的环境中共 147 项通过；该门禁只保证不伪造正式数据，不替代正式 P95、吞吐、RSS 和长稳结果。
- 真实 Provider E2E 门禁已补充：`AUTHZ_REQUIRE_REAL_PROVIDER=1` 时，`test/waf/scripts/authz-cross-module-contract.sh` 启动仅用于契约验收的常驻 HTTP Provider，并通过 `/healthz` 探活；地址不可用、Provider 未 ready 或误用 `control:` 协议时返回退出码 3 和 `BLOCKED/ENVIRONMENT_UNAVAILABLE`。`test/waf/scripts/authz-cross-module-contract-gate.sh` 已验证无效 Provider 地址的阻塞场景；在允许 loopback 监听的隔离环境中，严格 HTTP Provider 模式已完整通过 Provider → gatewayconfig → Guard → PreviousValid 恢复链路。`server/internal/guardconfig/authz_provider_http_process_test.go` 提供测试用常驻 HTTP Provider（`/healthz`、`/v1/authz/config`、`/shutdown`），而 `AUTHZ_PROVIDER_CONTROL_TEST=1` 明确限定为受限环境的控制协议回归，不作为真实 E2E 证据。

正式验收入口约定：

- AUTHZ 跨 module 常驻 HTTP Provider 契约验收使用 `AUTHZ_REQUIRE_REAL_PROVIDER=1 AUTHZ_REAL_PROVIDER_ADDR=<http或unix地址> bash test/waf/scripts/authz-cross-module-contract.sh`；脚本会等待 `/healthz` ready 后读取 `/v1/authz/config`。`control:` 地址只能配合 `AUTHZ_PROVIDER_CONTROL_TEST=1` 做受限环境回归，不得作为真实 Provider 证据；该测试进程本身也不能替代正式 Provider 服务、多节点或跨主机流量证据。
- P0-02 的七模式、长稳与恢复验收使用 `bash test/performance/p0/run.sh matrix|soak|recovery --plan <冻结计划>`，并要求 `P0B_FORMAL_ENVIRONMENT_READY=1`、`P0B_FORMAL_ENV_ID` 与冻结计划中的 `environment.environment_id` 完全一致；缺少任一声明时必须保持退出码 3 和 `BLOCKED/ENVIRONMENT_UNAVAILABLE`，不得启动 Docker 栈。
- AUTHZ 专用本地配对微基准使用 `AUTHZ_BENCH_MODE=local AUTHZ_BENCHTIME=100ms AUTHZ_BENCHCOUNT=3 AUTHZ_RACE=1 bash test/performance/p0/run-authz-01.sh`；它只产生本机微基准证据。将 `AUTHZ_BENCH_MODE=formal` 用于正式组件测量时，另需提供 `AUTHZ_FORMAL_ENVIRONMENT_READY=1`、`AUTHZ_FORMAL_ENV_ID` 和存在的 `AUTHZ_FORMAL_PLAN` 文件。

本轮复核：

- `AUTHZ_REQUIRE_REAL_PROVIDER=1 bash test/waf/scripts/authz-cross-module-contract.sh` 在允许 loopback 监听的隔离环境中以 TCP 和 Unix socket 两种地址均输出 `AUTHZ-01 cross-module contract: PASS` 与 `AUTHZ-01 process recovery contract: PASS`；`AUTHZ_PROVIDER_CONTROL_TEST=1` 控制协议回归同样通过。受限沙箱仍会因禁止 loopback 监听返回退出码 3 和 `BLOCKED/ENVIRONMENT_UNAVAILABLE`，门禁不会把控制协议误报为真实 E2E。期间修复脚本在 `set -u` 下展开空 curl 参数数组会提前退出且错误返回 0 的问题，TCP/Unix Provider 均改为显式 curl 分支。
- `GOCACHE=/tmp/jz-waf-go-cache go test -mod=readonly ./internal/gatewayconfig -count=1` 已通过；其中 `TestRollbackFanoutPreservesRestoredConfig`、`TestRollbackFanoutPartialFailureIsPersistedAsIncomplete`、`TestRollbackFanoutRecordFailureIsPersistedAsIncomplete`、`TestFanoutTransientFailureCanRetryExactAuthzSnapshot` 和 `TestRetryNodeSyncVersionRecoversAfterNodeProcessRestart` 分别覆盖回退快照逐字传递、部分节点失败、状态落库失败、瞬时失败自动重试和节点进程重启后的恢复。该组证据仍是 loopback/进程内契约，不等同真实跨主机网络故障、机器故障或完整发布编排。
- AZ-10 角色信任链配置已补齐：管理面 `role_claims` 经请求 DTO、策略校验、审计摘要和 Store 持久化后进入 Guard JWT 信任配置；每个 issuer 最多 8 个声明名、单项最多 64 字符，声明名格式与重复项均校验。`server/internal/jwttrust` 全量测试、`gateway/dynamic_security/jwtverify` 全量测试及 `TestBuildGuardHandlerJWTTrust` 定向测试通过，OpenAPI 片段与生成文件已重新合并。该证据证明配置传播契约，不替代真实 JWT 签发方或跨节点发布验收。
- P0 runner 已补充容器内存与 Linux `VmRSS` 双口径、soak/recovery 状态和 catch-up 恢复门禁；本地配对 benchmark 与 `-race` 通过，formal 环境缺失时稳定返回 `BLOCKED`，不生成伪造 PASS。
- 节点同步的 `/load` 响应体中途 EOF 已收口：`CaddyClient.LoadConfig` 不再忽略 200 响应体读取错误，`TestCaddyClientLoadConfigRejectsInterruptedResponseBody` 用可重复的传输层故障注入验证该错误会回到同步失败结果，供既有版本级失败节点恢复重试；这仍不替代真实跨主机网络中断与机器故障注入。
- 网关当前配置读取的响应体中途 EOF 也已收口：`CaddyClient.GetCurrentConfig` 返回带 `get config response body failed` 上下文的错误，`TestCaddyClientGetCurrentConfigRejectsInterruptedResponseBody` 验证回滚前读取失败不会被误归类为无上下文错误；这仍不替代真实跨主机网络中断与机器故障注入。
- 管理面健康检查的 `/config/` 响应体中途 EOF 也已收口：`CaddyClient.Ping` 不再忽略 `io.Copy` 错误，`TestCaddyClientPingRejectsInterruptedResponseBody` 验证 200 响应传输中断会回传明确错误，避免节点被误判为健康；这仍不替代真实跨主机网络中断与机器故障注入。
- AZ-12 生效时间语义已收口：授权快照编译保留尚未到 `valid_from` 的 `CONFIRMED/OWNER` 关系，仅排除已过期关系；网关 `relationValid` 按本地可信时钟执行 `valid_from <= now < valid_until`，因此未来关系会随时间自然激活，不会因发布时机丢失。`TestLoadAPIAuthzSnapshotRetainsFutureRelationsForGatewayFiltering` 覆盖该回归，过期关系拒绝测试继续通过。
- 事件落库边界安全校验已补齐：`SavePrimary` 在执行主事件 SQL 前拒绝未脱敏的对象引用、原始角色声明和非法决策枚举，并对 `Details` JSON 序列化错误显式返回；通过校验的授权决策才写入 `api_authorization_decisions`，持久化内容仅保留 HMAC 对象引用与脱敏角色。`TestSavePrimaryRejectsUnsanitizedAuthorizationBeforeInsert`、`TestSavePrimaryRejectsRawAuthorizationRoleBeforeInsert`、`TestSavePrimaryPersistsRedactedAuthorizationDecision`、`TestSavePrimaryRejectsUnencodableDetails` 已通过普通与 `-race` 定向测试。
- 发布扇出恢复语义已进一步收口：`SyncConfigToNodes` 在扇出前后检查 `context.Context`，取消后不访问后续节点并保留已完成节点同步记录；对可识别的 5xx、连接中断、超时和 EOF 做一次受控重试；显式回滚使用独立后台上下文把已验证恢复 JSON 扇出到节点，仅在目标节点同步和结果落库完整时报告成功，部分失败与状态落库失败分别返回 `ROLLBACK_NODE_SYNC_FAILED` / `ROLLBACK_NODE_SYNC_STATE_PERSIST_FAILED`。`TestRollbackFanoutPreservesRestoredConfig`、`TestRollbackFanoutPartialFailureIsPersistedAsIncomplete`、`TestRollbackFanoutRecordFailureIsPersistedAsIncomplete`、`TestFanoutTransientFailureCanRetryExactAuthzSnapshot`、`TestRetryNodeSyncVersionRecoversAfterNodeProcessRestart` 以及取消语义测试已通过。该证据仍属于进程内/loopback 故障注入，真实跨主机网络中断、机器重启和独立发布器编排仍待正式环境。
- Provider 兼容边界已补齐可复现探针：旧快照缺失新增可选字段、包含未知授权分片时，Provider 会保留已知授权事实并在重新编码时丢弃未知字段；独立 Provider 测试进程可通过 HTTP 或受限环境 `control:` 协议返回归一化快照，跨模块控制协议门禁已通过。该证据仍不等同正式 Provider 服务、真实旧二进制节点组合或跨主机发布链路，因此第 2 类正式验收项仍保留。

验证环境记录：

- 本地定向测试、相关 server/gateway 包测试及授权链 `-race` 测试均通过；`git diff --check` 通过。P0 工具全量回归在具备 loopback 监听权限的环境中为 147 项通过。受限沙箱内的 `httptest.NewServer` 会因 IPv6 `[::1]:0` 监听权限报错（`operation not permitted`），但在获准的沙箱外复跑后 `server/internal/gatewayconfig` 完整包及回滚扇出测试均通过；server 全模块扫描其余 `aimodel`、`aiorchestrator`、`apiscan`、`apisecurity` 等包仍在受限环境复现同类限制，未修改生产代码绕过该环境限制。

正式环境后置项（不影响本轮本地实现交付）：

- 机器/网络中断、正式 Provider、多节点/旧二进制组合及跨主机连续流量：后续在正式集成环境补做；本地已有 JSON/HTTP 边界、`PreviousValid`、PostgreSQL 版本选择、节点失败重试、进程重启恢复和候选→确认→发布→真实 HTTP 决策契约。
- P0-02 正式基准环境的 P95/P99、端到端吞吐、RSS、20 万级关系索引和长稳数据：后续在冻结基准环境补做；本地配对 benchmark、`-race`、20 万关系索引微基准及缺环境 `BLOCKED` 门禁已完成。

## 1. 问题与目标

开工时的三个断点（设计 §1、§4）：

1. 对象权属只在 server 侧离线评估（`apiauthz` evaluate 五档结论），从未编译下发，网关热路径无法实时判断 BOLA；
2. 网关 BFLA 观察（`authzcheck.go`）的角色取自**未验签** JWT claims，只能作为观察信号，设计安全不变量 1 禁止其进入保护级决策；
3. 现有 `api_object_ownership` 是"谁访问过哪个对象"的观测证据，缺少来源、置信度、确认状态，直接当下发依据会把"访问过"误当"拥有"（安全不变量 3）。

目标（全部 OBSERVE，本任务**不实现任何阻断**）：

- 把对象权属升级为带 `来源 / 置信度 / 确认状态 / 有效期` 的授权关系模型，历史访问数据迁移为候选，不自动成为 confirmed owner；
- 提供候选确认 / 拒绝工作流（人工审批 + 操作审计），确认后的关系与对象模型一起经现有配置发布链编译为签名快照下发网关；
- 网关在 API 动态防护管线内独立执行实时 BOLA / BFLA 决策：只有 JWT 状态为 `VERIFIED` 且 `verified_principal_id` 非空的身份才参与可信授权判定；身份未验证、可信主体缺失、关系缺失、策略语义不完整或证据不足统一输出 `UNKNOWN`，只记录，不得包装成高置信越权（安全不变量 6）；
- 每条决策带 `decision_id`、原因码、策略版本，事件脱敏，可在管理面查询。

本任务完成后，WDSP 对水平越权（BOLA）和垂直越权（BFLA）具备**基于可信身份的实时检测与证据链**；阻断能力（OBSERVE→PROTECT 发布、灰度、回退）属于后续任务书，本任务不得宣称 PROTECT 已完成。

## 2. 明确不做（等待设计 §41 待决策事项或后续任务书）

- Session / API Key / 受信上游 Header 验证器（设计 §9，待决策 1）；
- 租户层级、多租户主体的活动租户选择（设计 §10.3，待决策 2）；本任务仅做单层租户：verified tenant 与对象归属租户的一致性观察；
- owner 权威源同步连接器（待决策 3）；本任务仅支持创建绑定候选与人工导入/确认；
- 共享、委托、客服代查关系类型（待决策 5）；数据模型预留枚举，不开放配置入口；
- 列表接口过滤、批量对象检查（设计 §15.3、§18，待决策 6）；
- 响应字段 MASK/REMOVE/DENY（设计 §17.3，待决策 7）；
- 失败开放/关闭分级策略（待决策 8）：本任务一律 OBSERVE，不存在失败关闭；
- GraphQL / gRPC 对象提取、策略模拟工作台、SHADOW/CANARY 发布。

## 3. 现有代码与集成位置

| 现有位置 | 现状/使用方式 |
|---|---|
| `server/internal/apiauthz/` | 角色基线、`api_object_ownership` sweep（access_count/last_seen）、对象模型、字段权限、evaluate 五档 BOLA 结论；doc.go 明确权属是观测证据而非定罪 |
| `server/internal/apiauthz/evaluate.go` | 离线五档评估规则；"不仅凭 ID 变化定罪"纪律本任务继续沿用 |
| `server/internal/guardconfig/authz_rules.go` | 角色基线 + 字段权限向网关的发布通道（现有契约不得破坏） |
| `server/internal/gatewayconfig/` | 编译、不可变版本、发布、节点回执、回退的现有机制，复用，不新建发布通道 |
| `server/internal/jwttrust/` | JWT 信任策略、`VerificationResult`、主体指纹；事件已带 `verified_principal_id` / `verified_tenant_id` |
| `gateway/dynamic_security/jwtverify/` | 网关本地验签；当前在身份 HMAC 密钥缺失时可能返回 `StatusVerified` 但 `VerifiedPrincipalID` 为空，因此授权可信身份必须同时检查状态与非空主体 ID |
| `gateway/dynamic_security/detectors/authzcheck.go` | BFLA 角色基线观察 + 字段权限观察；现有未验签角色提取仅保留为旧观察信号，不得进入本任务的可信授权决策 |
| `gateway/dynamic_security/detectors/resource.go` | 对象 ID 提取（path/query）、连续数字 ID 枚举检测；仅辅助信号 |
| `gateway/dynamic_security/events/event.go` | 事件已含 verified 身份字段；本任务扩展授权决策字段 |
| `gateway/modules/jiuzhang_guard/module.go`、`apiprotect.go` | 请求顺序与 API 动态管线挂接点；新增决策不得改变既有防护先后关系 |
| `server/migrations/000043_*`、`000044_*` | 现有基线表迁移；新表编号先核对最新迁移号，不得猜测 |
| `server/openapi/fragments/07-api-security.yaml`、`CONTRACT.md` | OpenAPI 片段与契约约束 |

**实际新增位置**：server 侧关系接口与候选任务落在 `server/internal/apiauthz/relations.go`、`candidate_sweep.go`、`mem_relations.go`；网关决策器落在 `gateway/dynamic_security/detectors/authzdecide.go`。共用枚举仍按现有模块边界分别定义，网关未跨 Go 模块导入 server internal 包。

## 4. 数据模型契约（新增约定）

### 4.1 对象关系与候选

新建 `api_object_relations` 与 `api_object_relation_candidates`（设计 §26.2），关键字段契约：

| 字段 | 契约 |
|---|---|
| `application_id`、`object_type`、`object_ref` | `object_ref` 为带域分隔的 HMAC 引用（域前缀 `objref:`），与身份指纹密钥/域不同；不落明文对象 ID（设计 §12.3、§33） |
| `principal_id` | confirmed 关系中非空且仅接受 `verified_principal_id` 形态的主体；未验证身份不得写入关系 |
| `relation` | 首期开放 `OWNER`；`SHARED_WITH` / `DELEGATED_TO` / `SUPPORT_ACCESS` 枚举预留但不可配置 |
| `tenant_id` | 可空；来源为已验证 tenant claim 或人工指定，不得来自客户端请求参数 |
| `source` | `MANUAL` / `IMPORT` / `CREATE_BINDING`；`OBSERVED_ACCESS` 只允许出现在候选表 |
| `status` | `CONFIRMED` / `REVOKED` / `EXPIRED`；confirmed 关系物理或逻辑隔离于候选（设计 §26.3） |
| `valid_from` / `valid_until` | 有效期随关系下发；网关按本地可信时钟逐请求校验 `valid_from <= now < valid_until`（空 `valid_until` 表示无截止时间），后端任务置 `EXPIRED` 仅用于状态维护与触发重发布，不能替代热路径校验 |
| `evidence_ref`、`confirmed_by`、`confirmed_at`、`reason` | 证据引用与审批留痕；`reason` 非空进操作审计 |

候选表增加可空 `principal_id`、独立的 `legacy_identity_fingerprint`、`source_count`、`first_seen`、`last_seen`、`confidence_inputs`（来源多样性聚合，设计 §13.3）。只有由 VERIFIED 流量生成且 `principal_id` 非空的候选可进入确认流程；历史身份指纹与 `verified_principal_id` 属于不同信任域，禁止互相复制或转换。所有候选均不参与网关决策。

### 4.2 历史数据迁移

- `api_object_ownership` 现有行**整体迁移为候选**（`source=OBSERVED_ACCESS`、未确认）：对象 ID 由应用迁移任务使用对象引用专用密钥计算 `object_ref`，旧 `identity_fingerprint` 只写入 `legacy_identity_fingerprint`，`principal_id=NULL`，并标记为不可直接确认；不得直接转为 confirmed（设计 §36.2、安全不变量 3）；
- 对象引用密钥不可用时迁移任务必须失败并保留待迁移状态，不得落明文或用身份指纹密钥代替；迁移幂等、可重跑；保留原表只读一段时间，不硬删除历史审计能力；
- 切换到新候选采集器后停止旧 `api_object_ownership` sweep 写入，避免同一访问在新旧信任域重复累计；历史候选如需转正，必须由管理员通过手工关系/导入流程绑定一个经过校验的 `verified_principal_id`，原候选只作为证据引用；
- `api_role_baselines` 现有 confirmed 行打标 `identity_assurance=OBSERVED`：它们基于未验签角色学习，本任务中网关对 VERIFIED 身份执行 BFLA 判定时不直接复用（见 §7.3）。

### 4.3 对象模型下发范围

`api_object_models`（现有）补充发布标记与授权语义：只有 `publishable=TRUE`、端点归一化模板唯一、`required_relation=OWNER` 且 `owner_exclusive=TRUE` 的模型才能产生 `AUTHZ-BOLA-001`。缺少或冲突的授权语义只能输出 `UNKNOWN(policy)` / `AUTHZ-POLICY-001`，不能由“他人是 OWNER”推导当前主体必然越权。复合键、BODY 位置提取本期不下发（设计 §12.2 裁剪为 path + query）；共享、委托等模型待后续任务开放。

## 5. 管理接口契约（新增约定）

统一挂在 `server/internal/apiauthz` 现有路由前缀下，OpenAPI 片段不重复 `/api/v1` 前缀：

| 方法与路径 | 权限 | 用途 |
|---|---|---|
| GET `/authz/relations/candidates` | `api_authorization.read` | 候选关系分页列表（来源、次数、时间跨度、脱敏引用） |
| POST `/authz/relations/candidates/{id}/confirm` | `api_authorization.relation_manage` | 仅确认 `principal_id` 非空的候选为 CONFIRMED 关系；body 带 `relation`、`reason`，409 防并发；历史不可确认候选返回 409 并引导手工绑定/导入 |
| POST `/authz/relations/candidates/{id}/reject` | `api_authorization.relation_manage` | 拒绝并记录原因，候选不再浮现 |
| GET/POST `/authz/relations` | read / `relation_manage` | 查询/手工维护 confirmed 关系（含 IMPORT 录入） |
| GET `/authz/decisions` | `api_authorization.read` | 授权决策事件查询（decision_id、原因码、策略版本、脱敏证据） |
| GET `/authz/decisions/{id}` | `api_authorization.read` + `api_authorization.evidence_read` | 查询单条授权决策及脱敏证据；`application_id` 不匹配按 404 处理 |
| GET `/authz/coverage` | `api_authorization.read` | 覆盖率：VERIFIED 身份占比、对象模型覆盖、confirmed 关系占比、UNKNOWN 率 |

权限点新增 `api_authorization.relation_manage` 与 `api_authorization.evidence_read`（查看脱敏证据详情），种子迁移登记；确认/拒绝与手工维护进操作审计（字段差异摘要，不含明文对象 ID 与主体）。不存在 ID 404、字段错误 400/422 按仓库统一规范，列表执行应用范围校验。

防投毒纪律（设计 §13.3，必须在实现中强制执行）：

- 单次访问永不生成 confirmed；候选确认必须人工或走 IMPORT 审批；
- 高权限运维、测试机器人、服务账号身份类型不参与候选生成（复用 identity_type 判定）；
- 一个对象在短窗口内出现超过阈值的不同主体候选时，冻结该对象自动浮现并标记异常；
- 同一来源的重复弱信号不得无限抬高候选排序。

## 6. 编译与下发契约（新增约定）

复用 `gatewayconfig` 现有发布机制，新增授权决策策略分片（与 `authz_rules.go` 平级，不混入现有分片破坏契约）：

- 编译内容：对象模型（path/query 提取规则 + 端点模板 + OWNER-only 授权语义）、confirmed 关系索引（含 `valid_from` / `valid_until`，按 application + object_type 分桶）、`identity_assurance=VERIFIED` 的 confirmed 角色基线、发布版本与摘要；快照带最大有效期（设计 §27.2）；
- 建议默认值：单分片 confirmed 关系 ≤ 200,000 条，超过按 object_type 拆分并在编译期告警；单端点模型唯一键冲突在编译期报错拒绝发布；
- 原子替换：网关先整体校验再切换，禁止加载半份；发布失败保留上一有效版本并报告节点水位；
- 关系变更（确认/撤销/过期）触发增量重编译与再发布，走同一版本链，不得绕过审核直推；
- 快照不含明文对象 ID、明文主体；对象引用 HMAC 密钥与 JWT 信任链指纹密钥分离。当前实现不把该密钥写入版本快照，`PreviousValid` 也不携带历史密钥，Guard 回放时统一使用当前运行时密钥重注入；双密钥轮换窗口尚未实现，列为后续任务。

## 7. 网关决策契约（新增约定）

### 7.1 判定顺序（对应设计 §15.1，裁剪版）

```text
1. 独立定位两类基线：BOLA 对象模型、BFLA 端点角色基线；两者均未命中才无行为，BFLA 不以命中对象模型为前提
2. 构造可信身份上下文：仅 `jwtverify StatusVerified` 且 `VerifiedPrincipalID` 非空才是 VERIFIED；状态非 VERIFIED 或主体 ID 为空时，各个已命中分支分别输出 UNKNOWN(identity)
3. BFLA 分支：直接按 §7.3 的可信角色与 VERIFIED confirmed 角色基线比对；管理员端点没有对象 ID 时仍必须执行
4. BOLA 分支：仅在命中对象模型时提取对象标识（path 占位段 + query，复用 resource.go 提取纪律，raw 不出内存）；提取缺失/歧义 → UNKNOWN(object)
5. BOLA 策略前提：模型必须显式声明 `required_relation=OWNER` 且 `owner_exclusive=TRUE`；缺失/冲突 → UNKNOWN(policy) / AUTHZ-POLICY-001
6. BOLA 关系有效性：网关先按本地当前时间过滤非 CONFIRMED、尚未生效或已过期关系，再做主体与租户匹配；后端状态尚未改为 EXPIRED 不得使过期关系继续生效
7. 租户一致性：双方 tenant 均非空且不同 → AUTHZ-TENANT-001；仅一方为空 → UNKNOWN(tenant)；双方为空表示该模型不启用租户维度，不得使用请求参数补齐
8. BOLA 关系结论：自身命中有效 OWNER → ALLOW；存在他人有效 OWNER、自身无有效 OWNER 且 OWNER-only 前提成立 → AUTHZ-BOLA-001；没有足够关系数据 → UNKNOWN(relation)
9. 输出一个请求级决策组（全部 OBSERVE，请求一律放行）
```

### 7.2 决策输出

复用/扩展现有事件结构：新增请求级 `authz_decision` 字段组，包含共享的 `decision_id`、`policy_version` 与 `checks[]`。每个 BOLA/BFLA 检查项独立携带 `type`、`decision`（ALLOW/OBSERVE_VIOLATION/UNKNOWN）、`reason_code`（取设计 §25 子集：`AUTHZ-BOLA-001/002`、`AUTHZ-BFLA-001`、`AUTHZ-TENANT-001`、`AUTHZ-CONTEXT-001`、`AUTHZ-POLICY-001/002`）、`confidence`、`relation_state`；请求级结论按 `OBSERVE_VIOLATION > UNKNOWN > ALLOW` 聚合，不能让一个分支覆盖另一个分支的证据。证据只含结构信息与 HMAC 引用，不落原始对象 ID、Token、claims 值。`UNKNOWN` 在页面和统计中与违规明确分开（设计 §14.3）。

### 7.3 BFLA 可信角色来源

- JWT 信任策略的 issuer 配置新增显式 `role_claims` 映射（声明名列表，不自动猜测）；管理端校验声明名、数量与长度，发布时进入 JWT 信任配置；未配置映射时 BFLA 输出 UNKNOWN(role)，不得回退读取未验签 claims；
- `jwtverify.VerificationResult` 新增 `VerifiedRoles`：只在签名、issuer/audience/时间等校验全部通过后从 `role_claims` 读取，仅接受字符串或字符串数组，拒绝把数字、对象等类型隐式转成字符串，再经去重、限量、限长后写入；随后通过 `jiuzhang_guard` 请求上下文传给授权决策器。非 VERIFIED 或 `VerifiedPrincipalID` 为空时必须清空可信角色；日志和事件不得记录原始 claims 值；
- 现有基于未验签 claims 的 BFLA 检测器只保留为独立的 legacy 观察信号，标记 `role_source=OBSERVED`，不得写入本任务的 `authz_decision.checks[]`，也不得生成/确认 `identity_assurance=VERIFIED` 基线；新决策路径固定标记 `role_source=VERIFIED`；
- VERIFIED 流量的角色学习只生成 `identity_assurance=VERIFIED`、`source=OBSERVED`、`confirmed=false` 的候选行；沿用现有 `/api-security/authz/role-baselines` 列表和 `/{id}/confirm` 接口完成筛选与确认，无额外“重新生成”占位接口。`identity_assurance=OBSERVED` 的旧基线不与 VERIFIED 角色比对出违规，只显示“基线待重校准”（设计 §16.3、§36.3）。

### 7.4 性能与故障

- 热路径零网络 IO、零 PostgreSQL；本地索引查找 + 对象提取的 P95 增量目标 ≤ 2 ms（设计 §32.1），纳入 P0-02 配对基准；
- 单请求对象引用数量、关系索引内存、决策事件采样均设上限；事件异步批量写，存储不可用本地限量缓冲并告警，不影响请求放行；
- 快照过期：继续加载上一有效版本中的模型与索引并产生 `AUTHZ-POLICY-002` 观察与告警，但每条关系仍必须按自身 `valid_from` / `valid_until` 实时过滤；快照过期不得复活已过期关系，也不得因清空索引制造全量 UNKNOWN 事件洪峰。

## 8. UI / UX 与事件

- 应用下新增"对象授权"面板：候选列表（待确认数）、确认/拒绝操作、confirmed 关系视图、覆盖率卡片（VERIFIED 身份占比、模型覆盖、UNKNOWN 率）、决策事件时间线（身份验证 → 租户 → BOLA → BFLA → 结论）；
- 候选与 confirmed 在视觉上明确区分（虚线/徽标），禁止混淆展示（设计 §31.3）；对象引用默认脱敏，详情需 `evidence_read` 权限；
- 状态完整：加载、空数据、部分节点未生效、发布失败、无权限、保存/发布失败均有可恢复入口；不能只 Toast；
- 事件详情扩展授权决策字段，历史无字段事件显示"当时未记录"；UNKNOWN 不得渲染成"越权"。

## 9. 实施步骤

1. 核对 `apiauthz`、`guardconfig`、`jwtverify` 当前代码与最新迁移号；冻结表结构、枚举、事件字段与 OpenAPI 增量；
2. 先写迁移与防投毒单测：历史行→候选、单次访问不确认、冻结阈值、来源多样性；
3. 实现候选/关系存储、确认工作流、权限与审计，接口测试覆盖越权与并发；
4. 实现编译分片、快照校验、原子下发与节点水位，发布失败/回退测试；
5. 实现网关 `authzdecide.go` 决策与事件扩展，先单测判定矩阵，再接管线做真实网关集成测试（含 JWT OFF / 未配置应用 / 旧版本节点）；
6. 实现管理页面与事件详情，补 E2E（候选→确认→发布→攻击流量→决策可见）；
7. 跑 P0-02 配对基准（决策开/关），更新能力清单与 DEVELOPMENT_STATUS，WORKLOG 记录证据。

## 10. 必须通过的验收用例

| ID | 条件 | 预期 |
|---|---|---|
| AZ-01 | 历史 ownership 数据迁移 | 全部成为 `principal_id=NULL`、保留独立 legacy 指纹且不可直接确认的候选；对象引用用专用密钥计算；无一行自动 confirmed；迁移可重跑幂等 |
| AZ-02 | 单次/多次访问产生新的 ownership 证据 | 只生成候选；候选本身不改变网关结论，缺少既有 confirmed 关系时仍为 UNKNOWN(relation) |
| AZ-03 | 候选确认→编译→发布 | 仅 VERIFIED 流量产生且 `principal_id` 非空的候选可确认并进入快照；legacy 候选确认返回 409；未确认候选从不出现在快照 |
| AZ-04 | VERIFIED 用户访问本人 confirmed 对象 | 决策 ALLOW 证据，请求放行，事件含 decision_id |
| AZ-05 | VERIFIED 用户 A 访问 confirmed 属于 B 的对象 | 仅模型显式 `required_relation=OWNER`、`owner_exclusive=TRUE` 时产生 `AUTHZ-BOLA-001`；未声明或允许共享时为 UNKNOWN(policy)，请求均放行 |
| AZ-06 | 未验签/无凭据，或 `StatusVerified` 但 `VerifiedPrincipalID` 为空 | BOLA/BFLA 已命中分支只出 UNKNOWN(identity)；可信角色为空，不得产生授权违规结论 |
| AZ-07 | 对象无关系、模型授权语义缺失或对象提取歧义 | 分别输出 UNKNOWN(relation/policy/object)，页面与统计和违规分开展示 |
| AZ-08 | tenant 完整性矩阵 | 双方非空且不同才产生 `AUTHZ-TENANT-001`；仅一方为空为 UNKNOWN(tenant)；双方为空不启用租户维度；请求参数不得作为身份租户 |
| AZ-09 | VERIFIED 普通角色访问无对象 ID 的管理员端点基线 | 仍产生 `AUTHZ-BFLA-001`、`role_source=VERIFIED`；BFLA 不依赖对象模型；未验签同请求只走独立 legacy 观察信号 |
| AZ-10 | 角色信任链与旧 OBSERVED 基线 | 显式 `role_claims` 经验签结果和请求上下文传递；未配置映射为 UNKNOWN(role)；旧基线不出违规，VERIFIED 候选经现有确认接口确认后才参与判定 |
| AZ-11 | 伪造主体/对象投毒：多账号轮番访问同一对象 | 候选冻结并标记；confirmed 关系不被污染 |
| AZ-12 | 关系尚未生效、撤销或过期 | 即使后端状态任务/重发布尚未完成，网关也按本地时间过滤 `valid_from/valid_until`，不再把该关系作为有效命中；旧版本节点行为可解释 |
| AZ-13 | 发布失败/部分节点失败/回退 | 保留上一有效版本；节点水位可见；不静默丢失已生效配置 |
| AZ-14 | 快照过期、事件存储中断 | 按 §7.4 行为；旧快照不复活已过期关系，请求不受影响；告警与限量缓冲生效 |
| AZ-15 | 事件与日志审计 | 无明文对象 ID、Token、claims 值；reason 与字段差异进操作审计 |
| AZ-16 | 权限矩阵 | 无 `relation_manage` 不能确认；无 `evidence_read` 看不到详情；跨应用访问 404/403 |
| AZ-17 | 高并发 + 大索引基准 | P95 增量 ≤ 2 ms 目标内；无数据竞争（-race）、无无界内存/标签 |
| AZ-18 | 全流程 E2E | 创建对象→候选→确认→发布→他人访问→决策事件时间线完整可复核 |

AZ-01～14 需单元 + 真实网关组合验证；AZ-15/16 接口测试；AZ-18 E2E；AZ-17 在 P0-02 基准环境完成，不虚构性能数字。

## 11. 迁移、回退与完成定义

迁移以新表 + 可空字段为主；新候选采集器启用后停止旧 `api_object_ownership` sweep 写入，旧 evaluate 接口与原表进入只读兼容期，确认无消费者后再按设计 §36 废弃，不直接删历史数据。legacy 候选不得原地补写或推导 `principal_id`，转正必须通过手工关系/导入流程建立新的可信主体绑定并引用原证据。回退走真实发布链并保留审计；含本任务快照的系统回退到旧网关二进制前，须显式处理未知分片并提示行为变化。

完成条件：候选/关系模型、确认工作流、编译下发、网关 OBSERVE 决策、事件、UI、权限、审计、迁移、回退全部接线并通过 §10 用例。按本轮范围，上述本地实现与可复现契约已完成；正式 Provider、跨主机故障和正式性能数据列为后置验收。**本任务任何交付均为 OBSERVE**；宣称"越权防护已阻断"属于超出范围，PROTECT 以后续任务书为准。
