# WDSP 1.1.4 合并审查记录与修复建议

日期：2026-09-10。基线：`develop`，提交 `52bff9b63bd7be258b5da90c420094fc4d151fee`，标签 `wdsp-v1.1.4`。

修复起点仓库 HEAD：`6b9561d`，该提交仅增补 Kimi 修复计划；本报告后续记录 1.1.5 的实际修复与复核结果。

来源：本报告原有 Codex 审查 R01～R14、[Kimi 产品发现修复计划](/Users/zhanglei/Documents/JiuZhang_WAF/docs/tasks/wdsp-p1/PRODUCT_FINDINGS_FIX_PLAN.md)、Codex 对该计划的静态复核。本文保留原始来源编号，以本报告编号统一跟踪；Kimi 原文保留作来源，发生结论或方案冲突时采用本文注明的复核意见。

## 范围与结论

本次合并覆盖管理后端、动态防护检测器、网关配置编译与回滚、API 资产采集、备份恢复、Agent 采集与补传。主清单记录 **23 项已有代码依据的缺陷：P1 11 项、P2 12 项**，由原有 14 项与 Kimi 报告中经静态复核的 9 项组成。这不是全仓缺陷总数，也不表示全部问题均已运行复现。

另外保留 **7 条修复方案审查意见 D01～D07**、调查与设计台账、**31 个低危来源子项 L01～L31**。这些台账不混入 23 项缺陷统计，尤其不能把待调查、能力边界、文案改进直接统计成漏洞。Kimi #1～#4 与原报告的 4 项重复，已合并；D01～D07 是对修法的约束，不再重复计算底层缺陷。

按用户要求，排除仅涉及正式环境部署、裸机性能、跨主机验收的待办；安全问题不新增攻击探针或攻击验证。修复阶段执行单元测试、接口测试和本地回归，用于确认代码行为与构建完整性。

涉及多实例的发布锁、密钥初始化等代码一致性问题仍在审查范围内；正式环境部署验收暂缓，不等于排除这些代码问题。

P1 表示应优先处理的防护失效、发布阻断、进程崩溃或主要采集链路不可用问题；P2 表示其他授权判断、数据完整性、状态流转及可靠性问题。优先级为代码审查判断，不是 CVSS 评分。新增项暂沿用 Kimi 高危→P1、中危→P2 的顺序，实施前可按影响范围重评，不能从方案意见的优先级反推漏洞等级。

状态：R01～R23 已纳入 1.1.5 修复并完成本地回归；调查与设计项按下表状态保留。正式环境验收明确暂缓，不以本地测试替代正式环境证据。

| 编号 | 优先级 | 问题 | 证据 |
| --- | --- | --- | --- |
| R01 | P1 | AUTHZ 编译 SQL 使用迁移前的列名，WDSP 开启时发布失败 | 静态调用链与迁移对照 |
| R02 | P1 | 自定义 OBSERVE 规则切换整个 Coraza 事务的引擎模式 | 静态 + 此前局部验证 |
| R03 | P1 | 自定义正则的反斜杠转义改变匹配语义 | 静态 + 此前局部验证 |
| R04 | P1 | 可选 MMDB 缺失时 typed nil 导致后台扫描 panic | 静态 + 此前局部验证 |
| R05 | P2 | 撤销或过期后的同一对象关系无法重新授权 | 静态 |
| R06 | P2 | BOLA 租户判断依赖第一条 OWNER 关系 | 静态 + 此前局部验证 |
| R07 | P2 | BFLA 多角色判断依赖基线行顺序 | 静态 + 此前局部验证 |
| R08 | P1 | 完整历史配置回滚跳过回归发布门禁 | 静态 |
| R09 | P2 | 运行时策略回滚失败后遗留待发布 DRAFT | 静态 |
| R10 | P1 | 备份恢复遗漏防护关联数据，恢复后可能混用不同版本数据 | 静态 |
| R11 | P2 | 不同应用、Host 的同名 API 资产被合并 | 静态 |
| R12 | P1 | 事件明细数量上限提前终止文件、字段安全检查 | 静态；两处同类实现合并 |
| R13 | P1 | 规则查询错误被转为空配置，发布可能移除现有防护 | 静态 |
| R14 | P1 | 字段权限拦截使用未验签、未映射的角色声明 | 静态 |
| R15 | P1 | Agent 补传批次超过令牌桶容量后无法继续发送 | 静态；Kimi R-2 |
| R16 | P1 | tap 分帧器复用底层切片，覆写已交付帧 | 静态；Kimi R-3 |
| R17 | P2 | 应用自动封禁遮蔽全局人工封禁 | 静态；Kimi R-4 |
| R18 | P2 | 响应捕获将 103 等临时响应锁存为最终状态 | 静态；Kimi R-5 |
| R19 | P2 | 发布锁过期与非原子释放造成并发发布竞态 | 静态；Kimi R-6 |
| R20 | P2 | 首次并发初始化密钥时，各进程使用不同密钥 | 静态；Kimi R-7 |
| R21 | P2 | 证书轮换失败导致本地钥证及服务端指纹不一致 | 静态；Kimi R-8 |
| R22 | P2 | AI 供应商地址可改变已有密钥的发送目的地 | 静态；Kimi R-10 |
| R23 | P2 | 解压截断信号丢失，残缺内容被标为完整 | 静态；Kimi R-12 |

原有 R01～R14 编号与证据保持不变，新增缺陷从 R15 续编。Kimi 使用带连字符的 R-1～R-12，与本报告编号不是同一序列。

## 问题明细

### R01 · P1 · AUTHZ 编译使用已重命名的数据库列

位置：[AUTHZ 模型查询](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/guardconfig/authz_decision.go:33)、[正式迁移](/Users/zhanglei/Documents/JiuZhang_WAF/server/migrations/000018_stage8_full_schema.up.sql:9)、[发布配置装配](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/guardconfig/provider.go:490)。

查询仍引用 `ep.method`、`ep.path_template`、`ep.status`，但迁移已分别改为 `http_method`、`normalized_path`、`asset_status`。在应用装配了真实 `AuthzSnapshotStore` 且 WDSP 功能开启的正常发布路径上，PostgreSQL 会因不存在的列拒绝查询，错误向上传播并中止配置生成。

触发不要求数据库已有可发布对象模型：查询发生在 `len(models) == 0` 的分支之前。纯 WAF、WDSP 关闭而不进入该装配路径时，不据此认定受影响。

建议：对齐实际迁移后的列名，并在后续修复验收中覆盖“执行全部迁移后的数据库 + 真实 SQL 仓储 + 无对象模型”的发布场景。仅使用伪造 lister 的单元测试无法发现列名不匹配。

证据：静态确认；未执行真实数据库发布验证。

### R02 · P1 · 一条 OBSERVE 规则会降低后续 Coraza 规则的执行强度

位置：[OBSERVE 动作生成](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/customrules/customrules.go:181)。

`GenerateSecLang` 把单条自定义规则的 `OBSERVE` 动作生成为 `pass,log,ctl:ruleEngine=DetectionOnly`。其中 `ctl` 改变的是当前 Coraza 事务的引擎模式，而不只作用于这一条规则。请求先命中该观察规则、再命中其他阻断规则时，后续规则可以继续记录命中，却不再执行原有阻断。

此前真实 Coraza 的局部对照结果为：前置规则使用 `LOG` 时，后续 SQLi 规则命中且阻断；改用生成的 `OBSERVE` 时，同一 SQLi 规则仍命中但没有阻断。影响限定为同一事务中的后续 Coraza 防护，不推断为其他网关模块或后续请求均被关闭。

建议：使用仅影响本规则的非阻断记录动作，移除观察动作对事务级引擎模式的修改；保留独立规则正常执行的语义。

证据：[此前 Coraza 检查日志](/tmp/wdsp-review-20260910/coraza-probes.log:1)。

### R03 · P1 · 正则参数转义改变规则含义

位置：[操作参数生成](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/customrules/customrules.go:175)、[参数转义](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/customrules/customrules.go:203)。

`escapeSecLangArg` 将操作参数中的每个反斜杠翻倍。现有 Coraza/SecLang 解析路径没有将这种处理还原为原始正则语义，导致带转义字符的合法阻断规则失去预期匹配能力。例如 `^hello\s+world$` 原本匹配 `hello world`，生成后的 `^hello\\s+world$` 在此前局部检查中不再匹配。

这是规则序列化问题，不能只通过前端检查正则是否合法解决；规则仍可能成功生成并加载，而实际防护与管理员填写的表达式不同。

建议：依据当前 SecLang 解析器处理规则参数的方式进行序列化，保留正则反斜杠语义，同时继续防护引号、换行等规则注入边界。修复后再覆盖含空白类、数字类、字面反斜杠和引号的生成结果。

证据：[此前原始正则与生成正则对照](/tmp/wdsp-review-20260910/coraza-probes.log:11)。

### R04 · P1 · MMDB 缺失时后台地域扫描可导致进程退出

位置：[可选 MMDB 装配](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/app/app.go:1335)、[后台扫描装配](/Users/zhanglei/Documents/JiuZhang_WAF/server/cmd/api/main.go:253)、[接口 nil 判断](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/apigeo/sweep.go:127)、[MMDB 接收器解引用](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/apigeo/mmdb.go:141)。

允许缺失的 MMDB 文件会使应用保留一个空的 `*apigeo.MMDB`。该指针传入 `CountryLookup` 接口后，接口本身不等于 `nil`，因此 `SweepOnce` 的空值判断无法跳过扫描。遇到需要地域分类的公网 IP 敏感事件时，调用继续进入空接收器并发生 panic。

后台定时扫描在独立 goroutine 中调用该路径，调用链未恢复此 panic，因此可导致管理后端进程退出。触发需要进入实际地域查询；仅启动且没有合格事件时，并不必然立即崩溃。

建议：在接口装配前处理 typed nil，MMDB 不可用时明确停用对应扫描并保持状态可查询；必要时为接收器增加防御性检查，保持可选能力缺失时的降级约定。

证据：[此前缺失 MMDB 检查日志](/tmp/wdsp-review-20260910/server-probes.log:8)。

### R05 · P2 · 已撤销或过期的关系占用唯一键，阻止重新授权

位置：[关系唯一约束](/Users/zhanglei/Documents/JiuZhang_WAF/server/migrations/000136_authz_observe_relations.up.sql:83)、[创建关系](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/apiauthz/relations.go:301)、[撤销关系](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/apiauthz/relations.go:329)。

唯一键覆盖 `(application_id, object_type, object_ref, principal_id, relation)`，不区分关系状态。撤销、过期会保留原记录；随后通过创建或确认流程显式重新授予同一关系时，仍执行 `INSERT`，唯一约束冲突被转换为关系冲突错误。正常的“撤销后重新授权”或“到期后续授”因此无法完成。

建议：为显式重新授权设计带审计的关系版本或状态转换，并让唯一约束与有效关系生命周期一致。不能简单把重复导入自动解释为恢复授权，否则会改变撤销的安全语义。

证据：静态对照迁移、创建、确认与撤销流程；未执行授权操作。

### R06 · P2 · BOLA 用第一条 OWNER 关系确定对象租户

位置：[关系检索与租户选择](/Users/zhanglei/Documents/JiuZhang_WAF/gateway/dynamic_security/detectors/authzdecide.go:363)。

关系索引包含应用、对象类型和对象引用，但不含租户。检出同一对象引用的有效 OWNER 关系后，代码取第一条非空 `TenantID` 作为对象租户，先完成租户比较，再检查主体是否为 OWNER。

当同一应用的不同租户使用相同业务对象 ID 时，这些关系可以拥有相同对象引用。此前局部检查中，对同一租户 B 的合法 OWNER，仅调换租户 A/B 关系的排列顺序，结果就在 `OBSERVE_VIOLATION` 与 `ALLOW` 之间切换。这会污染越权告警和后续授权分析。

建议：明确对象标识的租户边界，让关系检索、对象引用和主体判定采用一致的身份维度；无法区分对象或存在关系歧义时返回 `UNKNOWN`，不能用第一条记录决定对象归属。

证据：[此前关系顺序对照](/tmp/wdsp-review-20260910/authz-probes.log:1)。影响限定为 AUTHZ-01 的 OBSERVE 决策，未据此认定已发生实际拦截绕过。

### R07 · P2 · BFLA 多角色的允许、拒绝由行顺序决定

位置：[首个角色匹配即返回](/Users/zhanglei/Documents/JiuZhang_WAF/gateway/dynamic_security/detectors/authzdecide.go:300)、[基线冲突检查](/Users/zhanglei/Documents/JiuZhang_WAF/gateway/dynamic_security/detectors/authzdecide.go:314)。

同一可信主体可以持有多个已验证角色。当前实现遍历基线，遇到第一个属于该主体的角色便立即返回允许或违例；冲突检查只发现“同一角色同时允许和拒绝”，没有处理主体持有的不同角色之间的组合语义。

此前对照中，主体同时持有允许角色与拒绝角色，仅交换两条等价基线的排列顺序，就得到 `ALLOW` 或 `OBSERVE_VIOLATION`。即使 SQL 使用固定排序，也只是把行排序变成了隐含授权优先级。

建议：规定并实现明确的多角色合并规则；没有既定允许优先或拒绝优先约定时，将冲突作为 `UNKNOWN` 处理。决策应由角色集合及政策决定，而不依赖输入排列。

证据：[此前多角色顺序对照](/tmp/wdsp-review-20260910/authz-probes.log:5)。同样限定为 AUTHZ-01 的 OBSERVE 判断错误。

### R08 · P1 · 完整历史配置回滚绕过 ENFORCE 回归门禁

位置：[完整回滚入口](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/gatewayconfig/publisher.go:983)、[直接加载历史配置](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/gatewayconfig/publisher.go:1018)、[正常发布门禁](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/gatewayconfig/publisher.go:493)、[恢复通道的密钥撤销约束](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/regression/gate.go:160)。

完整回滚只要求目标版本曾经发布成功，重注入当前密钥后直接调用 `loadGatewayConfig`，没有调用 `evaluateRegressionGate`。之后的 `verifyPublish` 不是发布前回归证据门禁，也无法代替其签名密钥、证据完整性和候选指纹检查。

门禁实现明确规定：恢复通道可豁免证据年龄，但不能豁免签名密钥已撤销、证据缺失等条件。因此，管理员通过完整历史回滚入口，仍能加载当前 ENFORCE 政策本应阻止的历史候选。这是已获回滚权限者可走通的门禁缺口，不是未认证访问问题；不依赖正式环境部署。

建议：对重注入完成后的实际候选内容计算指纹，在下发任何节点前执行恢复通道门禁，统一完整回滚与访问控制快照回滚的约束。

证据：静态追踪入口、发布器与门禁实现；未执行回滚。

### R09 · P2 · 回滚任务提前失败后，草稿仍可能随其他发布生效

位置：[回滚处理器的失败分支](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/apimodels/runtime_policy_handler.go:148)、[门禁早于访问控制快照与回写](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/gatewayconfig/publisher.go:498)、[待发布策略激活逻辑](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/apimodels/runtime_policy.go:152)。

`RollbackToKnownGood` 先提交旧模型恢复为 FORMAL、新建 DRAFT 的事务，再触发同步发布。发布调用返回非空 `error` 时，处理器会显式把 DRAFT 标为 FAILED；但返回“任务状态 FAILED、error 为 nil”时，它仅返回 502，并声称草稿已标记失败。

发布任务若在回归门禁、编译等前置阶段失败，访问控制快照尚未建立，负责联动 `MarkRuntimePoliciesPublishResult` 的路径未执行。此时新 DRAFT 仍处于待发布集合；下一次其他配置发布成功时，可能被一并转成 ACTIVE，违背错误响应中“需重新激活后再发布”的状态说明。

建议：对所有非成功任务结果显式、幂等地结算本次 DRAFT，使用不依赖已取消请求的收尾上下文；同时处理 FORMAL 模型已恢复与发布失败之间的一致性，不能只修改错误文案或只考虑草稿标签。

合并复核补充（Kimi #1 / D01）：`MarkRuntimePolicyFailed` 只改策略记录，而 `ListFormalSchemas` 按模型的 FORMAL 状态读取发布源，不依赖策略是否 FAILED。仅补调用该函数仍可能把已经恢复的模型留给后续发布。激活失败后的 VALIDATED 也属于待发布集合，不能认定为“语义无害”。后续验收条件应同时覆盖模型指针、发布源、策略状态以及实际下发内容。

证据：静态调用链。代码自身在 [失败兜底说明](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/apimodels/runtime_policy.go:416) 中也说明了孤儿 DRAFT 被后续发布带生效的风险，但当前兜底分支覆盖不全。

### R10 · P1 · 备份恢复的数据范围没有覆盖完整防护关联

位置：[备份表清单](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/backups/tables.go:31)、[范围外外键的处理说明](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/backups/tables.go:55)、[恢复事务](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/restores/service.go:424)、[恢复后检查](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/restores/service.go:599)。

`FULL` 与 `CONFIG_ONLY` 仍使用旧的 21 张表清单，未包含 `application_policies` 以及 JWT、Bot、API 运行时策略、对象关系等 WDSP 表。旧备份设计确实明示该范围；问题在于它没有覆盖当前应用、防护策略所依赖的关联数据，也没有在恢复时保护范围外引用的一致性。

恢复会临时关闭外键触发器，只删除、重插清单中的表。恢复到新库时，未备份的防护绑定和 WDSP 配置无法还原；恢复到已有数据库时，范围外表保留恢复前内容，可能引用已被替换或删除的应用、策略，或与恢复后的配置混用不同时间的数据。重新开启触发器不会在此流程中主动修复这些遗留引用。

当前后置检查主要读取 `users`、`applications`、`system_settings` 的数量，不检查上述关联和防护配置，所以仍可报告恢复成功。本项针对配置与引用完整性，不要求把所有历史访问日志纳入备份。

建议：定义 WDSP 配置恢复所需的完整依赖集合，更新备份清单、恢复拓扑和格式兼容策略；对于部分范围恢复，显式校验和处理范围外引用。成功条件应包含关联完整性及防护配置可重新编译，而不仅是几张核心表可读。

证据：静态；未创建备份或执行数据恢复。

### R11 · P2 · 不同应用、Host 的同名 API 被归入同一资产

位置：[发现资产的唯一键与冲突更新](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/apiassets/store.go:337)、[运行时采集传入应用信息](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/apiruntime/collector.go:691)、[Agent 资产联动](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/agents/machine_http.go:205)。

资产存储把 `method + pathTemplate` 作为全局 `endpoint_key`，没有纳入应用或域名。两个应用存在相同方法、路径模板时，第二次发现进入 `ON CONFLICT`，只累加命中数、时间和置信度，仍沿用首条资产的应用和域名。这使资产归属、流量统计及关联学习数据混在一起。

Agent 联动虽然在批内用 Host 去重，但调用 `UpsertDiscovery` 时没有传递应用、域名或 Host，最终仍进入上述全局唯一键。v2 未绑定来源会被正确留为 `UNASSIGNED`，本问题针对会执行 upsert 的 v1 或已声明绑定的 v2 路径；绑定写入来源记录本身并不能隔离目标资产。

建议：按照资产契约确定包含应用、域名及必要协议维度的稳定身份，统一数据库唯一约束、采集器与消费者，并迁移已有冲突数据；无法确定归属的来源继续待确认，不能默认归入已有同名端点。

证据：静态调用链。已定位资产与来源串并，不据此声称已验证跨应用策略执行或权限绕过。

### R12 · P1 · 明细数量上限提前结束安全检查，后续 BLOCK 不再评估

位置：[文件规则匹配达到上限后退出](/Users/zhanglei/Documents/JiuZhang_WAF/gateway/dynamic_security/detectors/filecomp.go:198)、[文件规则排序](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/guardconfig/file_compliance.go:36)、[字段权限达到上限后返回](/Users/zhanglei/Documents/JiuZhang_WAF/gateway/dynamic_security/detectors/authzcheck.go:225)、[统一决策求值](/Users/zhanglei/Documents/JiuZhang_WAF/gateway/dynamic_security/decision/engine.go:95)。

文件合规每个文件匹配 8 条规则后直接 `break`，而下发规则按方向、匹配类型、取值排序，没有确保阻断规则先于观察规则。因此，文件先匹配 8 条 OBSERVE 文件名规则时，后面的 MIME BLOCK 规则不会执行。该检测器用于上传及下载方向，明细容量限制改变了实际检测覆盖范围。

字段权限也存在同类问题：按 JSON 路径排序后，累计 20 个产生明细的字段便直接 `return`。若前面 20 个字段均匹配已配置的 READ_ONLY 或 SERVER_GENERATED 观察规则，后面的 FORBIDDEN 字段会被跳过。此处需要命中配置中的观察规则，单纯添加任意 20 个未知字段不足以触发。

统一决策按单条 finding 的类别和分数求值，前述观察明细不会仅因总数较多就必然代替被跳过的 BLOCK。因此，在没有其他独立拦截的情况下，本应由后续规则阻断的请求或响应可能被放行。

建议：将“保留多少条事件明细”与“必须完成哪些安全判断”分开；继续评估所有适用规则，保留最高强度处置及有限明细。单纯提高 8 或 20 的上限，只会移动触发边界。

证据：静态推导，未增加请求构造或运行时验证；两处相同根因合并为一项。

### R13 · P1 · 规则查询失败被当作空规则发布，可能移除现有防护

位置：[文件合规读取错误](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/guardconfig/file_compliance.go:63)、[响应脱敏读取错误](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/guardconfig/apiruntime.go:332)、[字段权限读取错误](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/guardconfig/authz_rules.go:124)、[写入完整新配置](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/guardconfig/provider.go:482)、[网关接受空文件规则](/Users/zhanglei/Documents/JiuZhang_WAF/gateway/modules/jiuzhang_guard/module.go:774)。

这些加载器把查询错误记录为 Warn 后返回 `nil`，调用方无法区分“确实没有启用规则”与“读取失败”。新发布生成完整配置，空段意味着没有对应防护，而不是保留网关已加载的旧规则。只要其余发布步骤完成，某个规则表的读取失败就可能把现有文件阻断、响应脱敏或字段权限配置清空。

兼容旧版本尚未建表是代码注释中的设计意图，但当前处理涵盖所有查询错误，包括已经启用防护后的读取失败。这会使一次配置发布把临时读取问题转换为持续的防护缺失。

建议：区分未启用、合法空集合、明确支持的旧格式与读取失败；已启用防护的查询错误应中止候选发布，或在有明确一致性约束的机制中保留上一份有效快照，不能静默用空规则替代。

证据：静态调用链。R01 当前可能先阻断 WDSP 发布；本项是独立的错误处理缺陷，影响前置查询成功或修复 R01 后的发布分支，未声称已在当前基线完成端到端触发。

### R14 · P1 · 字段权限 BLOCK 使用未验签角色，忽略可信角色映射

位置：[直接解析未验签角色](/Users/zhanglei/Documents/JiuZhang_WAF/gateway/dynamic_security/detectors/authzcheck.go:74)、[字段检查读取角色](/Users/zhanglei/Documents/JiuZhang_WAF/gateway/dynamic_security/detectors/authzcheck.go:225)、[角色决定 FORBIDDEN 是否适用](/Users/zhanglei/Documents/JiuZhang_WAF/gateway/dynamic_security/detectors/authzcheck.go:256)、[管线传参](/Users/zhanglei/Documents/JiuZhang_WAF/gateway/dynamic_security/pipeline/pipeline.go:295)、[已验证角色的产生位置](/Users/zhanglei/Documents/JiuZhang_WAF/gateway/dynamic_security/jwtverify/verifier.go:314)。

`ExtractRequestRoles` 明示只解析 JWT payload 中固定的 `role`、`roles`，不验签，角色声明仅应作观察信号。但字段权限检查直接使用它决定角色规则是否适用，并可生成实际 `BLOCK`。该路径没有消费 JWT 信任链已提供、按发行者 `role_claims` 映射得到的 `VerifiedRoles`。

即使启用 JWT PROTECT，也存在合法配置下的漏判：发行者配置 `role_claims=["groups"]`，合法签名令牌在 `groups` 中携带受 FORBIDDEN 规则约束的角色，但没有 `role`、`roles` 时，字段检查得到空角色集，跳过该角色行。问题是可信角色映射未贯通，不需要绕过签名验证。

JWT 信任链未强制验证的路径还会让客户端可改变的声明参与字段强制策略的适用性判断。此处没有认定 JWT PROTECT 会接受伪造签名；影响也区别于 R06、R07 中仅做观察的 AUTHZ-01 决策。

建议：强制字段权限统一消费经过验证、按配置映射的角色；未建立可信身份时明确表达不可判定，并规定对应处置，不能把未验签角色当作授权依据。旧的声明观察能力应保持观察语义。

证据：静态对照角色提取、JWT 验证结果与字段 BLOCK 调用链，未进行安全请求验证。

## 从 Kimi 发现中补入的缺陷

### R15 · P1 · Agent 补传批次大于令牌桶容量时永久无法获准发送

来源：Kimi R-2。位置：[补传预算扣减](/Users/zhanglei/Documents/JiuZhang_WAF/wdsp-agent/internal/agent/agent.go:1106)、[令牌桶容量与 Allow](/Users/zhanglei/Documents/JiuZhang_WAF/wdsp-agent/internal/ratelimit/ratelimit.go:44)。

补传先按缓存整批字节数调用 `Allow(size)`，之后才按 HTTP 发送上限分批；令牌补充始终被限制在 burst 内。当整批 size 大于 burst 时，无论等待多久都不可能满足，原批保留并在下一轮重复失败。大体积 Body 或较低带宽配额均可触发。持续积压还会增加缓存达到容量上限后淘汰数据的风险；不能把“所有含 Body 的批次都必然停滞”作为结论。

建议：按实际发送单元扣减预算，且每个单元必须可被当前预算算法接纳。仅限制为 8 MB 子批仍不足以覆盖 burst 更小的配置；需进一步分片或定义有界的超 burst 发送及偿还规则，同时报告补传停滞。

证据：静态确认 size、burst 与补充上限的关系；本次未执行断网、补传或压力验证。

### R16 · P1 · tap 分帧器复用缓冲区，后续帧覆写已返回的帧

来源：Kimi R-3。位置：[分帧缓冲复用](/Users/zhanglei/Documents/JiuZhang_WAF/wdsp-agent/internal/tapsrc/scan.go:186)。

跨读取块的帧通过 `append(sc.buf, ...)` 组装并放入结果集，随后 `sc.buf = sc.buf[:0]` 保留同一底层数组。同一次扫描中的后续帧或残留片段再次写入缓冲时，可能覆写已经加入结果集的帧，使内容损坏、解析失败或记录丢失。仅断言帧数量的测试覆盖不到内容所有权错误。

建议：在交付帧时转移独占所有权或复制到独立数组；修复检查应比较跨块帧与后续帧的完整内容，不能仅检查数量。

证据：静态确认切片别名和复用路径；未新增采集流量验证。

### R17 · P2 · 应用自动封禁遮蔽全局人工封禁

来源：Kimi R-4。位置：[首条命中返回](/Users/zhanglei/Documents/JiuZhang_WAF/gateway/modules/jiuzhang_guard/temporaryblock/temporaryblock.go:252)、[人工与自动处置分支](/Users/zhanglei/Documents/JiuZhang_WAF/gateway/modules/jiuzhang_guard/module.go:1417)。

`Blocked` 先检查应用条目再检查全局条目。相同 IP 同时存在应用自动封禁与全局人工封禁时，前者先返回，全局人工封禁未参与决策。自动封禁被延后处理，而白名单或 L7 allow 可在此前放行，破坏“人工封禁优先于白名单”的明确约定。

建议：读取时收集适用的应用与全局命中，明确人工封禁优先。删除自动封禁只能辅助清理，不能覆盖本地缓存及并发写回。具体方案约束见 D03。

证据：静态调用链；未发送封禁或绕过请求。

### R18 · P2 · 临时响应状态使最终响应不再被捕获

来源：Kimi R-5。位置：[响应状态捕获](/Users/zhanglei/Documents/JiuZhang_WAF/gateway/modules/jiuzhang_guard/apiresponse.go:99)。

`WriteHeader` 将第一次状态码写入 `c.status`，以后调用全部忽略，未区分 103 等临时响应。上游先发临时状态再发最终 200 时，最终状态被丢弃，缓冲响应还会按错误状态选择处理模式。

建议：临时响应不占用最终状态槽，也不触发最终响应的捕获决策；保留现有 101 协议升级的独立处理。不能笼统改成“所有 1xx 一律同样处理”而破坏升级路径。

证据：静态确认状态锁存路径；未启动上游协议验证。

### R19 · P2 · 发布锁过期及释放竞态破坏发布顺序

来源：Kimi R-6。位置：[锁获取与释放](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/gatewayconfig/publisher.go:324)、[节点下发](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/gatewayconfig/publisher.go:666)。

发布锁固定 120 秒，发布与节点下发可能超过有效期；旧任务尚未完成时新任务可获锁。释放锁又使用分离的 GET、比较、DEL，检查后发生锁过期与重新获取时，旧持有者可能删除新锁。多个任务交叉下发可使管理记录与节点实际配置顺序不一致。

建议：原子校验并释放锁；配置应用过程必须保持有效所有权，并处理所有权丢失与过期任务。节点应用顺序也须受到约束，不能将扇出移出锁或仅在执行前检查一次当作完整修复，见 D04。

证据：静态分析；未进行多节点部署或超时竞态验证。锁问题独立于 R09，不能仅因都涉及发布一致性就合并为同一根因。

### R20 · P2 · 并发首次初始化使内存密钥与数据库分叉

来源：Kimi R-7。位置：[对象引用密钥初始化](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/apiauthz/candidate_sweep.go:77)、[扫描签名密钥初始化](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/apiscan/sign.go:129)。

两个初始化器均先读设置，未读到时各自生成密钥，再通过可覆盖已有值的 `UpsertString` 保存，并直接使用自己生成的值。多进程同时首次初始化时，后写入者覆盖数据库，但先写入进程继续持有另一把密钥。对象引用 HMAC 与扫描签名等依赖因此可能在进程间不一致。

建议：以数据库原子首次创建或受控锁确定唯一获胜值；未创建成功的进程应重新读取并使用已存值，而不是返回自己生成的候选密钥。还应区分读取失败与确实不存在，避免错误时意外轮换。

证据：静态读取与写入调用链；未执行并发初始化或导出任何密钥。

### R21 · P2 · 证书轮换失败后，本地文件与服务端指纹无法一致恢复

来源：Kimi R-8。位置：[轮换文件写入](/Users/zhanglei/Documents/JiuZhang_WAF/wdsp-agent/internal/cert/manager.go:113)、[服务端提交新指纹](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/agents/machine_handler.go:632)、[轮换当前指纹约束](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/agents/store.go:461)。

轮换已写入新私钥、新证书后，若 CA 写入失败，代码只恢复旧私钥，留下旧 key 与新 cert。重启加载时无法组成有效身份。原文“静默降级”需要修正：Agent 加载失败分支已有 Warn 日志。

仅把旧证书也回滚仍不完整：服务端返回新证书前已经提交新指纹；旧证书只在宽限期内可用，再轮换时又不满足“当前生效指纹”条件。局部文件回滚可能把立即故障变成宽限期结束后的故障。

建议：将新身份持久化、服务端状态推进与失败恢复作为同一流程设计；需要能够恢复已签发的新身份或协调状态，而不是只回滚文件。复用旧 CA 也须满足其能验证新证书的前提。见 D05。

证据：静态对照客户端和服务端状态；未轮换或注册真实 Agent。

### R22 · P2 · AI 供应商地址变更可将已有密钥发往其他目标

来源：Kimi R-10。位置：[供应商地址与更新处理](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/aihandlers/models_handler.go:136)、[请求构造](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/aimodel/client.go:136)。

供应商 BaseURL 缺乏目的地址限制，请求客户端会向该地址附加解密后的 Bearer 密钥。持有 `ai.models.manage` 权限的调用者可修改已有供应商地址并保留原密钥引用，后续模型调用可能将该密钥发送到新的主机，或访问不应开放的内部端点。此处涉及已授权管理能力的边界，不是未认证请求直接获得密钥。

建议：明确配置地址权限与使用既有密钥的边界，绑定密钥允许的目的主机，检查 scheme、解析结果、拨号与重定向。产品已支持 ollama/local，私网接入应使用受控允许清单，不能全面禁用，见 D06。

证据：静态对照更新逻辑与客户端；未请求任何内部地址或外发密钥。

### R23 · P2 · 解压超限后丢失截断标记

来源：Kimi R-12。位置：[解压长度限制](/Users/zhanglei/Documents/JiuZhang_WAF/wdsp-agent/internal/httpsensor/body.go:139)。

解压器读取 `max+1` 字节以判断超限，随后截为 `max`，但返回值不带超限信号。调用方无法区分完整内容与被解压上限截断的内容，可能输出 `body_truncated=false`，使下游采集、分析或取证误把残缺内容当作完整 Body。

建议：将截断事实作为明确返回值传递，并与原始采集阶段的截断状态合并。保留现有内存上限，不能通过取消限制解决标记丢失。

证据：静态数据流；未构造压缩载荷验证。

## 修复方案审查意见（不重复计入缺陷数）

以下 7 项是对 Kimi 修复计划的修订约束，均已合入相应建议或待办；它们不是 7 个已修复的问题。

| 编号 | 优先级 | 原文位置 / 对应条目 | 合并后的修订要求 |
| --- | --- | --- | --- |
| D01 | P1 | [Kimi #1](/Users/zhanglei/Documents/JiuZhang_WAF/docs/tasks/wdsp-p1/PRODUCT_FINDINGS_FIX_PLAN.md:25) / R09 | FAILED 结算必须覆盖 FORMAL 模型和端点指针的发布一致性；VALIDATED 仍可被后续发布激活，不能视为无害。 |
| D02 | P1 | [Kimi #8](/Users/zhanglei/Documents/JiuZhang_WAF/docs/tasks/wdsp-p1/PRODUCT_FINDINGS_FIX_PLAN.md:72) / I04 | 生效的学习结果不能直接排除在证据绑定之外。冻结回归与发布共用的候选快照；独立版本必须同时绑定版本及内容哈希。 |
| D03 | P1 | [Kimi R-4](/Users/zhanglei/Documents/JiuZhang_WAF/docs/tasks/wdsp-p1/PRODUCT_FINDINGS_FIX_PLAN.md:143) / R17 | 读取时落实人工封禁优先；HDel 无法保证本地缓存和并发自动条目消失。 |
| D04 | P1 | [Kimi R-6](/Users/zhanglei/Documents/JiuZhang_WAF/docs/tasks/wdsp-p1/PRODUCT_FINDINGS_FIX_PLAN.md:147) / R19 | 原子解锁、有效所有权与实际配置应用顺序必须一起解决；扇出移出锁、执行前单次 fencing 均不构成完整修复。 |
| D05 | P2 | [Kimi R-8](/Users/zhanglei/Documents/JiuZhang_WAF/docs/tasks/wdsp-p1/PRODUCT_FINDINGS_FIX_PLAN.md:151) / R21 | 同时考虑服务端已经推进的证书指纹；回滚旧钥证不能作为跨端恢复成功条件。“静默降级”改为“有 Warn 日志的降级”。 |
| D06 | P2 | [Kimi R-10](/Users/zhanglei/Documents/JiuZhang_WAF/docs/tasks/wdsp-p1/PRODUCT_FINDINGS_FIX_PLAN.md:155) / R22 | 对 ollama/local 等受控内网端点提供明确允许机制，同时限制元数据等敏感目标与密钥外发；禁止一刀切封禁全部私网。 |
| D07 | P2 | [Kimi R-11](/Users/zhanglei/Documents/JiuZhang_WAF/docs/tasks/wdsp-p1/PRODUCT_FINDINGS_FIX_PLAN.md:157) / I11 | 保留 IP 总限速；如需账户维度，叠加独立限制。IP+用户名替换 IP 总桶会允许切换用户名放大请求额度。未使用辅助函数不等于登录链已经存在该漏洞。 |

D02 的代码依据：[学习结果装配](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/guardconfig/response_baselines.go:44) 读取会生效的学习基线；[配置生成与哈希](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/gatewayconfig/generator.go:154) 和 [发布门禁](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/gatewayconfig/publisher.go:493) 将回归证据绑定到实际候选内容。单独增加学习版本号但不纳入证据关联，无法保留这条约束。

D07 的代码依据：[未接线的辅助函数](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/middleware/ratelimit.go:93)、[实际登录限速装配](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/app/app.go:890)、[账户失败锁定](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/auth/service.go:211)。现有链路具备 IP 总限速与账户锁定，不能将辅助函数名称与实现不符直接等同于这些防护缺失。

## 来源映射与去重

下表覆盖 Kimi 全部 #1～#13 和 R-1～R-12。低危原文按领域另列 L01～L31，避免原文 R-L / R-C 命名不一致造成遗漏。

| Kimi 来源编号 | 合并位置 | 处理结论 |
| --- | --- | --- |
| #1 | R09、D01 | 与原 Codex 发现重复，补充模型与策略状态一致性要求 |
| #2 | R04 | 与原 Codex 发现重复；需要实际进入地域查询才触发，不能写成每周期必然 panic |
| #3 | R03 | 与原 Codex 发现重复；确认转义改变匹配语义，不泛化为所有带反斜杠正则全部不命中 |
| #4 | R08 | 与原 Codex 发现重复；恢复门禁针对实际下发的候选执行 |
| #5 | I01 | 恢复快照与数据库期望状态的产品决策 |
| #6 | I02 | 公钥登记管理能力待核对与设计 |
| #7 | I03 | 偶发命中的根因未确认 |
| #8 | I04、D02 | 学习快照与回归证据绑定设计 |
| #9 | I05 | XML 检测能力边界，未接受为新实现任务 |
| #10 | I06 | 可信关联键设计，默认防伪语义保留 |
| #11 | I07 | EDGE client_ip 归属问题待核对 |
| #12 | I08 | CRS 相位中断行为文档化 |
| #13 | I09 | OBSERVE Bot offer 事件口径文档化 |
| R-1 | I10 | JWT 路径规范化存在条件风险，源站路由触发条件未确认 |
| R-2 | R15 | 补传预算停滞，静态确认 |
| R-3 | R16 | 分帧切片别名，静态确认 |
| R-4 | R17、D03 | 人工封禁优先级缺陷；修法已纠正 |
| R-5 | R18 | 临时响应状态处理缺陷，静态确认 |
| R-6 | R19、D04 | 发布锁竞态；修法已纠正 |
| R-7 | R20 | 密钥并发初始化缺陷，静态确认 |
| R-8 | R21、D05 | 钥证与服务端指纹一致性缺陷；修法已纠正 |
| R-9 | I12 | 内存预算风险保留，实际峰值与 OOM 时序未确认 |
| R-10 | R22、D06 | 地址与密钥目的地边界缺陷；修法已纠正 |
| R-11 | I11、D07 | 限速辅助函数维护与增强项，不作为已确认登录漏洞 |
| R-12 | R23 | 解压截断信号丢失，静态确认 |

## 调查、设计与文档台账

以下事项保留为后续工作背景，本轮只合并材料，不执行调查脚本、攻击请求或功能开发。表内“待核对”可通过代码、已有日志和契约分析推进，不以新增安全验证为完成本次审查的前提。

| 编号 | 来源 | 当前状态 | 保留内容与后续边界 |
| --- | --- | --- | --- |
| I01 | #5 | 待设计 | GuardOverride 恢复线上配置不一定恢复 DB 规则本体。需区分快照恢复与持久期望状态，先设计差异/残留可见性；不能默认删除或禁用数据库规则。 |
| I02 | #6 | 待核对 / 能力建议 | Kimi 报告受信回归公钥缺少管理 API；核对现有管理入口及权限后再定最小接口。不能在合并文档时新增接口路径、权限码或执行密钥登记。 |
| I03 | #7 | 待调查 | CUSTOM_PACK 1001012 的偶发命中来自原演练记录，根因未定位；不推断为 Coraza 竞态或上游 bug。 |
| I04 | #8 | 待设计 | 学习写入导致候选变化的现象按来源保留；方案受 D02 约束，需要冻结候选或绑定学习版本，而不是弱化证据指纹。 |
| I05 | #9 | 能力边界待明确 | XML Body 处理及 XXE 覆盖缺口按原材料记录；区分未支持能力与既有承诺，短期文档化、实现另行决策。 |
| I06 | #10 | 产品设计 / 文档 | 默认覆盖不可信 X-Request-Id 有防伪目的。明确响应关联键及可信来源条件，不能直接恢复任意客户端透传。 |
| I07 | #11 | 待调查 | EDGE client_ip 为相同值不能单独证明代码硬编码；需核对真实 IP 链、来源数据及脱敏口径，原值不再复制进本报告。 |
| I08 | #12 | 文档待办 | 说明 CRS 已中断相位时后续自定义规则不继续执行的边界，不记作独立引擎漏洞。 |
| I09 | #13 | 文档待办 | 明确 BOT_CHALLENGE_OFFERED / OBSERVE 是流程记录及其统计分母口径，不重复登记 R2-7。 |
| I10 | R-1 | 条件风险待核对 | 原始路径与 selector 要求的规范路径可能不一致；是否形成保护绕过依赖源站归一化与路由等价性。先统一策略与实际路由契约，避免盲目清洗改变业务路径；未证明源站等价路径前不标为已复现绕过。 |
| I11 | R-11 | 维护 / 增强建议 | IPAndUsernameKey 无调用且名称与实现不符；当前登录使用 IP 总限速并有账户锁定。可清理死代码或叠加账户限速，不替换 IP 总桶。 |
| I12 | R-9 | 静态资源风险，影响边界待核对 | 待配对 Body 缺少统一字节预算的风险保留；连接上限与单连接限额相乘仅为上界估算，不是实测 RSS，不沿用“秒级 OOM”结论。 |
| I13 | B3 counters 关联风险 | 待调查 | botchallenge 中数字串处理按原记录已修；temporaryblock/ratelimit/riskengine 等 Lua 数字字段消费者需分别核对，不能从一个修复推断其他消费者均有缺陷。 |

原计划关闭项保留其来源状态：R2-6 CRS 族映射为“来源记录已修”，本轮未独立重验；R2-7 合并 I09；B3 本体为“来源记录已修”，其残留排查为 I13。上述状态不扩大为“全仓同类问题已修复”。

## Kimi 低危来源子项台账

原清单有 6 个领域、31 个分号分隔子项，并非 13 个一致定义的低危组。本表完整保留待办与复核意见；未逐项确认的影响和原始低危评级不作为本报告确认结论。L 编号只用于追踪来源，不与主清单重复汇总。

| 编号 | 领域 / 原文线索 | 状态与合并口径 |
| --- | --- | --- |
| L01 | 网关：响应相位 Decide 未传 Exceptions | 演进风险；需先确认当前是否存在需要例外的响应检测器，不能以未来注册表扩展当作当前确定缺陷。 |
| L02 | 网关：uri_prefix 尾斜杠 | 修正文案：`/api/` 可以匹配完全相同的路径，但子路径匹配口径异常；不能称“永不命中”。保留配置归一化核对项。 |
| L03 | 网关：engineFingerprint 缺 temp_block_poll_interval | 原文待核；需确认字段变更与引擎复用关系及实际影响。 |
| L04 | 网关：OBSERVE reChallenge 分支无事件 | 原文待核；先对齐事件契约及应记录条件。 |
| L05 | 网关：FAIL_CLOSED / 合规抑制保留上游响应头 | 原文待核；区分 Body 扣留和头部契约，核对具体残留头，不直接泛化为敏感内容泄露。 |
| L06 | eventparser：查询串脱敏不处理编码参数名 | 原文待核；按实际解码及匹配链确认覆盖范围。 |
| L07 | eventparser：审计时间错误回退当前时间 | 原文待核；保留时间真实性与错误可见性问题。 |
| L08 | eventparser：maskMatchedData 先遮蔽后截断 | 资源风险待核；不把复杂度风险当作已测 CPU 放大结论。 |
| L09 | 认证：CSRF 字符串比较非常量时间 | 纵深改进建议；仅凭比较方式不足以证明实际可利用的时间侧信道。 |
| L10 | 认证：登录无 Origin 校验 | 原文待核；结合 SameSite、登录 CSRF 与现有认证流程判断，不能只以缺少单项检查定漏洞。 |
| L11 | 会话：注销后 CSRF 键保留至 TTL | 原文待核；区分缓存清理与会话是否仍有效。 |
| L12 | 认证：停用/锁定和密码错误返回不同状态 | 原文待核；保留账号状态枚举与产品提示的边界问题。 |
| L13 | 认证：同时间步 TOTP 可重复使用 | 原文待核 / 增强建议；需明确消费语义与适用操作。 |
| L14 | 认证：ErrPasswordReused 被密码过期路径复用 | 错误语义待核，不能直接计为认证绕过。 |
| L15 | 审计：queryInt 溢出处理 | 原文待核；需确认参数输入、整数转换和下游限制。 |
| L16 | 设置：bot_signing_keys 未在 SensitiveSettingKeys | 敏感标记完整性待核。值本身为加密存储，List 还受行级敏感标记影响；不能据此宣称明文签名密钥暴露。 |
| L17 | 例外规则：Create 两段写入非事务 | 原文待核；保留失败后半成品与重复重试的一致性问题。 |
| L18 | 部署：stage5 可信代理默认网段宽 | stage5 配置边界待核；原文要求核实正式离线包的部分明确暂缓，不能把正式环境推测记作已确认问题。 |
| L19 | Agent：mirror 连接信号量未挂 ConnState | 原文待核；需确认信号量获取、释放和连接生命周期。 |
| L20 | Agent：补传反序列化失败跳过且不计数 | 原文待核；与 R15 的预算停滞根因不同，保留坏记录处置及可见性问题。 |
| L21 | Agent：flows 未尊重 429 / Retry-After | 原文待核；核对实际退避及服务端限流协议。 |
| L22 | Agent：enroll token 命令行输入 | 凭据输入方式改进；暴露范围依赖操作系统进程可见性，不输出或收集真实 token。 |
| L23 | Agent：buffer 目录未跟随 state-dir | 原文待核；保留自定义路径与持久缓存配置一致性问题。 |
| L24 | Agent：4 MB 响应截断无明确错误 | 原文待核；需区分传输层截断和解码器已有错误传播。 |
| L25 | Agent：expiredWarned 轮换后未重置 | 原文待核；属于状态与告警恢复问题。 |
| L26 | Agent：v2 补传未协商时分账错误 | 原文待核；核对协议协商、降级与记账路径。 |
| L27 | web：ApmTraceDrawer 空列表白屏 | 当前未确认。后端已初始化 `access_logs`、`security_events`、`otel_spans` 为 `[]`，前端也对 otel_spans 兜底；缺少其余前端兜底可列健壮性建议。 |
| L28 | web：OFF/OBSERVE 下门禁“不可用”提示 | 文案与模式表达建议，需按实际模式说明是否阻断发布。 |
| L29 | web：Date.parse NaN 无兜底 | 原文待核；需定位具体调用点及可能的非法输入，不能全仓泛化。 |
| L30 | web：trace 路径参数未编码 | 健壮性建议；后端 trace ID 有固定十六进制格式约束，当前未找到合法 ID 造成路径混淆的链路。 |
| L31 | web：eddt-head-tmp.tsx 空临时文件 | 清理建议；不作为功能或安全漏洞。 |

L27 复核依据：[后端 Trace 空集合初始化](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/apm/store.go:972)、[前端读取](/Users/zhanglei/Documents/JiuZhang_WAF/web/src/components/ApmTraceDrawer.tsx:100)。若以后发现其他路径会返回 null，应另补入口与数据契约证据后重新定性。

## 修复组织与工作量校正

建议先处理主清单中 P1 缺陷，再按共享模块组织 P2 修复。发布与恢复可合并审阅 R01/R08/R09/R13/R19，但各自根因和关闭证据独立保留；Agent 相关 R15/R16/R21/R23 可按模块分别实施。I04 的候选快照设计应与门禁修复一起评审，避免以绕开指纹约束解决可用性问题。调查、能力扩展及 L 清单不自动扩入代码修复范围。

| 来源估算 | 原文估算 | 合并后解释 |
| --- | --- | --- |
| F1～F4 | 10～11 天 | 仅是原 13 条及关联排查的估计，F3 部分实现另估；#1～#4 与本报告已有问题重复。 |
| Kimi R-1～R-12 | 明列工作量合计约 9 天 | 原工作量汇总漏算。该数包含待调查/增强项，尚未按本报告修订的方案重新估算。 |
| 上述两部分的同口径小计 | 约 19～20 人日 | 是原计划算术补全，不是本次合并后的承诺工期，更不是可直接换算的日历天数。 |
| 原 Codex 独有的 10 项、低危台账及未定实现 | 未完整估算 | 不包含在上面的小计中；去重、明确范围和修法后才能估算整个合并清单。 |

Kimi 原文的“25 项（高 3 / 中 9 / 低 13 组）”混合了条目与分组，不能与本报告 23 项直接相加。统一统计使用 R01～R23 主清单；D/I/L 台账分别统计，不将方案意见、重复发现和待调查风险凑成漏洞总数。

本轮实际修复按主清单逐项保留根因、最小差异和行为测试；版本关闭证据统一归入 1.1.5 发布提交。原计划中的正式环境复演仍不在本轮范围内。

## 检查记录与边界

主清单中 5 项附有此前本地局部检查结果（R02、R03、R04、R06、R07），其余 18 项依据源码、迁移和调用链分析。局部探针中用于暴露缺陷的失败，与常规测试套件结果分开记录；用户要求安全问题只发现之后，未再运行这些探针。

Kimi 文档自述“六域 go vet / go test -race 全绿”，但未在对应条目列齐提交、命令与日志关联；本次未将该自述改写为 Codex 已验证结果，也不以常规测试通过证明缺陷是否存在。下表保留 Codex 原审查的实际记录，二者不互相覆盖。

已完成的常规检查结果如下，本次未重复执行：

| 检查 | 结果 | 原始日志 |
| --- | --- | --- |
| 动态防护 Go 测试 | 通过 | [dynamic 日志](/tmp/wdsp-review-dynamic-tests-unrestricted.log) |
| 网关 guard Go 测试 | 通过 | [guard 日志](/tmp/wdsp-review-guard-tests-unrestricted.log) |
| 管理后端 Go 测试 | `TestWorkerUnresolvableHostFails` 失败；环境将无效域名解析为 IP，实际错误与“域名无法解析”的断言不同，未作为漏洞列入 | [server 日志](/tmp/wdsp-review-server-tests-unrestricted.log) |
| 前端类型检查 | 退出码 0 | [typecheck 日志](/tmp/wdsp-review-20260910/web-typecheck.log) |
| 前端测试 | 113 个文件、859 项测试通过 | [web 测试日志](/tmp/wdsp-review-20260910/web-tests.log) |

已有测试通过不否定上述缺陷，也不能作为全部安全路径已覆盖的结论。未对本报告执行正式环境部署、实际配置回滚、数据库恢复或外部攻击验证。

对象模型激活流程中仍有需要进一步确认的设计边界，暂未作为确定缺陷计数；AUTHZ-01 明确暂缓的 PROTECT、复杂共享关系、部分协议对象提取能力也未仅因尚未实现就列为 bug。

## 1.1.5 修复复核

R01～R23 均已完成代码修复。R22 采用已确认的产品规则：AI Provider 持久化绑定规范化目标源与目标白名单；目标源变化时在事务内清除原密钥，必须重新录入；连接前执行受限目标校验、DNS 解析检查和拨号地址复检。相关 OpenAPI 和管理端提示同步更新。

本地复核结果：Server 全量 Go 测试、`jiuzhang_guard` 全量 Go 测试、`dynamic_security` 全量 Go 测试、WDSP Agent 全量 Go 测试均通过；Web 目标回归 7 个文件、72 项测试通过，类型检查、lint 与生产构建通过。Web 首次全量回归通过 117/118 个文件、886/891 项测试，5 项失败均由 Node 暴露的不完整实验性 `localStorage` 导致；增加测试环境兼容实现后，相关 `SmartTable` 用例和本轮目标回归均通过。受当前主机高负载影响，后续串行全量复跑触发了旧用例内显式 20 秒超时，因此不记为全量全绿证据。按用户要求未执行攻击探针，也未执行正式环境、跨主机或专用硬件验证。

Kimi 来源文档与工作区中的其他并行开发改动继续保留，本次提交只收录 R01～R23、相关前端配套、文档和版本文件。最终关闭证据为 1.1.5 发布提交及标签 `wdsp-v1.1.5`。
