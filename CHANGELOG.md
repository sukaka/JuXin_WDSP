# 变更日志

本文档遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 规范。

## [Unreleased]

## [1.5.0] - 2026-11-17

### 新增

- **复杂对象授权关系**：支持 `OWNER` 与 `SHARED_WITH` 的 `ANY_OF` 组合关系，贯通授权向导、快照发布、网关决策、能力门和回滚校验，并补充共享关系迁移与接口回归。
- **身份风险挑战**：风险策略新增 CHALLENGE 处置，由 Bot 步骤消费请求内待挑战事实；OBSERVE 不实断，只有实际返回挑战页才记录 `challenged`，发布能力门阻止旧网关误载。
- **数据流证据与内外网边界**：补充运行时事件 Trace 关联和降级表达，按独立业务系统展示 API 调用与敏感字段；外网到内网依据地址范围和客户端来源证据展示，证据不足时明确标记边界未知。

### 修复与加固

- **Caddy 低端口监听**：新增可审计启动降权器，最终 Caddy 以 UID/GID 1000 运行，仅保留 ambient `NET_BIND_SERVICE`；Compose 保持 `cap_drop=ALL` 与 `no-new-privileges`，支持现场阈值 1024 下直接监听 82 端口。
- **发布流量验证**：改用独立精确端点 `/_wdsp/internal/v1/publish-smoke`，每次发布生成独立 HMAC 并绑定站点、发布 ID、nonce 和时效，不再依赖 Bot 墓碑；普通源站 404、错误 Host 和无效签名继续失败回滚。
- **升级与回滚**：完整包升级支持显式 `--new-compose-file`，旧镜像回滚使用一次性 legacy 配置；gateway 与 netmgrd 同次重建，镜像与 Compose 启动契约不符时在 retag 前拒绝。

### 交付与验证

- 完整运行包纳入 containerops 镜像，正式模式强制 Ed25519 签名、内容扫描、哈希与 RPM 校验；development 包必须显式声明，不能用于生产。
- 真实 Caddy、Publisher、PostgreSQL 与源站链路验证 Bot 未配置/RELEASED 发布成功、探针不进源站、异常回滚和不可达降级；低端口测试在隔离网络命名空间固定阈值 1024，并复现旧镜像权限失败。
- 兆芯 openEuler 实机的首次安装、1.3.0 升级/回滚、systemd、firewalld 与生产性能仍须在现场验收，不以 macOS 容器结果替代。
- 全仓回归中，未修改的 `gateway/tproxyd` `TestRelayActivityRenewsIdleTimeout`、`gateway/modules/jiuzhang_guard/behaviorstore` 真实 Valkey 集成用例（EOF/计数不符）与 `server/internal/apifiles` `TestFileAssetLineage` 仍失败，需独立修复；不将全仓测试结果记为全绿，本次变更相关包测试另行逐项验收。

## [1.4.0] - 2026-11-16

### 新增与修复

- **云 API 观测与数据流**：新增 Kafka 事件总线、Observation Receiver、Java 本地采集和 ClickHouse 投影；远程观测不传输原始 Body，并修正跨批次、多实例配对、重复调用复用及节点平均耗时口径。
- **数据流拓扑**：提供系统间 API 调用与敏感字段轨道、应用与实例视图、条件筛选、上下游下钻、自适应画布及全屏；优化轨道配色、文字可读性和流动方向表达。
- **API 资产与规范治理**：新增应用资产价值、响应 Schema、专项报告调度、参数格式候选和用途分类；规范审计覆盖路径参数、响应声明及鉴权配置，支持防公式注入的 CSV 导出。
- **业务弱点与接口组**：新增凭据传输、服务器信息泄露、对象枚举、流程偏离等检测及整改复测；新增接口组管理和凭据、可信租户、动作、接口组限速，支持 RATE_LIMIT、BLOCK、TEMP_BLOCK 处置。
- **应用风险与群控观察**：支持按应用覆盖风险策略、同设备多账号观察、趋势与主体明细；群控信号只观测，不直接触发封禁。
- **文件与数据安全**：覆盖文本、JSON、XML 和 DOCX/XLSX/PPTX 敏感识别、文件魔数检查、OOXML 签名与恢复、内容指纹关联、身份筛选和内联 HTML 溯源水印。
- **响应安全深化**：支持 JSON/XML/text/SSE 值级敏感观测、响应采样、gzip/br 有界解压与重编码、AES-256-GCM ENCRYPT、HMAC MAP 及授权恢复；事件不保留敏感原值或密钥。
- **身份手工封禁与解封**：新增管理 API、独立权限、审计、发布与回滚及前端操作；网关在保护地址与白名单之前按身份键执行 403，重复操作幂等，事件不携带身份键或凭据。
- **漏洞情报提醒**：新增 PHP 场景的 NVD 同步与 JSON 导入、订阅聚合提醒和应用技术栈手动映射；当前仅提醒，不自动生成阻断规则或虚拟补丁。
- **AI 安全与运营**：归档当前 API 安全 Agent、运营反馈与连续失败熔断，以及大模型输入输出策略、Prompt 注入、内容、PII 和 Token 声明预算检测实现；事件证据不保留 Prompt 原文。
- **工程与部署**：补充容器运维通道、数据库兼容性、Kafka/ClickHouse 部署、第三方许可证及 SBOM；修复事件测试异步落盘读取竞态。

### 已知验证边界

- 本批后端目标包、网关动态安全、Guard 完整回归、前端 1301 项测试、前端生产构建和 OpenAPI 双向对账通过；身份封禁相关两项 PostgreSQL/Valkey 实库集成测试因未配置凭据而跳过。
- 真实 Caddy 反代下的压缩响应与长连接 SSE、登录态浏览器、跨进程/多节点发布和性能尚未完成整体验收；SSE 流式脱敏、压缩 SSE、deflate、多重编码和二进制深检仍有限制。
- 本版本未形成正式吞吐、P95、资源占用、72 小时稳定性或生产容量证明，不宣称海量数据实时处理、集群高可用或生产部署验收完成。
- Brotli v1.3.0 已锁版并登记；全量许可证审计仍有既有的 `licenses/yaml` 未登记项。

## [1.3.0] - 2026-10-09

### 新增

- 新增机器身份（HTTP Message Signatures，NG-ID G1：RFC 9421+9530+8941 接入侧机器身份验证，S7 阶段；冻结设计 `docs/nextgen/NG-ID-g1-machine-identity.md`（实现状态 §7 同文件），出口记录 `docs/nextgen/s7/S7-EXIT-SUMMARY.md`）：**登记模型**（迁移 000183/000184 四表——身份/键（ACTIVE/RETIRED/REVOKED 状态机+轮换重叠窗口+revoked_seq 溯源）/绑定（应用×路径前缀×OBSERVE 缺省|PROTECT×proof_required）/撤销水位单行（只增不回退））；**管理面**（`apimachineid` 12 端点——身份 CRUD+公钥静态离线导入（唯一来源，keyid URL 形态不抓取，热路径零网络 IO）+轮换/撤销+绑定 CRUD；权限复用 jwt_trust.read/manage 零新增；写操作 HIGH 审计；principal_binding 与 jwt_trust VERIFIED 主体一致性强校验（发布边界指纹域换算——裁决 3））；**网关验证链**（`httpsig` 纯库（零第三方依赖，RFC 9421 附录 B 黄金样本+fuzz）+`detectors/machineid` 十步固定序（解析→keyid→算法→键状态→时效→覆盖成分→目标绑定→体摘要→验签→重放）+范围核对；算法词表 ed25519/ecdsa-p256-sha256/rsa-pss-sha512（排除 hmac 与 rsa-v1_5）；逐步冻结 reason 词表）；**重放防护**（Valkey Lua SET NX PX 单次原子往返（`mid:v1:nonce:` hash tag 同槽），存储缺席 OBSERVE 放行披露/PROTECT 503 fail-closed，严禁本机去重——双节点共享 Valkey 重放矩阵实证无一放行两次）；**轮换/撤销水位**（rotate 原子新旧键重叠窗口、revoke 与全局水位 seq+1 同事务、快照水位低于已应用水位网关拒载 `MID_WATERMARK_REGRESSION` fail-closed——普通回滚不复活已撤销键）；**防护协同**（VERIFIED 不豁免 WAF/CC/Bot/授权——SQLi 照拦、CC 429 照判、未豁免机器 Bot 挑战照走；Bot 豁免=身份 exempt∩绑定命中∩验证通过三重显式（MID_BOT_EXEMPT 事件））；**UNKNOWN 红线**（登记册/存储/体验证器异常全五态如实+`id.coverage_v1` 覆盖账本双承载，OBSERVE 放行披露/PROTECT 503·413 不伪装证明错误；401 固定短语不带 WWW-Authenticate 不冒用未注册方案）；**能力门**（网关自报恒报 detectors.machineid=mid/1，任一 PROTECT 绑定 required mid/1 fail-closed（CAP_MISSING），全 OBSERVE 零需求滚动升级——stage5 三态实证）；OpenAPI +12 → 727 双向零差集。stage5 参照客户端（`test/waf/mid-e2e/`，Go stdlib 三算法签名器零依赖）对测 I01~I05 全过（三算法/篡改矩阵/多标签/覆盖不足/时效/未登记键/DISABLED/算法不符/principal_binding 绑定与独立成立/双节点重放/Valkey 故障注入/撤销轮换回滚水位/WAF·CC·Bot 不绕过与三重豁免）；C01 无绑定应用零行为、C04 白名单跳过 CC 不绕过机器身份、C09 越权未认证 401+AUDIT_ADMIN 写 403；回归 40/40、13/13 不回退。**联调修正两处跨轨对齐**（设计 §7.3 登记）：principal_binding 发布域换算（server）与重放 Lua 返回值形态数组化（gateway）；RETIRED 窗口事件无 RETIRED 标注等遗留如实登记。
- 新增 MCP 工具调用安全首期（NG-MCP G1：远程 HTTP MCP（Streamable HTTP）tools/call 转发前检查+结果检查+目录资产与审核态，S6 阶段；冻结设计 `docs/nextgen/NG-MCP-g1-toolcall.md`（实现状态 §7 同文件），出口记录 `docs/nextgen/s6/S6-EXIT-SUMMARY.md`）：**绑定驱动识别**（应用×endpoint_path 精确匹配+POST+JSON 族内容确认，绑定缺失零行为 NG-T-C01；批处理数组/解析失败/非 tools/call 均 OBSERVE+SKIPPED 放行不误断）；**目录资产**（迁移 000181/000182 三表——目录（服务身份维度）/工具行（tool_hash=五元组（名/版本/规范化描述/双 Schema）域分隔 sha256 审批绑定不可变摘要，同名任何变更重算+重置 PENDING_REVIEW（旧审批不继承 NG-T-M02））/绑定（OBSERVE 缺省|PROTECT）；catalog_hash=排序拼接 APPROVED 摘要的 sha256 发布集摘要，网关装配期重算比对不符整目录拒装不误断）；**转发前检查链**（`detectors/mcpguard` 固定序：可信主体（仅 JWT VERIFIED 信号）→目录白名单（仅 APPROVED 下发）→Schema 冻结子集（全量解析不经 256 字符截留，未知字段缺省关闭世界）+绑定端点重复键升级违规+结构预算（深度 32/对象 2048/数组 4096/串 512KiB/值 65536/消息 4MiB）→路径/域名范围→调用预算→高风险默认拒绝（HIGH 或 approval_required；审批闭环后续子阶段 M07 NOT_APPLICABLE 不冒充）；违规双闸（绑定 PROTECT×引擎 PROTECT）定案，证据只落工具名/规则/字段路径/类型/长度不落原值）；**认证授权分离**（401+规范 Bearer challenge=JWT 信任链既有通道（受众不匹配），403=mcpguard 目录 ACL（allowed_principals/roles/tenants 逐维 AND），状态码/响应形态/事件通道三重区分；提示词伪造管理员文本不改变身份权限（NG-T-M06））；**结果检查与流式边界**（非流式 JSON 全检（output_schema+值级敏感规则复用同一编译产物 location=json，PROTECT 未外发前抑制 -32014 零字节泄漏）；SSE 逐逻辑消息即检即放不整流缓冲，违规则该条不发+中止上游+断连+`mcp.result_blocked_midstream`（disclosed_bytes/messages_forwarded 与实际一致——首条正常第二条违规不得报告「整个调用通过」，final_action 按实修正 BLOCK））；**协议化执行**（JSON-RPC 2.0 错误对象 committed 直写，id 回显+固定短语防探测+data.source/request_id 归因，产品扩展段注册 -32010~-32014 不冒用标准码，HTTP 403/413/429 分明）；**覆盖账本**（每候选请求 `mcp.coverage_v1` 双承载五态+新增 reason COV_NOT_MCP/COV_NO_CATALOG/COV_NO_TRUSTED_SUBJECT，观测永不贡献攻击分）；**管理面**（10 端点（目录 CRUD+审核+绑定 CRUD），迁移 000181/000182，权限复用 api_spec.read/manage 零新增，写操作 HIGH 审计，绑定变更触发整站发布，PROTECT 绑定未被 jwt_trust 覆盖发布校验警示（非阻断）；OpenAPI +10 → 715 双向零差集）；**能力门**（自报恒报 protocols.mcp=acl_v1+detectors.mcp.toolcall=mcp/2，含任一 PROTECT 绑定 required 两键 fail-closed（mcp/1 旧节点 CAP_MISSING 双列），全 OBSERVE 零需求滚动升级——stage5 三态实证）。stage5 官方 Go SDK（modelcontextprotocol/go-sdk v1.8.0，Apache-2.0/MIT）对测：mcp-testorigin 四件套（echo 带 origin_mark/敏感返回合成秘密值/SSE 首条正常次条敏感/高风险带调用计数器）经 M01~M06 全过（未授权 -32011+计数器=0 与受众错误 401 三重区分/同名变更旧审批不继承/嵌套·重复键·超长逐条 413/-32012 与 300KiB 尾部违规全量解析命中/非流式 -32014 未外发前阻断+SSE 首条实收次条不外发/扩展方法放行不判攻击/伪造管理员文本仍按 ACL 403）；回归 40/40、13/13 不回退。**联调修正三处**（设计 §7.3 登记）：catalog_hash 分隔符跨轨对齐（server 对齐网关 "" 拼接）；SSE 中途阻断 flush 缺失致首条未真实外发+Caddy 反代 ErrAbortHandler 恐慌吞事件（新增 proxyWithMCPSSEGuard 折算）+final_action 按实修正 BLOCK；ACL 插位「白名单后 Schema 前」经编排者裁决登记。
- 新增 gRPC G1 unary 有界深度检测（NG-GRPC-01~03，S5 阶段关闭；冻结设计 `docs/nextgen/NG-GRPC-g1-unary.md`，实现状态 §7 同文件，出口记录 `docs/nextgen/s5/S5-EXIT-SUMMARY.md`）：**帧读取**（`parser/grpcframe` 流式重组（跨 h2 DATA 分片）+四重预算（单消息 4MiB/64 消息/16MiB 合计/64MiB 全局）+先验证声明长度再分配+错误三分类）；**有界解压**（gzip 唯一批准算法，压缩 4MiB/解压 16MiB/倍率/CPU 四重预算读断不无限解压，未知算法协议化 UNIMPLEMENTED(12)）；**结构深检**（`detectors/grpcguard`——描述符 dynamicpb 解码后嵌套 ≤8/repeated·map ≤1024/string·bytes ≤256KiB/枚举值域/未知字段容许计数，证据=规则+路径+读取量不落值，缺描述符 SKIPPED(no_descriptor) 不误断、streaming 识别即降级 SKIPPED(streaming_degraded) 不冒充）；**协议化执行**（违规实断=trailers-only 响应（HTTP 200+grpc-status/grpc-message 固定短语防探测，映射 PERMISSION_DENIED(7)/RESOURCE_EXHAUSTED(8)/UNIMPLEMENTED(12)，committed 直写不走 Caddy 错误链阻断页——gRPC 客户端按协议消费，非 WAF HTML 403）；OBSERVE 缺省+UNKNOWN 恒不阻断）；**覆盖账本**（每候选请求 `grpc.coverage_v1`（方向/序号/压缩/读写量/描述符集名+hash/完成度）五态齐全）；**描述符绑定管理面**（迁移 000179 `api_grpc_bindings`（应用×服务×描述符集×模式，空=全局可见、绑定应用只用绑定集（同名服务跨应用隔离），CRUD 5 端点（api_spec.read/manage 零新增）+未登记服务差集清单，写操作 HIGH 审计；服务名词表对齐 protobuf 实际规则（迁移 000180 放宽大写驼峰））；**发布与能力门**（绑定随快照下发（版本戳覆盖），含任一 PROTECT 绑定 required `detectors.grpc.unary=grpc/2` fail-closed（全 OBSERVE 零需求滚动升级），网关能力自报升 grpc/2 恒成立）；**h2c 明文回源**（upstream scheme=h2c → Caddy transport versions:["h2c"]——gRPC 源站协商必备）；OpenAPI +5 → 705 双向零差集。stage5 真实 Go gRPC SDK 对测 R01~R06 全过（分片重组+full 读数/gzip 高倍率 PROTECT 8 拒 OBSERVE 放行/缺描述符直达/结构四分支 PROTECT 7 trailers-only/client-streaming 降级明示不误判/50 次 cancel 零泄漏）；回归 40/40、13/13 不回退。遗留如实登记（>1MiB 无压缩大请求体 h2c 转发挂起未定性、streaming G2/G3 顺延、零消息 PARTIAL 不定案）。
- 新增强流程管理恢复与运行观测（NG-FLOW-04，S4 阶段关闭；冻结设计 `docs/nextgen/NG-FLOW-strong-flow.md`，实现状态 §9 同文件，出口记录 `docs/nextgen/s4/S4-FLOW04-EXIT-NOTE.md`，S4 小结 `docs/nextgen/s4/S4-EXIT-SUMMARY.md`）：**流程基线页三 Tab 增强**（「流程基线（观察）/强流程定义/强流程实例」——定义列表与新建/DRAFT 编辑/复制新草稿/激活确认弹窗（PROTECT 警示）/停用/详情抽屉（步骤序列图+成功条件+允许转换与异常策略），实例列表（应用/状态/created_since 过滤）+详情抽屉（**INDETERMINATE 固定警示条「未知，不显示安全通过」逐字**+步骤轨迹 Timeline（evidence_read 裁剪两档如实）+恢复记录区块（管理对账条目）+恢复面板（三 action+reason 必填+乐观锁随行+409 分类提示）），权限 read/manage 控入口，jiuzhang_admin 路由守卫整页拒绝）；**运行指标内嵌既有 metrics 通道**（`GET /api-security/metrics` 零新端点：per-app labeled `strong_flow_instances` 五态分桶（缺省补 0）/INDETERMINATE 积压与占比/对账滞留 avg+max 秒/近 24h RESERVE 冲突率（无样本=0 不外推），无强流程实例整段省略（NG-T-C01 观测面零变化），采集失败保留上一轮）；OpenAPI 700 持平零差集。stage5 指标冒烟（分桶/积压 1→0/滞留 25.99s/冲突率 0.333 逐行实证）+Playwright 五场景全绿两轮（定义全流页面操作/正常流 CONFIRMED 轨迹/PROTECT 403 轨迹/INDETERMINATE 对账恢复/越权三处 403+整页拒绝）；回归 40/40、13/13、vitest 1045/1045 不回退。联调新发现如实登记（设计 §9.2：多 ACTIVE 定义绑定同端点 finalize 只消费首个预留（多绑定 CONFIRMED 语义待设计明确）、实例键 HMAC 输入不含 definition_id（同版本号不同名定义同 ref 撞键缝隙）、E2E 采集延迟/育龄窗清理纪律）。
- 新增强流程确认与恢复（NG-FLOW-03，S4；冻结设计 `docs/nextgen/NG-FLOW-strong-flow.md`，实现状态 §8 同文件，出口记录 `docs/nextgen/s4/S4-FLOW03-EXIT-NOTE.md`）：**响应回程成功判定**（网关 `flowguard/finalize.go`——成功预留请求包装响应记录器（仅 body 判定式步骤采样 ≤64KB、挂点在脱敏/水印/签名改写之前面向源站事实），判定式三形态可组合与命中才 commit（携带 fencing token，全步骤确认 → INSTANCE_CONFIRMED 事件）；**F04 红线**：超时/连接失败/判定不命中/形态无法解析 → 步骤 UNKNOWN+实例 INDETERMINATE 热状态标记，**绝不自动 release 为可重试**（超时可能已成功，回滚诱导重复扣款），同键重试恒 UNKNOWN 不重放成功语义）；**202 异步受理**（步骤 allows_202 且响应 202 → `FLOW-ACCEPTED-202` 受理待完成，实例保持 ACTIVE 不自动记完成）；**迟到 fencing**（lease 过期被接管后旧 token commit 一律 REJECTED FENCE-001 不覆盖新状态，事件链含两次 fencing 值）；**管理面对账恢复**（`GET .../strong-flows/instances/{id}` 详情——步骤轨迹全链+`status_semantics` 词表（INDETERMINATE=`UNKNOWN_NOT_CONFIRMED`+「未知，不显示安全通过」逐字不美化 §9.4 红线）+证据明细档仅 `api_authorization.evidence_read` 带出（D9 零新增权限点）；`POST .../instances/{id}/resolve`——action ∈ CONFIRM_SUCCEEDED→CONFIRMED / CONFIRM_NOT_EXECUTED→FAILED / KEEP_UNKNOWN 不推进，reason 必填、expected_version 乐观锁 409、终态拒重复 409 幂等不误伤、manage 权限+HIGH 审计 after JSON 全值，CONFIRM_* 推进终态落事件 reason_code=FLOW-RESOLVE-001+version+1；迁移 000178 step_events action CHECK 放宽 +RESOLVE 管理面专属留痕）；OpenAPI +2 → 700 双向零差集。stage5 E2E 八组全过（F01 完整确认流含并行组乱序合法/F04 超时 INDETERMINATE+源站记录型证据+对账收口/F05 迟到 fencing 两值/F06 版本切换/F08 恢复边界/202 受理/F07 复验/越权 403）；回归 40/40、13/13 不回退。**联调裁决两条已闭环**（设计 §8.6）：①F06 采「育龄窗下发」——发布面 ACTIVE ∪ 有非终态实例的 RETIRED 版本（网关 reserve 原子域 `definition_retired` 闸：RETIRED 仅存量续跑、新实例按 ACTIVE 版本键），stage5 复验旧实例按旧版本走完 CONFIRMED；②事件 `fencing_token` 恒为本事件自持有 token（REJECTED 携被拒旧 token、当前 fence 读数移 evidence `fence_current`；202 受理即预留轮换取新 token），PG 事件链 COMMIT OK/REJECTED 双行在册碰撞消解。页面与运行观测（FLOW-04）后续批。
- 新增强流程（响应确认型业务流程防护）首批：定义隔离与原子操作实断（NG-FLOW-01/02，S4；冻结设计 `docs/nextgen/NG-FLOW-strong-flow.md`，实现状态 §7 同文件，出口记录 `docs/nextgen/s4/S4-FLOW02-EXIT-NOTE.md`）：**定义模型**（迁移 000176 `api_strong_flow_definitions`+`api_strong_flow_steps`：应用+路径前缀+实例引用参数提取器绑定，版本单调、激活即冻结、编辑产同名新草稿、activate 同事务 RETIRED 旧版并触发发布，success_rule 三形态白名单键严格校验，timeout/lease 夹紧）；**实例隔离**（迁移 000177 `api_strong_flow_instances`+`api_strong_flow_step_events` 五态/词表 CHECK+双唯一约束幂等去重；Valkey 版本化键前缀 `sflow:v1:` hash tag 同槽；实例键=应用+可信租户+可信主体+定义版本+实例引用经 `sflow` 独立域 HMAC 脱敏 `sfref:` 形态，与授权 objref 域物理区分；旧观察态流程轨迹三无不可导入零迁移路径）；**原子操作**（网关 `detectors/flowguard` Valkey Lua 单次原子往返 reserve/commit/release，fencing=实例级 INCR 单调序号、旧 token 提交一律拒绝，幂等键+参数摘要绑定「实例+步骤」——同键同摘要幂等重放、同键异摘要冲突拒绝，lease 判定一律 Valkey 服务端 TIME 不消费网关时钟，lease 过期仅被争夺时接管不自动回滚）；**实断**（pipeline 接入授权评估后，定义级 OBSERVE 缺省/PROTECT 双闸，违规 403 统一 JSON `FLOW_VIOLATION_DENIED` 不泄露实例细节防探测，**UNKNOWN 恒不阻断**——Valkey 故障/密钥缺席/证据不足放行+`dependency_unavailable` 披露，严禁本地内存回退）；**事件链**（动作事实经主事件 `strong_flow` 数组随既有采集链落 PG 事件溯源，不建新通道）；**能力门**（网关自报 `detectors.flowguard=flow/1`，含 PROTECT 定义快照要求 flow/1 否则 `CAP_MISSING` fail-closed，全 OBSERVE 零需求滚动升级兼容）；管理面 definitions CRUD/activate/retire（manage+HIGH 审计）+ instances 列表（read），OpenAPI 698 双向零差集。stage5 E2E：F01 按序两步/F02 双网关并发恰一成功/F03 幂等两态/F07 停 Valkey UNKNOWN 放行+重启热状态读回/C08 能力门两态/越权 403 全过；回归 40/40、13/13 不回退。响应回程成功判定（commit 接线）/INDETERMINATE 对账恢复/页面属 FLOW-03/04 后续批。
- 新增 PROTECT 切换管理向导 / 影响评估 / 业务确认单（NG-AZ-04，S3 授权实断线收尾；冻结设计 `docs/nextgen/NG-AZ-04-protect-wizard.md`，实现状态节同文件，出口记录 `docs/nextgen/s3/S3-AZ04-EXIT-NOTE.md`）：授权主页新增「态势与实断资格」Tab（§8.4 六要素聚合——来源/有效期/冲突/最后同步/节点 ACK/当前能否实断）；**readiness 服务端派生**（`GET .../authz/enforcement-readiness`，六态徽章 READY/PROTECT_ACTIVE/NOT_PUBLISHABLE/BLOCKED_BY_NO_RELATION/CONFLICT/STALE/NODE + reasons 全列，与网关消费侧同语义唯一事实源）；**影响评估**（`POST .../authz/enforcement-impact` 只读：近 1~30 天 OBSERVE_VIOLATION 命中数（切换后将被 403 的近似量）/UNKNOWN 分桶/涉及主体数/脱敏样本按 evidence_read 裁剪）；**业务确认单**（迁移 000175：签发（manage 评估同时签发一次性 confirm_token，15 分钟 TTL 绑定端点×对象段）→签署（冻结确认文案 v1 含影响面计数）→PATCH 消费；`PATCH object-models` enforcement=PROTECT 强制 confirm_token 同一事务校验+切换+消费（五类 400 精确区分、失败整体回滚不留半切换），切回 OBSERVE 免 token，审计 after 追加 confirm_token 溯源闭环）；**五步向导**（选端点→影响评估→四要素→签署→提交与结果，发布失败如实展示「配置与生效不一致」+CAP_MISSING 缺口明细+Popconfirm 快捷切回不自动回退；双人复核本批不做并如实标注单人模式）；VERIFIED_VIOLATION 决策/事件详情直读 `authz_enforcement` 证据区块（八因子逐项/版本/水位/租约/四要素回执）；OPEN 冲突独立查询端点（`GET .../authz/conflicts`）。权限零新增（api_authorization.read/evidence_read/manage 既有映射，jiuzhang_admin 全 403 对照）。stage5 联调六组+Playwright 五场景全绿；回归 40/40、13/13、vitest 1019/1019 不回退，reconcile 691 零差集。
- 新增显式阻断资格 / VERIFIED_VIOLATION（NG-AZ-03，S3；冻结设计 `docs/nextgen/NG-AZ-03-verified-violation.md`，实现状态节同文件，出口记录 `docs/nextgen/s3/S3-AZ03-EXIT-NOTE.md`）：授权决策词表加第四值 **VERIFIED_VIOLATION**（判定结论非动作，final_action 词表不变、实断落既有 BLOCK），八因子阻断资格真值表全真才成立、任一不满足按既有 reason code 落 UNKNOWN/OBSERVE_VIOLATION 绝不阻断（**UNKNOWN 永不阻断**红线）；**PROTECT 开关** per-endpoint（`api_object_models.enforcement` + enforcement_owner/evidence_source/on_unknown 三伴随列，BFLA 侧 `api_role_baselines.enforcement` 无行级配置继承端点模型值，迁移 000174 列级增量全默认 OBSERVE 零行为变化），切换 PROTECT 经既有 object-models PATCH 强制四要素同请求提供（缺一 400 不降级猜义），切回 OBSERVE 无前置且历史值保留供审计（HIGH 风险审计 after 摘要含四要素全值，权限沿用 `api_authorization.manage` 不新增权限点）；**实断执行**复用既有 BLOCK 执行平面（`category=BLOCK` + `enforced=true` 经统一决策定案），403 统一 JSON `{"code":"AUTHZ_VIOLATION_DENIED","message":"无权访问该对象","request_id":"..."}` 不泄露对象/主体细节；**证据** `final_decision.authz_enforcement`（§1.4 冻结形状：八因子逐项布尔 + 版本/水位/租约读数 + enforcement_owner/evidence_source）随 api_runtime_events 主事件行内嵌零新表，`GET /api-security/authz/decisions` 扩展 `decision=VERIFIED_VIOLATION` 过滤 + 行内嵌证据原样带出（既有权限）；**能力门升 az/3**（含任一 PROTECT 端点的快照 required `detectors.authzdecide=az/3`，az/1/az/2 fail-closed，全 OBSERVE 快照 az/2 照常收载滚动升级可行）。stage5 E2E 六组全过（NG-T-A01 主链四段含源站零到达差分、PATCH 四要素八负向 400、UNKNOWN 不误断九负向样本逐条放行、BFLA 继承/行级显式/全 OBSERVE 三态、NG-T-C08 能力门三态、D7 lease 过期 strict 放行实证）；回归 40/40、13/13 不回退，reconcile 686 零差集。
- 新增撤销水位 / 租约 / 节点 ACK（NG-AZ-02，S3；冻结设计 `docs/nextgen/NG-AZ-02-watermark-lease-ack.md`，实现状态节同文件）：**向量撤销水位**（`api_authz_manual_revocation_seq` 手工通道撤销事务内原子 +1 + `api_authority_watermarks` 逐来源水位，各编号空间独立不混用，写入只增、普通回滚不回退）随签名快照经既有发布链下发（v2 快照字段 schema/revocation_watermark/lease_seconds/conflicted_objects/produced_at 全可选，v1 逐字节兼容）；PreviousValid 发布侧资格过滤（候选快照水位分量比较 ≥ 当前管理面水位且未过期，无合格置空不降级选旧）；网关节点水位记忆拒绝水位回退（`AUTHZ_WATERMARK_REGRESSION`，Provision 拒绝→/load 400 保留旧配置）；**租约**（per-app `authz_lease_seconds` 夹紧 15~300，strict 缺省 UNKNOWN+`AUTHZ-LEASE-001`+`dependency_unavailable` 披露 / degraded 评估继续+`AUTHZ-LEASE-002` 标记）；**冲突对象决策侧排除**（快照携带 `conflicted_objects`（OPEN，上限 10000 超限 fail-hard），BOLA 命中即 UNKNOWN+`AUTHZ-CONFLICT-001`，不出 VERIFIED/ALLOW）；**节点 ACK**（心跳携带授权快照版本/向量水位/应用时刻/租约，新表 `api_node_authz_acks`（迁移 000173）+ `GET /api/v1/api-security/authz/node-acks`（STALE_WITHIN_LEASE/STALE_EXPIRED/NEVER_ACKED/CLOCK_SKEW/FRESH + 最大陈旧窗口，权限沿用 `api_authorization.read`）；**能力门升级** detectors.authzdecide 自报 az/2，v2 快照发布要求 az/2（az/1 旧节点 fail-closed `CAP_MISSING:detectors.authzdecide`）。管理面新增 `PATCH /api/v1/api-security/object-models/{id}`（发布资格/OWNER 词表/排他/租约策略，api_authorization.manage）与 `applications.authz_lease_seconds` 写入路径；gateway_runtime 下发 `api_node_heartbeat_seconds`、`authz_clock_skew_max_seconds`。stage5 E2E 七类场景全过（两臂撤销不回退、回滚拒载、能力门、租约双策略、冲突排除与解除、ACK 状态、时延 4-7s 实测）；回归 40/40、13/13 不回退。
- 新增权威关系接入（NG-AZ-01 第一批，S3；设计 `docs/nextgen/NG-AZ-01-authority-ingest.md`）：权威来源登记/启停/范围授权/Ed25519 验签钥匙轮换（`GET/POST/PATCH /api/v1/api-security/authz/authorities`）+ 离线签名批次导入（`POST .../authorities/{id}/imports`）+ 水位/缺口/冲突状态视图（`GET .../status`）。**五步校验链**按设计冻结顺序——来源身份验签（事件/批次两级规范化签名，RETIRED 键限轮换窗口，三把钥匙不混用）→ 范围权限 → 重放幂等（event_id 已消费跳过计数、同序号重放拒收、delta 批内升序）→ 大小/字段白名单（未知字段拒收不忽略）→ 字段语义（relation 仅 OWNER——共享/委托/组继承/批量对象/复合 ID 首批不支持拒收展示，不降级猜义）；任一失败整批 REJECTED 逐条展示并留痕。snapshot 单事务原子切换（中断一行不动，绝不把未导入对象当撤销）；delta 缺口记 `AUTHZ_SOURCE_GAP`（gap_from 可查，补齐自动消除）；同对象两个不同有效 OWNER 记冲突（不按最后到达者覆盖，收敛自动解除）；撤销水位单调不下降。权威事件落既有 `api_object_relations` 模型（迁移 000172 扩 source='AUTHORITY_SYNC' + source_id/event_id/batch_id 溯源列），随既有发布链下发，不重建关系 CRUD；权限 `api_authorization.authority_manage/authority_import` 仅授 SECURITY_ADMIN（读沿用 `api_authorization.read`）。stage5 E2E 七步全过（含重放幂等/缺口/冲突/原子性/越权 403）。
- 新增 GraphQL 语义与资源预算首批（NG-GQL-03，S2；链路文档 `docs/nextgen/NG-GQL-03-wiring.md`）：管理面 `GET/PUT/DELETE /api/v1/api-security/apps/{id}/graphql-policy`（迁移 000171，权限沿用 `api_policy.read/edit`，无行=关闭全链零行为变化）→ 发布链 `api_graphql.policies.<application_id>` 下发（WDSP 门控、`stripAPIGuardSections` 回滚剥除、纳入 `api_policy_version` 版本戳、读取失败 fail-hard）→ 管线 `checkGraphQL`（Admission 短路之后、统一决策之前）：`gqlast.ParseBounded` 五道硬边界 → `SelectOperation`（多 operation 只算客户端显式指定者，parser 新增 `GraphQLOperationNameSpecified` 字段防推断名冒充协议指定）→ 可信文档摘要白名单直通（`DigestDocument` 口径，APQ 摘要不自动可信）→ `CostOfCached`（LRU 键含策略版本）→ 单请求预算 → app+tenant 定窗预算（匿名独立桶；进程内默认形态，Valkey 注入点保留）。失败分流（NG-T-G06）：结构准入失败 `GQL_ADMISSION_REJECTED` / 成本超限 `GQL_COST_EXCEEDED` / 窗超 `GQL_WINDOW_EXCEEDED`，OBSERVE 全量只记录、PROTECT 403 **GraphQL 协议错误语义 JSON**（`errors[].extensions.code`，非 WAF HTML 阻断页）；证据仅 cost/budget/reason/operation_kind 脱敏；每 GraphQL 请求一条 `graphql.cost_v1` 覆盖记录（SKIPPED=策略关闭/FULL/PARTIAL=超硬边界）。stage5 E2E 六场景全过（含 trusted 直通、时间窗独立桶、源站未到达对账），回归 40/40、13/13 不回退。
- 新增执行覆盖账本（NG-COV-01/02，设计依据 `docs/WDSP_API_WAF_NEXTGEN_RD_PLAN.md` S1）：管线三发射点（SKIPPED/FULL/PARTIAL+截断如实）与 guard 出入口 15 接线点计数（10 冻结阶段、`proxyAndCount` 精确归因——Coraza 中断归 `intercepted_waf` 不计源站到达），经 `coverage-observations.jsonl`（观测行 + counter_snapshot 行同源）由 logrotator 轮转，server 采集器断点续传、确定性 1/N 采样（默认 N=10）入三表（明细/分钟聚合/阶段计数快照，迁移 000168）；观测永不贡献攻击分（独立通道）；开关 `COVERAGE_OBSERVATIONS_ENABLED` 缺省关闭。
- 新增覆盖数据查询接口 `GET /api/v1/api-security/protection/coverage`（迁移 000169 权限 `api_protection.read`，仅授 SECURITY_ADMIN/AUDIT_ADMIN）：agg/stages 双视图，E 与双比率查询侧计算、E=0 强制 `no_applicable_traffic=true`（永不显示虚假 100%）、摄入溢出/非法时 `data_incomplete` 如实置真；窗口越界夹紧 7 天并注明。
- 新增无副作用模拟接口 `POST/GET /api/v1/api-security/protection/validations`（迁移 000170 权限 `api_protection.validate` 仅授 SECURITY_ADMIN）：脱敏 Finding 批次经真实 decision 引擎重放（批次/字段/长度白名单上限、拒绝 evidence 原文），输出 would_block 模拟判定与候选/最终动作、例外命中、CANNOT_REPRODUCE/EVIDENCE_INSUFFICIENT 如实三态；报告与策略/语料/输入摘要加强绑定，**读出时 STALE 求值不回写**。
- 新增能力发布门（NG-COV-04 第一批）：网关进程级 `capability_report`（sidecar `capability.json` 60s 原子刷新，逐键有据不报未实现能力）+ 发布链 `/load` 前逐节点集合包含校验；缺能力 `CAPABILITY_MISSING`（不发送 /load）、清单缺失/过期 `CAPABILITY_MANIFEST_UNAVAILABLE` 均 fail-closed；空需求免门禁（存量发布零行为变化）；远端次要节点 manifest 通道与 SHADOW/CANARY 灰度生命周期为后续批。
- 新增 HTTP 解析链一致性测试台 `test/httpchain/`（记录型源站、拓扑注册表、5 组隔离语料、T0/T1/chains 驱动）：direct/conn-reuse/trusted-proxy 三链路实测 pass（CL/TE 夹带不到源站、单连接无串扰、真实 IP 链双向），h2/path-rewrite 链路待扩。
- 新增 WDSP 免 Docker 裸机交付包（`dist/jiuzhang-wdsp-baremetal-linux-amd64.tar.gz`，约 225MB）：整套系统（管理后端、控制台、防护网关、PostgreSQL 16、Valkey 8、netmgrd、日志轮转）以单一目录直装 openEuler x86_64（含兆芯），systemd 七单元托管、目标机零软件依赖（仅需 systemd 与 curl）。包内自带 PostgreSQL/Valkey 运行时（供体镜像 digest 锁定，GOAMD64=v1 全静态二进制）；安装器自动完成账户/口令/env/initdb/控制台证书/宿主机指纹/GeoIP/宿主兼容符号链接（发布配置硬编码路径 `/etc/caddy/rules`、`/etc/caddy/certs`、`/srv/jiuzhang/blockpage.html`、`/var/log/caddy`）与健康自检；含 backup/restore/uninstall 与 docker 部署迁移指南。构建链路：`ops/baremetal/{build-runtimes,build-binaries,assemble}.sh`（均可重复执行、版本全锁）。
- 管理控制台支持 HTTPS 入口（离线包）：web 容器 HTTP :8080 与 HTTPS :8443 双栈托管；证书由安装期 `ops/install/console-cert.sh` 生成（自签、RSA-2048、100 年有效期、SAN 覆盖宿主机全部 IPv4 与 hostname，已存在不重新生成），落 `runtime/certificates/console.{crt,key}` 只读挂载；证书缺失时入口脚本自动退化为仅 HTTP；支持替换为内网 CA 签发的同名证书文件。
- 新增网络诊断工具（前台「系统运维 → 网络工具」）：支持 ping、TCP 端口探测、traceroute、DNS 查询与按需抓包 pcap 下载五种动作；server 新模块 `netdiag` 经共享卷文件契约下发至 netmgrd 串行执行并落库，任务状态机 PENDING/RUNNING/SUCCESS/FAILED/STOPPED/TIMEOUT，支持手动停止；权限 `network_tools.execute`/`network_tools.download` 仅授 SYSTEM_ADMIN，执行/下载/停止全量审计。
- 新增 NTP/DNS 网络设置（前台「系统设置 → 网络」分组）：`network.ntp_servers`/`network.dns_servers` 逐项校验后随网络配置下发，netmgrd 按 resolvectl/resolv.conf 与 timesyncd/chronyd 顺序落地，容器环境如实回报 UNSUPPORTED。
- 网络诊断抓包结果支持页面内直接查看：server Worker 在抓包产物搬移入库后用内置纯 Go pcap 解析器（零新增依赖）解析数据包列表（Ethernet II/VLAN → IPv4/IPv6 → TCP/UDP/ICMP/ICMPv6，最多前 200 个包，含端口/TCP flags/80 字符 payload 可打印预览），存 `netdiag_jobs.capture_packets`（迁移 `000163`）并随任务详情接口带出；解析失败不阻断任务成功，字段为 null 时页面回退为仅显示下载按钮。
- 新增 netmgrd Docker 服务与镜像（stage5 栈，与网关同网络命名空间，alpine digest 锁定）；新增数据库迁移 `000160` 至 `000162`、OpenAPI 片段 `20-network-tools.yaml`（661 路由对账零差集）及设计文档 `docs/NETWORK_TOOLS_DESIGN.md`。
- WAF 规则体系引入许可证已审开源防护策略（设计依据 `docs/WAF_RULE_ENRICHMENT_DESIGN.md` P1，全部 PINNED 锁定上游 commit+sha256）：① 主流搜索引擎爬虫 UA 声称标记 13 条（自建 `contrib/CUSTOM_PACK/fake-bot-claims.conf`，ID 1010201-1010213；原计划投递的 CRS fake-bot-plugin 因核心检测依赖 Coraza 不支持的 Lua rDNS、剔除后失去检测能力，评估后移除并以本包替代）；② phpmyadmin/drupal/dokuwiki/xenforo 四个 CRS 应用误报排除插件（Apache-2.0，`contrib/THIRD_PARTY/`，与 wordpress/nextcloud 同模式，启用即减误报）；③ monperrus/crawler-user-agents 爬虫 UA 指纹 1501 条（MIT，生成器 `tools/rulegen/crawler-ua` 产出 `contrib/CUSTOM_PACK/scanner-fingerprints-ext.conf`，ID 1002001-1003501）；④ ai.robots.txt AI 爬虫 UA 180 条（MIT，生成器 `tools/rulegen/ai-crawler` 产出 `contrib/CUSTOM_PACK/ai-crawler-control.conf`，ID 1010001-1010180）。检测类规则全部默认 OBSERVE（pass+log 只标记，不阻断、不累加异常评分）；许可证 NOTICE 归档 `licenses/{crs-plugins,crawler-user-agents,ai-robots-txt}/` 并已登记 DEPENDENCY_LICENSES.md / THIRD_PARTY_NOTICES.md。
- CRS auto-decoding-plugin 1.0.0 评估后投递（Apache-2.0，`crs/plugins/auto-decoding-plugin/`，PINNED 锁定 commit 6885a972）：剔除 Coraza 不支持的 `sqlHexDecode` 两条规则与 10 行 CRS 4.x 已删规则的 SecRuleUpdateTargetById 引用，**默认禁用**（config 内 `enabled=0`，按站启用前先 OBSERVE）；stage5 实测 base64 编码 `system('bash')` 与双重 URL 编码 SQLi 在启用态可检出并阻断（禁用态漏检）、正常业务参数零误报、PL1 单轮解码增量约 +26% p50/+16% p95（评估记录见插件目录 JIUZHANG-NOTES.md）；body-decompress-plugin 因核心解压逻辑依赖 Lua 评估后放弃。
- 新增威胁情报导入（WDSP P2-C1，abuse.ch Feodo C2 情报 → IP 黑名单，设计依据 `docs/WAF_RULE_ENRICHMENT_DESIGN.md` §3）：`POST /api/v1/threat-intel/import` 接收纯文本 IP 清单或 Feodo CSV（按表头自适应取 IP 与 family 列；坏行跳过计数、上限 5000 条、仅 IPv4），与历史导入集合（reason 前缀「威胁情报 <feed> 批次」的 GLOBAL DENY IMPORT 行）做集合对账——新 IP 建 ACTIVE 黑名单（TTL 默认 30 天、0=永久）、在册刷新有效期与批次号、本批消失标 EXPIRED 保留历史，绝不触碰人工/事件/自动封禁等来源规则，同址人工黑名单冲突跳过；权限 `access_rules.import` + CSRF + 操作审计，生效集变化自动触发网关配置发布。本期为手动导入+对账，定时拉取与设置页 UI 留作后续。
- 新增 NVD Web 漏洞策展队列生成器 `tools/rulegen/cve-draft`（WDSP P2-D1）：NVD API 2.0 拉取近 N 天披露（限速/重试/本地缓存），CVSS≥阈值 且（CWE 白名单 或 攻击关键词）过滤，与 `gateway/rules` 现有 CVE 覆盖去重，产出按分排序的评审队列 Markdown（`output/cve-review/cve-queue-<date>.md`）与符合 CUSTOM_PACK 约定的规则草稿骨架（TODO(analyst) 标记、cve-recent 段顺延建议 ID）；机器不生成检测规则，合入必须经分析师依据公开 PoC 填写并走规则双轨生命周期（DRAFT → OBSERVE → TP/FP → 审批 → BLOCK）。

### 安全与质量

- 修复授权中心 TRIAL 签名密钥轮换（2026-09-26 测试密钥库重建）后新签发 TRIAL 授权导入报「授权文件签名校验失败」：产品侧信任根 `vendor_pubkey.hex` 登记轮换后的 TRIAL 验签公钥 `trial-67b3a728-...`，旧 TRIAL 密钥保留并存（存量未到期 TRIAL 授权仍可验签）；正式密钥不变。
- 修复授权锁定态下「验签失败 → 无法导入 → 无法升级」死锁：授权门控白名单新增 `/api/v1/upgrades/` 前缀，锁定状态仍可经「系统升级」页面上传并应用签名升级包（会话认证、CSRF、系统管理员角色与发布签名校验均不受影响）。
- 修复纯 HTTP 部署下管理控制台登录态无法保持：会话 Cookie 的 `Secure` 属性改为按请求协议动态下发（直连 TLS 或前置反代 `X-Forwarded-Proto: https` 才带），HTTPS 部署安全姿态不变；prod 环境 `COOKIE_SECURE=true` 强制校验保留。
- 修复 WAF 安全事件 `client_ip` 落连接源 IP 而非真实客户端 IP：网关 guard 在真实 IP 改写时同步 Caddy `{http.vars.client_ip}` 变量（coraza-caddy 审计事务优先取该变量且不跟随 `RemoteAddr` 改写），并新增内部头携带原始 TCP 对端地址，server 侧回填 `connection_ip`/`client_port`（严格 netip 校验、非法忽略、内部头不进事件留痕）；旧版网关未上报时回退既有口径。
- 诊断目标在 server 与 netmgrd 两端校验（仅 IP/合法主机名）；系统二进制以参数数组调用不经 shell；抓包过滤仅 proto/host/port 三元素固定模板、不开放自由 BPF；ping 30s/traceroute 60s/抓包 5–300s 超时硬上限、pcap ≤100MB、输出截断 64KB；pcap sha256 入库且下载时校验一致。
- 修复宿主机升级执行器与安装器依赖核查漏 diffutils（S8 批次 C 发现 F1，openEuler 24.03 最小化环境实景暴露）：缺 `diff`/`cmp` 时执行器在 manifest 文件比对处报误导性错误（「存在未声明文件」实为比对命令缺失）；`ops/upgrade/upgrade-executor.sh` 与 `install-executor.sh` 依赖清单补 `diff`/`cmp`，缺失时点名「diffutils 包」报准确错误并 fail-closed（`ops/upgrade/tests/test_executor_dependencies.py` 5 用例 × 两脚本，upgrade-pack-harness 58/58）。
- 修复升级任务滞留 APPLYING 无兜底（S8 批次 C 发现 F7：执行器中断无结果文件 + API 重启 → 进程内 30 分钟等待定时器丢失，任务滞留阻塞后续升级预检）：迁移 `000185` 为 `upgrade_jobs` 新增 `executor_deadline` 持久化截止列（进入 APPLYING 即写入；旧行退化为 `started_at + 等待上限`），`reconcileExpiredApplying` 随结果对账循环对超期且无结果文件的任务标记 `FAILED`/`EXECUTOR_TIMEOUT`，留 HIGH 审计（`executor_timeout_close`）并触发 `UPGRADE_FAILED` 告警；不自动重跑、不伪装成功，可经既有 FAILED → ROLLING_BACK 入口手动回滚（`server/internal/upgrades/stranded_test.go` 5 用例 + fix-lab 活体闭环）。
- 修复 000185 登迁移栈顶后 7 个 PG 契约测试 down 序列未同步 prepend 首步（回滚 185）导致的落点偏移（apiauthz/apiauthzwizard/strongflow×2/apigrpcdesc×2 处/apimcp/apimachineid）；干净 PG 逐包串行复跑 119 PASS / 0 FAIL / 0 SKIP。连带口径更正：未设 `AUTHZ_TEST_PG_DSN` 时这些 Opt-in 契约测试静默 skip，此前「server 全量 103 包 ok」对 PG 契约测试为假绿（详见 `docs/nextgen/s8/S8-REL02-PACKAGE-REPORT.md` §11.2 补记）。

## [1.2.0] - 2026-09-12

### 新增

- 新增 openEuler / 兆芯 KX/KH 专用 amd64 自解压 `.run` 安装包构建器，可封装完整 WDSP 离线包、SHA-256 校验、Ed25519 签名及可选离线 RPM。
- 安装器自动检测 openEuler、兆芯 CPU、systemd 与运行依赖；缺失依赖时优先使用 dnf，缺少 dnf 时回退 yum。
- 新增文件描述符、进程数、网络队列、Docker systemd 限制与兆芯 CPU performance governor 调优；仅写入当前内核支持的参数。
- 新增显式 `--minimal-host` 模式，只停用已确认无关的服务，不卸载软件包，并保留 SSH、网络、防火墙、时间同步和容器运行能力。

### 安全与质量

- 正式 `.run` 与内层离线包均要求发布签名，development 未签名包必须显式放行且不得用于生产。
- 增加 openEuler/兆芯识别、dnf/yum 回退、调优边界、服务精简边界和自解压构建的自动化测试。
- 新增 openEuler / 兆芯构建、安装、验证及调优回退文档。

## [1.1.6] - 2026-09-12

### 新增（WDSP 阶段 4–8 能力补齐）

- 完善访问控制与安全运营闭环：支持安全事件预填黑名单、规则草稿态与关联事件、自定义拦截响应、保护地址自动识别、共享 NAT 防误封、限速策略向导及发布后真实流量校验。
- 扩展 API 动态防护：覆盖多格式 API 规范、协议与资产分类、参数关系和业务动作建模、授权配额、业务流偏差、失效凭证、响应采样与运行指标，并补齐对应管理页面。
- 增强 AI 安全运营：增加会话留存清理、输出自动续写、结构化事件与攻击画像、扩展 What-If 场景、提示词对抗门禁及分析明细接口。
- 完善监控与交付能力：增加告警维护窗口、文件描述符指标、可信代理分析、告警导出、依赖许可证清单、漏洞检查说明及独立验收脚本。
- 新增数据库迁移 `000141` 至 `000159`，同步更新网关、服务端、OpenAPI、前端与跨模块测试。

### 修复与加固

- 加固真实客户端 IP、共享 NAT、访问控制、CC 计数、API 上下文传递、响应侧检测和配置发布链路，补充错误处理与回归覆盖。
- 完善 API 资产、模型统计、参数观测、流程基线、凭证撤销、配额与安全事件的数据一致性和运行时处理。

### 文档与演示素材

- 新增适中语速的 6 分 53 秒 WDSP 产品解说脚本，突出统一 Web 与 API 动态防护、未知资产发现、身份与业务行为理解、双向检测及渐进式上线等产品优势。
- 新增与成片逐段对齐的剪映导入 SRT 字幕，共 28 个连续时间段，覆盖完整片长且无时间空隙、重叠。
- 视频、音频、截图、缓存和本地编译产物不作为产品源码纳入版本库。

## [1.1.5] - 2026-09-10

### 修复（WDSP 1.1.4 全仓审查）

- 修复 AUTHZ 配置编译、对象重新授权、BOLA/BFLA 多关系判定、回滚门禁和发布锁竞态，避免发布失败、授权结果依赖行顺序或并发发布互相覆盖。
- 修复自定义规则 OBSERVE 事务级降级、正则转义、可选 GeoIP 空指针、配置查询失败降为空配置、明细上限漏检及未验证角色参与字段权限判断等防护失效路径。
- 修复运行时回滚遗留草稿、备份恢复缺表、API 资产跨应用合并、自动封禁遮蔽人工封禁以及 1xx 响应状态误记等一致性问题。
- 修复 Agent 补传永久停滞、tap 缓冲区别名、证书轮换状态分裂与解压截断信号丢失，并补齐对应单元测试。
- AI Provider 增加规范化目标源绑定、目标白名单和安全拨号校验；修改目标源会清除已有密钥并要求重新录入，阻止密钥被转发到新目的地。
- 管理前端补齐对象关系重新授权、AI Provider 密钥失效提示、调用链空值/路径编码和安全回归状态表达，并同步更新 OpenAPI。

## [1.1.4] - 2026-09-10

### 新增（AUTHZ-01：对象授权关系确认与 BOLA/BFLA 网关 OBSERVE 决策）

- 完成对象授权关系与候选关系管理：支持候选扫描、人工确认、覆盖率统计、版本快照、发布、回退及 `PreviousValid` 恢复。
- 网关接入 BOLA/BFLA 统一决策与事件记录，保持 OBSERVE 只观测不阻断，并与 JWT 信任主体、访问控制事件及 API 运行时事件关联。
- 管理面新增对象授权关系 API、权限与审计链路，前端新增授权关系工作台；同步补齐 OpenAPI、数据库迁移及跨模块契约测试。
- 本地实现、迁移回放、发布恢复和网关跨模块验收完成；正式环境 Provider、跨主机链路及专用性能测量按任务书后置。

## [1.1.3] - 2026-09-10

> 本版本无产品代码变更：内容为 P0 发布证据再冻结与 Bot 挑战验收补证（文档与测试证据）。

### 新增（P0-01：S6 发布证据再冻结，绑定 wdsp-v1.1.2 干净构建输入）

- 发布提交 `3f6f6f8`（tag `wdsp-v1.1.2`）作为干净构建输入冻结：3653 个构建输入文件逐一 sha256、快照摘要与文件清单入 manifest、dirty=false；新证据包 `docs/evidence/releases/dev-s6-refreeze-1.1.2-20260909/` 与最终合并视图 `docs/evidence/merged-check-final-20260909.manifest.json`（check rc=0）。
- `--release` 门槛拒绝理由由 11 项收窄至 8 项（source.dirty / snapshot_sha256 / file_manifest 消解）；剩余：锁定镜像、有效配置指纹、测量硬件/72h 长稳、EVD-11/12 重建复跑，发布状态保持 DEVELOPMENT。
- 能力证据仓库冒烟合并逻辑支持同一验收 ID 被后续包再冻结（以新包记录为准）；CAPABILITIES.md 重生成（产品版本 1.1.2）。

### 新增（P1-02：Bot 挑战 BOT-004/006/018 真实环境补证）

- 验收矩阵 BOT-001~024 由 PASS 20 / PARTIAL 4 变为 **PASS 23 / PARTIAL 1**（FAIL 0），仅 BOT-013（移动网络/NAT 实测）保持环境阻塞。
- **BOT-004 多浏览器挑战链 PASS**（run `20260909T224253-3040ab`，23/23）：Chromium/Firefox/WebKit/移动 Safari/移动 Chrome 五通道全部走通 挑战→页内求解（2–107ms）→verify 204→clearance→源站 200；跨浏览器解析经第二域名 `bot-bench.localhost`，不依赖 Chromium 专有参数。新增 `run-browsers.sh` 与五通道 Playwright projects。
- **BOT-006 降级可读与无障碍 PASS**：CPU 6× 节流下挑战 102ms 完成、主线程探针最大 gap 91ms；纯键盘完成挑战全流程、焦点可见、aria snapshot 落盘。读屏实测仍 NOT_RUN（无辅助技术环境，已登记）。
- **BOT-018 洪峰与资源受控 PASS**（run `20260909T231820-d1f76b`，25/25）：新增 `flood-bench.sh`；签发洪峰 429 受控、验证洪峰 120 并发三类伪造零 clearance 零 panic、慢请求 2s 读超时截断、洪峰期间合法请求 30/30 全 200、Valkey 键数峰值 60 远低于上限、网关零重启零 OOM。环境如实标注为开发机非专用硬件。

### 披露（非本版本修复）

- 他人在研未提交代码 `server/internal/guardconfig/authz_decision.go` 引用不存在列 `ep.method`，主工作树下配置发布必失败（SQLSTATE 42703）；本轮证据栈构建自 HEAD 干净 worktree 规避，缺陷归 AUTHZ 线所有者（证据 `test/e2e/bot-challenge/runs/20260909T221713-8e02d4/`）。

## [1.1.2] - 2026-09-09

### 新增（P1-01：安全与 APM 标准客户演示）

> 任务书 docs/tasks/wdsp-p1/P1-01_SECURITY_APM_DEMO.md；验收 APMD-001～018 中 17 项 PASS，APMD-017（用户任务耗时验证）BLOCKED 如实保留（需未参与开发的人员，脚本已固化待执行）。证据见 docs/tasks/wdsp-p1/WORKLOG.md S2 记录与 A4 真实产品栈联调。

- 安全事件到关联请求、Trace、慢 SQL、异常的闭环定位演示（自建合成业务，真实产品栈四场景联调通过）。
- APM 数据健康可判别：未配置探针、存储失败、样本缺失分别返回明确状态，不再统一降为空页。
- 关联边界如实表达：Trace 匹配验证上下文，不只按时间相近归因；缺数据与权限边界可解释。

### 新增（P1-02：Bot 挑战及多信号策略）

> 任务书 docs/tasks/wdsp-p1/P1-02_BOT_CHALLENGE.md；验收矩阵 BOT-001～024 PASS 20 / PARTIAL 4 / FAIL 0（docs/WDSP_BOT_CHALLENGE_ACCEPTANCE_MATRIX.md）。运维手册 docs/BOT_CHALLENGE_OPERATIONS.md。

- **应用级浏览器挑战**：`bot_policy` 配置（缺省 OFF；OBSERVE 只记录，PROTECT 对合格的 HTTPS GET 浏览器文档导航签发 JS 挑战）；网关新增 Bot 挑战判定步骤（`bot_step.go`），四个放行出口统一经 `serveNextViaBot`；保留命名空间 `/_wdsp/bot/v1/` 本地处理不反向代理。
- **挑战服务**：`botchallenge/`（Valkey 共享态、签名签发/验证、失败计数）；信号评估只读消费身份行为窗口计数（`identitybehavior.PeekSnapshot`），不记账。
- **final_decision 增量扩展 CHALLENGE 动作**（P0-04 schema 有版本增量，旧动作含义不变；挑战成功只允许通过 Bot 步骤）。
- **管理面**：Bot 策略管理页（草稿/发布/回退）；浏览器与自动化基准 27/27 PASS；升级/关闭/回退演练 23/23 PASS。
- 如实披露：仅 Chromium 通道实测；慢设备/读屏、移动网络 IP 变化、签发验证洪峰压测待补（详见验收矩阵）。

### 新增（P1-03：Agent 解密后接入及协议覆盖）

> 任务书 docs/tasks/wdsp-p1/P1-03_AGENT_GATEWAY_PROTOCOLS.md；验收 AGT-001～028 中 26 项 PASS，AGT-021/022 BLOCKED_ENV（无真实 K8s 集群，组件级等价断言已覆盖）。支持矩阵 docs/agents/WDSP_AGENT_P1_SUPPORT_MATRIX.md。

- **真实 Nginx mirror 与 Envoy tap 接入**：E2E 各 11/11 PASS（Envoy tap 覆盖 h2/gRPC/WebSocket 元数据）；Kubernetes DaemonSet/RBAC 部署清单。
- **HTTP 事件 v2 契约**：解密后、多路复用场景的协议表达（请求/响应、截断、关联边界明确）；Agent v1→v2 升级与能力收回降级实证。
- **可靠性**：断线磁盘缓存、重放、背压、重启恢复经演练；Agent 采集为被动观测，不宣称阻断原始业务请求。
- 范围外如实标注 NOT_SUPPORTED：原生旁路 HTTP/2 HPACK 帧解析、WebSocket 帧正文、HTTP/3/QUIC、gRPC Protobuf 正文解码、AF_XDP、Agent 在线阻断。

### 新增（P1-04：规则与模型持续回归）

> 任务书 docs/tasks/wdsp-p1/P1-04_RULE_MODEL_REGRESSION.md；验收 REG-001～026 工具层/后端/门禁/回退全部实证通过。证据 docs/evidence/regressions/（P1-04-R2-FINAL-REPORT.md、P1-04-R4B-DRILL-REPORT.md）。

- **固定语料回归管线**：`test/regression/p1/`（语料契约、回放适配器、判定/对比，201 单测）；全量回放基线 48/48，候选对比精准捕获唯一预期内丢失检测并如实 FAIL。
- **发布门禁**：regression-policy 三态 OFF/OBSERVE/ENFORCE（默认 OFF）；受信验签公钥登记（system_settings）+ `tools/regsign` 签名工具（私钥不入库不入仓）；证据有效期默认 7 天；迁移 000134/000135。
- **回退演练**：ENFORCE 端到端 + 误报/故障回退全相位 PASS；配置版本回退与 GuardOverride 已知良好快照恢复均经实证。
- **管理界面**：安全回归管理页 + 页面 E2E 11/11；CI 新增 nightly 回归工作流。

### 修复（P1 实施期间抓出，均有证据链）

- server 证书查询 SQL 歧义（certColumns 未限定别名，SQLSTATE 42702）导致「HTTPS 域名+绑定证书」应用发布必失败。
- docker stage5 栈证书下发通道未接线（stage5-gateway-certs 卷 + 两 Dockerfile 预建目录）。
- botchallenge Store.Read 在真实 Valkey 下 HGETALL 数字型 bulk string 解析失败导致 verify 恒 503（luaFieldString 两型兼容）。
- web 回归详情页 gate_assessment.reasons 为 null 时白屏（归一化 + 守护测试）。
- s5_publish 发布锁 LOCK_BUSY 无重试（自动发布与显式发布竞争，补退避重试）。

### 已知限制（如实披露）

- APMD-017、AGT-021/022 及 Bot 四项 PARTIAL 待对应环境/人员条件补做，详见 docs/tasks/wdsp-p1/DELIVERY_SUMMARY.md。
- 13 条产品发现已转修复排期（docs/tasks/wdsp-p1/PRODUCT_FINDINGS_FIX_PLAN.md），最高优先级为回滚草稿孤儿化。
- P0 挂起项延续：JWT-18 与 BENCH-03/04/08/09/10/11/12 待专用隔离硬件与 72h 长稳窗口；发布状态保持 DEVELOPMENT（见 docs/tasks/wdsp-p0/WORKLOG.md S6 差距清单）。

## [1.1.0] - 2026-09-08

### 新增（P0-03：业务 JWT 验证信任链）

> 任务书 docs/tasks/wdsp-p0/P0-03_JWT_TRUST_CHAIN.md；迁移 000125–000127；验收 JWT-01～17 PASS、JWT-18 待专用测量硬件（如实 BLOCKED）。证据包 `docs/evidence/releases/dev-s3-jwt-20260907/`。

- **网关验签核心**：`gateway/dynamic_security/jwtverify/`（RS256/ES256 显式白名单验签、严格声明校验、JWKS 内网受限获取与有界缓存、KeysetVersion 指纹与管理面逐字节一致并互钉测试）。
- **网关挂接**：`jwt_trust.go`（真实 IP 之后、身份观测之前）；`apiprotect.go` serveNext 统一放行出口 JWT 强制处置（白名单/L7 allow 不绕过）；OBSERVE 只记录、PROTECT 401/503。
- **管理面**：`server/internal/jwttrust/`（策略 CRUD/预检/乐观锁/审计/静态 JWKS 私参拒收/ListForGuard 下发契约）；配置供应链 fail-hard 加载与 PROTECT 管线门禁；权限 `jwt_trust.read/manage`。
- **前端**：应用详情「JWT 信任策略」页签（草稿/预检/状态）；API 运行时事件详情展示 JWT 验证摘要。
- **测试**：真实网关冒烟 `test/e2e/jwt-trust-smoke.sh` 26/26（合法 200/伪造 401/OBSERVE 放行/VERIFIED+SQLi→403/事件落库/发布门禁）；接口测试真库覆盖。

### 新增（P0-04：整条请求处置解释与有限范围例外）

> 任务书 docs/tasks/wdsp-p0/P0-04_DECISION_SCOPED_EXCEPTIONS.md；迁移 000130–000132；验收 DEC-01～06、EXC-01～15 全 PASS。证据包 `docs/evidence/releases/dev-s4-dec-exc-20260907/`。

- **最终处置 final_decision**：网关 disposition 终止分支全量归因（执行者/动作/来源/状态码/规则引用/例外命中/处置步骤链）；Coraza 合流归因（下游中断如实记 BLOCK，决策结果不改写保留于 steps）；WAF 安全事件与 API 运行时事件跨侧 request_id 关联、幂等条件补全（已确认拦截优先）；事件详情抽屉「最终处置」区块。
- **例外能力重写**：多条件交集编译（URI/方法/来源 IP/参数名全匹配才生效）、运行时时间窗半开区间（控制面离线不延长）、LOG_ONLY/ADJUST_SCORE 停用门禁（历史数据迁移标 NEEDS_REVIEW）、发布全量快照 2000 容量字典序确定性、预览 409 乐观锁、从事件创建草稿绑定真实事件且缺证据不得启用、保护模块（JWT/协议底线/人工封禁/CC/配额）不可例外。
- **引擎侧语义**：corazasemantics 两规则标记法全维翻折 + 载荷覆盖集不动点实测（942100/942190/942270/942360+contrib 1001209 全摘除才放行）；审计日志携带 exc:<uuid>/excv:<version> 命中标记。
- **测试**：真实网关冒烟 `test/e2e/exception-p0-smoke.sh` 34/34；E2E `web/e2e/exception-p0.spec.ts` 5/5；接口测试 16/16；迁移 up/down/幂等演练 23/23。

### 新增（P0-01/02：能力证据清单与安全性能基准工具）

> 任务书 docs/tasks/wdsp-p0/P0-01、P0-02；证据冻结包 `docs/evidence/releases/dev-s6-freeze-20260908/`。

- **能力证据体系**：`docs/capabilities/capabilities.json`（15 项能力，实现/接线/验证三态分离）+ `tools/capability_evidence.py`（结构/断链/工件 sha256/状态伪造校验，原子写报告，38 单测）+ `docs/capabilities/CAPABILITIES.md` 自动生成；`--release` 门槛实测拒绝未达标发布。
- **基准工具**：`test/performance/p0`（run-plan 预检、隔离归属判定、检测/处置指标分离零分母 N/A、最近秩分位数禁平均伪汇总、事件对账、报告完整性；123 单测）。正式测量矩阵/72h 长稳/异机复跑待专用隔离硬件，BLOCKED 如实保留。
- **冻结现状**：63 条强制验收项全部可定位（PASS 52 / BLOCKED 10 / NOT_APPLICABLE 1）；能力验证 PASS 9 / BLOCKED 6；发布状态 DEVELOPMENT（差距清单见 docs/tasks/wdsp-p0/WORKLOG.md S6 记录）。

### 修复（P0 实施期间抓出）

- 审计写入在存在 000001 no_update/no_delete RULE 的库上报 0A000：recordWithDelivery 去掉 `ON CONFLICT (delivery_id)`，改普通 INSERT + 捕获 23505 幂等返回。

### 修复（1.0.1 审计管理员权限收敛）

- 审计管理员不再显示或访问「风险策略」「攻击活动」「Agent 管理」「授权管理」；新增迁移 000122 清理历史误授权限，同时保留授权失效时的授权恢复入口。
- 完整安装包的安装向导会自动安装并验证宿主机升级执行器；安装前检查 root、systemd 和必需命令，避免新装系统仍需单独安装执行器，或 Web 升级显示成功但实际未执行。

### 新增（APM 设置前台化：系统设置界面热生效）

- **APM 总开关与 ClickHouse 连接串界面化**：「系统设置 → APM 性能监控」页可配置 `APM_ENABLED` 与 `APM_CLICKHOUSE_DSN` 等价项（权限 `system_settings.read`/`.update`，SYSTEM_ADMIN）；界面值（`system_settings` 表 apm 组）优先于环境变量、保存后立即生效无需重启，未配置界面值时行为与纯 env 部署完全一致（无迁移种子）。
- **后端**：新增 `GET/PUT /api/v1/apm/settings`（挂主 mux，不受 APM 关闭 503 门控；DSN 经 clickhouse-go ParseDSN 校验、is_sensitive 不回显、审计只记 set/cleared）；ClickHouse 连接改由 `CHManager` 运行期惰性建连/DSN 变化重建（旧连接先回收，建连失败 Warn 降级不 500）；APM 路由恒注册 + 运行期 gate 门控（关闭时报文与原 503 stub 一致），系统告警 APM 评估器与组件探针随开关空转；capabilities 的 `apm_enabled` 改运行期判定。

### 新增（AI 自动化渗透防护增强 阶段2：Parser 歧义检测）

> 实施文档 docs/WDSP_AI_PENTEST_PROTECTION_ENHANCEMENT.md（阶段2）；无新迁移。全部信号仅 OBSERVE 不拦截。

- **解析歧义四类检测（网关 dynamic_security）**：重复 JSON 键（PARSER-DUP-JSON-001）、重复查询参数、重复 Header、重复表单参数；detector=`api_parser`、ScoreDelta=20、Severity=MEDIUM（仅过物化门槛），规则版本化 1.0.0；经统一 Finding 通道落 `api_runtime_findings`（PARSER_DUPLICATE_JSON_KEY/QUERY_PARAM/HEADER/FORM_PARAM），evidence 仅白名单键（parameter_name/value_count/rule_code/path）。
- **阶段1 强化（网关 identitybehavior）**：identity_observation 洪泛修复（16 容量已知 IP 集，扫描身份轮换 IP 观测记录 105→5 条/150 请求）；轮转快照携带完成桶计数（memory/Valkey Lua 同步），短突发请求量估算失真收敛。

### 新增（AI 自动化渗透防护增强 阶段3：Risk Engine + Enforcement）

> 实施文档同一（阶段3）；迁移 000101–000102。策略缺省 OBSERVE 零拦截；评估/存储故障 fail-open 放行；处置原因固定 `identity_risk_policy`。

- **身份风险引擎（网关 riskengine）**：身份滑窗信号累加（默认 24h；信号三入口——identitybehavior 侦察信号含 HEADLESS-001、apiprotect DetectorMatch、身份键与身份引擎同算法同盐）；内存+Valkey ZSET（`jiuzhang:guard:risk` 单 Lua 原子入账）双实现，Valkey 故障回退内存；双阈值（block/rate_limit+rps），OBSERVE 记 would_*、PROTECT 实断 403/429；执行点位于自动临时封禁之后、授权限速与 CC 之前；身份白名单零记账。
- **可解释处置事件**：RISK_POLICY_BLOCK/RATE_LIMIT（60s identity+action 节流）携带嵌套 risk 证据对象（identity_key/score/risk_level/threshold/mode/policy_version/action_taken/信号全量明细）；采集落 `access_control_events.details` JSONB（000101），action 映射 REJECT/OBSERVE，不产生 temporary_blocks、不计入 CC 统计。
- **管理面**：`security_risk_policy` 单行策略（000101，乐观锁+审计+PUT 发布下发 `risk_policy` 段）；`GET/PUT /api/v1/security/risk-policy`；权限 `risk_policy.read`（三角色）/`.edit`（仅 SECURITY_ADMIN，000102）；前端风险策略页（模式/双阈值/信号分值覆盖/等级档位）。
- **修复（实况验收抓出）**：发布装配漏注入 `risk_policy` 段（网关收不到策略）；采集解析器与网关线格式失配（扁平 vs 嵌套 risk 对象，事件被丢弃）——均已修复并补测试。

### 新增（AI 自动化渗透防护增强 阶段4：Attack Session + Business Security）

> 实施文档同一（阶段4）；迁移 000103–000105。聚合只读不改写源事件；PERSISTENCE 仅占位枚举。

- **攻击活动聚合**：`attack_session` + `attack_session_event`（`UNIQUE(source_table,source_id)` 幂等）两表；60s Sweep + 30min 不活跃滑窗；四类来源水位线增量（security/api_runtime/identity_behavior/access_control 事件），request_id 首选关联、IP 反查兜底、NAT 歧义跳过计数；request_count 跨源去重、双落同请求不互去；风险累计截断 [0,100]。
- **攻击阶段推断（规则表）**：阶段秩 UNKNOWN<RECON<DISCOVERY<AUTH_PROBE<AUTHORIZATION_PROBE<EXPLOIT<DATA_ACCESS<PERSISTENCE；行为事件规则码前缀映射、运行时事件按 detector/rule 映射（waf/api_schema/api_parser→EXPLOIT、resource_access 对象访问→AUTHORIZATION_PROBE、authentication→AUTH_PROBE、lifecycle→DISCOVERY、sensitive.value 实值→DATA_ACCESS；字段名命中不抬升阶段）、安全事件命中即 EXPLOIT；会话阶段取最高秩。
- **敏感业务流滥用**：`api_assets.business_type` 13 枚举（000105，应用层校验）全链路含前端编辑；Business 三判定器（BIZ-LOGIN 登录滥用/BIZ-EXPORT 导出滥用/BIZ-OBJENUM 对象枚举，写 BUSINESS_ABUSE 行为事件，OBSERVE 1.0.0，冷却重跑零产出）。
- **管理面**：`GET /api/v1/security/attack-sessions[/{id}]`（stage/risk_level/status/时间窗筛选，`attack_sessions.read` 三角色只读）；前端攻击活动列表+详情页（阶段筛选、会话事件时间线）。
- **疑似自动化攻击标注（迁移 000106）**：会话内有效阶段≥3 且命中自动化指示信号（无头/枚举/低慢/对象枚举类）即派生 `automation_suspected=true`（单调不回退），判定依据 `automation_basis`（命中阶段集+首个指示信号）随行持久化、前端 tooltip 可解释；攻击活动列表/详情页红色徽标展示；历史会话不追溯。
- **修复（实况验收抓出）**：阶段推断检测器名对齐网关实名（authentication/resource_access）；`sensitive.field`/`sensitive.in_query` 字段名命中不再抬升 DATA_ACCESS（仅 sensitive.value 实值保留）。

### 新增（AI 自动化渗透防护增强 阶段1：Identity + Behavior + Recon）

> 实施文档 docs/WDSP_AI_PENTEST_PROTECTION_ENHANCEMENT.md（阶段1：先解决 AI 自动化侦察与低慢扫描）；迁移 000097–000099。配置缺省零行为变化；行为统计失败 fail-open 不影响转发；本阶段全部检测信号仅 OBSERVE 不拦截。

- **Client Identity 引擎（网关）**：`identitybehavior` 包按请求提取 JWT/API Key/会话 Cookie 凭据（未验签仅关联用途）、浏览器指纹（UA+Accept 系头 HMAC）、弱 TLS 指纹，三级优先级派生确定性 identity_key（cred > anon 指纹 > IP）；同一浏览器多 IP 关联为同一身份；UA 启发式分类 HUMAN/BOT/UNKNOWN；identity 经请求上下文桥接进 WDSP 统一 RequestContext。
- **行为滑动窗口（网关）**：1m/5m/30m/24h 四窗，双桶轮转估值；计数含请求量、401/403/404/405/500、认证失败、参数变异（参数名+值类别签名 HLL）、敏感路径命中、唯一 URI（HLL）、新 URI（48h 已知集）；Valkey 单 Lua 单往返原子更新（键前缀 `jiuzhang:guard:ibh`），故障 fail-open 回退进程内存（LRU 有界）。
- **Recon 检测（七条规则，全部默认 OBSERVE、版本化 1.0.0）**：RECON-URI-001 URI 枚举、RECON-404-001 404 枚举、RECON-PATH-001 敏感路径探测（可配路径表）、RECON-METHOD-001 方法枚举、RECON-PARAM-001 参数变异、AUTH-FAIL-001 认证探测、RECON-LOWSLOW-001 低慢侦察（30m/24h 长窗）；阈值/分值/白名单（IP CIDR + UA 子串）全部配置化；检测器只产风险信号不阻断。
- **身份行为事件通道**：新增 `identity-events.log` JSONL（identity_observation / behavior_snapshot / recon_signal 三种记录，进程内节流防洪泛：观测 5min、快照 60s+1m 桶轮转补发、信号 60s）→ server `identityevents` 采集器断点续传批量入库；logrotator 纳入轮转。
- **管理面**：`client_identity` / `identity_ip_history` / `identity_credential` / `behavior_statistics` / `identity_behavior_events` 五表 + `security_behavior_policy` 单行策略（版本乐观锁）；风险分按 24h 信号加分求和（截断 [0,100]），等级 0-19/20-39/40-69/70+ 四档；请求量按行为快照 1m 窗计数估算累加（估算语义）。
- **API**：`GET /api/v1/security/identities`（列表/筛选/分页）、`GET .../{id}`（详情+IP历史+凭据+近期事件）、`GET .../{id}/behavior`（窗口时间序列）、`GET .../{id}/events`（信号事件）、`GET/PUT /api/v1/security/behavior-policy`（校验、409 乐观锁、审计、触发发布经 `identity_behavior` 段下发网关）；权限点 `security_identities.read`、`behavior_policy.read/.edit`。
- **前端**：「安全风险」新分组—风险身份列表/详情页（IP历史、关联凭据、行为趋势图、行为事件）；「应用防护策略」分组—行为策略页（阈值/敏感路径/七信号分值/白名单编辑）。

### 新增（APM 阶段0+阶段1：无 Agent 业务性能监控）

> 设计 docs/BUSINESS_PERFORMANCE_APM_DESIGN.md，决策 docs/APM_STAGE0_ADR.md，批次明细见 docs/DEVELOPMENT_STATUS.md APM 小节。默认关闭（`APM_ENABLED=false`），关闭时现有行为不变。

- **网关 trace 上下文**：W3C traceparent 入口严格校验，默认新建内部 trace_id/span_id（不信任外部上下文，tracestate 不续传、不向上游注入、不向客户端返回）；统一 RequestContext 补齐 TraceID/ApplicationID/ClientIP 等关联字段；API 运行时事件携带 trace_id。
- **访问日志全量覆盖**：采集点上移至 guard 入口，人工封禁/IP 黑名单/L7/CC 拦截的 403/429 同样产生记录；新增 trace_id/span_id/endpoint_key/path_template/ttfb_ms 字段；waf_action 收口 ALLOW/OBSERVE/BLOCK 三态；端点键对纯 WAF 站点同样归一化生成。
- **端点级 RED 聚合**：`http_endpoint_requests_total`/`http_endpoint_duration_ms`/`http_endpoint_ttfb_ms` 分钟级聚合（应用×端点×状态码类别×动作），Top-200 + 未归类/其它保留桶基数护栏，幂等可重算（迁移 000088）。
- **APM 查询接口**：`/api/v1/apm/overview|services|services/{id}|endpoints|traces/{trace_id}` 五接口（权限 `apm.overview.read`/`apm.services.read`/`apm.traces.read`）；trace 检索串联访问记录与关联 WAF 安全事件；`APM_ENABLED` 开关 + edition 下发 `apm_enabled`。
- **性能告警**：端点 P95 超限与端点错误率告警（最小请求量+持续窗口防误报）；accesslog-01 采集链路数据新鲜度探针。
- **业务性能前端**：总览/服务列表/端点性能三页面（菜单分组「业务性能」），全量图表标注「数据来源：无 Agent」，未开启全量访问日志时如实降级提示。

### 新增（APM 阶段2–5：OTel 数据面、Agent 基线、诊断下钻与深度诊断）

> 部署手册 docs/APM_DATA_PLANE_DEPLOYMENT.md，运维/排障/接入手册 docs/APM_OPERATIONS_GUIDE.md / docs/APM_TROUBLESHOOTING.md / docs/APM_ONBOARDING_GUIDE.md。迁移 000089–000094；全部默认关闭，遥测链路故障 fail-open 不影响 WAF 转发。

- **Agent 控制面**：一次性注册令牌 + CSR 注册、内置 Ed25519 CA（材料加密入库）、PoP 签名心跳/策略拉取/证书轮换、签名策略版本单调递增、证书指纹撤销列表；Agent 五态生命周期；管理接口全量高风险审计（`apm.agents.manage`/`apm.settings.manage`）。
- **OTel/ClickHouse 数据面**：双层 Collector（本地+中央，脱敏双清单、有界队列、tail_sampling 错误/慢/高风险优先保留）；ClickHouse traces/metrics 标准表与分钟聚合物化视图、分层 TTL（正常 7 天/错误慢 14 天/聚合 30 天起）；镜像 digest 双架构锁定。
- **Trace 检索与瀑布**：`/apm/trace-search` 多维检索（trace_id/request_id/服务/耗时/错误），瀑布图与 WAF 访问记录、安全事件同屏关联；属性白名单透传。
- **诊断下钻**：SQL 指纹慢查询（不出原始 statement）、异常指纹聚合、服务依赖边（客户端 span 派生如实标注）、多语言运行时指标（Go 首期）、SLO 目标管理与 `APM_SLO_BREACH` 告警（错误预算 OK/AT_RISK/BREACHED）。
- **深度诊断会话**：dry_run 开销预估→二次确认创建（默认 15 分钟、最长 2 小时）、签名诊断策略叠加与到期/停止/kill switch 自动恢复基线、Agent 失联本地硬截止兜底、Critical 级审计；诊断中心页四步向导。
- **Go 自埋点与网关 tracing**：`APM_SELF_TELEMETRY_ENABLED` 管理面 OTel 埋点（traces+runtime metrics）；`GATEWAY_TRACING_ENABLED` Caddy 原生 tracing handler 下发；`trace_inject_upstream` 网关向上游注入内部 traceparent（默认关）。
- **规模化与交付**：中央 Collector router+sampler 双层 HA 与 K8s 清单、ClickHouse 双副本变体与备份恢复文档、`APM_CLICKHOUSE` 健康探针与 `APM_INGEST_LAG` 采集滞后告警、SBOM/许可证审计全量覆盖、离线包纳入 APM 组件镜像；通知类别新增「业务性能」类。

### 新增（阶段8 主体：API 安全补全与多节点/运维能力）

> 覆盖阶段8 后续全部批次（迁移 000027–000087，000047 为并发改号空缺；000016–000026 见上文阶段8 各条目），批次明细见 docs/DEVELOPMENT_STATUS.md 阶段8 小节。

- **统一引擎深化**：协议识别词表由 REST/GRPC 扩为五值（新增 GRAPHQL/SOAP/WEBSOCKET 三检测器互斥打标，事件→采集→发现链路零改动透传）；Coraza 合流——下游中断经 coraza-caddy 哨兵归因补记 `waf.downstream_intercept` 明细（不 fork coraza-caddy，归因耦合与相位局限如实声明）；参数约束词汇升级 regex/nullable/empty_allowed，required 缺失在 PROTECT 模式升为 BLOCK。
- **学习闭环与运行时策略编译**：学习任务样本目标与采集落样闭环（000027）；达标多条件判定（最小样本/独立 IP/独立身份/学习时长/成功率，`api_learning` 设置组可调）+ 达标自动产非空 Schema 候选并自动提交评审（000038）；Runtime Model Compiler（000037）：FORMAL 版本事务内编译为 API 级运行时策略（DRAFT→VALIDATED→ACTIVE 状态机、content_hash 溯源、回滚克隆上一良好版本重发布）；响应 Schema 学习闭环（000051）与响应基线下发偏离检测；参数条件关系 REQUIRES/MUTEX/CO_OCCURS 确认下发与网关运行时检测（000068）。
- **响应侧脱敏**：ResponseContext + 统一引擎响应相位 + Response Transformer（MASK/HASH/REMOVE 字段级脱敏、重编码、Content-Length 修正）；MASK_RESPONSE 决策分支；`api_mask_rules` 随发布下发；失败策略 FAIL_OPEN（默认）/FAIL_CLOSED；流式/SSE/非 identity 编码直通不缓冲。
- **findings 与弱点中心**：运行时 findings 物化入库（000036，dedup_fingerprint 幂等、证据白名单脱敏）；风险处置 8 接口与七态状态机（000042，`api_risk` 权限点）；弱点中心（000039）：`api_weaknesses` + 处置动作只增不改、四规则周期派生、FIXED 再命中自动回 REPRODUCED。
- **敏感数据管理**（000040）：敏感数据类型五级分级（7 内置类型禁删禁改名）、脱敏规则 GLOBAL<APPLICATION<ENDPOINT 优先级合并求值、敏感字段 Sweep 生产与敏感态势 overview；值级敏感检测规则下发执行（QUERY 值命中升 BLOCK，单值截断 + 单请求求值预算防 CPU 放大）。
- **规范中心增强**（000046）：导入规范版本状态机（同名单 ACTIVE 部分唯一索引）、URL 导入（SSRF 防护、抓取函数可注入测试）、Swagger 2.0 最小映射转换、跨版本 CHANGED 级 diff 与任意两版本只读对比、导入回写运行时缺失资产。
- **AuthZ 实体层**（000043/000044/000048）：BFLA 角色基线、BOLA 对象权属、字段权限七属性三张表与 13 条接口；五档 BOLA 评估（证据而非定罪）；confirmed 基线与字段权限经发布通道下发并纳入版本哈希，网关 authzcheck 运行时检测（BFLA OBSERVE 信号、`authz.forbidden_field` PROTECT 可阻断）+ 响应方向字段权限判定。
- **资产生命周期**（000045）：DEPRECATED 近 N 天仍有流量自动判 ZOMBIE（归档须人工）、deprecate/restore 接口、资产价值九维评分可解释周期回填、服务资产聚合视图。
- **主动扫描 v1**（000053/000054/000056）：授权先于执行（主机白名单/时间窗/QPS/并发/探针画像/有效期）、双人分离（建标 `api_scan.manage` 与授权 `api_scan.execute` 分离、建标人不得自授权）、撤销即停；6 内置探针集词表；证据脱敏不落原文；签名头 X-JiuZhang-Scan 流量隔离（网关签名校验，扫描流量不进学习与行为基线）；复测桥接弱点中心状态机；前端扫描页四 Tab。
- **数据出境**（000058）：自研纯 Go 只读 MMDB 解析器（零新依赖，复用已登记 country.mmdb）；出境五档判定（内网/保留地址宁漏勿误）；`api_cross_border_events` 双保险幂等生产与 cross-border 看板（geo_enabled 降级标识）。
- **AI 定时运营**（000062/000063）：自研五段 cron 解析器（零新依赖）+ next_run_at 游标 claim 防重入；五种内置运营任务纯确定性查询只产报告不做任何变更；LLM 润色失败一律回退模板；全局开关默认关；第二批 5 个 READ_ONLY `api_*` AI 工具（弱点/敏感/运行时策略/规范/态势）。
- **LLM/MCP 安全**（000066/000070）：LLM API 双重确认识别、请求/响应观测（不落原文）、Prompt Injection 词表 v1（8 条仅 OBSERVE/LOW）、未授权模型名单检测；MCP JSON-RPC 方法词表核对与 tools/call 参数值级敏感检测（证据不落参数值）。
- **gRPC 与描述符解析**（000072/000076）：gRPC 识别与 5 字节前缀帧结构校验（帧异常 PROTECT 定案 403、压缩标志 OBSERVE）；protoset 上传 → 发布下发 → dynamicpb 动态解码（编译失败逐集 Warn 跳过），字段路径级敏感值检测；源码 API 发现工具 `tools/apisrc`（Go 路由字面量 → OpenAPI3 骨架导入规范中心）。
- **文件水印/签名/合规**（000071）：文本族不可见水印 + OOXML（docx/xlsx/pptx）docProps 水印（零新依赖，pdf 显式拒绝不静默）；文件签名 `jzsig1`（HMAC-SHA256，密钥加密下发，verify/rotate 接口审计不含密钥与完整 token）；文件合规规则双相位执行（上传 403、下载缓冲抑制，直通场景诚实降级）。
- **站点资产自动发现**（000077）：mirrorcap 全端口被动嗅探（HTTP Host + TLS ClientHello SNI）覆盖 MIRROR/ROUTED/TRANSPARENT 三模式；`site_asset_discoveries` 幂等 upsert（人工处置字段不被覆盖）；管理端确认/忽略/恢复（`site_discovery.*` 权限 + 审计）与前端「站点发现」页。
- **离线授权**（000078）：`.lic` 授权文件由授权中心离线 Ed25519 签发、产品侧验签导入；唯一 ACTIVE 部分唯一索引，导入新授权同事务取代旧授权；`license.*` 权限点（设计 docs/LICENSE_DESIGN.md）。
- **HA 与多节点**：节点版本遥测校验（000069：ACTIVE/STALE/SILENT 判定 + CONFIG_HASH_MISMATCH 告警）；网关心跳（`api_node_heartbeat_seconds`，无业务流量不失活）；发布扇出 v2（000074：同一份构建产物扇出全部次要节点 /load + 规范化哈希比对 + 逐节点回填，次要节点失败不阻断主发布；节点管理地址仅内网 + 拨号时 DNS 重解析复检防 SSRF）；主备高可用（000080：ha_groups/ha_group_members + havipd VIP 漂移，设计 docs/HA_ACTIVE_STANDBY_DESIGN.md）；双节点 ha-lab 编排与验证脚本 28/28 场景实测通过（docs/HA_TWO_NODE_DESIGN.md）。
- **性能基线实测**：Baseline Proxy 5337–5499 QPS（p95 9ms）vs Full API Security（OBSERVE）3211–3540 QPS（p95 13ms、0 失败）；Coraza 全量 CRS 开销约为 API 动态防护管线的 2.7 倍（网关水平扩展首要驱动是 WAF 规则评估）；11.5 万事件洪峰约 6.5 分钟追平零丢失；原始数据见 docs/evidence/api-security-performance-baseline.md。
- **HTTP/3**：Caddy 2.11 TLS 监听默认开启 h1/h2/h3；http3-lab 旁路实测 guard 管线/真实 IP/检测器/路径归一在 h3 下全部正常，proto=HTTP/3.0 三面记录（docs/HTTP3_SUPPORT.md；QUIC 层深度解析未做如实声明）；访问控制/CC 事件补 proto 列（000075）。
- **网口管理**（000049）：节点物理网口清单快照经 sidecar 采集 UPSERT（保留人工 sort_order/role，消失的口置 present=false），权限复用 `system_health.read`/`system_settings.update` 不新增（设计 docs/NETWORK_MODES_DESIGN.md）。
- **通知渠道**（000057/000060）：通知渠道表 + 内置 syslog 渠道（企业微信/飞书/SMTP 等密值字段 AES-256-GCM 加密落库、接口读出恒脱敏），notify 组抑制参数。
- **报表调度**（000082–000086）：报告内容上篇 Web 26 节 + 下篇 API 11 节并全面中文化（内容范围 WAF/API/WAF_API 可选）；定时报告计划（每天/每周/每月 UTC 固定时刻，FOR UPDATE SKIP LOCKED 认领防重）+ 生成后邮件发送；报表删除权限、API 资产纳入与页面方向设置。
- **TOTP 双因子认证**（000033）：RFC 6238，密钥 AES-256-GCM 加密存储不落明文，恢复码只存 SHA-256 哈希。
- **L7 访问控制规则**（000032）：URI/方法/请求头/Cookie/Query/来源 IP 组合条件首中即停（allow/block/redirect/custom_page），经发布通道随 GuardConfig 下发网关执行。
- **图谱/态势/告警/报告**：调用边派生（同身份 ≤10 分钟相邻调用成边，水位与 upsert 同事务）与 identity_count 持久化（000067）；API 态势 overview/trends/sources/targets 全真实 SQL 口径；API 专项告警三类型与告警静默/恢复（000055）；API 专项报告四类型（000059）；敏感文件资产与同身份批量下载风险（000061）；API 专项指标 15 项与 API_SECURITY 健康探针；用途分类内置业务种子与词表扩充（000073/000087）；OpenAPI 全量对账 504 条路由与文档零差集。

### 变更（阶段8 主体）

- 发布通道扩展：`gateway_runtime` 组六键（behavior_store/identity_salt 等）+ 正式模型版本 + 脱敏规则 + `api_policy_version` 内容哈希随整站发布下发；读取失败或取值非法中止发布（脱敏规则段缺失容忍 Warn 跳过）。
- `api_runtime_events` 扩充审计列（000035：client_ip/method/raw_path/latency_ms/model_version/policy_version，可空不伪造 0 值）；API 放行流量事件改为响应完成后输出（真实 response_status 与 latency_ms）。
- 运行时事件与全量访问日志两采集器由「EOF 才 flush」改为批量（默认 2000 行）/周期（默认 2s）flush 且断点同节奏落盘（崩溃重扫量有界，`WAF_COLLECTOR_FLUSH_BATCH`/`WAF_COLLECTOR_FLUSH_INTERVAL` 可配）；每个 flush 批次副作用与主事件并入单 DB 事务整批提交（失败整体回滚、断点不前移、重放幂等）。
- `api_runtime_findings` status 词表由注释约定四态升级为七态 CHECK 约束（存量 OPEN→NEW、ACKNOWLEDGED→IN_PROGRESS）。

### 修复（阶段8 主体）

- 全流程走查修复批（000079，真实「建站→发布→攻击→核验」走查暴露）：安全事件补 application_id 站点归属（Host 映射缓存 + 存量回填）；attack_type 误分类改严重度优先（存量同口径重算）；动态发布配置补错误路由（403 阻断页 + 正常/透传响应全覆盖 X-Jiuzhang-Request-ID 头）；被拦请求全量访问日志 response_status=0 改从错误链兜底取状态码；网关日志新增 logrotator sidecar 轮转（copytruncate，写入方 fd 不中断、采集断点自动重置）；五个采集器轮转判定即落断点（消除空文件期重复刷日志）。
- accesslogs 采集器断点按完整行累计错位与 EOF 落盘失败静默两处同域缺陷。
- 运行时策略查询 policySelect 列歧义导致恒 500（JOIN 后 42702，逐列补表前缀）。
- 网关心跳采集装配遗漏（`SetHeartbeatRecorder` 未在装配层接线，心跳已采集但不落 `api_gateway_nodes` 致节点活性/版本视图失真），ha-lab S3/S4 场景复测全通。

### 新增（设备运维控制台）

- `jiuzhang-console`（`server/cmd/console` + `server/internal/sysconsole`）：硬件服务器定制运维后台，
  专用账号（`jiuzhang-ops` 登录 shell）+ bcrypt 口令认证（`/etc/jiuzhang/console.yaml`，无默认口令，
  5 次失败退出）→ 白名单 REPL：`show sysinfo/network`、`set mgmt-ip/route/dns`、`ping`、`passwd`；
  参数全部经白名单校验，输入不交 shell 执行；网络变更经 sudoers 精确放行的唯一 root helper
  `ops/console/netapply.sh`（netplan 重写托管文件 + 备份，nmcli 兜底）；SSH 侧对该账户 ForceCommand
  强制进控制台并禁用转发/sftp；审计优先写 syslog（客户无权清除），兜底 `/var/log/jiuzhang-console.log`。安装：`ops/console/install-console.sh`（初始口令随机生成仅打印一次）。

### 新增（syslog 日志外发覆盖六类业务日志）

- syslog 外发范围由 3 类（安全事件 / 访问控制事件 / 全量访问日志）扩展至 6 类，新增**操作审计、登录日志、系统告警**：三者入库成功后经装配层闭包注入的投递函数非阻塞入队（避免包间循环依赖，模式同 `backups.AlertFunc`），外发失败（含 panic）不影响主流程；系统告警仅新建 OPEN 时外发，合并去重防循环放大。
- severity 映射补充：系统告警按等级 CRITICAL→2/HIGH→3/MEDIUM→4/LOW→5，登录失败与删除/禁用类审计→warning(4)，其余→info(6)；RFC5424 MSGID 新增 `operation-audit` / `login-log` / `system-alert`。
- 新增 3 个设置键（迁移 000050，`system_settings` logging 组，boolean 默认 true）：`syslog_forward_operation_audits` / `syslog_forward_login_logs` / `syslog_forward_system_alerts`，加入设置白名单，复用既有 `system_settings.update` 权限，不新增权限点。
- 测试：syslogfw 类型开关/severity/MSGID 单测，audits/loginlogs/systemalerts fan-out 单测（投递、nil 安全、panic 容忍、合并不重复外发），集成测试覆盖新设置键 PUT 200/400 与 Record 写库后投递。
- 文档：`docs/SECURITY_DESIGN.md` 新增「日志外发（syslog）」小节（架构、报文格式、六类范围、配置项表、可靠性语义）。

### 新增（三微模型增强批：参数/身份/访问）

- **参数微模型**：网关脱敏值观测（`param_observations`：length / value_hash / num，无明文）→ 表 `api_parameter_value_obs`（迁移 000031）→ 统计画像回填长度/值域/基数 → recommended 可真正产出；PATH/COOKIE 约束消费；`semantic_type` 启发式推断并下发网关；BODY 对象标识联动；参数关系 CO_OCCURS 候选只读；`POST .../models/{id}/parameters/confirm-batch` 批量采纳推荐约束。
- **身份微模型**：`api_identity_profiles` 离线聚合写入 + `GET /api-security/identity-profiles`（质量分）；JWT 结构级 OBSERVE（alg=none、kid 穿越、空签名、exp 过期，不验签）；管理面「身份画像」页 `/api-identity-profiles`（WDSP 能力门控 + `api_runtime.read`）。
- **访问微模型**：同凭据非常规小时 / UA 族突变 / 环境异常叠加信号（均 OBSERVE）；对象标识扩展至 Body 语义类型字段。
- **运营**：模型成熟度卡片钻取到参数模型 / 身份画像；集成测试 `TestStage8IdentityProfiles`、`TestStage8ParamValueObservations`。
- **身份画像详情**：`GET /api-security/identity-profiles/detail`（画像 + 五级风险评估 + 该指纹最近 10 条运行时事件，`api_runtime.read` 只读）；风险评估映射 GB/T 31509 修订稿（5.2.3 威胁频率 / 5.3.3 定性矩阵法）：可能性（高危事件分档，24h 密集上调、全数拦截消减）× 严重程度（最高风险分五档）经 5×5 矩阵定级 VERY_LOW…VERY_HIGH，只产信号不阻断；管理面身份画像列表行可点击打开详情抽屉；OpenAPI 补齐 identity-profiles 列表/详情文档。
- 纪律不变：检测器只 AddMatch；身份不由 IP 冒充；观测值不落证据明文。

### 新增（攻击变种 / 编码绕过增强包，+99 条）

- `attack-variants-evasion.conf`（99，ID 1001201–1001299，`ver: CUSTOM_PACK/1.4.0`）：面向同一攻击类的变形写法与 WAF 绕过手法，**不复制第三方 WAF 产品规则**。
  - 编码层：双重 URL / overlong UTF-8、全角与零宽字符、空字节截断、UTF-7、`%uXXXX`、双重 HTML 实体、半编码路径混用；
  - SQLi：注释/空白拆关键字、条件注释 `/*!50000*/`、时间/布尔/UNION/报错/堆叠、OOB(`into outfile`/`load_file`/`utl_*`)、CASE/IF 盲注、hex/unhex、高危参数旁拼接；
  - XSS：事件处理器、SVG/MathML、`javascript:`/`data:`、实体编码 script、srcdoc/formaction、DOM sink、CSS expression；
  - RCE：管道/逻辑连接、`$IFS`/ANSI-C quoting、PowerShell `-enc`、Windows LOLBins、brace/`/dev/tcp`、解释器一行执行；
  - LFI/RFI/SSRF：多级穿越、PHP wrapper、回环地址编码、云元数据、URL 凭据混淆；
  - Log4j/Struts 更深绕过：嵌套 lookup、全角 `${`、JNDI 协议族空白插入、单字符重构、OGNL Runtime 链、`%{...}` 强制求值；
  - XXE/反序列化/协议：参数实体、XInclude、Java/PHP/pickle 序列化头、TE/CL 走私、Host/Cookie 载荷走私、上传双扩展/NTFS ADS/`filename*`、JWT alg=none、GraphQL 内省。
- 本包由初版 54 条扩至 **99** 条（ID 段用满 1001201–1001299）；自建包总量 **500 → 545**（与 `TestCustomPackParses` 统计一致）。发布网关后执行 `POST /api/v1/waf-rules/sync` 同步元数据。

### 新增（开源 Web 系统 CNNVD/CVE + 加密 WebShell，+89 条）

- `oss-webapps-cve.conf`（50，ID 1000900–1000950）：WordPress/Drupal/Joomla/Discuz/DedeCMS/帝国 CMS/ThinkPHP/Laravel/Shiro/Fastjson/Struts2/Solr/XXL-JOB/若依/Jeecg/UEditor/泛微/致远/用友等公开利用路径与特征（依据公开 CVE/CNNVD 同源情报自行编写，非抄录第三方 WAF）。
- `webshell-obfuscation.conf`（39，ID 1001000–1001040）：多层编码链、动态函数、openssl/AES 加密马、蚁剑/哥斯拉/冰蝎痕迹、图片马、双扩展上传、defineClass 内存马等。
- 自建包总量 **297 → 386**。

### 新增（自建规则包二期扩展 +140 条）

- 新增 4 个自建包（ID 段 1000500–1000899，`ver: CUSTOM_PACK/1.1.0`）：
  - `sensitive-exposure.conf`（40）：`.git`/`.env`/密钥/备份/Actuator/IDE/CI 等敏感暴露；
  - `deserialization-rce.conf`（30）：Java/PHP/Python/.NET 反序列化、OGNL/SpEL/SSTI、LOLBins；
  - `bot-protocol.conf`（35）：危险方法、走私/TE、路径覆盖头、扫描器 UA、上传可执行文件、GraphQL 放大；
  - `cve-recent.conf`（35）：Tomcat/JBoss/Confluence/Exchange/Jenkins/Nacos/WebLogic 等组件利用路径。
- 自建包总量 **157 → 297**；加载路径不变（`Include /etc/caddy/rules/contrib/*/*.conf`）。发布后执行 `POST /api/v1/waf-rules/sync` 同步元数据入库。

### 新增（规则量扩展：多规则包体系）

- 规则库从单一 OWASP_CRS 扩展为多包结构：CRS 官方插件（incubator，PINNED）、第三方应用白名单包（wordpress/nextcloud rule-exclusions，Apache-2.0，PINNED）、自建包（CVE 应急/WebShell/扫描器指纹/云滥用/API 滥用，共 157 条）；规则总量 622 → 979。
- 自建包覆盖：log4j2/Spring4Shell/Confluence/ProxyShell/fastjson/Shiro/ThinkPHP/Struts2/未授权中间件、China Chopper/蚁剑/哥斯拉/冰蝎、sqlmap/nuclei/AWVS/敏感路径扫描、SSRF 云元数据/k8s/docker.sock/ES、GraphQL 内省/JWT alg=none/批量赋值/CRLF/XXE/路径穿越。
- 同步管线多来源去重入库（rule_source 隔离），发布按官方顺序 include（插件 config/before/after + contrib）。
- AI 规则生成闭环：降噪簇一键生成自定义规则草稿（DISABLED，人工审核启用），端点 `POST /api/v1/ai/noise/clusters/{id}/draft-rule`。
- 诚实排除：antivirus（`@inspectFile`）与 body-decompress（Lua `SecRuleScript`）插件经实测 Coraza 不支持已移除；Atomicorp 免费规则因许可证禁止再分发不入库。

### 新增（阶段8 / WDSP：统一 Web 与 API 动态防护）

- 统一动态安全引擎挂接 `jiuzhang_guard` 请求链：一次解析（JSON/form/XML/multipart/GraphQL）→ API 识别 → 路径归一 → 检测 → 统一决策；`api_dynamic_protection=false` 时行为与纯 WAF 完全一致。
- 运行时检测器：Schema 偏离、身份信号、认证有效性、敏感数据（URL 明文升 BLOCK）、BOLA 辅助、生命周期（已知端点基线）、行为滑窗、API 写限速。
- 统一运行时事件流：网关 JSONL → 管理面采集器 → `api_runtime_events`（request_id 幂等），API 端点由流量自动发现；冻结模型与已知端点基线经配置发布下发网关。
- 数据库 27 张表（迁移 000016-000018）与 27 个权限点（000019）；`/api/v1/api-security/*` 43 条接口（全量权限校验与操作审计，openapi.yaml 收录）。
- 模型版本生命周期（候选→评审→正式/拒绝/取代/归档）、参数模型、用途分类、API 图谱与拓扑、OpenAPI 规范导入对比、风险发现与安全态势。
- API 动态防护策略接口（模式 OFF/OBSERVE/PROTECT，settings 覆盖优先，发布到网关）。
- 10 个 `api_*` AI 工具（全部 READ_ONLY：AI 不得确认模型、发布或修改资产）。
- 管理前端 12 个阶段8 页面（端点资产、模型版本、学习中心、参数模型、用途分类、敏感数据、规范对比、安全图谱、调用拓扑、接口风险、影子与僵尸接口、接口策略）。
- `make stage8-*` 自动化命令 23 个；测试：接口集成 9/9、全链路 15/15、回放 10/10、安全 11/11、性能 5/5、前端 E2E 6 通过、纯 WAF 回归 40/40（详见 docs/STAGE8_TEST_REPORT.md）。
- 专项设计文档 15 份（统一架构/RequestContext/发现/归一化/参数/学习/版本/分类/Schema防护/身份/授权/敏感/行为/图谱/产品分离）。

### 修复

- 发布版本号秒级时间戳在快速连续发布时撞唯一约束，改为毫秒时间戳并支持序号重试。
- 模型版本号改为候选创建时分配，首个正式模型版本号为 v1。
- 前端 dev 代理前缀 `/api` 与阶段8 页面路由冲突导致整页刷新 404，收敛为 `/api/v1`。
- stage5 网关测试的多级代理用例改为按 Docker 子网动态取可信跳地址。

### 新增（阶段8 增补：站点与目录组织）

- 接口端点资产支持站点归属：发现链路经 `app_code`/Host 解析回填 `application_id`/`domain_id`（缓存解析器，人工改属不被命中覆盖）；新增目录维度（`directory_path` = 归一化路径去掉最后一段，迁移 000020 回填）。
- 新接口 `GET /api-security/endpoints/site-summary`（站点计数+未归属）与 `GET /api-security/endpoints/directory-tree`（目录聚合）；列表接口新增 `directory_path` 前缀与 `unassigned` 过滤并带出站点/目录列。
- 端点资产页改为左右两栏：左侧站点列表（计数角标）与目录树，右侧表格新增目录/站点列与可关闭过滤标签。

## [2.1.1] - 2026-07-23

### 安全修复

- **WDSP**：显式配置无效的 `API_DYNAMIC_PROTECTION_ENABLED` 时改为失败关闭，避免配置拼写错误意外启用 API 动态防护能力。

### 修复

- **WAF**：修复 Kimi 前端启动器同时传入互斥的 `--auto` 与 `--prompt`，导致真实 Kimi CLI 在执行任务前直接失败的问题。
- **WAF**：修复 Kimi 失败提示中的退出码变量边界，并增加与真实 CLI 参数约束一致的离线回归测试。

## [2.1.0] - 2026-07-23

### 新增

- **WDSP**：增加独立部署覆盖配置，明确开启 API 动态防护能力。
- **WAF**：增加 Codex 编排 Kimi CLI 的前端协作机制，使用独立 Git worktree、明确任务书和本地运行记录隔离 Agent 开发。
- **WAF**：增加前端改动范围检查与回归测试，阻止 Kimi 修改 Git 历史、其他工作树、后端或部署文件，以及通过相似路径和符号链接越界。
- **WAF**：增加前端任务与修复轮次模板，明确 Kimi 与 Codex 的职责、敏感信息边界和独立验收要求。

### 变更

- **WDSP**：接口防护菜单、前端直达路由和后端 API 路由统一受产品能力控制。
- **WDSP**：WAF 产品形态及能力探测失败时安全隐藏接口防护，避免仅凭管理员角色暴露 WDSP 功能。
- **WDSP**：后端镜像构建上下文纳入动态安全模块，修复启用 WDSP 后本地替换模块不可见导致的构建失败。

## [2.0.2] - 2026-07-23

### 修复

- 访问控制事件采集器使用断点前缀指纹识别 inode 与文件大小均未变化的日志轮转，避免轮转边界漏采日志。
- 断点只推进至完整 JSONL 行，并校验断点范围，避免半行补齐后永久丢失及损坏断点导致异常内存分配。
- CI 不再生成未消费的 Go 覆盖率文件，避免 GitHub 托管工具链缺少 `covdata` 时误报失败。

## [2.0.1] - 2026-07-23

### 安全修复

- 生产环境缺少或配置无效 `JIUZHANG_MASTER_KEY` 时拒绝启动，避免敏感配置在不可加密状态下运行。
- 认证中间件实时校验持久化会话、用户状态、角色和权限；撤销会话、禁用用户或调整权限后立即生效。
- 会话撤销和缓存索引维护不再静默忽略错误，密码修改与角色变更使用数据库事务保证原子性。
- 可信代理后的管理端连接 IP 按可信 CIDR 解析，避免伪造转发头污染审计日志和限流判断。

### 修复

- 最后一名系统管理员保护与升级任务创建改为数据库并发互斥，消除并发请求绕过。
- PostgreSQL 连接串使用标准 URL 编码和主机端口拼接，支持特殊字符密码与 IPv6 地址。
- 网关发布与回滚在无法读取旧配置、切换当前版本失败或恢复失败时准确终止并回滚，避免控制面显示成功但数据面状态不一致。
- 修复阶段7端到端用例的前端静态检查错误。
- 修复统计分析页无权限时错误提示为空的问题，并补充统一查询错误组件测试。

### 文档

- 新增前端 UI 风格指南，统一 WAF 与后续产品线的管理面视觉规范。

## [2.0.0] - 2026-07-22

### 新增

- 阶段7：AI 智能安全运营中心
  - 模型网关、Orchestrator、多 Agent、受控 Tool、SSE 会话与一次性分析；
  - 草稿/推荐（accept/reject）、Prompt/Memory/审计/成本/评估；
  - `AI_ENABLED` 独立启停；评估集 UI；事件详情一键 AI；
  - Tool 清单补齐（访问/WAF/CC 日志摘要、域名/源站、配置版本、统计排行等）；
  - 文档：`docs/STAGE7_TEST_REPORT.md`、`docs/AI_SECURITY_TEST_GUIDE.md`。
- M-22 例外策略 PUT；M-23 AI 草稿走完整 ValidateInput；M-24 CC 到期/解封访问控制事件。

### 修复

- 阶段4–7 安全与功能合并修复（见 `docs/tasks/STAGE_4_7_REMEDIATION_PLAN.md`）
  - 访问控制版本快照/API 脱敏 Valkey 密码；回滚注入运行时密钥；List 仅返回元数据；
  - 防护策略绑定/解绑 API 与前端；启用自定义规则写入发布 WAF directives；
  - **规则覆盖 rule_overrides**：CRUD API、优先级解析、发布注入 `ctl:ruleRemoveById`、WAF规则页管理；
  - 发布加载例外失败则任务失败；临时例外纳入 janitor 到期；
  - 保护地址仅按客户端 IP 放行；人工临时封禁优先于白名单；全局 TEMP_BLOCK 使用全局 ban key；
  - TEMP_BLOCK 在 Valkey Put 失败时保留 localOnly，Refresh 不再冲掉本地封禁；
  - 共享 engine 可重建、禁止半初始化；429 Content-Type 顺序修正；prod 默认 fail-closed；
  - 维护模式中间件拦截写操作；报告僵尸任务 WORKER_LOST 回收；访问控制版本前端页。

### 既有

- 阶段6：安全态势、统计报表、运行监控与正式交付
  - 统一指标模型与三级聚合（访问日志采集、幂等 upsert、迟到修正）、安全态势首页与 11 个统计分析接口；
  - 报告系统（日报/周报/月报/自定义，HTML + 中文 PDF，异步任务，哈希/权限/审计）；
  - 运行监控（10 类组件快照）与系统告警（18 类，合并/抑制/自动恢复）；
  - 加密备份（.jzbk 分块加密+尾部清单+五级验证）、隔离恢复与正式恢复、备份导入（全新环境恢复）；
  - 升级包/预检/执行/失败自动回滚、交付检查 22 项、离线部署包与安装向导；
  - SBOM（SPDX/CycloneDX 557 组件）与许可证审计、ops 运维脚本集、三权管理员手册与运维手册；
  - 前端「安全态势/报表中心/系统运维」11 个页面。
- 阶段5：IP访问控制、真实客户端IP识别与CC防护
  - 自主 jiuzhang_guard Caddy 模块（真实IP识别/可信代理/保护地址/黑白名单/CC限速/临时封禁/事件输出）；
  - 真实客户端IP识别（仅可信代理才信代理头，链遍历、超长链、伪造检测、映射归一）；
  - 全局/应用黑白名单（CIDR、临时规则自动失效、批量导入导出防公式注入、从事件建黑名单）；
  - CC防护（令牌桶/滑动窗口，按IP/应用/IP+URI限速，观察/429/临时封禁，Valkey 与有界内存双计数后端，Fail-open/Fail-closed）；
  - 访问控制事件统一采集入库（断点续传）与配置版本快照/回滚；
  - 管理前端「访问控制」五个页面。
- 阶段4：WAF策略和事件中心
  - 三套内置防护策略模板（宽松/标准/严格）+ 自定义策略，策略参数（模式/PL/阈值）发布下发网关；
  - CRS 4.28.0 规则元数据同步（622 条）与查询、策略级/应用级规则覆盖；
  - 自定义规则（结构化编辑 → SecLang，白名单校验，危险内容拦截）；
  - 例外策略（精确/临时/宽泛受控，宽泛强制风险确认，临时到期自动失效）；
  - 安全事件中心（采集器断点续传、事件标准化与脱敏、处置/备注/相关/CSV 导出、一键建例外）；
  - 管理前端「WAF策略」「事件中心」六个页面，审计管理员只读可见。
- 阶段3：Web应用接入、源站、证书与网关配置发布
  - 应用/域名/源站/证书管理与 SSRF 防护连通性测试；
  - 确定性 Caddy 配置生成、发布任务状态机、版本管理与回滚、失败保护；
  - 管理前端应用防护分组六个页面。
- 阶段2：身份认证、三权权限与系统基础
  - Argon2id 密码策略、图形验证码、服务端会话、登录锁定、CSRF 三重防护；
  - 三权互斥 RBAC、用户管理、登录日志、操作审计（哈希链）、系统设置；
  - 管理前端登录/工作台/用户/角色/日志/审计/设置/个人中心。
- 阶段1：网关技术验证
  - xcaddy 构建 Caddy v2.11.4 + coraza-caddy v2.5.0 + CRS 4.28.0 自定义镜像；
  - 三种防护模式、go-ftw CRS 回归、Request ID 全链路、Admin API Unix Socket、配置发布/回滚验证。
- 阶段0：项目初始化
  - 建立标准仓库目录结构；
  - 编写 AGENTS.md、README.md、THIRD_PARTY_NOTICES.md；
  - 建立 Docker Compose 基础环境；
  - 初始化前后端空项目；
  - 建立 CI 配置；
  - 编写开发状态文档。
