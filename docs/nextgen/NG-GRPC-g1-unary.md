# NG-GRPC gRPC G1（unary 有界深度检测）阶段级冻结设计（S5 设计稿，2026-10-06）

> 依据：`docs/WDSP_API_WAF_NEXTGEN_RD_PLAN.md` §10 全节（方向五：gRPC 有界深度检测——分期范围/技术设计/执行与验收）+ §14.2（性能候选门槛）+ §14.3（数据保护/outbox/时钟纪律）+ §15.2 NG-GRPC-01~03（三行完成证据）+ §16.2 NG-T-R01~R06（测试矩阵逐条）。
> 阶段级冻结：G1 三任务（01 帧读取/描述符/有界解压、02 字段深检与协议化执行、03 管理配置与覆盖统计）共享同一帧读取器、描述符注册表与协议化执行面，不可分割设计；本文一次冻结契约与决策点，按 §5 拆分分批实施。
> 前置事实（inventory 复核 2026-10-06）：
> - **帧与识别现状**（W14-GW/P2-05 v1 + W14-DESC 深化）：`gateway/dynamic_security/parser/parse_grpc.go`——Caddy 已终结 HTTP/2 传输层，到达引擎的请求体即 Length-Prefixed 帧序列；逐帧 5 字节前缀（压缩标志+大端声明长度）结构校验，三种畸形形态（truncated_frame_prefix / frame_exceeds_limit（默认上限 `DefaultGRPCMaxFrameBytes` 4MiB）/ length_exceeds_remaining）；截断体纪律（超 MaxBodyParseBytes 只留样本，样本边界不判 length_exceeds_remaining）；首帧消息瞬时留存（仅未压缩完整首帧、raw 子切片零拷贝、不落事件/日志）。识别：`IsGRPCMediaType`（`application/grpc` 与 `application/grpc+<suffix>`，**不含 grpc-web**）+路径形态双重确认（classifier.ClassifyGRPC 拆分 /package.Service/Method）；endpoint_key 全保留（EndpointKeyPreserve，服务/方法名即端点稳定身份）。
> - **描述符现状**：迁移 000076 `api_grpc_descriptors`（name 唯一/content BYTEA ≤1MiB/content_hash sha256/services JSONB 摘要/status ENABLED）+ 管理面 `apigrpcdesc`（RegisterRoutes CRUD）→ 发布链 `guardconfig/grpc_descriptors.go` 按 name 稳定序下发 `[{name, content_base64}]` → 网关 `grpcdesc` 装配编译（protodesc.NewFiles 集内自闭合 + dynamicpb 注册表，≤1MiB/集 ≤64 集；失败集 Warn 跳过降级帧结构观测）→ `Registry.Lookup(service, method)` **全局**查找（无 per-app 绑定——同名服务跨应用共用同一注册表）。
> - **检测现状**（`detectors/grpc.go` + `grpc_desc.go`）：帧结构观测 grpc.observed（INFO，计数+声明体量+decoded/descriptor 键）；畸形帧 grpc.malformed_frame（BLOCK 类——现状实断走 **HTTP 403 平面**（统一决策定案），非 gRPC 协议错误形态）；压缩只允许/禁止二态（allow_compression=false 时压缩标志产 grpc.unexpected_compression OBSERVE，**压缩帧不解无解压能力**）；有注册表时解码首帧→WalkStringFields（深度 8/256 字段/512 求值/20 命中）→值级敏感规则（与 JSON 同规则）→grpc.sensitive_field（OBSERVE，只字段路径+规则名不落值）；grpc.decode_error（OBSERVE/LOW，与 malformed_frame 区分）。**无 repeated/map/oneof 结构校验、无枚举/长度域校验、无未知字段策略**。
> - **能力自报现状**（`capability_report.go`）：`protocols.grpc="frame"`（有描述符下发时升 `"unary_g1"`）；detectors 清单 `grpc.frame=grpc/1`、有注册表时报 `grpc.unary`。
> - **管线挂接现状**（pipeline.go）：`classifier.ClassifyGRPC` 命中即 CheckGRPC（不挂 api.IsAPI 分类门槛）；`api.protocol=GRPC` 打标进事件与端点发现。
> - **缺口对照**（§10/R01~R06）：分片帧重组读取器（现状要求完整请求体）、有界解压（gzip）、字段结构校验（repeated/map/oneof/枚举/长度/未知字段）、协议化执行面（grpc-status/grpc-message trailers 形态而非 HTTP 403）、覆盖账本 gRPC 专项五态、缺描述符的「不称完整深检」覆盖语义、描述符↔应用绑定、cancel/deadline 资源释放显式设计。
> - **发布链/能力门/覆盖账本接入点**（S1~S4 先例）：快照段随 api_policy_version 版本戳；能力门 `detectors.<name>=<ns>/<N>` 序数比较（az/3、flow/1 先例）fail-closed `CAP_MISSING`；覆盖五态（SKIPPED/FULL/PARTIAL）管线检测器调用段接入点；`E=0 强制 no_applicable_traffic=true` 纪律。

## 1. 冻结契约

### 1.1 G1 范围与流量判定（NG-GRPC-03；D1）

**G1 = unary-only 有界深检**：unary 请求（单消息帧）+ unary 响应的协议校验与字段深检；批准的压缩算法（gzip，§1.5）；描述符校验与 repeated/map/oneof 结构语义（§1.4）。**不代表**支持所有 codec、gRPC-web 或任意流（§10.1 原文）。

判定形态（冻结）：
- **gRPC 候选**：`IsGRPCMediaType(Content-Type)`（application/grpc / +suffix——+json 等编码变体按帧结构校验但**字段深检仅 proto**（+json 变体不做 protobuf 解码，覆盖 SKIPPED(non_proto_codec)，不冒充深检））且方法 POST 且 `:path` 形如 `/package.Service/Method`（恰好两段非空——现状 classifier 口径冻结）。
- **streaming 降级**：识别为 gRPC 但请求帧序列 >1 条消息（client streaming）或响应为多消息流（server streaming——响应侧首帧后仍有后续帧）→ **明确降级**：覆盖状态 `SKIPPED(streaming_degraded)` + `grpc.streaming_observed` OBSERVE 明细（方向/首消息序号/不冒充深检文案）；**不是**「只检首帧」（§16.2 R05：首条正常第二条违规的用例不得报告「整个调用通过」——降级即如实声明不覆盖，不是部分通过）；帧结构校验仍然执行（结构畸形照判，与深检无关）。
- **非 gRPC**：零行为（grpc 检测器 SKIPPED，与现状一致）。

### 1.2 帧读取与有界重组（NG-GRPC-01；NG-T-R01；D2）

**流式帧读取器**（新 `parser/grpcframe`）：不从「完整请求体」假设出发，按数据片段流式重组（跨 TCP/HTTP 片段的消息边界正确处理，§10.2）：

- **先验证声明长度再分配内存**：读满 5 字节帧头 → 校验压缩标志位合法（bit0；其余位保留位非零按畸形）→ 校验声明长度 ≤ 单消息上限（**`MaxGRPCFrameBytes` 默认 4 MiB 现状冻结**）→ 按声明长度分配并读满消息体；声明长度 > 上限即拒绝（frame_exceeds_limit，**不分配**）。
- **请求侧预算**：单消息 ≤4MiB；单请求消息数 **≤64**；单请求声明合计 **≤16MiB**；网关总 gRPC 缓冲（并发读取器合计内存）**≤64MiB**（超限对新连接按 §1.6 RESOURCE_EXHAUSTED 协议化拒绝——预算端到端计算（§14.1），取值理由：4MiB×16 并发全消息驻留上限，与现状行为面存量不冲突）。
- **畸形处置（不错位读取、不污染后继请求）**：读取器为显式状态机（读帧头→读消息体→复位）；任何畸形（截断帧头/超上限/声明超剩余/保留位非零）→ 该请求按 §1.6 处置（OBSERVE 记录 grpc.malformed_frame / PROTECT 协议化拒绝）并**丢弃该请求后续体**（不再走帧）——读取器自身状态随请求生命周期销毁，**不存在跨请求状态**（Caddy 已终结 h2，请求体即帧序列边界天然封闭——「不错位」即不把一个请求的畸形残留带入下一请求，本形态天然成立，测试以同连接双请求前请求畸形后请求正常验证）。
- **与公共解析预算衔接**（§10.1 明示问题）：帧读取器走协议专属读取预算（本节），**不经过**公共完整 Body 解析上限（1MiB）——公共 `BodyTruncated` 样本逻辑对 gRPC 仅用于非深检观测面；深检路径以帧读取器全量读（受本节四重预算约束），读超预算即 PARTIAL 覆盖如实（非「完整深检」）。

### 1.3 描述符来源、编译与绑定（NG-GRPC-01/03；NG-T-R03；D3）

- **来源**：管理面登记 FileDescriptorSet（`protoc --descriptor_set_out --include_imports` 标准产物，集内依赖自闭合）——**反射（Reflection）不支持**（§10.2 明文：不在热路径访问 Reflection 服务；网关运行时无反射客户端）。
- **编译**：复用现状 `grpcdesc`（protodesc.NewFiles + dynamicpb，≤1MiB/集 ≤64 集）不动；装配失败集 Warn 跳过降级（现状纪律）。
- **绑定（新增）**：描述符集↔应用绑定表（迁移 000179，`api_grpc_descriptor_bindings(descriptor_id, application_id)`；**空绑定=全局生效**（现状语义）；应用存在任一绑定行时该应用**只用**其绑定集编译的注册表——同名服务跨应用各自深检各自消息，不错配描述符解错消息（正确性问题：同 /pkg.Service/Method 在两应用可能对应不同 proto）。注册表按应用维度装配（app→Registry），未绑定应用走全局注册表。
- **缺描述符红线（R03/NG-GRPC-03）**：该服务/方法未在（绑定）注册表登记 → **不称完整深检**：覆盖 `SKIPPED(no_descriptor)`，只做帧结构观测（grpc.observed 含 `matched=false`，现状键形）；PROTECT 下字段深检类策略**不适用**（不误断——缺描述符不是违规证据，UNKNOWN 恒不阻断红线同 AZ/FLOW 纪律）；管理面展示「未登记描述符的服务」清单（from 端点发现的 GRPC 协议端点 vs 注册表方法集——NG-GRPC-03 覆盖统计的一部分）。
- **版本管理**：描述符版本=集名+content_hash（现状列）随快照下发并纳入 api_policy_version 版本戳（现状已含——集合变化自然戳动）；实例观测证据 `descriptor` 键=集名（现状）。

### 1.4 字段深检语义（NG-GRPC-02；NG-T-R03；D4）

dynamicpb 解码后首期检查集（**可交付可验证，不画饼**；不重新序列化正常请求（§10.2 红线——检查只读））：

1. **结构校验**（新增 `detectors/grpcguard/structure.go`）：
   - 嵌套深度 ≤8（现状 walk 深度冻结）；
   - repeated 元素数 ≤1024/字段；map 条目数 ≤1024/字段；消息字段数（遍历产出）≤256（现状常量冻结复用）；
   - string/bytes 字段长度 ≤256KiB/字段（值级规则求值输入与现状截断 256 字符**不同层**——这是结构预算不是检测截断；§11.2-4 教训「不能只检查截断后的 256 字符」：结构超长本身即违规事实）；
   - oneof 语义：dynamicpb 解码天然保证单值——解码期 oneof 多值线格式异常即 decode_error（现状键）如实，不另立违规；
   - 枚举值域：值不在描述符枚举域 → `grpc.enum_out_of_range`（OBSERVE/PROTECT 按模式）；
   - 未知字段：**容许并计数**（proto3 兼容语义——未知字段是前瞻兼容正常形态，不作违规；遍历计数进观测证据 `unknown_fields`；§10.2「未知字段」覆盖项的承接口径：感知但不惩罚）。
   - 字段存在性按 protobuf 语义：默认值（零值/空串/false）**不误当缺失**（§10.2 明文）——required 判定不在 proto3 语义内，本批不做「必填缺失」类规则。
2. **值级敏感规则**（现状复用不动）：WalkStringFields → CompiledSensitiveValueRule（与 JSON 同规则）→ grpc.sensitive_field（OBSERVE）。
3. **结构违规定案**：`grpc.field_violation`（证据=字段路径（proto 名点路径）+规则名+读取量，**不落值**）——OBSERVE 缺省/PROTECT 按 §1.6 协议化执行。
4. 线格式损坏 → grpc.decode_error（现状）与结构违规严格区分（坏消息不是违规消息——UNKNOWN 范畴不升级实断）。

### 1.5 压缩有界解压（NG-GRPC-01；NG-T-R02；D5）

- **批准算法**：`grpc-encoding: gzip` 唯一（identity 即未压缩为基线）；其余 encoding 值 → **协议化 `UNIMPLEMENTED`**（grpc-status=12——这是 gRPC 规范语义（服务器不支持该编码的标准应答），**不是安全误断**；OBSERVE 模式则只记录 `grpc.unsupported_encoding` 转发不动）。
- **四重预算（联合压缩标志位判断）**：压缩字节 ≤4MiB（单消息上限同源）、解压字节 **≤16MiB**、倍率 **≤100×**、CPU 工作预算（解压纳入单请求处理时延预算 §1.7）；超限即 `grpc.compression_budget_exceeded`（OBSERVE/PROTECT 按模式，PROTECT=RESOURCE_EXHAUSTED(8)）——**不无限解压**（流式 gzip.Reader 配 io.LimitReader 双层（解压字节+倍率）读断）。
- `allow_compression=false` 现状语义保留（压缩标志置位→OBSERVE 记录不解不转发变化——但 G1 默认值改为 **true（允许 gzip 并深检）**——仅「允许」时才进入解压深检；false 时维持现状二态行为（标记不解）；下发现状键 `api_grpc_allow_compression` 沿用。

### 1.6 协议化执行（NG-GRPC-02；NG-T-R04；D6）

- **处置形态**：一元违规/畸形/超预算请求的实断 = **gRPC 协议错误**（**不是** HTTP 403 页面）：`HTTP 200 + HEADERS(Content-Type: application/grpc) + grpc-status/grpc-message 经 trailers 下发`——具体按 gRPC over h2 规范：**trailers-only 响应**（单 HEADERS 帧携带 `:status 200, content-type: application/grpc, grpc-status, grpc-message` 且 END_STREAM）——规范错误信息形态，真实 SDK 对测验证（NG-T-R04）。
- **状态映射（冻结）**：策略违规（field_violation/敏感判定实断面）→ `PERMISSION_DENIED(7)`；畸形帧/超预算 → `RESOURCE_EXHAUSTED(8)`；未支持压缩算法 → `UNIMPLEMENTED(12)`；认证失败（JWT 信任链 PROTECT 拒）→ `UNAUTHENTICATED(16)`；依赖失败（Valkey/描述符装配不可用且策略 PROTECT 要求 fail-closed）→ `UNAVAILABLE(14)`。grpc-message 为固定短语（不泄露策略/字段细节，防探测——AZ-03 统一体同纪律：真实原因只落事件）。
- **双模式缺省 OBSERVE**（应用级/策略级 mode 与现状双闸同纪律）；**UNKNOWN 恒不阻断**（缺描述符/解码失败/依赖不可用→放行+如实披露，不映射任何 grpc-status）。
- **执行面挂接**：apiprotect 统一决策 BLOCK 定案后按 `api.protocol=GRPC` 分流——gRPC 请求走 `writeAPIGRPCErrorResponse`（committed 直写（writeAPIStrongFlowDeniedResponse 先例：不走 Caddy 错误链/阻断页），HTTP/2 帧层直接写 trailers-only）；非 gRPC 维持现状平面。
- **不做响应改写**：检查只读，不重新序列化正常请求/响应（§10.2 红线）——实断响应是新写错误帧不是改写。

### 1.7 trailers 与取消（NG-GRPC-02；NG-T-R06；D7）

- **trailers 透传**：源站正常 trailers（含 grpc-status 业务值）与 trailers-only 响应**原样透传不改写**（现状 h2 透传自然成立——冻结「不破坏」断言进测试：业务 grpc-status≠0 的合法响应不被网关改写为成功、正常 trailer 键值原样到达）。
- **cancel/deadline**：客户端 RST_STREAM/请求 ctx 取消 → 读取器/解压缓冲/字段遍历任务随请求 ctx 释放（读取器无后台 goroutine——全部解析在请求 goroutine 内完成，ctx 取消即终止；**泄漏测试证明**（R06：cancel 后 goroutine 数回归基线、无缓冲驻留））。慢消费（客户端读取缓慢）→ 源站读取侧背压由 h2 流控天然承担，网关不无限缓存完整流（G1 unary 缓冲受 §1.2 四重预算封顶）。
- **已转发副作用不消除**：取消发生在转发后 → 执行事实不回滚（§10.2 明文：不得因释放传输资源就清除执行事实或自动允许重试；强流程接入时按其 INDETERMINATE 纪律——本批不挂强流程）。

### 1.8 覆盖账本接入（NG-GRPC-03；D8）

- 检测器名 **`grpcguard`**（新检测器（帧读取器+结构校验+执行面）；既有 `grpc`（帧校验）与 `grpc_desc`（字段观测）观测键形**不变**（事件兼容）——grpcguard 是 G1 的覆盖承载与实断主体）。
- **五态**：`SKIPPED`（非 gRPC / streaming 降级 / non_proto_codec / 未登记描述符（no_descriptor））/ `FULL`（unary 深检完成：帧重组+（按需解压）+描述符解码+结构校验全过）/ `PARTIAL`（帧序列部分解析（截断样本/中段畸形/预算触顶中途停止））。每 gRPC 请求一条 `grpc.coverage_v1` 覆盖记录：方向、消息序号（首帧=1）、压缩方式、描述符集名与 content_hash 前 8、实际读取/解压字节量、深检完成度（§10.3 口径）。
- **零分母纪律**：E=0（窗口无 gRPC 流量）→ `no_applicable_traffic=true`，不显示虚假 100%（S1 既有纪律沿用）。

### 1.9 管理面与发布链（NG-GRPC-03；D9）

- **描述符集管理**：复用 `apigrpcdesc`（000076 CRUD）不动；**新增绑定管理**（000179：`GET/POST/DELETE /api-security/grpc-descriptors/{id}/bindings`（按应用查询/绑定/解绑），权限复用 `api_policy.read/edit`（与 apigrpcdesc 同域零新增权限点，HIGH 审计）。
- **未登记服务清单**（覆盖统计）：`GET /api-security/grpc-descriptors/coverage`——端点发现中 protocol=GRPC 的 service/method 全集 vs 注册表方法集差集（按应用分桶，read 权限）——「缺描述符不称完整深检」的管理面可见性（R03 红线的运营面）。
- **策略面**：gRPC 深检 mode 挂应用级 API 动态防护双闸（现状 OBSERVE/PROTECT 语义）+`api_grpc_allow_compression`（沿用）——零新策略实体（结构预算常量为发布侧冻结值，首批不开放逐应用配置）。
- **发布链**：绑定关系随快照 `api_grpc_descriptor_bindings` 段下发（版本戳自然覆盖）；绑定变化触发发布（apiflows/strongflow SetPublishFunc 先例）。
- **NG-T-C01**：无描述符+无绑定+非 gRPC 流量 = 全链零行为（现状即零行为；grpcguard 未装配时注册表 nil 零行为）。

### 1.10 迁移与 OpenAPI 预估（D10）

- 迁移 **000179**（`api_grpc_descriptor_bindings`：descriptor_id FK CASCADE + application_id FK CASCADE + 唯一 (descriptor_id, application_id)）——单表单迁移号（000076 既有表不动）。
- OpenAPI 增量预估 **+3 → 703**：bindings list/bind/unbind（3）；coverage 清单并入（1）——**合计 +4 → 704**（逐一 reconcile 双向零差集；基线 700）。
- 能力门：detectors 自报 `grpc.unary` 版本升 **`grpc/2`**（G1 完成态=重组+解压+结构校验+协议化执行；现状 grpc/1=帧校验+描述符观测）——**含 PROTECT gRPC 策略（任一应用 PROTECT 且存在描述符绑定）的快照 required `detectors.grpc.unary=grpc/2`**（旧节点 grpc/1 fail-closed `CAP_MISSING:detectors.grpc.unary`——az/3、flow/1 同纪律）；protocols.grpc=unary_g1 层级不动（信息性）。

## 2. 冻结决策点（D1~D10）

| # | 结论（一句话） | 理由要点 |
|---|---|---|
| D1 范围 | unary-only：application/grpc(+suffix) 且 POST 且 /pkg.Service/Method；streaming 识别即降级 SKIPPED(streaming_degraded)+观测明细，非 gRPC 零行为 | §10.1 边界原文；R05「不得报告整个调用通过」的诚实形态是降级不覆盖而非检首帧 |
| D2 帧读取 | 流式读取器先验证声明长度再分配；四重预算（4MiB/64 消息/16MiB 合计/64MiB 全局）；状态机随请求销毁天然不错位；协议专属预算与公共 1MiB 解析预算分离 | §10.2「先验证再分配/跨片段边界」明文；预算端到端（§14.1）；截断样本教训（现状 length_exceeds_remaining 不可判的正确性来自完整读取） |
| D3 描述符 | 登记制（000076 复用）+per-app 绑定（000179，空=全局）；反射不支持；缺描述符 SKIPPED(no_descriptor) 不称完整深检、PROTECT 不误断；版本=集名+content_hash 入版本戳 | 全局注册表的同名服务跨应用错配是正确性问题（绑定是修复不是增强）；§10.2 反射禁令；R03 红线 |
| D4 字段深检 | 结构校验（深度 8/repeated·map ≤1024/string·bytes ≤256KiB/枚举域/未知字段容许计数）+值级敏感规则复用；不做 required 缺失判定；不重序列化 | 首期可交付可验证不画饼；§10.2「默认值不误当缺失」「不因检查重序列化」明文 |
| D5 压缩 | gzip 唯一批准；四重预算（压缩 4MiB/解压 16MiB/100×/CPU）；未知算法=协议化 UNIMPLEMENTED(12)（协议语义非误断）；allow_compression 默认翻 true 才可解压深检 | §10.2 压缩指南引用；R02「不无限解压」；未知编码的标准协议应答 ≠ 安全判定 |
| D6 协议化执行 | trailers-only 响应（:status 200 + grpc-status/grpc-message END_STREAM）；映射 7/8/12/14/16 冻结；OBSERVE 缺省+UNKNOWN 恒不阻断；committed 直写先例分流 api.protocol=GRPC | §10.3 状态码依据；防探测统一短语；强流程 403 直写先例 |
| D7 trailers/取消 | 正常 trailer 与 trailers-only 透传不改写；cancel/deadline 随请求 ctx 释放（解析全在请求 goroutine 无后台任务，泄漏测试证明）；已转发副作用不回滚 | §10.2 取消/deadline 明文；R06 资源释放断言形态 |
| D8 覆盖账本 | 新检测器 `grpcguard` 承载五态（SKIPPED 三形态/FULL/PARTIAL）+grpc.coverage_v1 记录（方向/序号/压缩/描述符/读写量）；既有 grpc/grpc_desc 观测键形不变；E=0 no_applicable_traffic | NG-GRPC-03「unary 完整范围、streaming 明确降级」的账本承载；事件兼容 |
| D9 管理面/能力门 | 000179 绑定表+绑定 CRUD（+3）与 coverage 清单（+1）→704；detectors.grpc.unary 自报升 grpc/2，含 PROTECT gRPC 策略快照 required grpc/2 fail-closed；NG-T-C01 零行为 | 旧节点误形态（HTTP 403 冒充 gRPC 错误）必须能力门拦截（az/3 先例）；权限零新增 |
| D10 测试 | R01~R06 逐条映射（§4）；帧读取器 Go fuzz（语料=合法帧变异+随机，CI 5min 持续）；真实 Go gRPC 客户端+独立测试服务（deployment 新增 grpc-testorigin 容器）；性能预算 p95 解析 ≤2ms/4MiB、解压 ≤10ms/16MiB（§14.2 候选门槛下挂） | 真实客户端对测是 NG-GRPC-02 完成证据原文；fuzz 是 R01 断言形态 |

## 3. 本批不做（范围外，如实标注）

- **G2/G3**：server streaming 逐消息检查与背压（G2）；client/bidi streaming 逐消息策略与会话预算（G3）——streaming 在 G1 只降级声明（§1.1），不做逐消息检查。
- **Reflection 描述符发现**（§10.2 明文不做）。
- **gRPC-web / grpc-json 转码深检**（+json 变体只帧校验不解码）；非 gzip 压缩算法（snappy/lz4/zstd）解压。
- **响应侧字段深检**（G1 只做响应帧结构校验与 grpc-status 观测；响应消息字段检查属后续批）。
- **xDS/服务发现集成、负载均衡策略感知**；gRPC 负载均衡/健康检查协议专属面。
- **逐应用结构预算配置**（首批冻结常量）；required 字段缺失规则（proto3 语义外）；强流程 gRPC 挂接（§1.7 明文不挂）。

## 4. 测试计划（NG-T-R01~R06 逐条映射）

| 用例 | 断言 | 实施位置 |
|---|---|---|
| R01 分片帧/长度错误/空消息 | 跨片段（1B/3B/5B/MSS 切片）正确重组；长度伪造（声明>上限/声明>剩余/保留位非零）不分配、按 §1.6 处置；空消息（长度 0）合法通过；同连接前请求畸形后请求正常不串位；fuzz（go test -fuzz 合法帧变异+随机语料，CI 5min）无 panic/无越界读 | gateway `parser/grpcframe` 单测+fuzz；stage5 同连接双请求集成 |
| R02 压缩膨胀/未知算法 | gzip 正常解压深检 FULL；zip bomb（倍率>100×/解压>16MiB）读断不超内存（峰值断言）；未知 encoding → PROTECT UNIMPLEMENTED(12) trailers-only（OBSERVE 记录转发）；覆盖状态正确（FULL/SKIPPED） | gateway 单测（预算矩阵）+stage5 grpcurl --encoding gzip/自定义 encoding 集成 |
| R03 repeated/map/oneof/缺描述符 | repeated>1024/map>1024/string>256KiB/嵌套>8/枚举越界逐条违规定案（证据不落值）；oneof 正常语义不误判；缺描述符 SKIPPED(no_descriptor)+PROTECT 放行不误断+管理面清单可见 | gateway 结构校验单测矩阵+stage5 测试服务方法级集成+管理面 coverage 端点断言 |
| R04 一元违规请求 | PROTECT trailers-only 响应（:status 200+grpc-status 7+grpc-message 固定短语+END_STREAM，**测试服务未执行**（服务端方法调用计数=0））；OBSERVE 转发记录；真实 Go gRPC 客户端收到的 error.Code()=PermissionDenied | stage5 E2E（真实 Go 客户端+grpc-testorigin） |
| R05 流首条正常后续违规 | G1 未实现 G2/G3：**明确部分覆盖**——streaming 识别降级 SKIPPED(streaming_degraded)+观测明细，**不报告**「整个调用通过」也不报告「完整深检」；帧结构畸形仍照判 | stage5 流式方法集成（覆盖记录断言） |
| R06 cancel/deadline/慢消费 | 客户端 cancel（RST_STREAM）后：读取器/解压/遍历资源释放（goroutine 回归基线、无缓冲驻留——运行时 goroutine 计数断言）；deadline 超时同纪律；慢消费背压不无限缓存 | gateway 集成测试（h2 客户端 cancel 注入）+24h 稳定性候选（§14.2，无 goroutine 单调增长） |
| 性能边界 | 解析+结构校验 p95 增量 ≤2ms（4MiB 消息）；gzip 解压 p95 ≤10ms（16MiB 膨胀）；全 OFF 吞吐降低 ≤2%/P99 增量 ≤1ms（§14.2 门槛沿用，普通 amd64+兆芯双报告） | `test/performance/` 基准（固定硬件声明） |

另：NG-T-C01（无描述符/无绑定/非 gRPC 全链零行为+存量回归 40/40、13/13 不回退）；集成四断言沿用 AZ-03 口径（客户端响应/源站到达/决策记录/运行态事件）；能力门三态（grpc/1 旧节点 fail-closed/grpc/2 收载/全 OBSERVE 零需求兼容滚动升级）stage5 实证。

**测试服务方案（冻结）**：`deployment/stage1/grpc-testorigin/`（Go `grpc.Server` 独立小镜像，方法集：Echo(unary)/敏感字段回显/大消息（4MiB 边界）/错误注入/streaming 方法；digest 锁定基础镜像；compose stage5 附加服务 `grpc-testorigin:18571`——与 testorigin 同纪律（RFC5737/虚构主体）；E2E 客户端=Go `google.golang.org/grpc` 真实 SDK（断言 error.Code() 与 trailers，不用 grpcurl 截图冒充——grpcurl 仅辅助）；**用完即删纪律与 testorigin 临时改动同**。

## 5. 实现拆分与顺序（文件级边界预估，实施批再冻结）

**批次 A：帧读取器+有界解压（NG-GRPC-01，gateway 单轨）**
- `gateway/dynamic_security/parser/grpcframe/`（流式读取器状态机+四重预算）；`parser/parse_grpc.go` 帧校验切至读取器（观测键形不变）；`detectors/grpcguard/`（骨架+gzip 有界解压+预算定案）；fuzz 语料与 CI 门禁。

**批次 B：描述符绑定+结构校验+协议化执行（NG-GRPC-02，双轨）**
- server：迁移 000179、bindings CRUD+coverage 清单、发布段+能力门聚合（required grpc/2 计算）；`apigrpcdesc` 不动。
- gateway：`grpcdesc` per-app 注册表装配；`detectors/grpcguard/structure.go`（§1.4 检查集）；`apiprotect` `writeAPIGRPCErrorResponse`（trailers-only committed 直写分流）；能力自报 grpc.unary 升 grpc/2。
- 依赖：批次 A 的读取器是 B 的输入；server/gateway 在 B 内可并行（共享契约为绑定 JSON 形状，本文 §1.3 已冻结）。

**批次 C：覆盖统计+管理面+E2E（NG-GRPC-03，server+web+QA 三轨）**
- server：coverage 清单端点（端点发现 vs 注册表差集）；web：描述符页绑定管理与未登记服务清单区块（复用 apigrpcdesc 页面先例）；QA：grpc-testorigin+真实 SDK E2E（R01~R06 全矩阵 stage5）+性能基准+能力门三态。

并行可行性：A 可独立先行（不动发布链）；B 的 server/gateway 并行；C 的 web 可在 B 的 API 契约冻结后提前起步（mock）。C01 回归门禁（40/40、13/13）每批必过。

## 6. 移交项（后续批次）

- G2（server streaming 逐消息检查与背压——「已放行消息不能撤回」语义单独立约）、G3（client/bidi streaming 逐消息策略+会话预算+客户端取消/重试兼容验证）。
- 非 gzip 压缩算法解压、gRPC-web 深检、响应侧字段深检。
- 逐应用结构预算与检测规则配置面；required/条件必填规则（proto3 语义外扩展评审）。
- 强流程（NG-FLOW）gRPC 挂接评审（unary 调用作为流程步骤形态）；gRPC 元数据（metadata KV）级检测（headers 内敏感/授权语义——与身份体系联动评审）。
- 24h 稳定性与兆芯性能报告（§14.2 全量门槛，与 ha-lab 演练矩阵合并编排）。

## 7. 实现状态（批次 B1/B2/C 已交付并 stage5 联调验收，2026-10-07；本节为实施记录，不改上文契约）

**状态：G1（unary 有界深检/压缩/协议处置与覆盖）已落地并经 stage5 R01~R06 全量验收。** server 绑定管理面（批次 B1）+ gateway 帧读取/解压/结构校验/协议化执行（批次 B2）+ 联调验收（批次 C）三批按 §5 拆分实施；出口记录 `docs/nextgen/s5/S5-EXIT-SUMMARY.md`。

### 7.1 决策点落点（D1~D10 → 实现位置）

| 决策 | 实现 |
|---|---|
| D1 范围与 streaming 降级 | gateway `dynamic_security/detectors/grpcguard/grpcguard.go`（Evaluate 判定形态：非 POST/+json 变体 skip；请求帧序列 >1 消息 → `SKIPPED(streaming_degraded)`+`grpc.streaming_observed`（方向/序号/messages_seen，不冒充深检）；帧结构校验照判） |
| D2 帧读取与预算 | gateway `dynamic_security/parser/grpcframe/`（批次 A 读取器：流式重组+四重预算+错误三分类（ProtocolError/BudgetError/EncodingError）；覆盖读数 bytes_read/completion 与实际一致（R01 实证 200KiB 分片重组 completion=full） |
| D3 描述符与绑定 | server：`apigrpcdesc`（000076 集 CRUD 复用）+ 迁移 000179 `api_grpc_bindings`（应用×服务×集×模式，空=全局，同（应用，服务）唯一，FK 级联）+ CRUD 5 端点 + 未登记服务差集端点；gateway `jiuzhang_guard/apigrpcguard.go` buildGRPCGuardConfig（per-app 绑定注册表+content_hash 读数；空绑定=全局 OBSERVE）；缺描述符 `SKIPPED(no_descriptor)` 不误断（R03 实证直达源站） |
| D4 字段深检 | gateway `grpcguard/structure.go` CheckStructure（嵌套 ≤8/repeated·map ≤1024/string·bytes ≤256KiB/遍历 ≤256/枚举值域/未知字段容许计数；证据=规则+路径+读取量不落值——R04 四分支（string_bytes_exceeded/depth_exceeded/enum_out_of_range/repeated_exceeded）stage5 实证精确读数） |
| D5 压缩 | gateway `grpcframe.Gunzip`（四重预算：压缩 4MiB/解压 16MiB/倍率/CPU）；`grpc.compression_budget_exceeded`（8 语义——R02 实证 20MiB 高倍率 PROTECT 拒 ResourceExhausted、OBSERVE 放行）；未知算法 `grpc.unsupported_encoding`（UNIMPLEMENTED(12) 协议语义）；`allow_compression` 三态（G1 默认 true） |
| D6 协议化执行 | gateway `apiprotect.go writeAPIGRPCErrorResponse`（trailers-only：HTTP 200+content-type application/grpc+grpc-status/grpc-message 固定短语+无体，committed 直写不走 Caddy 错误链；grpcguardBlockStatus 从 evidence.grpc_status 驱动映射 7/8/12/14/16；R04 实证客户端收纯 gRPC 错误 `grpc request rejected by protection policy`） |
| D7 trailers/取消 | 正常 trailers 透传不改写（Go gRPC 源站响应全链验证）；cancel/deadline 随请求 ctx 释放——R06 实证：50 次中途 cancel 后网关 RSS 598.5→422.6MiB 无驻留、caddy.log 零 panic、取消路径 `request.body_preserve_skipped{reason:body_read_error}` fail-open 如实披露 |
| D8 覆盖账本 | 检测器 `grpcguard` 五态（SKIPPED(non_grpc/non_proto_codec/streaming_degraded/no_descriptor/compression_disabled)/FULL/PARTIAL）+每候选请求 `grpc.coverage_v1` INFO（direction/message_seq/compression/bytes_read/decompressed_bytes/descriptor/descriptor_hash/skip_reason/unknown_fields/completion）——R01/R05 实证读数 |
| D9 管理面/能力门 | server 迁移 000179+CRUD+发布段 `api_grpc_bindings`（guardconfig/grpc_bindings.go + gatewayconfig/guard.go handler 映射）；能力门 `gatewayconfig/capability_gate.go`：含任一 PROTECT 绑定 → `detectors.grpc.unary=grpc/2`（全 OBSERVE 零需求）；网关 `capability_report.go` 恒报 grpc.unary=grpc/2+protocols.grpc=unary_g1（**进程能力非配置态**——联调修正，见 7.3-3） |
| D10 测试 | 单测+PG 契约（server：迁移 179/180 up/down、唯一键/词表/FK/级联/乐观锁/发布段两态/差集四象限/能力门两态）+ gateway -race 全绿 + stage5 R01~R06 真实 Go SDK 对测（`test/waf/grpc-e2e`）+回归 40/40、13/13 不回退 |

### 7.2 新增交付物（批次 C）

- **grpc-testorigin**（`deployment/stage1/grpc-testorigin/`）：零 protoc 依赖（手工 FileDescriptorProto+dynamicpb 编解码）——echo.EchoService（**大写驼峰服务名**，词表裁决实证面）{Echo,LargeEcho,CollectEcho} + echo.OtherService{Ping}（不在导出描述符集——R03 承载）；`-dump-descriptor` 构建期导出 echo.pb；镜像 digest 锁定（testorigin 同族供体）；compose overlay `deployment/docker-compose.stage5-grpc.yml`。
- **E2E 客户端**（`test/waf/grpc-e2e/`）：真实 Go gRPC SDK（grpc v1.76.0+protobuf v1.36.11 独立 go.mod 锁定），11 场景 verdict（真实 SDK 对测，未用 curl 冒充）。

### 7.3 联调新发现与修正（批次 C，2026-10-07）

1. **B1 词表偏差裁决（已闭环）**：B1 server 服务名 CHECK 全小写段误拒真实 proto 大写驼峰服务名（echo.EchoService）——裁决 server 放宽对齐 protobuf 标识符实际规则（包段小写 snake+服务段允许大写驼峰）：`apigrpcdesc/bindings.go` servicePattern + 迁移 000180（CHECK 放宽，down 恢复需先清大写行）；网关装配/匹配不动（只消费下发字符串）。PG 契约覆盖 up/down+大写通过+包段大写仍拒。
2. **h2c 明文回源（新能力，server 侧）**：Caddy http transport 默认 versions 不含 h2c（gRPC 源站协商失败 502）——`applications/store.go` scheme 词表加 `h2c` + `gatewayconfig/generator.go` transport 分支（scheme=h2c → `versions:["h2c"]`，tls 互斥）。R01 全链实证。
3. **能力门死锁修正（gateway 侧）**：`capability_report.go` GRPCUnary 原绑定「当前配置有描述符」——首次引入描述符的发布需求（unary_g1+grpc/2）vs 自报（frame/空）必然 fail-closed 死锁（联调实证 CAP_MISSING）。修正为**恒报**（detectors/protocols 是进程能力——grpcguard 在 binary 即成立，与 flowguard=flow/1、az/3 恒报同纪律）。
4. **发布段 handler 映射缺失（server 侧）**：`gatewayconfig/guard.go` handler 构造缺 `h["api_grpc_bindings"]` 赋值（绑定落 PG 但不下发 → grpcguard 双闸之二 engineProtect 永远 OBSERVE）——补映射后绑定下发（R04 PROTECT 实证）。
5. **WAF/CRS 与 gRPC 语义不适配（环境适配，非产品缺陷）**：CRS 920180（POST 无 Content-Length——h2 无 CL 恒误检）/9000102（二次阻断评估）/942100（libinjection 对 gzip 二进制随机字节撞 SQLi 指纹）+CUSTOM_PACK attack-protocol——gRPC 应用经 WAF 例外承载（REMOVE_RULE_TAG attack-protocol+attack-sqli+rule_ids 920180/920470/942100/9000102，methods=POST，uri_regex `^/echo\.`）。**教训两条**：①例外 uri_prefix 是**路径段边界匹配**（`/echo.` 不匹配 `/echo.EchoService/Echo`，须全限定段或 uri_regex）；②管线顺序 jiuzhang_guard（grpcguard）先于 Coraza——PROTECT 下 grpcguard 先拦（Coraza 不执行），OBSERVE 下才暴露 WAF 误检（这解释了 PROTECT 应用不经例外也「看似正常」的现象）。
6. **冒烟探针与 gRPC 源站**：新应用 Bot 墓碑缺失时 CC 探针打源站 502 判 VERIFY_FAILED（AZ-03 已知坑）——bot_policy `route_reservation=RESERVED_TOMBSTONE` 承载（两应用先例复用）。
7. **客户端侧三处自伤（E2E 工具修正）**：Go SDK 默认 MaxCallRecvMsgSize=4MiB 误拒源站大响应（WithDefaultCallOptions 放宽 64MiB）；client-streaming 未 CloseSend 与网关读体互等死锁（改 CloseSend+RecvMsg）；r01 消息 big_text 初版 3MiB 踩结构预算线（R01 正常流应用 200KiB——分片验证与违规验证分离）。
8. **grpc-testorigin 默认 MaxRecvMsgSize=4MiB** 误拒 R02 的 20MiB 消息（源站放宽 64MiB 后 R02-observe 真回显）。

### 7.4 已知限制与遗留（如实登记）

- **>1MiB 无压缩 gRPC 大请求体经 h2c 上游转发挂起**（联调实证：200KiB~300KiB 通、3MiB 稳定 DeadlineExceeded（10s+），源站未收到、网关已读全并放行）——疑 Caddy h2c transport 对无 Content-Length 大体转发/流控问题，**未定性**，列入后续排查（G1 帧预算语义（单消息 ≤4MiB）本身正确，该问题在转发层不在检测层）。
- streaming G2/G3 顺延（R05 当前为降级明示 SKIPPED(streaming_degraded)，非逐消息检查）。
- 零消息（空体）unary 请求：PARTIAL 如实呈现不定案（grpc.no_unary_message INFO——协议违规判定留集成批裁决）。
- map 键/值枚举逐条值域校验为后续增强点（structure.go 注释在册）；unknown 字段容许计数（感知不惩罚，§1.4 冻结语义）。
- 14（UNAVAILABLE）/16（UNAUTHENTICATED）状态码为预留常量（G1 内 UNKNOWN 恒不阻断不产出；JWT 信任链 gRPC 拒走既有 jwt_trust 通道）。
- reconcile 工具链环境备注：`tools/check-api-reconcile.py` 需带 pyyaml 的 python3（本机 /usr/bin/python3（Xcode 3.9）无 yaml，用 Framework 3.12 通过）。

### 7.5 E2E 证据摘要（stage5，2026-10-07；逐项原文见 S5 出口记录）

- **R01**：r01（双应用）`PASS text="hello-grpc" origin_mark=[grpc-test-origin]`（200KiB 分片重组+full+源站到达 metadata 实证）；覆盖 `completion=full bytes_read 与实际一致 descriptor=echo-g1 descriptor_hash=6abdee3a`。
- **R02**：PROTECT `code=ResourceExhausted desc="grpc request exceeds resource budget"`（trailers-only 固定短语）；OBSERVE `err=<nil>`（20MiB 高倍率放行+源站 64MiB 放宽后真回显）。
- **R03**：`PASS text="ping-no-descriptor" origin_mark=[grpc-test-origin]`（OtherService 未登记直达源站）；覆盖 `skip_reason=no_descriptor` 零 BLOCK。
- **R04**：string/depth/enum/repeated 四分支 PROTECT `code=PermissionDenied desc="grpc request rejected by protection policy"`（**纯 gRPC 错误（trailers-only），非 HTML 403**——客户端 desc 无 transport 错误前缀实证）；string-observe `err=<nil>` 放行；事件 field_violation 读数精确（read=307200/9/99/1025）。
- **R05**：`PASS text="collected:3"`（流式正常完成不误判）；覆盖 `skip_reason=streaming_degraded`+`grpc.streaming_observed messages_seen=2`（降级明示不冒充）。
- **R06**：50 次中途 cancel PASS；网关 RSS 598.5→422.6MiB（无驻留）、caddy.log 零 panic/runtime error、取消路径 `body_preserve_skipped{body_read_error}` fail-open 披露。
- 回归：stage5 40/40、custom-pack 13/13（串行）、server apigrpcdesc/gatewayconfig/guardconfig/applications/app 与 gateway 三模块全 ok（-count=1）、reconcile 705 双向零差集、gofmt 干净。
