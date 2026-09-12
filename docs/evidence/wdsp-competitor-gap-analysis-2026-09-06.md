# WDSP 与六家 WAF / WAAP 产品的优势和差距

> 调研日期：2026-09-06。比较对象：Cloudflare、长亭雷池、腾讯云、阿里云、Imperva、F5 Distributed Cloud。
>
> WDSP 基线：`develop`，HEAD `3c73774`，并包含本次读取时的本地工作区实现。因此，本报告不是对某个已发布安装包的认证。
>
> 方法：互联网检索厂商官方文档，结合 WDSP 代码、接线和历史测试记录抽查。本次未对六家产品部署实测，也未重新运行 WDSP 性能或安全回归；“官方提供”不等于本报告验证了检测效果。

## 1. 核心判断

**WDSP 最值得发展的方向，是面向私有化业务环境，把 Web 防护、API 业务上下文和 APM 排障放进同一个工作流程。** 已有代码为这个定位提供了基础，尤其是安全事件与 Trace 的关联、API 模型确认发布、SQL 和异常查询。

与当前头部产品比较，不能再把“支持 API、身份识别、响应检测、行为分析、AI”本身当作独有优势。六家产品已不同程度扩展到 WAAP，即 Web 与 API 防护，并提供 Bot、API 或其他配套模块。具体能力和收费边界见下文官方来源。

当前更明确的差距有四类：

1. **对抗深度**：高级 Bot 对抗、可信业务身份、跨请求风险判断，还需要更完整的实现和误报验证。
2. **覆盖范围**：分布式流量 Agent 的解密后采集、协议解析和规模化能力存在明确待办。
3. **运行证据**：已有开发环境性能数据，但不足以承诺生产吞吐、长时间稳定性和事件可见时延。
4. **交付和运营**：需要把多个检测与诊断模块变成可解释、可回退、客户容易接入的操作流程。

这不是“WDSP 没有竞争力”，也不是“功能多就已超过商业产品”。合理的现阶段定位是：**一套已经具有较广功能基础、需要继续证明防护质量和交付稳定性的私有化 Web / API 安全与业务性能平台。**

## 2. 比较口径：先把产品范围对齐

| 对象 | 本报告比较的范围 | 容易产生误判的边界 |
|---|---|---|
| WDSP | 本地代码中 Web 防护、动态 API 防护、身份行为、流量 Agent、APM | 设计文档、代码实现、集成接线、生产验证是不同完成程度；不能用模块数量计算完成率 |
| Cloudflare | WAF，必要时加 API Shield、Bot Management、DDoS 产品能力 | 完整 API Shield 为 Enterprise 付费附加能力；高级 Bot 有套餐要求；网络层高级能力也有独立产品边界。[WAF](https://developers.cloudflare.com/waf/)、[API Shield](https://developers.cloudflare.com/api-shield/)、[Bot 分数](https://developers.cloudflare.com/bots/concepts/bot-score/)、[DDoS](https://developers.cloudflare.com/ddos-protection/) |
| 长亭雷池 | 社区产品线与企业雷池分别参考 | 社区产品线包含个人、专业、商业型号，不能把全部功能算进免费版；长亭还单列 APISEC 产品，不能全部默认计入任一雷池版本。[社区文档](https://help.waf-ce.chaitin.cn/)、[企业雷池](https://www.chaitin.cn/zh/safeline)、[产品支持目录](https://support.chaitin.cn/) |
| 腾讯云 WAF | WAF 与选配的 API 安全、Bot 管理 | 部分能力依赖订阅和增购；API 风险分析包含旁路镜像处理，不能直接等同于每条规则都在线阻断。[API 安全](https://cloud.tencent.com/document/product/627/133175)、[API 策略](https://cloud.tencent.com/document/product/627/64339)、[购买配置](https://cloud.tencent.com.cn/document/product/627/11730) |
| 阿里云 WAF 3.0 | WAF、API 安全、Bot 与相关接入方式 | Agentic API 安全独立计费，其计算分析为离线方式；基础免费摘要与完整付费分析不同。不能据此说整个 WAF 都是离线防护。[Agentic API 安全](https://help.aliyun.com/zh/waf/web-application-firewall-3-0/user-guide/api-security-1/)、[防护配置](https://www.alibabacloud.com/help/zh/waf/web-application-firewall-3-0/user-guide/protection-configuration-overview) |
| Imperva | WAF、API Security、Advanced Bot Protection 组合 | API Security 官方提供云管理、自管理以及不同采集方式；不能认定只能上云，也不能把组合能力视为基础 WAF 全部标配。[API Security](https://www.imperva.com/products/api-security/)、[WAF](https://www.imperva.com/products/web-application-firewall-waf/) |
| F5 | Distributed Cloud 的 Web / API 防护与 Bot Defense | 本报告不混用 BIG-IP 的型号与授权；Bot 能力须核实对应版本和接入要求。[API Security](https://www.f5.com/products/distributed-cloud-services/api-security)、[Bot Defense 配置](https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/adv-security/configure-bot-defense) |

以下“WDSP 可竞争的方向”属于基于实现和部署形态的判断，不代表实测胜出。采购价格、服务响应、SLA 和具体授权，以同等配置的报价与合同核实，本报告不编造横向成本数字。

## 3. 逐家比较：我们的机会在哪里，差距在哪里

| 厂商 | 官方能力所体现的比较基准 | WDSP 可竞争的方向 | WDSP 主要差距或需要证明的部分 |
|---|---|---|---|
| **Cloudflare** | 全球网络承载与 DDoS 防护；WAF、API、Bot 可结合；API JWT 验证有 JWKS 和签名校验机制。[网络防护](https://www.cloudflare.com/network-services/use-cases/network-protection/)、[JWT 验证](https://developers.cloudflare.com/api-shield/security/jwt-validation/api/) | 内网业务、本地数据、定制业务策略，以及安全事件与本地 APM 的关联；适合客户希望自己控制防护与观测数据的场景 | 无法把自建反向代理与全球清洗网络视为等价；高级 Bot 信号、可信 JWT 和规模化运营证据需要补齐。大流量 DDoS 应考虑运营商或清洗服务配合 |
| **长亭雷池** | 企业产品强调语义分析、机器学习、API / Bot 与多种本地部署；社区文档已有动态防护、人机验证、CC 等能力。[企业产品](https://www.chaitin.cn/zh/safeline)、[防护功能](https://help.waf-ce.chaitin.cn/node/01973fc6-df65-74c8-b586-a88779e99a97) | 在私有化客户中展示 API 模型审核、业务关系配置与 APM 排障的组合价值；用完整业务演示证明价值 | 私有化并非相对雷池的独有优势。应同场验证 Web 攻击检出、正常业务误报、Bot 挑战体验、部署耗时和日常运维负担 |
| **腾讯云 WAF** | API 资产、风险、事件与策略；Bot 支持客户端挑战、情报和行为判断，并存在 JS 会话粒度的高级配置。[API 概览](https://cloud.tencent.com/document/product/627/133175)、[Bot](https://cloud.tencent.com/document/product/627/65688)、[会话策略](https://cloud.tencent.com/document/product/627/70709) | 不依赖单一云的本地业务覆盖；安全、API 与 APM 在同一产品中的协同，适合混合存量系统 | Bot 信号、托管运营以及客户现有云资源接入便利性是重要对比项。该文档中的高级 JS 会话策略面向 Web / H5，不能扩大解读成所有原生 App 场景 |
| **阿里云 WAF 3.0** | 云原生、CNAME、混合云接入；2026-07-31 推出 Agentic API 安全，引入大模型检测，旧 API 模块进入维护期。[接入方式](https://help.aliyun.com/zh/waf/web-application-firewall-3-0/user-guide/overview-8)、[API 更新](https://help.aliyun.com/zh/waf/web-application-firewall-3-0/user-guide/api-security-1/) | 本地部署与可定制的 API 在线策略，结合业务性能数据开展问题处置；在多种存量基础设施中提供一致工作流程 | “有 AI”已经不是独有卖点。需证明 AI 建议的正确性、审核后生效机制和业务影响，而非只展示解释文本；阿里云也有混合云方式，不能以“竞品只能公有云”比较 |
| **Imperva** | API 发现、业务逻辑风险、BOLA 检测响应，与 WAF / Bot 协同；支持自管理、Agent 和无 Agent 方式。[API Security](https://www.imperva.com/products/api-security/) | 本地研发可快速适配客户业务模型；以统一控制台和安全 / APM 关联争取特定客户场景 | BOLA、行为基线、多环境采集等能力已有直接竞争者。WDSP 需用真实授权关系、合法共享对象、角色切换等案例证明效果，不能把“存在越权检测器”当作效果证据 |
| **F5 Distributed Cloud** | API 发现、影子 API、请求与响应 Schema 学习、敏感数据识别；Bot 支持 JS 与移动 SDK 接入。[API 学习](https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/app-security/apiep-discovery-control)、[Bot 接入](https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/adv-security/configure-bot-defense) | 面向需要本地自主运维的业务，把防护策略与 Trace 排障串联；提供针对业务的关系确认流程 | API 学习和响应识别不是独有能力；移动端 Bot、跨环境接入、采集协议覆盖和端到端可运营性需要更强的实现与验证 |

**选择对标对象应按客户场景。** 全球互联网业务重点对标 Cloudflare；国内云上业务重点对标腾讯云、阿里云；私有化项目重点对标企业雷池、Imperva 的相应部署形态；多环境 API 与 Bot 场景重点参考 F5。不要拿免费版功能和另一家的全套企业授权直接排高低。

## 4. WDSP 的优势：哪些已有证据，哪些还只是机会

### 4.1 安全事件与 APM 关联：最值得展示的已有基础

这部分已经超出架构图或菜单占位：

- 后端已挂载概览、服务、端点、Trace 检索、SQL、异常、依赖和运行时接口，并有权限校验。[APM 路由](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/apm/handler.go)
- 应用启动流程使用实际 APM Store 与 ClickHouse 查询解析器，并注册 SLO、诊断会话相关组件。[应用接线](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/app/app.go)
- 安全事件详情按权限与 Request ID 提供 APM Trace 跳转；Trace 页面支持按 Request ID 定位。[事件详情](/Users/zhanglei/Documents/JiuZhang_WAF/web/src/pages/security-events/EventDetailDrawer.tsx)、[Trace 页面](/Users/zhanglei/Documents/JiuZhang_WAF/web/src/pages/apm-traces/ApmTracesPage.tsx)
- 诊断会话具备预估、确认、停止和全局停止开关接口。[诊断接口](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/apm/diagnostics_handler.go)

由此形成的产品机会是：值班人员从异常访问或安全事件出发，继续定位相关业务请求，再分析服务、SQL 和异常，减少跨系统查找。**当前已经核实上述组件和部分跳转接线；整个业务排障流程的耗时收益，仍需客户场景演示和实测。**

APM 也不是竞品完全没有的能力。阿里云有 ARMS，腾讯云有独立 APM 产品及调用链分析。WDSP 应比较集成体验、部署边界和总体成本，不应宣称在语言覆盖、探针成熟度或诊断深度上已全面领先。[ARMS 接入中心](https://help.aliyun.com/zh/arms/getting-started/arms-integration-center)、[腾讯云 APM](https://intl.cloud.tencent.com/zh/products/apm)

此外，**网关观测不能替代应用探针**。没有相应 OTel / 应用采集时，不能只根据入口请求就声称得到代码执行、SQL 调用或完整分布式 Trace；APM 数据面、上下文传播、采样与客户接入都需要明确验收。[APM 设计](/Users/zhanglei/Documents/JiuZhang_WAF/docs/BUSINESS_PERFORMANCE_APM_DESIGN.md)、[APM 客户接入指南](/Users/zhanglei/Documents/JiuZhang_WAF/docs/APM_ONBOARDING_GUIDE.md)

### 4.2 API 模型由人确认再发布：具有可运营的实现基础

模型后端已有差异、提交审核、确认、拒绝、激活、归档，以及参数关系确认操作。参数关系先成为候选，确认后再随配置发布进入强制检测，能支持安全人员审核学习结果。[模型接口](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/apimodels/handler.go)

这一设计适合复杂业务：把机器学到的模式和业务真正允许的规则分开，降低错误学习直接影响正常请求的风险。后续应验证审核工作量、策略回退、异常样本污染以及线上误报，而不是仅展示“自动学习成功”。

需要准确表达：**我们的优势候选是模型治理和业务适配流程，不是“只有我们会学习 API”。** Cloudflare 与 F5 已有 Schema / API 学习，其他厂商也提供资产和行为分析。[Cloudflare API 接入](https://developers.cloudflare.com/api-shield/get-started/)、[F5 API 学习](https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/app-security/apiep-discovery-control)

### 4.3 本地部署、自主控制与业务定制：适用场景优势

WDSP 的 Caddy / Coraza / CRS 网关、自主控制面、数据库与 APM 数据面适合围绕本地应用部署，业务策略和问题定位逻辑可由团队控制。[项目技术路线](/Users/zhanglei/Documents/JiuZhang_WAF/AGENTS.md)、[架构设计](/Users/zhanglei/Documents/JiuZhang_WAF/docs/ARCHITECTURE.md)

这对重视内网覆盖、数据位置、存量系统和专用业务策略的客户有吸引力。但雷池、Imperva，以及提供混合部署方式的产品也覆盖部分相同需求。因此应突出具体交付方案和业务适配结果，不能把私有化本身当作全市场独占优势。AI 等外部服务是否依赖联网，还需按实际部署配置逐项说明。

### 4.4 安全与性能共同描述业务影响：值得继续做深

WDSP 已有身份行为、API 检测、响应侧安全和 APM 等模块，具备组织统一调查上下文的条件。产品可进一步回答：“哪个接口、哪类身份、哪些对象被访问；采取了什么处置；是否关联业务错误或延迟”。[动态防护实现](/Users/zhanglei/Documents/JiuZhang_WAF/gateway/dynamic_security)、[身份行为实现](/Users/zhanglei/Documents/JiuZhang_WAF/gateway/modules/jiuzhang_guard/identitybehavior)、[APM 实现](/Users/zhanglei/Documents/JiuZhang_WAF/server/internal/apm)

这里的竞争价值是帮助用户完成调查和处置。**同一时间出现性能下降与攻击告警，并不能直接证明因果关系**；界面和 AI 解释应区分关联线索、已验证事实与推测。

## 5. 主要差距及其实际影响

### 5.1 高级 Bot 防护：有基础信号，尚不能等同于完整对抗体系

本地实现包含身份、浏览器特征、TLS 特征、行为观察、风险策略和 CC 等基础。但身份代码明确写明 TLS 指纹是“TLS 版本 + 密码套件”，拿不到 ClientHello，不做 JA3 / JA4；浏览器指纹基于 UA / Accept 类信息。[身份指纹实现](/Users/zhanglei/Documents/JiuZhang_WAF/gateway/modules/jiuzhang_guard/identitybehavior/identity.go)

本次未在所查业务流量防护链中确认完整的浏览器挑战、移动端 SDK、设备完整性及可信机器人验证体系。管理后台登录验证码不能算作被保护网站的人机挑战。

Cloudflare 官方 Bot 体系包含启发式、机器学习、JS 检测等多类信号；腾讯云提供 Bot 挑战及会话策略；F5 提供 JS / 移动 SDK 接入；雷池也有动态与人机防护。这意味着 WDSP 在撞库、模拟浏览器、低频分布式爬取等场景应专门补测。[Cloudflare Bot](https://developers.cloudflare.com/bots/concepts/bot-score/)、[腾讯云 Bot](https://cloud.tencent.com/document/product/627/65688)、[F5 Bot](https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/adv-security/configure-bot-defense)、[雷池防护](https://help.waf-ce.chaitin.cn/node/01973fc6-df65-74c8-b586-a88779e99a97)

建议优先完善信号可信度、挑战触发条件、豁免范围、失败回退和误挑战指标。JA4 是可考虑的一类信号，不是装上之后就自动获得高质量 Bot 防护。

### 5.2 业务身份可信度：JWT 结构识别与验签是两件事

业务流量认证检测器明确执行 JWT 结构级风险识别，不验签，仅观察；身份模块也明确 JWT Subject / OAuth Client ID 来自未验签 claims，只作关联，不用于授权判断。[认证检测器](/Users/zhanglei/Documents/JiuZhang_WAF/gateway/dynamic_security/detectors/authentication.go)、[身份凭据说明](/Users/zhanglei/Documents/JiuZhang_WAF/gateway/modules/jiuzhang_guard/identitybehavior/identity.go)

因此，这里不能写成“管理登录不安全”，也不能直接认定存在越权漏洞。准确差距是：**WDSP 当前所查能力不能等同于基于受信任发行方的 JWT 身份验证。** Cloudflare 的 API JWT 验证支持 JWKS、公钥签名校验和相应声明检查，提供了具体可对标的能力。[Cloudflare JWT 验证](https://developers.cloudflare.com/api-shield/security/jwt-validation/api/)

建议按应用建立受信任身份来源，支持必要的签名算法、Issuer / Audience / 有效期校验、密钥轮换与缓存失败策略。保留未验签身份的观察用途，但在模型、策略和界面上明确其可信程度。做 BOLA / BFLA 对抗时，还要有可信角色或对象归属依据；合法共享对象不能因为“多个账号访问”就直接被当成越权。

### 5.3 统一决策与例外：局部统一不等于所有防护只有一个裁决点

API 决策引擎已提供动作优先级及观察模式降级。然而 `Input.Exceptions` 仍标注为预留字段；该引擎的部分升级条件使用单个检测结果的 `ScoreDelta`，不能描述为所有风险天然累计后统一裁决。另有身份风险引擎负责自己的评分策略，不能反过来说产品完全没有风险评分。[API 决策引擎](/Users/zhanglei/Documents/JiuZhang_WAF/gateway/dynamic_security/decision/engine.go)、[身份风险引擎](/Users/zhanglei/Documents/JiuZhang_WAF/gateway/modules/jiuzhang_guard/riskengine)

请求链上，人工封禁、IP / L7、风险策略、CC、API 与 Coraza 处在不同阶段。**产品已有其他例外管理，并不意味着该预留字段已生效；预留字段未生效，也不等于全产品没有例外功能。** [请求处理顺序](/Users/zhanglei/Documents/JiuZhang_WAF/AGENTS.md)、[安全事件处置界面](/Users/zhanglei/Documents/JiuZhang_WAF/web/src/pages/security-events/EventDetailDrawer.tsx)

这主要影响解释与运维：用户需要知道最终是谁拦截、哪条规则有效、某个例外覆盖什么范围。优先补齐跨模块关联标识和最终处置记录，再按业务必要性完善统一例外，不必为追求概念统一而大改整个请求链。

Cloudflare 已提供序列缓解能力，但所查文档标注为 Enterprise 的封闭 Beta，应作为方向参考，不能算作普遍可购买的成熟标配。[序列缓解状态](https://developers.cloudflare.com/api-shield/security/sequence-mitigation/)

### 5.4 分布式流量 Agent：采集边界仍影响 API 可见性

2026-09-02 的交接文档记录 Phase 1–5 已开发，并记录 77 项 E2E 连续通过；同时明确列出 Gateway Sensor、AF_XDP 等后续阶段未开始。本次文件抽查与该待办方向一致，但没有重新执行这些测试。[Agent 剩余工作](/Users/zhanglei/Documents/JiuZhang_WAF/docs/agents/WDSP_AGENT_REMAINING_WORK.md)

需要重点关注的边界包括：

- TLS 终止后的 Nginx / Envoy 等网关镜像接入。
- HTTP/2、gRPC、WebSocket 帧解析与请求响应关联。
- eBPF 采集的截断边界；交接文档标注 snaplen 不超过 4096，完整采集须选择合适后端。
- 多 Receiver、负载均衡、千 Agent 场景，以及升级和回退。
- Kubernetes 当前归档测试包含模拟 API Server，不能替代真实集群的交付验证。

**这些限制针对分布式流量采集 Agent，不能扩大成“Caddy 反向代理不支持 HTTP/2 或 gRPC”。** APM 探针也属于另一条采集链，需要分别说明。

### 5.5 性能、事件时效与稳定性：已有数据，但承诺边界不足

仓库不是没有性能测试。[历史性能基线](/Users/zhanglei/Documents/JiuZhang_WAF/docs/evidence/api-security-performance-baseline.md) 已记录开发环境矩阵，以下为其中同一轮、相同测试 URL 的三臂结果：

| 场景 | 历史 QPS | 历史 P95 |
|---|---:|---:|
| 纯反向代理基线 | 5,229.45 | 10 ms |
| 仅 Coraza，DetectionOnly、全量 CRS PL1 | 1,464.97 | 28 ms |
| 仅 API 动态防护，OBSERVE | 3,859.46 | 13 ms |

**这些是历史实测记录，不是本次复测，也不是生产规格。** 环境为 M1 Pro / Docker Desktop 共享开发环境，短时压测；“WAF + API 同时开启”的生产组合、复杂业务报文、真实源站和长时间运行不能由这个表推导。也不能用该表推算与任何竞品的性能高低。

同一文档还记录了事件采集后续修复：W20 / W21 改善持续入库与断点恢复，W22 改善批次原子性及重放正确性。因此，不能把早期“只在 EOF 刷新”或“重启无界重扫”继续列为当前未修复问题。

不过，历史 W21 的十万级洪峰仍记录了 386 秒追平，W22 在共享高负载环境的端到端吞吐没有证明稳定提升。这说明还应在隔离环境验证事件入库、检索与告警延迟，而不是只测网关返回耗时。本次也未找到足以作为当前版本承诺依据的完整生产配置长稳测试归档。

### 5.6 威胁运营与交付体系：效果需要独立证据

采用 Coraza / CRS 是实际防护基础，但组件名称本身不能证明检测率、误报率或响应新漏洞的速度。商业厂商的语义分析、机器学习和情报宣传同样不能直接当成实测结论。

WDSP 需要建立可以持续复现的正常业务样本、攻击变体、规则回放、规则更新审核与回退流程，并记录每次升级的误报变化。部署升级、备份恢复、主备切换、监控告警和客户支持也应有可交付证据。对于已有设计和实现的项目，这里要求补证，不应未经核查就宣称功能缺失。

大流量 DDoS 还存在基础设施边界：流量如果已打满客户上游链路，本地应用网关难以解决。Cloudflare 的网络与清洗能力属于独立对比维度；WDSP 可通过组合交付覆盖需求。[Cloudflare DDoS 产品边界](https://developers.cloudflare.com/ddos-protection/)

## 6. UI / UX：把优势变成用户完成任务的效率

本节是根据代码流程和竞品公开文档提出的产品改进建议，**不是对六家付费控制台的现场可用性测评**。已有页面可能覆盖其中部分内容，实施前应进行任务走查。

| 用户任务 | WDSP 应重点验证或完善的体验 | 可执行的验收方式 |
|---|---|---|
| 接入第一个业务 | 一个入口说明反向代理、镜像、流量 Agent、APM 探针各能看到什么；部署后显示证书、流量、时间与数据新鲜度 | 用干净环境记录首次有效防护与首次 Trace 出现的耗时；出错时能从页面定位原因 |
| 判断一次拦截是否误报 | 展示最终拦截模块、命中依据、身份可信度、请求关联、受影响对象；说明例外影响的范围 | 用户能依据一次事件完成判断和有限范围调整，并从审计中重现过程 |
| 排查业务变慢 | 保留“安全事件 → Trace”的现有入口，补齐相关 API、服务、SQL、异常的上下文；区分未采样、无探针和无权限 | 真实慢 SQL 与独立攻击同时出现时，用户能分清关联与因果；缺数据时不展示误导性的空图结论 |
| 发布一个新模型 | 展示候选与已生效模型、差异、观察与拦截模式、预计影响、审核状态和回退入口 | 一名非开发安全人员能完成审核、发布、验证、回退，并知道当前线上版本 |
| 使用 AI 建议 | 把证据来源、建议动作、适用范围、失败情况与人工确认展示清楚 | 建议不可直接冒充已完成处置；低置信度和缺少样本时能明确说明，审核后产生可追溯操作 |

APM 功能不应继续在产品全景中遗漏。建议在功能导航和销售演示中明确两层：**无探针的入口业务性能**，以及**有相应应用采集的 Trace / SQL / 异常诊断**。这样既能展示产品价值，也不会让客户误以为安装网关即可自动获得所有代码级数据。

## 7. 改进优先级：先证明可用，再扩大覆盖

下面 P0 / P1 / P2 是产品工作的先后顺序，不是漏洞严重等级；每项都应拆成独立、可验收模块，不要求一次性重写。

| 优先级 | 工作项 | 对竞争力的作用 | 建议验收标准 |
|---|---|---|---|
| **P0** | 固化版本能力与证据清单 | 防止用设计稿或过期缺陷代表现状 | 按版本区分已实现、已接线、实测通过、受限和待办；至少提供一套可重复部署及回归记录 |
| **P0** | 同配置安全与性能基准 | 回答客户最重要的误报、漏报、时延问题 | 隔离环境测试正常业务、攻击变体、WAF / API / 组合模式；记录 P95 / P99、资源、错误率、事件可见延迟和数据丢失；长稳与重启恢复单独归档 |
| **P0** | 业务 JWT 信任链与身份标识 | 提升 API 身份和授权分析的可信度 | 伪造签名、错误发行方 / Audience、过期、密钥轮换、JWKS 不可达均有测试；未验证身份不能升级成可信授权依据 |
| **P0** | 最终处置解释与有限范围例外 | 降低误报处置成本 | 事件可追溯到最终模块、规则和有效配置；例外范围、到期和发布结果可见，且不意外绕过其他防护 |
| **P1** | 将安全 + APM 做成标准客户演示 | 把已有功能变成可感知差异 | 完成真实事件关联 Trace、慢 SQL / 异常定位；验证权限、缺采样、未接探针与数据延迟场景，记录任务耗时 |
| **P1** | Bot 挑战及多信号策略 | 缩小相对专业 Bot 产品的直接差距 | 针对正常浏览器、自动化浏览器、登录、爬取等场景建立样本；分别报告漏检、误挑战、挑战通过率和业务损失 |
| **P1** | Agent 解密后接入及协议覆盖 | 减少 API 资产与行为分析盲区 | 用真实网关和真实 K8s 验证；公开支持的协议、截断和关联边界；测试断网缓存、重连、背压和恢复 |
| **P1** | 规则与模型持续回归 | 证明升级后仍能稳定保护业务 | 固定正常业务与攻击语料，每次版本可回放；记录新增命中、误报变化和回退结果 |
| **P2** | 千 Agent / 多 Receiver / 大规模数据面 | 扩大适用客户规模 | 在目标部署规格下测持续吞吐、延迟、升级、节点失败和恢复；容量上限来自实测 |
| **P2** | AI 运营与生态集成扩展 | 减少重复人工工作 | AI 建议有可查证据与权限边界；按客户需要验证工单、SIEM、告警及处置回执，避免只有单向推送 |

若首批目标客户主要面对互联网爬虫和撞库，Bot 工作应提前；若主要是内网 API 与业务排障，优先把可信身份、安全 + APM 和真实采集覆盖做扎实。全球网络清洗不建议作为短期自建目标，可通过合作服务解决。

## 8. 建议组织一次同条件 POC，验证优势是否成立

选择目标客户最接近的两到三家产品，对齐授权模块、流量接入、保护模式、规则强度、数据保留期和支持服务，再执行以下任务。攻击用例仅在自有或明确授权的测试应用中执行。

| 场景 | 需要验证的结果 |
|---|---|
| 正常业务与 Web 攻击混合回放 | 业务成功率、误报、漏报、附加时延；同一数据集下比较，保留规则调优过程 |
| 多身份访问同类对象 | 正常共享、角色切换、批量操作与真正越权能否区分；要求可信身份及业务授权真值 |
| 模拟浏览器与低频分布式访问 | 不只看单 IP 限流；比较识别率、挑战策略和正常用户影响 |
| 安全事件与真实业务故障并存 | 从告警到确认影响和定位原因的时间；有无 Trace 时分别比较，验证 APM 集成实际收益 |
| 洪峰后排障与节点重启 | 事件可见延迟、告警延迟、丢失和重复、恢复时间；不能只报告请求端的零失败 |
| 新版本发布与回退 | 防护是否中断、策略是否一致、历史数据是否兼容、操作是否可审计 |

成本比较也应以相同目标为准：同时计算 WAF、API、Bot、APM、日志存储、硬件 / 云资源、交付和维护成本。没有报价与运行数据前，**“WDSP 一定更便宜”只能是待验证假设**。

## 9. 现有对外材料需要调整的表述

[现有 Top 20 文档](/Users/zhanglei/Documents/JiuZhang_WAF/docs/WDSP_TOP20_VS_WAF.md) 可以保留为能力目录，但其中针对“普通 WAF”的泛化描述不适合直接用于本次六家头部产品对比。API 状态盘点中的旧统计也不能直接当作当前完成比例；应结合后续代码和实测更新。

| 不宜继续泛化的说法 | 建议采用的表述 |
|---|---|
| 普通 WAF 只看 IP，没有 API 和身份 | 现代 WAAP 已覆盖 API、身份与行为；WDSP 聚焦具体业务模型和本地集成 |
| 只有 WDSP 能识别业务越权 | WDSP 已有相关检测与建模基础；实际覆盖和误报通过业务授权场景验证 |
| 有 AI 就比竞品先进 | 比较 AI 建议的依据、审核、实际效果与回退能力；阿里云等已经提供相应 AI 能力 |
| 只有我们支持私有化 | 说明 WDSP 的部署条件、数据边界、定制与运维方式，并与相同部署形态比较 |
| 竞品没有 APM | WDSP 已有安全与 APM 关联基础；比较完成同一排障任务所需的配置、步骤和成本 |
| 已有模块就等于生产成熟 | 同时提供运行接线、数据质量、测试记录、容量边界和客户验收证据 |

建议产品定位文案：

> **WDSP 面向私有化与混合业务环境，整合 Web 防护、API 动态防护和业务性能观测，帮助用户关联安全事件与业务请求，并按业务模型开展策略治理。**

这段定位对应已有实现方向；“防护更准、速度更快、成本更低、运维更省”应在同条件测试和客户交付之后再量化使用。

---

本次仅新增研究报告，未修改业务代码或运行生产测试。
