// Package apillm LLM API 安全 v1（P2-04 首批，任务书 §152-154；W12-GW 续 §154 MCP）。
//
// 数据源：网关统一主事件 llm_observation（识别 OpenAI 兼容/MCP 形态后的数据最小化观测：
// model/prompt 存在性/体量桶/token 用量/流式标记/MCP 方法名，不落 Prompt/Response 原文），
// 经 apiruntime 采集器接线（集成方装配）落 api_llm_observations（迁移 000066；
// mcp_method 列由迁移 000070 补入）。
//
// 本包职责：
//   - 采集写入：ObsStore.RecordLLMObservation 按 request_id 确定性派生主键幂等落库，
//     findings 复用事件 details 中 llm.* 明细口径（注入词表命中/未授权模型/
//     MCP 词表外方法与 tools/call 敏感参数信号）；
//   - 只读查询：GET /api/v1/api-security/llm/observations（过滤 model/endpoint/时间窗）
//     与 /llm/stats（模型分布/token 用量趋势/涉敏命中计数——复用 findings 口径）。
//   - 输入输出保护策略：security-policies CRUD 与不可变版本快照；enabled 策略经
//     GuardConfig.api_llm_security_policies 随整站发布下发，保存不冒充即时生效；
//     输出内容与 PII 开关由迁移 000196 增补，既有策略默认关闭。
//
// 权限：观测复用 api_runtime.read；策略使用 api_llm_security.read/manage（迁移 000195）。
// 未授权模型名单经发布通道下发（guardconfig gateway_runtime 组 api_llm_allowed_models，
// 逗号分隔；缺省不下发不判定）。
package apillm
