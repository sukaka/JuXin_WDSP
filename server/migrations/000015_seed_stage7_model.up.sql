-- 阶段7 种子：本地 Ollama 供应商与默认模型、8 个 AI Agent 注册行、模型路由档位默认值
-- 固定 UUID 保证幂等；模型路由档位默认全部指向本地 qwen2.5:3b（配置缺失不致命）。

BEGIN;

-- ---------- 模型供应商（本地 Ollama，无密钥） ----------
INSERT INTO ai_model_providers (id, name, provider_type, base_url, api_key_reference, status)
VALUES ('f7a10001-0000-4000-8000-000000000001', 'ollama-local', 'ollama', 'http://ollama:11434', '', 'ENABLED')
ON CONFLICT (name) DO NOTHING;

-- ---------- 默认模型（qwen2.5:3b，本地零成本） ----------
INSERT INTO ai_models (id, provider_id, model_code, display_name, context_window, max_output_tokens,
  supports_tools, supports_streaming, supports_structured_output, supports_embeddings,
  priority, timeout_seconds, cost_input_unit, cost_output_unit, status)
VALUES ('f7a10001-0000-4000-8000-000000000002', 'f7a10001-0000-4000-8000-000000000001',
  'qwen2.5:3b', 'Qwen2.5 3B（本地）', 32768, 2048, FALSE, TRUE, FALSE, FALSE, 1, 120, 0, 0, 'ENABLED')
ON CONFLICT (provider_id, model_code) DO NOTHING;

-- ---------- AI Agent 注册行（code 与 aiagents 包注册一致；dispatcher 为编排器内置总调度） ----------
INSERT INTO ai_agents (id, code, name, description, status) VALUES
('f7a10001-0000-4000-8000-000000000101', 'dispatcher',     '总调度 Agent',  '任务拆解、专业Agent调度、证据检查与结果合并（编排器内置，不可停用）', 'ENABLED'),
('f7a10001-0000-4000-8000-000000000102', 'security_event', '安全事件 Agent', '单事件分析、批量归纳、攻击画像与攻击链关联', 'ENABLED'),
('f7a10001-0000-4000-8000-000000000103', 'log_analysis',   '日志分析 Agent', '访问/WAF/CC/访问控制/审计日志与 Request ID 链路追踪', 'ENABLED'),
('f7a10001-0000-4000-8000-000000000104', 'waf_policy',     'WAF策略 Agent',  '误报研判、规则解释、策略优化建议与 What-If 模拟', 'ENABLED'),
('f7a10001-0000-4000-8000-000000000105', 'asset',          '资产 Agent',     '应用、域名、证书、配置版本与发布状态盘点', 'ENABLED'),
('f7a10001-0000-4000-8000-000000000106', 'ops_diagnostic', '运维诊断 Agent', '组件健康、系统告警、发布与备份故障根因分析', 'ENABLED'),
('f7a10001-0000-4000-8000-000000000107', 'report',         '报告 Agent',     '日报/周报/月报与事件专题安全运营总结', 'ENABLED'),
('f7a10001-0000-4000-8000-000000000108', 'knowledge',      '知识库 Agent',   'OWASP CRS 与产品文档知识问答（非当前运行事实）', 'ENABLED')
ON CONFLICT (code) DO NOTHING;

-- ---------- 模型路由档位默认值（simple/standard/high → model_code，由 /api/v1/ai/models/routes 维护） ----------
INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, description) VALUES
('ai', 'route_simple',   '"qwen2.5:3b"'::jsonb, 'string', 'AI 模型路由档位：简单分类任务模型'),
('ai', 'route_standard', '"qwen2.5:3b"'::jsonb, 'string', 'AI 模型路由档位：标准分析任务模型'),
('ai', 'route_high',     '"qwen2.5:3b"'::jsonb, 'string', 'AI 模型路由档位：高能力分析任务模型')
ON CONFLICT (setting_group, setting_key) DO NOTHING;

COMMIT;
