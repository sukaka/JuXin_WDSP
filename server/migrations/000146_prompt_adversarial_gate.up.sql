-- 000146 阶段7 §24.4 Prompt 发布流程补对抗测试环节。
--
-- 语义：发布门槛升级为 静态安全检查 + 测试集回归 PASSED + 对抗测试 ADVERSARIAL_PASSED
-- 三者齐备方可发布（人工审核语义不变，发布动作仍为人工触发）。本迁移为
-- ai_prompt_versions 补两列：
--   1) adversarial_result：对抗测试结论（'' = 未执行 / ADVERSARIAL_PASSED / ADVERSARIAL_FAILED）；
--   2) adversarial_detail：逐样本判定明细 JSON（[{id,category,attack,passed,reason},...]），
--      失败原因如实落库，供发布门报错与事后审计查阅。
-- 判定逻辑见 server/internal/aiprompts/adversarial.go（内置对抗样本集：
-- 提示注入/越权诱导/数据泄露诱导，样本取自迁移 000143 评估集的注入/越权类用例
-- 并结合本系统 AI 助手真实场景扩展）。
BEGIN;

ALTER TABLE ai_prompt_versions
    ADD COLUMN IF NOT EXISTS adversarial_result VARCHAR(20) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS adversarial_detail JSONB      NOT NULL DEFAULT '[]'::jsonb;

COMMENT ON COLUMN ai_prompt_versions.adversarial_result IS
    '对抗测试结论：空串 = 未执行；ADVERSARIAL_PASSED / ADVERSARIAL_FAILED；发布门要求 ADVERSARIAL_PASSED';
COMMENT ON COLUMN ai_prompt_versions.adversarial_detail IS
    '对抗测试逐样本判定明细 [{id,category,attack,passed,reason},...]，失败原因如实记录';

COMMIT;
