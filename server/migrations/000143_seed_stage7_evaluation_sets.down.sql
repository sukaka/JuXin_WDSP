-- 阶段7 §34.1 内置评估集种子回滚

BEGIN;

DELETE FROM ai_evaluation_sets WHERE code IN
  ('eval_event_analysis', 'eval_false_positive', 'eval_rule_explain', 'eval_attack_profile',
   'eval_attack_chain', 'eval_root_cause', 'eval_policy_advice', 'eval_what_if',
   'eval_report_summary', 'eval_prompt_injection', 'eval_privilege_denial', 'eval_insufficient_data');

COMMIT;
