-- 000134 回滚：删除安全回归证据登记与发布门禁表。
-- 注意：runs/cases/gate_decisions 为不可变证据留痕，回滚迁移会删除登记历史；
-- 受控本地目录中的对象文件由运维按保留期另行清理，本脚本不触碰文件。
BEGIN;

DROP TABLE IF EXISTS security_regression_gate_decisions;
DROP TABLE IF EXISTS security_regression_policy;
DROP TABLE IF EXISTS security_regression_run_objects;
DROP TABLE IF EXISTS security_regression_cases;
DROP TABLE IF EXISTS security_regression_runs;
DROP TABLE IF EXISTS security_regression_objects;

COMMIT;
