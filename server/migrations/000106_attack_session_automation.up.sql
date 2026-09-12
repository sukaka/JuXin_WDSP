-- 000106 attack_session 自动化攻击标注（WDSP AI 自动化渗透防护增强 阶段4 补充；设计 #45
-- 「一个身份在一段时间内是否正在执行自动化攻击行为」的显式派生标注）。
--   automation_suspected  派生判定：会话内有效阶段（非 UNKNOWN）≥ 3 且命中自动化指示
--                         信号（无头/枚举/低慢类，见 attacksessions/automation.go），
--                         单调 false→true（会话内证据只增不减，不回退）。
--   automation_basis      判定依据（可解释：命中阶段集 + 指示信号），随 suspected 同步维护。
BEGIN;

ALTER TABLE attack_session ADD COLUMN IF NOT EXISTS automation_suspected BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE attack_session ADD COLUMN IF NOT EXISTS automation_basis VARCHAR(256) NOT NULL DEFAULT '';

COMMIT;
