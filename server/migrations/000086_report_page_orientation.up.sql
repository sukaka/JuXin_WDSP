-- 报告可选项：PDF/Word 纸张方向（P 竖向 / L 横向）
BEGIN;

ALTER TABLE report_jobs ADD COLUMN IF NOT EXISTS page_orientation VARCHAR(2) NOT NULL DEFAULT 'P';
ALTER TABLE report_schedules ADD COLUMN IF NOT EXISTS page_orientation VARCHAR(2) NOT NULL DEFAULT 'P';

COMMIT;
