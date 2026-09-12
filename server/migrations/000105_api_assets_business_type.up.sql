-- 000105 api_assets 业务标签（WDSP AI 自动化渗透防护增强 阶段4；设计 #12.1）。
--   business_type  敏感业务流标签：LOGIN/REGISTER/PASSWORD_RESET/SMS/EMAIL/ORDER/PAYMENT/
--                  EXPORT/DOWNLOAD/SEARCH/QUERY_PERSONAL_DATA/AI_INFERENCE/OTHER。
-- 枚举值由应用层校验（apiassets handler/store；与 exposure 同纪律，不落 CHECK 约束
-- 便于后续扩枚举不迁移）；Export Abuse 检测按本列圈定导出端点（设计 #12.2）。
BEGIN;

ALTER TABLE api_assets ADD COLUMN IF NOT EXISTS business_type VARCHAR(32) NOT NULL DEFAULT 'OTHER';

COMMIT;
