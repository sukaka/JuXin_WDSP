-- WDSP Identity/Behavior V1.1：统一身份类型与置信度契约。
-- 仅增量扩展既有 client_identity / behavior_statistics 表，不创建重复表。
BEGIN;

ALTER TABLE client_identity
  ADD COLUMN IF NOT EXISTS identity_confidence SMALLINT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS confidence_source JSONB NOT NULL DEFAULT '[]'::jsonb;

-- 历史版本允许扩展身份字符串；先归一化存量数据，再收紧新契约约束。
UPDATE client_identity
SET identity_type = 'UNKNOWN'
WHERE identity_type NOT IN ('HUMAN','BOT','APPLICATION','SERVICE','MACHINE','AGENT','UNKNOWN');

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'client_identity_identity_confidence_range'
      AND conrelid = 'client_identity'::regclass
  ) THEN
    ALTER TABLE client_identity
      ADD CONSTRAINT client_identity_identity_confidence_range
      CHECK (identity_confidence BETWEEN 0 AND 100);
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'client_identity_identity_type_valid'
      AND conrelid = 'client_identity'::regclass
  ) THEN
    ALTER TABLE client_identity
      ADD CONSTRAINT client_identity_identity_type_valid
      CHECK (identity_type IN ('HUMAN','BOT','APPLICATION','SERVICE','MACHINE','AGENT','UNKNOWN'));
  END IF;
END $$;

ALTER TABLE behavior_statistics
  ADD COLUMN IF NOT EXISTS object_enum_count BIGINT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS account_enum_count BIGINT NOT NULL DEFAULT 0,
  -- 现有表的 window_start 即 V1.1 逻辑设计中的 window_started_at，避免重复列。
  ADD COLUMN IF NOT EXISTS window_ended_at TIMESTAMPTZ;

COMMIT;
