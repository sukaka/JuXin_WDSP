-- 仅用于无真实证据的测试环境；生产回滚不得自动删除证据或历史授权记录。
BEGIN;
DROP TABLE IF EXISTS request_pcap_download_grants;
ALTER TABLE request_pcap_artifacts
    DROP COLUMN IF EXISTS verification_error_code,
    DROP COLUMN IF EXISTS last_verified_at,
    DROP COLUMN IF EXISTS integrity_status;
COMMIT;
