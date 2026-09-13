-- 网络诊断工具任务表（netdiag 模块）
-- 管理面仅写共享卷请求文件，由网关侧 netmgrd 消费执行并回写结果；
-- 抓包产物（pcap）由 Worker 从共享卷搬入服务端数据目录并记录 sha256。

BEGIN;

CREATE TABLE netdiag_jobs (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  node            varchar(64)  NOT NULL,
  action          varchar(16)  NOT NULL CHECK (action IN ('ping','tcp_probe','traceroute','dns_query','capture')),
  target          varchar(253) NOT NULL,
  params          jsonb        NOT NULL DEFAULT '{}',
  status          varchar(12)  NOT NULL DEFAULT 'PENDING'
                  CHECK (status IN ('PENDING','RUNNING','SUCCESS','FAILED','STOPPED','TIMEOUT')),
  result_text     text         NOT NULL DEFAULT '',
  exit_code       int,
  duration_ms     bigint,
  capture_file    varchar(255) NOT NULL DEFAULT '',
  capture_size    bigint,
  capture_hash    varchar(64)  NOT NULL DEFAULT '',
  failure_message varchar(512) NOT NULL DEFAULT '',
  requested_by    uuid,
  request_id      varchar(64)  NOT NULL DEFAULT '',
  created_at      timestamptz  NOT NULL DEFAULT now(),
  started_at      timestamptz,
  finished_at     timestamptz
);

CREATE INDEX idx_netdiag_jobs_created ON netdiag_jobs (created_at DESC);

COMMIT;
