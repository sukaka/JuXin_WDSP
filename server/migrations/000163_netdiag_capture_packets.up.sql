-- 000163 网络诊断抓包页面内数据包解析展示（docs/NETWORK_TOOLS_DESIGN.md §3.6）：
--   netdiag_jobs.capture_packets 存 Worker 解析 pcap 后的数据包列表 JSONB
--   （NetdiagCapturePacket 数组，最多前 200 个包）；
--   NULL = 非抓包任务 / 产物未解析或解析失败（页面回退为仅显示下载按钮）。
--   仅详情接口（GetByID）带出，列表不查该列避免大 payload。
BEGIN;

ALTER TABLE netdiag_jobs
    ADD COLUMN IF NOT EXISTS capture_packets jsonb;

COMMIT;
