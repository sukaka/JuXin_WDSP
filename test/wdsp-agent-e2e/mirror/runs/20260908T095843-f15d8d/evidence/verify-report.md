# P1-03 G2 Nginx mirror 取证断言

记录总数：8

- [PASS] S1 记录存在
- [PASS] S1 方法/Host/路径
- [PASS] S1 query token 脱敏
- [PASS] S1 authorization/cookie 脱敏
- [PASS] S1 允许的普通头保留
- [PASS] S1 伪造 X-Forwarded-For 被 Nginx 覆盖
- [PASS] S1 五元组不采信外部头
- [PASS] S1 x-wdsp-* 控制头剥离
- [PASS] S1 单向源口径
- [PASS] S1 来源标识
- [PASS] S1 TLS 可见性 DECRYPTED（可信终止点拓扑断言）
- [PASS] S1 观测/原协议
- [PASS] S1 event_id 稳定形态
- [PASS] S2 记录存在
- [PASS] S2 JSON 一级字段脱敏
- [PASS] S3 源站 500 请求已镜像
- [PASS] S3 response 仍恒 null（源站状态不回填）
- [FAIL] S4 记录存在：
- [PASS] S5 慢上传记录存在
- [PASS] S6 取消后采集正常
- [PASS] S7 适配器恢复后采集正常
- [PASS] S8 无令牌 403
- [PASS] S8 错令牌 403
- [PASS] S8 多令牌 403
- [PASS] S8 forbidden 计数 ≥3
- [PASS] S9 socket 0660 属组 nginx
- [PASS] S10 记录存在
- [FAIL] S10 正文不驻留且原始大小照记：{"captured_bytes": 0, "original_total_size": 0, "truncated": false, "skipped_reason": ""}
- [PASS] 全局 无明文泄漏 tok-plain-s1…
- [PASS] 全局 无明文泄漏 plain-secret…
- [PASS] 全局 无明文泄漏 plain-cookie…
- [PASS] 全局 无明文泄漏 plain-secret…
- [PASS] 全局 无明文泄漏 plain-secret…
- [PASS] 全局 无明文泄漏 b17561f73944…
- [PASS] 业务 源站收全量上传（≥8MB+200KB）
