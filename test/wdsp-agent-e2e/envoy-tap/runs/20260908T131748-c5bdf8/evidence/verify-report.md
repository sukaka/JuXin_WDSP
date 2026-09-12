# P1-03 G3 Envoy tap 取证断言

记录总数：17

## 取消/截止场景实际到达形态（如实记录）

- grpc-s5: 1 条 [{"assoc": "COMPLETE", "reason": "", "grpc": {"service": "test.Echo", "method": "ServerStream", "grpc_status": null, "stream_state": "UNKNOWN"}}]
- grpc-s6: 1 条 [{"assoc": "COMPLETE", "reason": "", "grpc": {"service": "test.Echo", "method": "ServerStream", "grpc_status": 14, "stream_state": "CLOSED"}}]

## 断言

- [PASS] S1 6 条 H2 流全部按流配对（X-Rid 回显一致，不串流）
- [PASS] S1 来源/协议/TLS 口径
- [PASS] S1 capture_stream_id 为 null（tap 缓冲输出无流 ID，不造假）
- [PASS] S1 query token 脱敏
- [PASS] S1 五元组占位（tap 不含地址，不伪造）
- [PASS] S1 tap 时戳口径（latency 恒 0 不表达业务延迟）
- [PASS] S2 gRPC unary 记录存在
- [PASS] S2 service/method 解析
- [PASS] S2 grpc_status=0 + CLOSED
- [PASS] S2 HTTP 200 与 RPC 状态分列
- [PASS] S2 gRPC 正文不采集
- [PASS] S2 响应 trailers 可见
- [PASS] S3 记录存在
- [PASS] S3 grpc_status=3（HTTP 200 ≠ RPC 成功）
- [PASS] S3 trailer 敏感标记脱敏（set-cookie）
- [PASS] S4 streaming 成功记录（CLOSED/0）
- [PASS] S5 取消 不伪造成功（grpc_status≠0 或 UNKNOWN/REQUEST_ONLY）
- [PASS] S6 截止 不伪造成功（grpc_status≠0 或 UNKNOWN/REQUEST_ONLY）
- [PASS] S7 WS 握手记录存在
- [PASS] S7 握手视图 101 + COMPLETE
- [PASS] S7 握手请求头可见（upgrade/sec-websocket-key）
- [PASS] S7 相位 B 协议断言（observed=1.1 / PLAINTEXT）
- [PASS] S7 帧内容不驻留（正文为空）
- [PASS] S8 WS 握手失败记录（403）
- [PASS] S9 Envoy 重启后采集恢复（s9-after 记录存在）
- [PASS] S10 适配器恢复后采集恢复（s10-after 记录存在）
- [PASS] S12 记录存在
- [PASS] S12 truncated=true 且 original_total_size=null（截断但总大小未知）
- [PASS] 适配器断连/重连计数（S9 生效）
- [PASS] 适配器无解析错误/超限丢弃
- [PASS] 全局 无明文泄漏 plain-h2tok…
- [PASS] 全局 无明文泄漏 plain-ws-secret…
- [PASS] 全局 无明文泄漏 plain-trailer-se…
- [PASS] 全局 无明文泄漏 ws-frame-secret-…
