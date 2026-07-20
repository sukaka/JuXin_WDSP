# 操作审计设计（阶段2）

## 审计原则

- 服务端生成，不依赖前端上报
- 仅新增与查询，禁止 UPDATE/DELETE（数据库 RULE `operation_audits_no_update/no_delete` 强制）
- 高风险操作记录前后差异（脱敏）
- 失败操作同样记录
- 与 Request ID 关联，UTC 时间存储

## 审计范围（阶段2）

用户创建/修改/启停/解锁/删除、重置密码、角色分配、强制下线、修改密码、系统设置变更、导出登录日志/审计日志、登录相关事件（另入 login_logs）。

## 字段

id、occurred_at、user_id、username、source_ip、connection_ip、user_agent_summary、module、action、object_type、object_id、object_name、before_summary、after_summary、result、failure_reason、risk_level、request_id、previous_hash、record_hash

## 风险分级

| 等级 | 示例 |
|------|------|
| LOW | 查看、修改显示名、解锁 |
| MEDIUM | 创建用户、停用用户、修改系统设置、强制下线 |
| HIGH | 重置密码、删除用户、导出 |
| CRITICAL | 分配系统管理员角色 |

## 敏感字段脱敏

审计摘要（before/after）经 `MaskSensitiveJSON` 处理，以下字段统一替换为 `********`：
password、password_hash、old_password、new_password、temporary_password、session_id、cookie、token、csrf_token、captcha_code、private_key、secret、authorization。
临时密码仅在创建/重置接口响应中返回一次，绝不写入审计/日志。非法 JSON 不原样放行。

## 哈希链（防篡改基础）

- 每条记录含 `previous_hash`（上一条 record_hash）与 `record_hash`
- `record_hash = sha256(occurred_at|username|module|action|object_type|object_id|result|request_id|previous_hash)`（固定字段顺序规范化）
- `POST /api/v1/audits/verify-chain` 校验链完整性与记录哈希重算
- 不一致返回 mismatch 记录 ID 清单
- 数据库账号最小权限 + RULE 禁止改删，构成基础防篡改；不含区块链/可信时间戳（后续可选）

## 数据库权限

- 审计表：应用账号仅 INSERT/SELECT，RULE 禁止 UPDATE/DELETE
- 业务接口不提供审计修改/删除端点

## 查询与导出

- 查询：时间范围、操作人、来源IP、模块、操作、对象类型、结果、风险等级、Request ID
- 仅 AUDIT_ADMIN 有完整查询（audits.read）与导出（audits.export，CSV ≤10000 条）
- 导出操作本身记录审计（HIGH）
