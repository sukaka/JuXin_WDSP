# 配置发布设计（阶段3）

## 发布流程

```text
创建发布任务(幂等键去重)
  ↓
获取发布锁(Valkey SetNX + TTL 120s，防止并发发布)
  ↓
读取业务数据快照(applications/domains/upstreams/certificates)
  ↓
生成候选配置(确定性 Caddy JSON + 哈希)
  ↓
配置校验(结构 + Caddy 兼容)
  ↓
保存不可变配置版本
  ↓
Unix Socket POST /load 发布到 Caddy
  ↓
发布验证(Caddy admin 可用 + 配置已加载)
  ↓
成功: 标记当前版本 + 应用部署状态
失败: 保持旧配置 + 自动回滚 + 记录失败
```

## Unix Socket

- Caddy Admin API 仅绑定 `unix//var/run/caddy/admin.sock`
- 后端（配置控制器）与网关共享 socket 卷访问
- 不暴露 TCP 2019、不暴露宿主机公网、前端容器/测试源站不挂载
- socket 文件权限最小化（umask 077）

## 发布锁

- Valkey `jiuzhang:gateway:publish_lock`，SetNX + TTL 120s
- 同一时间仅一个发布任务，防止并发发布/回滚冲突
- 锁持有者是任务 ID，仅持有者可释放

## 发布任务

状态机：PENDING → GENERATING → VALIDATING → PUBLISHING → VERIFYING → SUCCESS/FAILED → (ROLLING_BACK → ROLLED_BACK)

字段：task_type/status/requested_by/target_version_id/current_step/progress/result_summary/failure_code/failure_message/idempotency_key/request_id

- 幂等键去重：相同幂等键返回同一任务
- 前端轮询任务进度（真实步骤，不模拟）

## 失败保护

- Caddy `/load` 原子性：无效配置返回 400 且不影响当前生效配置
- 生成/校验阶段失败：不调用 Caddy，现有配置不受影响
- 发布阶段失败（socket 断开/Caddy 400）：保持旧配置，记录失败候选
- 发布后验证失败：自动回滚到上一配置（GET /config/ 快照）

已实测：400 拒绝、网关断开、HTTPS 未绑证书等场景下现有应用持续可访问。

## 自动回滚

发布后验证失败时：
1. 标记版本 VERIFY_FAILED
2. 回滚到发布前快照配置（发布前 GET /config/ 获取）
3. 回滚失败记录 ROLLBACK_FAILED
4. 完整审计

## 配置版本

- 每次发布生成不可变版本（version_number + configuration_json + hash + business_snapshot + previous_version_id）
- 版本号：`V<时间戳>-<哈希前缀>`（全局唯一可排序）
- 当前版本唯一标记（is_current，原子切换）
- 失败版本不能作为回滚目标
- 历史版本可查看差异（与当前版本哈希对比）

## 人工回滚

- 选择历史 SUCCESS 版本 → 校验 → 发布该版本配置 → 验证 → 标记当前
- 回滚与发布共用发布锁
- 记录当前版本、目标版本、验证结果审计
