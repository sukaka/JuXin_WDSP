# IP访问控制设计（阶段5）

## 模型

| 维度 | 取值 |
|------|------|
| 规则类型 | ALLOW / DENY |
| 范围 | GLOBAL / APPLICATION |
| 有效期 | PERMANENT / TEMPORARY（15分钟/1小时/4小时/1天/7天/30天/自定义） |
| 状态 | DRAFT / ACTIVE / DISABLED / EXPIRED / DELETED |
| 来源 | MANUAL / SECURITY_EVENT / IMPORT / AUTO_BLOCK / SYSTEM |

地址支持单 IPv4、IPv4 CIDR、单 IPv6、IPv6 CIDR；禁止域名、协议、端口、通配、非法掩码；
IPv4 映射 IPv6 归一；CIDR 掩码化。`hit_count` / `last_hit_at` 由事件采集器按 IP_DENY_MATCH/IP_ALLOW_MATCH 事件回写。

## 优先级

```text
全局白 > 应用白 > 全局黑 > 应用黑 > CC防护 > WAF检测
```

- 第一层命中即决定最终动作；同层按显式优先级（数值小者优先），记录全部匹配供审计。
- 白名单绕过黑名单与 CC，不绕过协议校验与 WAF。
- 保护地址（`protected_addresses`）先于一切：网关/管理平台/数据库/缓存/源站/可信代理/回环/
  链路本地/自定义地址永不封禁；API 创建 DENY 命中保护地址直接 400 + 高风险审计。

## 临时规则与自动失效

- TEMPORARY 必须 `effective_until`（UTC 存储，前端按时区显示）；
- 网关按规则内嵌时间窗评估，到期无需发布即停止执行；
- 管理平台标记 EXPIRED 并保留历史；支持延期（extend）与立即解封（release）。

## 批量导入导出

- CSV（表头 `address,rule_type,scope_type,application_code,effective_until,reason`）或纯文本（每行一个地址）；
- 导入前校验：地址/重复/应用存在性/类型/时间/文件大小(≤1MB)/行数(≤10000)/保护地址；
  错误定位到行，预览（dry_run）后才可正式导入；
- 两种模式由管理员显式选择：`ALL_OR_NOTHING`（事务）或 `SKIP_ERRORS`；
- 导出 CSV 防公式注入：`=`、`+`、`-`、`@` 开头字段前加 `'`。

## 从安全事件加入黑名单

阶段4安全事件与访问控制事件均可作为来源：`source_type=SECURITY_EVENT` + `source_event_id`。
管理员必须确认范围（全局/应用）、时长、是否立即发布；命中保护地址直接拒绝；
不得未经确认自动永久封禁（临时封禁转永久需人工操作 `convert-to-permanent`）。

## 配置发布与版本

- 发布走统一发布链路（同阶段3/4）：草稿校验 → 生成 guard 配置 → 差异与版本 → 网关校验 → 发布 → 验证；
- 每次发布将访问控制全量配置（可信代理/保护地址/黑白名单/CC策略）快照存入
  `access_control_versions`（不可变、version_no 自增、配置哈希、变更摘要、发布结果回填）；
- 回滚：读取历史快照，以其覆盖当前数据重新走完整发布流程（`POST /api/v1/access-control/versions/{id}/rollback`）；
- 发布失败：当前名单与 CC 继续生效，不清空、不切观察模式，保存错误，支持重试与回滚，全部审计。

## 接口

见 docs/API_DESIGN.md 阶段5 章节（`/access-rules`、`/protected-addresses`、`/access-control/versions`）。
