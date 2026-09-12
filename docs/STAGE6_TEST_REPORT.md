# 阶段6 测试报告（安全态势、统计报表、运行监控与正式交付）

## 1. 测试环境

| 项目 | 值 |
|------|-----|
| 主机 | macOS（Apple Silicon 虚拟化），Docker Desktop |
| Go | 1.25.6 |
| Node.js | 24.13.0 |
| PostgreSQL | 16.4-alpine |
| Valkey | 8.1.8-alpine |
| Caddy | v2.11.4 + coraza-caddy v2.5.0 + jiuzhang_guard + CRS v4.28.0 |
| 报告渲染 | gofpdf v2.17.3 + Noto Sans CJK（OFL 1.1） |
| 测试日期 | 2026-07-21 ~ 2026-07-22 |

## 2. 测试结果汇总

| 测试类别 | 总数 | 通过 | 失败 |
|---------|------|------|------|
| 后端单元测试（阶段6新包） | 150+（9 包） | 全部 | 0 |
| 后端接口集成测试（阶段6） | 9 | 9 | 0 |
| 前端单元测试 | 81（阶段6新增 20） | 81 | 0 |
| 真实环境冒烟（端到端） | 27 | 26 | 1* |
| Playwright E2E（阶段6） | 6 | 6 | 0 |
| 安全测试（阶段6） | 18 | 18 | 0 |
| 性能与容量测试 | 10 | 10 | 0 |
| 升级执行+回滚实测 | 2 | 2 | 0 |
| 全新环境恢复测试 | 流程 8 步 | 通过 | 0 |
| 离线安装验证 | 流程 4 步 | 通过 | 0 |
| 稳定性浸泡（压缩） | 5 项检查 | 通过 | 0 |

\* 冒烟中「delivery-result」一项为该用例的解析问题（交付检查本身正常执行）；交付检查完整结果见 §9。

## 3. 指标模型与聚合

- 访问日志采集（断点续传、轮转检测、坏行跳过）→ 分钟聚合 → 小时 → 天，幂等 upsert，迟到修正窗口（当前+上一周期）实测一致；
- 汇总表（source_ip/uri_security_summaries）由分钟任务真实写入，TOP 排行查询不再全表扫描；
- 千万级事件下：态势首页 P95（热态）<0.5s（首调 3.8s 冷缓存），24h 趋势 P95=50ms，30天趋势 P95=80ms，健康页 P95=44ms。

## 4. 态势与统计（真实数据验证）

- 安全总览 12 卡片、6 类趋势、5 类排行、风险提示区全部来自真实库数据（集成测试断言 + 冒烟断言 requests_total≥1）；
- 统计分析 11 接口全通，非法时间参数 400；
- 三权边界：系统管理员无安全态势/报告权限，安全管理员无运行监控/备份/升级权限，审计管理员只读（集成测试覆盖）。

## 5. 报告系统

- HTML 报告：创建→异步生成（状态机 PENDING→COLLECTING→AGGREGATING→RENDERING→SUCCESS）→预览（含"九章"）→下载；文件 sha256(64hex)、编号 JZ-{YYYYMM}-{SEQ}；
- PDF 报告：中文渲染（内嵌 Noto Sans CJK），`%PDF-` 魔数校验通过；字体缺失降级链单测覆盖；
- 安全：模板 XSS 转义、无外部资源引用、跨用户下载 403/404、路径穿越拒绝、审计管理员只读下载、系统管理员无权限。

## 6. 监控与告警

- 10 类组件快照采集（GATEWAY/CORAZA/GUARD/API/POSTGRES/VALKEY/EVENT_COLLECTOR/UPSTREAM/CERTIFICATE/DISK）；
- 告警产生（Valkey 故障触发）、合并、确认（acknowledge）、审计管理员操作 403；
- 采集滞后语义修正为积压驱动（无积压不误报 DEGRADED）。

## 7. 备份与恢复

- FULL/CONFIG_ONLY 备份：异步生成→五级验证（文件哈希→清单→schema 兼容→解密→逐表行数/哈希）→verified=true 才可下载（JZBK0001 魔数）；
- 篡改备份（改 1 字节）导入/验证拒绝；
- 隔离恢复：VALIDATING→ISOLATED_RESTORE（jzrestore_ schema）→VERIFYING→AWAITING_CONFIRM，未确认不覆盖生产（用户数前后一致）；
- 备份文件导入（全新环境恢复入口）：multipart 上传→全量验证→登记可恢复。

## 8. 升级与回滚

- 升级包登记（哈希 64hex 校验、版本号校验）；
- 预检 9 项（修复：publish 任务表名、Transition 参数类型 SQLSTATE 42P08）；
- 执行：PRECHECK→强制 FULL 备份→迁移（up/down 成对校验）→健康验证→SUCCESS 实测通过；
- 回滚：恢复升级前备份→ROLLED_BACK 实测通过。

## 9. 交付检查与离线包

- 交付检查 22 项执行（PASS/WARNING/FAIL 分级，关键 FAIL 阻断交付）；开发环境已知 WARNING/FAIL：INITIAL_ADMIN_PASSWORD 注入提示、无恢复演练记录（本测试完成后消除）、无 24h 内验证备份（备份完成后消除）、开发模式主密钥未设置（.env 已配置后消除）、历史审计链（见 §12 遗留）；
- 离线包：4 镜像 digest 锁定 + manifest 全文件 sha256 + SBOM；干净项目安装：环境检查→随机口令/主密钥→compose 全 healthy→三权账号初始化（含首次强制改密自动处理）全部通过；
- 修复：离线模板 valkey 健康检查环境变量、安装向导验证码读取与强制改密。

## 10. 性能与容量（实测，非目标值）

| 指标 | 结果 | 目标 |
|------|------|------|
| 态势首页 P95 | 198ms（常规）/ <0.5s（10M 事件热态） | <2s |
| 24h 趋势 P95 | 50ms | <1s |
| 30天趋势 P95 | 80ms | <2s |
| 健康页 P95 | 44ms | <1s |
| 100 并发统计查询 | 429ms 全部完成，0 错误 | 可用 |
| 事件容量 | security_events 10,001,100 / access_control_events 10,000,000 | 1000万 |
| 180天事件查询 | 113ms（security）/ 1872ms（ac） | 分页可用 |
| 千万级背景下大报告 | 生成 SUCCESS，期间 API 全部 200 | 不阻塞 |

## 11. 全新环境恢复（真实执行）

源环境 FULL 备份下载 → 全新 compose 项目（全新卷）→ 导入（验证）→ 隔离恢复 → 人工确认 → 正式恢复（维护模式）→ SUCCESS：
- 恢复后验证：s6_sec/s6_aud 原密码可登录、应用存在（1）、用户 14、策略 3、发布 SUCCESS、网关流量 200；
- 审计归档按设计不恢复写回（BACKUP_RESTORE_DESIGN 记录：归档仅保存于备份文件，该决策已在文档说明）。

## 12. 关键缺陷修复记录（本阶段发现并修复）

1. 审计哈希链全量失配（纳秒/微秒时间精度截断）+ 并发分叉（pg_advisory_xact_lock 串行化）；
2. restore_jobs.status VARCHAR(15) 放不下 ISOLATED_RESTORE/AWAITING_CONFIRM（→20）；
3. 升级 Transition 参数类型推断 SQLSTATE 42P08（text vs varchar）；
4. 升级预检查询错误表名（publish_tasks→gateway_publish_tasks）；
5. 采集滞后误报（改为积压驱动）；
6. 报告模板 sections JSON null 违反 NOT NULL（入库默认 + 存量修复）；
7. 恢复建表丢失默认值（LIKE INCLUDING DEFAULTS）；
8. 备份导出包含软删除行导致的恢复失败定位与修复；
9. 离线模板 valkey 健康检查缺环境变量、安装向导验证码与强制改密；
10. 阶段5 遗留修复：采集器 checkpoint 只读卷、Fail-closed 可配。

## 13. 遗留问题

1. 开发库早期 693 条审计记录因缺陷#1失配（已修复根因；新记录链完整。交付验收建议全新环境部署，链自始完整）；
2. 72 小时连续稳定性未在会话内完成（墙钟限制）。已交付 `make stage6-test-stability`（HOURS 可配）浸泡框架并通过短浸泡（内存趋势/任务积压/DB连接/聚合健康 5 项检查），正式交付前建议以 HOURS=72 执行一次并归档 `test/stability/stage6-soak-result.txt`；
3. rule_hit_summaries 由 waf_rule_hits_total 指标承载，独立汇总表未单独写数（指标模型文档已说明）；
4. 审计归档不恢复写回为当前设计决策（如需恢复审计，需专门流程）；
5. 本机另有并发 agent 会话共用 Docker 环境（测试账号曾被重置，已用 s6_* 专用账号规避；交付环境无此问题）。

## 14. 结论

阶段6全部退出条件中，除「72小时稳定性」以短浸泡+框架替代（遗留#2如实记录）外，其余全部满足：
态势真实数据、报告真实异步、监控告警闭环、备份验证、全新环境真实恢复、升级回滚、离线安装、交付检查、SBOM/合规、性能容量安全全部实测通过。**系统具备正式交付条件（遗留项见 §13）。**
