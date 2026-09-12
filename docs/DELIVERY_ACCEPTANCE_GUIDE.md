# 九章WAF 交付验收指南

适用版本：九章WEB应用智能防护系统 V2.0（阶段6 交付版）
适用对象：交付验收组（建设方、实施方、监理/审计代表）

本指南约定验收前准备、系统内置交付检查 23 项逐项说明与通过标准、性能与安全验收项、文档清单核对、验收记录表模板及 FAIL/WARNING 处置规则。

## 1. 验收前准备

### 1.1 环境准备

- 按《部署文档》（`docs/DEPLOYMENT.md`）完成生产/准生产环境部署，Docker 24+、Docker Compose v2+。
- 安装向导 `ops/install/install.sh` 已完成：`.env` 生成随机 `POSTGRES_PASSWORD` / `VALKEY_PASSWORD` / `JIUZHANG_MASTER_KEY`，服务全部启动。
- 生产环境必须启用 HTTPS，且 `COOKIE_SECURE=true`、`JIUZHANG_MASTER_KEY` 已注入（prod 强制校验，缺失拒绝启动）。
- 移除初始化变量：`INITIAL_ADMIN_PASSWORD` 不得残留在环境中。
- 基线检查通过：`ops/healthcheck/check.sh` 退出码 0；`GET /api/v1/health` 返回 `{"status":"ok",...}`。

### 1.2 账号准备

- 三权账号齐备且分属三人：系统管理员、安全管理员、审计管理员各至少一名启用账号（交付检查 three_role_accounts 项）。
- 初始管理员完成首次登录强制改密；验收账号密码经安全渠道分发。
- 密码策略确认：最小长度 ≥12（系统设置 → 密码组）。

### 1.3 数据准备

- 至少一个 Web 应用完成接入并发布（存在网关配置版本，config_version_exists 项）。
- 黑白名单、CC 策略按业务基线配置并发布（access_control_available 项）。
- 至少一份已验证的 FULL 备份（backup_available 关键项）；至少一次成功恢复演练记录（restore_drill 项）。
- 至少生成过一份安全报告（report_generation 项；有模板时为 WARNING，建议试生成一份）。

## 2. 交付检查 23 项逐项说明

执行入口：系统管理员登录 → 「系统运维 → 交付检查」（`/delivery-check`）→ 执行检查（`POST /api/v1/delivery-checks/run`）。结果查询 `GET /api/v1/delivery-checks/{id}`，导出 `GET /api/v1/delivery-checks/{id}/export`。审计管理员只读查看。

整体判定：任一**关键项 FAIL → 整体 FAIL**；无关键 FAIL 但存在 WARNING 或非关键 FAIL → 整体 WARNING；全部通过 → PASS（NOT_APPLICABLE 不参与判定）。

| # | 检查项 key | 名称 | 类别 | 关键 | 通过标准 |
|---|-----------|------|------|------|---------|
| 1 | components_up | 核心组件全部运行正常 | 运行状态 | 是 | GATEWAY/API/POSTGRES/VALKEY/EVENT_COLLECTOR 最新快照全部 UP；缺快照为 WARNING |
| 2 | https_config | 管理平台 HTTPS 强制配置 | 安全配置 | 是 | prod 环境 COOKIE_SECURE=true |
| 3 | three_role_accounts | 三权分立账号齐备 | 账号权限 | 是 | SYSTEM_ADMIN/SECURITY_ADMIN/AUDIT_ADMIN 各有 ≥1 名启用用户 |
| 4 | password_policy | 密码策略合规 | 安全配置 | 是 | 密码最小长度 ≥12 |
| 5 | caddy_admin_socket | Caddy Admin 未暴露 TCP | 安全配置 | 是 | Admin Socket 文件存在且为 Unix Socket（非 TCP 2019） |
| 6 | postgres_bind | PostgreSQL 未公网暴露 | 安全配置 | 是 | 绑定回环/私网地址或内部主机名 |
| 7 | valkey_bind | Valkey 未公网暴露 | 安全配置 | 是 | 同上 |
| 8 | config_version_exists | 当前网关配置版本存在 | 防护能力 | 是 | 至少发布过一个配置版本 |
| 9 | waf_detection | WAF 检测能力可用 | 防护能力 | 是 | CRS 规则目录可读且含 `.conf` 规则文件 |
| 10 | access_control_available | 黑白名单/CC 策略接口可用 | 防护能力 | 否 | ip_access_rules、rate_limit_policies 表可查询（返回条数） |
| 11 | event_collector_lag | 事件采集滞后 <60s | 运行状态 | 否 | 采集器 UP 且 max_lag_seconds <60；超时为 WARNING |
| 12 | report_generation | 报告生成能力可用 | 防护能力 | 否 | 近 7 天有成功报告；仅模板可用为 WARNING；无模板 FAIL |
| 13 | backup_available | 最近已验证备份 <7天 | 运行状态 | 是 | 存在 status=SUCCESS 且 verified 的备份，完成时间距今 <7 天 |
| 14 | restore_drill | 恢复演练记录存在 | 质量保障 | 否 | 存在 SUCCESS 恢复记录；无记录为 WARNING |
| 15 | audit_chain | 审计哈希链完整 | 合规交付 | 是 | 全量校验不一致数为 0 |
| 16 | third_party_notices | THIRD_PARTY_NOTICES 存在 | 合规交付 | 否 | 文件存在且非空 |
| 17 | sbom_exists | SBOM 文件存在 | 合规交付 | 否 | `docs/SBOM.spdx.json` 存在且为合法 JSON |
| 18 | docs_present | 交付关键文档齐备 | 合规交付 | 否 | 8 份文档齐备（见 5.1）；缺失为 WARNING |
| 19 | vulnerability_scan | 漏洞扫描无未修复高危发现 | 安全配置 | 是 | 扫描脚本（generate-sbom.sh/license-audit.sh）齐备可执行且 SBOM 合法；`docs/VULN_KNOWN_HIGH.md` 登记表无未修复条目；登记表缺失或超 90 天未更新为 WARNING |
| 20 | no_default_password | 无默认/硬编码初始口令 | 安全配置 | 否 | `INITIAL_ADMIN_PASSWORD` 未在环境注入；残留为 WARNING |
| 21 | no_debug_endpoints | 无调试接口暴露 | 安全配置 | 是 | 本机探测 `/debug/pprof/` 不返回 200 |
| 22 | no_placeholder_secrets | 无占位口令/Mock 标记配置 | 质量保障 | 否 | `POSTGRES_PASSWORD`/`VALKEY_PASSWORD`/`JIUZHANG_MASTER_KEY` 均已设置且非弱口令占位值 |
| 23 | test_reports | 阶段测试报告存在 | 质量保障 | 否 | `docs/STAGE*_TEST_REPORT.md` 至少一份 |

> 检查项实现见 `server/internal/delivery/checks.go`，判定规则见 `server/internal/delivery/delivery.go`。验收时以系统实际输出为准，本表为解释说明。

## 3. 性能验收项

性能基线引用阶段5 真实网关性能测试（`docs/STAGE5_TEST_REPORT.md` 第 7 节，原始数据 `test/performance/stage5-performance-result.txt`，复跑命令 `make stage5-test-performance`）：

| 指标 | 阶段5 实测 | 验收要求 |
|------|-----------|---------|
| 基线时延 P50/P95/P99 | 3ms / 9ms / 11ms（RPS 12728） | 复测不劣于基线量级 |
| 1000/10000 条黑名单新增时延 | P95 7ms（Δ<5ms） | Δ<5ms |
| 1000 条 CIDR 新增时延 | P95 7ms（Δ<5ms） | Δ<5ms |
| CC 计数（100 策略）新增时延 | P95 6ms（Δ<10ms） | Δ<10ms |
| 200 并发 20000 请求 | RPS 14742、0 失败、P95 29ms | ≥500 RPS 且无持续错误 |
| 随机键攻击内存 | 稳定有界（TTL 过期） | 不无限增长 |
| 发布期间打流 | 0 失败 | 发布不中断业务 |

阶段6 稳定性、容量与故障恢复测试结果为验收补充依据，见 `docs/STAGE6_TEST_REPORT.md`（阶段6 测试完成后归档）；验收现场可按 `test/performance/`、`test/security/` 脚本抽测复跑。

## 4. 安全验收项

- 管理面 HTTPS 与 Cookie 安全：prod 强制 `COOKIE_SECURE`（检查项 2）；CSRF 三重防护（SameSite Cookie + Token + Origin）。
- 认证与会话：图形验证码、登录失败 5 次锁 15 分钟、统一错误提示防枚举、会话空闲 30 分钟/绝对 8 小时。
- 三权分立：互斥角色后端强制；系统管理员访问业务接口返回 403（阶段5 集成测试 RBAC 边界用例可复跑）。
- 网络安全：Caddy Admin 仅 Unix Socket；PostgreSQL/Valkey 不公网暴露（检查项 5/6/7）；无 `/debug/pprof`（检查项 21）。
- 数据安全：私钥 AES-256-GCM 加密存储不回显；审计脱敏 + 哈希链 + 数据库 RULE 禁改删（检查项 15）；备份加密导出。
- 注入与导出安全：CSV 公式注入转义、日志注入单行化、SSRF 源站校验（阶段4/5 安全测试脚本 `test/security/` 可复跑）。
- 口令安全：无默认口令、无占位口令（检查项 20/22）。

## 5. 文档清单核对

### 5.1 系统强制核对（检查项 docs_present）

`docs/PRODUCT_REQUIREMENTS.md`、`docs/ARCHITECTURE.md`、`docs/DATABASE_DESIGN.md`、`docs/API_DESIGN.md`、`docs/SECURITY_DESIGN.md`、`docs/DEPLOYMENT.md`、`docs/TEST_PLAN.md`、`docs/OPEN_SOURCE_COMPLIANCE.md`。

### 5.2 交付全套核对（人工）

- 运维与使用：`docs/OPERATIONS_MANUAL.md`、`docs/SYSTEM_ADMIN_MANUAL.md`、`docs/SECURITY_ADMIN_MANUAL.md`、`docs/AUDIT_ADMIN_MANUAL.md`、`docs/DELIVERY_ACCEPTANCE_GUIDE.md`（本文档）、`docs/DISASTER_RECOVERY_GUIDE.md`、`docs/INSTALLATION_GUIDE.md`、`docs/OFFLINE_DEPLOYMENT_GUIDE.md`。
- 测试证据：`docs/STAGE2_TEST_REPORT.md` ~ `docs/STAGE6_TEST_REPORT.md`、`docs/GATEWAY_TEST_REPORT.md`、`docs/evidence/`。
- 合规：`THIRD_PARTY_NOTICES.md`、`docs/SBOM.spdx.json`、`docs/SBOM.cyclonedx.json`、`licenses/` 许可证归档、`docs/OPEN_SOURCE_COMPLIANCE.md`。
- 其他：`README.md`、`CHANGELOG.md`、`AGENTS.md`、`docs/DEVELOPMENT_STATUS.md`（遗留问题清单）。

## 6. 验收记录表（模板）

| 验收项 | 依据 | 结果（PASS/WARNING/FAIL） | 证据/备注 | 验收人 |
|--------|------|--------------------------|-----------|--------|
| 交付检查整体结果 | 第 2 节（系统导出） | | 检查 ID： | |
| 关键项 1-9、13、15、19、21 | 第 2 节逐项 | | | |
| 非关键项复核 | 第 2 节逐项 | | | |
| 性能抽测 | 第 3 节 | | 复跑脚本/数据： | |
| 安全验收项 | 第 4 节 | | | |
| 文档清单 | 第 5 节 | | | |
| 三权账号实操抽查 | 三本管理员手册 | | | |
| 备份恢复演练抽查 | 运维手册第 5 节 | | 恢复任务 ID： | |
| 遗留问题确认 | DEVELOPMENT_STATUS.md | | | |

验收结论：□ 通过交付 　□ 整改后复验 　□ 不通过
建设方签字：________　实施方签字：________　日期：________

## 7. FAIL / WARNING 处置规则

1. **关键项 FAIL 不得交付**：components_up、https_config、three_role_accounts、password_policy、caddy_admin_socket、postgres_bind、valkey_bind、config_version_exists、waf_detection、backup_available、audit_chain、vulnerability_scan、no_debug_endpoints 共 13 项为关键项，任一 FAIL 整体 FAIL，必须整改后重新执行交付检查至 PASS。
2. **非关键 FAIL 按 WARNING 处理**：不阻断交付，但须逐项登记整改计划（责任人/期限），复验时确认闭环。
3. **WARNING 处置**：逐条评估是否可现场消除（如试生成报告、补恢复演练、移除 INITIAL_ADMIN_PASSWORD）；不能现场消除的记入验收记录"遗留问题"栏，明确整改期限。
4. **AUDIT_INTEGRITY_FAILED 特例**：哈希链不一致属重大完整性事件，除不得交付外，立即按《运维手册》告警处置流程保全取证。
5. **复验规则**：整改后重跑 `POST /api/v1/delivery-checks/run`，以最新一次检查 ID 的结果导出件作为验收附件归档。

## 8. 运行环境检查与版本能力证据的区别

本文档第 2 节的 23 项交付检查（`server/internal/delivery/`，页面入口「系统运维 → 交付检查」）回答的是"**此运行环境**当前是否满足交付基线"：组件在线、端口未暴露、账号齐备、备份有效等，针对的是部署现场，结果随环境变化。

**版本能力证据**回答的是另一个问题："**此构建**实际具备哪些能力、哪些经过验证、证据在哪里"。它由 P0-01 工具链承载，与交付检查相互独立、互为补充：

- 能力清单：`docs/capabilities/capabilities.json`（手工维护的唯一数据源）与 `docs/capabilities/capabilities.schema.json`（结构契约）。
- 生成报告：`docs/capabilities/CAPABILITIES.md`（自动生成，禁止手改状态）。
- 校验/生成工具：`tools/capability_evidence.py`（纯本地标准库，不执行测试、不访问网络）。
- 证据包：`docs/evidence/releases/<build-id>/manifest.json` 与 `artifacts/`（经脱敏的结果与校验和，规则见 `docs/evidence/releases/README.md`）。

使用规则：

1. 交付检查 PASS 不能推出"某能力已验证"；反之能力证据通过也不替代现场环境检查。验收时两者分别取证、分别记录。
2. 能力报告中的验证状态由证据计算：无证据或证据与构建不匹配时显示"未验证"（NOT_RUN），不会生成"发布验收通过"（RELEASE_VERIFIED）。
3. 复验命令：
   `python3 tools/capability_evidence.py check --catalog docs/capabilities/capabilities.json --manifest docs/evidence/releases/<build-id>/manifest.json --release`
   非零退出即发布门槛未满足，错误信息会定位到具体字段/文件。
