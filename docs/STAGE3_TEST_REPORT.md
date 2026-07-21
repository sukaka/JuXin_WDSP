# 阶段3 测试报告（Web应用接入、源站、证书与网关配置发布）

## 1. 测试环境

| 项目 | 值 |
|------|-----|
| 主机 | macOS（Apple Silicon 虚拟化），Docker Desktop |
| Go | 1.25.6 |
| Node.js | 24.13.0 |
| PostgreSQL | 16.4-alpine |
| Valkey | 8.1.8-alpine |
| Caddy | v2.11.4 + coraza-caddy v2.5.0 + CRS v4.28.0（阶段1镜像） |
| 测试日期 | 2026-07-21 |

## 2. 测试结果汇总

| 测试类别 | 总数 | 通过 | 失败 | 跳过 |
|---------|------|------|------|------|
| 后端单元测试（阶段3新增） | 28 | 28 | 0 | 0 |
| 后端接口集成测试（阶段3） | 9 | 9 | 0 | 0 |
| 阶段2回归（单元+集成） | 41 | 41 | 0 | 0 |
| 前端单元测试 | 33 | 33 | 0 | 0 |
| Playwright E2E（阶段3） | 1 | 1 | 0 | 0 |
| 真实网关发布验证 | 6 | 6 | 0 | 0 |
| **合计** | **118** | **118** | **0** | **0** |

## 3. 后端单元测试（阶段3新增 28）

| 模块 | 用例 | 覆盖 |
|------|------|------|
| validation | 6 | 应用编码、域名规范化、泛域名规则、泛域名匹配、源站地址、控制字符 |
| encryption | 7 | 加密解密往返、随机 nonce、错误密钥、无效密文、hex/base64 密钥、长度校验、密钥生成 |
| certificates（解析） | 8 | PEM 解析、无效 PEM、私钥匹配、无效私钥、有效期、状态、到期级别、域名匹配、密钥强度 |
| gatewayconfig（生成器） | 6 | 确定性、结构、三种防护模式、多源站权重、禁用源站排除、HTTPS 跳转 |
| middleware（阶段2） | 5 | RBAC、CSRF、RequestID、sameOrigin |
| 其他（阶段2 security/audits/config） | 8 | 密码、审计脱敏、配置 |

## 4. 后端接口集成测试（阶段3 共 9）

独立测试库 + Valkey DB15。

| 用例 | 覆盖 |
|------|------|
| TestStage3CreateApplication | 系统管理员创建业务应用被 403（三权边界） |
| TestStage3SecurityAdminCRUD | 安全管理员创建应用、重复编码 409 |
| TestStage3DomainValidation | 合法域名、泛域名、非法泛域名 400、含协议域名 400 |
| TestStage3UpstreamSSRF | 云元数据 SSRF_BLOCKED、回环 SSRF_BLOCKED、非法协议拒绝 |
| TestStage3CertificateUpload | 上传合法证书、重复指纹拒绝 |
| TestStage3CertificateKeyMismatch | 私钥不匹配拒绝 |
| TestStage3CertificateExpired | 过期证书拒绝 |
| TestStage3PrivateKeyNotExposed | 列表/详情不泄露私钥 |
| TestStage3UpstreamWeightValidation | 权重 0/101 拒绝（修复 *int 区分未提供与非法值） |

## 5. 前端单元测试（33）

子代理开发（6 个测试文件）：api client、auth store、permission、menu、登录页、阶段3 页面/工具。

## 6. Playwright E2E（阶段3 场景一）

`e2e/stage3-app-onboarding.spec.ts` — 完整业务闭环：

安全管理员登录 → 创建应用 → 配置域名（HTTP监听）→ 配置源站 → 连通性测试（tcp_connected=true, http_status=200）→ 启用 → 预览（server>0, hash）→ 发布（SUCCESS）→ 网关访问（upstream_mark=REACHED_ORIGIN）→ SQLi 阻断（403）。

## 7. 真实网关发布验证（stage3 整合编排）

编排：postgres + valkey + api + gateway + testorigin（共享 admin socket 卷）。

| 验证点 | 结果 |
|--------|------|
| 后端经共享卷访问 Caddy Admin Socket | 通过 |
| 应用创建+域名+源站+启用 | 通过 |
| 发布到网关（Unix Socket /load） | SUCCESS |
| 正常请求经网关转发到源站 | REACHED_ORIGIN |
| SQLi 被防护模式阻断 | 403 |
| 观察模式 SQLi 到达源站 | 通过 |
| 配置版本记录 | has_current=True |
| 回滚版本B→版本A | 防护模式恢复 403 |
| 幂等键重复发布 | 返回同一任务 |
| 发布失败保护（400/网关断开/未绑证书） | 原应用仍可访问 200 |

## 8. 过程中发现并已修复的问题

| 问题 | 根因 | 修复 |
|------|------|------|
| Caddy 400 "no such host admin.sock" | admin.listen 缺 `unix/` 前缀被误解析 TCP | 规范化 admin.listen |
| Caddy 400 "unknown field retries" | reverse_proxy 顶层 retries 非法 | 移到 load_balancing.retries |
| Caddy 400 "unknown field weight" | upstream 无 weight 字段 | 改 selection_policy.weights 数组 |
| publish-tasks 500 | LIMIT 参数索引错位 | 动态参数索引 |
| 权重 0 返回 200 | defaultInt 掩盖显式非法值 | *int 区分未提供与非法值 |
| macOS 无法访问容器 unix socket | Docker Desktop bind mount 不支持 socket | 改用共享卷（后端容器与网关） |
| 权重校验绕过 | 指针类型后判断逻辑不匹配 | 修正风险判断 |

## 9. 构建与部署验证

| 项目 | 结果 |
|------|------|
| 后端 go build / vet | 通过 |
| 前端 typecheck / lint / build | 通过 |
| server Dockerfile（阶段3镜像） | 通过 |
| stage3 整合编排一键启动 | 全部 healthy |
| 后端容器经共享卷发布到网关 | 通过 |
| stage3 编排一键停止 | 通过 |

## 10. 已知限制

1. 阶段3未启用 HTTPS/TLS 端到端（证书管理已完成，HTTPS 应用接入在证书绑定后可用，当前以 HTTP 验证为主）；
2. 源站主动健康检查由 Caddy reverse_proxy 的 health_checks 承担（已配置），独立健康检查调度器在后续增强；
3. 证书主密钥开发环境为临时内存密钥（生产必须配置 JIUZHANG_MASTER_KEY）；
4. 发布验证为基础检查（Caddy admin 可用 + 配置加载），源站级发布后健康验证在后续增强；
5. 前端 antd 全量引入单 chunk 较大，未做代码分割。
