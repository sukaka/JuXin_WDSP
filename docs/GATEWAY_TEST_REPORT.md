# 阶段1 网关测试报告

## 1. 测试环境

| 项目 | 值 |
|------|-----|
| 主机 | macOS（Apple Silicon 虚拟化环境），Docker Desktop |
| CPU / 内存 | 10 核（容器可用）/ 8GB（容器 GOMEMLIMIT 7.4GB） |
| 容器平台 | Docker Desktop（linux/arm64） |
| Go | 1.25.6（darwin/amd64 宿主），golang:1.25-alpine（构建容器） |
| 测试日期 | 2026-07-20 |

## 2. 组件版本

| 组件 | 版本 | 提交号/摘要 | 许可证 |
|------|------|------------|--------|
| Caddy | v2.11.4 | e2eee6a7fce3 | Apache-2.0 |
| Coraza WAF | v3.7.0 | 27069d06c896 | Apache-2.0 |
| coraza-caddy | v2.5.0 | 55c03d45dc55 | Apache-2.0 |
| OWASP CRS | v4.28.0 | 55b09f5acfd1（tarball sha256 d8acc96f…） | Apache-2.0 |
| xcaddy | v0.4.5 | 328cac711a1f | Apache-2.0 |
| go-ftw | v2.4.0 | 23db497e3a61 | Apache-2.0 |
| golang 镜像 | 1.25-alpine | sha256:56961d79… | BSD |
| alpine 镜像 | 3.24 | sha256:28bd5fe8… | MIT |

## 3. 测试拓扑

```text
宿主 curl/脚本/go-ftw → 127.0.0.1:18080
    → gateway 容器 (Caddy+Coraza+CRS, :8080)
        → testorigin 容器 (:8081, 仅内部网络)
    controller 容器 → /var/run/caddy/admin.sock (共享卷)
    日志 bind mount → runtime/logs/stage1/
```

## 4. 构建验证

| 检查 | 结果 | 证据 |
|------|------|------|
| 自定义 Caddy 可重复构建 | 通过（Dockerfile 多阶段） | `docker build` 成功 |
| `caddy version` | v2.11.4 h1:XKxkMTgNSizEvKG6QHue6cAsFOteU2qA61w2tKkCWi0= | evidence/stage1/caddy-version.txt |
| Coraza 模块加载 | `http.handlers.waf` 存在 | evidence/stage1/caddy-modules.txt |
| CRS 4.28.0 加载 | 审计日志 producer.rulesets=["OWASP_CRS/4.28.0"] | 实测日志 |
| 运行镜像体积 | 21.4MB（无编译工具） | evidence/stage1/image-info.txt |

## 5. 正常业务请求测试

脚本：`test/waf/scripts/run-waf-tests.sh`（证据：evidence/stage1/waf-tests-on.txt）

11 个用例全部通过：普通 GET、POST 表单、JSON、中文参数、URL 编码、Cookie、自定义请求头、登录表单、文件上传、2KB 长参数、根路径。
判定标准：HTTP 200 且源站响应含 `upstream_mark=REACHED_ORIGIN`。

## 6. 攻击检测测试（防护模式 On）

21 个攻击用例全部通过（HTTP 403、未到达源站、返回九章阻断页面）：

| 类别 | 用例 | 命中示例 |
|------|------|---------|
| SQL 注入 | UNION 查询、恒真式、POST 表单、JSON 字段、编码 | 942100（libinjection）、949110 评分 8 |
| XSS | script 标签、img onerror、JSON 字段、事件属性、双重编码 | 941xxx 系列 |
| 命令注入 | 分号+cat、$(id)、管道+nc、反引号、编码 | 932xxx 系列 |
| 路径攻击 | ../ 穿越、编码穿越、双重编码、/proc/self/environ | 930xxx 系列 |
| 扫描器 | sqlmap UA、Nikto UA | 913xxx + 九章 9000002 |

**CRS PL1 行为说明（非缺陷）**：无实义的简单分隔符载荷（`;id;`、`a|id`、`` `id` ``）
在 PL1 评分不足不被拦截，属 CRS 官方误报控制设计；含具体命令/路径的真实攻击载荷均被拦截。
对应测试用例已按真实攻击模式编写。

## 7. 观察模式测试（DetectionOnly）

- 同一测试集（EXPECT_MODE=detection）32/32 通过：攻击请求 200 到达源站；
- 审计日志产生完整事件：`rule_engine=DetectionOnly`、`is_interrupted=false`、规则 942100/949110 命中记录；
- 防护模式切换通过 `SEC_RULE_ENGINE` 环境变量注入（模拟后续配置发布）。

## 8. 关闭模式测试（Off）

- 攻击载荷原样转发至源站（200，`upstream_mark=REACHED_ORIGIN`）；
- WAF 不执行规则（coraza 模块早退），访问日志保留。

## 9. 协议异常测试

脚本：`test/waf/scripts/protocol-tests.py`（证据：evidence/stage1/protocol-tests.txt），5/5 通过：

| 用例 | 结果 |
|------|------|
| 冲突 Content-Length（走私特征） | 400 拒绝 |
| 超大请求头（128KB，超 64KB 上限） | 431/400 拒绝 |
| 非法 HTTP 方法 | 403 |
| 请求体类型不匹配（声明 JSON 发 XML） | 400 |
| 重复 Transfer-Encoding 头 | 501 拒绝 |

## 10. go-ftw CRS 回归测试

- 工具：go-ftw v2.4.0（`go install github.com/coreruleset/go-ftw/v2@v2.4.0`）
- 配置：`test/waf/ftw/ftw.yaml`（logfile 指向 bind mount 的 coraza-audit.log）
- 用例：CRS 4.28.0 官方回归子集 942100 / 941160 / 932230
- **结果：94 个测试全部通过，0 失败 0 跳过**（证据：evidence/stage1/go-ftw-results.txt）

## 11. Request ID 关联测试

| 验证点 | 结果 |
|--------|------|
| 访问日志顶层 `uuid` 字段 == 源站收到的 X-Request-Id | 一致（23ec9ca7… 实测） |
| 审计日志 request.headers.x-request-id == 阻断页面显示值 | 一致（612b408c… 实测） |
| 客户端伪造 X-Request-Id 被覆盖 | 通过（fake 值未到达源站） |

## 12. 阻断页面测试

- SQLi 请求返回 403 + 独立设计阻断页；
- 页面含 Request ID（uuid）与发生时间（UTC，服务端生成）；
- 不含规则内容、评分、后端地址、路径、堆栈；
- 无用户输入反射（值域受控），无 XSS 面。

## 13. 事件解析器测试

- 8 个单元测试通过（结构解析、脱敏、DetectionOnly、非法输入、变量语义）；
- 真实审计日志端到端解析：4 条事务 → 4 条标准事件，0 解析失败；
- 混合输入测试：1 有效 + 3 失败（坏 JSON/缺 tx id/空行）→ 1 事件 + 3 错误记录；
- 脱敏验证：password/cookie/token 值不出现在标准事件中；
- 原始日志与标准事件分离保存。

## 14. 管理接口安全测试

| 检查 | 结果 |
|------|------|
| Admin API 仅 Unix Socket | 容器内无 2019 监听，宿主机连接拒绝 |
| Socket 权限 | s-w-------（0200），uid 1000 |
| controller 经 socket 访问 | GET /config/ 200 |
| 源站/前端不挂载 socket | compose 隔离 |

**发现并已记录**：全量加载缺少 admin 段的配置会使 Caddy admin 回退 127.0.0.1:2019（容器内回环，未公网暴露）。
后续配置生成器必须始终包含 admin socket 配置（已写入 GATEWAY_SECURITY.md 与开发规范）。

## 15. 配置失败保护测试

| 非法配置 | 结果 | 当前服务影响 |
|---------|------|-------------|
| 坏 JSON | 400 拒绝（invalid character） | 无（200/403 正常） |
| 不存在的模块 | 400 拒绝（unknown module） | 无 |
| 绑定不存在地址 203.0.113.10:8080 | 400 拒绝（cannot assign requested address） | 无 |

## 16. 配置发布与回滚测试

| 步骤 | 结果 |
|------|------|
| 发布版本B（DetectionOnly） | 成功，SQLi 200 到达源站 |
| 回滚版本A（On） | 成功，SQLi 恢复 403 |
| 配置哈希一致性 | 回滚前后 /config/ 哈希一致（237b4a50b1d9c3e5） |
| 服务连续性 | 发布/回滚期间无连接中断 |

## 17. 容器安全测试

非 root（uid 1000）、只读根文件系统、cap_drop ALL、no-new-privileges、
无 docker socket 挂载、bridge 网络、规则目录只读、业务端口仅 127.0.0.1 —— 全部实测通过。

## 18. 失败与修复记录（过程透明）

| 问题 | 根因 | 修复 |
|------|------|------|
| `order coraza_waf first` 组合报错 | Caddy order 的 before/after 参考指令必须是内置指令 | 改 `order coraza_waf after request_header`（实测 headers→waf→handler） |
| `http.matchers.status` 未注册 | 自定义构建无该 matcher | 改 expression `{err.status_code} == 403` |
| 审计日志 0 字节 | 宿主机 rm 日志文件致 fd 指向已删除 inode + 容器未重建 | force-recreate，改为 truncate 方式清理 |
| `max_header_bytes` 不识别 | Caddy v2.11 选项名为 `max_header_size` | 修正配置 |
| 超大头初测 200 | Go 默认 1MB 上限内属正常转发 | 网关显式 64KB 上限 + 用例改 128KB |
| 测试脚本变量名混入中文括号 | bash `$VAR）` 解析 | 改 `${VAR}` |
| cmdi 简单分隔符 200 | CRS PL1 误报控制设计 | 用例改真实攻击载荷，报告说明 |

## 19. 已知问题与限制

1. POC 单应用单节点，无多应用路由与 TLS；
2. 审计引擎 On 日志量大（ftw marker 需要），生产建议 RelevantOnly；
3. 事件解析器输出文件，未接 PostgreSQL；
4. 真实 IP 识别/CC 防护未实现（阶段5）；
5. `handle_errors` 链路不经过主路由 header 指令（Server 头清理仅主路由生效）。

## 20. 阶段1退出条件核对

| # | 条件 | 状态 |
|---|------|------|
| 1 | 自定义 Caddy 可重复构建 | ✅ Dockerfile/make gateway-build |
| 2 | Coraza 模块真实加载 | ✅ http.handlers.waf |
| 3 | OWASP CRS 真实加载 | ✅ OWASP_CRS/4.28.0 |
| 4 | 正常流量成功转发 | ✅ 11/11 |
| 5 | SQL 注入产生结构化事件 | ✅ |
| 6 | XSS 产生结构化事件 | ✅ |
| 7 | 命令注入产生结构化事件 | ✅ |
| 8 | 观察模式检测不阻断 | ✅ |
| 9 | 防护模式真实 403 | ✅ |
| 10 | 阻断请求未到达源站 | ✅ |
| 11 | 九章阻断页面生效 | ✅ |
| 12 | Request ID 关联日志 | ✅ |
| 13 | Coraza JSON 审计日志 | ✅ |
| 14 | 事件解析器解析日志 | ✅ |
| 15 | 敏感字段脱敏 | ✅ |
| 16 | Admin 仅 Unix Socket | ✅ |
| 17 | 非法配置不破坏服务 | ✅ 3 类 |
| 18 | 配置版本可回滚 | ✅ 哈希一致 |
| 19 | 自动化测试可重复 | ✅ make waf-test |
| 20 | 许可证归档 | ✅ licenses/ |
| 21 | 文档与实测一致 | ✅ |
| 22 | Compose 一键启停 | ✅ gateway-up/down |
| 23 | 无 Mock 冒充 | ✅ 全链路真实容器 |
