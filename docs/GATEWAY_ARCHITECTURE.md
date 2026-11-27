# 网关架构设计（阶段1 POC）

## 组件构成

| 组件 | 角色 | 来源 |
|------|------|------|
| Caddy v2.11.4 | HTTP 服务器 / 反向代理 / 动态配置 | 上游二进制模块，xcaddy 编译 |
| Coraza WAF v3.7.0 | SecLang 规则引擎 | coraza-caddy 引入 |
| coraza-caddy v2.6.0 | Caddy 集成模块（`coraza_waf` 指令） | xcaddy `--with` 编译 |
| OWASP CRS v4.28.0 | 通用攻击规则集 | 官方 tarball，只读挂载 |
| jiuzhang_guard | 自主访问控制/CC 防护模块 | 阶段5开发（当前占位） |
| eventparser | 自主事件解析器 | 阶段1 POC |

## 构建链路

```text
golang:1.25-alpine (构建阶段)
  → go install xcaddy@v0.4.5
  → xcaddy build v2.11.4 --with coraza-caddy/v2@v2.6.0
  → CGO_ENABLED=0 静态二进制
alpine:3.24 (运行阶段)
  → 非 root 用户 caddy (uid 1000)
  → ENTRYPOINT umask 077
```

构建可重复执行：`docker build -t jiuzhang-gateway:stage1 gateway/` 或 `make gateway-build`。

## 配置加载顺序

```text
SecRuleEngine {env}                    # Caddyfile 注入（Off/DetectionOnly/On）
Include coraza.conf                    # 请求体/响应体处理、JSON 审计日志
Include crs/crs-setup.conf             # CRS setup（PL1、阈值、版本标记）
Include exclusions/before-crs.conf     # 运行时例外（官方推荐位置）
Include crs/rules/*.conf               # CRS 4.28.0 规则（上游文件，不修改）
Include exclusions/after-crs.conf      # 配置时例外（官方推荐位置）
Include jiuzhang/jiuzhang-custom.conf  # 九章自定义规则（ID 9000000+ 段）
```

原则：

- 不修改 `rules/crs/rules/` 下任何上游规则文件；
- 运行时例外放 CRS 之前，配置时例外放 CRS 之后（CRS 官方调优建议）；
- 自定义规则使用独立 ID 段，避免与 CRS（900xxx-999xxx）及 coraza.conf（200000-200006）冲突。

## 中间件顺序

经 `caddy adapt` 实测验证：

```text
headers (request_header 注入 X-Request-Id)
  → waf (coraza_waf)
  → headers (deferred:true，设置默认安全响应头并移除 Server)
  → reverse_proxy / 业务 handler
  → handle_errors (403 → 阻断页面)
```

Caddy `order` 指令限制：before/after 的参考指令必须是内置指令，
第三方指令 `coraza_waf` 只能作为主语，故保留 `order coraza_waf after request_header`；
同时在站点内通过 `route` 块将 `header`（含 `-Server` 触发 `deferred:true`）显式置于
`coraza_waf` 之后、`reverse_proxy` 之前，与生产配置生成器（`gatewayconfig/headers.go`）
完全对齐，满足 Request ID 先注入（审计日志可记录）、WAF 先于业务执行，并避免 deferred
`ResponseWriterWrapper` 位于 `coraza_waf` 前方阻塞 WebSocket 101 `Hijack`。

## Request ID 关联设计

```text
Caddy {http.request.uuid}
  ├── request_header X-Request-Id  → 源站请求头（覆盖客户端传入）
  ├── access.log 顶层 uuid 字段
  ├── Coraza 审计日志 request.headers.x-request-id
  └── 阻断页面 templates 渲染

事件解析器以 x-request-id 为关联键；缺失时退化为 Coraza 事务 ID。
```

## 日志体系

| 日志 | 格式 | 内容 | 消费者 |
|------|------|------|--------|
| access.log | JSON | 访问日志，含 uuid、状态、耗时 | 审计/排障 |
| caddy.log | JSON | 运行日志，配置加载、错误 | 运维 |
| coraza-audit.log | JSONL | 事务级 WAF 审计（含规则命中） | eventparser |
| events.jsonl | JSONL | 九章标准事件（脱敏） | 阶段4事件中心 |
| parse-errors.jsonl | JSONL | 解析失败记录（不静默丢弃） | 排障 |

## 配置发布链路（POC 验证版）

```text
Caddyfile + 环境变量
  → caddy adapt 生成 JSON 配置版本（version-a/b.json）
  → controller 容器经 Unix Socket POST /load
  → Caddy 原子切换；失败自动回滚到上一有效配置
  → 回滚验证：配置哈希一致、行为恢复
```

关键经验（已写入安全设计）：全量替换配置会覆盖 admin 设置，
配置生成器必须始终显式包含 `admin unix//var/run/caddy/admin.sock`。

## 后续阶段演进

- 阶段3：配置生成器（应用模型 → Caddy JSON）、版本表、发布任务；
- 阶段4：eventparser 对接 PostgreSQL 分区表，事件中心；
- 阶段5：jiuzhang_guard 模块（黑白名单、CC、真实 IP、可信代理）。
