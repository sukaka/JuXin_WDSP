# 阶段1 网关技术验证（POC）

## 目标

验证 Caddy + Coraza WAF + OWASP CRS 能够组成九章防护网关，完成正常请求转发、攻击检测、观察/防护模式、日志关联、安全发布和失败回退的真实闭环。

本阶段不开发完整管理页面。

## 架构

```text
测试客户端 (curl / 测试脚本 / go-ftw)
    │  HTTP 127.0.0.1:18080
    ▼
┌─────────────────────────────────────────────┐
│ 九章防护网关 jiuzhang-gateway:stage1          │
│  Caddy 2.11.4 + Coraza 3.7.0 + CRS 4.28.0   │
│                                             │
│  request_header (生成/覆盖 X-Request-Id)      │
│      ↓                                      │
│  coraza_waf   (CRS 检测, On/DetectionOnly)  │
│      ↓                                      │
│  reverse_proxy                              │
│      ↓                                      │
│  handle_errors (403 → 九章阻断页面)           │
└──────────┬──────────────────────────────────┘
           │ 内部网络 stage1-net
           ▼
   测试源站 jiuzhang-testorigin:8081

管理通道：
  controller 容器 ──Unix Socket──▶ Caddy Admin API (/var/run/caddy/admin.sock)

日志：
  /var/log/caddy/ (bind mount → runtime/logs/stage1/)
  ├── access.log        Caddy 访问日志（JSON，含顶层 uuid 字段）
  ├── caddy.log         Caddy 运行日志
  └── coraza-audit.log  Coraza JSON 审计日志（JSONL）
```

## 组件版本

全部版本经 2026-07-20 联网核查，详见 [DEPENDENCIES.md](DEPENDENCIES.md)。

| 组件 | 版本 | 许可证 |
|------|------|--------|
| Caddy | v2.11.4 | Apache-2.0 |
| Coraza WAF | v3.7.0 | Apache-2.0 |
| coraza-caddy | v2.5.0 | Apache-2.0 |
| OWASP CRS | v4.28.0 | Apache-2.0 |
| xcaddy | v0.4.5 | Apache-2.0 |
| go-ftw | v2.4.0 | Apache-2.0 |

## 快速开始

```bash
# 构建镜像（自定义 Caddy + 测试源站）
make gateway-build

# 启动（默认防护模式 On）
make gateway-up GATEWAY_PORT=18080

# 观察模式
make gateway-up GATEWAY_PORT=18080 SEC_RULE_ENGINE=DetectionOnly

# 关闭模式
make gateway-up GATEWAY_PORT=18080 SEC_RULE_ENGINE=Off

# 运行全部测试（WAF 攻击测试 + 协议异常测试 + go-ftw CRS 回归）
make waf-test

# 停止
make gateway-down
```

## 请求处理顺序（POC 实测）

```text
接收请求
  ↓
request_header 生成/覆盖 X-Request-Id（Caddy uuid，不信任客户端传入）
  ↓
coraza_waf：CRS 攻击检测（模式由 SecRuleEngine 决定）
  ↓
reverse_proxy 转发到测试源站
  ↓
阻断时 handle_errors 返回九章阻断页面
  ↓
写访问日志 + Coraza JSON 审计日志
```

中间件顺序经 `caddy adapt` 实测验证为 `headers → waf → 业务 handler`。
Caddy `order` 指令的 before/after 参考指令必须是内置指令，第三方指令
`coraza_waf` 只能作为主语移动，因此使用 `order coraza_waf after request_header`
（等效实现"request_header 先于 coraza_waf，coraza_waf 先于业务 handler"）。

## 防护模式

POC 通过环境变量 `SEC_RULE_ENGINE` 注入 Caddyfile 模板：

```text
SecRuleEngine {$SEC_RULE_ENGINE:On}
```

| 模式 | 行为 | 验证结果 |
|------|------|---------|
| Off | 不执行 WAF 规则，正常转发，保留访问日志 | 攻击载荷原样到达源站 |
| DetectionOnly | 检测并记录事件，不阻断 | 攻击请求 200 到达源站，审计日志含规则命中 |
| On | 达到阈值阻断，返回九章阻断页面 | 攻击请求 403，未到达源站 |

后续配置发布系统将为每个应用生成不同的 `SecRuleEngine` 指令值，
通过 Admin API 发布实现模式变更（已在版本A/B发布与回滚测试中验证链路）。

## 关键文件

```text
gateway/
├── Dockerfile                      # 多阶段构建自定义 Caddy（xcaddy）
├── configs/
│   ├── Caddyfile                   # 网关主配置
│   └── blockpage.html              # 九章阻断页面
├── rules/
│   ├── coraza.conf                 # Coraza 基础配置（JSON 审计日志）
│   ├── crs/
│   │   ├── crs-setup.conf          # CRS setup（标准策略：PL1/阈值5）
│   │   ├── crs-setup.conf.example  # CRS 官方模板（未修改）
│   │   ├── rules/                  # CRS 4.28.0 规则（未修改）
│   │   └── plugins/
│   ├── exclusions/
│   │   ├── before-crs.conf         # 运行时例外（CRS 之前）
│   │   └── after-crs.conf          # 配置时例外（CRS 之后）
│   └── jiuzhang/jiuzhang-custom.conf  # 九章自定义规则（自验规则 9000001）
├── modules/jiuzhang_guard/         # 阶段5自主模块（占位）
├── internal/eventparser/           # 事件解析器（含单元测试）
├── cmd/eventparser/                # 事件采集器 POC
└── scripts/docker-entrypoint.sh    # 容器入口（umask 077）

deployment/
├── docker-compose.stage1.yml       # 阶段1编排
└── stage1/
    ├── testorigin/                 # 独立测试源站（Go）
    └── config-tests/               # 配置发布/回滚测试用 JSON

test/waf/
├── ftw/                            # go-ftw 配置与 CRS 回归子集
└── scripts/
    ├── run-waf-tests.sh            # 32 个正常+攻击用例
    └── protocol-tests.py           # 5 个协议异常用例
```

## 测试源站接口

`deployment/stage1/testorigin`（独立 Go 程序，非管理后端）：

- `GET /`：服务标识（含 upstream_mark / request_id）
- `GET /health`：健康检查
- `GET/POST /echo`：回显方法、路径、头摘要、体摘要（敏感头脱敏）
- `POST /login`：表单登录模拟
- `POST /api/json`：JSON 接口模拟
- `POST /upload`：文件上传模拟

## 事件采集

```bash
# 一次性解析当前审计日志
cd gateway && go run ./cmd/eventparser \
  -audit ../runtime/logs/stage1/coraza-audit.log \
  -events ../runtime/logs/stage1/events.jsonl \
  -errors ../runtime/logs/stage1/parse-errors.jsonl \
  -once -node gateway-poc-01

# 常驻采集（跟踪模式）
cd gateway && go run ./cmd/eventparser \
  -audit ../runtime/logs/stage1/coraza-audit.log \
  -events ../runtime/logs/stage1/events.jsonl \
  -errors ../runtime/logs/stage1/parse-errors.jsonl \
  -node gateway-poc-01
```

## 已知限制（POC 范围）

1. 单应用单网关节点，无多应用路由；
2. 事件解析器输出 JSON 文件，未对接 PostgreSQL（阶段4接入事件中心）；
3. 防护模式切换通过重建容器注入环境变量，后续由配置发布系统在线变更；
4. 真实客户端 IP 识别（可信代理）在阶段5由 jiuzhang_guard 模块实现；
5. 未启用 HTTPS/TLS 与证书管理（阶段3）；
6. 审计引擎 POC 使用 `On`（go-ftw marker 需要），生产建议 RelevantOnly；
7. 阻断页面静态模板由 templates 模块渲染，Request ID/时间为服务端生成值，无用户输入反射。

## 测试证据

原始命令输出归档于 `docs/evidence/stage1/`，汇总见 [GATEWAY_TEST_REPORT.md](GATEWAY_TEST_REPORT.md)。
