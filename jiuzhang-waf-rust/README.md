# 九章WEB应用智能防护系统V2.0（Rust）

这是一个独立实现的 HTTP 应用安全网关。程序直接编译为宿主机二进制，运行时不依赖容器、Go 服务、Caddy、Coraza、数据库或缓存服务。

## 当前交付边界

本目录是重构的第一阶段，不是对现有系统全部功能的替换。已经实现：

- HTTP 反向代理，支持 HTTP/HTTPS 源站；
- 请求 ID、可信代理识别、转发头重建和逐跳头清理；
- SQL 注入、跨站脚本、命令注入、路径穿越、文件包含、空字节和扫描器特征检测；
- `off`、`observe`、`protect` 三种检测模式；
- IP/CIDR 允许列表与拒绝列表；
- 有容量上限的固定窗口限速；
- 有上限的请求体缓冲、源站超时、响应流式转发；
- JSON Lines 安全事件、查询参数值脱敏和进程计数器；
- 独立监听的健康检查与只读指标接口。

尚未实现：HTTPS 客户端接入、多站点与负载均衡、CRS 规则兼容、管理控制台、用户权限、数据库事件中心、配置热更新、集群和报表。不要在未完成这些能力前将它视为现有系统的等价替代品。

## 本地启动

要求 Rust 1.85 或更新版本。直接依赖的精确版本写在 `Cargo.toml`，完整依赖图由 `Cargo.lock` 锁定。

```bash
cd jiuzhang-waf-rust
cp config.example.toml config.local.toml
cargo run -- --config config.local.toml --check-config
cargo run -- --config config.local.toml
```

默认配置假设源站位于 `127.0.0.1:3000`。可用下面的临时服务做一次本机验证：

```bash
python3 -m http.server 3000 --bind 127.0.0.1
```

网关默认监听 `127.0.0.1:18080`，只读运行接口监听 `127.0.0.1:19090`。

```bash
curl -i http://127.0.0.1:18080/
curl -i 'http://127.0.0.1:18080/search?q=1%20union%20select%20password'
curl -s http://127.0.0.1:19090/health
curl -s http://127.0.0.1:19090/metrics
```

事件写入 `var/security-events.jsonl`。日志目标只保留查询参数名，所有查询参数值均替换为 `<redacted>`，请求体和敏感请求头不写入事件文件。

## 配置要点

| 配置 | 含义 |
|---|---|
| `server.listen` | 对外 HTTP 代理地址 |
| `server.admin_listen` | 健康检查与指标地址；不要暴露到公网 |
| `server.upstream` | 单个源站的绝对 URL，不允许用户信息、查询或片段 |
| `protection.mode` | `off` 不执行攻击签名，`observe` 仅记录，`protect` 拒绝命中请求 |
| `protection.max_body_bytes` | 单请求最大缓冲字节数，允许 1 KiB 至 100 MiB |
| `access_control.trusted_proxies` | 只有连接来源命中这些网段时才读取 `X-Forwarded-For` |
| `access_control.allow` | 优先于拒绝列表和限速，但仍执行请求体检查与攻击检测 |
| `access_control.deny` | 拒绝指定 IP 或 CIDR |
| `rate_limit.max_tracked_ips` | 限速表最大客户端数；达到容量且没有过期项时拒绝新客户端 |
| `logging.events_path` | JSON Lines 事件文件位置 |

修改配置后先运行 `--check-config`。当前版本需要重启进程才能加载新配置。

## 构建与验证

```bash
cargo fmt --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo build --release
```

生成的程序为 `target/release/jiuzhang-native-waf`。裸机服务和加固示例见 `docs/OPERATIONS.md` 与 `packaging/jiuzhang-native-waf.service`。

## 代码结构

```text
src/app.rs         请求编排、反向代理、响应与指标
src/client_ip.rs   可信代理链解析
src/config.rs      强类型配置与启动校验
src/detection.rs   内置签名和解码检查
src/event.rs       安全事件结构与脱敏落盘
src/rate_limit.rs  有界固定窗口计数器
src/main.rs        进程入口与双端口服务
tests/             真实 TCP 源站与 HTTP 客户端集成测试
```

独立设计说明见 `docs/ARCHITECTURE.md`，规则口径见 `docs/DETECTION_RULES.md`，重构及登记材料的注意事项见 `docs/REWRITE_NOTES.md`。

## 60 页源码材料

`dist/` 中提供恰好 60 页的 PDF、可检索 HTML 和逐文件 SHA-256 清单。材料按完整源码序列收录前 30 页和末尾 30 页，每页固定 50 行，中间省略范围在清单中明确标注。内容包含真实源码、测试、构建及原生部署配置，不包含全量系统平移或 WDSP/API 能力。

如需在修改源码后重新生成，先准备 Python 3.9+ 和 Noto CJK TTF 字体，再执行：

```bash
python3 -m venv .venv-source-book
.venv-source-book/bin/pip install --requirement tools/requirements-source-book.txt
.venv-source-book/bin/python tools/render_source_book.py
.venv-source-book/bin/python tools/render_source_book.py --check
```

默认字体路径为仓库现有 `server/assets/fonts/NotoSansCJKsc-VF.ttf`；其他环境通过 `--font /path/to/font.ttf` 指定。`--check` 会核验 60 页页数、每页 50 行、逐页源码完整性、HTML 页数以及文件和文档哈希。
