# 网关安全设计（阶段1 POC）

## 1. 管理接口安全

| 措施 | 实现 | 验证 |
|------|------|------|
| Admin API 绑定 | `admin unix//var/run/caddy/admin.sock` | 容器内仅 8080 业务端口监听 |
| 不监听 TCP | 无 0.0.0.0:2019 | 宿主机 `curl 127.0.0.1:2019` 连接拒绝 |
| Socket 权限 | 容器入口 `umask 077`，socket 文件 `s-w-------`(0200) | `ls -la` 实测 |
| 访问主体 | 仅 controller（配置控制器角色）容器挂载 socket 卷，uid 1000 | curl 经 socket 成功 |
| 前端/源站隔离 | testorigin 不挂载 socket 卷 | compose 配置 |

**重要经验教训**：通过 Admin API 全量加载的 JSON 配置若缺少 `admin` 段，
Caddy 会回退到默认 `127.0.0.1:2019`。后续配置生成器必须始终显式包含
`admin unix//var/run/caddy/admin.sock`，发布前安全校验必须拒绝缺失或 TCP 形式的 admin 配置。

## 2. 容器安全

| 项目 | 状态 |
|------|------|
| Caddy 主进程非 root 运行 | 入口仅瞬时以 root 执行自研 Go 降权器；最终 Caddy 为 caddy（uid/gid 1000），origin（测试源站）亦非 root |
| 只读根文件系统 | `read_only: true` + tmpfs `/tmp` |
| Capabilities | 入口仅临时持有 `NET_BIND_SERVICE`/`SETUID`/`SETGID`/`SETPCAP`；Go helper 通过 Linux syscall 降权，最终五类 capability 集合均仅含 `CAP_NET_BIND_SERVICE`（`0x400`） |
| no-new-privileges | 是；由 Go helper 在降权前设置，最终 Caddy 进程保持 `NoNewPrivs: 1` |
| privileged | 否 |
| Docker Socket | 未挂载 |
| network_mode: host | 否（独立 bridge 网络 stage1-net） |
| 规则目录 | 只读挂载 |
| 端口暴露 | 业务端口仅绑定 127.0.0.1；源站不暴露宿主机端口 |
| 镜像 | 多阶段构建，运行镜像无编译工具（21MB） |
| latest 标签 | 无（全部版本+摘要锁定） |

### 1024 以下端口绑定与降权

在 `no-new-privileges` 下，不能依赖 Caddy 二进制的文件 capability 获得低端口绑定权限。
入口以 root 短暂运行 `gateway/cmd/wdsp-gateway-bind` 构建的自研 Go helper；实现不依赖外部
降权工具或文件 capability。helper 首先通过 `runtime.LockOSThread()` 锁定 OS 线程，要求
effective UID 为 0，随后在同一工作线程中依次执行：

1. 通过 `prctl(PR_SET_NO_NEW_PRIVS, 1)` 设置 `NoNewPrivs`，并以 `setgroups(nil)` 清空补充组；
2. 通过 `prctl(PR_SET_KEEPCAPS, 1)` 保留降权后的 permitted capabilities；
3. 遍历 `0..cap_last_cap`，通过 `PR_CAPBSET_DROP` 丢弃 bounding set 中除
   `CAP_NET_BIND_SERVICE` 外的所有能力；
4. 依次调用 `setresgid(1000, 1000, 1000)`、`setresuid(1000, 1000, 1000)`，使 real、effective、
   saved、filesystem UID/GID 全部为 1000；
5. 通过 `capset` 将 inheritable、permitted、effective 集合都设为仅 `CAP_NET_BIND_SERVICE`，
   再通过 `prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_BIND_SERVICE)` 提升 ambient 能力；
6. 读取 `/proc/self/status`，逐项验证 `Uid`/`Gid` 四个值均为 1000、`Groups` 为空、
   `CapInh`/`CapPrm`/`CapEff`/`CapBnd`/`CapAmb` 均为 `0000000000000400`（`0x400`）、
   `NoNewPrivs` 为 `1`。缺字段、解析失败或任何值不符都会中止，不得执行后续入口；
7. 验证及审计日志写入成功后，才通过 `syscall.Exec` 执行原入口
   `/usr/local/bin/docker-entrypoint.sh`，原样传递参数与环境。

因此最终 Caddy 主进程 UID/GID 均为 1000，五类 capability 集合均仅 `0x400`，补充组为空，
`NoNewPrivs` 保持为 `1`；入口的 root 身份和其余三项临时能力不得遗留到 Caddy 进程。

该能力只解决本机 `bind(2)` 的权限检查，不会开放防火墙，也不代表站点已外部可达。
防火墙与 bind 权限是两层独立控制，1024 以下端口仍须按站点逐一配置并核验 firewalld。

## 3. 日志与隐私

### 分层策略

| 层 | 内容 | 控制 |
|----|------|------|
| 原始审计日志 | Coraza JSON（含请求头 B 部分） | 容器内 0600，bind mount 受控目录，不直接对外 |
| 标准事件 | 九章事件结构 | 解析器强制脱敏后输出 |

### 脱敏规则（eventparser 实现，含单元测试）

- 不输出完整请求头集合；仅提取 User-Agent（截断 256）与 x-request-id；
- Authorization / Cookie / Set-Cookie / X-API-Key 等敏感头值不进入标准事件；
- URI 查询串中 password/token/secret/session 等参数值替换为 `masked`；
- 匹配数据（matched_data）按键值模式循环遮蔽全部出现位置并截断 128 字符；
  命中变量为敏感头（REQUEST_HEADERS:Authorization/Cookie 等）时值段整段遮蔽；
- 完整请求体落盘为 POC 专用配置（审计日志 Parts 为 ABCIJDEFHZ，含 C 部分；受
  SecRequestBodyLimit 12.5MB 限制，生产发布模板必须改用 RelevantOnly 并评审是否保留 C/E，见
  `rules/coraza.conf` 审计段警告注释）；
- 私钥、证书内容不进入任何日志。

### 解析失败处理

- 失败记录写入 `parse-errors.jsonl`，只保留结构化摘要（原因 + 尽力提取的 tx_id +
  行长度 + 行内容 SHA-256），不落原始审计行——原始行可能含 Authorization/Cookie/
  口令明文，排查时凭 tx_id/哈希对照原始审计日志（0600）；
- 不静默丢弃。

## 4. Request ID 安全

- 网关使用 Caddy `{http.request.uuid}` 生成内部标识；
- `request_header` 强制覆盖客户端传入的 `X-Request-Id`（实测伪造值被覆盖）；
- 审计日志、访问日志、阻断页面、源站日志使用同一标识关联。

## 5. 阻断页面安全

- 不展示规则内容、异常评分、后端地址、文件路径、堆栈、内部错误、管理地址；
- 仅展示请求编号（Caddy uuid，值域 `[0-9a-f-]`）与服务端时间；
- 不反射任何用户输入，无 XSS 面；
- 独立设计，不模仿任何现有 WAF 产品。

## 6. 真实客户端 IP（POC 状态与规划）

- POC 阶段无前置代理，Coraza 直接采用 TCP 连接源 IP（`RemoteAddr`）；
- 未信任 `X-Forwarded-For`（Caddy 默认 trusted proxies 为空）；
- 阶段5由 jiuzhang_guard 实现可信代理列表与真实 IP 识别。

## 7. 配置注入防护（POC 状态）

- 网关配置当前来自受控文件（Caddyfile + 规则文件，只读挂载）；
- 不接受运行时用户输入拼接配置；
- 后续配置生成器采用结构化 JSON 生成 + 白名单校验，禁止字符串模板无条件拼接。

## 8. 默认响应头

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- 移除 `Server` 头（主路由）；handle_errors 链路默认不携带。

## 9. 已知风险与限制

1. POC 未启用 TLS（阶段3实现证书管理）；
2. SecAuditEngine POC 为 On（日志量大），生产按应用策略 RelevantOnly；
3. 原始审计日志含请求头原文，依赖目录权限与卷隔离保护；
4. 未实现 CC 防护与频率限制（阶段5）；
5. 网关单节点，无 HA（V2.0 范围外）。
