# 容器运维通道设计（containerops sidecar）

适用版本：WDSP 1.x（容器运维功能部署侧）。本文是部署与信任边界契约；管理面 API 路由、
请求/响应模式由后端线实现并在 docs/API_DESIGN.md 与 server/openapi 登记后生效，
本文不冻结后端 schema。

## 1. 背景与目标

管理面需要提供容器级运维能力（查看组件状态/日志、重启服务容器、按锁定镜像更新）。
但 API 容器按 `read_only` + `cap_drop ALL` 最小权限运行，直接挂载
`/var/run/docker.sock` 等于把宿主机 root 等价权限交给管理面进程，违反安全底线。

因此引入 **containerops sidecar**：全栈唯一挂载 docker.sock 的组件，以独立守护进程
（`server/cmd/containeropsd`，仅 Go 标准库）向 API 提供经白名单收敛的运维通道。

## 2. 信任边界

```text
浏览器 → 管理前端 → 管理 API（认证/权限/CSRF/审计）
                          │  Unix Socket（共享卷，无 TCP）
                          ▼
                  containerops sidecar ──→ /var/run/docker.sock ──→ Docker Engine
                  （唯一持有 docker.sock；
                    白名单 + 项目标签双重校验，fail-closed）
```

- **docker.sock 唯一持有者**：只有 containerops 服务挂载 `/var/run/docker.sock`。
  API、web、gateway 等任何其他容器严禁挂载（compose 注释标注为安全底线）。
- **API 侧只有 socket 文件**：API 容器挂载共享命名卷（stage5 为 `stage5-containerops`，
  挂载点 `/app/runtime/containerops`；离线生产包为 `containerops-data`，同路径），
  只能向 `/app/runtime/containerops/containerops.sock` 发起请求，无法直接触碰 Docker API。
- **sidecar 无网络面**：不声明任何端口，compose 中以 `network_mode: none` 运行；
  请求只可能来自挂载了共享卷的 API 容器（卷粒度隔离）。
- **socket 文件权限**：sidecar 以非 root（uid 1000）运行，socket 文件落在共享卷中；
  共享卷仅挂载给 api 与 containerops 两个服务，第三方容器无法经卷路径触达。
- **docker.sock 访问授权**：sidecar 容器经 `group_add: ${CONTAINEROPS_DOCKER_GID}`
  注入宿主机 docker 组 gid（Linux 通常为 docker 组；Docker Desktop/root-owned 场景为 0，
  compose 缺省 0）。安装期用 `ops/install/prepare-containerops.sh [-e .env]` 探测写入，
  不在镜像内固化任何宿主机 gid，镜像本体不含任何 capability。

## 3. Unix Socket 协议（部署侧契约）

- 传输：HTTP/1.1 over Unix Domain Socket（sidecar 监听 `CONTAINEROPS_SOCKET`，
  默认 `/run/containerops/containerops.sock`；API 侧经 `CONTAINEROPS_SOCKET`
  环境变量指向同一卷内路径）。选 HTTP 是为可调试性（`curl --unix-socket`）与
  Go 标准库原生支持，不引入新依赖。
- sidecar 环境变量（compose 下发，不暴露 TCP）：
  - `CONTAINEROPS_SOCKET`：监听 socket 路径；
  - `DOCKER_HOST=unix:///var/run/docker.sock`：Docker API 入口；
  - `CONTAINEROPS_PROJECT`：允许运维的 compose 项目名（stage5 为 `jiuzhang-stage5`，
    离线生产包为 `jiuzhang-<产品线>`）；
  - `CONTAINEROPS_ALLOWED_SERVICES`：逗号分隔的服务白名单。
- 通用约束：请求体上限（默认 64KB）、连接/读超时（默认 10s/30s）、单响应大小上限
  （日志读取默认截断至 1MB 并显式标记 truncated）；错误一律返回结构化 JSON，
  不暴露 Go 堆栈、Docker API 原始错误原文中的宿主机路径细节。
- 具体端点清单、请求/响应字段以后端线实现与 OpenAPI 登记为准（见第 9 节）。

## 4. 权限与审计

- **管理面侧**：容器运维接口属系统管理员运维域，路由层按权限点强制校验，
  所有写操作（重启、更新）经 CSRF 校验并记录操作审计（操作人、目标服务、
  动作、参数摘要、SUCCESS/FAILURE、requestID）——与系统控制（hostctl）同一口径。
- **sidecar 侧**：每个请求记录审计行（时间、动作、目标服务/容器、结果、耗时），
  落 stdout 由 Docker 日志驱动采集；审计行不含任何环境变量值、凭据与完整 inspect 载荷
  （见第 6 节脱敏）。
- **双重校验**：sidecar 对每个目标同时校验（a）容器 `com.docker.compose.project`
  标签等于 `CONTAINEROPS_PROJECT`、（b）`com.docker.compose.service` 在白名单内；
  任一不满足即拒绝并记审计，绝不"先操作后告警"。

## 5. 白名单与镜像更新策略

- **服务白名单**（`CONTAINEROPS_ALLOWED_SERVICES`）：
  - stage5：`api,gateway,postgres,valkey,logrotator,netmgrd,testorigin,ollama`
    （白名单允许包含当前 compose 中不存在的服务名，按"目标必须同时命中项目标签 +
    白名单"双重校验，多余项不构成放行面）；
  - 离线生产包：`api,web,gateway,postgres,valkey,logrotator,netmgrd`；
  - sidecar 自身（`containerops`）永远不在白名单内：能重启 Docker 的组件不允许
    被通道自身操作，防止通道自毁与权限递归放大。
- **镜像更新（update）纪律**：
  - 只接受显式锁定的镜像引用（`name:tag` 且 tag 不得为 `latest`，或
    `name:tag@sha256:<digest>`）；拒绝 `latest`、拒绝无 tag 的裸仓库名、
    拒绝与当前产品版本基线不一致的任意 tag（遵循 AGENTS.md「禁止 latest」红线）；
  - 更新动作 = 拉取锁定镜像 → 重建目标容器 → 健康检查 → 失败回滚到原镜像 ID；
    全程记录操作审计与 sidecar 审计行；
  - 数据类容器（postgres/valkey）的更新只允许同大版本内的补丁镜像，
    禁止任何卷删除/重建类操作；通道不提供 `volume rm`、`system prune`、
    镜像删除等破坏性语义。

## 6. 日志脱敏与上限

- 容器日志读取：默认只返回尾部 N 行（上限 1000）/ 尾部字节（上限 1MB），
  超限显式截断标记；逐行剥离控制字符（防日志注入伪造终端/审计行）。
- inspect/状态输出：仅返回白名单字段（状态、健康、镜像、启动时间、重启计数等），
  不返回容器环境变量值（Env 可能含口令）、不返回挂载点以外的宿主机路径细节。
- 脱敏口径与 docs/SECURITY_DESIGN.md「日志隐私」一致：password/token/secret/
  private_key 等关键词命中的值一律掩码。

## 7. API 自停风险

API 容器是请求发起方，对自身容器的 stop/update 会切断操作会话：

- 通道对 `api` 服务**只允许 restart**（Docker 层自动拉起，restart 策略
  `unless-stopped` 保证恢复），**禁止 stop 与在线 update**；
- API 自身的版本更新走既有宿主机升级执行器通道（`ops/upgrade/upgrade-executor.sh`，
  Web 上传升级包），不经过本通道；
- 对其他服务的 update/restart 不影响 API 会话连续性；gateway 重启期间数据面
  中断窗口按既有发布变更流程（docs/OPERATIONS_MANUAL.md 第 6 节）评估与记录。

## 8. 非容器部署不可用口径

裸机 systemd 形态（`ops/baremetal/`）没有 docker.sock，容器运维通道不可用：

- sidecar 不部署；API 启动时探测 `CONTAINEROPS_SOCKET` 指向的 socket 文件，
  不存在则容器运维接口统一返回 503 降级（与 APM 未接入口径一致：返回降级而非报错），
  前端隐藏/置灰对应入口；
- 不得在非容器形态伪造容器状态数据；不可用状态必须在页面与接口响应中显式表达。

## 9. 待后端线完成

- `server/cmd/containeropsd` 守护进程实现（本文第 3 节协议契约）；
- 管理面路由注册、权限点、操作审计装配，并在 docs/API_DESIGN.md 与
  server/openapi 登记（本任务不编造响应 schema）；
- 升级包组件白名单（ops/upgrade/build-upgrade-pack.sh 与宿主机
  upgrade-executor.sh 双侧）纳入 containerops 组件——新增组件须两侧同步，属发布线工作。
