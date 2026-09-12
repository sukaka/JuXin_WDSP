# 离线包与物理机网关改动记录

> 记录日期：2026-09-03  
> 适用仓库：`JiuZhang_WAF`  
> 本次验证包：`jiuzhang-waf-offline-2.5.5-amd64.tar.gz`

## 一、改动目标

解决物理机使用生产离线包部署时的端口换算问题：生产网关容器改为使用宿主机网络，UI 中配置的站点端口直接对应宿主机监听端口，不再需要把宿主机端口换算成容器端口。

本次改动只涉及生产离线包和裸机网关相关路径。开发、演示及实验环境的 Compose 编排不在本次范围内。

## 二、代码与配置改动

### 1. 生产离线包构建

文件：`ops/offline-package/build.sh`

- 离线包构建参数扩展为产品线、版本和架构：
  - `--product waf|wdsp|api`
  - `--version X.Y.Z`
  - `--arch amd64|arm64`，支持 `x86`、`x86_64`、`aarch64` 别名
- 产物命名统一为：`jiuzhang-{product}-offline-{version}-{arch}.tar.gz`。
- 增加目标架构校验，避免导出错误架构的镜像。
- 第三方镜像按目标架构拉取，并进行 digest/架构检查。
- 离线包增加日志轮转镜像、可选 APM 数据面镜像及对应编排/挂载目录。
- 增加裸机网关包 `gateway-linux-{arch}.tar.gz`，包含网关二进制、规则、bootstrap 配置、systemd unit、安装脚本和验收脚本。
- `--skip-images` 明确为“仅验证文件结构”的模式：该模式不包含可运行镜像和裸机网关二进制，不能直接用于目标机部署。
- 生产 gateway 服务改为：
  - `network_mode: host`
  - 删除端口映射和业务 Docker 网络
  - 保留 `cap_drop: ALL`
  - 增加 `cap_add: NET_BIND_SERVICE`，允许非 root 网关绑定 80/443
- 生产网关改用无站点 bootstrap Caddyfile，首启不预置 POC 站点。
- API 服务透传 `GATEWAY_VALKEY_ADDR=127.0.0.1:${VALKEY_PORT:-6379}`。

### 2. API 到 Valkey 的地址配置

文件：

- `server/internal/config/config.go`
- `server/internal/config/config_test.go`
- `server/internal/app/app.go`

改动内容：

- `GatewayConfig` 增加 `ValkeyAddr` 字段。
- 支持读取环境变量 `GATEWAY_VALKEY_ADDR`。
- 网关 Valkey 地址优先使用显式配置；未配置时回退到 `Cache.Host:Cache.Port`。
- 增加默认回退、显式覆盖和环境变量读取测试。

这样可以兼容两种运行形态：

- 生产 host 网络网关：使用 `127.0.0.1:6379`。
- 原有裸机、开发及其他非 host 网络形态：继续使用原有缓存配置。

### 3. Docker 离线包安装器

文件：`ops/install/install.sh`

- 增加 firewalld 配置步骤。
- firewalld 运行时默认放行：
  - `80/tcp`
  - `443/tcp`
  - `1024-65535/tcp`
- 增加 `--no-firewall` 选项，用于跳过自动防火墙配置。
- 删除生成 `.env` 时不再使用的 `GATEWAY_PORT` 配置行。
- 保留 `--gateway-port` 的端口占用检查逻辑。
- 启动流程和日志步骤编号同步更新。

### 4. 裸机网关安装与验收

文件：

- `ops/install/install-gateway-baremetal.sh`
- `ops/install/verify-gateway-baremetal.sh`

改动内容：

- 裸机网关安装时默认放行 80、443 和 1024-65535 端口。
- 同步更新安装摘要、运维提示和验收脚本提示。
- 保留对 1024 以下自定义端口需要额外放行的说明。

### 5. 文档同步

文件：

- `docs/DEPLOYMENT.md`
- `docs/BARE_METAL_GATEWAY_DESIGN.md`
- `docs/DEVELOPMENT_STATUS.md`

同步内容：

- 更新多架构离线包说明。
- 更新生产业务代理端口规划：80/443 及 1024-65535 端口可直接使用。
- 说明生产离线包网关使用 host 网络是业务端口直绑的受控例外。
- 补充授权导入、指纹采集、运维控制台和 HA 实验编排说明。
- 更新开发状态基线，明确管理面仍禁止 host 网络。

## 三、文件变更清单

本次涉及的运行时代码、脚本和文档如下：

```text
ops/offline-package/build.sh
server/internal/config/config.go
server/internal/config/config_test.go
server/internal/app/app.go
ops/install/install.sh
ops/install/install-gateway-baremetal.sh
ops/install/verify-gateway-baremetal.sh
docs/DEPLOYMENT.md
docs/BARE_METAL_GATEWAY_DESIGN.md
docs/DEVELOPMENT_STATUS.md
```

## 四、验证结果

已完成以下验证：

- `gofmt`：通过。
- Shell 语法检查：通过。
- `go test ./internal/config/... ./internal/guardconfig/...`：通过。
- `go build ./...`：通过。
- `go test ./...`：通过。
- `docker compose config`：通过。
- 离线包生成：通过，验证产物为 `/tmp/jz-offline-verify/jiuzhang-waf-offline-2.5.5-amd64.tar.gz`。
- Compose 结构确认：gateway 无 `ports`，使用 `network_mode: host`，包含 `NET_BIND_SERVICE`。
- 包内 bootstrap Caddyfile 与源码一致：通过。
- `install.sh --help`、`verify-gateway-baremetal.sh --help`：通过。

说明：全仓库 `git diff --check` 仍会报告两个与本次无关的历史文档尾随空格问题；本次涉及文件的局部 diff 检查通过，未修改这些无关文件。

## 五、当前离线包的使用限制

本次验证包使用了 `--skip-images`，因此：

- 可以用于检查目录结构、Compose 模板、配置文件和脚本。
- `images/` 不包含可加载的 Docker 镜像。
- `gateway-linux-amd64.tar.gz` 不包含可运行的 Caddy 二进制。
- 不能直接在全新目标机上完成运行时部署。

如果需要完整可运行离线包，构建时不要加 `--skip-images`，并确保目标版本的 `jiuzhang-server`、`jiuzhang-gateway`、`jiuzhang-logrotator` 镜像已经按目标架构准备好。

## 六、已安装环境的“只升级文件”方式

用户已安装现有版本、只希望更新文件时，不需要重新安装，也不要删除数据卷，不要执行 `docker compose down -v`。

先将离线包复制到目标机并解压，然后替换网关相关文件：

```bash
PKG=/opt/upgrade/jiuzhang-waf-offline-2.5.5-amd64
DEPLOY=/opt/jiuzhang/current

cd "$DEPLOY"
cp gateway/Caddyfile "gateway/Caddyfile.bak.$(date +%Y%m%d%H%M%S)"
cp gateway/blockpage.html "gateway/blockpage.html.bak.$(date +%Y%m%d%H%M%S)"
cp "$PKG/gateway/Caddyfile" gateway/Caddyfile
cp "$PKG/gateway/blockpage.html" gateway/blockpage.html
cp -a "$PKG/gateway/rules/." gateway/rules/
cp "$PKG/ops/install/install.sh" ops/install/install.sh
cp "$PKG/ops/install/install-gateway-baremetal.sh" ops/install/install-gateway-baremetal.sh
cp "$PKG/ops/install/verify-gateway-baremetal.sh" ops/install/verify-gateway-baremetal.sh
```

更新后仅重载网关：

```bash
docker compose config
docker compose up -d --no-deps gateway
bash ops/healthcheck/check.sh
```

注意：

- 不要覆盖现有 `.env`、数据库目录、PostgreSQL/Valkey 数据卷。
- `docker-compose.yml` 不建议直接覆盖，应先与现有文件做差异合并，以保留现场自定义配置。
- 若要启用 host 网络，需将新 Compose 中 gateway 服务的 `network_mode`、能力配置和 API 的 `GATEWAY_VALKEY_ADDR` 合并到现有 Compose；合并前保留备份。
- 仅复制文件不会升级 API 镜像中的 Go 代码。要让 `GATEWAY_VALKEY_ADDR` 逻辑生效，必须同时准备并加载对应版本的 API 镜像，然后再按镜像升级流程更新 API。
- 如果当前目标只是更新 Caddy 配置、规则和运维脚本，则不需要重启 API。

## 七、未执行事项

- 未提交 Git commit。
- 未推送远程仓库。
- 未覆盖用户已有的其他脏文件或现场配置。
- 未在真实生产主机上执行安装或重启操作。
