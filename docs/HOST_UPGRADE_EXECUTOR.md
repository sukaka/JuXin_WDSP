# 宿主机升级执行器安装说明

宿主机升级执行器负责读取 API 写入的升级任务，在宿主机校验补丁、加载 Docker 镜像、重建对应服务并执行健康检查。它不把 Docker Socket 暴露给 API 容器。

## 首次安装并升级到 1.0.1

下面命令中的 `/opt/jiuzhang/...` 需要替换为实际生产部署路径：

```bash
tar -xzf jiuzhang-wdsp-patch-1.0.0-to-1.0.1-amd64.tar.gz \
  jiuzhang-wdsp-patch-1.0.0-to-1.0.1-amd64/installer

sudo ./jiuzhang-wdsp-patch-1.0.0-to-1.0.1-amd64/installer/install-executor.sh \
  --compose-file /opt/jiuzhang/docker-compose.yml \
  --env-file /opt/jiuzhang/.env \
  --patch "$PWD/jiuzhang-wdsp-patch-1.0.0-to-1.0.1-amd64.tar.gz"
```

安装脚本会自动找到 API 容器 `/app/runtime` 对应的宿主机目录，安装并启用 systemd 服务，然后投递补丁任务。升级成功后，后续补丁可直接在 Web 界面上传和执行。

## 检查状态

```bash
sudo systemctl status jiuzhang-upgrade-executor.path
sudo systemctl status jiuzhang-upgrade-executor.service
sudo journalctl -u jiuzhang-upgrade-executor.service -n 100 --no-pager
```

执行器配置文件位于 `/etc/jiuzhang/upgrade-executor.conf`，程序位于 `/usr/local/libexec/jiuzhang-upgrade-executor`。安装脚本要求宿主机已安装 Docker Compose、systemd、`jq`、`curl`、`python3`、`flock`、`sha256sum`、`realpath`、`timeout`（coreutils），以及 `diff`、`cmp`（diffutils——执行器 manifest 文件比对与 compose 覆盖判异必需；openEuler 等最小化环境缺省不带，缺失时安装器/执行器会点名「diffutils 包」报准确错误并 fail-closed）。

## 更新执行器自身

`upgrade-executor.sh` 在仓库更新后（例如引入新组件支持），必须在宿主机重新运行 `install-executor.sh` 完成安装（重新拷贝 `/usr/local/libexec/jiuzhang-upgrade-executor` 并重启 systemd 单元），否则 path 单元触发的仍是旧版程序。功能升级包（见下）会在包内 `installer/` 随附当版安装器与执行器。

## 中断与超时语义

执行器进程被中断（kill、断电等，未写出结果文件）后**不自动续跑、不重复执行**。服务端对进入 APPLYING 超过等待上限（默认 30 分钟，截止时刻持久化于 `upgrade_jobs.executor_deadline`，API 重启不丢失）仍无结果文件的任务兜底标记 `FAILED`/`EXECUTOR_TIMEOUT`，留 HIGH 审计（`executor_timeout_close`）并触发 `UPGRADE_FAILED` 告警；**不自动重跑、不伪装成功**，人工核查后可经既有「FAILED → ROLLING_BACK」入口手动回滚。已写出结果文件的任务不受该兜底影响，仍由结果对账流程处理。

## package_type=upgrade（功能升级包，多组件）

自 1.3.0 起执行器除 `runtime-patch` 外还接受 `package_type=upgrade` 的功能升级包（`ops/upgrade/build-upgrade-pack.sh` 产物，命名 `jiuzhang-wdsp-upgrade-X.Y.Z-ARCH.tar.gz`）。协议要点：

- manifest 校验：`product=wdsp`、`change_type` 为 `feature`/`bugfix`、`version_from`/`version_to`/`version` 与任务一致、`arch` 与宿主机架构一致。
- **组件白名单**：`components` 与 `images[]` 只允许 `api`、`web`、`gateway`、`netmgrd`，逐一对应（`component == service`），未知组件一律拒绝。
- **内容校验**：`manifest.files` 逐一校验存在性/大小/SHA-256，并反查包内除 `manifest.json`/`manifest.sig` 外不得有未声明文件（与服务端 artifact.go「归档↔清单一一对应」同口径；`manifest.sig` 为包内签名，验签在服务端上传闸门完成，执行器不重复验签）；包内 `SHA256SUMS` 存在时作为纵深再校验一遍。
- **执行**：逐组件 `gzip -dc images/<组件>-<arch>.tar.gz | docker load` → retag 到 compose 期望标签 → `docker compose up -d --no-deps <各 service>` → 已选组件实际探测与管理 API 健康检查连续稳定 → 回写 results。失败路径沿用 runtime-patch 的回滚语义（retag 回退旧镜像并重建容器）。
- **新组件首次部署**：manifest 中宿主 compose（含已并入片段）不存在的服务，要求包内 `compose/upgrade-services.yml` 恰好补齐——执行器合并试解析后校验：新增服务集合 == 缺失服务集合、片段不改写任何既有服务的镜像、新服务镜像与 manifest 声明一致。校验通过才把片段安装到 `<DataDir>/upgrade-executor/compose-overrides.d/upgrade-<version_to>.yml`（幂等：同名文件内容必须一致），此后每次 compose 调用自动并入。回滚时摘除该片段、`compose rm -sf` 移除新容器并删除新加载的镜像标签。

## 升级后就绪标准（两种包共用）

- 已选服务必须恰有一个运行容器，且镜像 ID 等于本次加载并 retag 的目标镜像。`compose ps` / `docker inspect` 失败不视为成功；声明了 HEALTHCHECK 的容器必须为 healthy。
- API：容器内请求 `/api/v1/health`；Web：容器内请求首页及反向代理的 `/api/v1/health`，不以 running 代替服务可用。
- Gateway：宿主机通过该容器挂载的 `/var/run/caddy/admin.sock` 请求现有 Caddy Admin `GET /config/`，不新增 TCP 管理端口。这是控制面存活检查，不代替真实业务流量验收。
- netmgrd：容器内执行 `netmgrd --healthcheck`，只读访问容器私有 Unix Socket `/tmp/wdsp-netmgrd-health.sock`（0600）。首次轮询未完成、配置无效、执行/状态回写失败、正在处理、监督循环结果过期或关闭均不就绪；尚未下发配置是合法空闲状态。探针不执行 `ip` / `sysctl`，不改网络配置，也不依赖旧进程遗留的成功 status。
- 所有已选组件和宿主机管理 API 必须持续通过至少 10 秒；每轮 API 检查后重新读取全体容器快照，容器 ID、镜像 ID、重启次数、启动时间变化都会重新计时。超时按既有失败/回滚路径处理。

此就绪检查需要新版宿主执行器；旧宿主执行器不会因上传应用镜像包自动更新。新版 netmgrd 镜像内置上述探针。实际发布前应让完整安装基线同时包含新版执行器与 netmgrd；本地代码/桩测试不代表真实 openEuler 部署验收。

## 安全边界

- 执行器只接受 `runtime-patch`（组件服务名 `api`/`web`）与 `upgrade`（组件白名单 `api`/`web`/`gateway`/`netmgrd`）两类包，其余 `package_type` 一律拒绝。
- 每次执行前校验外层 SHA-256、manifest 版本与机器架构；`upgrade` 包另按 `manifest.files` 做全量文件级校验与反查。
- 解压时拒绝绝对路径、目录穿越、符号链接及异常文件数量。
- 新版本健康检查失败时，自动把服务镜像标签恢复到升级前的镜像并重建容器；新组件升级失败时摘除 compose 片段、移除新容器与新镜像标签。
