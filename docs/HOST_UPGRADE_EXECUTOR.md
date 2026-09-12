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

执行器配置文件位于 `/etc/jiuzhang/upgrade-executor.conf`，程序位于 `/usr/local/libexec/jiuzhang-upgrade-executor`。安装脚本要求宿主机已安装 Docker Compose、systemd、`jq`、`curl`、`python3`、`flock` 和 `sha256sum`。

## 安全边界

- 执行器只接受 `runtime-patch` 类型且组件服务名为 `api` 或 `web` 的补丁。
- 每次执行前校验外层 SHA-256、包内 `SHA256SUMS`、manifest 版本与机器架构。
- 解压时拒绝绝对路径、目录穿越、符号链接及异常文件数量。
- 新版本健康检查失败时，自动把服务镜像标签恢复到升级前的镜像并重建容器。
