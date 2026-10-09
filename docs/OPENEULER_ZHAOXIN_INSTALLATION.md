# openEuler / 兆芯 `.run` 安装与主机优化

本文说明如何为兆芯 x86-64（KX/KH）服务器构建和安装 WDSP 自解压交付包。安装器默认只接受 openEuler 与兆芯 CPU；在其他已完成兼容性验证的平台上，必须分别显式使用 `--allow-compatible-os` 或 `--allow-non-zhaoxin`。

## 交付边界

- 目标架构为 `amd64`，适用于兆芯 KX/KH 的 x86-64 指令集。
- 正式包必须同时包含 SHA-256 校验和 Ed25519 签名；未签名包仅用于开发验证。
- 安装器不会关闭 SELinux、防火墙、SSH、NetworkManager、时间同步或 CPU 安全缓解措施。
- `--minimal-host` 只停用明确与 WDSP 无关的打印、蓝牙、局域网发现、邮件和 NFS 服务，不卸载 RPM，不修改软件仓库。
- “精简操作系统”应基于 openEuler 最小化安装镜像完成。对已投入使用的宿主机自动卸载软件风险过高，不属于安装器职责。

## 构建正式包

先完成 WDSP amd64 镜像构建，并通过环境变量提供仓库外的 Ed25519 发布私钥：

```bash
WDSP_SIGNING_KEY=/secure/path/release-private-key.pem \
  ./ops/offline-package/build-openeuler-zhaoxin-run.sh --version 1.2.0
```

如已有同版本正式离线包，可直接封装：

```bash
WDSP_SIGNING_KEY=/secure/path/release-private-key.pem \
  ./ops/offline-package/build-openeuler-zhaoxin-run.sh \
  --version 1.2.0 \
  --offline-package dist/jiuzhang-wdsp-offline-1.2.0-amd64.tar.gz
```

完整的离线交付必须传入与目标机 **同一 openEuler 版本、x86-64 架构**匹配的 RPM 目录；其顶层必须包含 `docker-compose-plugin-*.rpm`。该目录还必须包含 Docker 引擎、Docker CLI、运行时及 `docker-compose-plugin` 的所有事务依赖，不能只放一个 Compose RPM。构建器会拒绝缺少 `docker-compose-plugin` 的目录：

```bash
WDSP_SIGNING_KEY=/secure/path/release-private-key.pem \
  ./ops/offline-package/build-openeuler-zhaoxin-run.sh \
  --version 1.2.0 \
  --rpm-dir /secure/openeuler-24.03-x86_64-rpms
```

使用完整运行包脚本时，`--rpm-dir` 为必填项：

```bash
WDSP_SIGNING_KEY=/secure/path/release-private-key.pem \
  ./ops/offline-package/package-runtime-run.sh \
  --rpm-dir /secure/openeuler-24.03-x86_64-rpms
```

由于 `.run` 载荷本身需要 `tar`/`gzip` 展开，如果目标机缺少这两个命令，仍需可用的本地 dnf/yum 仓库；安装器会先尝试 `dnf`，再回退 `yum`。

仅做结构测试时可使用 `--development --skip-images`。这种包没有可运行镜像，不能用于生产部署。

## 安装

先使用仓库发布公钥校验 Ed25519 外层签名，再校验 SHA-256：

```bash
base64 -d < jiuzhang-wdsp-openeuler-zhaoxin-1.2.0-amd64.run.sig > /tmp/wdsp-run.sig.raw
openssl pkeyutl -verify -pubin \
  -inkey /安全介质/release-signing.pub -rawin \
  -in jiuzhang-wdsp-openeuler-zhaoxin-1.2.0-amd64.run \
  -sigfile /tmp/wdsp-run.sig.raw
rm -f /tmp/wdsp-run.sig.raw
```

```bash
sha256sum -c jiuzhang-wdsp-openeuler-zhaoxin-1.2.0-amd64.run.sha256
sudo ./jiuzhang-wdsp-openeuler-zhaoxin-1.2.0-amd64.run
```

新建专用宿主机可以增加安全精简选项：

```bash
sudo ./jiuzhang-wdsp-openeuler-zhaoxin-1.2.0-amd64.run --minimal-host
```

安装器会自动完成以下检查与准备：

1. 验证 root、openEuler、x86-64/兆芯 CPU 和 systemd 环境。
2. 通过 dnf 或 yum 补齐 tar、gzip、OpenSSL、curl、jq、Python 3、Docker 与 Compose v2；Docker 会按 `docker`、`docker-engine` 顺序兼容新旧 openEuler 包名，Compose v2 仅接受 `docker-compose-plugin`，不将旧版 `docker-compose` 视为替代品。
3. 使用自解压头内置的发布公钥校验内层离线包哈希和正式签名；通过后才安装随包 RPM、执行宿主机准备脚本和标准 WDSP 安装向导。
4. 写入持久化 limits、sysctl 和 Docker systemd 限制。
5. 在内核提供 cpufreq 接口时，将兆芯 CPU governor 切换为 `performance`。

## 调优内容

| 范围 | 持久化位置 | 默认策略 |
|---|---|---|
| 文件描述符与进程数 | `/etc/security/limits.d/99-jiuzhang-wdsp.conf` | `nofile=1048576`、`nproc=262144` |
| 内核与网络队列 | `/etc/sysctl.d/99-jiuzhang-wdsp.conf` | 增大 file-max、listen/SYN backlog、端口范围等受支持参数 |
| Docker 服务限制 | `/etc/systemd/system/docker.service.d/99-jiuzhang-wdsp.conf` | 提高 `LimitNOFILE`、`LimitNPROC`、`TasksMax` |
| 兆芯 CPU | `/etc/systemd/system/jiuzhang-wdsp-cpu-performance.service` | 可用时立即设置为 `performance`，并在重启后恢复 |

调优只写入当前内核实际暴露的 sysctl 项。若宿主机与其他业务共用，应先用 `--skip-tuning` 安装，并由运维团队结合容量基线单独审批参数。

## 安装后验证

```bash
docker info
docker compose version
sysctl fs.file-max net.core.somaxconn
systemctl show docker -p LimitNOFILE -p LimitNPROC -p TasksMax
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || true
cd /opt/jiuzhang-wdsp/current && sudo bash ops/install/acceptance.sh
```

安装记录和版本目录保存在 `/opt/jiuzhang-wdsp/releases/<version>`，`/opt/jiuzhang-wdsp/current` 指向当前版本。

未签名的 development 包只能在隔离验证环境中使用，安装时必须明确传入 `--allow-unsigned`；生产交付不得使用此参数。

## 回退宿主机调优

停用 WDSP 后，可删除安装器创建的两个 `99-jiuzhang-wdsp.conf` 文件与 Docker override，禁用并删除 `jiuzhang-wdsp-cpu-performance.service`，再执行 `sysctl --system`、`systemctl daemon-reload` 并重启 Docker。CPU governor 应按服务器原始电源策略恢复；被 `--minimal-host` 停用的服务需依据部署前清单逐项重新启用。
