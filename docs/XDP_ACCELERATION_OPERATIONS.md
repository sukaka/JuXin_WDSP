# eBPF/XDP 内核态快速丢包加速运维手册（Phase 9D-2）

## 1. 能力定位与安全红线

`jiuzhang-xdpguard`（源码 `gateway/xdpguard/` 与 `gateway/cmd/xdpguard/`）是九章 WDSP 的可选内核态 L3 源 IP 快速丢包守护进程，仅在物理业务网卡入口（XDP Hook）执行**全局有效 IP 黑名单**与**全局有效临时封禁**的微秒级丢包，将高并发 DDoS/暴力扫描流量阻断在内核网络协议栈与用户态 Caddy/Coraza 之前。

强制安全边界（不可绕过）：

1. **仅全局范围**：控制面仅同步 `scope_type='GLOBAL'` 的生效黑名单与 `application_id IS NULL` 的全局临时封禁，绝不下发单应用级规则，避免同一宿主机上的其他业务应用被误断。
2. **双重受保护地址隔离**：管理后端（`server/internal/xdpaccel/filter.go`）与 `xdpguard` 守护进程（`gateway/xdpguard/filter.go`）各自独立执行 `prefix.Overlaps(...)` 排除检查，凡与以下任一地址重叠的候选前缀（含宽网段如 `10.0.0.0/8`、`0.0.0.0/0`、`::/0`）一律禁止写入内核 `blocked_v4`/`blocked_v6` Map：
   - 系统内建不可封禁段：`127.0.0.0/8`、`169.254.0.0/16`、`0.0.0.0/32`、`224.0.0.0/4`、`255.255.255.255/32`、`::1/128`、`fe80::/10`、`::/128`、`ff00::/8`；
   - 宿主机全部本机网卡 IP（`net.InterfaceAddrs()` 实时发现的 `/32`、`/128`）；
   - 控制面当前启用的全部 `protected_addresses`。
3. **零 TCP 监听**：`xdpguard` 仅绑定受控 Unix Domain Socket（默认 `/var/run/caddy/sidecars/xdpguard.sock`，权限 `0660`，拒绝符号链接与非 Socket 文件），不开放任何 TCP/UDP 端口。
4. **Fail-Open 故障开放**：任何加载、挂载或权限失败均自动摘除残留链接并回退至 `fallback_userspace`，原有用户态网关防护继续生效；关闭开关（`enabled=false`）或进程收到 `SIGTERM`/`SIGINT` 时自动卸载全部 XDP 链接并清空 Map，确保业务不黑洞。

---

## 2. Linux 内核与网卡要求

| 项目 | 最低要求 | 推荐配置 |
|------|----------|----------|
| Linux 内核 | 5.10+（支持 `BPF_MAP_TYPE_LPM_TRIE`、`BPF_MAP_TYPE_PERCPU_ARRAY`、`BPF_LINK_TYPE_XDP`） | 5.15 LTS / 6.1+ / 6.6+ |
| 权限能力 | 仅 `CAP_BPF` + `CAP_NET_ADMIN`（非 root 用户 `uid=1000` 可运行） | 通过 `systemd` `AmbientCapabilities` 最小授权 |
| 架构 | `linux/amd64`、`linux/arm64`（纯 Go `CGO_ENABLED=0` 静态二进制，构建期零 clang） | 同左 |
| 挂载模式 `native` | 物理网卡驱动原生支持 XDP（如 `ixgbe`、`i40e`、`ice`、`mlx5_core`、`virtio_net`、`ena`、`bnxt_en`） | 生产推荐 `auto`（优先 `native`，驱动不支持时自动回退 `generic`） |
| 挂载模式 `generic` | 任意支持 XDP SKB 模式的 Linux 物理网卡 | 无原生驱动时的兼容模式 |

---

## 3. 物理业务网卡选择与管理口隔离

- **禁止挂载的虚拟/环回网卡**：前后端及 `xdpguard` 一致拒绝 `lo` 以及 `docker*`、`br-*`、`veth*`、`virbr*`、`cni*`、`flannel*`、`cali*`、`tun*`、`tap*`、`wg*`。
- **强隔离管理口（强烈推荐）**：多网口裸机部署时，务必在 `/etc/jiuzhang/xdpguard.env` 中配置 `XDPGUARD_EXCLUDE_INTERFACES` 指定管理/SSH/数据库/高可用心跳网口（例如 `XDPGUARD_EXCLUDE_INTERFACES=eno1,ens3f1`）。即使控制面误将该网口写入配置，`xdpguard` 也会直接拒绝挂载并返回 `400`。

---

## 4. 无特权容器环境行为（优雅回退）

在默认 Docker Compose 无特权容器（无 `CAP_BPF`/`CAP_NET_ADMIN`、无宿主机物理网卡命名空间）或未部署 `jiuzhang-xdpguard.service` 的环境中：

- 管理后端探测 `/var/run/caddy/sidecars/xdpguard.sock` 会如实返回 `available=false`、`status="unavailable"`、`mode="fallback_userspace"`、`kernel_attached=false`，绝不伪造在线状态。
- 若守护进程已启动但缺少内核权限，同步请求将触发 Fail-Open，如实返回 `status="degraded"`、`mode="fallback_userspace"`、`kernel_attached=false` 与真实内核错误信息，原有用户态访问控制/CC/WAF 持续正常工作。

---

## 5. Systemd 部署步骤（生产裸机网关）

1. **构建并安装静态二进制**（支持 `amd64` / `arm64`，零 CGO）：

   ```bash
   cd gateway
   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /usr/local/bin/jiuzhang-xdpguard ./cmd/xdpguard
   chmod 0755 /usr/local/bin/jiuzhang-xdpguard
   ```

2. **创建运行目录与可选环境文件**：

   ```bash
   install -d -o 1000 -g 1000 -m 0750 /var/run/caddy/sidecars
   cat <<'EOF' | sudo tee /etc/jiuzhang/xdpguard.env
   # 明确排除 SSH/管理口与高可用心跳口，防止误挂载
   XDPGUARD_EXCLUDE_INTERFACES=eno1
   XDPGUARD_ATTACH_MODE=auto
   # 可选：若需加载离线 clang 预编译 CO-RE ELF 对象，取消下一行注释
   # XDPGUARD_BPF_OBJ=/etc/jiuzhang/xdp_drop.o
   EOF
   sudo chmod 0640 /etc/jiuzhang/xdpguard.env
   ```

3. **安装并启动 systemd 服务**：

   ```bash
   sudo cp deployment/systemd/jiuzhang-xdpguard.service /etc/systemd/system/jiuzhang-xdpguard.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now jiuzhang-xdpguard.service
   sudo systemctl status jiuzhang-xdpguard.service
   ```

4. **通过 Unix Socket 自检（无需 TCP）**：

   ```bash
   curl --unix-socket /var/run/caddy/sidecars/xdpguard.sock http://unix/healthz
   curl --unix-socket /var/run/caddy/sidecars/xdpguard.sock http://unix/v1/stats
   ```

5. **在管理界面启用**：
   进入「系统运维 -> 内核 XDP 加速」（`/xdp-acceleration`），填写物理业务网卡名（如 `ens192`），选择挂载模式 `auto`，保存配置并点击「立即同步黑名单至 XDP」，核对卡片中 `内核态已挂载` 与目标网卡的 `xdp_native`/`xdp_generic` 状态。

---

## 6. 紧急卸载与故障回滚

1. **通过控制台一键停用**：在 `/xdp-acceleration` 关闭「启用 XDP 内核加速」并保存，控制面会向 `POST /v1/sync` 下发 `enabled=false`，守护进程立即卸载全部 XDP 链接并清空 Map。
2. **停止 systemd 守护进程**：

   ```bash
   sudo systemctl stop jiuzhang-xdpguard.service
   ```

   由于所有挂载均基于 `bpf_link` 文件描述符生命周期，进程退出或收到 `SIGTERM` 时内核会自动摘除对应的 XDP 钩子。

3. **宿主机内核级紧急强制摘除（兜底命令）**：

   ```bash
   # 查看网卡当前 XDP 挂载状态
   ip -details link show dev <nic>

   # 强制卸载指定物理网卡上的所有 XDP 程序（native/generic 通用）
   sudo ip link set dev <nic> xdp off
   sudo ip link set dev <nic> xdpgeneric off 2>/dev/null || true
   sudo ip link set dev <nic> xdpdrv off 2>/dev/null || true
   ```

4. **核对恢复结果**：确认 `ip link show dev <nic>` 输出中不再包含 `prog/xdp`，且业务流量正常由用户态 `jiuzhang-gateway` 承接。
