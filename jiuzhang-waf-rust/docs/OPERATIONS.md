# 裸机运行与运维

## 发布前检查

```bash
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo build --release
```

把二进制、配置和 systemd 单元安装到不同目录。以下命令是部署示例，需要按实际发行版调整：

```bash
sudo install -m 0755 target/release/jiuzhang-native-waf /usr/local/bin/jiuzhang-native-waf
sudo install -d -m 0750 /etc/jiuzhang-native-waf
sudo install -m 0640 config.example.toml /etc/jiuzhang-native-waf/config.toml
sudo install -m 0644 packaging/jiuzhang-native-waf.service /etc/systemd/system/jiuzhang-native-waf.service
```

编辑 `/etc/jiuzhang-native-waf/config.toml`，设置真实源站和监听地址。服务单元使用 `DynamicUser=yes`，状态目录由 systemd 创建。事件路径保持为相对的 `var/security-events.jsonl`，因此实际文件位于 `/var/lib/jiuzhang-native-waf/var/security-events.jsonl`。

```bash
/usr/local/bin/jiuzhang-native-waf --config /etc/jiuzhang-native-waf/config.toml --check-config
sudo systemctl daemon-reload
sudo systemctl enable --now jiuzhang-native-waf
sudo systemctl status jiuzhang-native-waf
```

如果配置监听低于 1024 的端口，需要由管理员明确配置端口转发或最小能力授权；默认示例使用高端口，不授予额外网络能力。

## 日常检查

```bash
curl --fail http://127.0.0.1:19090/health
curl --fail http://127.0.0.1:19090/metrics
sudo journalctl -u jiuzhang-native-waf --since today
```

`/health` 只说明进程和 HTTP 服务存活，不表示源站已经完成主动健康检查。`/metrics` 是进程启动以来的计数，不是持久化历史数据。管理监听没有认证，必须保持回环地址，或放在具备外部访问控制的受控内网。

## 配置变更与升级

当前配置不自动热加载。建议流程：备份配置和二进制 → 安装候选文件 → 执行 `--check-config` → 重启服务 → 检查健康、指标和真实代理请求。启动失败时恢复上一份配置或二进制，不要跳过校验强行运行。

```bash
sudo systemctl restart jiuzhang-native-waf
sudo systemctl stop jiuzhang-native-waf
```

停止或重启会清空内存限速窗口与指标。已经落盘的事件不会被删除。

## 事件文件维护

事件文件会持续追加，当前版本没有内建轮转。可以由 logrotate 执行 `copytruncate`，或停止服务后归档再启动。任何轮转方案都应先限制保留容量并验证文件权限。事件包含客户端 IP 和参数名，仍应按内部安全日志管理。

备份至少包括配置文件和事件归档。备份前确认其中不含业务方不允许复制的信息；本实现不会把请求体、Authorization 或 Cookie 值主动写入安全事件。

## 已知运行限制

- 客户端接入仅支持 HTTP；TLS 终止需后续原生实现，不应通过未审计的临时转发脚本代替。
- 一个进程只支持一个源站，没有主动健康检查和负载均衡。
- 限速和指标是单进程内存状态，不适用于多副本一致计数。
- 请求体检查需要缓冲，大请求上限应结合宿主机内存与并发量设置。
- 事件写入失败会记录进程错误，但请求不会因此被阻断；需要监控磁盘空间和文件权限。
