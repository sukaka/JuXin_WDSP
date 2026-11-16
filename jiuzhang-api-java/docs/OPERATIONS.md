# 原生运行说明

## 安装

将 `dist/jiuzhang-api-security.jar` 安装到 `/usr/local/share/jiuzhang-api-security/`，将正式配置、模型和授权文件安装到 `/etc/jiuzhang-api-security/`。身份盐通过权限为 0600 的 EnvironmentFile 注入，不写入源码或示例配置。

```bash
java -jar /usr/local/share/jiuzhang-api-security/jiuzhang-api-security.jar \
  --check-config /etc/jiuzhang-api-security/application.properties
sudo systemctl daemon-reload
sudo systemctl enable --now jiuzhang-api-security
```

服务单元示例位于 `packaging/jiuzhang-api-security.service`。默认高端口不需要额外 capability；如改用特权端口，应由管理员选择最小化授权或外部端口转发。

## 检查与变更

```bash
curl --fail http://127.0.0.1:19091/health
curl --fail http://127.0.0.1:19091/metrics
sudo journalctl -u jiuzhang-api-security --since today
```

修改配置、正式模型或授权关系后，先执行配置检查，再重启服务。当前版本不支持热更新。升级前保留旧 JAR 与配置，升级后验证正常请求、攻击阻断、响应脱敏、事件查询和源站故障返回。

事件文件需要外部轮转策略。轮转前评估采集和归档需求；当前核心不提供断点采集器或数据库事件中心，不能把文件存在等同于长期审计能力。
