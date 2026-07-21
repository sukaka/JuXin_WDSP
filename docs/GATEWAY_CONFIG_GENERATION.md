# 网关配置生成设计（阶段3）

## 输入数据

配置生成器从 PostgreSQL 的结构化数据生成 Caddy JSON 配置：

- applications（编码、防护模式）
- application_domains（规范化域名、HTTP/HTTPS 监听、跳转）
- upstreams（源站地址、权重、健康检查、超时、重试）
- certificates（HTTPS 证书 PEM + 加密私钥，发布时解密写入数据目录）
- 全局：阻断页面、Request ID、访问日志、Admin Socket

## 规范化

- 域名：`NormalizeHostname`（小写、去尾部点、去空白）
- 源站：`NormalizedHost`（小写、去空白），IP 用 netip 规范化
- 端口：1-65535 校验
- 应用编码：3-64 小写字母数字短横线

## 确定性生成

相同业务数据必须生成相同规范化配置与相同哈希：

- server 按监听端口分组，端口按字典序排序
- 路由按应用编码排序
- 源站按 host:port 排序
- upstreams 数组与 `selection_policy.weights` 顺序一一对应
- `encoding/json` 对 map 键自动按字典序序列化
- 哈希：sha256(序列化后的 JSON)

## 配置结构

```text
admin: unix/<socket>
logging: caddy.log (json)
apps.http.servers:
  srv<N>:
    listen: [":port"]
    routes:
      - match: [{host: [domain]}]
        handle:
          - headers(request): X-Request-Id = {http.request.uuid}（覆盖客户端传入）
          - waf: SecRuleEngine <Off|DetectionOnly|On> + 固定加载顺序
          - headers(response): 安全响应头 + 删除 Server
          - reverse_proxy: upstreams + load_balancing + health_checks + transport
    tls_connection_policies (HTTPS): sni 匹配 + 证书选择
    automatic_https: disable
```

## Caddy 兼容要点（实测）

- `admin.listen` 必须 `unix/<path>`（无前缀路径被误解析为 TCP 地址）
- `reverse_proxy` 无顶层 `retries` 字段 → 放 `load_balancing.retries`
- `upstream` 仅支持 `dial`、`max_requests` → 权重用 `selection_policy.weights` 数组（顺序对应 upstreams）
- WAF 三种模式映射：`OFF→SecRuleEngine Off`、`OBSERVE→DetectionOnly`、`PROTECT→On`
- 加载顺序固定：`coraza.conf → crs-setup.conf → before-crs.conf → crs/rules/*.conf → after-crs.conf → jiuzhang-custom.conf`

## 敏感字段处理

- 私钥：AES-256-GCM 加密存储（主密钥环境注入），发布时解密写入数据目录（权限 0600，仅所有者），Caddy 引用文件路径
- 私钥不进入配置 JSON、日志、审计、API 响应
- 证书 PEM 可公开，私钥仅在发布时以最小权限文件提供给网关

## 输出

- Caddy JSON 候选配置（runtime/configs/candidates/）
- 配置哈希（版本关联与幂等）
- server/route 统计
- 业务快照（发布审计）
