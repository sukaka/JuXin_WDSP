# 可信代理设计（阶段5）

## 模型

| 字段 | 说明 |
|------|------|
| id / name | 标识与名称 |
| cidr | 单个 IPv4、IPv4 CIDR、单个 IPv6、IPv6 CIDR（规范化存储） |
| ip_version | IPV4 / IPV6（派生） |
| header_type | X_FORWARDED_FOR / X_REAL_IP / FORWARDED / CUSTOM |
| custom_header_name | header_type=CUSTOM 时必填（`[A-Za-z0-9._-]`，≤64） |
| priority | 数值小者优先（默认 100） |
| status | ENABLED / DISABLED |
| scope / node_name | GLOBAL 或 NODE（节点级，仅指定网关节点生效） |
| description / version / 审计字段 | 乐观锁与审计 |

## 规则

- 禁止域名、带协议、带端口、通配符、控制字符；CIDR 掩码化（`192.168.1.77/24` → `192.168.1.0/24`）；
  IPv4 映射 IPv6 归一。
- 唯一性：未删除的 (cidr, node_name) 不可重复（409）。
- 匹配：连接源 IP 命中多条时代先级数值小者生效（如精确单 IP 优先于大段 CIDR）。
- 头类型绑定：可信代理只信任其配置的那一种头，其余头一律忽略（防"换一种头绕过"）。

## 接口

`GET/POST /api/v1/trusted-proxies`、`GET/PUT/DELETE /{id}`、`POST /{id}/enable|disable`、`POST /test`。

**测试端点**（`POST /test`）：输入 `{cidr, test_ips[]}`，返回每个 IP 的合法性与命中结果
（本 CIDR 是否命中 + 库中已启用代理的命中列表），供前端"可信代理测试"。

## 权限

- 安全管理员：全量管理；
- 系统管理员：可信代理与保护地址维护（组件级，不得创建业务黑白名单与 CC 策略）；
- 审计管理员：只读。

## 发布

可信代理随配置发布下发到网关（GLOBAL 全量 + 本节点 NODE 级），
网关 Provision 时编译为优先级匹配集合。发布/版本/回滚走统一发布链路（见 IP_ACCESS_CONTROL_DESIGN）。
