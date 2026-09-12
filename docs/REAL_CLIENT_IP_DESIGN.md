# 真实客户端IP识别设计（阶段5）

## 核心原则

**只有 TCP 连接来源属于可信代理时，才能信任代理头；否则必须使用连接源 IP。**
绝不无条件读取 `X-Forwarded-For` / `X-Real-IP` / `Forwarded` / 自定义头。

## 处理流程

```text
提取连接源 IP（RemoteAddr 去端口，netip 解析，非法即拒绝）
  ↓
连接源命中可信代理？（优先级匹配）
  ├─ 否 → 客户端IP = 连接源（忽略全部代理头）；
  │        若携带代理头 → TRUSTED_PROXY_INVALID 事件（伪造尝试）
  └─ 是 → 按该代理配置的 header_type 取值：
          X_FORWARDED_FOR / X_REAL_IP / FORWARDED / CUSTOM（自定义头仅对显式配置的代理生效）
          ↓
        头值校验（禁控制字符、长度≤2048、首个同名头）
          ↓
        链解析（从右向左跳过连续可信代理，第一个非可信地址为客户端）
          ├─ 任一元素非法 → 回退连接源 + FORWARDED_HEADER_INVALID 事件
          ├─ 链长 > 16（可配）→ 回退连接源 + FORWARDED_CHAIN_TOO_LONG 事件
          └─ 全链可信 → 最左端声明可被客户端注入（前置可信代理追加而非覆盖），
             不采信，保守回落连接源 + TRUSTED_PROXY_INVALID 事件（action=CONNECTION_FALLBACK）
```

## 头解析细则

- **X-Forwarded-For**：逗号分隔 IP 列表，任一元素非法整体作废；重复头取首个（Go `Header.Get` 固定规则）。
- **X-Real-IP**：单 IP。
- **Forwarded（RFC 7239）**：按 `;` 取 `for=` 参数，去引号/端口/IPv6 方括号；`unknown` 与 `_` 开头混淆标识跳过。
- **自定义头**：语义同 XFF，仅对 `header_type=CUSTOM` 且配置同名头的可信代理生效。
- **IPv4 映射 IPv6** 统一归一（`::ffff:1.2.3.4` → `1.2.3.4`），匹配与计数口径一致。

## 识别结果向下游传播

- `r.RemoteAddr` 改写为真实 IP（Coraza/访问日志/reverse_proxy 的 XFF 自动正确）；
- `X-Real-Ip` 强制覆盖为真实 IP（客户端传入值不被信任）；
- 连接源 IP 保留于事件 `connection_ip` 字段。

## 日志字段（访问控制事件与访问日志）

`client_ip`、`connection_ip`，以及结构化三字段（网关 `events.Event` 与 `accessLogRecord` 上报，
omitempty + 长度截断；服务端落 `access_control_events` 与 `access_logs`，迁移 000144）：

- `client_ip_source`：识别来源枚举 `CONNECTION / X_FORWARDED_FOR / X_REAL_IP / FORWARDED / CUSTOM_HEADER`；
- `trusted_proxy_used`：命中的可信代理名（未经可信代理解析时为空）；
- `forwarded_chain_summary`：截断的代理链摘要（伪造/非法头场景为原始头值截断片段）。

## 测试（真实网关实测）

直接访问、伪造XFF、伪造X-Real-IP、单级可信代理、多级代理、混合链（单元）、
IPv6（单元）、映射归一、非法头回退、超长链回退、重复头首值、自定义头（单元）。
见 `test/waf/scripts/stage5-gateway-tests.sh` 与 `gateway/modules/jiuzhang_guard/clientip/` 单测。
