# 身份认证设计（阶段2）

## 登录流程

```text
用户提交 用户名+密码+验证码
  ↓
GET /auth/captcha 获取验证码（服务端生成，答案存 Valkey，TTL 120s）
  ↓
POST /auth/login
  ├─ 验证码校验（一次性使用，验证后立即失效）
  ├─ 用户查询（不存在 → 统一错误，记录 BAD_CREDENTIALS）
  ├─ 状态检查（禁用/锁定 → 统一"账号不可用"）
  ├─ Argon2id 密码校验（失败 → 失败计数+1，达阈值锁定）
  ├─ 密码过期检查
  ├─ 查询角色与权限
  ├─ 创建服务端会话（Valkey）
  ├─ 签发 CSRF Token（Valkey，关联会话）
  └─ Set-Cookie 下发会话标识（HttpOnly/Secure/SameSite=Lax）
```

## 密码策略

- 存储：Argon2id（m=64MB, t=3, p=2），每密码独立随机 16 字节 Salt，常量时间比较
- 策略（可配置，存 system_settings）：
  - 最小长度 12，必须含大小写/数字/特殊字符
  - 不得与用户名相同或包含完整用户名
  - 弱口令清单检查
  - 历史 5 次不得重复（password_histories）
  - 有效期 90 天，到期前 7 天提醒
  - 管理员重置/首次创建后 must_change_password=true
- 初始管理员：首次启动生成一次性随机密码（仅 stdout 打印一次）或环境变量注入，首次登录强制改密；不落日志、不入库明文

## 登录失败锁定

- 连续失败 5 次锁定 15 分钟（可配置）
- 成功登录清零失败计数
- 登录接口按 IP 限速（默认 10 次/分钟）
- 验证码接口按 IP 限速（20 次/分钟）
- 失败统一返回"用户名或密码错误"，不区分用户不存在/密码错误/禁用（锁定返回"账号不可用"）

## 会话设计

- 服务端会话：Valkey `jiuzhang:session:<id>`（JSON）
- Cookie 仅存随机会话标识：`jiuzhang_session`，HttpOnly/Secure/SameSite=Lax/Path=/
- 字段：会话ID、用户ID、用户名、角色、权限、创建时间、最近活动、绝对过期、来源IP、UA摘要
- 超时：空闲 30 分钟（活动刷新 TTL），绝对 8 小时（不随活动延长）
- PostgreSQL `login_sessions` 仅存审计摘要（session_hash = sha256(id)），不保存原始 ID
- 单用户最大 5 会话（超限淘汰最旧）；可配置单会话模式
- 失效场景：主动退出、强制下线、修改密码（其他会话）、用户禁用/删除、角色变更

## CSRF 防护

三重防护（所有写操作 POST/PUT/DELETE）：
1. SameSite=Lax Cookie
2. CSRF Token：登录/me 签发，写操作必须携带 `X-CSRF-Token` 头，Valkey 校验（关联会话）
3. Origin 校验：存在 Origin 时必须与 Host 同源

豁免：登录、获取验证码、健康检查（仍需 Origin 检查 + 限速）。

## 验证码设计

- 服务端生成：4 位随机字符（去除 0/O/1/I/l 易混淆），自绘 PNG（干扰线+干扰点+随机偏移，无第三方依赖）
- 答案存 Valkey，TTL 120 秒，一次性使用（验证后立即删除）
- 不返回前端，不区分大小写（可配置）
- 验证码接口按 IP 限速

## 失败处理

| 场景 | 响应 | 内部记录 |
|------|------|---------|
| 用户不存在 | 401 用户名或密码错误 | BAD_CREDENTIALS |
| 密码错误 | 401 用户名或密码错误 | BAD_CREDENTIALS + 失败计数 |
| 验证码错误 | 400 验证码错误或已过期 | CAPTCHA_INVALID |
| 账号禁用 | 403 账号不可用 | ACCOUNT_DISABLED |
| 账号锁定 | 403 账号不可用 | ACCOUNT_LOCKED |
| 密码过期 | 403 密码已过期 | PASSWORD_EXPIRED |
| 首次登录未改密 | 403 PASSWORD_CHANGE_REQUIRED | - |

日志不记录密码、验证码答案、完整会话标识。
