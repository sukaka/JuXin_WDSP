# 阶段2 测试报告（身份认证、三权权限与系统基础）

## 1. 测试环境

| 项目 | 值 |
|------|-----|
| 主机 | macOS（Apple Silicon 虚拟化），Docker Desktop |
| Go | 1.25.6 |
| Node.js | 24.13.0（.nvmrc 锁定） |
| PostgreSQL | 16.4-alpine |
| Valkey | 8.1.8-alpine |
| 浏览器 | Chromium Headless Shell 133（Playwright 1.50.1） |
| 测试日期 | 2026-07-21 |

## 2. 测试结果汇总

| 测试类别 | 总数 | 通过 | 失败 | 跳过 |
|---------|------|------|------|------|
| 后端单元测试 | 13 | 13 | 0 | 0 |
| 后端接口集成测试 | 28 | 28 | 0 | 0 |
| 前端单元测试（Vitest） | 23 | 23 | 0 | 0 |
| Playwright E2E | 16 | 16 | 0 | 0 |
| 安全测试（API） | 16 | 16 | 0 | 0 |
| **合计** | **96** | **96** | **0** | **0** |

## 3. 后端单元测试（13）

`go test ./internal/...`

| 模块 | 用例 | 覆盖 |
|------|------|------|
| security | 5（含子测试） | Argon2id 哈希/验证、盐随机性、密码策略 11 场景、临时密码 100 次迭代合规、随机令牌 |
| audits | 2 | 敏感字段脱敏（嵌套/数组/非法JSON）、哈希链确定性 |
| middleware | 5 | sameOrigin、RequestID 净化、RequirePermission（401/200/403）、CSRF 安全方法/有效Token |
| config | 1 | 配置加载 |

## 4. 后端接口集成测试（28）

`go test ./tests/`（独立测试库 jiuzhang_waf_test + 独立 Valkey DB15）

### 认证（10）
健康检查、登录成功、错误密码统一提示、不存在账号统一提示、验证码错误、连续失败锁定、未认证访问、退出后会话失效、CSRF 缺失拒绝、Request ID 响应头。

### RBAC 与用户管理（13）
安全管理员访问用户管理 403、审计管理员修改用户 403、审计管理员可读审计/登录日志、系统管理员不可读完整审计、重复用户名 409、不能停用最后一个系统管理员、不能删除自己、重置密码+临时密码+强制改密、审计记录含脱敏、审计哈希链完整、强制下线、改密后其他会话失效、弱密码拒绝。

### 系统设置与限速（5）
读取设置、修改密码策略并生效、设置乐观锁冲突、非管理员访问设置 403、登录接口限速触发 RATE_LIMITED。

## 5. 前端单元测试（23）

`npm test`（5 个测试文件）

| 文件 | 用例 | 覆盖 |
|------|------|------|
| api/client.test.ts | 7 | credentials、CSRF 自动附加、信封解包、ApiError、401 回调 |
| stores/auth.test.ts | 3 | 登录会话、CSRF 内存存储、退出重置 |
| utils/permission.test.ts | 5 | hasPermission/hasAnyPermission |
| utils/menu.test.ts | 5 | 菜单按角色过滤 |
| pages/login/LoginPage.test.tsx | 3 | 登录表单渲染、验证码刷新、提交 |

## 6. Playwright E2E（16）

`npx playwright test`（真实后端 18081 + vite dev server 代理 + 真实 Valkey 验证码）

### 场景一：系统管理员（6）
登录工作台、菜单权限（无操作审计）、创建安全管理员返回临时密码、用户列表搜索、修改密码策略、退出登录。

### 场景二：安全管理员（4）
临时密码登录强制改密→改密后工作台、菜单极简、直接访问用户管理 403（页面+API 双层）、查看个人会话。

### 场景三：审计管理员（5）
菜单含登录日志/操作审计、查看登录日志、查看操作审计、API 层可读审计/拒绝用户管理、尝试创建用户 403。

### 场景四：账号锁定（1）
连续 5 次错误密码锁定 → 正确密码不能登录 → 管理员解锁 → 重新登录成功。

## 7. 安全测试（16）

`test/security/stage2-api-security.sh`

SQL 注入、XSS、超大请求体、非法 Content-Type、未认证访问、伪造会话 Cookie、畸形会话 ID、安全响应头（nosniff/XFO/no-store/无 X-Powered-By）、404/错误不泄露堆栈路径、用户名枚举一致性（统一提示）、健康检查无敏感信息 —— 全部通过。

## 8. 过程中发现并已修复的问题（真实记录）

| 问题 | 根因 | 修复 |
|------|------|------|
| 登录后 /me 返回 401 | 中间件包装顺序错误，RequireAuth 在 sessionMiddleware 注入 Principal 之前执行 | 调整 authChain 顺序 |
| 密码正确但登录 BAD_CREDENTIALS | INET 列扫描到 *string 失败（pgx 无法将 INET 扫入 string） | 改用 netip.Addr 扫描 |
| 5173 代理登录失败 18081 成功 | IPv6 `[::1]` 带方括号，INET 插入 login_sessions 失败 | middleware.RemoteIP 改用 net.SplitHostPort |
| 页面创建用户 403 CSRF_INVALID | vite 代理 changeOrigin:true 使 Origin(5173)≠Host(18081) | vite 代理改 changeOrigin:false |
| E2E 触发 RATE_LIMITED | 限速值启动时缓存，改设置不生效；captcha 限速硬编码 | 限速中间件支持 LimitDynamic 动态读取 |
| Vitest 误跑 Playwright 用例 | e2e/*.spec.ts 被 Vitest 收集 | vite.config test.exclude 排除 e2e/ |
| 用户列表找不到目标用户 | E2E 创建大量用户致目标用户被分页挤出 | 用例改为搜索定位 |

## 9. 构建与部署验证

| 项目 | 结果 |
|------|------|
| 后端 `go build ./...` | 通过 |
| 后端 `go vet ./...` | 通过 |
| 前端 typecheck / lint / build | 通过 |
| server Dockerfile 构建 | 通过（多阶段，非 root，21MB 级） |
| web Dockerfile 构建 | 通过（Node 构建 + Caddy 托管） |
| docker-compose.stage2 一键启动 | postgres/valkey/api/web 全部 healthy |
| 容器内自动迁移 + 初始管理员创建 | 通过（一次性随机密码 stdout 打印） |
| 容器内登录闭环 | 通过（must_change_password=true） |
| docker-compose.stage2 一键停止 | 通过 |

## 10. 已知限制

1. 开发环境管理面使用 HTTP（生产必须 HTTPS + COOKIE_SECURE=true，已在配置中强制校验 prod 环境）；
2. 审计哈希链为基础防篡改（数据库 RULE 禁改删 + 哈希链），未含可信时间戳/外部存证；
3. 前端 antd 全量引入单 chunk 约 1.34MB，未做代码分割（后续阶段优化）；
4. 验证码为自主实现的字符 PNG（点阵字体+干扰线），强度满足基础需求，后续可增强；
5. E2E 期间临时调高登录限速（global setup/teardown 自动恢复默认值 10 次/分钟）。
