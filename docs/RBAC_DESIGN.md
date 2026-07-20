# RBAC 权限设计（阶段2）

## 模型

```text
用户 → 用户角色(user_roles) → 角色(roles) → 角色权限(role_permissions) → 权限(permissions)
```

一账号仅一个内置管理角色（三权互斥），内置角色权限不可通过界面修改。

## 三权角色

| 角色 | 职责 | 阶段2权限 | 禁止 |
|------|------|----------|------|
| SYSTEM_ADMIN 系统管理员 | 用户/角色/系统设置/网关维护/备份 | users.*, roles.read, permissions.read, system_settings.*, login_logs.read_limited, sessions.*, profile.*, dashboard.read_basic | 删除/修改审计日志、查看完整安全事件、修改安全策略 |
| SECURITY_ADMIN 安全管理员 | 应用/策略/规则/名单/事件/报表 | profile.*, sessions.read_self, sessions.revoke_self, dashboard.read_basic（阶段2仅基础工作台） | 管理三权账号、分配角色、查看全部审计、修改系统参数 |
| AUDIT_ADMIN 审计管理员 | 查看日志/审计/导出/审查 | audits.*, login_logs.*, users.read_summary, roles.read, permissions.read, profile.*, sessions.read_self, sessions.revoke_self, dashboard.read_basic | 创建/修改用户、重置密码、修改配置、删除审计 |

## 权限矩阵（阶段2 接口）

| 接口 | SYSTEM_ADMIN | SECURITY_ADMIN | AUDIT_ADMIN |
|------|:---:|:---:|:---:|
| GET /users | ✅ | ❌ | ❌ |
| POST /users | ✅ | ❌ | ❌ |
| PUT/DELETE /users/{id} | ✅ | ❌ | ❌ |
| POST /users/{id}/reset-password | ✅ | ❌ | ❌ |
| POST /users/{id}/unlock /disable /enable | ✅ | ❌ | ❌ |
| DELETE /users/{id}/sessions | ✅ | ❌ | ❌ |
| GET /roles /permissions | ✅ | ❌ | ✅ |
| GET /system-settings | ✅ | ❌ | ❌ |
| PUT /system-settings | ✅ | ❌ | ❌ |
| GET /login-logs | 摘要(limited) | 自己 | ✅ 全部 |
| GET /login-logs/export | ❌ | ❌ | ✅ |
| GET /audits /audits/export | ❌ | ❌ | ✅ |
| GET /profile /auth/sessions | ✅ | ✅ | ✅ |
| POST /auth/change-password | ✅ | ✅ | ✅ |

## 权限命名

统一 `资源.动作`：`users.read`、`users.create`、`audits.export`、`system_settings.update`。
禁止 `admin`/`manage_all`/`super` 等含糊命名。

## 后端校验

- 所有受保护接口经 `RequirePermission(perm)` 中间件强制校验
- 前端菜单/路由/按钮隐藏仅改善体验，不构成安全边界
- 权限从会话（登录时加载角色聚合权限）读取，角色变更后目标用户会话全部失效

## 角色互斥与保护规则

- 一账号仅一个内置管理角色（AssignRole 替换式）
- 禁止停用/删除最后一个可用系统管理员
- 禁止删除/停用当前登录账号
- 分配 SYSTEM_ADMIN 角色记录 CRITICAL 级审计
- 角色变更强制目标用户重新认证（全部会话失效）

## 前端控制

- 路由守卫：未登录跳 /login，must_change_password 跳改密页，无权限跳 403
- 菜单按角色权限过滤
- 按钮级 `hasPermission` 控制（如导出、新建）
- 后端 403 正确展示"无权执行该操作"
