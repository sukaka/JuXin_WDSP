# 接口设计文档

## 接口规范

### 统一前缀

```text
/api/v1
```

### 统一返回格式

```json
{
  "code": "SUCCESS",
  "message": "操作成功",
  "data": {},
  "request_id": "uuid"
}
```

### 分页格式

```json
{
  "items": [],
  "page": 1,
  "page_size": 20,
  "total": 0
}
```

### 错误码

HTTP 状态码与业务错误码必须同时正确使用。

| HTTP 状态码 | 业务错误码示例 | 说明 |
|------------|---------------|------|
| 200 | SUCCESS | 成功 |
| 400 | INVALID_PARAM | 参数错误 |
| 401 | UNAUTHORIZED | 未认证 |
| 403 | FORBIDDEN | 无权限 |
| 404 | NOT_FOUND | 资源不存在 |
| 409 | CONFLICT | 资源冲突 |
| 500 | INTERNAL_ERROR | 服务器内部错误 |

## 主要接口

### 认证

```text
POST   /api/v1/auth/login
POST   /api/v1/auth/logout
GET    /api/v1/auth/me
POST   /api/v1/auth/change-password
GET    /api/v1/auth/sessions
DELETE /api/v1/auth/sessions/{id}
```

### 用户与角色

```text
GET    /api/v1/users
POST   /api/v1/users
GET    /api/v1/users/{id}
PUT    /api/v1/users/{id}
DELETE /api/v1/users/{id}
POST   /api/v1/users/{id}/reset-password
GET    /api/v1/roles
GET    /api/v1/permissions
```

### 应用

```text
GET    /api/v1/applications
POST   /api/v1/applications
GET    /api/v1/applications/{id}
PUT    /api/v1/applications/{id}
DELETE /api/v1/applications/{id}
POST   /api/v1/applications/{id}/enable
POST   /api/v1/applications/{id}/disable
POST   /api/v1/applications/{id}/test-origin
GET    /api/v1/applications/{id}/status
GET    /api/v1/applications/{id}/events
```

### 源站

```text
GET    /api/v1/applications/{id}/upstreams
POST   /api/v1/applications/{id}/upstreams
PUT    /api/v1/upstreams/{id}
DELETE /api/v1/upstreams/{id}
POST   /api/v1/upstreams/{id}/health-check
```

### 证书

```text
GET    /api/v1/certificates
POST   /api/v1/certificates
GET    /api/v1/certificates/{id}
DELETE /api/v1/certificates/{id}
POST   /api/v1/certificates/validate
```

### 防护策略

```text
GET    /api/v1/protection-policies
POST   /api/v1/protection-policies
GET    /api/v1/protection-policies/{id}
PUT    /api/v1/protection-policies/{id}
DELETE /api/v1/protection-policies/{id}
```

### 规则和例外

```text
GET    /api/v1/waf-rules
GET    /api/v1/waf-rules/{rule_id}
PUT    /api/v1/waf-rules/{rule_id}/override
GET    /api/v1/custom-rules
POST   /api/v1/custom-rules
PUT    /api/v1/custom-rules/{id}
DELETE /api/v1/custom-rules/{id}
POST   /api/v1/custom-rules/{id}/test

GET    /api/v1/exceptions
POST   /api/v1/exceptions
PUT    /api/v1/exceptions/{id}
DELETE /api/v1/exceptions/{id}
```

### 黑白名单和CC

```text
GET    /api/v1/access-rules
POST   /api/v1/access-rules
PUT    /api/v1/access-rules/{id}
DELETE /api/v1/access-rules/{id}
POST   /api/v1/access-rules/import
GET    /api/v1/access-rules/export

GET    /api/v1/rate-limit-policies
POST   /api/v1/rate-limit-policies
PUT    /api/v1/rate-limit-policies/{id}
DELETE /api/v1/rate-limit-policies/{id}
```

### 安全事件

```text
GET    /api/v1/security-events
GET    /api/v1/security-events/{id}
PUT    /api/v1/security-events/{id}/disposition
POST   /api/v1/security-events/{id}/notes
POST   /api/v1/security-events/{id}/add-to-blacklist
POST   /api/v1/security-events/{id}/create-exception
GET    /api/v1/security-events/export
```

### 配置发布

```text
POST   /api/v1/gateway/config/preview
POST   /api/v1/gateway/config/validate
POST   /api/v1/gateway/config/publish
GET    /api/v1/gateway/config/versions
GET    /api/v1/gateway/config/versions/{id}
POST   /api/v1/gateway/config/versions/{id}/rollback
GET    /api/v1/gateway/publish-tasks/{id}
```

### 首页、审计和报表

```text
GET    /api/v1/dashboard/overview
GET    /api/v1/dashboard/trends
GET    /api/v1/dashboard/distributions
GET    /api/v1/audits
GET    /api/v1/audits/export
GET    /api/v1/reports
POST   /api/v1/reports
GET    /api/v1/reports/{id}
GET    /api/v1/reports/{id}/download
```

## 安全要求

1. 所有接口执行身份认证；
2. 所有写接口执行权限校验和 CSRF 校验；
3. 登录和高风险接口限速；
4. 接口错误不返回堆栈信息；
5. 生产环境关闭调试接口。

## OpenAPI 3

正式接口实现后，使用 OpenAPI 3 规范生成接口文档，存放于 `docs/openapi.yaml`。
