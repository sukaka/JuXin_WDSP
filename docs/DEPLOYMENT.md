# 部署文档

## 环境要求

- Docker 24+
- Docker Compose v2+
- Linux（推荐 Ubuntu 22.04+ / CentOS 8+）
- 4 核 CPU、8GB 内存、本地 SSD（最低要求）

## 部署方式

V2.0 使用 Docker Compose 部署，不使用 Kubernetes。

## 快速部署

### 1. 准备环境变量

```bash
cp .env.example .env
# 编辑 .env，修改数据库密码、Valkey 密码、会话密钥等
```

### 2. 启动基础服务

```bash
docker compose up -d postgres valkey
```

### 3. 初始化数据库

```bash
# 待阶段2完成后提供迁移命令
```

### 4. 启动管理服务

```bash
# 待阶段2完成后提供启动命令
```

### 5. 启动防护网关

```bash
# 待阶段1完成后提供启动命令
```

## 端口规划

| 服务 | 端口 | 说明 |
|------|------|------|
| 管理后端 | 8080 | 管理 API |
| 管理前端 | 5173 | 开发环境，生产环境由 Nginx/Caddy 托管 |
| PostgreSQL | 5432 | 仅绑定 127.0.0.1 |
| Valkey | 6379 | 仅绑定 127.0.0.1 |
| Caddy Admin | Unix Socket | /var/run/caddy/admin.sock |
| 业务代理 | 80/443 | 按需配置 |

## 数据目录

```text
runtime/
├── configs/       # 配置文件
├── certificates/  # 证书文件
├── logs/          # 日志文件
├── reports/       # 报表文件
└── backups/       # 备份文件
```

## 安全要求

1. PostgreSQL 和 Valkey 仅绑定 127.0.0.1；
2. Caddy Admin API 仅通过 Unix Socket 访问；
3. 管理端默认只监听内网；
4. 生产环境必须使用 HTTPS；
5. 定期备份 `runtime/` 目录和数据库。

## 备份与恢复

待阶段7补充详细备份恢复流程。

## 升级

待阶段7补充升级流程。
