# 九章 WDSP 裸机安装包（linux/amd64）

九章 WEB 应用智能防护系统 V2.0（WDSP 产品线）的免 Docker 裸机交付包。
面向 openEuler x86_64（含兆芯 KX/KH、海光 C86 等 x86-64 兼容信创平台）等
不便或不允许运行 Docker 的生产环境：全部组件（PostgreSQL 16、Valkey 8、
Caddy 网关/控制台、管理后端 API、netmgrd、logrotator）随包携带，
由 systemd 托管，单一运行账户 `jiuzhang`（netmgrd 例外，以 root 运行）。

- 默认安装根：`/opt/jiuzhang-wdsp`（下文记作 `$R`，可用 `INSTALL_ROOT` 覆盖）
- 包内布局 = 安装后布局；目标机仅需 glibc 系统环境 + systemd + curl/openssl/iproute2

## 目录结构

```
bin/                   caddy / jiuzhang-api / netmgrd / logrotator.sh / pg/ / valkey/
web/                   管理前端 SPA（web/dist 构建产物）
console/               控制台 Caddyfile 模板（双栈 / 仅 HTTP）
gateway/               Caddyfile.bootstrap.template、blockpage.html、rules/（CRS 等规则）
migrations/            数据库迁移（api 启动时自动执行）
assets/fonts/          报表字体（NotoSansCJKsc）
geoip/                 GeoIP 离线库（ip2region_v4.xdb、city-ipv6.mmdb、country.mmdb，支持放官方 DB-IP Lite .mmdb）
env.template           运行环境模板（install.sh 渲染为 $R/env）
ops/                   console-cert.sh / fingerprint.sh / backup.sh / restore.sh / lib/common.sh
systemd/               7 个单元模板（install.sh 渲染安装）
tmpfiles.d/jiuzhang.conf   Coraza 持久化目录声明（/tmp/coraza）
install.sh uninstall.sh backup.sh restore.sh README.md
```

安装后运行时数据（均不在包内，由 install.sh 创建）：

```
$R/env                        运行环境（0640 root:jiuzhang，含随机口令）
$R/certificates/              控制台自签证书（console.crt/key，100 年）
$R/data/pgdata                PostgreSQL 数据目录（0700）
$R/data/valkey/               Valkey 数据与 valkey.conf
$R/data/caddy/                网关 XDG config/data（autosave.json 在此）
$R/data/caddy-console/        控制台 Caddy XDG 目录（与网关隔离）
$R/data/runtime/              api 数据（geoip/ license/ certificates/ configs/ backups/ hostctl/ …）
$R/data/logs/caddy/           全部网关日志（caddy/access/coraza-audit/guard-events/api-runtime-events/…）
$R/data/run/caddy/            admin.sock 与 sidecars/（network.json ↔ netmgrd）
$R/backups/                   backup.sh 产物
```

## 构建产包（仓库内，macOS）

```bash
ops/baremetal/build-runtimes.sh   # 产出 bin/pg、bin/valkey（仅需在有更新时执行）
ops/baremetal/build-binaries.sh   # 产出 bin/caddy、jiuzhang-api、netmgrd、logrotator.sh
ops/baremetal/assemble.sh         # 构建前端并组装 dist/jiuzhang-wdsp-baremetal-linux-amd64/
                                  # + tar.gz + .sha256（不删 bin/，可重复执行）
```

交付物：`dist/jiuzhang-wdsp-baremetal-linux-amd64.tar.gz` 与同名 `.sha256` 旁车。

## 安装

```bash
tar -xzf jiuzhang-wdsp-baremetal-linux-amd64.tar.gz
cd jiuzhang-wdsp-baremetal-linux-amd64
# 建议先校验：sha256sum -c ../jiuzhang-wdsp-baremetal-linux-amd64.tar.gz.sha256
sudo bash install.sh
```

- `sudo INSTALL_ROOT=/data/wdsp bash install.sh`：自定义安装根
- `sudo JZ_SKIP_SYSTEMD=1 bash install.sh`：只部署文件/数据/单元，不启动服务
  （结束时打印手工启动指引；用于彩排、容器化封装或手工编排场景）
- install.sh 幂等：重装保留 `env`、pgdata、valkey.conf、控制台证书，仅补缺失配置键

安装流程要点：预检（x86_64/命令/端口 8080·8443·18081·5432·6379·80·443）→
创建 `jiuzhang` 账户 → 部署文件 → 生成随机口令写入 `$R/env` → initdb +
createdb（jiuzhang_waf）→ 渲染 valkey.conf → 生成控制台自签证书 →
写宿主机指纹与 GeoIP → 渲染 Caddy 配置 → 建宿主兼容符号链接 →
安装 7 个 systemd 单元 → 按序启动 → 健康等待（各 60s 上限）→ firewalld 放行。

安装完成后：

- 控制台：`http://<主机IP>:8080/`（证书齐备时另有 `https://<主机IP>:8443/`，自签告警属预期）
- 初始账号 `jiuzhang_admin`，初始口令在 `$R/env` 的 `INITIAL_ADMIN_PASSWORD` 行
  （首次登录强制改密；改密后删除该行并 `systemctl restart jiuzhang-api`）
- 下一步：控制台「系统管理 → 授权管理」导入授权文件

## 从 docker 部署迁移

同一台宿主机从 docker 栈迁移（宿主机指纹不变，授权继续有效）：

```bash
# 1. 旧栈在线导出数据库（pg_dump 一致性快照即可；容器名以实际为准，
#    stage5/wdsp 基座为 jiuzhang-stage5-postgres）
docker exec jiuzhang-stage5-postgres pg_dump -U jiuzhang jiuzhang_waf | gzip > jiuzhang-waf.dump.gz

# 2. 停 docker 栈（释放 80/443/8080 等端口）
docker compose -f deployment/docker-compose.stage5.yml -f deployment/docker-compose.wdsp.yml down

# 3. 安装裸机版（见上节），装完后先停 api
sudo bash install.sh
sudo systemctl stop jiuzhang-api

# 4. 灌库（口令取自 $R/env；先 drop/create）
source <(sudo grep -E '^POSTGRES_PASSWORD=' /opt/jiuzhang-wdsp/env)
export LD_LIBRARY_PATH=/opt/jiuzhang-wdsp/bin/pg/syslib:/opt/jiuzhang-wdsp/bin/pg/lib/postgresql/16/lib
PG_BIN=/opt/jiuzhang-wdsp/bin/pg/lib/postgresql/16/bin
sudo -E PGPASSWORD="$POSTGRES_PASSWORD" $PG_BIN/dropdb -h 127.0.0.1 -U jiuzhang --if-exists jiuzhang_waf
sudo -E PGPASSWORD="$POSTGRES_PASSWORD" $PG_BIN/createdb -h 127.0.0.1 -U jiuzhang jiuzhang_waf
gunzip -c jiuzhang-waf.dump.gz | sudo -E PGPASSWORD="$POSTGRES_PASSWORD" \
  $PG_BIN/psql -h 127.0.0.1 -U jiuzhang -d jiuzhang_waf -v ON_ERROR_STOP=1

# 5. 拷贝授权与站点资产（docker 卷 stage5_runtime 或绑定目录下的 runtime/）
sudo cp -a <旧runtime>/license/.  /opt/jiuzhang-wdsp/data/runtime/license/
sudo cp -a <旧runtime>/certificates/. /opt/jiuzhang-wdsp/data/runtime/certificates/   # 如有站点证书
sudo cp -a <旧runtime>/geoip/.    /opt/jiuzhang-wdsp/data/runtime/geoip/               # 可选，包内已带 country.mmdb
sudo chown -R jiuzhang:jiuzhang /opt/jiuzhang-wdsp/data/runtime

# 6. 起服务并验证授权仍有效（系统管理 → 授权管理；同宿主机指纹不变）
sudo systemctl start jiuzhang-api
```

站点发布配置、策略、事件均在数据库内，随 dump 迁移；网关配置由 api 启动后
重新经 Admin API 发布，无需拷贝 caddy autosave。

## 日常运维

```bash
systemctl status jiuzhang-postgres jiuzhang-valkey jiuzhang-gateway \
  jiuzhang-api jiuzhang-web jiuzhang-netmgrd jiuzhang-logrotator
journalctl -u jiuzhang-api --since '1 hour ago'        # 单服务日志
journalctl -u 'jiuzhang-*' -f                          # 全部组件日志
```

- 备份：`sudo bash $R/ops/backup.sh`（产物 `$R/backups/*.tar.gz`，0600）。
  建议 crontab 每日执行并异地留存：
  ```
  # crontab -e（root）
  17 3 * * * /opt/jiuzhang-wdsp/ops/backup.sh >> /var/log/jiuzhang-backup.log 2>&1
  ```
- 恢复：`sudo bash $R/ops/restore.sh --from <备份.tar.gz>`
  （恢复前自动先做一次兜底备份；env 默认不覆盖，`--force-env` 才覆盖）
- 升级：用新包重跑 `install.sh`（env/pgdata/证书保留），然后
  `systemctl restart jiuzhang-gateway jiuzhang-api jiuzhang-web`
- 修改控制台端口：改 `$R/env` 的 `WEB_PORT`/`WEB_HTTPS_PORT` 后重跑 `install.sh`
  （仅重渲染 Caddyfile，不影响数据）

## 安全说明

- 单一运行账户 `jiuzhang`（system user，nologin）；netmgrd 例外以 root 运行
  （需 NET_ADMIN 改网口/写 `/etc/resolv.conf`、timesyncd/chronyd 配置）
- 口令与密钥：仅落 `$R/env`（0640 root:jiuzhang）与 `$R/data/valkey/valkey.conf`
  （0640 jiuzhang）；备份归档整体 0600 且 MANIFEST 标注含密
- 网关 Admin API 仅 Unix Socket（`$R/data/run/caddy/admin.sock`，UMask 0077），
  不暴露 TCP；管理 API 仅监听 127.0.0.1:18081，由控制台反代 `/api`
- PostgreSQL/Valkey 仅监听 127.0.0.1；firewalld 运行中仅放行 8080/8443/80/443
- systemd 加固：网关/控制台 `CAP_NET_BIND_SERVICE` + `NoNewPrivileges` +
  `ProtectSystem=strict` + `ReadWritePaths=$R/data`（网关另放行 /tmp/coraza）
- 宿主兼容符号链接（发布配置硬编码路径 → 安装根；卸载时仅移除仍指向安装根的）：
  ```
  /etc/caddy/rules              -> $R/gateway/rules
  /etc/caddy/certs              -> $R/data/runtime/certificates
  /srv/jiuzhang/blockpage.html  -> $R/gateway/blockpage.html
  /var/log/caddy                -> $R/data/logs/caddy
  ```
- 切勿对网关 Caddy 去掉 `--resume` 启动（会清空站点发布配置）；
  切勿把 console/Caddyfile 交给网关单元使用（二者 XDG 目录与 autosave 完全隔离）

## 卸载

```bash
sudo bash $R/uninstall.sh            # 停服务、删单元/符号链接，数据保留在 $R
sudo bash $R/uninstall.sh --purge    # 追加删除 $R 与 jiuzhang 账户（含全部数据）
```
