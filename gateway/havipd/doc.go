// Package havipd 九章主备高可用宿主机侧 VIP 执行组件（页面配置主备组与 VIP 漂移）。
//
// 设计依据：docs/HA_ACTIVE_STANDBY_DESIGN.md §8（D-1：封装 keepalived，不自研 VRRP）。
//
// 职责边界：本组件是发布链路的「VIP 执行末端」——读取共享卷中的期望主备配置
// ha-vip.json（默认 /var/run/caddy/sidecars/ha-vip.json，由发布链路写入），
// 生成 keepalived 配置并管理其生命周期（启动/重载/停止），周期采集 VRRP 状态
// （MASTER/BACKUP/FAULT/DISABLED/STOPPED）与漂移事件，回写 ha-vip-status.json
// （同目录）供发布链路/管理面消费。本组件不碰网桥/路由（netmgrd 职责）、不碰
// 数据面进程（Caddy/tproxyd 由各自组件管理）。
//
// 下发契约（与发布端对齐，勿单方面变更）：
//
//	输入  ha-vip.json:
//	  {"group":"ha-main","state":"ENABLED",
//	   "members":[{"node":"gw-a","priority":120},{"node":"gw-b","priority":100}],
//	   "vrrp":{"vrid":51,"vips":["192.168.31.100/24"],"iface":"eth0",
//	     "preempt":false,"advert_int_ms":1000,"auth_pass":"…",
//	     "unicast_peers":["192.168.31.61"]},
//	   "updated_at":"..."}
//	输出  ha-vip-status.json:
//	  {"group":"ha-main","node":"gw-a","state":"MASTER|BACKUP|FAULT|DISABLED|STOPPED",
//	   "keepalived_running":true,"vips_present":["192.168.31.100/24"],"priority":120,
//	   "last_transition_at":"...","applied_at":"...","message":"...",
//	   "events":[{"at":"...","from":"BACKUP","to":"MASTER","detail":"..."}]}
//
// 状态判定（M2 语义，如实记录）：keepalived 进程存活 + 本机持有 VIP = MASTER；
// 存活 + 未持有 = BACKUP；配置启用但进程不存活 = FAULT；配置 DISABLED = DISABLED；
// 无有效配置 = STOPPED。漂移事件按状态迁移记录（封顶 100 条，滚动丢弃最旧）。
//
// 执行语义与安全约束（网络/VIP 属高危操作，以下约束不得放宽）：
//
//   - 全部外部动作经 exec 参数数组执行（不经 shell），单动作 5s 超时；零新增
//     第三方 Go 依赖（keepalived 为系统包，非 Go 依赖）；
//   - keepalived 配置/契约含 VRRP 认证串：文件一律 0600，内容禁入日志；
//   - 幂等：配置指纹不变不重载 keepalived；信号只发给本组件 pidfile 记录的
//     进程（绝不信号其他 keepalived 实例）；
//   - 失败不 crash-loop：keepalived 缺失/启动失败/配置解析失败保留进程驻留，
//     status 显式报错，按轮询周期重试；
//   - 进程退出（SIGTERM）：先停本组件管理的 keepalived（VIP 随之释放），自身
//     不残留子进程。
package havipd
