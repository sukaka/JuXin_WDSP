// Package netmgrd 九章多模式部署宿主机侧网络执行组件（页面配置网桥与路由牵引）。
//
// 设计依据：docs/NETWORK_MODES_DESIGN.md（透明串接二层桥、路由牵引三层转发）。
//
// 职责边界：本组件是发布链路的「网络执行末端」——读取共享卷中的期望网络配置
// network.json（默认 /var/run/caddy/sidecars/network.json，由发布链路写入），
// 在 Linux 主机上幂等执行网桥/转发/静态路由，并把执行状态回写
// network-status.json（同目录）供发布链路/运维消费。本组件不做检测、不碰
// 数据面进程（Caddy/tproxyd 等由各自组件管理）。
//
// 下发契约（与发布端对齐，勿单方面变更）：
//
//	输入  network.json:
//	  {"bridges":[{"name":"br0","ports":["eth2","eth3"],
//	     "link_pair":{"enabled":true,"hold_down_ms":1000,"hold_up_ms":5000,
//	       "max_flaps_per_hour":20}}],
//	   "ip_forward":true,
//	   "routes":[{"dst":"10.9.0.0/24","via":"192.168.50.1"}],
//	   "updated_at":"..."}
//	输出  network-status.json:
//	  {"applied_at":"...","ok":bool,
//	   "bridges":[{"name":"br0","state":"ok|error","message":"..."}],
//	   "ip_forward":"ok|error|skipped",
//	   "routes":[{"dst":"...","via":"...","state":"ok|error","message":"..."}],
//	   "link_pairs":[{"bridge":"br0","state":"BOTH_UP|PROPAGATED_DOWN|SUPPRESSED",
//	     "down_port":"eth2","propagated_port":"eth3",
//	     "propagated_by_linkpair":true,"flap_count_hour":3,
//	     "last_event_at":"...","message":"..."}],
//	   "message":"..."}
//
// 执行语义与安全约束（网络配置属高危操作，以下约束不得放宽）：
//
//   - 全部动作经 `ip`/`sysctl` 命令执行（exec 参数数组，不经 shell），每个动作
//     5s 超时；零新增依赖（不引入 netlink 库）；
//   - 幂等：重复执行同一配置无副作用（存在即跳过、replace 覆盖同名路由）；
//   - 网桥：不存在则创建；成员口 reconcile（补缺失、对多余成员 nomaster）；
//     最后 set up；
//   - 安全红线：成员口若已配 IP 地址（`ip -j addr show` 存在 inet 地址或非
//     link  scope inet6 地址）则拒绝收入桥（防误把管理口/业务口拉进桥）——
//     该桥整桥记 error 且本轮不做任何变更；
//   - ip_forward：true → sysctl 置 1；false → skipped（不主动关闭，见
//     apply.go 注释）；
//   - 路由：只增不删（最小实现）——`ip route replace` 覆盖同名路由，期望外
//     路由不清理，status 注明由运维处理；
//   - 每项独立成败记入 status，单项失败不影响其他项执行；
//   - 失败不 crash-loop：配置解析失败保留 last-good 配置并在 status 显式报错；
//     执行失败保留进程驻留，按轮询周期重试。
//
// 已知边界（最小实现）：仅 IPv4；桥已存在但非 bridge 类型时报错不接管；
// 成员口从其他桥直接改挂（kernel re-master）不额外拦截（口上无 IP 才会走到
// 该路径）。
package netmgrd
