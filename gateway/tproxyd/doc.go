// Package tproxyd 九章透明串接（透明代理）部署模式前置牵引进程（PoC，阶段D 技术验证）。
//
// 设计依据：docs/NETWORK_MODES_DESIGN.md §4.3。
//
// 数据通路：二层桥 br0 串接两口 → bridge-nf-call-iptables=1 使桥接流量过
// iptables → nat/PREROUTING REDIRECT 把桥上目标 TCP 流量牵引到本进程 →
// SO_ORIGINAL_DST 读取 conntrack 记录的原始目的地址（五元组透明性的关键）→
// 向 loopback 上的 Caddy（listener 挂 proxy_protocol wrapper）前置一行
// PROXY protocol v1（真实源 IP/端口 + 原始目的）→ 双向字节透传。
// Caddy 完成 coraza_waf 检测与 reverse_proxy 回源，事件/访问日志中的客户端
// 地址即真实源地址，而非牵引进程地址。
//
// 职责边界：本进程只做「牵引 + 五元组上报 + SNI 分流 + 字节透传」，不做安全
// 检测；串接在数据通路上，进程死亡由看门狗清除 REDIRECT 规则恢复桥接直通
// （fail-open，见 deployment/docker/tproxy-lab/entrypoint.sh）。
//
// HTTPS 多虚拟主机 SNI 分流（ProtectHosts 非空时启用，sni.go）：嗅探 TLS
// ClientHello 的 SNI（仅 Peek 不消费字节），清单内域名的连接送 TargetTLS
// （Caddy TLS 监听器）终结检测；清单外域名按 SO_ORIGINAL_DST 原始目的直接
// TCP 透传回源站——TLS 端到端不断开，WAF 无需部署这些域名的证书。解析失败
// （截断/畸形/无 SNI/ECH）一律倒向 TargetTLS 检测路径，嗅探读超时关连接，
// 杜绝借畸形 ClientHello 绕过防护。域名精确匹配（小写归一、容忍末尾点），
// 不支持通配符。
//
// 配置模式（产品化）：发布链路下发文件（/var/run/caddy/sidecars/tproxyd.json）
// 存在即文件优先，轮询 15s 在线启停/热切换；无文件时环境变量兜底（PoC/lab 路径）。
// 详见 fileconfig.go 与 supervisor.go。
//
// 已知边界（PoC 范围）：仅 IPv4（PROXY v1 TCP4）；REDIRECT 方案回源连接由
// Caddy 发起，源站看到的对端是 WAF 地址（与反代语义一致）；内核 TPROXY 目标
// 实测可用，双向全透明（源地址保持到源站）留作后续增强。
package tproxyd
