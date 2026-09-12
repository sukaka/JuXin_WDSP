// Package mirrorcap 九章镜像（旁路）部署模式旁路采集器（PoC，阶段C 技术验证）。
//
// 设计依据：docs/NETWORK_MODES_DESIGN.md §4.2。
//
// 数据通路：交换机 SPAN/镜像口 → 本机 AF_PACKET 纯 syscall 抓包（gopacket/pcapgo
// EthernetHandle，无 libpcap、无 cgo，CGO_ENABLED=0 可静态编译）→ TCP 四元组流重组
// （tcpassembly/tcpreader）→ 逐条 http.ReadRequest 还原明文 HTTP/1.x 请求 →
// Coraza(DetectionOnly) + dynamic_security 统一检测管线 → 事件以 api-runtime-events
// JSONL 契约（jiuzhang_guard/apievents.Record）落盘，由服务端既有采集器入库。
//
// 旁路铁律：本组件只读分析，绝不回注报文、绝不阻断；管线决策结果一律封顶 OBSERVE。
//
// 配置模式（产品化）：发布链路下发文件（/var/run/caddy/sidecars/mirrorcap.json）
// 存在即文件优先，轮询 15s 在线启停/热更新；无文件时环境变量兜底（PoC/lab 路径）。
// 详见 fileconfig.go 与 supervisor.go。
//
// 站点资产被动发现（可选，discovery 配置块，与检测独立启停）：发现接口抓全端口
// TCP 过境流量做首包协议嗅探——HTTP 取 Host、TLS ClientHello 取 SNI（纯标准库手写
// 解析，见 sni.go），连同四元组目的端（真实服务器 IP:Port）聚合成 site_discovery
// 记录周期写入 JSONL（见 discovery.go），供服务端采集入库；同一接口双角色时与检测
// 共用一个抓包句柄（流工厂按目的端口分流，见 stream.go/supervisor.go）。
//
// 已知边界（PoC 范围）：仅 HTTP/1.x 请求侧明文流量；不重组/分析响应；HTTPS 镜像
// 无法解密（无密钥，旁路模式下也无终止能力）；抓包丢包不熔断、不回传背压。
package mirrorcap
