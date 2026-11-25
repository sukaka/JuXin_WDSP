# 聚信压测工具（JuXin Bench）— WDSP 与通用 WAF 压力测试套件

**聚信压测工具**同时支持 **九章 WDSP（v1.11.1）** 与 **任意有授权的反向代理型 WAF**，在指标口径、三段式稳态隔离、RFC 2544 自动二分无损搜索、NetSecOPEN EMIX 混合流量与带压安全评分卡上严格遵循 **IETF RFC 2544 / RFC 3511 / RFC 9411（NetSecOPEN）** 行业测试标准。

> **口径声明**：本工具基于自主研发的纯 Go 引擎（`l7bench` / `bench-origin` / `rpsload`）与开源压测生态（`k6` / `wrk2`）在 Linux 平台实现软件级高精度测试，所有报告均如实标注软件测试口径，未执行项严格标记 `NOT_RUN`。

## 目录结构

```text
test/performance/delivery-stress/
├── README.md                                 # 本操作手册
├── dist/                                     # 预编译静态 linux/amd64 (GOAMD64=v1) 二进制
│   ├── l7bench-linux-amd64                   # 聚信压测工具 L7 多源 IP 核心引擎（tps/cps/cc/emix + TCP/TLS/TTFB/TTLB）
│   ├── bench-origin-linux-amd64              # 高性能测试源站（EMIX 全尺寸常驻内存 + POST/上传完整消费体）
│   └── rpsload-linux-amd64                   # 逐请求 CSV 恒定 RPS 发生器
├── l7bench/                                  # l7bench 源码与单测（纯 Go 标准库）
├── origin/                                   # bench-origin 源码、单测与可选 Nginx 静态配置
├── k6/wdsp-suite.js                          # k6 六合一开环压测脚本（阶梯/带宽/CPS/混流/事件风暴/72h长稳）
├── corpus/owasp-security-corpus.json         # 自研非破坏性合规语料（OWASP Top 10 + 逃逸 + 易误报正常集）
├── scripts/
│   ├── setup-loadgen-centos7.sh              # CentOS 7 / 阿里云压测机初始化（k6/wrk/wrk2/iperf3/TCP 调优）
│   ├── setup-multi-ip.sh                     # 压测机万兆口多源 IP 池配置（突破单 IP 65535 端口墙）
│   ├── gen-test-certs.sh                     # 生成压测用 RSA-2048 与 ECDSA-P256 两套自签证书
│   ├── preflight-fingerprint.sh              # 被测机硬件/NUMA/网卡/磁盘 fio/WDSP 版本指纹采集
│   ├── l4-throughput.py                      # 4 层传输层（TCP/UDP 单向/双向）吞吐压测封装与 JSON 解析器
│   ├── binary-search.py                      # RFC 2544 自动二分无损容量搜索编排器
│   ├── security-under-load.py                # RFC 9411 带压安全效能评分卡（支持自定义 WAF 拦截码）
│   ├── collect-metrics.sh                    # 被测机实时采集（/jiuzhang/runtime + 宿主/网卡/双盘/事件积压）
│   ├── reconcile-events.py                   # WDSP 事件追平轮询 + PostgreSQL 唯一 request_id 零丢失对账
│   └── summarize-run.py                      # 聚合全部原始产物，一键导出 Markdown + 离线可视化 HTML + PDF + JSON 报告
├── templates/customer-delivery-report.md     # 双环境客户交付报告模板
└── tests/test_delivery_stress.py             # 全部 Python 与 Shell 单元测试
```

---

## 快速上手（聚信压测工具标准 6 步流程）

### 1. 解压并启动高性能测试源站
```bash
tar -xzf juxin-bench-linux-amd64.tar.gz -C /root/
cd /root/delivery-stress
ulimit -n 1048576
# 源站机启动（阿里云 8C16G 可加 taskset -c 0-1）
nohup ./dist/bench-origin-linux-amd64 -listen :18090 > /tmp/bench-origin.log 2>&1 &
```

### 2. 压测机配置多源 IP 池（测高 CPS / 10 万+ 并发连接必备）
```bash
# 在 CentOS 7 万兆口绑 32 个源 IP（≈ 160 万可用源端口），模拟多客户端子网
sudo bash scripts/setup-multi-ip.sh up --iface ens1f0 --prefix 10.10.1 --start 101 --count 32 --mask 24
```
> 测完清理：`sudo bash scripts/setup-multi-ip.sh down --iface ens1f0 --prefix 10.10.1 --start 101 --count 32 --mask 24`。

### 3. 生成 RSA-2048 & ECDSA-P256 压测证书（兆芯 KH-40000 必测对比）
```bash
bash scripts/gen-test-certs.sh --out-dir /tmp/wdsp-test-certs --domain bench.wdsp.local
# 分别上传到 WDSP 站点，对比 RSA-2048 与 ECDSA-P256 的 HTTPS CPS
```

### 4. 跑 4 层传输层吞吐 + 7 层应用层核心指标（严格三段式，仅统计 Steady State）
```bash
mkdir -p ./juxin-out
LIPS="10.10.1.101-10.10.1.132"   # 阿里云单 IP 时去掉 --local-ips 参数

# (0) 4 层传输层吞吐（先在目标/源站机启动 iperf3 -s -D，再执行单向/双向 TCP 与 UDP 压测）
python3 scripts/l4-throughput.py --target 10.10.1.20 --proto tcp --direction forward --mode routed_forward --streams 16 --duration 30 --omit 5 --out-json ./juxin-out/l4-tcp-fwd.json
python3 scripts/l4-throughput.py --target 10.10.1.20 --proto tcp --direction bidir   --mode routed_forward --streams 16 --duration 30 --omit 5 --out-json ./juxin-out/l4-tcp-bidir.json
python3 scripts/l4-throughput.py --target 10.10.1.20 --proto udp --direction forward --mode routed_forward --streams 8 --udp-bitrate 10G --packet-len 1400 --duration 30 --omit 5 --out-json ./juxin-out/l4-udp-fwd.json

# (0b) 7 层 HTTP / HTTPS 大包过检吞吐（256KB 文件下载，全防护）
./dist/l7bench-linux-amd64 -mode tps -url http://10.10.1.10  -host bench.wdsp.local -path /static/256k.bin -local-ips "$LIPS" -rate 3500 -ramp-up 15s -steady 120s -ramp-down 5s -out-json ./juxin-out/l7-http-256k.json
./dist/l7bench-linux-amd64 -mode tps -url https://10.10.1.10 -host bench.wdsp.local -path /static/256k.bin -local-ips "$LIPS" -tls-version 1.3 -rate 3000 -ramp-up 15s -steady 120s -ramp-down 5s -out-json ./juxin-out/l7-https-256k.json

# (A) HTTP/HTTPS 恒定事务 TPS（RFC 2544 自动二分搜最大无损点 + 180s 长稳态确认）
python3 scripts/binary-search.py \
  --l7bench ./dist/l7bench-linux-amd64 --mode tps \
  --url https://10.10.1.10 --host bench.wdsp.local --path /static/256b.txt \
  --local-ips "$LIPS" --tls-version 1.3 \
  --min 500 --max 20000 --max-err-pct 0.0 --max-p99-ms 50 \
  --ramp-up 15s --steady 45s --ramp-down 5s --confirm-steady 180s \
  --out-dir ./juxin-out/bs-tps-https

# (B) NetSecOPEN EMIX 多尺寸混合吞吐（1K/4K/16K/64K/256K/1M 权重，冲多 Gbps）
python3 scripts/binary-search.py \
  --l7bench ./dist/l7bench-linux-amd64 --mode emix --emix-preset netsecopen \
  --url https://10.10.1.10 --host bench.wdsp.local \
  --local-ips "$LIPS" --tls-version 1.3 \
  --min 500 --max 25000 --max-err-pct 0.0 --max-p99-ms 100 \
  --ramp-up 15s --steady 45s --ramp-down 5s --confirm-steady 180s \
  --out-dir ./juxin-out/bs-emix-https

# (C) HTTPS 新建连接速率 CPS（Full Handshake，1 req/conn，锁定 TLS 1.2 套件或 TLS 1.3）
python3 scripts/binary-search.py \
  --l7bench ./dist/l7bench-linux-amd64 --mode cps \
  --url https://10.10.1.10 --host bench.wdsp.local --path /static/1b.txt \
  --local-ips "$LIPS" --tls-version 1.2 --tls-cipher TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 \
  --min 200 --max 10000 --max-err-pct 0.0 --max-p99-ms 100 \
  --ramp-up 15s --steady 45s --ramp-down 5s --confirm-steady 180s \
  --out-dir ./juxin-out/bs-cps-tls12-rsa

# (D) 海量并发长连接保持上限 CC（示例：爬坡建立 20,000 条持久化 HTTPS 连接并稳态保持 180s）
./dist/l7bench-linux-amd64 -mode cc \
  -url https://10.10.1.10 -host bench.wdsp.local -path /static/256b.txt \
  -local-ips "$LIPS" -conns 20000 -cc-interval 10s \
  -ramp-up 60s -steady 180s -ramp-down 20s \
  -out-json ./juxin-out/cc-20k.json
```

### 5. 带压安全效能评分卡（Security under Load，75% 背景满载 + OWASP/逃逸/易误报回放）
```bash
# 通用支持 WDSP 与其他 WAF（测其他 WAF 可按需调整 --block-statuses 或加 --treat-reset-as-block）
python3 scripts/security-under-load.py \
  --url https://10.10.1.10 --host bench.wdsp.local \
  --rounds 3 --block-statuses 401,403,406,444 \
  --bg-l7bench ./dist/l7bench-linux-amd64 --bg-mode emix --bg-rate 3000 \
  --bg-steady 60s --bg-ramp-up 10s --bg-local-ips "$LIPS" \
  --out-json ./juxin-out/security-scorecard.json
```

### 6. 事件零丢失对账、72h 长稳与一键导出 Markdown / HTML / JSON 报告
- **事件风暴与追平对账**：用 `k6/wdsp-suite.js`（`SCENARIO=event_storm`）+ `scripts/reconcile-events.py --wait-drain`；
- **24h / 72h 长稳**：用 `k6/wdsp-suite.js`（`SCENARIO=soak`）+ `scripts/collect-metrics.sh --interval 30`；
- **一键汇总导出交付报告**（同时生成 Markdown + 带离线 SVG 图表的 HTML 可视化报告 + 结构化 JSON）：
```bash
python3 scripts/summarize-run.py \
  --env-name "KY5288G1 (2xKH-40000 32C / openEuler 24.03 SP3 / 裸机网关)" \
  --fingerprint ./stress-out/fp/fingerprint.json \
  --l4-json "4层-TCP单向转发=./juxin-out/l4-tcp-fwd.json" \
  --l4-json "4层-TCP双向全双工=./juxin-out/l4-tcp-bidir.json" \
  --l4-json "4层-UDP大包转发=./juxin-out/l4-udp-fwd.json" \
  --l7bench-json "7层-HTTP大包吞吐=./juxin-out/l7-http-256k.json" \
  --l7bench-json "7层-HTTPS大包吞吐=./juxin-out/l7-https-256k.json" \
  --l7bench-json "HTTPS_TPS_Confirm=./juxin-out/bs-tps-https/trial-confirm-xxxx.json" \
  --l7bench-json "HTTPS_EMIX_Confirm=./juxin-out/bs-emix-https/trial-confirm-xxxx.json" \
  --l7bench-json "TLS12_RSA_CPS=./juxin-out/bs-cps-tls12-rsa/trial-confirm-xxxx.json" \
  --l7bench-json "HTTPS_CC_20k=./juxin-out/cc-20k.json" \
  --binary-search-json "TPS_HTTPS=./juxin-out/bs-tps-https/binary-search-result.json" \
  --binary-search-json "EMIX_HTTPS=./juxin-out/bs-emix-https/binary-search-result.json" \
  --binary-search-json "CPS_TLS12_RSA=./juxin-out/bs-cps-tls12-rsa/binary-search-result.json" \
  --security-scorecard-json ./juxin-out/security-scorecard.json \
  --metrics ./stress-out/metrics/runtime-metrics.csv \
  --reconcile ./stress-out/reconcile.json \
  --out-md ./juxin-out/ky5288-report.md \
  --out-html ./juxin-out/ky5288-report.html \
  --out-pdf ./juxin-out/ky5288-report.pdf \
  --out-json ./juxin-out/ky5288-summary.json
```

## 源码重新交叉编译（锁定 GOAMD64=v1 兼容兆芯 KH-40000）
```bash
(cd test/performance/delivery-stress/l7bench && GOOS=linux GOARCH=amd64 GOAMD64=v1 CGO_ENABLED=0 go build -ldflags="-s -w" -o ../dist/l7bench-linux-amd64 .)
(cd test/performance/delivery-stress/origin  && GOOS=linux GOARCH=amd64 GOAMD64=v1 CGO_ENABLED=0 go build -ldflags="-s -w" -o ../dist/bench-origin-linux-amd64 .)
(cd test/performance/rpsload                 && GOOS=linux GOARCH=amd64 GOAMD64=v1 CGO_ENABLED=0 go build -ldflags="-s -w" -o ../delivery-stress/dist/rpsload-linux-amd64 .)
```
