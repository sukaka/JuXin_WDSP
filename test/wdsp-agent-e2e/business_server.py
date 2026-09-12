#!/usr/bin/env python3
# business_server.py —— WDSP Agent E2E 模拟业务 HTTP 服务（替换原 python -m http.server）。
# Phase 3 HTTP Sensor 验收端点（契约 docs/agents/WDSP_AGENT_PHASE3_CONTRACT.md §2-§6）：
#   GET  /            200 text/plain "wdsp-agent-e2e business ok"（沿用原首页断言）
#   GET  /index.html  200 同上（步骤 9/11e 流量）
#   POST /api/login   200 application/json（脱敏断言：请求 Authorization/JSON password）
#   GET  /big         200 text/plain，5050B（>limits.max_body_size=1024 触发响应截断断言）
#   POST /upload      200 application/json（请求体 application/octet-stream → content_type 跳过断言）
#   GET  /gz          200 application/json + Content-Encoding: gzip（解压采集断言）
#   GET  /api/payment 200 application/json（Phase 4 定向提升断言：uri_prefix override 命中）
# 仍为模拟业务：不持久化、不校验入参；HTTP/1.1 + 显式 Content-Length 支持 keep-alive，
# curl Connection: close 短连接照常触发双方 FIN（flow_end 路径不回归）。
import gzip
from http.server import BaseHTTPRequestHandler, HTTPServer

# 5050 字节（50 × 101B），保证超过验收策略 limits.max_body_size=1024 且非 JSON（text/* 白名单内）。
BIG_BODY = (("x" * 100) + "\n") * 50

GZ_PAYLOAD = b'{"ok":true,"msg":"gzip-json","n":42}'


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, body=b"", ctype="application/json", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, b"wdsp-agent-e2e business ok", "text/plain")
        elif self.path == "/big":
            self._send(200, BIG_BODY.encode(), "text/plain")
        elif self.path == "/gz":
            self._send(200, gzip.compress(GZ_PAYLOAD), "application/json",
                       {"Content-Encoding": "gzip"})
        elif self.path == "/api/payment":
            self._send(200, b'{"payment":true,"order":"ord_e2e"}')
        else:
            self._send(404, b'{"error":"not found"}')

    def do_POST(self):
        # 读尽请求体（模拟业务不关心内容；不读尽会导致连接复位影响流关闭语义）
        n = int(self.headers.get("Content-Length") or 0)
        if n > 0:
            remaining = n
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, 65536))
                if not chunk:
                    break
                remaining -= len(chunk)
        if self.path == "/api/login":
            self._send(200, b'{"token":"dummy-token"}')
        elif self.path == "/upload":
            self._send(200, b'{"uploaded":true}')
        else:
            self._send(404, b'{"error":"not found"}')

    def log_message(self, *args):  # 静默访问日志（e2e 日志已多）
        pass


if __name__ == "__main__":
    # 说明：历史 D-06 规避（TCP_MAXSEG=1400 + ethtool 关 TSO/GSO）已随 agent 侧修复
    # （64KB 帧缓冲，README D-06）撤除——/big 的 5050B 单写在 TSO/GSO 全开下会聚合成
    # 超 MTU 帧，恰好作为修复后超帧抓取能力的真实验收流量。
    HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
