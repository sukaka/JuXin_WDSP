#!/usr/bin/env python3
"""九章阶段1 协议异常测试

覆盖 run-waf-tests.sh 中无法用 curl 表达的协议级用例：
- 非法 Content-Length（请求走私特征）
- 超大请求头
- 非法 HTTP 方法
- 请求体与 Content-Type 不匹配
- 重复异常请求头

仅对本地 POC 网关执行，不破坏测试环境。
"""
import http.client
import json
import os
import socket
import sys

GATEWAY_HOST = os.environ.get("GATEWAY_HOST", "127.0.0.1")
GATEWAY_PORT = int(os.environ.get("GATEWAY_PORT", "18080"))
EXPECT_MODE = os.environ.get("EXPECT_MODE", "on")  # on / detection

results = []


def record(name, passed, detail=""):
    results.append((name, passed, detail))
    print(f"{'PASS' if passed else 'FAIL'}  {name} ({detail})")


def raw_request(payload: bytes, timeout=10):
    """发送原始 TCP 请求并返回响应头部分。"""
    s = socket.create_connection((GATEWAY_HOST, GATEWAY_PORT), timeout=timeout)
    try:
        s.sendall(payload)
        chunks = []
        while True:
            data = s.recv(65536)
            if not data:
                break
            chunks.append(data)
            if b"\r\n\r\n" in b"".join(chunks):
                # 头部已完整，尝试再读一点 body 后结束
                try:
                    s.settimeout(1.0)
                    more = s.recv(65536)
                    chunks.append(more)
                except socket.timeout:
                    pass
                break
        return b"".join(chunks)
    finally:
        s.close()


def status_of(raw: bytes) -> int:
    try:
        line = raw.split(b"\r\n", 1)[0].decode("latin-1")
        return int(line.split()[1])
    except Exception:
        return 0


def expected_attack_status():
    return 403 if EXPECT_MODE == "on" else 200


def http_request(method, path, body=None, headers=None, expect_status=None, name=None):
    conn = http.client.HTTPConnection(GATEWAY_HOST, GATEWAY_PORT, timeout=10)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        resp.read()
        want = expect_status if expect_status is not None else expected_attack_status()
        record(name, resp.status == want, f"status={resp.status} want={want}")
    except Exception as e:
        record(name, False, f"exception: {e}")
    finally:
        conn.close()


def test_conflicting_content_length():
    """走私特征：两个冲突的 Content-Length。Go HTTP 服务器会拒绝(400)，
    网关层或 Go 任一层拒绝均可接受，但绝不允许以 200 通过到源站。"""
    payload = (
        b"POST /echo HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Content-Length: 5\r\n"
        b"Content-Length: 10\r\n"
        b"\r\n"
        b"hello"
    )
    try:
        raw = raw_request(payload)
        st = status_of(raw)
        record("proto-conflicting-content-length", st in (400, 403, 411, 501),
               f"status={st}, must not be 200")
    except Exception as e:
        record("proto-conflicting-content-length", False, f"exception: {e}")


def test_oversized_header():
    """超大请求头（约 128KB，超过网关 64KB 上限）。HTTP 层应拒绝（431/400）。"""
    big = "x" * 131072
    payload = (
        b"GET /echo HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"X-Oversized: " + big.encode() + b"\r\n"
        b"\r\n"
    )
    try:
        raw = raw_request(payload)
        st = status_of(raw)
        record("proto-oversized-header", st in (400, 431),
               f"status={st}, want 431/400")
    except Exception as e:
        # 服务器直接断开连接同样视为拒绝
        record("proto-oversized-header", True, f"connection rejected: {type(e).__name__}")


def test_invalid_method():
    """非法 HTTP 方法：CRS 911 方法强制或协议层拒绝。"""
    conn = http.client.HTTPConnection(GATEWAY_HOST, GATEWAY_PORT, timeout=10)
    try:
        conn.request("HACKMETHOD", "/echo")
        resp = conn.getresponse()
        resp.read()
        want = expected_attack_status()
        record("proto-invalid-method", resp.status in (want, 400, 405, 501),
               f"status={resp.status}")
    except Exception as e:
        record("proto-invalid-method", True, f"rejected: {type(e).__name__}")
    finally:
        conn.close()


def test_body_type_mismatch():
    """声明 JSON 但发送 XML 内容：解析失败应 400/403。"""
    conn = http.client.HTTPConnection(GATEWAY_HOST, GATEWAY_PORT, timeout=10)
    try:
        conn.request("POST", "/api/json", body="<xml>not json</xml>",
                     headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        resp.read()
        want = expected_attack_status()
        record("proto-body-type-mismatch", resp.status in (want, 400),
               f"status={resp.status}")
    except Exception as e:
        record("proto-body-type-mismatch", False, f"exception: {e}")
    finally:
        conn.close()


def test_duplicate_anomalous_headers():
    """重复异常请求头（多个相同的 Transfer-Encoding 变体）。"""
    payload = (
        b"POST /echo HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Transfer-Encoding: identity\r\n"
        b"\r\n"
        b"0\r\n\r\n"
    )
    try:
        raw = raw_request(payload)
        st = status_of(raw)
        record("proto-duplicate-te-headers", st in (400, 403, 501),
               f"status={st}, must not be 200")
    except Exception as e:
        record("proto-duplicate-te-headers", True, f"rejected: {type(e).__name__}")


def main():
    print("=" * 60)
    print(f"九章阶段1 协议异常测试  {GATEWAY_HOST}:{GATEWAY_PORT}  mode={EXPECT_MODE}")
    print("=" * 60)
    test_conflicting_content_length()
    test_oversized_header()
    test_invalid_method()
    test_body_type_mismatch()
    test_duplicate_anomalous_headers()

    total = len(results)
    passed = sum(1 for _, p, _ in results if p)
    failed = total - passed
    print("=" * 60)
    print(f"总用例数: {total}")
    print(f"通过:     {passed}")
    print(f"失败:     {failed}")
    print("跳过:     0")
    if failed:
        print("失败用例:")
        for name, p, detail in results:
            if not p:
                print(f"  - {name}: {detail}")
    print("=" * 60)
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
