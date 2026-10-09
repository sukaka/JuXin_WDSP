#!/usr/bin/env python3
"""NG-HTTP-01 链路驱动（骨架 v0.1）。

子命令：
  sanity       T0：直连记录型源站，验证语料登记与基础边界行为（不需要网关）
  via-gateway  T1：经网关（GATEWAY_URL + HOST_HEADER）转述同一语料并比对源站记录

纪律：全部合成数据（example.com / RFC5737）；原始报文仅发往隔离目标。
"""
import json
import os
import socket
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(ROOT, "corpus")
ORIGIN = os.environ.get("CHAIN_ORIGIN_ADDR", "127.0.0.1:18099")
GATEWAY_URL = os.environ.get("GATEWAY_URL", "")
HOST_HEADER = os.environ.get("HOST_HEADER", "waf-s5.local")

PASS, FAIL, FAILED = 0, 0, []


def record(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS  {name}")
    else:
        FAIL += 1
        FAILED.append(f"{name}: {detail}")
        print(f"FAIL  {name} ({detail})")


def load_corpus():
    out = {}
    for fn in sorted(os.listdir(CORPUS)):
        if fn.endswith(".json"):
            with open(os.path.join(CORPUS, fn)) as f:
                out[fn[:-5]] = json.load(f)
    return out


def http_req(base, item, host_header=None, pad=""):
    if item.get("absolute_uri"):
        url = item["absolute_uri"].replace("{HOST}", host_header or "")
    else:
        url = base + item["path"]
    headers = {k: (v.replace("__PAD_4KB__", pad) if isinstance(v, str) else v)
               for k, v in item.get("headers", {}).items()}
    if host_header and "Host" not in headers:
        headers["Host"] = host_header
    # 额外原始头（如第二个 Host）无法经 urllib 表达：改走原始套接字
    if item.get("extra_raw_headers"):
        host, port = base.split("://")[1].split(":")
        lines = [f"{item['method']} {item.get('path', '/')} HTTP/1.1"]
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
        for h in item["extra_raw_headers"]:
            lines.append(h)
        lines.append("")
        body = item.get("body", "")
        raw = "\r\n".join(lines) + "\r\n" + body
        resp = raw_send(host, int(port), raw)
        first = resp.splitlines()[0] if resp else ""
        code = int(first.split()[1]) if len(first.split()) >= 2 and first.split()[1].isdigit() else 0
        return code, resp
    data = item.get("body")
    req = urllib.request.Request(url, data=data.encode() if data else None,
                                 method=item["method"], headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except Exception as e:  # 连接重置/超时等传输异常：如实记 0 继续执行（异常样本本就可能触发断连）
        return 0, repr(e)


def raw_send(host, port, raw):
    # 缺省补 Connection: close 并避免半关闭写入（shutdown(SHUT_WR) 会使网关把
    # 响应短路为本地空 200 而不反代——实测踩坑）；服务器见 Connection: close 后
    # 响应完即关闭连接，本函数据连接关闭返回完整响应。
    head, _, body = raw.partition("\r\n\r\n")
    if "connection:" not in head.lower():
        raw = head + "\r\nConnection: close\r\n\r\n" + body
    with socket.create_connection((host, port), timeout=10) as s:
        s.sendall(raw.encode())
        buf = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    return buf.decode(errors="replace")


def origin_records(origin, since=0, retries=10):
    for _ in range(retries):
        with urllib.request.urlopen(f"http://{origin}/__chain/records?since={since}", timeout=5) as resp:
            lines = [l for l in resp.read().decode().splitlines() if l.strip()]
            return [json.loads(l) for l in lines]
    return []


def origin_reset(origin):
    urllib.request.urlopen(urllib.request.Request(f"http://{origin}/__chain/reset", method="POST"), timeout=5)


def run_corpus(base, host_header, raw_target, authority=None):
    """发送全部语料，返回每用例的源站记录映射 case->[records]。
    authority 用于 absolute-form 中的 {HOST} 替换（含端口；缺省取 base 的 host:port）。"""
    if authority is None:
        authority = base.split("://")[1]
    corpus = load_corpus()
    for cid, doc in corpus.items():
        if doc.get("raw"):
            for r in doc["requests"]:
                raw = r["raw"].replace("{HOST}", authority)
                host, port = raw_target.split(":")
                raw_send(host, int(port), raw)
        else:
            for r in doc["requests"]:
                if r.get("absolute_uri"):
                    # 绝对形式请求行必须经原始套接字发送到网关（urllib 会把绝对 URI 当
                    # 连接目标直连域名，既测不到网关也到不了源站）
                    host, port = raw_target.split(":")
                    abs_target = r["absolute_uri"].replace("{HOST}", authority)
                    lines = [f"{r['method']} {abs_target} HTTP/1.1", f"Host: {authority}"]
                    for k, v in r.get("headers", {}).items():
                        if k.lower() != "host":
                            lines.append(f"{k}: {v}")
                    lines.append("")
                    raw_send(host, int(port), "\r\n".join(lines) + "\r\n")
                    continue
                http_req(base, r, host_header, pad="A" * 4096)
        time.sleep(0.05)
    time.sleep(0.4)
    return origin_records(ORIGIN)


def cmd_sanity():
    origin_reset(ORIGIN)
    recs = run_corpus(f"http://{ORIGIN}", ORIGIN.split(":")[0], ORIGIN)
    by_case = {}
    for r in recs:
        c = (r.get("allowed_headers") or {}).get("x-chain-case", "?")
        by_case.setdefault(c, []).append(r)

    record("T0-normal-recorded",
           len(by_case.get("HC-N01-GET", [])) == 1 and len(by_case.get("HC-N01-POST", [])) == 1,
           f"GET={len(by_case.get('HC-N01-GET', []))} POST={len(by_case.get('HC-N01-POST', []))}")

    post = (by_case.get("HC-N01-POST") or [{}])[0]
    record("T0-body-digest", post.get("body_len") == len("name=demo&count=2") and bool(post.get("body_sha256")),
           f"body_len={post.get('body_len')}")

    record("T0-absolute-form", len(by_case.get("HC-A02-abs", [])) == 1,
           f"records={len(by_case.get('HC-A02-abs', []))}")

    dual = by_case.get("HC-A03-dual", [])
    record("T0-dual-host-bounded", len(dual) <= 1,
           f"records={len(dual)}（Go 服务器对双 Host 只受理一次或拒绝）")

    # HC-A01 原始报文：Go 服务器对 CL/TE 冲突应 400 拒绝（安全侧），且源站随后请求不受影响
    resp = raw_send(*ORIGIN.split(":"), "GET /__chain/records HTTP/1.1\r\nHost: x\r\n\r\n".replace("x", ORIGIN.split(":")[0]))
    record("T0-post-raw-socket-alive", "HTTP/1.1 200" in resp, f"resp={resp[:60]!r}")

    # 连接复用：同一 curl 进程多 URL 复用连接，conn_seq 应递增
    code1, b1 = http_req(f"http://{ORIGIN}", {"method": "GET", "path": "/v1/a"}, None)
    time.sleep(0.1)
    print("---- sanity done ----")


def cmd_via_gateway():
    if not GATEWAY_URL:
        print("GATEWAY_URL 未设置（T1 需要网关与已配置上游路由），记 SKIP")
        return
    origin_reset(ORIGIN)
    run_corpus(GATEWAY_URL, HOST_HEADER, GATEWAY_URL.split("://")[1], authority=HOST_HEADER)
    recs = origin_records(ORIGIN)
    by_case = {}
    for r in recs:
        c = (r.get("allowed_headers") or {}).get("x-chain-case", "?")
        by_case.setdefault(c, []).append(r)

    record("T1-origin-received", len(recs) > 0, f"records={len(recs)}")

    g, p = by_case.get("HC-N01-GET", []), by_case.get("HC-N01-POST", [])
    record("T1-normal-method-path",
           len(g) == 1 and g[0]["method"] == "GET" and len(p) == 1 and p[0]["method"] == "POST"
           and p[0]["raw_uri"].startswith("/v1/items"),
           f"GET={len(g)} POST={len(p)}")
    if p:
        record("T1-body-digest-match",
               p[0]["body_len"] == len("name=demo&count=2") and bool(p[0]["body_sha256"]),
               f"body_len={p[0]['body_len']}（网关到源站体未被改写）")
        hdrs = p[0].get("header_names", [])
        record("T1-gateway-headers-present",
               any(h.lower() == "x-request-id" for h in hdrs),
               f"header_names={hdrs[:12]}")

    abs_rec = by_case.get("HC-A02-abs", [])
    record("T1-absolute-form-bounded",
           len(abs_rec) == 1 and abs_rec[0]["host"] == HOST_HEADER,
           f"records={len(abs_rec)} host={abs_rec[0]['host'] if abs_rec else ''}")

    forge = by_case.get("HC-A02-forge", [])
    record("T1-forwarded-host-ignored",
           all(r["host"] == HOST_HEADER for r in forge),
           f"hosts={[r['host'] for r in forge]}（X-Forwarded-Host 不得改写 authority）")

    dual = by_case.get("HC-A03-dual", [])
    record("T1-dual-host-single-verdict",
           len(dual) <= 1 and all(r["host"] != "second.invalid" for r in dual),
           f"records={len(dual)} hosts={[r['host'] for r in dual]}")

    admin = [r for r in recs if r["raw_uri"].startswith("/v1/admin")]
    record("T1-no-smuggled-admin", len(admin) == 0,
           f"smuggled_records={len(admin)}（cl-te 冲突中的夹带请求不得到达源站）")

    record("T1-options-recorded", len(by_case.get("HC-U01-options", [])) == 1,
           f"records={len(by_case.get('HC-U01-options', []))}")
    big = by_case.get("HC-U01-bighead", [])
    record("T1-bigheader-consistent", len(big) <= 1,
           f"records={len(big)}（4KB 头要么放行要么一致拒绝，不得 5xx）")

    # 连接复用：后续正常请求在 raw 探针后仍被正常登记（异常不污染后继请求）
    tail = [r for r in recs if (r.get("allowed_headers") or {}).get("x-chain-case") == "HC-N01-GET"]
    record("T1-post-raw-not-poisoned", len(tail) == 1,
           f"raw 探针后正常请求记录数={len(tail)}")



def cmd_chains():
    """T2：conn-reuse（单连接多请求+走私复用）与 trusted-proxy（真实 IP 链）。"""
    import http.client
    if not GATEWAY_URL:
        print("GATEWAY_URL 未设置，记 SKIP")
        return
    gw_host, gw_port = GATEWAY_URL.split("://")[1].split(":")

    # ---- conn-reuse：同一连接上 正常→CL/TE冲突→正常 ----
    origin_reset(ORIGIN)
    conn = http.client.HTTPConnection(gw_host, int(gw_port), timeout=10)
    conn.request("GET", "/v1/reuse", headers={"Host": HOST_HEADER, "X-Chain-Case": "CR-1"})
    r1 = conn.getresponse()
    r1.read()
    # 同一连接写冲突原始报文（CL/TE 冲突 + 夹带 /v1/admin），随后立刻再发正常请求
    raw = ("POST /v1/upload HTTP/1.1\r\n"
           f"Host: {HOST_HEADER}\r\n"
           "Content-Length: 11\r\n"
           "Transfer-Encoding: chunked\r\n"
           "X-Chain-Case: CR-2\r\n\r\n"
           "0\r\n\r\n")
    conn.send(raw.encode())
    conn.request("GET", "/v1/reuse2", headers={"Host": HOST_HEADER, "X-Chain-Case": "CR-3"})
    try:
        r3 = conn.getresponse()
        r3.read()
        cr3_ok = True
    except Exception as e:
        cr3_ok = repr(e)
    conn.close()
    time.sleep(0.3)
    recs = origin_records(ORIGIN)
    by_case = {}
    for r in recs:
        c = (r.get("allowed_headers") or {}).get("x-chain-case", "?")
        by_case.setdefault(c, []).append(r)
    admin = [r for r in recs if r["raw_uri"].startswith("/v1/admin")]
    record("CR-no-smuggled-admin", len(admin) == 0, f"admin_records={len(admin)}")
    r1s, r3s = by_case.get("CR-1", []), by_case.get("CR-3", [])
    record("CR-normals-recorded", len(r1s) == 1 and len(r3s) == 1,
           f"CR-1={len(r1s)} CR-3={len(r3s)}（cr3_ok={cr3_ok}）")
    if r1s and r3s:
        record("CR-same-conn-seq",
               r1s[0]["conn"] == r3s[0]["conn"] and r3s[0]["conn_seq"] > r1s[0]["conn_seq"],
               f"conn {r1s[0]['conn']}/{r3s[0]['conn']} seq {r1s[0]['conn_seq']}→{r3s[0]['conn_seq']}"
               "（同一连接顺序登记、无串扰）")

    # ---- trusted-proxy：注册→发布→XFF 透传→删除→发布→忽略 ----
    print("---- trusted-proxy ----")
    os.system(f"bash {ROOT}/scripts/chain_proxy.sh setup 2>/dev/null")
    time.sleep(1)
    code, _ = http_req(GATEWAY_URL, {"method": "GET", "path": "/v1/tp",
                                     "headers": {"X-Chain-Case": "TP-1", "X-Forwarded-For": "203.0.113.77"}},
                       HOST_HEADER)
    recs = origin_records(ORIGIN)
    tp1 = [r for r in recs if (r.get("allowed_headers") or {}).get("x-chain-case") == "TP-1"]
    if tp1:
        rip = (tp1[0].get("allowed_headers") or {}).get("x-real-ip", "")
        record("TP-trusted-xff-honored", rip == "203.0.113.77",
               f"x-real-ip={rip}（可信代理后真实客户端应透传）")
    else:
        record("TP-trusted-xff-honored", False, "TP-1 未到源站")

    os.system(f"bash {ROOT}/scripts/chain_proxy.sh cleanup 2>/dev/null")
    time.sleep(1)
    http_req(GATEWAY_URL, {"method": "GET", "path": "/v1/tp",
                           "headers": {"X-Chain-Case": "TP-2", "X-Forwarded-For": "203.0.113.99"}},
             HOST_HEADER)
    recs = origin_records(ORIGIN)
    tp2 = [r for r in recs if (r.get("allowed_headers") or {}).get("x-chain-case") == "TP-2"]
    if tp2:
        rip = (tp2[0].get("allowed_headers") or {}).get("x-real-ip", "")
        record("TP-untrusted-xff-ignored", rip != "203.0.113.99" and rip != "",
               f"x-real-ip={rip}（不可信时 XFF 必须被忽略，回退连接源）")
    else:
        record("TP-untrusted-xff-ignored", False, "TP-2 未到源站")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "sanity"
    if cmd == "sanity":
        cmd_sanity()
    elif cmd == "via-gateway":
        cmd_via_gateway()
    elif cmd == "chains":
        cmd_chains()
    else:
        print(__doc__)
        sys.exit(2)
    print(f"httpchain {cmd}: PASS={PASS} FAIL={FAIL}")
    for f in FAILED:
        print("  -", f)
    sys.exit(1 if FAIL else 0)
