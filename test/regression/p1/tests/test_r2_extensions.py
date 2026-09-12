"""R2 新增能力单元测试：LOCAL_REJECT 动作词表、client 声明校验、
PoW 求解器（与网关 Go 实现同向量核对）、挑战页参数解析、
Bot 求解回放流（本地假网关，不冒充真实栈证据）。"""

from __future__ import annotations

import http.server
import json
import sys
import threading
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
P1_DIR = TESTS_DIR.parents[0]
for p in (str(TESTS_DIR), str(P1_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

import p1fixture  # noqa: E402
from adapters.http_replay import (  # noqa: E402
    HttpReplayAdapter,
    parse_challenge_params,
    pow_solve,
)
from p1reg import corpus as corpus_mod  # noqa: E402
from p1reg.judge import judge_case  # noqa: E402

RID = p1fixture.VALID_RUN_ID

# 与网关 botchallenge Go 实现 Solve 同输入同输出的核对向量
# （Go 侧一次性打印，难度 4/8/12 三档）
POW_VECTORS = {
    "cid": "00112233445566778899aabbccddeeff",
    "nonce": "ffeeddccbbaa99887766554433221100",
    "app": "app-uuid-0001",
    "host": "p1reg-protect.local",
    "solutions": {4: "13", 8: "1472", 12: "2561"},
}


class TestPowSolveParity(unittest.TestCase):
    def test_matches_go_implementation(self):
        for diff, want in POW_VECTORS["solutions"].items():
            got = pow_solve(POW_VECTORS["cid"], POW_VECTORS["nonce"],
                            POW_VECTORS["app"], POW_VECTORS["host"], diff)
            self.assertEqual(got, want, f"difficulty={diff}")

    def test_invalid_hex_returns_none(self):
        self.assertIsNone(pow_solve("zz", "00", "a", "h", 4))


class TestParseChallengeParams(unittest.TestCase):
    def test_extracts_params_block(self):
        html = ('<script nonce="abc" id="wdsp-bot-params" type="application/json">'
                '{"challenge_id":"00","nonce":"11","difficulty":4,"app":"a","host":"h",'
                '"verify_path":"/_wdsp/bot/v1/verify"}</script>')
        p = parse_challenge_params(html)
        self.assertIsNotNone(p)
        self.assertEqual(p["challenge_id"], "00")
        self.assertEqual(p["difficulty"], 4)

    def test_non_challenge_page_returns_none(self):
        self.assertIsNone(parse_challenge_params("<html>ok</html>"))
        self.assertIsNone(parse_challenge_params(""))


class TestLocalRejectVocab(unittest.TestCase):
    def _doc(self, action, module="bot"):
        doc = p1fixture.minimal_case_doc("BOT-UNK-TST-001", "UNKNOWN")
        for prof in doc["expectations_by_profile"].values():
            prof["expected_detection"] = {"module": module, "rule_family": "tombstone"}
            prof["expected_final_action"] = action
        return doc

    def test_local_reject_accepted(self):
        doc = self._doc("LOCAL_REJECT")
        errors = corpus_mod.validate_case_doc(doc)
        self.assertEqual(errors, [])

    def test_unknown_action_rejected(self):
        doc = self._doc("BLOCK_409")
        errors = corpus_mod.validate_case_doc(doc)
        self.assertTrue(any("expected_final_action" in e for e in errors))

    def test_local_reject_with_module_none_rejected(self):
        doc = self._doc("LOCAL_REJECT", module="none")
        errors = corpus_mod.validate_case_doc(doc)
        self.assertTrue(any("期望矛盾" in e for e in errors))

    def test_judge_local_reject_match(self):
        doc = self._doc("LOCAL_REJECT")
        obs = {"executed": True, "valid": True, "execution_state": "COMPLETED",
               "detection": {"detected": True, "module": "bot", "rule_family": "tombstone"},
               "observed_action": "LOCAL_REJECT", "origin_reached": False, "assertions": []}
        r = judge_case(doc, "OBSERVE", obs)
        self.assertEqual(r["status"], "PASS")


class TestClientDeclaration(unittest.TestCase):
    def test_valid_client_declaration(self):
        doc = p1fixture.minimal_case_doc()
        doc["client"] = {"bot_challenge_solve": True}
        self.assertEqual(corpus_mod.validate_case_doc(doc), [])

    def test_unknown_client_key_rejected(self):
        doc = p1fixture.minimal_case_doc()
        doc["client"] = {"auto_magic": True}
        errors = corpus_mod.validate_case_doc(doc)
        self.assertTrue(any("client" in e for e in errors))

    def test_non_bool_solve_rejected(self):
        doc = p1fixture.minimal_case_doc()
        doc["client"] = {"bot_challenge_solve": "yes"}
        errors = corpus_mod.validate_case_doc(doc)
        self.assertTrue(any("bot_challenge_solve" in e for e in errors))


# ---- 本地假网关：挑战/verify/通行全流程（单元测试，非真实栈证据）----

_FAKE_CID = "00112233445566778899aabbccddeeff"
_FAKE_NONCE = "ffeeddccbbaa99887766554433221100"
_FAKE_DIFF = 8


def _fake_pow_ok(solution: str) -> bool:
    from adapters.http_replay import _lp
    import hashlib
    d = hashlib.sha256(
        b"wdsp-bot-pow-v1" + _lp(bytes.fromhex(_FAKE_CID)) + _lp(bytes.fromhex(_FAKE_NONCE))
        + _lp(b"fake-app") + _lp(b"fake.local") + _lp(solution.encode())).digest()
    return d[0] == 0  # difficulty 8 = 首字节全零


class _FakeGateway(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):  # 静默
        pass

    def _challenge(self):
        params = json.dumps({
            "challenge_id": _FAKE_CID, "nonce": _FAKE_NONCE, "difficulty": _FAKE_DIFF,
            "app": "fake-app", "host": "fake.local",
            "verify_path": "/_wdsp/bot/v1/verify", "budget_ms": 5000,
        })
        body = ('<html><script nonce="x" id="wdsp-bot-params" type="application/json">'
                + params + "</script></html>").encode()
        self.send_response(403)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Set-Cookie", "__Host-wdsp-bot-session=sess-1; Path=/; Secure; HttpOnly")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _origin_ok(self):
        body = b'{"upstream_mark":"REACHED_ORIGIN"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Wdsp-Origin-Mark", "jiuzhang-test-origin")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _cookies(self):
        raw = self.headers.get("Cookie") or ""
        out = {}
        for part in raw.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                out[k.strip()] = v.strip()
        return out

    def do_GET(self):
        if "__Host-wdsp-bot-clearance" in self._cookies():
            self._origin_ok()
        else:
            self._challenge()

    def do_POST(self):
        if self.path != "/_wdsp/bot/v1/verify":
            self.send_error(404)
            return
        n = int(self.headers.get("Content-Length") or 0)
        try:
            req = json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            req = {}
        if self._cookies().get("__Host-wdsp-bot-session") != "sess-1":
            self.send_error(403)
            return
        if _fake_pow_ok(str(req.get("solution", ""))):
            self.send_response(204)
            self.send_header(
                "Set-Cookie",
                "__Host-wdsp-bot-clearance=clr-1; Path=/; Secure; HttpOnly; SameSite=Lax")
            self.end_headers()
        else:
            self.send_error(403)


class _FakeServer:
    def __init__(self):
        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), _FakeGateway)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()


def _nav_case(solve: bool):
    doc = p1fixture.minimal_case_doc("BOT-BEN-TST-001", "BENIGN")
    doc["steps"] = [{
        "step_id": "s1", "action": "http_request",
        "request": {"method": "GET", "path": "/", "headers": {}},
        "wait": None,
        "assert": [{"type": "http_status_in", "statuses": [200]},
                   {"type": "origin_marker_present"}],
    }]
    if solve:
        doc["client"] = {"bot_challenge_solve": True}
    return doc


class TestBotSolveFlow(unittest.TestCase):
    def _adapter(self, port):
        return HttpReplayAdapter(
            allowed_targets={f"127.0.0.1:{port}"},
            environment={"base_url": f"http://127.0.0.1:{port}",
                         "origin_mark": "jiuzhang-test-origin"})

    def test_solve_flow_reaches_origin(self):
        with _FakeServer() as srv:
            obs = self._adapter(srv.port).execute_case(_nav_case(True), "PROTECT", RID)
        self.assertEqual(obs["execution_state"], "COMPLETED")
        self.assertEqual(obs["http"]["last_status"], 200)
        self.assertTrue(obs["origin_reached"])
        kinds = [p["kind"] for p in obs["perf"]]
        self.assertEqual(kinds, ["step", "verify", "retry"])
        rids = [p["request_id"] for p in obs["perf"]]
        self.assertEqual(rids[1], f"{RID}-BOT-BEN-TST-001-01-vfy")
        self.assertEqual(rids[2], f"{RID}-BOT-BEN-TST-001-01-rty")
        unmet = [a for a in obs["assertions"] if not a["met"]]
        self.assertEqual(unmet, [])

    def test_no_solve_keeps_challenge_403(self):
        with _FakeServer() as srv:
            obs = self._adapter(srv.port).execute_case(_nav_case(False), "PROTECT", RID)
        self.assertEqual(obs["http"]["last_status"], 403)
        self.assertFalse(obs["origin_reached"])
        self.assertEqual([p["kind"] for p in obs["perf"]], ["step"])

    def test_perf_records_latency_and_status(self):
        with _FakeServer() as srv:
            obs = self._adapter(srv.port).execute_case(_nav_case(True), "PROTECT", RID)
        for rec in obs["perf"]:
            self.assertIsInstance(rec["latency_ms"], float)
            self.assertGreaterEqual(rec["latency_ms"], 0.0)
            self.assertIn(rec["status"], (200, 204, 403))
            self.assertIn("origin_reached", rec)


if __name__ == "__main__":
    unittest.main()
