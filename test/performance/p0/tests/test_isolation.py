"""隔离归属判定测试（BENCH-01/BENCH-02 的可单测部分）。"""

from __future__ import annotations

import socket
import sys
import unittest
from pathlib import Path

P0_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(P0_DIR))

from p0bench import isolation  # noqa: E402

RUN_A = "20260906T100000-aaaaaa"
RUN_B = "20260906T100000-bbbbbb"


def labels(project_suffix: str, run_id: str | None) -> dict:
    out = {"com.docker.compose.project": f"p0bench-{project_suffix}"}
    if run_id is not None:
        out["p0bench.run_id"] = run_id
    return out


class TestOwnership(unittest.TestCase):
    """BENCH-01：归属判定要求 project 标签与 run_id 标签同时匹配。"""

    def test_own_resource_accepted(self):
        self.assertTrue(isolation.owns_resource(labels(RUN_A, RUN_A), RUN_A))

    def test_other_run_rejected(self):
        # 另一个 run_id 的资源：project 不同
        self.assertFalse(isolation.owns_resource(labels(RUN_B, RUN_B), RUN_A))

    def test_same_project_wrong_run_label_rejected(self):
        bad = labels(RUN_A, RUN_B)
        bad["com.docker.compose.project"] = f"p0bench-{RUN_A}"
        self.assertFalse(isolation.owns_resource(bad, RUN_A))

    def test_missing_run_label_rejected(self):
        self.assertFalse(isolation.owns_resource(labels(RUN_A, None), RUN_A))

    def test_missing_project_label_rejected(self):
        self.assertFalse(isolation.owns_resource({"p0bench.run_id": RUN_A}, RUN_A))

    def test_shared_stage5_style_resource_rejected(self):
        stage5 = {"com.docker.compose.project": "jiuzhang-stage5"}
        self.assertFalse(isolation.owns_resource(stage5, RUN_A))

    def test_none_and_invalid_run_id(self):
        self.assertFalse(isolation.owns_resource(None, RUN_A))
        self.assertFalse(isolation.owns_resource(labels(RUN_A, RUN_A), "bad id"))

    def test_run_id_format(self):
        self.assertTrue(isolation.validate_run_id(RUN_A))
        for bad in ("", "x", "20260906T100000", "20260906T100000-AAAAAA", "p0bench-x"):
            self.assertFalse(isolation.validate_run_id(bad))

    def test_project_derivation(self):
        self.assertEqual(isolation.project_for_run(RUN_A), f"p0bench-{RUN_A}")
        with self.assertRaises(ValueError):
            isolation.project_for_run("invalid")


class TestTargetClassification(unittest.TestCase):
    """BENCH-02：共享/外部目标与重定向逃离一律拒绝。"""

    def setUp(self):
        self.allowed = frozenset({"127.0.0.1:18080", "127.0.0.1:18081", "bench-origin.internal:8081"})

    def test_project_port_allowed(self):
        cls, _ = isolation.classify_target("http://127.0.0.1:18080/", self.allowed)
        self.assertEqual(cls, "allowed")

    def test_registered_target_allowed(self):
        cls, _ = isolation.classify_target("http://bench-origin.internal:8081/echo", self.allowed)
        self.assertEqual(cls, "allowed")

    def test_unlisted_loopback_port_rejected(self):
        # 其他端口（如共享 stage5 栈的 18081→这里换成未登记端口）拒绝
        cls, reason = isolation.classify_target("http://127.0.0.1:9999/", self.allowed)
        self.assertEqual(cls, "rejected")
        self.assertIn("不属于", reason)

    def test_external_host_rejected(self):
        for url in (
            "http://example.com/",
            "https://169.254.169.254/latest/meta-data",
            "http://10.0.0.8:8080/api",
        ):
            cls, _ = isolation.classify_target(url, self.allowed)
            self.assertEqual(cls, "rejected", url)

    def test_bad_scheme_and_userinfo_rejected(self):
        self.assertEqual(isolation.classify_target("ftp://127.0.0.1:18080/", self.allowed)[0], "rejected")
        self.assertEqual(
            isolation.classify_target("http://user:pass@127.0.0.1:18080/", self.allowed)[0],
            "rejected",
        )

    def test_host_without_port_entry_matches_any_port(self):
        allowed = frozenset({"bench-origin.internal"})
        cls, _ = isolation.classify_target("http://bench-origin.internal:9999/x", allowed)
        self.assertEqual(cls, "allowed")

    def test_port_entry_does_not_match_other_port(self):
        allowed = frozenset({"127.0.0.1:18080"})
        cls, _ = isolation.classify_target("http://127.0.0.1:443/", allowed)
        self.assertEqual(cls, "rejected")

    def test_redirect_escape_rejected(self):
        ok, reason = isolation.check_redirect_chain(
            ["http://127.0.0.1:18080/step1", "http://evil.example.com/"], self.allowed
        )
        self.assertFalse(ok)
        self.assertIn("逃离", reason)

    def test_redirect_chain_inside_allowed(self):
        ok, _ = isolation.check_redirect_chain(
            ["http://127.0.0.1:18080/a", "http://127.0.0.1:18081/b"], self.allowed
        )
        self.assertTrue(ok)


class TestPortAndEnvIdentity(unittest.TestCase):
    def test_is_port_free(self):
        with socket.socket() as srv:
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            busy = srv.getsockname()[1]
            self.assertFalse(isolation.is_port_free(busy))
        self.assertTrue(isolation.is_port_free(busy))

    def test_environment_identity(self):
        fp = isolation.compute_environment_fingerprint("machine-x", "host-y")
        self.assertEqual(len(fp), 16)
        ok, _ = isolation.check_environment_identity(fp, fp)
        self.assertTrue(ok)
        ok, reason = isolation.check_environment_identity(fp, "other")
        self.assertFalse(ok)
        self.assertIn("不符", reason)


if __name__ == "__main__":
    unittest.main()
