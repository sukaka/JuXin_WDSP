"""语料 manifest 校验与回放生成器测试（§5）。"""

from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

P0_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(P0_DIR))

from p0bench import corpus, replay  # noqa: E402
from p0bench.plan import PROFILES  # noqa: E402

MANIFEST_PATH = P0_DIR / "corpus" / "manifest.json"


def load_repo_manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


class TestRepoManifest(unittest.TestCase):
    def test_repo_manifest_valid(self):
        errors = corpus.validate_manifest(load_repo_manifest())
        self.assertEqual(errors, [], "仓库语料必须通过校验:\n" + "\n".join(errors))

    def test_normal_categories_cover_spec(self):
        m = load_repo_manifest()
        cats = {c["category"] for c in m["cases"] if c["label"] == "normal"}
        for required in (
            "normal_sql_text",
            "normal_search_symbols",
            "normal_unicode_cjk",
            "normal_xml_body",
            "normal_multipart",
            "normal_upload",
            "normal_pagination",
            "normal_shared_object_role_switch",
            "normal_legit_jwt",
            "normal_boundary_size",
        ):
            self.assertIn(required, cats)

    def test_attack_cases_marked_self_synthetic(self):
        for c in load_repo_manifest()["cases"]:
            if c["label"] == "attack":
                self.assertEqual(c["source"], "self_synthetic", c["case_id"])

    def test_all_cases_cover_declared_profiles(self):
        m = load_repo_manifest()
        declared = m["expected_actions"]["profiles"]
        self.assertEqual(
            sorted(declared), sorted(list(PROFILES) + ["jwt_off", "jwt_protect"]),
            "语料须声明七模式主基线 + JWT 配对 profile",
        )
        for c in m["cases"]:
            for prof in declared:
                self.assertIn(prof, c["expected_action"], f"{c['case_id']} 缺 {prof}")

    def test_jwt_cases_undeferred_with_real_semantics(self):
        """S3 交付后：JWT 语料解除 deferred，期望值指向 jwt_trust 真实行为。"""
        m = load_repo_manifest()
        cases = {c["case_id"]: c for c in m["cases"]}
        a = cases["A-JWT-01"]
        self.assertFalse(a.get("deferred"), "A-JWT-01 必须解除 deferred")
        self.assertEqual(a["expected_detection_module"], "jwt_trust")
        self.assertEqual(a["expected_action"]["jwt_protect"], "BLOCK_401",
                         "PROTECT 下篡改签名 Token 真实行为为 401")
        self.assertEqual(a["expected_action"]["jwt_off"], "PASS")
        for prof in PROFILES:
            self.assertEqual(a["expected_action"][prof], "PASS",
                             f"七模式基线 JWT 关闭，{prof} 放行如实记录")
        self.assertEqual(a["expected_event"]["type"], "access_control_event")
        self.assertEqual(a["origin_expectation"], "not_reached_when_protected")
        self.assertEqual(a.get("jwt_inject"), "tampered")
        n = cases["N-JWT-01"]
        self.assertFalse(n.get("deferred"), "N-JWT-01 必须解除 deferred")
        self.assertEqual(n["expected_action"]["jwt_protect"], "PASS",
                         "VERIFIED 继续后续检测，合法 JWT 不应被拦截")
        self.assertEqual(n["expected_event"]["type"], "none")
        self.assertEqual(n.get("jwt_inject"), "valid")
        # 语料不含任何静态 Token 材料
        for c in m["cases"]:
            headers = (c.get("request_override") or {}).get("headers") or {}
            self.assertFalse(
                any(k.lower() == "authorization" for k in headers),
                f"{c['case_id']} 禁止静态 Authorization（运行期现场签发注入）",
            )


class TestManifestValidationFailures(unittest.TestCase):
    def setUp(self):
        self.m = load_repo_manifest()

    def test_duplicate_case_id(self):
        dup = copy.deepcopy(self.m["cases"][0])
        self.m["cases"].append(dup)
        self.assertTrue(any("重复" in e for e in corpus.validate_manifest(self.m)))

    def test_missing_category_detected(self):
        self.m["cases"] = [c for c in self.m["cases"] if c["category"] != "normal_upload"]
        self.assertTrue(any("normal_upload" in e for e in corpus.validate_manifest(self.m)))

    def test_unknown_template_detected(self):
        self.m["cases"][0]["template"] = "nope"
        self.assertTrue(corpus.validate_manifest(self.m))

    def test_bad_expected_action_detected(self):
        self.m["cases"][0]["expected_action"]["proxy"] = "MAYBE"
        self.assertTrue(corpus.validate_manifest(self.m))

    def test_non_synthetic_source_rejected(self):
        self.m["cases"][0]["source"] = "third_party_corpus"
        self.assertTrue(corpus.validate_manifest(self.m))

    def test_bad_jwt_inject_rejected(self):
        case = next(c for c in self.m["cases"] if c["case_id"] == "N-JWT-01")
        case["jwt_inject"] = "sometimes"
        errors = corpus.validate_manifest(self.m)
        self.assertTrue(any("jwt_inject" in e for e in errors))

    def test_static_authorization_header_rejected(self):
        self.m["cases"][0].setdefault("request_override", {}).setdefault(
            "headers", {}
        )["Authorization"] = "Bearer static-token"
        errors = corpus.validate_manifest(self.m)
        self.assertTrue(any("Authorization" in e for e in errors),
                        "语料静态写入 Authorization 必须被拒绝")

    def test_expected_action_profile_set_mismatch(self):
        # 缺声明内键
        case = self.m["cases"][0]
        del case["expected_action"]["jwt_protect"]
        errors = corpus.validate_manifest(self.m)
        self.assertTrue(any("jwt_protect" in e for e in errors))
        # 多未声明键
        m2 = load_repo_manifest()
        m2["cases"][0]["expected_action"]["jwt_mystery"] = "PASS"
        errors2 = corpus.validate_manifest(m2)
        self.assertTrue(any("未在 expected_actions.profiles 声明" in e for e in errors2))

    def test_unknown_declared_profile_rejected(self):
        self.m["expected_actions"]["profiles"].append("jwt_sometimes")
        errors = corpus.validate_manifest(self.m)
        self.assertTrue(any("未知 profile" in e for e in errors))

    def test_missing_baseline_profile_declaration_rejected(self):
        self.m["expected_actions"]["profiles"].remove("proxy")
        errors = corpus.validate_manifest(self.m)
        self.assertTrue(any("七模式主基线" in e for e in errors))


class TestReplayGeneration(unittest.TestCase):
    def setUp(self):
        self.m = load_repo_manifest()

    def test_deterministic(self):
        a = replay.generate_requests(self.m, "waf_protect")
        b = replay.generate_requests(self.m, "waf_protect")
        self.assertEqual(a, b, "同一 seed 生成必须确定")

    def test_deferred_excluded(self):
        reqs = replay.generate_requests(self.m, "combined_protect")
        case_ids = {r["case_id"] for r in reqs}
        for c in self.m["cases"]:
            if c.get("deferred"):
                self.assertNotIn(c["case_id"], case_ids)

    def test_request_id_format_and_override_applied(self):
        reqs = {r["case_id"]: r for r in replay.generate_requests(self.m, "proxy")}
        self.assertRegex(reqs["N-SQL-01"]["request_id"], r"^N-SQL-01-\d{4}$")
        self.assertEqual(reqs["A-PROTO-01"]["method"], "TRACE")
        self.assertIn("UNION SELECT", reqs["A-SQLI-01"]["query"])

    def test_expected_action_attached(self):
        reqs = {r["case_id"]: r for r in replay.generate_requests(self.m, "waf_protect")}
        self.assertEqual(reqs["A-SQLI-01"]["expected_action"], "BLOCK_403")
        self.assertEqual(reqs["N-SQL-01"]["expected_action"], "PASS")

    def test_expected_action_attached_for_jwt_pair_profile(self):
        reqs = {r["case_id"]: r for r in replay.generate_requests(self.m, "jwt_protect")}
        self.assertEqual(reqs["A-JWT-01"]["expected_action"], "BLOCK_401")
        self.assertEqual(reqs["N-JWT-01"]["expected_action"], "PASS")
        self.assertEqual(reqs["N-SQL-01"]["expected_action"], "PASS")

    def test_jwt_inject_marker_propagated(self):
        reqs = {r["case_id"]: r for r in replay.generate_requests(self.m, "jwt_protect")}
        self.assertEqual(reqs["N-JWT-01"].get("jwt_inject"), "valid")
        self.assertEqual(reqs["A-JWT-01"].get("jwt_inject"), "tampered")
        for cid, r in reqs.items():
            if cid not in ("N-JWT-01", "A-JWT-01"):
                self.assertNotIn("jwt_inject", r, f"{cid} 不应携带 jwt_inject 标记")

    def test_no_static_authorization_in_generated_requests(self):
        reqs = {r["case_id"]: r for r in replay.generate_requests(self.m, "proxy")}
        jwt = reqs["N-JWT-01"]
        self.assertNotIn("Authorization", jwt["headers"],
                         "Token 不得静态出现在语料/生成请求中（运行期头文件注入）")
        self.assertNotIn("Bearer", json.dumps({k: v for k, v in jwt.items() if k != "headers"}))


if __name__ == "__main__":
    unittest.main()
