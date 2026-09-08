"""run-plan 校验测试（P0-02 §7 预登记门槛）。"""

from __future__ import annotations

import copy
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

P0_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(P0_DIR))

from p0bench import cli  # noqa: E402
from p0bench.plan import (  # noqa: E402
    JWT_PAIR_PROFILES,
    PROFILES,
    PlanError,
    check_corpus_hash,
    load_plan,
    validate_plan,
)

EXAMPLE = P0_DIR / "run-plan.example.json"


def load_example() -> dict:
    return json.loads(EXAMPLE.read_text(encoding="utf-8"))


class TestPlanValidation(unittest.TestCase):
    def test_example_plan_passes(self):
        errors = validate_plan(load_example())
        self.assertEqual(errors, [], "示例计划必须通过全量校验:\n" + "\n".join(errors))

    def test_missing_top_level_sections_rejected(self):
        for key in ("environment", "build", "config", "corpus", "load", "resource_limits", "thresholds"):
            plan = load_example()
            del plan[key]
            errors = validate_plan(plan)
            self.assertTrue(errors, f"缺 {key} 必须报错")
            self.assertTrue(any(key in e for e in errors))

    def test_missing_threshold_fields_rejected(self):
        for key in (
            "normal_unexpected_error_rate_max",
            "p99_regression",
            "event_visibility_latency_ms_max",
            "recovery_time_seconds_max",
        ):
            plan = load_example()
            del plan["thresholds"][key]
            errors = validate_plan(plan)
            self.assertTrue(any(key in e for e in errors), f"缺门槛 {key} 必须报错")

    def test_seven_profiles_complete_and_modes_fixed(self):
        plan = load_example()
        plan["config"]["profiles"] = plan["config"]["profiles"][:6]
        self.assertTrue(validate_plan(plan), "七模式不完整必须报错")

        plan = load_example()
        plan["config"]["profiles"][0]["waf_mode"] = "ON"  # proxy 必须 OFF
        self.assertTrue(validate_plan(plan), "profile 模式偏离 §4 表必须报错")

    def test_latest_image_rejected(self):
        plan = load_example()
        plan["build"]["images"]["gateway"] = "jiuzhang-gateway:latest"
        errors = validate_plan(plan)
        self.assertTrue(any("latest" in e for e in errors))

    def test_durations_and_repeats_floor(self):
        plan = load_example()
        plan["load"]["warmup_seconds"] = 30
        self.assertTrue(validate_plan(plan))
        plan = load_example()
        plan["load"]["steady_point_seconds"] = 120
        self.assertTrue(validate_plan(plan))
        plan = load_example()
        plan["load"]["repeats"] = 2
        self.assertTrue(validate_plan(plan))
        plan = load_example()
        plan["load"]["soak"]["combined_protect_hours"] = 24
        self.assertTrue(validate_plan(plan))

    def test_loadgen_tool_enum_and_version(self):
        plan = load_example()
        plan["load"]["loadgen"]["tool"] = "heyab"
        self.assertTrue(validate_plan(plan))
        plan = load_example()
        plan["load"]["loadgen"]["version"] = ""
        self.assertTrue(validate_plan(plan), "压测器版本必须登记")

    def test_load_plan_errors(self):
        with self.assertRaises(PlanError):
            load_plan("/nonexistent/plan.json")
        with tempfile.TemporaryDirectory() as td:
            bad = Path(td) / "bad.json"
            bad.write_text("{not json", encoding="utf-8")
            with self.assertRaises(PlanError):
                load_plan(bad)


class TestJwtPairPlan(unittest.TestCase):
    """config.jwt_pair（JWT-18 配对实验声明）校验。"""

    def test_example_declares_pair_and_passes(self):
        plan = load_example()
        self.assertIn("jwt_pair", plan["config"])
        self.assertEqual(validate_plan(plan), [])

    def test_without_pair_requires_jwt_toggle_false(self):
        plan = load_example()
        del plan["config"]["jwt_pair"]
        plan["config"]["toggles"]["jwt"] = False
        self.assertEqual(validate_plan(plan), [], "纯七模式基线（无配对声明）必须仍可通过")

    def test_missing_required_fields_rejected(self):
        for key in ("app_code", "issuer", "audience"):
            plan = load_example()
            del plan["config"]["jwt_pair"][key]
            errors = validate_plan(plan)
            self.assertTrue(any(f"jwt_pair.{key}" in e for e in errors), f"缺 {key} 必须报错")

    def test_bad_ttl_rejected(self):
        plan = load_example()
        plan["config"]["jwt_pair"]["token_ttl_seconds"] = 30
        self.assertTrue(any("token_ttl_seconds" in e for e in validate_plan(plan)))

    def test_token_required_true_rejected(self):
        plan = load_example()
        plan["config"]["jwt_pair"]["selector"]["token_required"] = True
        errors = validate_plan(plan)
        self.assertTrue(any("token_required" in e for e in errors),
                        "配对语料含不带 Token 的正常样本，token_required=true 必须拒绝")

    def test_selector_path_rules(self):
        plan = load_example()
        sel = plan["config"]["jwt_pair"]["selector"]
        sel["path_exact"] = "/echo"  # 与 path_prefix 同时提供
        self.assertTrue(validate_plan(plan), "path_exact/path_prefix 二选一，同时提供必须报错")
        plan = load_example()
        plan["config"]["jwt_pair"]["selector"] = {"path_prefix": "api"}  # 不以 / 开头
        self.assertTrue(validate_plan(plan))
        plan = load_example()
        plan["config"]["jwt_pair"]["selector"] = {"path_prefix": "/api?x=1"}  # 含 query
        self.assertTrue(validate_plan(plan))

    def test_toggle_pair_consistency(self):
        plan = load_example()
        plan["config"]["toggles"]["jwt"] = False
        errors = validate_plan(plan)
        self.assertTrue(any("toggles.jwt" in e for e in errors),
                        "声明 jwt_pair 时 toggles.jwt=false 必须报错（预登记诚实性）")
        plan = load_example()
        del plan["config"]["jwt_pair"]
        errors = validate_plan(plan)  # toggles.jwt 仍为 true
        self.assertTrue(any("toggles.jwt" in e for e in errors),
                        "jwt=true 缺 jwt_pair 声明必须报错")

    def test_shuffle_jwt_pair_outputs_pair_only(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(["shuffle-profiles", "--seed", "20260906", "--jwt-pair"])
        self.assertEqual(rc, 0)
        out = buf.getvalue().split()
        self.assertEqual(sorted(out), sorted(JWT_PAIR_PROFILES))
        self.assertEqual(len(out), 2)
        # 与七模式不混
        buf2 = io.StringIO()
        with redirect_stdout(buf2):
            cli.main(["shuffle-profiles", "--seed", "20260906"])
        self.assertEqual(sorted(buf2.getvalue().split()), sorted(PROFILES))


class TestCorpusHashCheck(unittest.TestCase):
    def test_hash_match_and_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            corpus = root / "corpus" / "manifest.json"
            corpus.parent.mkdir(parents=True)
            corpus.write_text('{"schema_version":1}', encoding="utf-8")
            import hashlib

            digest = hashlib.sha256(b'{"schema_version":1}').hexdigest()
            plan = {"corpus": {"manifest_path": "corpus/manifest.json", "manifest_sha256": digest}}
            self.assertIsNone(check_corpus_hash(plan, root))
            plan["corpus"]["manifest_sha256"] = "0" * 64
            err = check_corpus_hash(plan, root)
            self.assertIsNotNone(err)
            self.assertIn("不匹配", err)

    def test_missing_corpus_file(self):
        with tempfile.TemporaryDirectory() as td:
            plan = {"corpus": {"manifest_path": "nope.json", "manifest_sha256": "0" * 64}}
            err = check_corpus_hash(plan, td)
            self.assertIn("缺失", err)

    def test_repo_example_plan_corpus_hash_matches(self):
        plan = load_example()
        self.assertIsNone(
            check_corpus_hash(plan, REPO_ROOT),
            "示例计划登记的语料哈希必须与仓库语料一致",
        )


if __name__ == "__main__":
    unittest.main()
