"""P1 语料 schema v1 校验器测试：拒绝分支、哈希自校验、路径越界、分母口径（REG-001/002/003）。"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
P1_DIR = TESTS_DIR.parents[0]
for p in (str(TESTS_DIR), str(P1_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

import p1fixture  # noqa: E402
from p1reg import corpus as corpus_mod  # noqa: E402
from p1reg.profiles import profile_ids  # noqa: E402

KNOWN_PROFILES = ("OBSERVE", "PROTECT")


class CorpusFixture(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.root = Path(self._td.name)
        self.docs = [
            p1fixture.minimal_case_doc("WAF-BEN-TST-001", "BENIGN"),
            p1fixture.minimal_case_doc("WAF-ATK-TST-001", "ATTACK"),
        ]
        self.manifest_path = p1fixture.write_corpus(self.root, self.docs)

    def validate(self, manifest_path=None):
        return corpus_mod.validate_corpus(manifest_path or self.manifest_path, KNOWN_PROFILES)[1]

    def rewrite_manifest(self, mut):
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        mut(manifest)
        self.manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


class TestRepoCorpus(unittest.TestCase):
    """仓库自带语料必须持续通过校验（REG-001 正例）。"""

    def setUp(self):
        self.corpus = corpus_mod.require_valid_corpus(
            p1fixture.REPO_MANIFEST, profile_ids(p1fixture.PROFILES_DIR))

    def test_repo_manifest_valid(self):
        _, errors = corpus_mod.validate_corpus(
            p1fixture.REPO_MANIFEST, profile_ids(p1fixture.PROFILES_DIR))
        self.assertEqual(errors, [], "仓库 P1 语料必须通过校验:\n" + "\n".join(errors))

    def test_repo_case_count_and_truth_mix(self):
        docs = [it["doc"] for it in self.corpus["cases"].values()]
        self.assertGreaterEqual(len(docs), 15)
        self.assertLessEqual(len(docs), 25)
        benign = [d for d in docs if d["truth"] == "BENIGN"]
        attack = [d for d in docs if d["truth"] == "ATTACK"]
        self.assertGreaterEqual(len(benign), 5, "不得只有攻击集")
        self.assertGreaterEqual(len(attack), 5)

    def test_repo_only_waf_family_in_s1(self):
        fams = {it["doc"]["family"] for it in self.corpus["cases"].values()}
        self.assertEqual(fams, {"waf"}, "S1 仅交付 waf 类样本，其余族待对应阶段落地后补充")

    def test_repo_partitions_cover_train_and_holdout(self):
        parts = {it["doc"]["dataset_partition"] for it in self.corpus["cases"].values()}
        self.assertIn("TRAIN", parts)
        self.assertIn("HOLDOUT", parts)
        for it in self.corpus["cases"].values():
            doc = it["doc"]
            if doc["truth"] == "ATTACK":
                self.assertNotEqual(doc["dataset_partition"], "TRAIN",
                                    f"{doc['case_id']}: 攻击样本不进训练集")

    def test_repo_all_cases_cover_both_profiles(self):
        for it in self.corpus["cases"].values():
            for pid in ("OBSERVE", "PROTECT"):
                self.assertIn(pid, it["doc"]["expectations_by_profile"], it["doc"]["case_id"])

    def test_repo_all_self_synthetic(self):
        for it in self.corpus["cases"].values():
            self.assertEqual(it["doc"]["source"], "self_synthetic", it["doc"]["case_id"])

    def test_example_run_plan_pins_current_manifest_hash(self):
        from p0bench.plan import sha256_file

        plan = json.loads(p1fixture.RUN_PLAN_EXAMPLE.read_text(encoding="utf-8"))
        actual = sha256_file(p1fixture.REPO_MANIFEST)
        self.assertEqual(plan["corpus"]["manifest_sha256"], actual,
                         "run-plan.example.json 登记的语料哈希与仓库语料不一致（改语料后须同步重登记）")


class TestManifestStructure(CorpusFixture):
    def test_fixture_valid(self):
        self.assertEqual(self.validate(), [])

    def test_unknown_major_version_rejected(self):
        self.rewrite_manifest(lambda m: m.update(schema_version=2))
        self.assertTrue(any("未知 schema 主版本" in e for e in self.validate()))

    def test_schema_version_non_int_rejected(self):
        self.rewrite_manifest(lambda m: m.update(schema_version="1"))
        self.assertTrue(any("schema_version" in e for e in self.validate()))

    def test_missing_top_fields(self):
        for key in ("corpus_id", "created_at", "description"):
            self.rewrite_manifest(lambda m, k=key: m.pop(k))
            self.assertTrue(any(key in e for e in self.validate()), key)
            self.setUp()

    def test_empty_cases_rejected(self):
        self.rewrite_manifest(lambda m: m.update(cases=[]))
        self.assertTrue(any("cases" in e for e in self.validate()))

    def test_duplicate_case_id_rejected(self):
        def mut(m):
            m["cases"].append(dict(m["cases"][0]))
        self.rewrite_manifest(mut)
        self.assertTrue(any("重复 case_id" in e for e in self.validate()))

    def test_duplicate_file_rejected(self):
        def mut(m):
            dup = dict(m["cases"][0])
            dup["case_id"] = "WAF-BEN-TST-002"
            m["cases"].append(dup)
        self.rewrite_manifest(mut)
        self.assertTrue(any("重复引用文件" in e for e in self.validate()))

    def test_entry_missing_content_sha256(self):
        self.rewrite_manifest(lambda m: m["cases"][0].pop("content_sha256"))
        self.assertTrue(any("content_sha256" in e for e in self.validate()))


class TestPathTraversal(CorpusFixture):
    def set_entry_file(self, value):
        self.rewrite_manifest(lambda m: m["cases"][0].update(file=value))

    def test_absolute_path_rejected(self):
        self.set_entry_file("/etc/passwd")
        self.assertTrue(any("绝对路径" in e for e in self.validate()))

    def test_dotdot_rejected(self):
        self.set_entry_file("cases/../manifest.json")
        self.assertTrue(any("路径越界" in e or "'..'" in e for e in self.validate()))

    def test_backslash_rejected(self):
        self.set_entry_file("cases\\x.json")
        self.assertTrue(any("反斜杠" in e for e in self.validate()))

    def test_outside_cases_dir_rejected(self):
        self.set_entry_file("other/waf-ben-tst-001.json")
        self.assertTrue(any("cases/" in e for e in self.validate()))

    def test_nested_subdir_rejected(self):
        self.set_entry_file("cases/sub/waf-ben-tst-001.json")
        self.assertTrue(any("cases/" in e for e in self.validate()))

    def test_non_json_suffix_rejected(self):
        self.set_entry_file("cases/waf-ben-tst-001.txt")
        self.assertTrue(any(".json" in e for e in self.validate()))

    def test_missing_file_rejected(self):
        self.set_entry_file("cases/waf-ben-tst-999.json")
        self.assertTrue(any("不存在" in e for e in self.validate()))

    def test_symlink_escape_rejected(self):
        outside = self.root / "outside.json"
        outside.write_text(json.dumps(self.docs[0]), encoding="utf-8")
        link = self.root / "corpus" / "cases" / "waf-ben-tst-escape.json"
        try:
            link.symlink_to(outside)
        except OSError:
            self.skipTest("当前文件系统不支持 symlink")
        self.set_entry_file("cases/waf-ben-tst-escape.json")
        errors = self.validate()
        self.assertTrue(any("越界" in e for e in errors), errors)


class TestContentHash(CorpusFixture):
    def test_tampered_case_file_detected(self):
        p = self.root / "corpus" / "cases" / "waf-ben-tst-001.json"
        raw = p.read_bytes()
        p.write_bytes(raw[:-2] + b" }\n")  # 改一字节，保持合法 JSON
        errors = self.validate()
        self.assertTrue(any("内容哈希失配" in e for e in errors), errors)

    def test_wrong_registered_hash_detected(self):
        self.rewrite_manifest(lambda m: m["cases"][0].update(content_sha256="0" * 64))
        self.assertTrue(any("内容哈希失配" in e for e in self.validate()))

    def test_case_id_mismatch_entry_vs_file(self):
        self.rewrite_manifest(lambda m: m["cases"][0].update(case_id="WAF-BEN-TST-099"))
        self.assertTrue(any("不一致" in e for e in self.validate()))

    def test_case_version_mismatch_entry_vs_file(self):
        self.rewrite_manifest(lambda m: m["cases"][0].update(case_version=99))
        self.assertTrue(any("不一致" in e for e in self.validate()))

    def test_hash_covers_request_truth_assertion(self):
        """REG-002：改请求/真值/断言任一字段，登记哈希即失配。"""
        p = self.root / "corpus" / "cases" / "waf-ben-tst-001.json"
        doc = json.loads(p.read_text(encoding="utf-8"))
        doc["truth"] = "UNKNOWN"
        doc["criticality"] = "STANDARD"
        p.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        errors = self.validate()
        self.assertTrue(any("内容哈希失配" in e for e in errors), errors)


class TestCaseDocValidation(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.root = Path(self._td.name)

    def validate_doc(self, doc):
        mp = p1fixture.write_corpus(self.root, [doc])
        return corpus_mod.validate_corpus(mp, KNOWN_PROFILES)[1]

    def test_bad_case_id_format(self):
        doc = p1fixture.minimal_case_doc("BAD-ID")
        doc["case_id"] = "BAD-ID"
        errors = self.validate_doc(doc)
        self.assertTrue(any("case_id" in e for e in errors))

    def test_bad_truth_value(self):
        errors = self.validate_doc(p1fixture.minimal_case_doc(truth="MALICIOUS"))
        self.assertTrue(any("truth" in e for e in errors))

    def test_missing_truth_reason(self):
        doc = p1fixture.minimal_case_doc()
        doc["truth_reason"] = ""
        self.assertTrue(any("truth_reason" in e for e in self.validate_doc(doc)))

    def test_unknown_truth_cannot_be_mandatory(self):
        doc = p1fixture.minimal_case_doc("WAF-UNK-TST-001", "UNKNOWN", criticality="MANDATORY")
        self.assertTrue(any("MANDATORY" in e for e in self.validate_doc(doc)))

    def test_deferred_requires_reason(self):
        doc = p1fixture.minimal_case_doc(deferred=True, criticality="STANDARD")
        self.assertTrue(any("deferred_reason" in e for e in self.validate_doc(doc)))

    def test_deferred_cannot_be_mandatory(self):
        doc = p1fixture.minimal_case_doc(deferred=True, deferred_reason="依赖未交付")
        self.assertTrue(any("MANDATORY" in e for e in self.validate_doc(doc)))

    def test_deferred_with_reason_accepted(self):
        doc = p1fixture.minimal_case_doc(
            "WAF-ATK-TST-002", "ATTACK",
            deferred=True, deferred_reason="依赖 P0-04 例外能力",
            criticality="STANDARD")
        self.assertEqual(self.validate_doc(doc), [])

    def test_bad_partition(self):
        doc = p1fixture.minimal_case_doc(dataset_partition="TEST")
        self.assertTrue(any("dataset_partition" in e for e in self.validate_doc(doc)))

    def test_bad_criticality(self):
        doc = p1fixture.minimal_case_doc(criticality="HIGH")
        self.assertTrue(any("criticality" in e for e in self.validate_doc(doc)))

    def test_bad_family(self):
        doc = p1fixture.minimal_case_doc(family="waf2")
        self.assertTrue(any("family" in e for e in self.validate_doc(doc)))

    def test_non_synthetic_source_rejected(self):
        doc = p1fixture.minimal_case_doc(source="third_party_corpus")
        self.assertTrue(any("source" in e for e in self.validate_doc(doc)))

    def test_missing_license_or_authorization(self):
        doc = p1fixture.minimal_case_doc(license="")
        self.assertTrue(any("license" in e for e in self.validate_doc(doc)))
        doc = p1fixture.minimal_case_doc(authorization=" ")
        self.assertTrue(any("authorization" in e for e in self.validate_doc(doc)))

    def test_steps_empty_rejected(self):
        doc = p1fixture.minimal_case_doc(steps=[])
        self.assertTrue(any("steps" in e for e in self.validate_doc(doc)))

    def test_step_unknown_action_rejected(self):
        doc = p1fixture.minimal_case_doc()
        doc["steps"][0]["action"] = "shell_exec"
        self.assertTrue(any("action" in e for e in self.validate_doc(doc)))

    def test_step_duplicate_step_id_rejected(self):
        doc = p1fixture.minimal_case_doc()
        doc["steps"].append(copy.deepcopy(doc["steps"][0]))
        self.assertTrue(any("step_id 重复" in e for e in self.validate_doc(doc)))

    def test_unparseable_assertion_type_rejected(self):
        doc = p1fixture.minimal_case_doc()
        doc["steps"][0]["assert"] = [{"type": "sql_exec", "query": "select 1"}]
        errors = self.validate_doc(doc)
        self.assertTrue(any("无法解析的断言" in e for e in errors), errors)

    def test_assertion_missing_param_rejected(self):
        doc = p1fixture.minimal_case_doc()
        doc["steps"][0]["assert"] = [{"type": "http_status_in"}]
        self.assertTrue(any("statuses" in e for e in self.validate_doc(doc)))

    def test_assertion_bad_status_code_rejected(self):
        doc = p1fixture.minimal_case_doc()
        doc["steps"][0]["assert"] = [{"type": "http_status_in", "statuses": [999]}]
        self.assertTrue(any("statuses" in e for e in self.validate_doc(doc)))

    def test_assertion_extra_param_rejected(self):
        doc = p1fixture.minimal_case_doc()
        doc["steps"][0]["assert"] = [{"type": "header_present", "name": "X-A", "evil": "x"}]
        self.assertTrue(any("不接受参数" in e for e in self.validate_doc(doc)))

    def test_wait_unknown_type_rejected(self):
        doc = p1fixture.minimal_case_doc()
        doc["steps"][0]["wait"] = {"type": "sleep_forever"}
        self.assertTrue(any("无法解析的等待条件" in e for e in self.validate_doc(doc)))

    def test_wait_delay_must_be_positive(self):
        doc = p1fixture.minimal_case_doc()
        doc["steps"][0]["wait"] = {"type": "delay_ms", "ms": 0}
        self.assertTrue(any("正整数" in e for e in self.validate_doc(doc)))

    def test_header_crlf_rejected(self):
        doc = p1fixture.minimal_case_doc()
        doc["steps"][0]["request"]["headers"] = {"X-Test": "a\r\nInjected: b"}
        self.assertTrue(any("CRLF" in e for e in self.validate_doc(doc)))

    def test_method_not_in_vocab_rejected(self):
        doc = p1fixture.minimal_case_doc()
        doc["steps"][0]["request"]["method"] = "CONNECT"
        self.assertTrue(any("method" in e for e in self.validate_doc(doc)))

    def test_reset_flush_valkey_prefix_requires_template_with_run_id(self):
        doc = p1fixture.minimal_case_doc(reset_plan={"scope": "case", "actions": ["flush_valkey_prefix"],
                                                     "valkey_prefix_template": "p1reg:shared:"})
        errors = self.validate_doc(doc)
        self.assertTrue(any("{run_id}" in e for e in errors), errors)

    def test_reset_scope_none_with_real_actions_rejected(self):
        doc = p1fixture.minimal_case_doc(reset_plan={"scope": "none", "actions": ["reset_app_state"]})
        self.assertTrue(any("scope=none" in e for e in self.validate_doc(doc)))

    def test_reset_unknown_action_rejected(self):
        doc = p1fixture.minimal_case_doc(reset_plan={"scope": "run", "actions": ["drop_database"]})
        self.assertTrue(any("未知重置动作" in e for e in self.validate_doc(doc)))

    def test_expectations_missing_profile_rejected(self):
        doc = p1fixture.minimal_case_doc()
        doc["expectations_by_profile"] = {"OBSERVE": doc["expectations_by_profile"]["OBSERVE"]}
        self.assertTrue(any("PROTECT" in e for e in self.validate_doc(doc)))

    def test_expectations_unknown_profile_rejected(self):
        doc = p1fixture.minimal_case_doc()
        doc["expectations_by_profile"]["BOGUS"] = dict(doc["expectations_by_profile"]["OBSERVE"])
        self.assertTrue(any("未知 profile" in e for e in self.validate_doc(doc)))

    def test_expectation_contradiction_none_module_with_block(self):
        doc = p1fixture.minimal_case_doc()
        doc["expectations_by_profile"]["PROTECT"]["expected_final_action"] = "BLOCK_403"
        errors = self.validate_doc(doc)
        self.assertTrue(any("期望矛盾" in e for e in errors), errors)

    def test_expectation_contradiction_module_with_pass(self):
        doc = p1fixture.minimal_case_doc("WAF-ATK-TST-003", "ATTACK")
        doc["expectations_by_profile"]["OBSERVE"]["expected_final_action"] = "PASS"
        errors = self.validate_doc(doc)
        self.assertTrue(any("期望矛盾" in e for e in errors), errors)

    def test_bad_final_action(self):
        doc = p1fixture.minimal_case_doc()
        doc["expectations_by_profile"]["OBSERVE"]["expected_final_action"] = "MAYBE"
        self.assertTrue(any("expected_final_action" in e for e in self.validate_doc(doc)))

    def test_evidence_requirements_unknown_key(self):
        doc = p1fixture.minimal_case_doc(evidence_requirements={"access_log": True, "magic": True})
        self.assertTrue(any("未知证据需求键" in e for e in self.validate_doc(doc)))

    def test_evidence_requirements_all_false(self):
        doc = p1fixture.minimal_case_doc(evidence_requirements={"access_log": False})
        self.assertTrue(any("至少" in e for e in self.validate_doc(doc)))

    def test_seed_non_int_rejected(self):
        doc = p1fixture.minimal_case_doc(seed="42")
        self.assertTrue(any("seed" in e for e in self.validate_doc(doc)))

    def test_benign_must_not_expect_detection(self):
        doc = p1fixture.minimal_case_doc()
        doc["expectations_by_profile"]["OBSERVE"]["expected_detection"] = {"module": "coraza_crs"}
        doc["expectations_by_profile"]["OBSERVE"]["expected_final_action"] = "DETECT_PASS"
        errors = self.validate_doc(doc)
        self.assertTrue(any("BENIGN" in e for e in errors), errors)

    def test_attack_without_any_detection_expectation_rejected(self):
        doc = p1fixture.minimal_case_doc("WAF-ATK-TST-004", "ATTACK")
        for pid in ("OBSERVE", "PROTECT"):
            doc["expectations_by_profile"][pid]["expected_detection"] = {"module": "none"}
            doc["expectations_by_profile"][pid]["expected_final_action"] = "PASS"
            doc["expectations_by_profile"][pid]["expected_origin"] = "reached"
        errors = self.validate_doc(doc)
        self.assertTrue(any("无检测期望" in e for e in errors), errors)


class TestDenominatorPolicy(unittest.TestCase):
    def test_accuracy_cases_excludes_unknown_and_deferred(self):
        _td = tempfile.TemporaryDirectory()
        self.addCleanup(_td.cleanup)
        root = Path(_td.name)
        docs = [
            p1fixture.minimal_case_doc("WAF-BEN-TST-001", "BENIGN"),
            p1fixture.minimal_case_doc("WAF-ATK-TST-001", "ATTACK"),
            p1fixture.minimal_case_doc("WAF-UNK-TST-001", "UNKNOWN"),
            p1fixture.minimal_case_doc("WAF-ATK-TST-002", "ATTACK",
                                       deferred=True, deferred_reason="依赖未交付",
                                       criticality="STANDARD"),
        ]
        mp = p1fixture.write_corpus(root, docs)
        corpus, errors = corpus_mod.validate_corpus(mp, KNOWN_PROFILES)
        self.assertEqual(errors, [], errors)
        active = {it["doc"]["case_id"] for it in corpus_mod.iter_active_cases(corpus)}
        self.assertEqual(active, {"WAF-BEN-TST-001", "WAF-ATK-TST-001", "WAF-UNK-TST-001"})
        accuracy = {it["doc"]["case_id"] for it in corpus_mod.accuracy_cases(corpus)}
        self.assertEqual(accuracy, {"WAF-BEN-TST-001", "WAF-ATK-TST-001"})


if __name__ == "__main__":
    unittest.main()
