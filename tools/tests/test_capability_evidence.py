#!/usr/bin/env python3
"""tools/capability_evidence.py 的单元测试（P0-01 S1）。

覆盖任务书验收用例 EVD-01～EVD-09。运行方式：
    python3 -m unittest discover -s tools/tests -p 'test_capability_evidence.py'

夹具全部在临时目录中构造（自带 AGENTS.md 作为仓库根标记），不触碰真实仓库数据。
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "capability_evidence.py"
sys.path.insert(0, str(REPO_ROOT / "tools"))

import capability_evidence as ce  # noqa: E402


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def make_capability(cap_id="demo-cap", test_ids=("BENCH-05",), scenarios=None,
                    verification="NOT_RUN", impl="IMPLEMENTED", integ="CONNECTED"):
    cap = {
        "id": cap_id,
        "name": f"能力{cap_id}",
        "owner_module": "demo",
        "product_lines": ["WDSP"],
        "deployment_modes": ["REVERSE_PROXY"],
        "implementation_status": impl,
        "integration_status": integ,
        "verification_status": verification,
        "implementation_refs": [{"path": "src/main.go", "symbol": "main"}],
        "required_test_ids": list(test_ids),
        "prerequisites": [],
        "limitations": [],
        "evidence_refs": [],
    }
    if scenarios is not None:
        cap["scenarios"] = scenarios
    return cap


def make_catalog(caps):
    return {"schema_version": 1, "catalog_id": "test-catalog", "capabilities": caps}


def draft_manifest():
    """任务书 §4.2 的草稿最小示例（check --release 必须拒绝它）。"""
    return {
        "schema_version": 1,
        "build_id": "draft-local",
        "product_version": "unresolved",
        "source": {"commit": None, "dirty": True, "snapshot_sha256": None, "file_manifest": []},
        "images": [],
        "config_fingerprint": None,
        "environment": {"id": "not-provisioned"},
        "started_at": None,
        "ended_at": None,
        "tests": [],
        "release_status": "DEVELOPMENT",
    }


def verified_manifest(tests):
    file_manifest = [{"path": "src/main.go", "sha256": _sha("package main")}]
    return {
        "schema_version": 1,
        "build_id": "build-2026-09-06-001",
        "product_version": "1.0.1",
        "source": {
            "commit": "a" * 40,
            "dirty": False,
            "snapshot_sha256": ce.canonical_snapshot(file_manifest),
            "file_manifest": file_manifest,
        },
        "images": [{
            "name": "jiuzhang-gateway",
            "version": "1.0.1",
            "platform": "linux/amd64",
            "digest": "sha256:" + "0" * 64,
        }],
        "config_fingerprint": "cf-" + "1" * 16,
        "environment": {"os": "linux", "kernel": "6.1", "cpu": "8c", "mem": "16G"},
        "started_at": "2026-09-06T08:00:00Z",
        "ended_at": "2026-09-06T09:00:00Z",
        "tests": tests,
        "release_status": "DEVELOPMENT",
    }


class Workspace:
    """临时仓库/证据包夹具。"""

    def __init__(self, root: Path):
        self.root = root
        (root / "AGENTS.md").write_text("# fixture\n", encoding="utf-8")
        (root / "src").mkdir()
        (root / "src" / "main.go").write_text("package main\n", encoding="utf-8")
        self.catalog_path = root / "docs" / "capabilities" / "capabilities.json"
        self.catalog_path.parent.mkdir(parents=True)
        self.evidence_root = root / "docs" / "evidence" / "releases" / "build-fixture"
        self.artifacts = self.evidence_root / "artifacts"
        self.artifacts.mkdir(parents=True)
        self.manifest_path = self.evidence_root / "manifest.json"

    def artifact(self, name="result.log", content="ok"):
        (self.artifacts / name).write_text(content, encoding="utf-8")
        return {"path": f"artifacts/{name}", "sha256": _sha(content)}

    def write_catalog(self, catalog):
        self.catalog_path.write_text(
            json.dumps(catalog, ensure_ascii=False, indent=2), encoding="utf-8")

    def write_manifest(self, manifest):
        self.manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.ws = Workspace(Path(self._tmp.name))

    def run_check(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = ce.main(["check", "--catalog", str(self.ws.catalog_path),
                            "--manifest", str(self.ws.manifest_path), *extra])
        return code, out.getvalue(), err.getvalue()

    def run_render(self, output):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = ce.main(["render", "--catalog", str(self.ws.catalog_path),
                            "--manifest", str(self.ws.manifest_path),
                            "--output", str(output)])
        return code, out.getvalue(), err.getvalue()

    def run_cli(self, *argv):
        return subprocess.run(
            [sys.executable, str(TOOL_PATH), *argv],
            capture_output=True, text=True, timeout=60)


class TestEvd01UnverifiedNotPass(Base):
    """EVD-01：条目代码存在、没有测试证据 → 已实现与未验证分别显示，不能 PASS。"""

    def test_implemented_but_unverified(self):
        self.ws.write_catalog(make_catalog([make_capability()]))
        self.ws.write_manifest(draft_manifest())
        code, out, _ = self.run_check()
        self.assertEqual(code, 0, "合法未验证草稿 check 应返回 0")
        self.assertIn("结构有效，未完成验收", out)
        self.assertIn("验证=NOT_RUN", out)
        self.assertIn("实现=IMPLEMENTED", out)

    def test_forged_catalog_status_rejected(self):
        cap = make_capability(verification="PASS")  # 手填覆盖，证据计算为 NOT_RUN
        self.ws.write_catalog(make_catalog([cap]))
        self.ws.write_manifest(draft_manifest())
        code, _, err = self.run_check()
        self.assertNotEqual(code, 0)
        self.assertIn("状态伪造", err)
        self.assertIn("verification_status", err)

    def test_forged_release_status_rejected(self):
        manifest = draft_manifest()
        manifest["release_status"] = "RELEASE_VERIFIED"
        self.ws.write_catalog(make_catalog([make_capability()]))
        self.ws.write_manifest(manifest)
        code, _, err = self.run_check()
        self.assertNotEqual(code, 0)
        self.assertIn("状态伪造", err)
        self.assertIn("release_status", err)

    def test_pass_record_without_artifacts_rejected(self):
        manifest = verified_manifest([{
            "id": "BENCH-05", "capabilities": ["demo-cap"],
            "status": "PASS", "command": "bench run",
        }])
        self.ws.write_catalog(make_catalog([make_capability()]))
        self.ws.write_manifest(manifest)
        code, _, err = self.run_check()
        self.assertNotEqual(code, 0)
        self.assertIn("PASS 记录必须附证据工件", err)


class TestEvd02SkipMeansNotRun(Base):
    """EVD-02：一个强制测试 SKIP、进程退出码 0 → 场景 NOT_RUN；发布门槛失败。"""

    def test_skip_scenario_not_run_release_fails(self):
        manifest = verified_manifest([{
            "id": "BENCH-05", "capabilities": ["demo-cap"], "status": "SKIP",
            "command": "bench run", "reason": "环境缺失",
        }])
        self.ws.write_catalog(make_catalog([make_capability()]))
        self.ws.write_manifest(manifest)
        code, out, _ = self.run_check()
        self.assertEqual(code, 0, "SKIP 记录结构合法，check 应返回 0")
        self.assertIn("验证=NOT_RUN", out)
        code, _, err = self.run_check("--release")
        self.assertEqual(code, 1)
        self.assertIn("NOT_RUN", err)


class TestEvd03BuildBindingMismatch(Base):
    """EVD-03：证据 commit/dirty 快照/镜像/有效配置不匹配 → 拒绝绑定并说明冲突。"""

    def _manifest_with_record(self, extra):
        rec = {"id": "BENCH-05", "capabilities": ["demo-cap"], "status": "SKIP",
               "reason": "x"}
        rec.update(extra)
        return verified_manifest([rec])

    def test_build_id_mismatch(self):
        m = self._manifest_with_record({"build_id": "other-build"})
        self.ws.write_catalog(make_catalog([make_capability()]))
        self.ws.write_manifest(m)
        code, _, err = self.run_check()
        self.assertNotEqual(code, 0)
        self.assertIn("构建绑定不匹配", err)
        self.assertIn("build_id", err)

    def test_commit_mismatch(self):
        m = self._manifest_with_record({"commit": "b" * 40})
        self.ws.write_catalog(make_catalog([make_capability()]))
        self.ws.write_manifest(m)
        code, _, err = self.run_check()
        self.assertNotEqual(code, 0)
        self.assertIn("构建绑定不匹配", err)
        self.assertIn("commit", err)

    def test_config_fingerprint_mismatch(self):
        m = self._manifest_with_record({"config_fingerprint": "cf-" + "9" * 16})
        self.ws.write_catalog(make_catalog([make_capability()]))
        self.ws.write_manifest(m)
        code, _, err = self.run_check()
        self.assertNotEqual(code, 0)
        self.assertIn("构建绑定不匹配", err)
        self.assertIn("config_fingerprint", err)

    def test_image_digest_missing_fails_release(self):
        m = verified_manifest([{
            "id": "BENCH-05", "capabilities": ["demo-cap"], "status": "PASS",
            "artifacts": [self.ws.artifact()],
        }])
        m["images"][0]["digest"] = None
        cap = make_capability(verification="PASS")
        self.ws.write_catalog(make_catalog([cap]))
        self.ws.write_manifest(m)
        code, _, err = self.run_check("--release")
        self.assertEqual(code, 1)
        self.assertIn("digest", err)

    def test_image_latest_tag_rejected(self):
        m = verified_manifest([])
        m["images"][0]["version"] = "latest"
        self.ws.write_catalog(make_catalog([make_capability()]))
        self.ws.write_manifest(m)
        code, _, err = self.run_check()
        self.assertNotEqual(code, 0)
        self.assertIn("latest", err)


class TestEvd04TamperAndDuplicateIds(Base):
    """EVD-04：篡改报告文件、删除文件、重复测试/能力 ID → 校验失败且能定位。"""

    def _write_pass_setup(self):
        art = self.ws.artifact()
        m = verified_manifest([{
            "id": "BENCH-05", "capabilities": ["demo-cap"], "status": "PASS",
            "artifacts": [art],
        }])
        self.ws.write_catalog(make_catalog([make_capability(verification="PASS")]))
        self.ws.write_manifest(m)
        return art

    def test_tampered_artifact(self):
        self._write_pass_setup()
        (self.ws.artifacts / "result.log").write_text("tampered", encoding="utf-8")
        code, _, err = self.run_check()
        self.assertNotEqual(code, 0)
        self.assertIn("哈希不符", err)
        self.assertIn("artifacts/result.log", err)

    def test_deleted_artifact(self):
        self._write_pass_setup()
        (self.ws.artifacts / "result.log").unlink()
        code, _, err = self.run_check()
        self.assertNotEqual(code, 0)
        self.assertIn("路径不存在", err)

    def test_duplicate_test_id(self):
        art = self.ws.artifact()
        rec = {"id": "BENCH-05", "capabilities": ["demo-cap"], "status": "PASS",
               "artifacts": [art]}
        m = verified_manifest([rec, dict(rec)])
        self.ws.write_catalog(make_catalog([make_capability()]))
        self.ws.write_manifest(m)
        code, _, err = self.run_check()
        self.assertNotEqual(code, 0)
        self.assertIn("测试 ID 重复", err)
        self.assertIn("BENCH-05", err)

    def test_duplicate_capability_id(self):
        self.ws.write_catalog(make_catalog([make_capability(), make_capability()]))
        self.ws.write_manifest(draft_manifest())
        code, _, err = self.run_check()
        self.assertNotEqual(code, 0)
        self.assertIn("能力 ID 重复", err)
        self.assertIn("demo-cap", err)

    def test_broken_evidence_ref(self):
        cap = make_capability()
        cap["evidence_refs"] = ["BENCH-99"]
        self.ws.write_catalog(make_catalog([cap]))
        self.ws.write_manifest(draft_manifest())
        code, _, err = self.run_check()
        self.assertNotEqual(code, 0)
        self.assertIn("断链", err)
        self.assertIn("BENCH-99", err)


class TestEvd05PathAndCommandSafety(Base):
    """EVD-05：路径越界/符号链接越界/URL/恶意 command → 拒绝；不发请求、不执行命令。"""

    def _manifest_with_artifact_path(self, path):
        return verified_manifest([{
            "id": "BENCH-05", "capabilities": ["demo-cap"], "status": "PASS",
            "artifacts": [{"path": path, "sha256": "0" * 64}],
        }])

    def _expect_rejected(self, manifest, keyword):
        self.ws.write_catalog(make_catalog([make_capability()]))
        self.ws.write_manifest(manifest)
        code, _, err = self.run_check()
        self.assertNotEqual(code, 0)
        self.assertIn(keyword, err)

    def test_dotdot_escape(self):
        self._expect_rejected(self._manifest_with_artifact_path("../../outside.log"), "路径越界")

    def test_absolute_path_outside(self):
        self._expect_rejected(self._manifest_with_artifact_path("/etc/passwd"), "路径越界")

    def test_symlink_escape(self):
        outside = self.ws.root / "secret.log"
        outside.write_text("secret", encoding="utf-8")
        link = self.ws.artifacts / "link.log"
        link.symlink_to(outside)
        self._expect_rejected(self._manifest_with_artifact_path("artifacts/link.log"), "路径越界")

    def test_url_rejected_no_fetch(self):
        self._expect_rejected(
            self._manifest_with_artifact_path("https://example.invalid/x.log"), "不允许远程 URL")

    def test_implementation_ref_escape(self):
        cap = make_capability()
        cap["implementation_refs"] = [{"path": "../../../etc/passwd"}]
        self.ws.write_catalog(make_catalog([cap]))
        self.ws.write_manifest(draft_manifest())
        code, _, err = self.run_check()
        self.assertNotEqual(code, 0)
        self.assertIn("路径越界", err)

    def test_command_never_executed(self):
        marker = self.ws.root / "pwned"
        m = verified_manifest([{
            "id": "BENCH-05", "capabilities": ["demo-cap"], "status": "SKIP",
            "reason": "x", "command": f"touch {marker} && curl https://evil.invalid",
        }])
        self.ws.write_catalog(make_catalog([make_capability()]))
        self.ws.write_manifest(m)
        code, _, _ = self.run_check()
        self.assertEqual(code, 0)
        self.assertFalse(marker.exists(), "command 字段只作审计文本，绝不执行")


class TestEvd06SchemaEnumTime(Base):
    """EVD-06：不支持的 schema 版本、错误枚举/时间 → 明确失败，不按默认 PASS 容错。"""

    def test_unsupported_catalog_schema_version(self):
        cat = make_catalog([make_capability()])
        cat["schema_version"] = 2
        self.ws.write_catalog(cat)
        self.ws.write_manifest(draft_manifest())
        code, _, err = self.run_check()
        self.assertNotEqual(code, 0)
        self.assertIn("schema_version", err)

    def test_unsupported_manifest_schema_version(self):
        m = draft_manifest()
        m["schema_version"] = 99
        self.ws.write_catalog(make_catalog([make_capability()]))
        self.ws.write_manifest(m)
        code, _, err = self.run_check()
        self.assertNotEqual(code, 0)
        self.assertIn("schema_version", err)

    def test_bad_test_status_enum(self):
        m = verified_manifest([{"id": "BENCH-05", "capabilities": [], "status": "PASSED"}])
        self.ws.write_catalog(make_catalog([make_capability()]))
        self.ws.write_manifest(m)
        code, _, err = self.run_check()
        self.assertNotEqual(code, 0)
        self.assertIn("非法枚举值", err)

    def test_not_applicable_requires_reason(self):
        m = verified_manifest([{"id": "BENCH-05", "capabilities": [], "status": "NOT_APPLICABLE"}])
        self.ws.write_catalog(make_catalog([make_capability()]))
        self.ws.write_manifest(m)
        code, _, err = self.run_check()
        self.assertNotEqual(code, 0)
        self.assertIn("NOT_APPLICABLE", err)

    def test_bad_time_format(self):
        m = draft_manifest()
        m["started_at"] = "2026-13-40 25:61"
        self.ws.write_catalog(make_catalog([make_capability()]))
        self.ws.write_manifest(m)
        code, _, err = self.run_check()
        self.assertNotEqual(code, 0)
        self.assertIn("started_at", err)

    def test_ended_before_started(self):
        m = draft_manifest()
        m["started_at"] = "2026-09-06T09:00:00Z"
        m["ended_at"] = "2026-09-06T08:00:00Z"
        self.ws.write_catalog(make_catalog([make_capability()]))
        self.ws.write_manifest(m)
        code, _, err = self.run_check()
        self.assertNotEqual(code, 0)
        self.assertIn("早于开始时间", err)


class TestEvd07DeterministicRenderAndAtomicWrite(Base):
    """EVD-07：同输入生成两次输出确定；生成中注入写入失败时原文件完整。"""

    def _setup(self):
        art = self.ws.artifact()
        m = verified_manifest([{
            "id": "BENCH-05", "capabilities": ["demo-cap"], "status": "PASS",
            "artifacts": [art],
        }])
        m["release_status"] = "RELEASE_VERIFIED"
        self.ws.write_catalog(make_catalog([make_capability(verification="PASS")]))
        self.ws.write_manifest(m)

    def test_render_deterministic(self):
        self._setup()
        out1 = self.ws.root / "r1.md"
        out2 = self.ws.root / "r2.md"
        code, _, _ = self.run_render(out1)
        self.assertEqual(code, 0)
        code, _, _ = self.run_render(out2)
        self.assertEqual(code, 0)
        self.assertEqual(out1.read_bytes(), out2.read_bytes(), "同一输入两次生成必须逐字节一致")

    def test_render_failure_preserves_original(self):
        self._setup()
        out = self.ws.root / "report.md"
        out.write_text("ORIGINAL", encoding="utf-8")
        original_replace = ce.os.replace

        def boom(*a, **k):
            raise OSError("注入的写入失败")

        ce.os.replace = boom
        try:
            with self.assertRaises(OSError):
                ce.atomic_write(out, "NEW CONTENT")
        finally:
            ce.os.replace = original_replace
        self.assertEqual(out.read_text(encoding="utf-8"), "ORIGINAL")
        leftovers = [p for p in out.parent.iterdir() if p.name.endswith(".tmp")]
        self.assertEqual(leftovers, [], "失败时不得残留临时文件")

    def test_render_does_not_mutate_catalog(self):
        self._setup()
        before = self.ws.catalog_path.read_bytes()
        code, _, _ = self.run_render(self.ws.root / "r.md")
        self.assertEqual(code, 0)
        self.assertEqual(self.ws.catalog_path.read_bytes(), before, "render 不得改变源清单")


class TestEvd08SnapshotChangesWithUntrackedSource(Base):
    """EVD-08：增加影响构建的未跟踪源码 → 快照摘要改变；旧快照证据不能继续用。"""

    def test_untracked_file_changes_snapshot(self):
        entries1 = ce.build_file_manifest(self.ws.root,
                                          exclude_names=(".git", "docs",))
        snap1 = ce.canonical_snapshot(entries1)
        # 新增未跟踪源码（不走 git diff 也能被发现）
        (self.ws.root / "src" / "new_untracked.go").write_text("package main // new\n",
                                                               encoding="utf-8")
        entries2 = ce.build_file_manifest(self.ws.root,
                                          exclude_names=(".git", "docs",))
        snap2 = ce.canonical_snapshot(entries2)
        self.assertNotEqual(snap1, snap2, "新增未跟踪源码必须改变快照摘要")

    def test_stale_snapshot_rejected(self):
        entries = [{"path": "src/main.go", "sha256": _sha("package main")}]
        stale = ce.canonical_snapshot(entries)
        m = verified_manifest([])
        # 声明旧快照，但清单已包含新文件 → 不一致必须拒绝
        m["source"]["file_manifest"] = entries + [
            {"path": "src/new_untracked.go", "sha256": _sha("package main // new")}]
        m["source"]["snapshot_sha256"] = stale
        self.ws.write_catalog(make_catalog([make_capability()]))
        self.ws.write_manifest(m)
        code, _, err = self.run_check()
        self.assertNotEqual(code, 0)
        self.assertIn("快照摘要与 file_manifest 不一致", err)


class TestEvd09ApmAgentScenarioAnnotation(Base):
    """EVD-09：APM 有页面无探针/数据面、Agent 某模式未实测 → 分场景标注，不宣称全能力通过。"""

    def _catalog(self):
        apm = make_capability(
            cap_id="apm-entry", test_ids=("BENCH-05", "BENCH-08"),
            scenarios=[
                {"id": "gateway-entry", "name": "网关入口性能", "deployment_mode": "REVERSE_PROXY",
                 "mandatory": True, "required_test_ids": ["BENCH-05"],
                 "note": "入口性能不等于代码级观测。"},
                {"id": "apm-probe", "name": "探针+数据面", "deployment_mode": "APM_PROBE",
                 "mandatory": True, "required_test_ids": ["BENCH-08"],
                 "note": "Trace/SQL/异常取决于对应采集是否部署。"},
            ])
        apm["prerequisites"] = ["ClickHouse 数据面可用"]
        apm["limitations"] = ["入口性能≠代码级观测：无探针时不能展示 Trace/SQL/异常"]
        agent = make_capability(
            cap_id="agent-capture", test_ids=("BENCH-10",),
            scenarios=[
                {"id": "agent-pipeline", "name": "Agent 采集转发", "deployment_mode": "AGENT",
                 "mandatory": True, "required_test_ids": ["BENCH-10"],
                 "note": "未实现阶段单独标明，不得由 Caddy 网关同类协议支持反推。"},
            ],
            impl="PARTIAL", integ="PARTIAL")
        agent["deployment_modes"] = ["AGENT", "MIRROR"]
        agent["limitations"] = ["Agent 未实现阶段见 docs/agents/WDSP_AGENT_REMAINING_WORK.md，单独标明"]
        return make_catalog([apm, agent])

    def test_scenario_split_annotation(self):
        art = self.ws.artifact()
        m = verified_manifest([{
            "id": "BENCH-05", "capabilities": ["apm-entry"], "status": "PASS",
            "artifacts": [art],
        }])
        self.ws.write_catalog(self._catalog())
        self.ws.write_manifest(m)
        code, out, _ = self.run_check()
        self.assertEqual(code, 0)
        self.assertIn("验证=NOT_RUN", out)

        report = self.ws.root / "cap.md"
        code, _, _ = self.run_render(report)
        self.assertEqual(code, 0)
        text = report.read_text(encoding="utf-8")
        self.assertIn("`gateway-entry`（网关入口性能，强制）：PASS", text)
        self.assertIn("`apm-probe`（探针+数据面，强制）：NOT_RUN", text)
        self.assertIn("BENCH-08：无测试记录（缺失）", text)
        self.assertIn("入口性能≠代码级观测", text)
        self.assertIn("未实现阶段", text)
        # 一个可用场景不能覆盖其他必测场景：能力汇总不得为 PASS
        overview = [ln for ln in text.splitlines() if "apm-entry" in ln and "|" in ln]
        self.assertTrue(any("NOT_RUN" in ln for ln in overview))
        self.assertFalse(any("| PASS |" in ln and "apm-entry" in ln for ln in overview))


class TestReleaseGateEndToEnd(Base):
    """EVD-12 工具侧门槛：齐全才 RELEASE_VERIFIED；草稿最小示例必须被拒绝。"""

    def test_full_evidence_release_verified(self):
        art = self.ws.artifact()
        m = verified_manifest([{
            "id": "BENCH-05", "capabilities": ["demo-cap"], "status": "PASS",
            "artifacts": [art],
        }])
        m["release_status"] = "RELEASE_VERIFIED"
        self.ws.write_catalog(make_catalog([make_capability(verification="PASS")]))
        self.ws.write_manifest(m)
        code, out, _ = self.run_check("--release")
        self.assertEqual(code, 0)
        self.assertIn("RELEASE_VERIFIED", out)

    def test_draft_rejected_by_release_flag_via_cli(self):
        self.ws.write_catalog(make_catalog([make_capability()]))
        self.ws.write_manifest(draft_manifest())
        proc = self.run_cli("check", "--catalog", str(self.ws.catalog_path),
                            "--manifest", str(self.ws.manifest_path), "--release")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("发布门槛未满足", proc.stderr)

    def test_draft_check_via_cli_exit_zero_with_annotation(self):
        self.ws.write_catalog(make_catalog([make_capability()]))
        self.ws.write_manifest(draft_manifest())
        proc = self.run_cli("check", "--catalog", str(self.ws.catalog_path),
                            "--manifest", str(self.ws.manifest_path))
        self.assertEqual(proc.returncode, 0)
        self.assertIn("结构有效，未完成验收", proc.stdout)

    def test_blocked_record_release_fails(self):
        m = verified_manifest([{
            "id": "BENCH-05", "capabilities": ["demo-cap"], "status": "BLOCKED",
            "reason": "ENVIRONMENT_UNAVAILABLE",
        }])
        cap = make_capability(verification="BLOCKED")
        self.ws.write_catalog(make_catalog([cap]))
        self.ws.write_manifest(m)
        code, _, err = self.run_check("--release")
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED", err)


class TestRealRepoCatalog(unittest.TestCase):
    """对仓库内真实清单做冒烟校验：结构合法、引用路径存在、与累计真实证据一致。"""

    def test_repo_catalog_valid_against_latest_manifest(self):
        catalog = REPO_ROOT / "docs" / "capabilities" / "capabilities.json"
        releases = REPO_ROOT / "docs" / "evidence" / "releases"
        # draft-local 是空 tests 的工具自检夹具；清单 evidence_refs 非空后必须用真实证据包校验
        candidates = sorted(
            d / "manifest.json"
            for d in releases.iterdir()
            if d.is_dir() and d.name != "draft-local" and (d / "manifest.json").exists()
        ) if releases.exists() else []
        if not catalog.exists() or not candidates:
            self.skipTest("仓库清单或证据 manifest 尚未生成")
        # 清单按阶段累计引用多个证据包（如 jwt-verification→S3 包、waf-exceptions→S4 包），
        # 而校验器只接受单个 manifest 且要求 evidence_refs 在其中闭合；故将全部真实证据包的
        # tests 合并为临时视图（工件路径相对 docs/evidence/ 重写，sha256 原样沿用）再校验。
        # 同一验收 ID 被后续包重新冻结（如 S6 refreeze 绑定新构建）时，以排序靠后的新包记录为准。
        merged_tests = []
        merged_index = {}
        latest = None
        for manifest_path in candidates:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            latest = data
            for rec in data.get("tests", []):
                rec = dict(rec)
                rec["artifacts"] = [
                    {"path": f"releases/{manifest_path.parent.name}/{art['path']}",
                     "sha256": art["sha256"]}
                    for art in rec.get("artifacts", [])
                ]
                if rec["id"] in merged_index:
                    merged_tests[merged_index[rec["id"]]] = rec
                else:
                    merged_index[rec["id"]] = len(merged_tests)
                    merged_tests.append(rec)
        merged = {k: v for k, v in latest.items() if k != "tests"}
        merged["build_id"] = "merged-check-view"
        merged["tests"] = merged_tests
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                    "w", encoding="utf-8", suffix=".manifest.json",
                    prefix=".merged-check-", dir=releases.parent, delete=False) as fh:
                json.dump(merged, fh, ensure_ascii=False)
                tmp_path = Path(fh.name)
            proc = subprocess.run(
                [sys.executable, str(TOOL_PATH), "check", "--catalog", str(catalog),
                 "--manifest", str(tmp_path)], capture_output=True, text=True, timeout=60)
        finally:
            if tmp_path is not None:
                tmp_path.unlink(missing_ok=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("结构有效，未完成验收", proc.stdout)
        # 期望状态分布以清单声明为准（工具已校验声明值与证据计算值一致）
        declared = [c["verification_status"]
                    for c in json.loads(catalog.read_text(encoding="utf-8"))["capabilities"]]
        for status in ("NOT_RUN", "PASS", "FAIL", "BLOCKED"):
            self.assertEqual(proc.stdout.count(f"验证={status}"), declared.count(status),
                             f"{status} 能力数应与清单一致")


if __name__ == "__main__":
    unittest.main()
