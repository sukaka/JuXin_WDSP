"""P1 回归 run-plan 结构校验（kind=p1_regression_run_plan）。

与 P0 run-plan 的关系：P0 计划面向七模式性能/长稳测量（p0bench.plan 校验口径
不动）；回归计划面向“同一语料 × OBSERVE/PROTECT 的前后版本配对回放”，
只保留回归必需字段。两 schema 以 kind 字段区分，禁止混用。
"""

from __future__ import annotations

import json
from pathlib import Path

from p0bench.plan import COMMIT_RE, PLAN_ID_RE, RFC3339_RE, SHA256_RE

from .profiles import DEFAULT_PROFILE_IDS

KIND = "p1_regression_run_plan"
PURPOSES = ("BASELINE", "CANDIDATE", "SMOKE")


class RunPlanError(Exception):
    """回归 run-plan 不满足契约。"""


def load_run_plan(path: str | Path) -> dict:
    p = Path(path)
    try:
        with p.open("r", encoding="utf-8") as fh:
            plan = json.load(fh)
    except FileNotFoundError as exc:
        raise RunPlanError(f"回归 run-plan 不存在: {p}") from exc
    except json.JSONDecodeError as exc:
        raise RunPlanError(f"回归 run-plan 不是合法 JSON: {p}: {exc}") from exc
    if not isinstance(plan, dict):
        raise RunPlanError("回归 run-plan 顶层必须是 JSON 对象")
    return plan


def _err(errors: list[str], path: str, msg: str) -> None:
    errors.append(f"{path}: {msg}")


def validate_run_plan(plan: dict, known_profiles=DEFAULT_PROFILE_IDS) -> list[str]:
    errors: list[str] = []
    if not isinstance(plan, dict):
        return ["run-plan 顶层必须是 JSON 对象"]
    if plan.get("schema_version") != 1:
        _err(errors, "schema_version", "必须为 1")
    if plan.get("kind") != KIND:
        _err(errors, "kind", f"必须为 {KIND!r}（与 P0 性能计划区分，禁止混用）")
    plan_id = plan.get("plan_id")
    if not isinstance(plan_id, str) or not PLAN_ID_RE.match(plan_id):
        _err(errors, "plan_id", "必须匹配 plan-YYYYMMDDTHHMMSS-xxxxxx")
    created = plan.get("created_at")
    if not isinstance(created, str) or not RFC3339_RE.match(created):
        _err(errors, "created_at", "必须为 RFC3339 时间戳")
    if plan.get("purpose") not in PURPOSES:
        _err(errors, "purpose", f"必须为 {PURPOSES} 之一（BASELINE=改动前基线）")

    env = plan.get("environment")
    if not isinstance(env, dict):
        _err(errors, "environment", "缺必填字段或类型错误")
    else:
        eid = env.get("environment_id")
        if not isinstance(eid, str) or len(eid) < 8:
            _err(errors, "environment.environment_id", "必须是不短于 8 字符的环境唯一标识")
        iso = env.get("isolation")
        if not isinstance(iso, dict):
            _err(errors, "environment.isolation", "缺必填字段（隔离方式必须登记）")
        else:
            if iso.get("mode") not in ("compose_project", "dedicated_host"):
                _err(errors, "environment.isolation.mode", "必须为 compose_project 或 dedicated_host")
            rt = iso.get("registered_targets")
            if not isinstance(rt, list) or not all(isinstance(t, str) for t in rt):
                _err(errors, "environment.isolation.registered_targets", "必须为字符串数组")
        clock = env.get("clock")
        if not isinstance(clock, dict) or not (isinstance(clock.get("max_skew_ms"), int) and clock.get("max_skew_ms", 0) >= 1):
            _err(errors, "environment.clock.max_skew_ms", "必须为正整数毫秒")

    build = plan.get("build")
    if not isinstance(build, dict):
        _err(errors, "build", "缺必填字段（回归必须绑定执行构建）")
    else:
        commit = build.get("git_commit")
        if not isinstance(commit, str) or not COMMIT_RE.match(commit):
            _err(errors, "build.git_commit", "必须为 7-40 位小写十六进制提交号")
        if not isinstance(build.get("worktree_dirty"), bool):
            _err(errors, "build.worktree_dirty", "必须为布尔值")

    corpus = plan.get("corpus")
    if not isinstance(corpus, dict):
        _err(errors, "corpus", "缺必填字段")
    else:
        if not isinstance(corpus.get("manifest_path"), str) or not corpus.get("manifest_path"):
            _err(errors, "corpus.manifest_path", "必须为非空字符串（仓库内相对路径）")
        mh = corpus.get("manifest_sha256")
        if not isinstance(mh, str) or not SHA256_RE.match(mh):
            _err(errors, "corpus.manifest_sha256", "必须为 64 位小写 sha256")
        if not isinstance(corpus.get("seed"), int) or isinstance(corpus.get("seed"), bool):
            _err(errors, "corpus.seed", "必须为整数（固定随机种子）")

    profiles = plan.get("profiles")
    if not isinstance(profiles, list) or not profiles:
        _err(errors, "profiles", "必须为非空数组")
    else:
        for i, pid in enumerate(profiles):
            if pid not in known_profiles:
                _err(errors, f"profiles[{i}]", f"未知 profile {pid!r}（已登记: {list(known_profiles)}）")
        if len(set(profiles)) != len(profiles):
            _err(errors, "profiles", "存在重复 profile")
    return errors


def require_valid_run_plan(plan: dict, known_profiles=DEFAULT_PROFILE_IDS) -> None:
    errors = validate_run_plan(plan, known_profiles)
    if errors:
        raise RunPlanError("回归 run-plan 不满足契约：\n" + "\n".join(f"  - {e}" for e in errors))
