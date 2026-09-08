"""p1reg 命令行入口（供 test/performance/p0/run.sh 的 regression/compare 子命令调用，亦可独立使用）。

子命令：
  validate-corpus   --manifest F [--profiles-dir D]   P1 语料 schema v1 + 内容哈希自校验，退出码 2
  corpus-hash       --manifest F                      输出 manifest 文件 sha256
  validate-run-plan --plan F [--profiles-dir D]       回归 run-plan 结构校验，退出码 2
  validate-run-id   --run-id R                        run_id 格式校验（compare 输入防路径逃逸）
  gen-plan          --manifest F --profiles-dir D --seed N [--run-id R]
                                                    生成确定性回放计划（stdout）
  init-cases        --replay-plan F                   由回放计划生成 cases.jsonl NOT_RUN 骨架（stdout）
  write-report      --run-dir D                       只读 run 目录 → report.md
  compare           --baseline D --candidate D [--out D]
                                                    只读两个已完成证据目录逐例配对比较；
                                                    PASS=0，FAIL/NOT_PASSED=1，结构错误=2
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from p0bench.isolation import validate_run_id

from . import compare as compare_mod
from . import corpus as corpus_mod
from . import replayplan
from . import report as report_mod
from . import runplan as runplan_mod
from .profiles import DEFAULT_PROFILE_IDS, ProfileError, profile_ids
from .vocab import REASON_NOT_ATTEMPTED


def _known_profiles(args):
    if getattr(args, "profiles_dir", None):
        try:
            return profile_ids(args.profiles_dir)
        except ProfileError as exc:
            print(str(exc), file=sys.stderr)
            raise SystemExit(2)
    return DEFAULT_PROFILE_IDS


def _cmd_validate_corpus(args) -> int:
    known = _known_profiles(args)
    corpus, errors = corpus_mod.validate_corpus(args.manifest, known)
    if errors:
        for e in errors:
            print(f"CORPUS_ERROR: {e}", file=sys.stderr)
        return 2
    print(f"CORPUS_OK cases={len(corpus['cases'])} manifest_sha256={corpus['manifest_sha256']}")
    return 0


def _cmd_corpus_hash(args) -> int:
    from p0bench.plan import sha256_file

    print(sha256_file(args.manifest))
    return 0


def _cmd_validate_run_plan(args) -> int:
    known = _known_profiles(args)
    try:
        plan = runplan_mod.load_run_plan(args.plan)
    except runplan_mod.RunPlanError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    errors = runplan_mod.validate_run_plan(plan, known)
    if errors:
        for e in errors:
            print(f"RUN_PLAN_ERROR: {e}", file=sys.stderr)
        return 2
    print("RUN_PLAN_OK")
    return 0


def _cmd_validate_run_id(args) -> int:
    if not validate_run_id(args.run_id):
        print(f"RUN_ID_INVALID: {args.run_id!r}", file=sys.stderr)
        return 2
    print("RUN_ID_OK")
    return 0


def _cmd_gen_plan(args) -> int:
    known = _known_profiles(args)
    corpus, errors = corpus_mod.validate_corpus(args.manifest, known)
    if errors:
        for e in errors:
            print(f"CORPUS_ERROR: {e}", file=sys.stderr)
        return 2
    plan = replayplan.generate_plan(corpus, known, args.seed, run_id=args.run_id)
    print(json.dumps(plan, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def _cmd_init_cases(args) -> int:
    """由回放计划生成 cases.jsonl 骨架：全部 NOT_RUN（执行层填充前的诚实初始态）。"""
    try:
        plan = json.loads(Path(args.replay_plan).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"replay-plan 读取失败: {exc}", file=sys.stderr)
        return 2
    if not isinstance(plan, dict) or plan.get("kind") != replayplan.PLAN_KIND:
        print("replay-plan kind 非法", file=sys.stderr)
        return 2
    for e in plan.get("entries", []):
        row = {
            "case_id": e["case_id"],
            "case_version": e["case_version"],
            "profile": e["profile"],
            "truth": e["truth"],
            "criticality": e["criticality"],
            "family": e["family"],
            "dataset_partition": e["dataset_partition"],
            "executed": False,
            "valid": False,
            "status": "NOT_RUN",
            "reasons": [f"{REASON_NOT_ATTEMPTED}: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假）"],
            "detail": {},
        }
        print(json.dumps(row, ensure_ascii=False))
    return 0


def _cmd_write_report(args) -> int:
    try:
        out = report_mod.write_report(args.run_dir)
    except report_mod.ReportError as exc:
        print(f"报告生成失败: {exc}", file=sys.stderr)
        return 2
    print(f"已生成 {out}")
    return 0


def _cmd_compare(args) -> int:
    try:
        doc = compare_mod.compare_runs(args.baseline, args.candidate)
    except compare_mod.CompareError as exc:
        print(f"COMPARE_ERROR: {exc}", file=sys.stderr)
        return 2
    if args.out:
        cj, md = compare_mod.write_compare(doc, args.out)
        print(f"已生成 {cj}")
        print(f"已生成 {md}")
    else:
        print(compare_mod.render_compare_markdown(doc))
    print(f"COMPARE_VERDICT: {doc['verdict']}")
    for r in doc["verdict_reasons"]:
        print(f"  - {r}")
    return 0 if doc["verdict"] == "PASS" else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="p1reg", description="P1-04 规则/模型回归工具（R1 工具层）")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("validate-corpus", help="P1 语料 schema v1 校验（含内容哈希自校验）")
    p.add_argument("--manifest", required=True)
    p.add_argument("--profiles-dir", default=None)
    p.set_defaults(func=_cmd_validate_corpus)

    p = sub.add_parser("corpus-hash", help="输出 manifest 文件 sha256")
    p.add_argument("--manifest", required=True)
    p.set_defaults(func=_cmd_corpus_hash)

    p = sub.add_parser("validate-run-plan", help="回归 run-plan 结构校验")
    p.add_argument("--plan", required=True)
    p.add_argument("--profiles-dir", default=None)
    p.set_defaults(func=_cmd_validate_run_plan)

    p = sub.add_parser("validate-run-id", help="run_id 格式校验")
    p.add_argument("--run-id", required=True)
    p.set_defaults(func=_cmd_validate_run_id)

    p = sub.add_parser("gen-plan", help="生成确定性回放计划（stdout JSON）")
    p.add_argument("--manifest", required=True)
    p.add_argument("--profiles-dir", default=None)
    p.add_argument("--seed", type=int, required=True)
    p.add_argument("--run-id", default=None)
    p.set_defaults(func=_cmd_gen_plan)

    p = sub.add_parser("init-cases", help="由回放计划生成 cases.jsonl NOT_RUN 骨架（stdout JSONL）")
    p.add_argument("--replay-plan", required=True)
    p.set_defaults(func=_cmd_init_cases)

    p = sub.add_parser("write-report", help="只读 run 目录 → report.md")
    p.add_argument("--run-dir", required=True)
    p.set_defaults(func=_cmd_write_report)

    p = sub.add_parser("compare", help="前后版本逐例配对比较（只读证据目录）")
    p.add_argument("--baseline", required=True, help="baseline run 证据目录")
    p.add_argument("--candidate", required=True, help="candidate run 证据目录")
    p.add_argument("--out", default=None, help="比较结果输出目录（缺省仅打印到 stdout）")
    p.set_defaults(func=_cmd_compare)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
