#!/usr/bin/env python3
"""pack_evidence.py — 把 p1reg 真实回放证据目录打包为 R3 受控登记导入包
（WDSP P1-04 R4b；任务书 §6.2/§7.1）。

输入：run.sh regression 真实回放产出的证据目录（cases.jsonl/perf.jsonl/
report.md/plan.json/replay-plan.json）+ 候选配置指纹（cfgfpv1:<hash>，
取自负载该候选的 gateway_config_versions.configuration_hash）。

输出（--out-dir 下）：
  cases-chunk-001.raw.json   用例分块原始 JSON（需 regsign canonicalize 后上传）
  manifest.raw.json          报告清单原始 JSON（同上；files[].sha256/size_bytes
                             按「规范形分块字节 + report/perf 原文字节」填写）
  pack-index.json            打包留痕（各文件 sha256、计数对账、口径说明）

口径（与 server/internal/regression/manifest.go 对齐）：
  - 分块 case_id 唯一性：p1reg cases.jsonl 每例双 profile 两行，本工具以
    "<case_id>@<PROFILE>" 组合键作为分块 case_id（pack-index 留痕说明）；
  - declared_status 如实取 cases.jsonl 汇总（任一 FAIL 即 FAIL），不伪造 PASS；
  - counts 由分块实际内容统计，与服务端 ReconcileCounts 同口径；
  - 时间：run_started_at= replay-plan.json mtime，run_finished_at= report.md
    mtime，created_at=打包时刻（均 UTC RFC3339）；
  - 仅标准库。
"""
import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

CHUNK_NAME = "cases-chunk-001.json"
REPORT_NAME = "report.md"
PERF_NAME = "perf.jsonl"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def rfc3339(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True, help="p1reg 证据目录")
    ap.add_argument("--fingerprint", required=True, help="cfgfpv1:<configuration_hash>")
    ap.add_argument("--level", default="FULL", choices=["SMOKE", "FULL", "RELEASE"])
    ap.add_argument("--corpus-version", type=int, default=1)
    ap.add_argument("--compiler", default="coraza-caddy/CRS (stage5 compose image)")
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    rd = args.run_dir
    cases_path = os.path.join(rd, "cases.jsonl")
    perf_path = os.path.join(rd, "perf.jsonl")
    report_path = os.path.join(rd, "report.md")
    plan_path = os.path.join(rd, "plan.json")
    replay_path = os.path.join(rd, "replay-plan.json")
    for p in (cases_path, perf_path, report_path, plan_path, replay_path):
        if not os.path.isfile(p):
            print("缺少证据文件: " + p, file=sys.stderr)
            return 2

    plan = json.load(open(plan_path))
    corpus = plan.get("corpus") or {}
    build = plan.get("build") or {}
    corpus_sha256 = corpus.get("manifest_sha256", "")
    corpus_id = os.path.splitext(os.path.basename(corpus.get("manifest_path", "")))[0] or "unknown"
    # corpus_id 以语料清单自身声明为准（plan 只登记路径）
    try:
        corpus_id = json.load(open(corpus.get("manifest_path"))).get("corpus_id", corpus_id)
    except Exception:
        pass
    if not corpus_sha256 or not args.fingerprint.startswith("cfgfpv1:"):
        print("plan 缺 corpus.manifest_sha256 或指纹非法", file=sys.stderr)
        return 2

    cases = []
    with open(cases_path) as f:
        for line in f:
            line = line.strip()
            if line:
                cases.append(json.loads(line))
    if not cases:
        print("cases.jsonl 为空", file=sys.stderr)
        return 2

    chunk_cases = []
    for c in cases:
        detail = c.get("detail") or {}
        action = detail.get("action") or {}
        # 词表映射：p1reg 语料 criticality 为 MANDATORY/STANDARD；服务端登记
        # schema（manifest.go CaseResult）为 MANDATORY/OPTIONAL——STANDARD 映射为
        # OPTIONAL 并在 pack-index 留痕（强制口径不变：仅 MANDATORY 进强制计数）。
        crit = c.get("criticality", "")
        if crit == "STANDARD":
            crit = "OPTIONAL"
        entry = {
            "case_id": "%s@%s" % (c["case_id"], c.get("profile", "")),
            "case_version": c.get("case_version", 1),
            "criticality": crit,
            "diff": {
                "detection": detail.get("detection"),
                "action": action,
                "origin": detail.get("origin"),
                "reasons": c.get("reasons") or [],
            },
            "expected_action": action.get("expected", ""),
            "family": c.get("family", ""),
            "observed_action": action.get("observed", ""),
            "status": c.get("status", ""),
            "truth": c.get("truth", ""),
        }
        chunk_cases.append(entry)

    run_id = json.load(open(os.path.join(rd, "manifest.json"))).get("run_id") or os.path.basename(rd.rstrip("/"))
    chunk = {"schema_version": 1, "run_id": run_id, "cases": sorted(chunk_cases, key=lambda x: x["case_id"])}

    os.makedirs(args.out_dir, exist_ok=True)
    chunk_raw = os.path.join(args.out_dir, "cases-chunk-001.raw.json")
    with open(chunk_raw, "w", encoding="utf-8") as f:
        json.dump(chunk, f, ensure_ascii=False, indent=1, sort_keys=True)

    # 计数（与 ReconcileCounts 同口径）
    n = {"planned": 0, "executed": 0, "skipped": 0, "blocked": 0, "not_run": 0,
         "passed": 0, "failed": 0, "mandatory_total": 0, "mandatory_failed": 0}
    for cs in chunk["cases"]:
        n["planned"] += 1
        st = cs["status"]
        if st == "PASS":
            n["executed"] += 1
            n["passed"] += 1
        elif st == "FAIL":
            n["executed"] += 1
            n["failed"] += 1
        elif st == "SKIP":
            n["skipped"] += 1
        elif st == "BLOCKED":
            n["blocked"] += 1
        elif st == "NOT_RUN":
            n["not_run"] += 1
        if cs["criticality"] == "MANDATORY":
            n["mandatory_total"] += 1
            if st != "PASS":
                n["mandatory_failed"] += 1
    declared = "PASS" if (n["failed"] == 0 and n["executed"] == n["planned"] and n["planned"] > 0) else "FAIL"

    # files 哈希：分块按规范形字节（调用方 canonicalize 后须与 index 复核），
    # report/perf 按原文字节。规范形在 shell 侧由 regsign 产出后回填——此处先
    # 按「紧凑 sort_keys 无 HTML 转义」直接生成规范形等价字节并自证。
    def canon_bytes(obj):
        return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":")).encode("utf-8")

    chunk_canon = canon_bytes(chunk)
    files = [
        {"role": "CASES_CHUNK", "name": CHUNK_NAME,
         "sha256": hashlib.sha256(chunk_canon).hexdigest(), "size_bytes": len(chunk_canon)},
        {"role": "REPORT", "name": REPORT_NAME,
         "sha256": sha256_file(report_path), "size_bytes": os.path.getsize(report_path)},
        {"role": "PERF", "name": PERF_NAME,
         "sha256": sha256_file(perf_path), "size_bytes": os.path.getsize(perf_path)},
    ]

    manifest = {
        "schema_version": 1,
        "run_id": run_id,
        "level": args.level,
        "created_at": rfc3339(datetime.now(tz=timezone.utc).timestamp()),
        "run_started_at": rfc3339(os.path.getmtime(replay_path)),
        "run_finished_at": rfc3339(os.path.getmtime(report_path)),
        "declared_status": declared,
        "candidate": {
            "config_fingerprint": args.fingerprint,
            "build_digest": build.get("git_commit", ""),
            "compiler": args.compiler,
            "corpus_id": corpus_id,
            "corpus_version": args.corpus_version,
            "corpus_sha256": corpus_sha256,
            "plan_sha256": sha256_file(replay_path),
        },
        "counts": n,
        "files": files,
    }
    manifest_raw = os.path.join(args.out_dir, "manifest.raw.json")
    with open(manifest_raw, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=1, sort_keys=True)

    index = {
        "kind": "p1_regression_evidence_pack",
        "run_id": run_id,
        "source_run_dir": os.path.abspath(rd),
        "fingerprint": args.fingerprint,
        "declared_status": declared,
        "counts": n,
        "case_id_rule": "<case_id>@<PROFILE>（p1reg 双 profile 两行合并为唯一分块键）",
        "chunk_canonical_sha256": files[0]["sha256"],
        "note": "manifest.raw.json 与 cases-chunk-001.raw.json 须经 regsign canonicalize 后与 index 哈希复核再上传",
        "created_at": manifest["created_at"],
    }
    with open(os.path.join(args.out_dir, "pack-index.json"), "w", encoding="utf-8") as f:
        json.dump(index, f, ensure_ascii=False, indent=1, sort_keys=True)
    print(json.dumps(index, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
