"""p0bench 命令行入口（供 run.sh 调用，亦可独立使用）。

子命令：
  validate-plan   --plan F                 结构校验（§7），错误逐行输出，退出码 2
  corpus-hash     --manifest F             输出语料 sha256
  check-target    --url U --allow E ...    目标/重定向允许判定（BENCH-02）
  owns            --run-id R               从 stdin 读 "name<TAB>labels" 行，全部归属才退出 0
  env-fingerprint --machine-id S --hostname S
  formal-gate     --plan F --ready V --environment-id ID --evidence F
  gen-requests    --manifest F [--profile P]   语料确定性回放请求（JSONL）
  shuffle-profiles --seed N [--jwt-pair]   固定种子随机化执行顺序（默认七模式；--jwt-pair 输出 JWT 配对）
  jwt-jwks        --key PEM --kid K        由本 run 私钥导出静态 JWKS（仅公钥，stdout）
  jwt-mint        --key PEM --kid K --issuer I --audience A --out-header F [--tamper-out-header F]
                                           现场签发有效/篡改签名 Token 并写 0600 头文件（JWT-18）
"""

from __future__ import annotations

import argparse
import sys

from . import corpus as corpus_mod
from . import formal_gate
from . import isolation
from . import replay
from .plan import PROFILES, PlanError, load_plan, validate_plan


def _cmd_validate_plan(args) -> int:
    try:
        plan = load_plan(args.plan)
    except PlanError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    errors = validate_plan(plan)
    if errors:
        for e in errors:
            print(f"PLAN_ERROR: {e}", file=sys.stderr)
        return 2
    print("PLAN_OK")
    return 0


def _cmd_corpus_hash(args) -> int:
    print(corpus_mod.manifest_sha256(args.manifest))
    return 0


def _cmd_check_target(args) -> int:
    allowed = frozenset(args.allow or [])
    cls, reason = isolation.classify_target(args.url, allowed)
    if cls != "allowed":
        print(f"TARGET_REJECTED: {reason}", file=sys.stderr)
        return 1
    for loc in args.redirect or []:
        ok, why = isolation.check_redirect_chain([loc], allowed)
        if not ok:
            print(f"REDIRECT_REJECTED: {why}", file=sys.stderr)
            return 1
    print("TARGET_ALLOWED")
    return 0


def _cmd_owns(args) -> int:
    """stdin 每行: <资源名><TAB><逗号分隔标签>。空输入或任一不归属 → 退出 1。"""
    saw = False
    for line in sys.stdin:
        line = line.rstrip("\n")
        if not line:
            continue
        saw = True
        name, _, label_str = line.partition("\t")
        labels = {}
        for item in label_str.split(","):
            k, _, v = item.partition("=")
            if k:
                labels[k.strip()] = v.strip()
        if not isolation.owns_resource(labels, args.run_id):
            print(f"NOT_OWNED: {name}", file=sys.stderr)
            return 1
    if not saw:
        print("NOT_OWNED: 空资源列表（无可校验对象，拒绝按归属处理）", file=sys.stderr)
        return 1
    print("OWNED")
    return 0


def _cmd_env_fingerprint(args) -> int:
    print(isolation.compute_environment_fingerprint(args.machine_id, args.hostname))
    return 0


def _cmd_formal_gate(args) -> int:
    try:
        plan = load_plan(args.plan)
    except PlanError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    result = formal_gate.evaluate(plan, args.ready, args.environment_id)
    formal_gate.write_evidence(args.evidence, result)
    print(result["status"])
    if result["status"] == "BLOCKED":
        for detail in result["details"]:
            print(f"FORMAL_ENVIRONMENT_BLOCKED: {detail}", file=sys.stderr)
        return formal_gate.BLOCKED_EXIT_CODE
    return 0


def _cmd_gen_requests(args) -> int:
    import json as _json

    try:
        manifest = corpus_mod.load_manifest(args.manifest)
    except corpus_mod.CorpusError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    errors = corpus_mod.validate_manifest(manifest)
    if errors:
        for e in errors:
            print(f"CORPUS_ERROR: {e}", file=sys.stderr)
        return 2
    for req in replay.generate_requests(manifest, args.profile):
        print(_json.dumps(req, ensure_ascii=False))
    return 0


def _cmd_set_status(args) -> int:
    """更新 run 目录 status.json 中的一条验收记录（不存在则创建骨架）。"""
    import json as _json
    from pathlib import Path

    path = Path(args.run_dir) / "status.json"
    doc = {"records": {}}
    if path.is_file():
        try:
            doc = _json.loads(path.read_text(encoding="utf-8"))
        except _json.JSONDecodeError as exc:
            print(f"status.json 损坏: {exc}", file=sys.stderr)
            return 2
    doc.setdefault("records", {})[args.test_id] = {
        "status": args.status,
        "mandatory": not args.optional,
        "reason": args.reason or "",
        "evidence": args.evidence or "",
    }
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(_json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)
    print(f"{args.test_id} -> {args.status}")
    return 0


def _cmd_shuffle_profiles(args) -> int:
    """以固定种子随机化执行顺序（§4：固定随机种子并随机化顺序）。

    默认输出七模式主基线；--jwt-pair 输出 JWT-18 配对 profile
    （jwt_off/jwt_protect，不混入主基线）。
    """
    import random

    from .plan import JWT_PAIR_PROFILES

    order = list(JWT_PAIR_PROFILES if args.jwt_pair else PROFILES)
    random.Random(args.seed).shuffle(order)
    print("\n".join(order))
    return 0


def _cmd_jwt_jwks(args) -> int:
    """导出本 run 测试私钥对应的静态 JWKS（仅公钥；stdout，不入证据敏感面）。"""
    import json as _json

    from . import jwttool

    try:
        jwks = jwttool.build_jwks(args.key, args.kid)
    except jwttool.JWTToolError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(_json.dumps(jwks, ensure_ascii=False, separators=(",", ":")))
    return 0


def _cmd_jwt_mint(args) -> int:
    """现场签发 Token 并写头文件（0600）。输出只含文件路径，绝不含 Token。"""
    from . import jwttool

    try:
        token = jwttool.mint_token(
            args.key,
            kid=args.kid,
            issuer=args.issuer,
            audience=args.audience,
            subject=args.subject,
            ttl_seconds=args.ttl,
        )
        jwttool.write_header_file(args.out_header, token)
        if args.tamper_out_header:
            jwttool.write_header_file(args.tamper_out_header, jwttool.tamper_token(token))
    except jwttool.JWTToolError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(f"WROTE {args.out_header}")
    if args.tamper_out_header:
        print(f"WROTE {args.tamper_out_header}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="p0bench", description="P0-02 基准共享校验 CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("validate-plan")
    p.add_argument("--plan", required=True)
    p.set_defaults(func=_cmd_validate_plan)

    p = sub.add_parser("corpus-hash")
    p.add_argument("--manifest", required=True)
    p.set_defaults(func=_cmd_corpus_hash)

    p = sub.add_parser("check-target")
    p.add_argument("--url", required=True)
    p.add_argument("--allow", action="append", default=[])
    p.add_argument("--redirect", action="append", default=[])
    p.set_defaults(func=_cmd_check_target)

    p = sub.add_parser("owns")
    p.add_argument("--run-id", required=True)
    p.set_defaults(func=_cmd_owns)

    p = sub.add_parser("env-fingerprint")
    p.add_argument("--machine-id", required=True)
    p.add_argument("--hostname", required=True)
    p.set_defaults(func=_cmd_env_fingerprint)

    p = sub.add_parser("formal-gate", help="核对正式环境显式声明与冻结计划")
    p.add_argument("--plan", required=True)
    p.add_argument("--ready", default="0", help="P0B_FORMAL_ENVIRONMENT_READY 的值")
    p.add_argument("--environment-id", default="", help="P0B_FORMAL_ENV_ID 的值")
    p.add_argument("--evidence", required=True, help="门禁证据 JSON 输出路径")
    p.set_defaults(func=_cmd_formal_gate)

    p = sub.add_parser("gen-requests", help="按语料生成确定性回放请求（JSONL）")
    p.add_argument("--manifest", required=True)
    p.add_argument("--profile", default=None)
    p.set_defaults(func=_cmd_gen_requests)

    p = sub.add_parser("set-status", help="写入/更新 run 目录 status.json 记录")
    p.add_argument("--run-dir", required=True)
    p.add_argument("--test-id", required=True)
    p.add_argument("--status", required=True,
                   choices=("PASS", "FAIL", "SKIP", "BLOCKED", "NOT_RUN", "NOT_APPLICABLE"))
    p.add_argument("--reason", default="")
    p.add_argument("--evidence", default="")
    p.add_argument("--optional", action="store_true")
    p.set_defaults(func=_cmd_set_status)

    p = sub.add_parser("shuffle-profiles", help="固定种子随机化执行顺序（默认七模式）")
    p.add_argument("--seed", type=int, required=True)
    p.add_argument("--jwt-pair", action="store_true",
                   help="输出 JWT-18 配对 profile（jwt_off/jwt_protect）而非七模式")
    p.set_defaults(func=_cmd_shuffle_profiles)

    p = sub.add_parser("jwt-jwks", help="由本 run 测试私钥导出静态 JWKS（仅公钥）")
    p.add_argument("--key", required=True, help="PEM 私钥路径（run 目录 0600 测试密钥）")
    p.add_argument("--kid", required=True)
    p.set_defaults(func=_cmd_jwt_jwks)

    p = sub.add_parser("jwt-mint", help="现场签发 Bearer Token 头文件（0600，JWT-18 配对回放注入用）")
    p.add_argument("--key", required=True)
    p.add_argument("--kid", required=True)
    p.add_argument("--issuer", required=True)
    p.add_argument("--audience", required=True)
    p.add_argument("--subject", default="p0bench-user")
    p.add_argument("--ttl", type=int, default=3600, help="Token 有效期（秒，须覆盖回放窗口）")
    p.add_argument("--out-header", required=True, help="有效 Token 头文件输出路径")
    p.add_argument("--tamper-out-header", default=None, help="篡改签名 Token 头文件输出路径")
    p.set_defaults(func=_cmd_jwt_mint)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
