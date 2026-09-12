"""run-plan 加载与结构校验（P0-02 任务书 §7）。

权威校验逻辑。run-plan.schema.json 是同字段的文档化镜像；二者必须同步演进。
缺必填字段时 strict 模式（correctness/matrix/soak/recovery）拒绝启动；
smoke 模式允许缺字段运行但结果只能标记 smoke。

冻结语义：计划一旦用于正式运行即不可覆盖（运行器以只读副本存入 run 目录），
运行后修改门槛必须生成新 plan_id 与新运行。
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

PLAN_ID_RE = re.compile(r"^plan-[0-9]{8}T[0-9]{6}-[a-z0-9]{6}$")
RFC3339_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2})$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{7,40}$")
MEM_RE = re.compile(r"^[0-9]+[mMgG]$")
CPU_RE = re.compile(r"^[0-9]+(\.[0-9]+)?$")

PROFILES = (
    "proxy",
    "waf_observe",
    "waf_protect",
    "api_observe",
    "api_protect",
    "combined_observe",
    "combined_protect",
)
PROFILE_MODES = {
    "proxy": ("OFF", "OFF"),
    "waf_observe": ("DETECTION_ONLY", "OFF"),
    "waf_protect": ("ON", "OFF"),
    "api_observe": ("OFF", "OBSERVE"),
    "api_protect": ("OFF", "PROTECT"),
    "combined_observe": ("DETECTION_ONLY", "OBSERVE"),
    "combined_protect": ("ON", "PROTECT"),
}
# JWT-18 配对 profile（S3 起接线）：同构建同基础配置（waf=Off、api_mode=OFF），
# 仅 JWT 信任链 OFF vs PROTECT（静态 JWKS，运行期本地测试密钥）。不属于七模式
# 主基线；计划经 config.jwt_pair 声明后由运行器在七模式之外追加执行。
JWT_PAIR_PROFILES = ("jwt_off", "jwt_protect")
JWT_PAIR_JWT_MODES = {"jwt_off": "OFF", "jwt_protect": "PROTECT"}
PROTECT_PROFILES = frozenset(
    p for p, (waf, api) in PROFILE_MODES.items() if waf == "ON" or api == "PROTECT"
)
PURPOSES = ("BEFORE", "AFTER", "SMOKE", "LONG_RUN", "RECOVERY")
LOADGEN_TOOLS = ("ab", "curl", "wrk", "k6")
SERVICE_NAMES = ("gateway", "api", "postgres", "valkey", "testorigin", "logrotator")


class PlanError(Exception):
    """run-plan 结构或内容不满足预登记契约。"""


def load_plan(path: str | Path) -> dict:
    p = Path(path)
    try:
        with p.open("r", encoding="utf-8") as fh:
            plan = json.load(fh)
    except FileNotFoundError as exc:
        raise PlanError(f"run-plan 不存在: {p}") from exc
    except json.JSONDecodeError as exc:
        raise PlanError(f"run-plan 不是合法 JSON: {p}: {exc}") from exc
    if not isinstance(plan, dict):
        raise PlanError("run-plan 顶层必须是 JSON 对象")
    return plan


def _err(errors: list[str], path: str, msg: str) -> None:
    errors.append(f"{path}: {msg}")


def _require(errors: list[str], obj: dict, path: str, key: str):
    if key not in obj:
        _err(errors, path, f"缺必填字段 {key}")
        return None
    return obj[key]


def _check_profiles(errors: list[str], profiles) -> None:
    if not isinstance(profiles, list):
        _err(errors, "config.profiles", "必须是数组")
        return
    seen = set()
    for i, prof in enumerate(profiles):
        path = f"config.profiles[{i}]"
        if not isinstance(prof, dict):
            _err(errors, path, "必须是对象")
            continue
        pid = prof.get("profile_id")
        if pid not in PROFILE_MODES:
            _err(errors, path, f"未知 profile_id {pid!r}")
            continue
        seen.add(pid)
        want_waf, want_api = PROFILE_MODES[pid]
        if prof.get("waf_mode") != want_waf or prof.get("api_mode") != want_api:
            _err(
                errors,
                path,
                f"{pid} 的 waf_mode/api_mode 必须为 {want_waf}/{want_api}，"
                "七模式只允许改变任务书 §4 表中的开关",
            )
    missing = [p for p in PROFILES if p not in seen]
    if missing:
        _err(errors, "config.profiles", f"七模式不完整，缺: {', '.join(missing)}")


def _check_jwt_pair(errors: list[str], pair) -> None:
    """config.jwt_pair（可选）：JWT-18 配对实验声明。声明后运行器追加
    jwt_off/jwt_protect 配对 profile；权威校验逻辑在此，schema 文件为镜像。"""
    if not isinstance(pair, dict):
        _err(errors, "config.jwt_pair", "必须是对象")
        return
    for key in ("app_code", "issuer", "audience"):
        if not isinstance(pair.get(key), str) or not pair.get(key):
            _err(
                errors,
                f"config.jwt_pair.{key}",
                "必须为非空字符串（app_code 为基准应用编码，须已存在于基准栈）",
            )
    kid = pair.get("kid")
    if kid is not None and (not isinstance(kid, str) or not kid):
        _err(errors, "config.jwt_pair.kid", "必须为非空字符串")
    ttl = pair.get("token_ttl_seconds")
    if ttl is not None and not (isinstance(ttl, int) and ttl >= 60):
        _err(errors, "config.jwt_pair.token_ttl_seconds", "必须为 >=60 的整数秒（覆盖回放窗口）")
    sel = pair.get("selector")
    if sel is None:
        return
    if not isinstance(sel, dict):
        _err(errors, "config.jwt_pair.selector", "必须是对象")
        return
    methods = sel.get("methods")
    if methods is not None and not (
        isinstance(methods, list)
        and methods
        and all(isinstance(m, str) and m for m in methods)
    ):
        _err(errors, "config.jwt_pair.selector.methods", "必须为非空字符串数组")
    pe = sel.get("path_exact") or ""
    pp = sel.get("path_prefix") or ""
    if bool(pe) == bool(pp):
        _err(errors, "config.jwt_pair.selector", "path_exact 与 path_prefix 必须且仅须提供一个")
    for val in (pe, pp):
        if val and (not val.startswith("/") or "?" in val or "#" in val):
            _err(errors, "config.jwt_pair.selector", "路径必须以 / 开头且不含 query/fragment")
    if sel.get("token_required"):
        _err(
            errors,
            "config.jwt_pair.selector.token_required",
            "配对语料含不携带 Token 的正常样本，必须为 false（JWT 可选），"
            "否则 jwt_protect 下全部正常样本将被 401，配对失去意义",
        )


def validate_plan(plan: dict) -> list[str]:
    """返回错误列表；空列表表示满足 §7 预登记门槛。"""
    errors: list[str] = []

    if plan.get("schema_version") != 1:
        _err(errors, "schema_version", "必须为 1")
    plan_id = plan.get("plan_id")
    if not isinstance(plan_id, str) or not PLAN_ID_RE.match(plan_id):
        _err(errors, "plan_id", "必须匹配 plan-YYYYMMDDTHHMMSS-xxxxxx")
    created = plan.get("created_at")
    if not isinstance(created, str) or not RFC3339_RE.match(created):
        _err(errors, "created_at", "必须为 RFC3339 时间戳")
    if plan.get("purpose") not in PURPOSES:
        _err(errors, "purpose", f"必须为 {PURPOSES} 之一")

    env = _require(errors, plan, "", "environment")
    if isinstance(env, dict):
        eid = env.get("environment_id")
        if not isinstance(eid, str) or len(eid) < 8:
            _err(errors, "environment.environment_id", "必须是不短于 8 字符的环境唯一标识")
        hw = _require(errors, env, "environment", "hardware")
        if isinstance(hw, dict):
            for key in ("cpu_model", "cpu_cores", "memory_gb", "storage", "network"):
                if key not in hw:
                    _err(errors, "environment.hardware", f"缺必填字段 {key}")
            if "cpu_cores" in hw and not (isinstance(hw["cpu_cores"], int) and hw["cpu_cores"] >= 1):
                _err(errors, "environment.hardware.cpu_cores", "必须为正整数")
        for key in ("os", "docker_version"):
            if not isinstance(env.get(key), str) or not env.get(key):
                _err(errors, f"environment.{key}", "必须为非空字符串")
        iso = _require(errors, env, "environment", "isolation")
        if isinstance(iso, dict):
            if iso.get("mode") not in ("compose_project", "dedicated_host"):
                _err(errors, "environment.isolation.mode", "必须为 compose_project 或 dedicated_host")
            if not isinstance(iso.get("registered_targets"), list):
                _err(errors, "environment.isolation.registered_targets", "必须为数组")
        clock = _require(errors, env, "environment", "clock")
        if isinstance(clock, dict):
            if not isinstance(clock.get("sync_method"), str) or not clock.get("sync_method"):
                _err(errors, "environment.clock.sync_method", "必须为非空字符串")
            skew = clock.get("max_skew_ms")
            if not (isinstance(skew, int) and skew >= 1):
                _err(errors, "environment.clock.max_skew_ms", "必须为正整数毫秒")

    build = _require(errors, plan, "", "build")
    if isinstance(build, dict):
        commit = build.get("git_commit")
        if not isinstance(commit, str) or not COMMIT_RE.match(commit):
            _err(errors, "build.git_commit", "必须为 7-40 位小写十六进制提交号")
        if not isinstance(build.get("worktree_dirty"), bool):
            _err(errors, "build.worktree_dirty", "必须为布尔值")
        images = _require(errors, build, "build", "images")
        if isinstance(images, dict):
            for key in ("gateway", "server", "testorigin"):
                img = images.get(key)
                if not isinstance(img, str) or not img:
                    _err(errors, f"build.images.{key}", "必须为锁定 tag 的镜像名")
                elif img.endswith(":latest") or ":" not in img:
                    _err(errors, f"build.images.{key}", "禁止 latest 或无 tag 镜像")

    config = _require(errors, plan, "", "config")
    if isinstance(config, dict):
        bcv = config.get("base_config_version")
        if not isinstance(bcv, str) or not bcv:
            _err(errors, "config.base_config_version", "必须为节点回执确认的有效配置版本")
        profiles = _require(errors, config, "config", "profiles")
        if profiles is not None:
            _check_profiles(errors, profiles)
        toggles = _require(errors, config, "config", "toggles")
        if isinstance(toggles, dict):
            for key in ("jwt", "response_detection", "identity_behavior", "log_sampling", "apm"):
                if not isinstance(toggles.get(key), bool):
                    _err(errors, f"config.toggles.{key}", "必须为布尔值（§4：额外开关必须写明）")
        if "jwt_pair" in config:
            _check_jwt_pair(errors, config["jwt_pair"])
            if toggles is not None and toggles.get("jwt") is not True:
                _err(errors, "config.toggles.jwt", "声明 jwt_pair 配对实验时 toggles.jwt 必须为 true（预登记诚实性）")
        elif isinstance(toggles, dict) and toggles.get("jwt") is True:
            _err(errors, "config.toggles.jwt", "jwt=true 必须配套 config.jwt_pair 声明（工具仅支持 JWT-18 配对形态）")

    corpus = _require(errors, plan, "", "corpus")
    if isinstance(corpus, dict):
        mp = corpus.get("manifest_path")
        if not isinstance(mp, str) or not mp:
            _err(errors, "corpus.manifest_path", "必须为非空字符串")
        mh = corpus.get("manifest_sha256")
        if not isinstance(mh, str) or not SHA256_RE.match(mh):
            _err(errors, "corpus.manifest_sha256", "必须为 64 位小写 sha256")
        if not isinstance(corpus.get("seed"), int):
            _err(errors, "corpus.seed", "必须为整数（固定随机种子）")

    load = _require(errors, plan, "", "load")
    if isinstance(load, dict):
        if load.get("model") not in ("open_fixed_rate", "closed_concurrency"):
            _err(errors, "load.model", "必须为 open_fixed_rate 或 closed_concurrency")
        w = load.get("warmup_seconds")
        if not (isinstance(w, int) and w >= 60):
            _err(errors, "load.warmup_seconds", "预热至少 60 秒（§6.1）")
        sp = load.get("steady_point_seconds")
        if not (isinstance(sp, int) and sp >= 300):
            _err(errors, "load.steady_point_seconds", "每个稳定负载点至少 300 秒（§6.1）")
        rp = load.get("repeats")
        if not (isinstance(rp, int) and rp >= 3):
            _err(errors, "load.repeats", "每个性能点至少 3 次有效重复（§6.1）")
        ladder = load.get("rps_ladder")
        if not (
            isinstance(ladder, list)
            and ladder
            and all(isinstance(x, int) and x > 0 for x in ladder)
        ):
            _err(errors, "load.rps_ladder", "必须为非空正整数数组")
        lg = _require(errors, load, "load", "loadgen")
        if isinstance(lg, dict):
            if lg.get("tool") not in LOADGEN_TOOLS:
                _err(errors, "load.loadgen.tool", f"必须为 {LOADGEN_TOOLS} 之一")
            if not isinstance(lg.get("version"), str) or not lg.get("version"):
                _err(errors, "load.loadgen.version", "必须登记压测器版本（运行时再采集核对）")
        soak = _require(errors, load, "load", "soak")
        if isinstance(soak, dict):
            pm = soak.get("per_profile_minutes")
            if not (isinstance(pm, int) and pm >= 30):
                _err(errors, "load.soak.per_profile_minutes", "七模式各至少 30 分钟（§6.3）")
            ch = soak.get("combined_protect_hours")
            if not (isinstance(ch, int) and ch >= 72):
                _err(errors, "load.soak.combined_protect_hours", "combined_protect 长稳至少 72 小时（§6.3）")
            ratio = soak.get("sustained_load_ratio")
            if not (isinstance(ratio, (int, float)) and 0 < ratio <= 1):
                _err(errors, "load.soak.sustained_load_ratio", "必须为 (0,1] 区间数值")
        smoke = _require(errors, load, "load", "smoke")
        if isinstance(smoke, dict):
            if not (isinstance(smoke.get("duration_seconds"), int) and smoke["duration_seconds"] >= 1):
                _err(errors, "load.smoke.duration_seconds", "必须为正整数")
            if not (isinstance(smoke.get("rps"), int) and smoke["rps"] >= 1):
                _err(errors, "load.smoke.rps", "必须为正整数")

    rl = _require(errors, plan, "", "resource_limits")
    if isinstance(rl, dict):
        services = _require(errors, rl, "resource_limits", "services")
        if isinstance(services, dict):
            if not services:
                _err(errors, "resource_limits.services", "至少登记一个服务的资源上限")
            for name, spec in services.items():
                if name not in SERVICE_NAMES:
                    _err(errors, f"resource_limits.services.{name}", "未知服务名")
                    continue
                if not isinstance(spec, dict):
                    _err(errors, f"resource_limits.services.{name}", "必须是对象")
                    continue
                cpu = spec.get("cpu")
                if not (isinstance(cpu, str) and CPU_RE.match(cpu)):
                    _err(errors, f"resource_limits.services.{name}.cpu", "格式如 \"4.0\"")
                mem = spec.get("memory")
                if not (isinstance(mem, str) and MEM_RE.match(mem)):
                    _err(errors, f"resource_limits.services.{name}.memory", "格式如 \"4G\" / \"512m\"")
        smg = rl.get("steady_memory_growth_mb_per_hour_max")
        if not (isinstance(smg, (int, float)) and smg >= 0):
            _err(errors, "resource_limits.steady_memory_growth_mb_per_hour_max", "必须为非负数")
        drm = rl.get("disk_retention_max_mb")
        if not (isinstance(drm, (int, float)) and drm > 0):
            _err(errors, "resource_limits.disk_retention_max_mb", "必须为正数")
        if rl.get("queue_growth") != "bounded":
            _err(errors, "resource_limits.queue_growth", "必须为 bounded（背压有界，§7）")

    th = _require(errors, plan, "", "thresholds")
    if isinstance(th, dict):
        if th.get("mandatory_security_cases") != "ALL_PASS":
            _err(errors, "thresholds.mandatory_security_cases", "必须为 ALL_PASS（§7）")
        ner = th.get("normal_unexpected_error_rate_max")
        if not (isinstance(ner, (int, float)) and ner >= 0):
            _err(errors, "thresholds.normal_unexpected_error_rate_max", "必须为非负数")
        tr = th.get("throughput_regression_min_ratio")
        if not (isinstance(tr, (int, float)) and 0 < tr <= 1):
            _err(errors, "thresholds.throughput_regression_min_ratio", "必须为 (0,1] 区间数值")
        p99 = th.get("p99_regression")
        if not isinstance(p99, dict):
            _err(errors, "thresholds.p99_regression", "必须为对象 {max_ratio, max_abs_ms}")
        else:
            if not (isinstance(p99.get("max_ratio"), (int, float)) and p99["max_ratio"] >= 1):
                _err(errors, "thresholds.p99_regression.max_ratio", "必须 >= 1")
            if not (isinstance(p99.get("max_abs_ms"), (int, float)) and p99["max_abs_ms"] >= 0):
                _err(errors, "thresholds.p99_regression.max_abs_ms", "必须 >= 0")
        dfp = th.get("detection_false_positive_rate_max")
        if not (isinstance(dfp, (int, float)) and dfp >= 0):
            _err(errors, "thresholds.detection_false_positive_rate_max", "必须为非负数")
        bfp = th.get("block_false_positive_max")
        if not (isinstance(bfp, int) and bfp >= 0):
            _err(errors, "thresholds.block_false_positive_max", "必须为非负整数")
        pel = th.get("persisted_event_permanent_loss_max")
        if not (isinstance(pel, int) and pel >= 0):
            _err(errors, "thresholds.persisted_event_permanent_loss_max", "必须为非负整数")
        evl = th.get("event_visibility_latency_ms_max")
        if not (isinstance(evl, int) and evl >= 1):
            _err(errors, "thresholds.event_visibility_latency_ms_max", "必须为正整数毫秒（正式测量前冻结）")
        rts = th.get("recovery_time_seconds_max")
        if not (isinstance(rts, int) and rts >= 1):
            _err(errors, "thresholds.recovery_time_seconds_max", "必须为正整数秒（正式测量前冻结）")

    return errors


def require_valid_plan(plan: dict) -> None:
    errors = validate_plan(plan)
    if errors:
        raise PlanError("run-plan 不满足预登记契约：\n" + "\n".join(f"  - {e}" for e in errors))


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def check_corpus_hash(plan: dict, repo_root: str | Path) -> str | None:
    """核对计划登记的语料哈希与实际文件。返回错误描述或 None（一致）。"""
    corpus = plan.get("corpus") or {}
    manifest_path = corpus.get("manifest_path")
    want = corpus.get("manifest_sha256")
    if not manifest_path or not want:
        return "run-plan 缺 corpus.manifest_path / manifest_sha256"
    p = Path(repo_root) / manifest_path
    if not p.is_file():
        return f"语料文件缺失: {manifest_path}"
    actual = sha256_file(p)
    if actual != want:
        return f"语料哈希不匹配: 登记 {want}，实际 {actual}"
    return None
