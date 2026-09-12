#!/usr/bin/env python3
"""WDSP 版本能力与证据清单工具（P0-01，S1）。

读取受版本管理的能力清单（capabilities.json）与某次构建的证据包 manifest，
校验结构与构建绑定，按任务书 §4.3 计算能力验证状态，并生成可读 Markdown 报告。

命令契约（docs/tasks/wdsp-p0/P0-01_CAPABILITY_EVIDENCE.md §5）：

    python3 tools/capability_evidence.py check  --catalog <清单> --manifest <manifest> [--release]
    python3 tools/capability_evidence.py render --catalog <清单> --manifest <manifest> --output <报告>

行为要点：
- 仅使用 Python 标准库；不执行测试、不访问网络、不调用 shell。
- manifest 中测试记录的 command 字段只作审计文本，绝不执行。
- 所有路径解析真实路径后限定在仓库根（清单实现引用）或证据包根（manifest 工件）内；
  拒绝越界 `..`、外部绝对路径、越界符号链接与远程 URL。
- render 对同一输入产生逐字节相同输出；写入采用临时文件后原子替换，
  写入失败时原文件保持完整。

退出码：0 结构有效；1 发布门槛未满足（仅 --release）；2 结构/完整性错误。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime
from pathlib import Path

SCHEMA_VERSION = 1

IMPL_STATUS = {"NOT_STARTED", "PARTIAL", "IMPLEMENTED"}
INTEG_STATUS = {"NOT_CONNECTED", "PARTIAL", "CONNECTED"}
VERIFY_STATUS = {"NOT_RUN", "PASS", "FAIL", "BLOCKED"}
PRODUCT_LINES = {"WAF", "WDSP", "API"}
DEPLOY_MODES = {"REVERSE_PROXY", "MIRROR", "AGENT", "APM_PROBE"}
TEST_STATUS = {"PASS", "FAIL", "SKIP", "BLOCKED", "NOT_RUN", "NOT_APPLICABLE"}
RELEASE_STATUS = {"DEVELOPMENT", "RELEASE_VERIFIED"}

TEST_ID_RE = re.compile(r"^(EVD|BENCH|JWT|DEC|EXC)-\d{2}$")
CAP_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
RFC3339_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2})$")
URL_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")

# 状态严重度：汇总取最差结果（任务书 §4.3）。
STATUS_RANK = {"PASS": 0, "NOT_RUN": 1, "BLOCKED": 2, "FAIL": 3}

# 源码快照默认排除：版本元数据、证据输出、依赖缓存、凭据文件与运行数据。
DEFAULT_SNAPSHOT_EXCLUDES = (
    ".git",
    "node_modules",
    "dist",
    "runtime",
    "docs/evidence",
    ".env",
)


class CheckError(Exception):
    """结构/完整性校验错误；消息必须能定位到字段或文件。"""


def fail(loc: str, msg: str) -> None:
    raise CheckError(f"{loc}: {msg}")


# ---------------------------------------------------------------------------
# 路径安全
# ---------------------------------------------------------------------------

def resolve_within(base: Path, value, loc: str, must_exist: bool = True) -> Path:
    """将 value 解析为真实路径并限定在 base 内。

    拒绝远程 URL、越界 ..、base 之外的绝对路径与越界符号链接。
    """
    if not isinstance(value, str) or not value:
        fail(loc, "路径必须是非空字符串")
    if URL_RE.match(value) or "://" in value:
        fail(loc, f"不允许远程 URL，工具不会发起网络请求：{value!r}")
    base_real = Path(os.path.realpath(base))
    candidate = Path(value)
    target = candidate if candidate.is_absolute() else base_real / candidate
    real = Path(os.path.realpath(target))
    if real != base_real and base_real not in real.parents:
        fail(loc, f"路径越界：{value!r} 解析为 {real}，超出允许根 {base_real}")
    if must_exist and not real.exists():
        fail(loc, f"路径不存在：{value!r}（解析为 {real}）")
    return real


def find_repo_root(catalog_path: Path) -> Path:
    """从清单位置向上查找含 AGENTS.md 的目录作为仓库根；找不到则报错。"""
    start = Path(os.path.realpath(catalog_path)).parent
    for parent in (start, *start.parents):
        if (parent / "AGENTS.md").exists():
            return parent
    fail(str(catalog_path), "无法定位仓库根（向上未找到 AGENTS.md），请确认清单位于仓库内")
    raise AssertionError("unreachable")


# ---------------------------------------------------------------------------
# JSON 装载与通用校验
# ---------------------------------------------------------------------------

def load_json(path: Path, what: str):
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        fail(str(path), f"无法读取{what}：{exc}")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        fail(str(path), f"{what} JSON 语法错误：第 {exc.lineno} 行第 {exc.colno} 列：{exc.msg}")
    raise AssertionError("unreachable")


def require_str(value, loc: str, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        fail(loc, f"必须是非空字符串，实际 {value!r}")
    return value


def require_enum(value, allowed, loc: str) -> str:
    if value not in allowed:
        fail(loc, f"非法枚举值 {value!r}，允许值：{sorted(allowed)}")
    return value


def parse_rfc3339(value, loc: str):
    if not isinstance(value, str) or not RFC3339_RE.match(value):
        fail(loc, f"时间必须是 UTC RFC3339（如 2026-09-06T08:00:00Z），实际 {value!r}")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail(loc, f"时间值无效：{value!r}")
    raise AssertionError("unreachable")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical_snapshot(file_manifest) -> str:
    """对构建输入文件清单生成规范化摘要（路径排序后逐条混入）。"""
    h = hashlib.sha256()
    for entry in sorted(file_manifest, key=lambda e: e["path"]):
        h.update(entry["path"].encode("utf-8"))
        h.update(b"\0")
        h.update(entry["sha256"].encode("ascii"))
        h.update(b"\n")
    return h.hexdigest()


def build_file_manifest(root: Path, exclude_names=DEFAULT_SNAPSHOT_EXCLUDES):
    """枚举构建输入文件并逐文件哈希；包含未跟踪源码，排除凭据/缓存/证据输出。"""
    root = Path(os.path.realpath(root))
    entries = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in exclude_names)
        for name in sorted(filenames):
            if name in exclude_names or name.startswith(".env"):
                continue
            full = Path(dirpath) / name
            if full.is_symlink() or not full.is_file():
                continue
            rel = full.relative_to(root).as_posix()
            entries.append({"path": rel, "sha256": sha256_file(full)})
    return entries


# ---------------------------------------------------------------------------
# 能力清单校验
# ---------------------------------------------------------------------------

def _validate_capability(cap, idx: int, repo_root: Path) -> dict:
    loc = f"capabilities[{idx}]"
    if not isinstance(cap, dict):
        fail(loc, "能力条目必须是对象")

    cid = require_str(cap.get("id"), f"{loc}.id")
    if not CAP_ID_RE.match(cid):
        fail(f"{loc}.id", f"能力 ID 须为小写机器 ID（^[a-z0-9][a-z0-9-]*$），实际 {cid!r}")
    loc = f"capabilities[{cid}]"
    require_str(cap.get("name"), f"{loc}.name")
    require_str(cap.get("owner_module"), f"{loc}.owner_module")

    for field, allowed in (("product_lines", PRODUCT_LINES), ("deployment_modes", DEPLOY_MODES)):
        values = cap.get(field)
        if not isinstance(values, list) or not values:
            fail(f"{loc}.{field}", "必须是非空数组")
        if len(set(values)) != len(values):
            fail(f"{loc}.{field}", f"存在重复成员：{values!r}")
        for j, v in enumerate(values):
            require_enum(v, allowed, f"{loc}.{field}[{j}]")

    require_enum(cap.get("implementation_status"), IMPL_STATUS, f"{loc}.implementation_status")
    require_enum(cap.get("integration_status"), INTEG_STATUS, f"{loc}.integration_status")
    require_enum(cap.get("verification_status"), VERIFY_STATUS, f"{loc}.verification_status")

    refs = cap.get("implementation_refs")
    if not isinstance(refs, list) or not refs:
        fail(f"{loc}.implementation_refs", "必须是非空数组，实现/接线状态必须有引用支撑")
    for j, ref in enumerate(refs):
        rloc = f"{loc}.implementation_refs[{j}]"
        if not isinstance(ref, dict):
            fail(rloc, "实现引用必须是对象")
        path = require_str(ref.get("path"), f"{rloc}.path")
        resolve_within(repo_root, path, f"{rloc}.path")
        if "symbol" in ref:
            require_str(ref["symbol"], f"{rloc}.symbol")

    required = cap.get("required_test_ids")
    if not isinstance(required, list):
        fail(f"{loc}.required_test_ids", "必须是数组（可为空，但空集合永远无法获得 PASS）")
    for j, tid in enumerate(required):
        if not isinstance(tid, str) or not TEST_ID_RE.match(tid):
            fail(f"{loc}.required_test_ids[{j}]",
                 f"测试 ID 须匹配 {TEST_ID_RE.pattern}，实际 {tid!r}")
    if len(set(required)) != len(required):
        fail(f"{loc}.required_test_ids", f"存在重复测试 ID：{required!r}")

    scenarios = cap.get("scenarios")
    norm_scenarios = []
    if scenarios is None:
        norm_scenarios.append({
            "id": "default",
            "name": "默认场景",
            "deployment_mode": cap["deployment_modes"][0],
            "mandatory": True,
            "required_test_ids": list(required),
            "note": None,
        })
    else:
        if not isinstance(scenarios, list) or not scenarios:
            fail(f"{loc}.scenarios", "必须是非空数组")
        seen_sid = set()
        union: set = set()
        for j, scen in enumerate(scenarios):
            sloc = f"{loc}.scenarios[{j}]"
            if not isinstance(scen, dict):
                fail(sloc, "场景必须是对象")
            sid = require_str(scen.get("id"), f"{sloc}.id")
            if not CAP_ID_RE.match(sid):
                fail(f"{sloc}.id", f"场景 ID 须为小写机器 ID，实际 {sid!r}")
            if sid in seen_sid:
                fail(f"{sloc}.id", f"场景 ID 重复：{sid!r}")
            seen_sid.add(sid)
            require_str(scen.get("name"), f"{sloc}.name")
            require_enum(scen.get("deployment_mode"), DEPLOY_MODES, f"{sloc}.deployment_mode")
            mandatory = scen.get("mandatory")
            if not isinstance(mandatory, bool):
                fail(f"{sloc}.mandatory", "必须是布尔值")
            sids = scen.get("required_test_ids")
            if not isinstance(sids, list):
                fail(f"{sloc}.required_test_ids", "必须是数组")
            for k, tid in enumerate(sids):
                if not isinstance(tid, str) or not TEST_ID_RE.match(tid):
                    fail(f"{sloc}.required_test_ids[{k}]",
                         f"测试 ID 须匹配 {TEST_ID_RE.pattern}，实际 {tid!r}")
            union.update(sids)
            norm_scenarios.append({
                "id": sid,
                "name": scen["name"],
                "deployment_mode": scen["deployment_mode"],
                "mandatory": mandatory,
                "required_test_ids": list(sids),
                "note": scen.get("note"),
            })
        if union != set(required):
            fail(f"{loc}.required_test_ids",
                 f"顶层 required_test_ids 必须等于各场景并集；差异："
                 f"仅顶层 {sorted(set(required) - union)}，仅场景 {sorted(union - set(required))}")

    for field in ("prerequisites", "limitations"):
        items = cap.get(field)
        if not isinstance(items, list):
            fail(f"{loc}.{field}", "必须是数组")
        for j, item in enumerate(items):
            require_str(item, f"{loc}.{field}[{j}]")

    evidence_refs = cap.get("evidence_refs")
    if not isinstance(evidence_refs, list):
        fail(f"{loc}.evidence_refs", "必须是数组（空数组表示未验证）")
    for j, ref in enumerate(evidence_refs):
        require_str(ref, f"{loc}.evidence_refs[{j}]")

    normalized = dict(cap)
    normalized["_scenarios"] = norm_scenarios
    return normalized


def validate_catalog(catalog, repo_root: Path) -> list:
    if not isinstance(catalog, dict):
        fail("capabilities.json", "清单顶层必须是对象")
    sv = catalog.get("schema_version")
    if sv != SCHEMA_VERSION:
        fail("capabilities.json.schema_version",
             f"不支持的 schema 版本 {sv!r}（本工具支持 {SCHEMA_VERSION}）；"
             "破坏性升级须保留旧版本读取或明确拒绝")
    require_str(catalog.get("catalog_id"), "capabilities.json.catalog_id")
    caps = catalog.get("capabilities")
    if not isinstance(caps, list) or not caps:
        fail("capabilities.json.capabilities", "必须是非空数组")
    seen = {}
    normalized = []
    for i, cap in enumerate(caps):
        nc = _validate_capability(cap, i, repo_root)
        cid = nc["id"]
        if cid in seen:
            fail(f"capabilities[{cid}].id",
                 f"能力 ID 重复：{cid!r}（首次出现于 capabilities[{seen[cid]}]）")
        seen[cid] = i
        normalized.append(nc)
    return normalized


# ---------------------------------------------------------------------------
# 证据包 manifest 校验
# ---------------------------------------------------------------------------

def _validate_source(source, loc: str):
    if not isinstance(source, dict):
        fail(loc, "source 必须是对象")
    commit = source.get("commit")
    if commit is not None:
        if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{7,40}", commit):
            fail(f"{loc}.commit", f"提交号须为 7-40 位小写十六进制或 null，实际 {commit!r}")
    dirty = source.get("dirty")
    if not isinstance(dirty, bool):
        fail(f"{loc}.dirty", "必须是布尔值（不得隐藏 dirty 标记）")
    snapshot = source.get("snapshot_sha256")
    if snapshot is not None and (not isinstance(snapshot, str) or not SHA256_RE.match(snapshot)):
        fail(f"{loc}.snapshot_sha256", f"须为 64 位小写十六进制或 null，实际 {snapshot!r}")
    fm = source.get("file_manifest")
    if not isinstance(fm, list):
        fail(f"{loc}.file_manifest", "必须是数组（可为空，空则无法通过发布门槛）")
    seen = set()
    for i, entry in enumerate(fm):
        eloc = f"{loc}.file_manifest[{i}]"
        if not isinstance(entry, dict):
            fail(eloc, "文件清单条目必须是对象")
        path = require_str(entry.get("path"), f"{eloc}.path")
        if URL_RE.match(path) or "://" in path or Path(path).is_absolute() or ".." in Path(path).parts:
            fail(f"{eloc}.path", f"构建输入路径必须是仓库内相对路径，实际 {path!r}")
        if path in seen:
            fail(f"{eloc}.path", f"文件清单路径重复：{path!r}")
        seen.add(path)
        digest = entry.get("sha256")
        if not isinstance(digest, str) or not SHA256_RE.match(digest):
            fail(f"{eloc}.sha256", f"须为 64 位小写十六进制，实际 {digest!r}")
    if snapshot is not None and fm:
        actual = canonical_snapshot(fm)
        if actual != snapshot:
            fail(f"{loc}.snapshot_sha256",
                 "源码快照摘要与 file_manifest 不一致（疑似篡改或清单缺失文件）："
                 f"声明 {snapshot}，按清单重算 {actual}")


def _validate_images(images, loc: str):
    if not isinstance(images, list):
        fail(loc, "images 必须是数组（空数组无法通过发布门槛）")
    for i, img in enumerate(images):
        iloc = f"{loc}[{i}]"
        if not isinstance(img, dict):
            fail(iloc, "镜像条目必须是对象")
        require_str(img.get("name"), f"{iloc}.name")
        version = require_str(img.get("version"), f"{iloc}.version")
        if version == "latest":
            fail(f"{iloc}.version", "禁止使用 latest 标签，必须锁定版本")
        require_str(img.get("platform"), f"{iloc}.platform")
        digest = img.get("digest")
        if digest is not None and (not isinstance(digest, str) or not DIGEST_RE.match(digest)):
            fail(f"{iloc}.digest", f"镜像 digest 须为 sha256:<64位小写十六进制>，实际 {digest!r}")


def _validate_test_record(rec, idx: int, manifest: dict, evidence_root: Path,
                          require_artifacts_for_pass: bool = True) -> dict:
    loc = f"manifest.tests[{idx}]"
    if not isinstance(rec, dict):
        fail(loc, "测试记录必须是对象")
    tid = rec.get("id")
    if not isinstance(tid, str) or not TEST_ID_RE.match(tid):
        fail(f"{loc}.id", f"测试 ID 须匹配 {TEST_ID_RE.pattern}，实际 {tid!r}")
    loc = f"manifest.tests[{tid}]"

    status = rec.get("status")
    require_enum(status, TEST_STATUS, f"{loc}.status")

    caps = rec.get("capabilities", [])
    if not isinstance(caps, list):
        fail(f"{loc}.capabilities", "适用能力必须是数组")
    for j, c in enumerate(caps):
        require_str(c, f"{loc}.capabilities[{j}]")

    command = rec.get("command")
    if command is not None and not isinstance(command, str):
        fail(f"{loc}.command", "command 是审计文本，必须是字符串；本工具绝不执行它")

    reason = rec.get("reason")
    if status == "NOT_APPLICABLE":
        if not isinstance(reason, str) or not reason:
            fail(f"{loc}.reason",
                 "NOT_APPLICABLE 仅限有明确产品范围依据的场景排除，必须记录原因；"
                 "不能把必测失败改成不适用")

    artifacts = rec.get("artifacts", [])
    if not isinstance(artifacts, list):
        fail(f"{loc}.artifacts", "必须是数组")
    for j, art in enumerate(artifacts):
        aloc = f"{loc}.artifacts[{j}]"
        if not isinstance(art, dict):
            fail(aloc, "工件条目必须是对象")
        path = require_str(art.get("path"), f"{aloc}.path")
        real = resolve_within(evidence_root, path, f"{aloc}.path")
        if not real.is_file():
            fail(f"{aloc}.path", f"工件不是普通文件：{path!r}")
        digest = art.get("sha256")
        if not isinstance(digest, str) or not SHA256_RE.match(digest):
            fail(f"{aloc}.sha256", f"须为 64 位小写十六进制，实际 {digest!r}")
        actual = sha256_file(real)
        if actual != digest:
            fail(f"{aloc}.sha256",
                 f"工件哈希不符（疑似篡改）：{path!r} 声明 {digest}，实际 {actual}")

    if status == "PASS" and require_artifacts_for_pass and not artifacts:
        fail(f"{loc}.artifacts", "PASS 记录必须附证据工件（路径+sha256），无证据不得记为通过")

    # 构建绑定：记录级字段若给出，必须与 manifest 一致（EVD-03）。
    if "build_id" in rec and rec["build_id"] != manifest.get("build_id"):
        fail(f"{loc}.build_id",
             f"构建绑定不匹配：记录声明 {rec['build_id']!r}，manifest build_id 为 {manifest.get('build_id')!r}")
    if "commit" in rec and rec["commit"] != manifest.get("source", {}).get("commit"):
        fail(f"{loc}.commit",
             f"构建绑定不匹配：记录 commit {rec['commit']!r} 与 manifest source.commit "
             f"{manifest.get('source', {}).get('commit')!r} 冲突")
    if "config_fingerprint" in rec and rec["config_fingerprint"] != manifest.get("config_fingerprint"):
        fail(f"{loc}.config_fingerprint",
             f"构建绑定不匹配：记录配置指纹 {rec['config_fingerprint']!r} 与 manifest "
             f"config_fingerprint {manifest.get('config_fingerprint')!r} 冲突")

    return {"id": tid, "status": status, "capabilities": caps, "reason": reason}


def validate_manifest(manifest, manifest_path: Path, evidence_root: Path) -> dict:
    if not isinstance(manifest, dict):
        fail(str(manifest_path), "manifest 顶层必须是对象")
    sv = manifest.get("schema_version")
    if sv != SCHEMA_VERSION:
        fail("manifest.schema_version",
             f"不支持的 schema 版本 {sv!r}（本工具支持 {SCHEMA_VERSION}）")
    require_str(manifest.get("build_id"), "manifest.build_id")
    require_str(manifest.get("product_version"), "manifest.product_version")

    _validate_source(manifest.get("source"), "manifest.source")
    _validate_images(manifest.get("images", []), "manifest.images")

    cf = manifest.get("config_fingerprint")
    if cf is not None and not isinstance(cf, str):
        fail("manifest.config_fingerprint", "必须是字符串或 null（仅非敏感有效配置的规范化哈希）")

    env = manifest.get("environment")
    if not isinstance(env, dict):
        fail("manifest.environment", "必须是对象（OS/内核、CPU/内存、拓扑、工具版本、时钟状态）")

    started = manifest.get("started_at")
    ended = manifest.get("ended_at")
    started_dt = parse_rfc3339(started, "manifest.started_at") if started is not None else None
    ended_dt = parse_rfc3339(ended, "manifest.ended_at") if ended is not None else None
    if started_dt and ended_dt and ended_dt < started_dt:
        fail("manifest.ended_at", f"结束时间 {ended} 早于开始时间 {started}")

    tests = manifest.get("tests")
    if not isinstance(tests, list):
        fail("manifest.tests", "必须是数组")
    records = {}
    for i, rec in enumerate(tests):
        norm = _validate_test_record(rec, i, manifest, evidence_root)
        if norm["id"] in records:
            fail(f"manifest.tests[{norm['id']}].id", f"测试 ID 重复：{norm['id']!r}")
        records[norm["id"]] = norm

    release_status = manifest.get("release_status")
    if release_status is not None:
        require_enum(release_status, RELEASE_STATUS, "manifest.release_status")

    return {
        "raw": manifest,
        "records": records,
        "started_dt": started_dt,
        "ended_dt": ended_dt,
        "declared_release_status": release_status,
    }


# ---------------------------------------------------------------------------
# 状态计算（任务书 §4.3）
# ---------------------------------------------------------------------------

def _worst(statuses) -> str:
    return max(statuses, key=lambda s: STATUS_RANK[s])


def compute_scenario_status(scenario: dict, capability_id: str, records: dict):
    """返回 (status, details)。任一 FAIL→FAIL；无失败但有 BLOCKED→BLOCKED；
    缺失/SKIP/未执行→NOT_RUN；全部实际执行且通过且绑定匹配→PASS。"""
    details = []
    contrib = []
    for tid in scenario["required_test_ids"]:
        rec = records.get(tid)
        if rec is None:
            contrib.append("NOT_RUN")
            details.append(f"{tid}：无测试记录（缺失）")
            continue
        rec_caps = rec["capabilities"]
        if rec_caps and capability_id not in rec_caps:
            contrib.append("NOT_RUN")
            details.append(f"{tid}：记录存在但未声明适用于能力 {capability_id}（缺失）")
            continue
        st = rec["status"]
        if st == "PASS":
            contrib.append("PASS")
            details.append(f"{tid}：PASS")
        elif st == "FAIL":
            contrib.append("FAIL")
            details.append(f"{tid}：FAIL")
        elif st == "BLOCKED":
            contrib.append("BLOCKED")
            details.append(f"{tid}：BLOCKED（{rec.get('reason') or '环境阻塞'}）")
        elif st == "NOT_APPLICABLE":
            contrib.append("NOT_RUN")
            details.append(f"{tid}：NOT_APPLICABLE（{rec.get('reason')}）——必测项排除需审核，不自动计为通过")
        else:  # SKIP / NOT_RUN
            contrib.append("NOT_RUN")
            details.append(f"{tid}：{st}（未实际执行通过，不计为验证）")
    if not scenario["required_test_ids"]:
        return "NOT_RUN", ["强制测试集合为空：空集合无法获得 PASS"]
    return _worst(contrib), details


def compute_capability_status(capability: dict, records: dict):
    """返回 (status, [(scenario, status, details)])。汇总取强制场景最差结果。"""
    per_scenario = []
    mandatory = []
    for scen in capability["_scenarios"]:
        status, details = compute_scenario_status(scen, capability["id"], records)
        per_scenario.append((scen, status, details))
        if scen["mandatory"]:
            mandatory.append(status)
    if not mandatory:
        return "NOT_RUN", per_scenario
    return _worst(mandatory), per_scenario


def release_gate_failures(capabilities: list, manifest_info: dict, computed: dict) -> list:
    """RELEASE_VERIFIED 门槛：干净构建输入 + 锁定镜像 + 强制范围无 FAIL/BLOCKED/NOT_RUN。"""
    raw = manifest_info["raw"]
    reasons = []
    source = raw.get("source", {})
    if not source.get("commit"):
        reasons.append("source.commit 为空：发布证据必须绑定实际提交")
    if source.get("dirty"):
        reasons.append("source.dirty=true：存在影响构建的未提交内容，发布证据必须绑定干净构建输入")
    if not source.get("snapshot_sha256"):
        reasons.append("source.snapshot_sha256 为空：缺少构建输入快照摘要")
    if not source.get("file_manifest"):
        reasons.append("source.file_manifest 为空：缺少构建输入文件清单")
    images = raw.get("images", [])
    if not images:
        reasons.append("images 为空：发布证据必须记录锁定镜像")
    for i, img in enumerate(images):
        if not img.get("digest"):
            reasons.append(f"images[{i}]（{img.get('name', '?')}）缺少实际镜像 digest")
    if not raw.get("config_fingerprint"):
        reasons.append("config_fingerprint 为空：缺少有效配置指纹")
    if not manifest_info["started_dt"] or not manifest_info["ended_dt"]:
        reasons.append("started_at/ended_at 缺失：发布证据必须记录验收时间窗")
    for cap in capabilities:
        status, per_scenario = computed[cap["id"]]
        if status != "PASS":
            scen_note = "、".join(
                f"{scen['id']}={st}" for scen, st, _ in per_scenario if scen["mandatory"]
            )
            reasons.append(
                f"能力 {cap['id']}（{cap['name']}）验证状态为 {status}（{scen_note}），"
                "RELEASE_VERIFIED 要求强制范围无 FAIL/BLOCKED/NOT_RUN"
            )
    return reasons


def compute_release_status(capabilities, manifest_info, computed) -> str:
    return "RELEASE_VERIFIED" if not release_gate_failures(capabilities, manifest_info, computed) else "DEVELOPMENT"


# ---------------------------------------------------------------------------
# 交叉检查与主流程
# ---------------------------------------------------------------------------

def cross_validate(capabilities, manifest_info, catalog_name: str, manifest_name: str):
    records = manifest_info["records"]
    cap_ids = {c["id"] for c in capabilities}
    for cap in capabilities:
        for ref in cap["evidence_refs"]:
            if ref not in records:
                fail(f"{catalog_name}:capabilities[{cap['id']}].evidence_refs",
                     f"断链：证据引用 {ref!r} 在 {manifest_name} 的 tests 中不存在")
    for tid, rec in records.items():
        for c in rec["capabilities"]:
            if c not in cap_ids:
                fail(f"{manifest_name}:tests[{tid}].capabilities",
                     f"断链：测试记录引用了清单中不存在的能力 {c!r}")


def evaluate(catalog_path: Path, manifest_path: Path):
    """完整校验并计算状态。返回 (capabilities, manifest_info, computed, release_status)。"""
    catalog_path = Path(os.path.realpath(catalog_path))
    manifest_path = Path(os.path.realpath(manifest_path))
    repo_root = find_repo_root(catalog_path)
    evidence_root = manifest_path.parent

    catalog = load_json(catalog_path, "能力清单")
    capabilities = validate_catalog(catalog, repo_root)

    manifest = load_json(manifest_path, "证据 manifest")
    manifest_info = validate_manifest(manifest, manifest_path, evidence_root)

    cross_validate(capabilities, manifest_info, str(catalog_path), str(manifest_path))

    computed = {}
    for cap in capabilities:
        status, per_scenario = compute_capability_status(cap, manifest_info["records"])
        computed[cap["id"]] = (status, per_scenario)
        declared = cap["verification_status"]
        if declared != status:
            fail(f"{catalog_path}:capabilities[{cap['id']}].verification_status",
                 f"状态伪造：清单声明 {declared}，但证据计算为 {status}。"
                 "verification_status 由证据计算，禁止手填覆盖；请用 render 生成报告并同步清单")

    release_status = compute_release_status(capabilities, manifest_info, computed)
    declared_rs = manifest_info["declared_release_status"]
    if declared_rs is not None and declared_rs != release_status:
        fail(f"{manifest_path}:release_status",
             f"状态伪造：manifest 声明 {declared_rs}，按门槛计算为 {release_status}")
    return capabilities, manifest_info, computed, release_status


# ---------------------------------------------------------------------------
# 报告生成
# ---------------------------------------------------------------------------

def render_markdown(capabilities, manifest_info, computed, release_status,
                    catalog_path: Path, manifest_path: Path) -> str:
    raw = manifest_info["raw"]
    ended = raw.get("ended_at") or raw.get("started_at")
    report_date = ended[:10] if isinstance(ended, str) else "未记录（草稿证据包）"

    lines = []
    add = lines.append
    add("# WDSP 版本能力清单（自动生成）")
    add("")
    add("> 本文件由 `tools/capability_evidence.py render` 自动生成，禁止手工修改状态。")
    add("> 重新生成：`python3 tools/capability_evidence.py render "
        f"--catalog {catalog_path.name} --manifest <manifest> --output CAPABILITIES.md`")
    add("")
    add(f"- 构建：{raw.get('build_id')}")
    add(f"- 产品版本：{raw.get('product_version')}")
    source = raw.get("source", {})
    commit = source.get("commit") or "未记录"
    dirty = source.get("dirty")
    add(f"- 源码提交：{commit}（dirty={'是' if dirty else '否'}）")
    add(f"- 报告日期：{report_date}")
    add(f"- 发布状态：{release_status}")
    if release_status != "RELEASE_VERIFIED":
        add("- 说明：本报告不构成发布验收通过证明；无证据能力一律显示未验证，不展示通过徽标。")
    add("")
    add("## 能力总览")
    add("")
    add("| 能力 | 产品线 | 实现状态 | 接线状态 | 验证状态 |")
    add("|---|---|---|---|---|")
    for cap in capabilities:
        status, _ = computed[cap["id"]]
        add(f"| {cap['name']}（`{cap['id']}`） | {'/'.join(cap['product_lines'])} | "
            f"{cap['implementation_status']} | {cap['integration_status']} | {status} |")
    add("")
    add("## 分场景明细")
    for cap in capabilities:
        status, per_scenario = computed[cap["id"]]
        add("")
        add(f"### {cap['name']}（`{cap['id']}`）")
        add("")
        add(f"- 实现模块：{cap['owner_module']}")
        add(f"- 部署模式：{', '.join(cap['deployment_modes'])}")
        add(f"- 验证状态（强制场景最差结果）：{status}")
        add("- 实现引用：")
        for ref in cap["implementation_refs"]:
            symbol = f"（{ref['symbol']}）" if ref.get("symbol") else ""
            add(f"  - `{ref['path']}`{symbol}")
        add("- 场景：")
        for scen, st, details in per_scenario:
            mandatory = "强制" if scen["mandatory"] else "参考"
            add(f"  - `{scen['id']}`（{scen['name']}，{mandatory}）：{st}")
            if scen.get("note"):
                add(f"    - 说明：{scen['note']}")
            for d in details:
                add(f"    - {d}")
        if cap["prerequisites"]:
            add("- 前提：")
            for p in cap["prerequisites"]:
                add(f"  - {p}")
        if cap["limitations"]:
            add("- 限制（如实保留）：")
            for p in cap["limitations"]:
                add(f"  - {p}")
        refs = cap["evidence_refs"]
        add(f"- 证据引用：{', '.join(refs) if refs else '无（未验证）'}")
    add("")
    return "\n".join(lines)


def atomic_write(path: Path, text: str) -> None:
    """临时文件写入后原子替换；任何失败都不会破坏已存在的原文件。"""
    path = Path(path)
    directory = path.parent
    if not directory.exists():
        fail(str(path), f"输出目录不存在：{directory}")
    fd, tmp_name = tempfile.mkstemp(dir=str(directory), prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_check(args) -> int:
    capabilities, manifest_info, computed, release_status = evaluate(
        Path(args.catalog), Path(args.manifest))
    print(f"清单结构有效：{args.catalog}")
    print(f"证据 manifest 结构有效：{args.manifest}")
    for cap in capabilities:
        status, _ = computed[cap["id"]]
        print(f"  能力 {cap['id']}: 实现={cap['implementation_status']} "
              f"接线={cap['integration_status']} 验证={status}")
    print(f"发布状态（计算值）：{release_status}")
    if args.release:
        failures = release_gate_failures(capabilities, manifest_info, computed)
        if failures:
            print("发布门槛未满足，--release 拒绝通过：", file=sys.stderr)
            for reason in failures:
                print(f"  - {reason}", file=sys.stderr)
            return 1
        print("发布门槛全部满足：RELEASE_VERIFIED")
        return 0
    if release_status != "RELEASE_VERIFIED":
        print("结构有效，未完成验收：存在未验证/未通过的能力，本结果不能作为发布验收证明。")
    return 0


def cmd_render(args) -> int:
    capabilities, manifest_info, computed, release_status = evaluate(
        Path(args.catalog), Path(args.manifest))
    text = render_markdown(capabilities, manifest_info, computed, release_status,
                           Path(args.catalog), Path(args.manifest))
    atomic_write(Path(args.output), text)
    print(f"报告已生成：{args.output}（发布状态 {release_status}）")
    if release_status != "RELEASE_VERIFIED":
        print("注意：报告不含通过徽标；未验证能力已如实标注。")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="capability_evidence.py",
        description="WDSP 版本能力与证据清单校验/生成工具（P0-01）")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("check", "render"):
        p = sub.add_parser(name)
        p.add_argument("--catalog", required=True, help="能力清单 capabilities.json 路径")
        p.add_argument("--manifest", required=True, help="证据包 manifest.json 路径")
        if name == "check":
            p.add_argument("--release", action="store_true",
                           help="启用发布门槛：任何未满足项返回非零")
        else:
            p.add_argument("--output", required=True, help="生成的 Markdown 报告路径")
    args = parser.parse_args(argv)
    try:
        if args.command == "check":
            return cmd_check(args)
        return cmd_render(args)
    except CheckError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
