"""语料 manifest 校验（P0-02 任务书 §5）。

每条样本必须包含：case_id、类别、请求模板、生成种子、正常/攻击标签、
期望识别模块、各模式期望动作、源站期望、期望事件、来源/许可证说明。
deferred=true 的样本（依赖 S4 未交付能力）不计入任何检出/拦截率分母。

JWT（P0-03/S3 已交付）接线约定：
- expected_actions.profiles 除七模式主基线外可声明 jwt_off/jwt_protect 配对
  profile（JWT-18），每条样本（含 deferred）必须为全部声明 profile 给出期望；
- jwt_inject（valid/tampered）声明该样本回放时由运行器现场签发 Bearer Token
  并经 run 目录 0600 临时头文件注入；request_override.headers 禁止静态写入
  Authorization（语料不含任何 Token 材料）。
"""

from __future__ import annotations

import json
from pathlib import Path

from .plan import JWT_PAIR_PROFILES, PROFILES, sha256_file

LABELS = ("normal", "attack")
ACTIONS = ("PASS", "DETECT_PASS", "BLOCK_403", "BLOCK_401", "RATE_LIMIT_429")
ORIGIN_EXPECTATIONS = ("reached", "not_reached", "not_reached_when_protected")
EVENT_TYPES = ("none", "waf_security_event", "api_event", "access_control_event", "access_log")
JWT_INJECT_MODES = ("valid", "tampered")
ALL_PROFILES = PROFILES + JWT_PAIR_PROFILES
CASE_ID_RE_PART = r"^[NA]-[A-Z]+-\d{2}$"

import re

CASE_ID_RE = re.compile(CASE_ID_RE_PART)


class CorpusError(Exception):
    """语料 manifest 不满足 §5 契约。"""


def load_manifest(path: str | Path) -> dict:
    p = Path(path)
    try:
        with p.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError as exc:
        raise CorpusError(f"语料 manifest 不存在: {p}") from exc
    except json.JSONDecodeError as exc:
        raise CorpusError(f"语料 manifest 不是合法 JSON: {p}: {exc}") from exc
    if not isinstance(data, dict):
        raise CorpusError("语料 manifest 顶层必须是 JSON 对象")
    return data


def validate_manifest(manifest: dict) -> list[str]:
    errors: list[str] = []

    if manifest.get("schema_version") != 1:
        errors.append("schema_version: 必须为 1")
    sl = manifest.get("source_license")
    if not isinstance(sl, dict) or sl.get("origin") != "self_synthetic":
        errors.append("source_license.origin: 本阶段语料必须为 self_synthetic（自研合成）")
    templates = manifest.get("request_templates")
    if not isinstance(templates, dict) or not templates:
        errors.append("request_templates: 必须为非空对象")
        templates = {}

    # 声明的 profile 集合：七模式主基线必须全部声明；可追加 jwt_off/jwt_protect
    # 配对 profile（JWT-18）。每条样本的 expected_action 必须恰好覆盖声明集合。
    declared = (manifest.get("expected_actions") or {}).get("profiles")
    if not isinstance(declared, list) or not declared:
        errors.append("expected_actions.profiles: 必须为非空数组")
        declared = list(PROFILES)
    else:
        unknown = [p for p in declared if p not in ALL_PROFILES]
        if unknown:
            errors.append(f"expected_actions.profiles: 未知 profile {unknown}（已知 {list(ALL_PROFILES)}）")
        missing_base = [p for p in PROFILES if p not in declared]
        if missing_base:
            errors.append(f"expected_actions.profiles: 七模式主基线必须全部声明，缺 {missing_base}")

    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        errors.append("cases: 必须为非空数组")
        return errors

    seen_ids: set[str] = set()
    normal_categories: set[str] = set()
    for i, case in enumerate(cases):
        path = f"cases[{i}]"
        if not isinstance(case, dict):
            errors.append(f"{path}: 必须是对象")
            continue
        cid = case.get("case_id")
        if not isinstance(cid, str) or not CASE_ID_RE.match(cid):
            errors.append(f"{path}.case_id: 必须匹配 N-<类>-NN / A-<类>-NN")
        elif cid in seen_ids:
            errors.append(f"{path}.case_id: 重复 {cid}")
        else:
            seen_ids.add(cid)
        label = case.get("label")
        if label not in LABELS:
            errors.append(f"{path}.label: 必须为 normal/attack")
        cat = case.get("category")
        if not isinstance(cat, str) or not cat:
            errors.append(f"{path}.category: 必须为非空字符串")
        elif label == "normal":
            normal_categories.add(cat)
        tpl = case.get("template")
        if tpl not in templates:
            errors.append(f"{path}.template: 未定义的请求模板 {tpl!r}")
        if not isinstance(case.get("seed"), int):
            errors.append(f"{path}.seed: 必须为整数生成种子")
        if not isinstance(case.get("expected_detection_module"), str) or not case.get(
            "expected_detection_module"
        ):
            errors.append(f"{path}.expected_detection_module: 必须为非空字符串")
        actions = case.get("expected_action")
        if not isinstance(actions, dict):
            errors.append(f"{path}.expected_action: 必须为覆盖全部声明 profile 的对象")
        else:
            for prof in declared:
                if actions.get(prof) not in ACTIONS:
                    errors.append(
                        f"{path}.expected_action.{prof}: 必须为 {ACTIONS} 之一"
                    )
            extra = sorted(k for k in actions if k not in declared)
            if extra:
                errors.append(
                    f"{path}.expected_action: 含未在 expected_actions.profiles 声明的键 {extra}"
                )
        inject = case.get("jwt_inject")
        if inject is not None and inject not in JWT_INJECT_MODES:
            errors.append(f"{path}.jwt_inject: 必须为 {JWT_INJECT_MODES} 之一")
        override = case.get("request_override") or {}
        ov_headers = override.get("headers") or {}
        if isinstance(ov_headers, dict) and any(
            str(k).lower() == "authorization" for k in ov_headers
        ):
            errors.append(
                f"{path}.request_override.headers: 禁止静态写入 Authorization "
                "（Token 由 jwt_inject 声明 + 运行期临时头文件注入，语料不含 Token 材料）"
            )
        if case.get("origin_expectation") not in ORIGIN_EXPECTATIONS:
            errors.append(
                f"{path}.origin_expectation: 必须为 {ORIGIN_EXPECTATIONS} 之一"
            )
        ev = case.get("expected_event")
        if not isinstance(ev, dict) or ev.get("type") not in EVENT_TYPES:
            errors.append(f"{path}.expected_event.type: 必须为 {EVENT_TYPES} 之一")
        if case.get("source") != "self_synthetic":
            errors.append(f"{path}.source: 必须为 self_synthetic（自研合成标注）")
        if not isinstance(case.get("description"), str) or not case.get("description"):
            errors.append(f"{path}.description: 必须为非空说明")

    # 正常语料类别覆盖（§5 列举类别）
    required_normal = {
        "normal_sql_text",
        "normal_search_symbols",
        "normal_unicode_cjk",
        "normal_json_body",
        "normal_xml_body",
        "normal_multipart",
        "normal_upload",
        "normal_pagination",
        "normal_shared_object_role_switch",
        "normal_legit_jwt",
        "normal_boundary_size",
    }
    missing = sorted(required_normal - normal_categories)
    if missing:
        errors.append(f"正常语料类别不完整（§5），缺: {', '.join(missing)}")
    return errors


def require_valid_manifest(manifest: dict) -> None:
    errors = validate_manifest(manifest)
    if errors:
        raise CorpusError("语料 manifest 不满足契约：\n" + "\n".join(f"  - {e}" for e in errors))


def manifest_sha256(path: str | Path) -> str:
    return sha256_file(path)


def iter_active_cases(manifest: dict):
    """产出计入指标的非 deferred 样本。"""
    for case in manifest.get("cases", []):
        if not case.get("deferred"):
            yield case
