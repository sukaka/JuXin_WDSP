"""P1 回归 profile 定义加载与校验（profiles/*.json）。

profile 描述一组生效模式组合（WAF 引擎 / API 动态防护 / JWT / 风险策略），
语料 expectations_by_profile 的键必须正好覆盖已登记 profile 集合。
S1 交付 OBSERVE 与 PROTECT 两个 profile；后续阶段新增 profile 时
语料校验自动要求全量覆盖，防止新模式下期望缺失。
"""

from __future__ import annotations

import json
import re
from pathlib import Path

PROFILE_ID_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,31}$")

#  profiles 目录不可用时的兜底词表（单元测试用）；真实校验以目录内容为准
DEFAULT_PROFILE_IDS = ("OBSERVE", "PROTECT")


class ProfileError(Exception):
    """profile 定义不满足契约。"""


def _validate_profile_doc(doc, path: Path) -> list[str]:
    errors: list[str] = []
    if not isinstance(doc, dict):
        return [f"{path.name}: 顶层必须是 JSON 对象"]
    if doc.get("schema_version") != 1:
        errors.append(f"{path.name}.schema_version: 必须为 1")
    pid = doc.get("profile_id")
    if not isinstance(pid, str) or not PROFILE_ID_RE.match(pid):
        errors.append(f"{path.name}.profile_id: 必须匹配 {PROFILE_ID_RE.pattern}")
    elif path.name != pid.lower() + ".json":
        errors.append(f"{path.name}: 文件名必须为 {pid.lower()}.json（与 profile_id 对应）")
    if not isinstance(doc.get("description"), str) or not doc.get("description"):
        errors.append(f"{path.name}.description: 必须为非空说明")
    modes = doc.get("modes")
    if not isinstance(modes, dict) or not modes:
        errors.append(f"{path.name}.modes: 必须为非空对象（生效模式组合）")
    else:
        for k, v in modes.items():
            if not isinstance(k, str) or not k or not isinstance(v, str) or not v:
                errors.append(f"{path.name}.modes.{k!r}: 键值都必须为非空字符串")
    if not isinstance(doc.get("blocking"), bool):
        errors.append(f"{path.name}.blocking: 必须为布尔值（该 profile 是否产生在线阻断）")
    return errors


def load_profiles(profiles_dir: str | Path) -> dict[str, dict]:
    """加载并校验 profiles 目录。任一文件非法即抛 ProfileError（逐条列出）。"""
    d = Path(profiles_dir)
    if not d.is_dir():
        raise ProfileError(f"profiles 目录不存在: {d}")
    errors: list[str] = []
    out: dict[str, dict] = {}
    files = sorted(d.glob("*.json"))
    if not files:
        raise ProfileError(f"profiles 目录无 profile 定义: {d}")
    for f in files:
        try:
            doc = json.loads(f.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"{f.name}: 不是合法 JSON: {exc}")
            continue
        errors.extend(_validate_profile_doc(doc, f))
        pid = doc.get("profile_id") if isinstance(doc, dict) else None
        if isinstance(pid, str):
            if pid in out:
                errors.append(f"{f.name}: 重复 profile_id {pid}")
            else:
                out[pid] = doc
    if errors:
        raise ProfileError("profile 定义不满足契约：\n" + "\n".join(f"  - {e}" for e in errors))
    return out


def profile_ids(profiles_dir: str | Path) -> tuple[str, ...]:
    return tuple(sorted(load_profiles(profiles_dir).keys()))
