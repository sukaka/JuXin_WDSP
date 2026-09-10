"""P0-02 正式基准环境就绪门禁。

正式矩阵、长稳与恢复实验必须由操作员显式声明运行在已登记的隔离环境。
门禁只核对声明与冻结计划，不把本机短测或自动探测结果当作正式环境证明。
"""

from __future__ import annotations

import json
from pathlib import Path


BLOCKED_EXIT_CODE = 3


def evaluate(plan: dict, ready: str, environment_id: str) -> dict:
    """返回可审计的门禁结果；不记录环境变量全集或任何凭据。"""
    environment = plan.get("environment") if isinstance(plan, dict) else None
    expected_id = environment.get("environment_id") if isinstance(environment, dict) else None
    reasons: list[str] = []
    if ready != "1":
        reasons.append("P0B_FORMAL_ENVIRONMENT_READY 未声明为 1")
    if not isinstance(expected_id, str) or not expected_id:
        reasons.append("冻结计划缺少 environment.environment_id")
    if not environment_id:
        reasons.append("P0B_FORMAL_ENV_ID 未提供")
    elif isinstance(expected_id, str) and environment_id != expected_id:
        reasons.append("P0B_FORMAL_ENV_ID 与冻结计划 environment.environment_id 不一致")

    is_ready = not reasons
    return {
        "status": "READY" if is_ready else "BLOCKED",
        "reason": "FORMAL_ENVIRONMENT_READY" if is_ready else "ENVIRONMENT_UNAVAILABLE",
        "plan_environment_id": expected_id,
        "runtime_environment_id": environment_id or None,
        "ready_assertion": ready,
        "formal_claim": is_ready,
        "details": reasons,
    }


def write_evidence(path: str | Path, result: dict) -> Path:
    """原子写入门禁证据，便于报告和人工复核。"""
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output)
    return output
