"""隔离与归属判定（P0-02 任务书 §3.1，验收 BENCH-01/02）。

规则要点：
- 每次运行唯一 run_id，compose project 固定为 p0bench-<run_id>。
- 资源归属判定要求同时满足 project 标签与 run_id 标签（数据库重建、容器停止、
  卷删除、故障注入、清理前的强制校验）。
- 压测/攻击目标必须属于本 project 网络（127.0.0.1 上本 run 的发布端口）或
  登记的专用测试地址；其余一律拒绝，重定向不得逃离允许集合。
- 仅设置 ALLOW_TEST=true 不足以证明隔离，本模块不读取该变量。
"""

from __future__ import annotations

import re
import socket
from urllib.parse import urlsplit

RUN_ID_RE = re.compile(r"^[0-9]{8}T[0-9]{6}-[a-z0-9]{6}$")
PROJECT_PREFIX = "p0bench-"
RUN_ID_LABEL = "p0bench.run_id"
COMPOSE_PROJECT_LABEL = "com.docker.compose.project"

_ALLOWED_SCHEMES = frozenset({"http", "https"})


def validate_run_id(run_id: str) -> bool:
    return isinstance(run_id, str) and RUN_ID_RE.match(run_id) is not None


def project_for_run(run_id: str) -> str:
    if not validate_run_id(run_id):
        raise ValueError(f"非法 run_id: {run_id!r}")
    return PROJECT_PREFIX + run_id


def owns_resource(labels: dict | None, run_id: str) -> bool:
    """资源（容器/卷/网络/数据库标记）是否属于本次运行。

    要求 compose project 标签与 run_id 标签同时匹配；任一缺失或不符即不归属，
    禁止对其进行停止/删除/重建/故障注入。
    """
    if not isinstance(labels, dict) or not validate_run_id(run_id):
        return False
    return (
        labels.get(COMPOSE_PROJECT_LABEL) == project_for_run(run_id)
        and labels.get(RUN_ID_LABEL) == run_id
    )


def _split_host_port(authority: str) -> tuple[str, str | None]:
    authority = authority.strip().lower()
    if not authority:
        return "", None
    if ":" in authority:
        host, _, port = authority.rpartition(":")
        return host, port
    return authority, None


def _target_matches(host: str, port: str | None, allowed_entry: str) -> bool:
    ahost, aport = _split_host_port(allowed_entry)
    if not ahost or host != ahost:
        return False
    # 登记条目带端口时必须精确匹配；不带端口时匹配该主机任意端口
    return aport is None or aport == port


def classify_target(url: str, allowed: set[str] | frozenset[str]) -> tuple[str, str]:
    """判定目标地址归属。返回 (类别, 原因)。

    类别: "allowed"（本 project 端口或登记地址）| "rejected"。
    allowed 集合由预检装配：本 run 的 127.0.0.1 发布端口（host:port 形式）
    加上 run-plan environment.isolation.registered_targets。
    """
    if not isinstance(url, str) or not url:
        return "rejected", "空目标地址"
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        return "rejected", f"URL 解析失败: {exc}"
    if parts.scheme.lower() not in _ALLOWED_SCHEMES:
        return "rejected", f"不允许的协议: {parts.scheme!r}（仅 http/https）"
    if parts.username or parts.password:
        return "rejected", "目标 URL 不得携带 userinfo 凭据"
    host = (parts.hostname or "").lower()
    if not host:
        return "rejected", "目标缺少主机名"
    port = str(parts.port) if parts.port is not None else None
    for entry in allowed:
        if _target_matches(host, port, entry):
            return "allowed", f"匹配允许目标 {entry}"
    return "rejected", f"目标 {host}:{port or '-'} 不属于本 project 网络或登记的专用测试地址"


def check_redirect_chain(locations: list[str], allowed: set[str] | frozenset[str]) -> tuple[bool, str]:
    """重定向链每一跳都必须仍在允许集合内（§3.1：重定向不可逃离允许目标）。"""
    for loc in locations:
        cls, reason = classify_target(loc, allowed)
        if cls != "allowed":
            return False, f"重定向逃离允许目标: {loc}（{reason}）"
    return True, "ok"


def is_port_free(port: int, host: str = "127.0.0.1", timeout: float = 0.5) -> bool:
    """端口占用检查（§3.1.6）：能连上即视为被占用。"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return False
    except OSError:
        return True


def compute_environment_fingerprint(machine_id: str, hostname: str) -> str:
    """环境唯一标识指纹：由宿主稳定标识合成，预检与 run-plan 比对。

    不采集/输出任何凭据或环境变量。machine_id 由运行器从宿主只读信息
    （如 /etc/machine-id 或 IOPlatformUUID）获取并脱敏后传入。
    """
    import hashlib

    raw = f"p0bench|{machine_id.strip()}|{hostname.strip()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def check_environment_identity(plan_environment_id: str, actual_fingerprint: str) -> tuple[bool, str]:
    """run-plan 登记的环境标识必须与实际环境指纹一致（§3.1.4）。"""
    if not plan_environment_id or not actual_fingerprint:
        return False, "环境标识为空"
    if plan_environment_id != actual_fingerprint:
        return False, (
            f"环境唯一标识不符: 计划登记 {plan_environment_id!r}，实际 {actual_fingerprint!r}"
        )
    return True, "ok"
