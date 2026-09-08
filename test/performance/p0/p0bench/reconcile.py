"""事件对账计数（P0-02 任务书 §6.2.4，验收 BENCH-08）。

输入为按 request_id 对齐的多层记录，输出：
eligible / generated / persisted_unique / duplicated / pending / dropped / unknown。

定义：
- eligible:    按产生条件应产生事件的请求数（去重键=可信 request_id）。
- generated:   网关侧日志实际出现的事件（eligible 集合内去重计数）。
- persisted_unique: 管理存储/查询可见的唯一事件数。
- duplicated:  持久化层出现的重复条数（总数 - 唯一数）。
- pending:     已生成但尚未持久化（恢复追平窗口内的临时不可见，不等于丢失）。
- dropped:     有明确丢弃记录的事件数（丢弃台账，非推断）。
- unknown:     eligible 中既未生成也无丢弃记录的差额；恢复后仍 >0 视为疑点，
               不以短时间查询不到直接判断永久丢失。

仅管理查询可见但 request_id 不在 eligible 集合的事件计入 foreign（可能来自
伪造内部关联 ID，§6.2.1 禁止信任外部同名请求头）。
"""

from __future__ import annotations


def reconcile_events(
    eligible_ids,
    generated_ids,
    persisted_ids,
    dropped_ids=None,
) -> dict:
    eligible = set(eligible_ids or [])
    generated_all = [r for r in (generated_ids or []) if r in eligible]
    generated = set(generated_all)
    persisted_all = [r for r in (persisted_ids or []) if r in eligible]
    persisted = set(persisted_all)
    dropped = set(dropped_ids or []) & eligible

    foreign_generated = [r for r in (generated_ids or []) if r not in eligible]
    foreign_persisted = [r for r in (persisted_ids or []) if r not in eligible]

    pending = generated - persisted
    unknown = eligible - generated - dropped

    return {
        "eligible": len(eligible),
        "generated": len(generated),
        "generated_records": len(generated_all),
        "persisted_unique": len(persisted),
        "persisted_records": len(persisted_all),
        "duplicated": len(persisted_all) - len(persisted),
        "pending": len(pending),
        "dropped": len(dropped),
        "unknown": len(unknown),
        "foreign_generated": len(foreign_generated),
        "foreign_persisted": len(foreign_persisted),
    }


def permanent_loss(recon: dict, catchup_complete: bool) -> int | None:
    """永久丢失量：仅在恢复追平完成后判定；未完成返回 None（不可判定）。

    追平完成后，eligible 中既未持久化也无明确丢弃记录的数量即永久丢失。
    """
    if not catchup_complete:
        return None
    return recon["eligible"] - recon["persisted_unique"] - recon["dropped"]
