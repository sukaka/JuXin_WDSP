/* ==================== 阶段8 / WDSP：接口动态防护 展示元数据 ==================== */

/** 接口端点资产状态（与 server/internal/apiassets 状态枚举一致） */
export const API_ENDPOINT_STATUS_META: Record<string, { color: string; label: string }> = {
  DISCOVERED: { color: 'blue', label: '已发现' },
  CONFIRMED: { color: 'green', label: '已确认' },
  IGNORED: { color: 'default', label: '已忽略' },
  DEPRECATED: { color: 'orange', label: '已废弃' },
}

/** 接口端点学习状态（与 server/internal/apiassets 学习状态枚举一致） */
export const API_LEARNING_STATUS_META: Record<string, { color: string; label: string }> = {
  NOT_STARTED: { color: 'default', label: '未开始' },
  LEARNING: { color: 'processing', label: '学习中' },
  PAUSED: { color: 'gold', label: '已暂停' },
  LEARNED: { color: 'green', label: '已完成' },
}

/** 接口模型版本状态（与 server/internal/apimodels 状态枚举一致） */
export const API_MODEL_VERSION_STATUS_META: Record<string, { color: string; label: string }> = {
  CANDIDATE: { color: 'blue', label: '候选' },
  IN_REVIEW: { color: 'purple', label: '评审中' },
  FORMAL: { color: 'green', label: '正式' },
  REJECTED: { color: 'red', label: '已拒绝' },
  SUPERSEDED: { color: 'default', label: '已被取代' },
  ARCHIVED: { color: 'default', label: '已归档' },
}
