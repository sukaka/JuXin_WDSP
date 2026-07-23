/* ==================== 阶段8 / WDSP：接口动态防护 展示元数据 ==================== */

/** 接口端点资产状态（与 server/internal/apiassets 状态枚举一致） */
export const API_ENDPOINT_STATUS_META: Record<string, { color: string; label: string }> = {
  DISCOVERED: { color: 'blue', label: '已发现' },
  CONFIRMED: { color: 'green', label: '已确认' },
}

/** 接口模型版本状态（与 server/internal/apimodels 状态枚举一致） */
export const API_MODEL_VERSION_STATUS_META: Record<string, { color: string; label: string }> = {
  CANDIDATE: { color: 'blue', label: '候选' },
  FORMAL: { color: 'green', label: '正式' },
  SUPERSEDED: { color: 'default', label: '已被取代' },
}
