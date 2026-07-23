/* ==================== 阶段8 / WDSP：接口动态防护 展示元数据 ==================== */

import type { TreeDataNode } from 'antd'

/** 目录树扁平项（/api-security/endpoints/directory-tree 返回项） */
export interface DirectoryFlatItem {
  directory_path: string
  endpoint_count: number
}

/**
 * 把目录扁平列表组装成 antd Tree 层级数据：
 * - 按 `/` 切段逐级建树，节点 key 用全路径（如 /test、/test/php）
 * - 计数写在叶子（精确匹配）节点标题「段名 (计数)」；中间节点若无独立计数仅显示段名
 * - 空目录 '' 与 '/' 归到根节点（key 为 '/'）
 */
export function buildDirectoryTree(flat: DirectoryFlatItem[]): TreeDataNode[] {
  interface MutableNode {
    key: string
    title: string
    children?: MutableNode[]
  }
  const byPath = new Map<string, MutableNode>()

  const ensure = (fullPath: string, segment: string): MutableNode => {
    let node = byPath.get(fullPath)
    if (!node) {
      node = { key: fullPath, title: segment }
      byPath.set(fullPath, node)
    }
    return node
  }

  for (const { directory_path: dir, endpoint_count: count } of flat) {
    const segments = dir.split('/').filter(Boolean)
    if (segments.length === 0) {
      const root = ensure('/', '/')
      root.title = `/ (${count})`
      continue
    }
    let fullPath = ''
    let parent: MutableNode | undefined
    segments.forEach((segment, index) => {
      fullPath += `/${segment}`
      const node = ensure(fullPath, segment)
      if (index === segments.length - 1) {
        node.title = `${segment} (${count})`
      }
      if (parent) {
        parent.children = parent.children ?? []
        if (!parent.children.includes(node)) {
          parent.children.push(node)
        }
      }
      parent = node
    })
  }

  // 顶层节点：根 '/' 或单段路径（如 /api）
  const roots: MutableNode[] = []
  for (const node of byPath.values()) {
    const depth = node.key === '/' ? 0 : node.key.split('/').filter(Boolean).length
    if (depth <= 1) {
      roots.push(node)
    }
  }

  // 按全路径排序，保证渲染顺序稳定
  const sortRecursive = (nodes: MutableNode[]): void => {
    nodes.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0))
    for (const n of nodes) {
      if (n.children) sortRecursive(n.children)
    }
  }
  sortRecursive(roots)

  return roots
}

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

/** 敏感字段数据类型 */
export const API_SENSITIVE_TYPE_META: Record<string, { color: string; label: string }> = {
  phone: { color: 'volcano', label: '手机号' },
  id_card: { color: 'magenta', label: '身份证号' },
  bank_card: { color: 'red', label: '银行卡号' },
  email: { color: 'orange', label: '邮箱' },
  credential: { color: 'magenta', label: '凭据口令' },
  token: { color: 'volcano', label: '令牌密钥' },
  name: { color: 'gold', label: '姓名' },
  address: { color: 'gold', label: '住址' },
}

/** 风险发现严重级别 */
export const API_FINDING_SEVERITY_META: Record<string, { color: string; label: string }> = {
  CRITICAL: { color: 'magenta', label: '严重' },
  HIGH: { color: 'red', label: '高' },
  MEDIUM: { color: 'orange', label: '中' },
  LOW: { color: 'blue', label: '低' },
  INFO: { color: 'default', label: '信息' },
}

/** 风险发现类型 */
export const API_FINDING_TYPE_META: Record<string, { color: string; label: string }> = {
  SHADOW: { color: 'volcano', label: '影子接口' },
  ZOMBIE: { color: 'magenta', label: '僵尸接口' },
  DEPRECATED: { color: 'orange', label: '已下线接口' },
  BOLA: { color: 'red', label: '对象级越权' },
  BFLA: { color: 'red', label: '功能级越权' },
  SCHEMA_DEVIATION: { color: 'orange', label: '模型偏离' },
  SENSITIVE_LEAK: { color: 'magenta', label: '敏感数据泄露' },
  MASS_ASSIGNMENT: { color: 'red', label: '批量赋值' },
  BEHAVIOR_ANOMALY: { color: 'volcano', label: '行为异常' },
}

/** 风险发现处置状态 */
export const API_FINDING_STATUS_META: Record<string, { color: string; label: string }> = {
  OPEN: { color: 'red', label: '待处置' },
  ACKNOWLEDGED: { color: 'gold', label: '已知晓' },
  RESOLVED: { color: 'green', label: '已解决' },
  FALSE_POSITIVE: { color: 'default', label: '误报' },
}

/** Schema 违例类型 */
export const API_VIOLATION_TYPE_META: Record<string, { color: string; label: string }> = {
  undefined_field: { color: 'orange', label: '未定义字段' },
  type_mismatch: { color: 'red', label: '类型不匹配' },
  missing_field: { color: 'gold', label: '缺失字段' },
  constraint_violation: { color: 'volcano', label: '约束违例' },
}

/** 规范对比差异类型 */
export const API_SPEC_DIFF_TYPE_META: Record<string, { color: string; label: string }> = {
  MISSING_IN_RUNTIME: { color: 'volcano', label: '运行时缺失' },
  MISSING_IN_SPEC: { color: 'orange', label: '规范缺失' },
  CHANGED: { color: 'gold', label: '定义变更' },
}

/** API 防护模式 */
export const API_PROTECTION_MODE_META: Record<string, { color: string; label: string }> = {
  OFF: { color: 'default', label: '关闭' },
  OBSERVE: { color: 'gold', label: '观察' },
  PROTECT: { color: 'green', label: '防护' },
}
