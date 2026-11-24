import type { CSSProperties } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Alert, Space, Typography } from 'antd'
import { securityRegressionApi } from '../../api/securityRegression'
import type { PublishTaskItem } from '../../types'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { hasPermission } from '../../utils/permission'
import {
  REG_GATE_MODE_META,
  extractFingerprintFromGateMessage,
  isRegressionGateFailure,
} from '../../utils/securityRegression'

/**
 * 配置发布入口的回归门禁状态（WDSP P1-04）。
 * - 无 security_regression.read 权限时不渲染（不向无权账号泄露且不发请求）；
 * - 门禁为默认 OFF 时不展示黄色警示条，避免干扰常规配置发布；
 * - 仅在 OBSERVE / ENFORCE 启用态展示当前门禁提示与安全回归入口；
 * - 策略加载失败如实提示，不静默吞错。
 */
export default function RegressionGateNotice({ style }: { style?: CSSProperties }) {
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canRead = hasPermission(permissions, 'security_regression.read')
  const policyQuery = useQuery({
    queryKey: ['security-regression-policy'],
    queryFn: securityRegressionApi.getPolicy,
    enabled: canRead,
  })
  if (!canRead) return null
  if (policyQuery.isError) {
    return (
      <Alert
        style={style}
        type="warning"
        showIcon
        message="回归门禁策略状态加载失败"
        description={
          policyQuery.error instanceof Error ? policyQuery.error.message : undefined
        }
      />
    )
  }
  const policy = policyQuery.data
  if (!policy || (policy.mode !== 'OBSERVE' && policy.mode !== 'ENFORCE')) return null
  const banner =
    policy.mode === 'ENFORCE'
      ? {
          type: 'success' as const,
          text: '回归门禁强制中：缺少绑定当前候选指纹且核验通过的回归证据时，发布将被拒绝',
        }
      : {
          type: 'info' as const,
          text: '回归门禁观察中：发布时计算并记录门禁结论，但不阻断不合规发布',
        }
  return (
    <Alert
      style={style}
      type={banner.type}
      showIcon
      message={
        <Space size={8} wrap>
          <StatusTag value={policy.mode} map={REG_GATE_MODE_META} />
          <span>{banner.text}</span>
          <Link to="/security-regressions">查看安全回归</Link>
        </Space>
      }
    />
  )
}

/**
 * 发布任务的回归门禁失败明细：列出确切缺失项（failure_message 原文，纯文本
 * 受限展开）+ 前往回归详情的跳转（指纹可提取时深链列表过滤）。仅展示与跳转，
 * 点击不会静默运行压测或修改生产规则（§8）。
 */
export function RegressionGateFailureDetail({ task }: { task: PublishTaskItem }) {
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canRead = hasPermission(permissions, 'security_regression.read')
  if (!isRegressionGateFailure(task.failure_code)) return null
  const fingerprint = extractFingerprintFromGateMessage(task.failure_message)
  const unavailable = task.failure_code === 'REGRESSION_GATE_UNAVAILABLE'
  return (
    <Space direction="vertical" size={8} style={{ display: 'flex', marginTop: 8 }}>
      <Typography.Paragraph
        style={{ marginBottom: 0, whiteSpace: 'pre-wrap' }}
        ellipsis={{ rows: 4, expandable: true, symbol: '展开' }}
      >
        {`确切缺失项：${task.failure_message || '（服务端未返回明细）'}`}
      </Typography.Paragraph>
      {canRead && (
        <Space size={12} wrap>
          <Link
            to={
              fingerprint
                ? `/security-regressions?fingerprint=${encodeURIComponent(fingerprint)}`
                : '/security-regressions'
            }
          >
            前往安全回归{fingerprint ? '（按候选指纹过滤）' : ''}查看证据与恢复动作
          </Link>
          {unavailable && (
            <Typography.Text type="secondary">
              门禁依赖不可用：请先恢复依赖（策略/密钥登记/证据存储），发布未静默放行
            </Typography.Text>
          )}
        </Space>
      )}
    </Space>
  )
}
