import { Alert, Button, Space, Typography } from 'antd'
import { Link } from 'react-router-dom'
import type { ApmAvailability } from '../types'
import { APM_REASON_CODE_LABELS, formatLagMs } from '../utils/apm'
import { formatDateTime } from '../utils/format'

/**
 * APM 数据质量自述（availability，P1-01 §4.3）统一展示：
 * - 字段缺失（旧后端）→「状态信息不足」，不编造原因；
 * - UNAVAILABLE →「调用链存储暂不可用」+ 原因 + 重试，不展示零值健康结论；
 * - PARTIAL / observed_sources 仅 GATEWAY → 如实说明数据边界；
 * - READY 且无原因码 → 不渲染（正常态不打搅）。
 */
export default function ApmAvailabilityAlert({
  availability,
  onRetry,
  retryLoading,
}: {
  availability?: ApmAvailability | null
  onRetry?: () => void
  retryLoading?: boolean
}) {
  if (availability == null) {
    return (
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 12 }}
        message="状态信息不足"
        description="当前服务未返回数据质量信息（可能是旧版本后端）；以下仅展示原始查询结果，不推断缺失原因。"
      />
    )
  }

  const reasons = (availability.reason_codes ?? []).map(
    (code) => APM_REASON_CODE_LABELS[code] ?? code,
  )

  if (availability.query_state === 'UNAVAILABLE') {
    return (
      <Alert
        type="warning"
        showIcon
        style={{ marginBottom: 12 }}
        message="调用链存储暂不可用"
        description={
          <Space direction="vertical" size={4}>
            {reasons.length > 0 && <span>原因：{reasons.join('；')}</span>}
            <span>
              存储恢复前，本页结果不代表业务真实状况，也不会展示「业务健康」「无异常」等零值结论。
            </span>
            {onRetry && (
              <span>
                <Button size="small" loading={retryLoading} onClick={onRetry}>
                  重试
                </Button>
              </span>
            )}
          </Space>
        }
      />
    )
  }

  // observed_sources 防御性兜底（契约恒为数组，旧/异常后端若给 null 不得让整页崩溃）
  const sources = availability.observed_sources ?? []
  const gatewayOnly = sources.length > 0 && !sources.includes('OTEL')
  const showReasons = availability.query_state === 'PARTIAL' && reasons.length > 0

  if (!availability.partial && !gatewayOnly && !showReasons) return null

  return (
    <Space direction="vertical" size={8} style={{ display: 'flex', marginBottom: 12 }}>
      {availability.partial && (
        <Alert
          type="warning"
          showIcon
          message="结果可能不完整"
          description={
            showReasons
              ? `原因：${reasons.join('；')}。以下仅为当前可用部分。`
              : '存在丢 Span、数据面降级或权限裁剪，以下仅为当前可用部分。'
          }
        />
      )}
      {gatewayOnly && (
        <Alert
          type="info"
          showIcon
          message="目前仅有网关观测数据"
          description={
            <Space direction="vertical" size={4}>
              <span>
                当前仅有入口延迟、TTFB
                等网关侧指标；代码级调用链、SQL 与异常诊断需要为应用接入 OTel 探针（安装流量镜像
                Agent 不会生成代码级 Trace）。接入步骤见《APM 客户接入指南》。
              </span>
              <span>
                <Link to="/apm-agents">
                  <Button size="small" type="link" style={{ padding: 0 }}>
                    前往「Agent 管理」创建注册令牌
                  </Button>
                </Link>
              </span>
            </Space>
          }
        />
      )}
    </Space>
  )
}

/** 采集/入库水位行（等待入库态展示；未知显示「未知」，不由空结果推断） */
export function ApmIngestWatermark({ availability }: { availability?: ApmAvailability | null }) {
  return (
    <Space direction="vertical" size={2}>
      <Typography.Text style={{ fontSize: 12 }}>
        最近采集时间：
        {availability?.last_collected_at ? formatDateTime(availability.last_collected_at) : '未知'}
      </Typography.Text>
      <Typography.Text style={{ fontSize: 12 }}>
        最近入库时间：
        {availability?.last_ingested_at ? formatDateTime(availability.last_ingested_at) : '未知'}
      </Typography.Text>
      <Typography.Text style={{ fontSize: 12 }}>
        入库滞后估计：{formatLagMs(availability?.estimated_lag_ms)}（表级水位估计，非该请求的精确延迟）
      </Typography.Text>
    </Space>
  )
}
