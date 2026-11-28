import { useEffect, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Card, Progress, Space, Steps, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { rulePacksApi } from '../../api/rulePacks'
import StatusTag from '../../components/StatusTag'
import { formatDateTime } from '../../utils/format'
import {
  formatRulePackFailureCode,
  isTerminalRulePackJobStatus,
  parseSyncReport,
  resolveRulePackStepIndex,
  RULEPACK_DEFAULT_POLL_INTERVAL_MS,
  RULEPACK_JOB_STATUS_META,
  RULEPACK_NODE_STEP_META,
} from './rulePackMeta'
import type { RulePackJob, RulePackNodeState } from '../../types'

export interface RulePackJobProgressProps {
  jobId: string
  initialJob?: RulePackJob | null
  pollIntervalMs?: number
  onFinished?: (job: RulePackJob) => void
}

const PIPELINE_STEPS = [
  { key: 'STAGING_LOCAL', title: '主节点解包' },
  { key: 'STAGING_STANDBY', title: '备节点落盘' },
  { key: 'PUBLISHING', title: '网关发布校验' },
  { key: 'ACTIVATING', title: '切换激活版本' },
  { key: 'SYNCING_METADATA', title: '同步规则元数据' },
]

const NODE_STATE_COLUMNS: ColumnsType<RulePackNodeState> = [
  {
    title: '节点',
    key: 'node',
    width: 170,
    render: (_, row) => (
      <Space size={6} wrap>
        <Typography.Text strong>{row.node_name}</Typography.Text>
        <Tag color={row.role === 'PRIMARY' ? 'gold' : 'blue'}>
          {row.role === 'PRIMARY' ? '主节点' : '备节点'}
        </Tag>
      </Space>
    ),
  },
  {
    title: '落盘校验',
    dataIndex: 'stage_status',
    width: 96,
    render: (v: string) => <StatusTag value={v} map={RULEPACK_NODE_STEP_META} />,
  },
  {
    title: '网关加载',
    dataIndex: 'load_status',
    width: 96,
    render: (v: string) => <StatusTag value={v} map={RULEPACK_NODE_STEP_META} />,
  },
  {
    title: '激活切换',
    dataIndex: 'activate_status',
    width: 96,
    render: (v: string) => <StatusTag value={v} map={RULEPACK_NODE_STEP_META} />,
  },
  {
    title: '诊断信息',
    key: 'error',
    render: (_, row) =>
      row.error_message || row.error_code ? (
        <Typography.Text type="danger" style={{ fontSize: 12 }}>
          {[row.error_code, row.error_message].filter(Boolean).join('：')}
        </Typography.Text>
      ) : (
        '-'
      ),
  },
]

/**
 * 规则包应用 / 回滚 5 阶段实时进度组件。
 * 每 1.5s 轮询 GET /api/v1/rule-packs/jobs/{job_id}，到达终态自动停止并回调 onFinished。
 */
export default function RulePackJobProgress({
  jobId,
  initialJob,
  pollIntervalMs = RULEPACK_DEFAULT_POLL_INTERVAL_MS,
  onFinished,
}: RulePackJobProgressProps) {
  const finishedJobIdRef = useRef<string | null>(null)

  const jobQuery = useQuery({
    queryKey: ['rule-packs', 'job', jobId],
    queryFn: () => rulePacksApi.getJob(jobId),
    initialData: initialJob ?? undefined,
    refetchInterval: (query) => {
      const status = query.state.data?.status
      if (status && isTerminalRulePackJobStatus(status)) {
        return false
      }
      return pollIntervalMs
    },
    retry: 2,
  })

  const job = jobQuery.data ?? initialJob ?? null

  useEffect(() => {
    if (!job || !isTerminalRulePackJobStatus(job.status)) return
    if (finishedJobIdRef.current === job.id) return
    finishedJobIdRef.current = job.id
    onFinished?.(job)
  }, [job, onFinished])

  if (!job) {
    return <Typography.Text type="secondary">正在读取任务进度...</Typography.Text>
  }

  const isFailed = job.status === 'FAILED' || job.status === 'ROLLED_BACK'
  const isSuccess = job.status === 'SUCCESS'
  const activeIdx = resolveRulePackStepIndex(job)
  const syncReport = parseSyncReport(job.sync_report)
  const nodeStates = job.node_states ?? []
  const isRollback = job.job_type === 'ROLLBACK'

  const stepItems = PIPELINE_STEPS.map((step, idx) => {
    let status: 'wait' | 'process' | 'finish' | 'error' = 'wait'
    if (isSuccess) {
      status = 'finish'
    } else if (isFailed) {
      if (idx < activeIdx) status = 'finish'
      else if (idx === activeIdx) status = 'error'
      else status = 'wait'
    } else {
      if (idx < activeIdx) status = 'finish'
      else if (idx === activeIdx) status = 'process'
      else status = 'wait'
    }
    return {
      key: step.key,
      title: step.title,
      status,
    }
  })

  return (
    <Space direction="vertical" size={14} style={{ width: '100%' }}>
      <Card
        size="small"
        title={
          <Space wrap size={8}>
            <Typography.Text strong>
              {isRollback ? '规则包回滚任务' : '规则包应用任务'}
            </Typography.Text>
            <Typography.Text code>
              {job.previous_version
                ? `${job.previous_version} → ${job.target_version || '-'}`
                : job.target_version || '-'}
            </Typography.Text>
            <StatusTag value={job.status} map={RULEPACK_JOB_STATUS_META} />
            {job.allow_degraded_ha && <Tag color="volcano">HA 应急降级模式</Tag>}
          </Space>
        }
        extra={
          job.finished_at ? (
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              完成时间：{formatDateTime(job.finished_at)}
            </Typography.Text>
          ) : null
        }
      >
        <Space direction="vertical" size={14} style={{ width: '100%' }}>
          <div>
            <Progress
              percent={isSuccess ? 100 : Math.max(0, Math.min(100, job.progress ?? 0))}
              status={isFailed ? 'exception' : isSuccess ? 'success' : 'active'}
            />
            <Typography.Text type="secondary">
              {job.current_step || '正在执行规则包切换流水线...'}
            </Typography.Text>
          </div>

          <Steps size="small" current={Math.min(activeIdx, PIPELINE_STEPS.length - 1)} items={stepItems} />

          {isSuccess && (
            <Alert
              type="success"
              showIcon
              message={
                isRollback
                  ? `已成功回滚至规则包 ${job.target_version || ''} 并刷新网关与规则库`
                  : `离线规则包 ${job.target_version || ''} 已生效并完成规则库自动同步`
              }
              description={
                <Space direction="vertical" size={4}>
                  {syncReport && (
                    <Typography.Text>
                      {`规则库同步汇总：新增 ${syncReport.added} 条、更新 ${syncReport.updated} 条、未变 ${syncReport.unchanged} 条、库中共 ${syncReport.total_in_db} 条${syncReport.total_parsed > 0 ? `（共解析 ${syncReport.total_parsed} 条）` : ''}`}
                    </Typography.Text>
                  )}
                  {job.publish_task_id && (
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                      关联配置发布任务：{job.publish_task_id.slice(0, 8)}
                    </Typography.Text>
                  )}
                  {job.allow_degraded_ha && (
                    <Typography.Text type="warning" style={{ fontSize: 12 }}>
                      本次为 HA 应急降级生效（原因：{job.degraded_reason || '-'}），请待备节点恢复后及时补齐同步。
                    </Typography.Text>
                  )}
                </Space>
              }
            />
          )}

          {isFailed && (
            <Alert
              type="error"
              showIcon
              message={`任务执行失败：${formatRulePackFailureCode(job.failure_code)}`}
              description={
                <Space direction="vertical" size={4}>
                  {job.failure_message && <Typography.Text>{job.failure_message}</Typography.Text>}
                  <Typography.Text strong>
                    {job.failure_code === 'METADATA_SYNC_FAILED'
                      ? '注意：网关已切换至目标规则包，仅规则库元数据同步失败；可通过右上角「更多运维 → 同步CRS规则」补齐索引。'
                      : `现网网关已保持原有规则版本${job.previous_version ? `（${job.previous_version}）` : ''}，业务流量未受影响。`}
                  </Typography.Text>
                </Space>
              }
            />
          )}
        </Space>
      </Card>

      {nodeStates.length > 0 && (
        <Card size="small" title={`节点执行明细（${nodeStates.length} 个节点）`}>
          <Table<RulePackNodeState>
            size="small"
            rowKey="id"
            columns={NODE_STATE_COLUMNS}
            dataSource={nodeStates}
            pagination={false}
            scroll={{ x: 600 }}
          />
        </Card>
      )}
    </Space>
  )
}
