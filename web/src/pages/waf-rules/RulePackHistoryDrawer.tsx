import { useCallback, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Collapse,
  Drawer,
  Input,
  Modal,
  Space,
  Switch,
  Table,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { EyeOutlined, RollbackOutlined } from '@ant-design/icons'
import { ApiError } from '../../api/client'
import { rulePacksApi } from '../../api/rulePacks'
import StatusTag from '../../components/StatusTag'
import { formatBytes, formatDateTime } from '../../utils/format'
import RulePackJobProgress from './RulePackJobProgress'
import RulePackPreviewCard from './RulePackPreviewCard'
import {
  hasUnreadyStandby,
  isTerminalRulePackJobStatus,
  RULEPACK_STATUS_META,
} from './rulePackMeta'
import type { RulePackCurrentStatus, RulePackItem, RulePackJob } from '../../types'

export interface RulePackHistoryDrawerProps {
  open: boolean
  canManage: boolean
  currentStatus?: RulePackCurrentStatus | null
  pollIntervalMs?: number
  onClose: () => void
  onRollbackSuccess?: (job: RulePackJob) => void
}

/**
 * 离线规则包版本历史与一键回滚抽屉（§7.2）：
 * - 分页列出全部历史规则包与内置基线，支持只读查看预检报告（waf_rules.read）
 * - 对保留快照的历史版本向有 waf_rules.pack.manage 权限的管理员提供「回滚到此版本」
 * - 回滚复用 RulePackJobProgress 实时轮询 5 阶段进度，成功后自动刷新规则库
 */
export default function RulePackHistoryDrawer({
  open,
  canManage,
  currentStatus,
  pollIntervalMs,
  onClose,
  onRollbackSuccess,
}: RulePackHistoryDrawerProps) {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()

  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)
  const [inspectPack, setInspectPack] = useState<RulePackItem | null>(null)
  const [rollbackTarget, setRollbackTarget] = useState<RulePackItem | null>(null)
  const [allowDegradedHA, setAllowDegradedHA] = useState(false)
  const [degradedReason, setDegradedReason] = useState('')
  const [degradedReasonError, setDegradedReasonError] = useState<string | null>(null)
  const [activeRollbackJob, setActiveRollbackJob] = useState<RulePackJob | null>(null)
  const [rollbackJobTerminal, setRollbackJobTerminal] = useState(false)

  const listQuery = useQuery({
    queryKey: ['rule-packs', 'list', page, pageSize],
    queryFn: () => rulePacksApi.list({ page, page_size: pageSize }),
    enabled: open,
  })

  const inspectDetailQuery = useQuery({
    queryKey: ['rule-packs', 'detail', inspectPack?.id],
    queryFn: () => rulePacksApi.get(inspectPack!.id),
    enabled: open && inspectPack !== null,
    initialData: inspectPack ?? undefined,
  })

  const rollbackMutation = useMutation({
    mutationFn: (vars: { id: string; allowDegraded: boolean; reason: string }) =>
      rulePacksApi.rollback(vars.id, {
        allow_degraded_ha: vars.allowDegraded,
        degraded_reason: vars.allowDegraded ? vars.reason.trim() : '',
      }),
    onSuccess: (job) => {
      setRollbackTarget(null)
      setAllowDegradedHA(false)
      setDegradedReason('')
      setDegradedReasonError(null)
      setActiveRollbackJob(job)
      setRollbackJobTerminal(isTerminalRulePackJobStatus(job.status))
    },
    onError: (e: unknown) => {
      message.error(e instanceof ApiError ? e.message : '发起回滚失败')
    },
  })

  const handleRollbackJobFinished = useCallback(
    (job: RulePackJob) => {
      setActiveRollbackJob(job)
      setRollbackJobTerminal(true)
      void queryClient.invalidateQueries({ queryKey: ['rule-packs'] })
      if (job.status === 'SUCCESS') {
        void queryClient.invalidateQueries({ queryKey: ['waf-rules'] })
        onRollbackSuccess?.(job)
      }
    },
    [onRollbackSuccess, queryClient],
  )

  const standbyUnready = Boolean(
    currentStatus?.ha_sync_enabled && hasUnreadyStandby(currentStatus.nodes),
  )

  const isRollbackRunning = activeRollbackJob !== null && !rollbackJobTerminal

  const handleConfirmRollback = () => {
    if (!rollbackTarget) return
    if (allowDegradedHA && !degradedReason.trim()) {
      const err = '开启应急降级时必须填写降级原因'
      setDegradedReasonError(err)
      message.warning(err)
      return
    }
    setDegradedReasonError(null)
    rollbackMutation.mutate({
      id: rollbackTarget.id,
      allowDegraded: allowDegradedHA,
      reason: degradedReason,
    })
  }

  const columns: ColumnsType<RulePackItem> = [
    {
      title: '规则包版本',
      dataIndex: 'rulepack_version',
      width: 190,
      render: (v: string, record) => (
        <Space size={4} wrap>
          <Typography.Text code strong={record.status === 'APPLIED'}>
            {v}
          </Typography.Text>
          {record.is_builtin && <Tag color="geekblue">内置基线</Tag>}
        </Space>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 170,
      render: (v: string, record) => (
        <Space size={4} wrap>
          <StatusTag value={v} map={RULEPACK_STATUS_META} />
          {record.can_rollback && <Tag color="cyan">可回滚</Tag>}
          {(v === 'SUPERSEDED' || v === 'ROLLED_BACK') && !record.can_rollback && (
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              已清理
            </Typography.Text>
          )}
        </Space>
      ),
    },
    {
      title: 'CRS 版本',
      dataIndex: 'crs_version',
      width: 100,
      render: (v: string) => v || '-',
    },
    {
      title: '文件大小',
      dataIndex: 'file_size',
      width: 100,
      render: (v: number) => (v > 0 ? formatBytes(v) : '-'),
    },
    {
      title: '上传时间',
      dataIndex: 'uploaded_at',
      width: 165,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '生效时间',
      dataIndex: 'applied_at',
      width: 165,
      render: (v?: string | null) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 185,
      fixed: 'right',
      render: (_, record) => (
        <Space size={4}>
          <Button
            type="link"
            size="small"
            icon={<EyeOutlined />}
            onClick={() => setInspectPack(record)}
          >
            预检详情
          </Button>
          {canManage && record.can_rollback && (
            <Button
              type="link"
              size="small"
              danger
              icon={<RollbackOutlined />}
              disabled={isRollbackRunning}
              onClick={() => {
                setAllowDegradedHA(false)
                setDegradedReason('')
                setDegradedReasonError(null)
                setRollbackTarget(record)
              }}
            >
              回滚到此版本
            </Button>
          )}
        </Space>
      ),
    },
  ]

  return (
    <>
      <Drawer
        title="规则包版本历史与回滚"
        open={open}
        onClose={() => {
          if (isRollbackRunning) return
          setActiveRollbackJob(null)
          setRollbackJobTerminal(false)
          onClose()
        }}
        width={960}
        closable={!isRollbackRunning}
        maskClosable={!isRollbackRunning}
        keyboard={!isRollbackRunning}
        destroyOnHidden
      >
        <Space direction="vertical" size={16} style={{ width: '100%' }}>
          {currentStatus && (
            <Alert
              type="info"
              showIcon
              message={`当前生效版本：${currentStatus.active_version || '未版本化（传统目录）'} · CRS ${currentStatus.active_crs_version || '-'}`}
              description={`系统默认保留最近 ${currentStatus.retention || 5} 个历史有效快照，并永久保护当前版本、内置基线及最近配置版本引用的规则快照。`}
            />
          )}

          {activeRollbackJob && (
            <RulePackJobProgress
              jobId={activeRollbackJob.id}
              initialJob={activeRollbackJob}
              pollIntervalMs={pollIntervalMs}
              onFinished={handleRollbackJobFinished}
            />
          )}

          {listQuery.isError ? (
            <Alert
              type="error"
              showIcon
              message="加载规则包版本历史失败"
              description={listQuery.error instanceof ApiError ? listQuery.error.message : undefined}
            />
          ) : (
            <Table<RulePackItem>
              size="small"
              rowKey="id"
              loading={listQuery.isLoading}
              columns={columns}
              dataSource={listQuery.data?.items ?? []}
              scroll={{ x: 1080 }}
              pagination={{
                current: page,
                pageSize,
                total: listQuery.data?.total ?? 0,
                showSizeChanger: true,
                showTotal: (t) => `共 ${t} 条`,
                onChange: (p, ps) => {
                  setPage(p)
                  setPageSize(ps)
                },
              }}
            />
          )}
        </Space>
      </Drawer>

      <Modal
        title={`规则包预检与详情：${inspectPack?.rulepack_version ?? ''}`}
        open={inspectPack !== null}
        onCancel={() => setInspectPack(null)}
        footer={
          <Button onClick={() => setInspectPack(null)}>关闭</Button>
        }
        width={820}
        destroyOnHidden
      >
        {inspectDetailQuery.data ? (
          <RulePackPreviewCard pack={inspectDetailQuery.data} />
        ) : (
          <Typography.Text type="secondary">加载中...</Typography.Text>
        )}
      </Modal>

      <Modal
        title="确认回滚离线规则包"
        open={rollbackTarget !== null}
        onCancel={() => {
          if (rollbackMutation.isPending) return
          setRollbackTarget(null)
        }}
        onOk={handleConfirmRollback}
        okText="确认回滚"
        cancelText="取消"
        okButtonProps={{
          danger: true,
          disabled: standbyUnready && !allowDegradedHA,
        }}
        confirmLoading={rollbackMutation.isPending}
        destroyOnHidden
      >
        {rollbackTarget && (
          <Space direction="vertical" size={12} style={{ width: '100%' }}>
            <Typography.Paragraph style={{ marginBottom: 0 }}>
              确定将网关规则从当前版本{' '}
              <Typography.Text code>{currentStatus?.active_version || '-'}</Typography.Text>{' '}
              回滚至历史版本{' '}
              <Typography.Text code strong>
                {rollbackTarget.rulepack_version}
              </Typography.Text>
              （CRS {rollbackTarget.crs_version || '-'}）吗？
            </Typography.Paragraph>
            <Alert
              type="info"
              showIcon
              message="回滚过程经过完整网关校验与冒烟验证，成功后自动回退规则库元数据，且不修改客户自定义规则与例外配置。"
            />
            {standbyUnready && (
              <Collapse
                size="small"
                items={[
                  {
                    key: 'rollback-degraded-ha',
                    label: '应急降级：仅主节点回滚生效',
                    children: (
                      <Space direction="vertical" size={8} style={{ width: '100%' }}>
                        <Space align="center">
                          <Switch
                            checked={allowDegradedHA}
                            onChange={(checked) => {
                              setAllowDegradedHA(checked)
                              if (!checked) setDegradedReasonError(null)
                            }}
                          />
                          <Typography.Text strong>
                            允许备机离线降级仅主节点回滚（默认关闭）
                          </Typography.Text>
                        </Space>
                        {allowDegradedHA && (
                          <div>
                            <Input.TextArea
                              rows={2}
                              maxLength={500}
                              showCount
                              value={degradedReason}
                              status={degradedReasonError ? 'error' : undefined}
                              placeholder="必填：请填写应急降级回滚原因"
                              onChange={(e) => {
                                setDegradedReason(e.target.value)
                                if (e.target.value.trim()) setDegradedReasonError(null)
                              }}
                            />
                            {degradedReasonError && (
                              <Typography.Text type="danger" style={{ fontSize: 12 }}>
                                {degradedReasonError}
                              </Typography.Text>
                            )}
                          </div>
                        )}
                      </Space>
                    ),
                  },
                ]}
              />
            )}
          </Space>
        )}
      </Modal>
    </>
  )
}
