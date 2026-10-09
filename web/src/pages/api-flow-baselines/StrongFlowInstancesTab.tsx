import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  DatePicker,
  Descriptions,
  Drawer,
  Input,
  Radio,
  Select,
  Space,
  Tag,
  Timeline,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { applicationsApi } from '../../api/applications'
import { ApiError } from '../../api/client'
import {
  strongFlowApi,
  type StrongFlowInstance,
  type StrongFlowInstanceDetail,
  type StrongFlowStepEvent,
} from '../../api/strongFlow'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import {
  INSTANCE_STATUS_META,
  INSTANCE_TRANSITIONS_NOTE,
  RESOLVE_ACTION_META,
  STEP_EVENT_RESULT_META,
  canResolveInstance,
  classifyResolveConflict,
  shortInstanceKey,
} from '../../utils/strongFlow'

/** 管理恢复记录判定（FLOW-RESOLVE-001 原因码 / RESOLVE 动作——管理面对账来源，与网关执行侧区分） */
function isResolveEvent(ev: StrongFlowStepEvent): boolean {
  return ev.action === 'RESOLVE' || ev.reason_code === 'FLOW-RESOLVE-001'
}

function eventColor(ev: StrongFlowStepEvent): string {
  if (ev.result === 'OK') return 'green'
  if (ev.result === 'CONFLICT') return 'orange'
  if (ev.result === 'REJECTED') return 'red'
  return 'gray'
}

/** 步骤轨迹单条目渲染（摘要档四字段 + 明细档按 evidence_read 服务端裁剪后如实带出） */
function StepEventLine({ ev }: { ev: StrongFlowStepEvent }) {
  return (
    <Space direction="vertical" size={2}>
      <Space size={8} wrap>
        <Typography.Text strong>{ev.step_key || '（实例级）'}</Typography.Text>
        <Tag color="blue">{ev.action}</Tag>
        <Tag color={STEP_EVENT_RESULT_META[ev.result]?.color}>
          {STEP_EVENT_RESULT_META[ev.result]?.label ?? ev.result}
        </Tag>
        {isResolveEvent(ev) ? <Tag color="purple">管理对账</Tag> : null}
        <Typography.Text type="secondary">
          {formatDateTime(ev.occurred_at)}
        </Typography.Text>
      </Space>
      {ev.fencing_token !== undefined || ev.reason_code || ev.request_id ? (
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          {ev.fencing_token !== undefined
            ? `fencing_token=${ev.fencing_token}`
            : ''}
          {ev.reason_code ? ` · ${ev.reason_code}` : ''}
          {ev.request_id ? ` · request ${ev.request_id.slice(0, 8)}…` : ''}
        </Typography.Text>
      ) : null}
    </Space>
  )
}

/** 管理恢复表单（仅 ACTIVE/INDETERMINATE 可提交；expected_version 随行携带当前实例 version） */
function ResolvePanel({
  detail,
  onResolved,
}: {
  detail: StrongFlowInstanceDetail
  onResolved: () => void
}) {
  const { message } = AntdApp.useApp()
  const [action, setAction] = useState<string>('KEEP_UNKNOWN')
  const [reason, setReason] = useState('')
  const [conflict, setConflict] = useState<{
    kind: 'version' | 'terminal' | 'other'
    message: string
  } | null>(null)

  const resolveMut = useMutation({
    mutationFn: () =>
      strongFlowApi.resolveInstance(detail.id, {
        action,
        reason: reason.trim(),
        expected_version: detail.version,
      }),
    onSuccess: () => {
      message.success(
        action === 'KEEP_UNKNOWN'
          ? '已留痕保持未知（RESOLVE 事件落库）'
          : '实例已按对账结论推进终态',
      )
      setConflict(null)
      setReason('')
      onResolved()
    },
    onError: (e: unknown) => {
      if (e instanceof ApiError && e.status === 409) {
        setConflict({
          kind: classifyResolveConflict(e.message),
          message: e.message,
        })
        return
      }
      message.error(e instanceof ApiError ? e.message : '恢复提交失败')
    },
  })

  const reasonMissing = reason.trim() === ''

  return (
    <div>
      <Typography.Text strong>管理恢复（对账）</Typography.Text>
      <Space
        direction="vertical"
        size={8}
        style={{ width: '100%', marginTop: 8 }}
      >
        <Radio.Group
          value={action}
          onChange={(e) => setAction(e.target.value as string)}
          options={Object.entries(RESOLVE_ACTION_META).map(([value, meta]) => ({
            value,
            label: `${meta.label}（${value}）`,
          }))}
        />
        <Typography.Text type="secondary">
          {RESOLVE_ACTION_META[action]?.hint}
        </Typography.Text>
        <Typography.Text type="secondary">
          乐观锁版本：v{detail.version}（随提交比对，不匹配 409）
        </Typography.Text>
        <Input.TextArea
          aria-label="对账理由"
          rows={3}
          maxLength={512}
          showCount
          placeholder="对账理由（必填——恢复决定必须留理由，HIGH 审计全值在册）"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
        />
        {conflict ? (
          <Alert
            type="warning"
            showIcon
            message={
              conflict.kind === 'version'
                ? '版本冲突，请刷新后重试'
                : conflict.kind === 'terminal'
                  ? '实例已终态'
                  : '恢复被拒（409）'
            }
            description={
              conflict.kind === 'other'
                ? conflict.message
                : `${conflict.message}。实例状态可能已被其他操作变更，请刷新实例后再决定。`
            }
            action={
              <Button size="small" onClick={onResolved}>
                刷新实例
              </Button>
            }
          />
        ) : null}
        <Space>
          <Button
            type="primary"
            danger={action !== 'KEEP_UNKNOWN'}
            disabled={reasonMissing || reason.trim().length > 512}
            loading={resolveMut.isPending}
            onClick={() => resolveMut.mutate()}
          >
            提交恢复
          </Button>
          {reasonMissing ? (
            <Typography.Text type="secondary">reason 必填</Typography.Text>
          ) : null}
        </Space>
      </Space>
    </div>
  )
}

/** 实例详情抽屉：INDETERMINATE 固定警示条（逐字）+ 步骤轨迹时间线 + 恢复记录 + 恢复操作 */
function InstanceDetailDrawer({
  id,
  canManage,
  onClose,
}: {
  id: string
  canManage: boolean
  onClose: () => void
}) {
  const qc = useQueryClient()
  const detailQuery = useQuery({
    queryKey: ['strong-flow-instance', id],
    queryFn: () => strongFlowApi.getInstance(id),
  })
  const detail = detailQuery.data
  const resolveEvents = useMemo(
    () => (detail?.steps ?? []).filter(isResolveEvent),
    [detail],
  )
  const hasEvidenceDetail = (detail?.steps ?? []).some(
    (ev) => ev.fencing_token !== undefined || ev.reason_code || ev.request_id,
  )

  const refresh = () => {
    void detailQuery.refetch()
    void qc.invalidateQueries({ queryKey: ['strong-flow-instances'] })
  }

  return (
    <Drawer
      title={
        detail
          ? `强流程实例：${detail.definition_name || detail.definition_id.slice(0, 8)} · v${detail.definition_version}`
          : '强流程实例详情'
      }
      width={880}
      open
      onClose={onClose}
      destroyOnHidden
    >
      <QueryErrorAlert error={detailQuery.error} message="加载实例详情失败" />
      {detail ? (
        <Space direction="vertical" size={16} style={{ width: '100%' }}>
          {detail.status === 'INDETERMINATE' ? (
            <Alert
              type="warning"
              showIcon
              message={detail.status_message}
              description={
                <>
                  状态语义{' '}
                  <Typography.Text code>
                    {detail.status_semantics}
                  </Typography.Text>
                  ：本实例业务执行结果未确认（超时/失败/判定不命中均不自动回滚——源站可能已成功），
                  请核实源站事实后人工对账；不得按已通过处理。
                </>
              }
            />
          ) : null}
          <Descriptions size="small" column={2} bordered>
            <Descriptions.Item label="状态">
              <Space size={8}>
                <StatusTag value={detail.status} map={INSTANCE_STATUS_META} />
                <Typography.Text type="secondary">
                  {detail.status_message}
                </Typography.Text>
              </Space>
            </Descriptions.Item>
            <Descriptions.Item label="乐观锁版本">
              v{detail.version}
            </Descriptions.Item>
            <Descriptions.Item label="定义" span={2}>
              {detail.definition_name || '—'} · v{detail.definition_version}
              （创建时冻结，不换图）
            </Descriptions.Item>
            <Descriptions.Item label="实例键" span={2}>
              <Typography.Text code copyable={{ text: detail.instance_key }}>
                {detail.instance_key}
              </Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="租户引用">
              <Typography.Text code>
                {shortInstanceKey(detail.tenant_ref)}
              </Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="主体引用">
              <Typography.Text code>
                {shortInstanceKey(detail.principal_ref)}
              </Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="创建时间">
              {formatDateTime(detail.created_at)}
            </Descriptions.Item>
            <Descriptions.Item label="终态时间">
              {detail.terminated_at
                ? formatDateTime(detail.terminated_at)
                : '—'}
            </Descriptions.Item>
          </Descriptions>

          {canManage && canResolveInstance(detail.status) ? (
            <ResolvePanel detail={detail} onResolved={refresh} />
          ) : null}

          <div>
            <Typography.Text strong>
              步骤轨迹（{detail.steps.length} 条事件）
            </Typography.Text>
            {!hasEvidenceDetail && detail.steps.length > 0 ? (
              <Typography.Paragraph
                type="secondary"
                style={{ marginTop: 4, marginBottom: 0 }}
              >
                证据明细（fencing_token / reason_code / request_id）需
                api_authorization.evidence_read 权限，当前为摘要档轨迹。
              </Typography.Paragraph>
            ) : null}
            <Timeline
              style={{ marginTop: 12 }}
              items={detail.steps.map((ev, i) => ({
                key: i,
                color: eventColor(ev),
                children: <StepEventLine ev={ev} />,
              }))}
            />
          </div>

          <div>
            <Typography.Text strong>实例恢复记录</Typography.Text>
            {resolveEvents.length > 0 ? (
              <Timeline
                style={{ marginTop: 12 }}
                items={resolveEvents.map((ev, i) => ({
                  key: i,
                  color: 'purple',
                  children: <StepEventLine ev={ev} />,
                }))}
              />
            ) : (
              <Typography.Paragraph type="secondary" style={{ marginTop: 8 }}>
                暂无管理恢复记录。
              </Typography.Paragraph>
            )}
          </div>

          <Alert
            type="info"
            showIcon
            message="实例状态机"
            description={INSTANCE_TRANSITIONS_NOTE}
          />
        </Space>
      ) : (
        <Typography.Text type="secondary">加载中…</Typography.Text>
      )}
    </Drawer>
  )
}

/**
 * 强流程实例（NG-FLOW-02/03 §1.9）：五态实例列表 + 详情（步骤轨迹/恢复记录）+ 管理恢复。
 * INDETERMINATE=未知待对账（「未知，不显示安全通过」§9.4 红线，UI 不美化）。
 */
export default function StrongFlowInstancesTab() {
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'api_flow.manage')
  const [applicationId, setApplicationId] = useState<string>()
  const [statusFilter, setStatusFilter] = useState<string>()
  const [createdSince, setCreatedSince] = useState<string>()
  const [page, setPage] = useState(1)
  const [detailId, setDetailId] = useState<string | null>(null)

  const applicationsQuery = useQuery({
    queryKey: ['applications', 'strong-flow-options'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
  })

  const listQuery = useQuery({
    queryKey: [
      'strong-flow-instances',
      applicationId,
      statusFilter,
      createdSince,
      page,
    ],
    queryFn: () =>
      strongFlowApi.listInstances({
        application_id: applicationId || undefined,
        status: statusFilter || undefined,
        created_since: createdSince || undefined,
        page,
        page_size: 20,
      }),
  })

  const columns: ColumnsType<StrongFlowInstance> = [
    {
      title: '状态',
      dataIndex: 'status',
      width: 120,
      render: (v: string) => <StatusTag value={v} map={INSTANCE_STATUS_META} />,
    },
    {
      title: '定义',
      key: 'definition',
      width: 200,
      ellipsis: true,
      render: (_, record) => (
        <span>
          {record.definition_name || record.definition_id.slice(0, 8)}{' '}
          <Typography.Text type="secondary">
            v{record.definition_version}
          </Typography.Text>
        </span>
      ),
    },
    {
      title: '实例键',
      dataIndex: 'instance_key',
      width: 220,
      render: (v: string) => (
        <Typography.Text code title={v}>
          {shortInstanceKey(v)}
        </Typography.Text>
      ),
    },
    {
      title: '租户引用',
      dataIndex: 'tenant_ref',
      width: 150,
      render: (v: string) => shortInstanceKey(v),
    },
    {
      title: '主体引用',
      dataIndex: 'principal_ref',
      width: 150,
      render: (v: string) => shortInstanceKey(v),
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      width: 170,
      render: formatDateTime,
    },
    {
      title: '终态时间',
      dataIndex: 'terminated_at',
      width: 170,
      render: (v?: string | null) => (v ? formatDateTime(v) : '—'),
    },
    {
      title: '操作',
      key: 'actions',
      width: 90,
      fixed: 'right',
      render: (_, record) => (
        <Button type="link" size="small" onClick={() => setDetailId(record.id)}>
          详情
        </Button>
      ),
    },
  ]

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Typography.Paragraph type="secondary" style={{ marginBottom: 0 }}>
        强流程实例（PG
        事实源）：五态状态机，INDETERMINATE=未知待对账——超时/失败/判定不命中恒
        UNKNOWN 不自动回滚； 恢复操作仅在 ACTIVE/INDETERMINATE
        可用，终态拒绝重复恢复。
      </Typography.Paragraph>
      <Space wrap>
        <Select
          showSearch
          optionFilterProp="label"
          allowClear
          placeholder="全部应用"
          style={{ width: 260 }}
          value={applicationId}
          loading={applicationsQuery.isLoading}
          options={(applicationsQuery.data?.items ?? []).map((app) => ({
            value: app.id,
            label: `${app.name}（${app.code}）`,
          }))}
          onChange={(v) => {
            setApplicationId(v)
            setPage(1)
          }}
        />
        <Select
          allowClear
          placeholder="全部状态"
          style={{ width: 150 }}
          value={statusFilter}
          options={Object.entries(INSTANCE_STATUS_META).map(
            ([value, meta]) => ({ value, label: meta.label }),
          )}
          onChange={(v) => {
            setStatusFilter(v)
            setPage(1)
          }}
        />
        <DatePicker
          showTime
          placeholder="创建时间不早于"
          style={{ width: 220 }}
          onChange={(v) => {
            setCreatedSince(v ? v.toISOString() : undefined)
            setPage(1)
          }}
        />
      </Space>
      <QueryErrorAlert error={listQuery.error} message="加载强流程实例失败" />
      <SmartTable<StrongFlowInstance>
        storageKey="strong-flow-instances"
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        scroll={{ x: 1300 }}
        pagination={{
          current: page,
          pageSize: 20,
          total: listQuery.data?.total ?? 0,
          showSizeChanger: false,
          onChange: setPage,
        }}
        locale={{ emptyText: '暂无强流程实例' }}
      />
      {detailId ? (
        <InstanceDetailDrawer
          id={detailId}
          canManage={canManage}
          onClose={() => setDetailId(null)}
        />
      ) : null}
    </Space>
  )
}
