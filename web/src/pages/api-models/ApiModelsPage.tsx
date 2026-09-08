import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { App as AntdApp, Button, Card, Drawer, Form, Input, Modal, Select, Space, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { PlusOutlined } from '@ant-design/icons'
import { apiEndpointsApi, apiModelsApi, type ApiModelVersion } from '../../api/apiAssets'
import { apiRuntimePoliciesApi, API_RUNTIME_POLICY_STATUS_META } from '../../api/apiRuntime'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import { API_MODEL_VERSION_STATUS_META } from '../../utils/stage8'

interface CandidateFormValues {
  schema_json: string
  change_summary?: string
}

/** 评审操作弹窗状态：提交评审 / 拒绝共用（comment 可选） */
interface ReviewAction {
  type: 'submit' | 'reject'
  record: ApiModelVersion
}

/** 状态机可用性（与 server/internal/apimodels 状态迁移一致） */
const canSubmitReview = (s: string) => s === 'CANDIDATE'
const canConfirmVersion = (s: string) => s === 'CANDIDATE' || s === 'IN_REVIEW'
const canRejectVersion = (s: string) => s === 'CANDIDATE' || s === 'IN_REVIEW'
const canActivateVersion = (s: string) => s === 'FORMAL'
const canArchiveVersion = (s: string) => s === 'FORMAL' || s === 'SUPERSEDED' || s === 'REJECTED'

/** 版本展示标签：vN + 状态（供对比/溯源选择器使用） */
function versionLabel(v: ApiModelVersion): string {
  const statusLabel = API_MODEL_VERSION_STATUS_META[v.status]?.label ?? v.status
  return `v${v.version_number} · ${statusLabel} · ${v.content_hash.slice(0, 8)}`
}

/** API Schema 模型版本（按接口管理，候选经评审与确认后冻结为正式模型） */
export default function ApiModelsPage() {
  const { message, modal } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canEdit = hasPermission(permissions, 'api_model.edit')
  const canReview = hasPermission(permissions, 'api_model.review')
  const canActivate = hasPermission(permissions, 'api_model.activate')
  const canArchive = hasPermission(permissions, 'api_model.archive')
  const canLearn = hasPermission(permissions, 'api_learning.start')

  const [endpointId, setEndpointId] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [createOpen, setCreateOpen] = useState(false)
  const [reviewAction, setReviewAction] = useState<ReviewAction | null>(null)
  const [reviewComment, setReviewComment] = useState('')
  /** 对比抽屉：diffSource 为当前版本，diffOtherId 为对比版本 */
  const [diffSource, setDiffSource] = useState<ApiModelVersion | null>(null)
  const [diffOtherId, setDiffOtherId] = useState<string | undefined>()
  /** 策略溯源抽屉：按模型版本查其编译产生的运行时策略 */
  const [traceSource, setTraceSource] = useState<ApiModelVersion | null>(null)
  const [detailRecord, setDetailRecord] = useState<ApiModelVersion | null>(null)
  const [form] = Form.useForm<CandidateFormValues>()

  /** 接口选择器数据源（模型版本按接口查询） */
  const endpointsQuery = useQuery({
    queryKey: ['api-endpoints', 'options'],
    queryFn: () => apiEndpointsApi.list({ page: 1, page_size: 100 }),
  })

  /** 接口列表加载后默认选中第一个，避免页面空白 */
  useEffect(() => {
    if (!endpointId && endpointsQuery.data?.items.length) {
      setEndpointId(endpointsQuery.data.items[0].id)
    }
  }, [endpointId, endpointsQuery.data])

  const listQuery = useQuery({
    queryKey: ['api-models', endpointId, page, pageSize],
    queryFn: () => apiModelsApi.list(endpointId as string, { page, page_size: pageSize }),
    enabled: !!endpointId,
  })

  /** 版本对比：other → 当前版本 的字段级差异（服务端计算并落库） */
  const diffQuery = useQuery({
    queryKey: ['api-model-diff', diffSource?.id, diffOtherId],
    queryFn: () => apiModelsApi.diff(diffSource?.id as string, diffOtherId as string),
    enabled: !!diffSource && !!diffOtherId,
  })

  /** 模型 → 策略溯源：该模型版本编译产生的运行时策略 */
  const traceQuery = useQuery({
    queryKey: ['api-model-runtime', traceSource?.id],
    queryFn: () => apiRuntimePoliciesApi.listByModel(traceSource?.id as string),
    enabled: !!traceSource,
  })

  const invalidateModels = () => void qc.invalidateQueries({ queryKey: ['api-models'] })

  const createMut = useMutation({
    mutationFn: (body: { schema: Record<string, string>; change_summary?: string }) =>
      apiModelsApi.createCandidate(endpointId as string, body),
    onSuccess: () => {
      message.success('候选版本已创建')
      setCreateOpen(false)
      form.resetFields()
      invalidateModels()
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '创建失败'),
  })

  const confirmMut = useMutation({
    mutationFn: (id: string) => apiModelsApi.confirm(id),
    onSuccess: (r) => {
      message.success(r.message || '已冻结')
      invalidateModels()
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '冻结失败'),
  })

  const reviewMut = useMutation({
    mutationFn: (action: ReviewAction & { comment?: string }) =>
      action.type === 'submit'
        ? apiModelsApi.submitReview(action.record.id, action.comment)
        : apiModelsApi.reject(action.record.id, action.comment),
    onSuccess: (r) => {
      message.success(r.message || '操作成功')
      setReviewAction(null)
      setReviewComment('')
      invalidateModels()
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '操作失败'),
  })

  const activateMut = useMutation({
    mutationFn: (id: string) => apiModelsApi.activate(id),
    onSuccess: (r) => {
      message.success(r.message || '已激活')
      invalidateModels()
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '激活失败'),
  })

  const archiveMut = useMutation({
    mutationFn: (id: string) => apiModelsApi.archive(id),
    onSuccess: (r) => {
      message.success(r.message || '已归档')
      invalidateModels()
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '归档失败'),
  })

  const relearnMut = useMutation({
    mutationFn: (id: string) => apiEndpointsApi.learningStart(id),
    onSuccess: (r) => {
      message.success(r.message || '学习任务已启动')
      invalidateModels()
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '启动学习失败'),
  })

  /** 行内操作统一二次确认：冻结后不可通过偏离自动扩宽 */
  const confirmFreeze = (record: ApiModelVersion) => {
    modal.confirm({
      title: '冻结确认',
      content: `确定将接口「${record.endpoint_key}」的版本 v${record.version_number} 冻结为正式模型吗？冻结后不可通过偏离自动扩宽。`,
      onOk: () => confirmMut.mutate(record.id),
    })
  }

  const confirmActivate = (record: ApiModelVersion) => {
    modal.confirm({
      title: '激活确认',
      content: `确定将版本 v${record.version_number} 激活为接口「${record.endpoint_key}」的当前模型吗？对应运行时策略将标记为待发布，随下次整站发布生效。`,
      onOk: () => activateMut.mutate(record.id),
    })
  }

  const confirmArchive = (record: ApiModelVersion) => {
    modal.confirm({
      title: '归档确认',
      content: `确定归档版本 v${record.version_number}（${record.endpoint_key}）吗？归档后仅保留只读溯源。`,
      onOk: () => archiveMut.mutate(record.id),
    })
  }

  /** 重新学习：为当前选中接口启动新一轮学习（已有运行中任务时服务端返回 409） */
  const confirmRelearn = () => {
    if (!endpointId || !selectedEndpoint) {
      message.warning('请先选择接口')
      return
    }
    modal.confirm({
      title: '重新学习',
      content: `确定为接口「${selectedEndpoint.endpoint_key}」启动新一轮学习吗？学习完成后将自动生成新的候选版本。`,
      onOk: () => relearnMut.mutate(endpointId),
    })
  }

  const openReview = (type: ReviewAction['type'], record: ApiModelVersion) => {
    setReviewAction({ type, record })
    setReviewComment('')
  }

  const openDiff = (record: ApiModelVersion) => {
    setDiffSource(record)
    setDiffOtherId(undefined)
  }

  const openCreate = () => {
    if (!endpointId) {
      message.warning('请先选择接口')
      return
    }
    setCreateOpen(true)
  }

  const handleCreate = (v: CandidateFormValues) => {
    if (!endpointId) {
      message.warning('请先选择接口')
      return
    }
    let schema: Record<string, string> = {}
    try {
      schema = JSON.parse(v.schema_json || '{}') as Record<string, string>
    } catch {
      message.error('结构定义须为 JSON 对象')
      return
    }
    createMut.mutate({ schema, change_summary: v.change_summary || undefined })
  }

  const selectedEndpoint = endpointsQuery.data?.items.find((e) => e.id === endpointId)

  const columns: ColumnsType<ApiModelVersion> = [
    {
      title: '接口键',
      dataIndex: 'endpoint_key',
      ellipsis: true,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: '版本',
      dataIndex: 'version_number',
      width: 80,
      render: (v: number) => `v${v}`,
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={API_MODEL_VERSION_STATUS_META} />,
    },
    {
      title: '哈希',
      dataIndex: 'content_hash',
      width: 140,
      render: (v: string) => (v ? <Typography.Text code>{v.slice(0, 10)}…</Typography.Text> : '-'),
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 280,
      fixed: 'right',
      render: (_, record) => (
        <Space size={0} wrap>
          {canReview && canSubmitReview(record.status) ? (
            <Button type="link" size="small" onClick={() => openReview('submit', record)}>
              提交评审
            </Button>
          ) : null}
          {canEdit && canConfirmVersion(record.status) ? (
            <Button type="link" size="small" onClick={() => confirmFreeze(record)}>
              确认冻结
            </Button>
          ) : null}
          {canReview && canRejectVersion(record.status) ? (
            <Button type="link" size="small" danger onClick={() => openReview('reject', record)}>
              拒绝
            </Button>
          ) : null}
          {canActivate && canActivateVersion(record.status) ? (
            <Button type="link" size="small" onClick={() => confirmActivate(record)}>
              激活
            </Button>
          ) : null}
          {canArchive && canArchiveVersion(record.status) ? (
            <Button type="link" size="small" onClick={() => confirmArchive(record)}>
              归档
            </Button>
          ) : null}
          <Button type="link" size="small" onClick={() => openDiff(record)}>
            对比
          </Button>
          <Button type="link" size="small" onClick={() => setTraceSource(record)}>
            策略溯源
          </Button>
        </Space>
      ),
    },
  ]

  return (
    <Card
      title="API 模型版本"
      extra={
        <Space>
          {canLearn ? (
            <Button onClick={confirmRelearn} disabled={!endpointId} loading={relearnMut.isPending}>
              重新学习
            </Button>
          ) : null}
          {canEdit ? (
            <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>
              创建候选
            </Button>
          ) : null}
        </Space>
      }
    >
      <Typography.Paragraph type="secondary">
        选择接口后管理其 Schema 模型版本：候选版本经评审与人工确认后冻结为正式模型；激活为当前模型后，对应运行时策略随下次整站发布生效。
      </Typography.Paragraph>
      <QueryErrorAlert error={endpointsQuery.error ?? listQuery.error} />
      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          placeholder="选择接口"
          showSearch
          optionFilterProp="label"
          style={{ width: 320 }}
          loading={endpointsQuery.isLoading}
          value={endpointId}
          options={(endpointsQuery.data?.items ?? []).map((e) => ({
            value: e.id,
            label: e.endpoint_key,
          }))}
          onChange={(v) => {
            setEndpointId(v)
            setPage(1)
          }}
        />
      </Space>
      <SmartTable<ApiModelVersion>
        storageKey="api-models"
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        onRow={(record) => ({
          onDoubleClick: () => setDetailRecord(record),
          style: { cursor: 'pointer' },
        })}
        locale={endpointId ? undefined : { emptyText: '请先选择接口查看模型版本' }}
        scroll={{ x: 1000 }}
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

      <Drawer
        title="创建候选版本"
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        width={560}
        destroyOnHidden
        footer={
          <Space style={{ display: 'flex', justifyContent: 'flex-end' }}>
            <Button onClick={() => setCreateOpen(false)}>取消</Button>
            <Button type="primary" loading={createMut.isPending} onClick={() => form.submit()}>
              创建
            </Button>
          </Space>
        }
      >
        <Typography.Paragraph type="secondary">
          目标接口：<Typography.Text code>{selectedEndpoint?.endpoint_key ?? '-'}</Typography.Text>
        </Typography.Paragraph>
        <Form<CandidateFormValues>
          form={form}
          layout="vertical"
          initialValues={{ schema_json: '{"id":"number","name":"string"}' }}
          onFinish={handleCreate}
        >
          <Form.Item
            name="schema_json"
            label="结构定义（JSON）"
            rules={[{ required: true, message: '请输入结构定义' }]}
          >
            <Input.TextArea rows={4} style={{ fontFamily: 'monospace' }} />
          </Form.Item>
          <Form.Item name="change_summary" label="变更说明（可选）">
            <Input placeholder="本次候选相对上一版本的变化" autoComplete="off" />
          </Form.Item>
        </Form>
      </Drawer>

      <Modal
        title={reviewAction?.type === 'submit' ? '提交评审' : '拒绝模型版本'}
        open={reviewAction !== null}
        onCancel={() => setReviewAction(null)}
        onOk={() =>
          reviewAction &&
          reviewMut.mutate({ ...reviewAction, comment: reviewComment.trim() || undefined })
        }
        okText={reviewAction?.type === 'submit' ? '提交评审' : '确认拒绝'}
        okButtonProps={{
          danger: reviewAction?.type === 'reject',
          loading: reviewMut.isPending,
        }}
        cancelText="取消"
        destroyOnHidden
      >
        <Typography.Paragraph type="secondary">
          目标版本：<Typography.Text code>{reviewAction?.record.endpoint_key}</Typography.Text>{' '}
          v{reviewAction?.record.version_number}
          {reviewAction?.type === 'submit' ? '，提交后进入评审中状态。' : '，拒绝后版本标记为已拒绝。'}
        </Typography.Paragraph>
        <Input.TextArea
          rows={3}
          placeholder={reviewAction?.type === 'submit' ? '评审意见（可选）' : '拒绝原因（可选，建议填写）'}
          value={reviewComment}
          onChange={(e) => setReviewComment(e.target.value)}
        />
      </Modal>

      <Drawer
        title={
          diffSource
            ? `版本对比：v${diffSource.version_number}（${diffSource.endpoint_key}）`
            : '版本对比'
        }
        open={diffSource !== null}
        onClose={() => setDiffSource(null)}
        width={560}
        destroyOnHidden
      >
        <Typography.Paragraph type="secondary">
          字段级差异方向：对比版本 → 当前版本（新增 / 移除 / 类型变化）。
        </Typography.Paragraph>
        <Select
          placeholder="选择对比版本"
          style={{ width: '100%', marginBottom: 16 }}
          value={diffOtherId}
          options={(listQuery.data?.items ?? [])
            .filter((v) => v.id !== diffSource?.id)
            .map((v) => ({ value: v.id, label: versionLabel(v) }))}
          onChange={(v) => setDiffOtherId(v)}
        />
        {diffOtherId ? (
          diffQuery.isLoading ? (
            <Typography.Text type="secondary">差异计算中…</Typography.Text>
          ) : diffQuery.error ? (
            <Typography.Text type="danger">
              {diffQuery.error instanceof ApiError ? diffQuery.error.message : '获取差异失败'}
            </Typography.Text>
          ) : diffQuery.data ? (
            <Space direction="vertical" size={12} style={{ width: '100%' }}>
              <div>
                <Typography.Text strong>新增字段</Typography.Text>
                <div style={{ marginTop: 4 }}>
                  {diffQuery.data.diff.added.length > 0 ? (
                    diffQuery.data.diff.added.map((f) => (
                      <Tag key={f} color="green">
                        {f}
                      </Tag>
                    ))
                  ) : (
                    <Typography.Text type="secondary">无</Typography.Text>
                  )}
                </div>
              </div>
              <div>
                <Typography.Text strong>移除字段</Typography.Text>
                <div style={{ marginTop: 4 }}>
                  {diffQuery.data.diff.removed.length > 0 ? (
                    diffQuery.data.diff.removed.map((f) => (
                      <Tag key={f} color="red">
                        {f}
                      </Tag>
                    ))
                  ) : (
                    <Typography.Text type="secondary">无</Typography.Text>
                  )}
                </div>
              </div>
              <div>
                <Typography.Text strong>类型变化</Typography.Text>
                <div style={{ marginTop: 4 }}>
                  {diffQuery.data.diff.type_changed.length > 0 ? (
                    diffQuery.data.diff.type_changed.map((c) => (
                      <div key={c.field}>
                        <Typography.Text code>{c.field}</Typography.Text>：{c.from} → {c.to}
                      </div>
                    ))
                  ) : (
                    <Typography.Text type="secondary">无</Typography.Text>
                  )}
                </div>
              </div>
            </Space>
          ) : null
        ) : (
          <Typography.Text type="secondary">请选择要对比的历史版本</Typography.Text>
        )}
      </Drawer>

      <Drawer
        title={
          traceSource
            ? `策略溯源：v${traceSource.version_number}（${traceSource.endpoint_key}）`
            : '策略溯源'
        }
        open={traceSource !== null}
        onClose={() => setTraceSource(null)}
        width={560}
        destroyOnHidden
      >
        <Typography.Paragraph type="secondary">
          该模型版本冻结时编译产生的 API 级运行时策略（随整站发布联动生效；完整列表见「运行时策略」页）。
        </Typography.Paragraph>
        {traceQuery.isLoading ? (
          <Typography.Text type="secondary">加载中…</Typography.Text>
        ) : traceQuery.error ? (
          <Typography.Text type="danger">
            {traceQuery.error instanceof ApiError ? traceQuery.error.message : '获取运行时策略失败'}
          </Typography.Text>
        ) : (traceQuery.data ?? []).length === 0 ? (
          <Typography.Text type="secondary">该模型版本尚未编译出运行时策略</Typography.Text>
        ) : (
          <Space direction="vertical" size={12} style={{ width: '100%' }}>
            {(traceQuery.data ?? []).map((p) => (
              <Card key={p.id} size="small">
                <Space direction="vertical" size={4}>
                  <Space size={8}>
                    <Typography.Text strong>{p.runtime_version}</Typography.Text>
                    <StatusTag value={p.status} map={API_RUNTIME_POLICY_STATUS_META} />
                  </Space>
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                    内容哈希 <Typography.Text code>{p.content_hash.slice(0, 16)}…</Typography.Text>
                  </Typography.Text>
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                    创建时间 {formatDateTime(p.created_at)}
                  </Typography.Text>
                  {p.error ? (
                    <Typography.Text type="danger" style={{ fontSize: 12 }}>
                      失败原因：{p.error}
                    </Typography.Text>
                  ) : null}
                </Space>
              </Card>
            ))}
          </Space>
        )}
      </Drawer>

      <RecordDetailDrawer
        open={detailRecord !== null}
        title="模型版本详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </Card>
  )
}
