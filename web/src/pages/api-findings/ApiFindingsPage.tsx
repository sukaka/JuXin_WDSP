import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Button,
  Card,
  Descriptions,
  Drawer,
  Form,
  Input,
  Modal,
  Segmented,
  Select,
  Space,
  Table,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import type { FormInstance } from 'antd'
import type { NamePath } from 'antd/es/form/interface'
import type { ColumnsType } from 'antd/es/table'
import {
  apiFindingsApi,
  type ApiFinding,
  type ApiFindingHandleAction,
  type ApiFindingSummaryBucket,
  type ApiFindingSummaryGroupBy,
} from '../../api/apiSecurity'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime, formatJson } from '../../utils/format'
import { hasAnyPermission, hasPermission } from '../../utils/permission'
import {
  API_FINDING_SEVERITY_FILTER_OPTIONS,
  API_FINDING_SEVERITY_META,
  API_FINDING_STATUS_META,
  API_FINDING_TYPE_META,
  API_SUBJECT_TYPE_META,
  getApiFindingTypeMeta,
} from '../../utils/stage8'

/** 动态兼容动态/扩展风险类型（如 SCHEMA_*、LLM_* 等），避免页面回退原始英文码 */
function FindingTypeTag({ value }: { value: string }) {
  const meta = getApiFindingTypeMeta(value)
  return <Tag color={meta.color}>{meta.label}</Tag>
}

/** 页面内全部处置动作（confirm/start/ignore/archive 备注可选；resolve/false-positive 走必填弹窗） */
type FindingAction = ApiFindingHandleAction | 'resolve' | 'false-positive'

/**
 * 按当前状态给出可用处置动作（与 server 端 risk.go 状态机迁移表一一对应；
 * 后端状态机为最终裁决，此处仅做按钮显隐）：
 * NEW → confirm/false-positive/ignore；CONFIRMED → start/resolve/false-positive/ignore；
 * IN_PROGRESS → resolve/false-positive/ignore；RESOLVED/FALSE_POSITIVE/IGNORED → archive；ARCHIVED 终态无动作。
 */
function availableActions(status: string): FindingAction[] {
  switch ((status || '').toUpperCase()) {
    case 'NEW':
      return ['confirm', 'false-positive', 'ignore']
    case 'CONFIRMED':
      return ['start', 'resolve', 'false-positive', 'ignore']
    case 'IN_PROGRESS':
      return ['resolve', 'false-positive', 'ignore']
    case 'RESOLVED':
    case 'FALSE_POSITIVE':
    case 'IGNORED':
      return ['archive']
    default:
      // ARCHIVED 终态或未识别状态：不给出动作，避免必然被后端 400 拒绝的非法流转
      return []
  }
}

/** 处置动作中文名（按钮与成功提示共用） */
const ACTION_LABEL: Record<FindingAction, string> = {
  confirm: '确认',
  start: '开始处置',
  resolve: '标记解决',
  'false-positive': '标记误报',
  ignore: '忽略',
  archive: '归档',
}

/** 汇总三视图的中文名与首列标题 */
const SUMMARY_VIEW_META: Record<ApiFindingSummaryGroupBy, { label: string; column: string }> = {
  subject: { label: '按主体', column: '主体' },
  endpoint: { label: '按接口', column: '接口' },
  type: { label: '按类型', column: '类型' },
}

/** 汇总桶行 key：按视图取相应维度字段（匿名主体/未关联端点为空串，退化为稳定常量） */
function summaryRowKey(view: ApiFindingSummaryGroupBy, r: ApiFindingSummaryBucket): string {
  if (view === 'subject') return `${r.subject_type ?? ''}|${r.subject_id ?? ''}`
  if (view === 'endpoint') return r.endpoint_id ?? r.endpoint_key ?? ''
  return r.finding_type ?? ''
}

/** 汇总桶分组键展示：subject=主体标识（空为匿名主体）、endpoint=接口键（空为未关联）、type=风险类型标签 */
function SummaryKeyCell({ view, bucket }: { view: ApiFindingSummaryGroupBy; bucket: ApiFindingSummaryBucket }) {
  if (view === 'type') {
    return <FindingTypeTag value={bucket.finding_type ?? ''} />
  }
  if (view === 'endpoint') {
    return bucket.endpoint_key ? (
      <Typography.Text code>{bucket.endpoint_key}</Typography.Text>
    ) : (
      <Typography.Text type="secondary">未关联</Typography.Text>
    )
  }
  if (!bucket.subject_id) {
    return <Typography.Text type="secondary">匿名主体</Typography.Text>
  }
  return (
    <Space size={4}>
      {bucket.subject_type ? <StatusTag value={bucket.subject_type} map={API_SUBJECT_TYPE_META} /> : null}
      <Typography.Text code>{bucket.subject_id}</Typography.Text>
    </Space>
  )
}

/** 带必填文本域的处置弹窗（标记解决/标记误报共用）：关闭即销毁表单状态 */
function FindingActionModal<T extends Record<string, string>>({
  title,
  target,
  form,
  fieldName,
  fieldLabel,
  placeholder,
  loading,
  onCancel,
  onFinish,
}: {
  title: string
  target: ApiFinding | null
  form: FormInstance<T>
  fieldName: keyof T & string
  fieldLabel: string
  placeholder: string
  loading: boolean
  onCancel: () => void
  onFinish: (values: T) => void
}) {
  return (
    <Modal
      title={target ? `${title}：${target.title}` : title}
      open={target !== null}
      onCancel={onCancel}
      confirmLoading={loading}
      okText="确定"
      cancelText="取消"
      onOk={() => form.submit()}
      destroyOnHidden
    >
      <Form<T> form={form} layout="vertical" onFinish={onFinish} preserve={false}>
        {/* keyof T & string 与 antd NamePath 条件类型不兼容；表单键恒为字符串，收窄为默认 NamePath */}
        <Form.Item
          name={fieldName as NamePath}
          label={fieldLabel}
          rules={[
            { required: true, whitespace: true, message: `请输入${fieldLabel}` },
            // 后端上限 512 字符（riskNoteMaxRunes），前端收紧到 500 留余量
            { max: 500, message: `${fieldLabel}不超过 500 字` },
          ]}
        >
          <Input.TextArea rows={4} maxLength={500} showCount placeholder={placeholder} />
        </Form.Item>
      </Form>
    </Modal>
  )
}

/** API 风险发现（WDSP / 阶段8 + P0 风险中心）：风险列表、三视图降噪汇总与七态处置流转 */
export default function ApiFindingsPage() {
  const { message, modal } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  /** 处置按钮显隐：api_risk.handle；汇总卡片与详情增强：api_risk.read（handle 含读语义） */
  const canHandle = hasPermission(permissions, 'api_risk.handle')
  const canViewRisk = hasAnyPermission(permissions, ['api_risk.read', 'api_risk.handle'])

  const [findingType, setFindingType] = useState<string | undefined>()
  const [severity, setSeverity] = useState<string | undefined>()
  const [status, setStatus] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [selected, setSelected] = useState<ApiFinding | null>(null)
  const [summaryView, setSummaryView] = useState<ApiFindingSummaryGroupBy>('type')
  const [resolveTarget, setResolveTarget] = useState<ApiFinding | null>(null)
  const [fpTarget, setFpTarget] = useState<ApiFinding | null>(null)
  const [resolveForm] = Form.useForm<{ resolution: string }>()
  const [fpForm] = Form.useForm<{ reason: string }>()

  const listQuery = useQuery({
    queryKey: ['api-findings', findingType, severity, status, page, pageSize],
    queryFn: () =>
      apiFindingsApi.list({
        finding_type: findingType,
        severity,
        status,
        page,
        page_size: pageSize,
      }),
  })

  /** 汇总三视图一次拉取（无 group_by 参数），Segmented 仅做前端本地切换 */
  const summaryQuery = useQuery({
    queryKey: ['api-findings', 'summary'],
    queryFn: () => apiFindingsApi.summary(),
    enabled: canViewRisk,
  })

  /** 风险详情增强（主体/风险分/累计命中/证据/版本 + 近似关联 request_id）；api_risk.read 才可查 */
  const detailQuery = useQuery({
    queryKey: ['api-findings', 'detail', selected?.id],
    queryFn: () => apiFindingsApi.detail(selected?.id as string),
    enabled: selected !== null && canViewRisk,
  })

  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  /** 处置成功后：失效列表/汇总/详情、关闭抽屉与弹窗 */
  const afterAction = () => {
    void qc.invalidateQueries({ queryKey: ['api-findings'] })
    setSelected(null)
    setResolveTarget(null)
    setFpTarget(null)
  }

  const handleMut = useMutation({
    mutationFn: ({ id, action }: { id: string; action: ApiFindingHandleAction }) =>
      apiFindingsApi.handle(id, action),
    onSuccess: (_r, vars) => {
      message.success(`${ACTION_LABEL[vars.action]}成功`)
      afterAction()
    },
    onError,
  })

  const resolveMut = useMutation({
    mutationFn: ({ id, resolution }: { id: string; resolution: string }) => apiFindingsApi.resolve(id, resolution),
    onSuccess: () => {
      message.success('已标记为解决')
      afterAction()
    },
    onError,
  })

  const falsePositiveMut = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) => apiFindingsApi.falsePositive(id, reason),
    onSuccess: () => {
      message.success('已标记为误报')
      afterAction()
    },
    onError,
  })

  /** confirm/start/ignore/archive：二次确认后直接提交（备注可选，页面从简不传） */
  const confirmAction = (record: ApiFinding, action: ApiFindingHandleAction) => {
    const textMap: Record<ApiFindingHandleAction, string> = {
      confirm: `确定确认风险「${record.title}」吗？确认后表示该风险属实。`,
      start: `确定开始处置风险「${record.title}」吗？状态将流转为处理中。`,
      ignore: `确定忽略风险「${record.title}」吗？忽略后不再出现在待处置列表。`,
      archive: `确定归档风险「${record.title}」吗？归档后该风险转为历史记录。`,
    }
    modal.confirm({
      title: `${ACTION_LABEL[action]}确认`,
      content: textMap[action],
      onOk: () => handleMut.mutate({ id: record.id, action }),
    })
  }

  /** 处置动作分发：resolve/false-positive 走必填弹窗，其余二次确认 */
  const runAction = (record: ApiFinding, action: FindingAction) => {
    if (action === 'resolve') {
      setResolveTarget(record)
    } else if (action === 'false-positive') {
      setFpTarget(record)
    } else {
      confirmAction(record, action)
    }
  }

  /** 抽屉内的处置按钮组（按状态机可用性过滤 + 权限显隐） */
  const drawerActions = (record: ApiFinding) => (
    <Space style={{ marginBottom: 16 }} wrap>
      {availableActions(record.status).map((action) => (
        <Button key={action} onClick={() => runAction(record, action)}>
          {ACTION_LABEL[action]}
        </Button>
      ))}
    </Space>
  )

  const summaryBuckets: ApiFindingSummaryBucket[] =
    summaryView === 'subject'
      ? (summaryQuery.data?.by_subject ?? [])
      : summaryView === 'endpoint'
        ? (summaryQuery.data?.by_endpoint ?? [])
        : (summaryQuery.data?.by_finding_type ?? [])

  const summaryColumns: ColumnsType<ApiFindingSummaryBucket> = [
    {
      title: SUMMARY_VIEW_META[summaryView].column,
      key: 'key',
      ellipsis: true,
      render: (_, r) => <SummaryKeyCell view={summaryView} bucket={r} />,
    },
    { title: '风险条目', dataIndex: 'count', width: 100 },
    { title: '累计命中', dataIndex: 'hits', width: 100 },
    {
      title: '最高级别',
      dataIndex: 'max_severity',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={API_FINDING_SEVERITY_META} />,
    },
    {
      title: '最近发现',
      dataIndex: 'last_seen_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
  ]

  const columns: ColumnsType<ApiFinding> = [
    {
      title: '类型',
      dataIndex: 'finding_type',
      width: 110,
      render: (v: string) => <FindingTypeTag value={v} />,
    },
    {
      title: '严重级别',
      dataIndex: 'severity',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={API_FINDING_SEVERITY_META} />,
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={API_FINDING_STATUS_META} />,
    },
    { title: '标题', dataIndex: 'title', ellipsis: true },
    {
      title: '接口',
      dataIndex: 'endpoint_key',
      width: 220,
      ellipsis: true,
      render: (v: string, record) =>
        v ? (
          <Tooltip title={`${v}（ID: ${record.endpoint_id ?? '-'}）`}>
            <Typography.Text code>{v}</Typography.Text>
          </Tooltip>
        ) : (
          '-'
        ),
    },
    {
      title: '首次发现',
      dataIndex: 'first_seen_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '最近发现',
      dataIndex: 'last_seen_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: canHandle ? 200 : 80,
      fixed: 'right',
      render: (_, record) => (
        <Space size={0} wrap>
          <Button type="link" size="small" onClick={() => setSelected(record)}>
            详情
          </Button>
          {/* 行内快捷动作：仅给出前向入口（确认/开始处置），完整动作见详情抽屉 */}
          {canHandle
            ? availableActions(record.status)
                .filter((a) => a === 'confirm' || a === 'start')
                .map((action) => (
                  <Button key={action} type="link" size="small" onClick={() => runAction(record, action)}>
                    {ACTION_LABEL[action]}
                  </Button>
                ))
            : null}
        </Space>
      ),
    },
  ]

  /** 详情增强数据（api_risk.read 才有）；未加载完成前抽屉先展示列表行数据 */
  const detail = detailQuery.data?.finding
  const relatedIds = detailQuery.data?.related_request_ids ?? []
  const evidenceEntries = Object.entries(detail?.evidence ?? {})

  return (
    <Card title="API 风险发现">
      <Typography.Paragraph type="secondary">
        运行时识别出的 API 风险：影子/僵尸 API、对象级与功能级越权、模型偏离、敏感数据泄露等。支持按主体/接口/类型三维汇总，
        处置流转：确认 → 开始处置 → 解决/误报/忽略 → 归档（七态状态机，非法流转由后端拒绝）。
      </Typography.Paragraph>
      {canViewRisk ? (
        <Card type="inner" size="small" title="风险汇总" style={{ marginBottom: 16 }}>
          <Space direction="vertical" size={12} style={{ width: '100%' }}>
            <Segmented<ApiFindingSummaryGroupBy>
              value={summaryView}
              onChange={setSummaryView}
              options={(
                [
                  ['subject', '按主体'],
                  ['endpoint', '按接口'],
                  ['type', '按类型'],
                ] as Array<[ApiFindingSummaryGroupBy, string]>
              ).map(([value, label]) => ({ value, label }))}
            />
            <QueryErrorAlert error={summaryQuery.error} />
            <Table<ApiFindingSummaryBucket>
              rowKey={(r) => summaryRowKey(summaryView, r)}
              size="small"
              loading={summaryQuery.isLoading}
              columns={summaryColumns}
              dataSource={summaryBuckets}
              pagination={false}
              locale={{ emptyText: '暂无风险发现' }}
            />
          </Space>
        </Card>
      ) : null}
      <QueryErrorAlert error={listQuery.error} />
      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          placeholder="风险类型"
          allowClear
          style={{ width: 160 }}
          value={findingType}
          options={Object.entries(API_FINDING_TYPE_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => {
            setFindingType(v)
            setPage(1)
          }}
        />
        <Select
          placeholder="严重级别"
          allowClear
          style={{ width: 140 }}
          value={severity}
          options={API_FINDING_SEVERITY_FILTER_OPTIONS}
          onChange={(v) => {
            setSeverity(v)
            setPage(1)
          }}
        />
        <Select
          placeholder="处置状态"
          allowClear
          style={{ width: 140 }}
          value={status}
          options={Object.entries(API_FINDING_STATUS_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => {
            setStatus(v)
            setPage(1)
          }}
        />
      </Space>
      <SmartTable<ApiFinding>
        storageKey="api-findings"
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        scroll={{ x: 1200 }}
        onRow={(record) => ({
          onDoubleClick: () => setSelected(record),
          style: { cursor: 'pointer' },
        })}
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
        title={selected ? `风险详情：${selected.title}` : '风险详情'}
        open={selected !== null}
        onClose={() => setSelected(null)}
        width={720}
      >
        {selected ? (
          <>
            <Descriptions column={2} size="small" style={{ marginBottom: 16 }}>
              <Descriptions.Item label="风险类型">
                <FindingTypeTag value={selected.finding_type} />
              </Descriptions.Item>
              <Descriptions.Item label="严重级别">
                <StatusTag value={selected.severity} map={API_FINDING_SEVERITY_META} />
              </Descriptions.Item>
              <Descriptions.Item label="处置状态">
                <StatusTag value={selected.status} map={API_FINDING_STATUS_META} />
              </Descriptions.Item>
              <Descriptions.Item label="接口">
                {selected.endpoint_key ? <Typography.Text code>{selected.endpoint_key}</Typography.Text> : '-'}
              </Descriptions.Item>
              <Descriptions.Item label="接口 ID">
                {selected.endpoint_id ? <Typography.Text code>{selected.endpoint_id}</Typography.Text> : '-'}
              </Descriptions.Item>
              <Descriptions.Item label="请求 ID">
                <Typography.Text code>{selected.request_id || '-'}</Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label="发现 ID">
                <Typography.Text code>{selected.id}</Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label="首次发现">{formatDateTime(selected.first_seen_at)}</Descriptions.Item>
              <Descriptions.Item label="最近发现">{formatDateTime(selected.last_seen_at)}</Descriptions.Item>
              {/* 以下为风险中心详情字段（GET /findings/{id}，api_risk.read），加载完成后展示 */}
              {detail ? (
                <>
                  <Descriptions.Item label="主体类型">
                    {detail.subject_type ? <StatusTag value={detail.subject_type} map={API_SUBJECT_TYPE_META} /> : '-'}
                  </Descriptions.Item>
                  <Descriptions.Item label="主体标识">
                    {detail.subject_id ? <Typography.Text code>{detail.subject_id}</Typography.Text> : '匿名主体'}
                  </Descriptions.Item>
                  <Descriptions.Item label="风险分">{detail.risk_score ?? '-'}</Descriptions.Item>
                  <Descriptions.Item label="累计命中">{detail.count}</Descriptions.Item>
                  <Descriptions.Item label="模型版本">{detail.model_version || '-'}</Descriptions.Item>
                  <Descriptions.Item label="策略版本">{detail.policy_version || '-'}</Descriptions.Item>
                </>
              ) : null}
              <Descriptions.Item label="标题" span={2}>
                {selected.title}
              </Descriptions.Item>
            </Descriptions>
            {canViewRisk ? <QueryErrorAlert error={detailQuery.error} /> : null}
            {canHandle ? (
              <>
                <Typography.Title level={5}>处置操作</Typography.Title>
                {drawerActions(selected)}
              </>
            ) : null}
            {detail ? (
              <>
                <Typography.Title level={5}>关联请求</Typography.Title>
                <Typography.Paragraph type="secondary" style={{ marginBottom: 8 }}>
                  {detailQuery.data?.related_request_note ??
                    '同 API（同身份）近期运行时事件的请求 ID，近似关联，非精确命中回放'}
                </Typography.Paragraph>
                {relatedIds.length > 0 ? (
                  <Space size={4} wrap style={{ marginBottom: 16 }}>
                    {relatedIds.map((rid) => (
                      <Typography.Text key={rid} code>
                        {rid}
                      </Typography.Text>
                    ))}
                  </Space>
                ) : (
                  <Typography.Paragraph type="secondary">暂无关联请求</Typography.Paragraph>
                )}
              </>
            ) : null}
            {evidenceEntries.length > 0 ? (
              <>
                <Typography.Title level={5}>证据（已脱敏）</Typography.Title>
                <Typography.Paragraph>
                  <pre style={{ background: '#fafafa', padding: 12, fontSize: 12, overflow: 'auto', margin: 0 }}>
                    {formatJson(detail?.evidence)}
                  </pre>
                </Typography.Paragraph>
              </>
            ) : null}
            <Typography.Title level={5}>风险明细</Typography.Title>
            <Typography.Paragraph>
              <pre style={{ background: '#fafafa', padding: 12, fontSize: 12, overflow: 'auto', margin: 0 }}>
                {formatJson(detail?.detail ?? selected.detail)}
              </pre>
            </Typography.Paragraph>
          </>
        ) : null}
      </Drawer>

      {/* 标记解决：处置说明必填；标记误报：误报原因必填（后端字段 reason） */}
      <FindingActionModal<{ resolution: string }>
        title="标记解决"
        target={resolveTarget}
        form={resolveForm}
        fieldName="resolution"
        fieldLabel="处置说明"
        placeholder="说明根因与修复方式，如：已下线该接口并回收密钥"
        loading={resolveMut.isPending}
        onCancel={() => setResolveTarget(null)}
        onFinish={(v) =>
          resolveTarget && resolveMut.mutate({ id: resolveTarget.id, resolution: v.resolution.trim() })
        }
      />
      <FindingActionModal<{ reason: string }>
        title="标记误报"
        target={fpTarget}
        form={fpForm}
        fieldName="reason"
        fieldLabel="误报原因"
        placeholder="说明判定为误报的依据，如：该字段为测试环境造数"
        loading={falsePositiveMut.isPending}
        onCancel={() => setFpTarget(null)}
        onFinish={(v) => fpTarget && falsePositiveMut.mutate({ id: fpTarget.id, reason: v.reason.trim() })}
      />
    </Card>
  )
}
