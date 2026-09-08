import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  AutoComplete,
  Button,
  Card,
  Descriptions,
  Drawer,
  Form,
  Input,
  InputNumber,
  Modal,
  Popconfirm,
  Progress,
  Select,
  Space,
  Spin,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { ApiError } from '../../api/client'
import { apmApi, type ApmSloBody } from '../../api/apm'
import EChart from '../../components/EChart'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { hasPermission } from '../../utils/permission'
import { formatDateTime } from '../../utils/format'
import { apmSloTrendOption } from '../../utils/apmCharts'
import {
  APM_SLO_METRIC_TYPE_META,
  APM_SLO_STATUS_META,
  formatPercent,
  formatSloValue,
} from '../../utils/apm'
import type { ApmSloItem, ApmSloMetricType } from '../../types'

const METRIC_TYPE_OPTIONS: { value: ApmSloMetricType; label: string }[] = [
  { value: 'availability', label: '可用性（成功请求占比）' },
  { value: 'latency_p95', label: 'P95 时延（毫秒阈值）' },
]

const WINDOW_OPTIONS = [
  { value: '7d', label: '7 天（7d）' },
  { value: '30d', label: '30 天（30d）' },
]

/** SLO 管理（读权限 apm.overview.read，写权限 apm.settings.manage 控制按钮显隐）：
 *  列表（目标/当前值/达标率/剩余错误预算/状态）+ 新建/编辑 Modal + 删除 Popconfirm + 详情 Drawer（达标率趋势） */
export default function ApmSlosPage() {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'apm.settings.manage')

  const [editTarget, setEditTarget] = useState<ApmSloItem | null>(null)
  const [modalOpen, setModalOpen] = useState(false)
  const [detailId, setDetailId] = useState<string | null>(null)
  const [form] = Form.useForm<ApmSloBody>()
  const metricType = Form.useWatch('metric_type', form)

  const listQuery = useQuery({
    queryKey: ['apm', 'slos'],
    queryFn: () => apmApi.slos(),
  })

  // 服务建议值：当前时间窗内的服务清单（上限 100），允许自由输入
  const servicesQuery = useQuery({
    queryKey: ['apm', 'services', 'slo-form-options'],
    queryFn: () =>
      apmApi.services({
        start_time: new Date(Date.now() - 24 * 3600 * 1000).toISOString(),
        end_time: new Date().toISOString(),
        page: 1,
        page_size: 100,
      }),
    retry: false,
  })

  const detailQuery = useQuery({
    queryKey: ['apm', 'slos', 'detail', detailId],
    queryFn: () => apmApi.slo(detailId as string),
    enabled: detailId !== null,
  })

  const onError = (e: unknown) => {
    // 409/参数校验等错误统一按 ApiError 透传后端消息（不静默吞错）
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const saveMutation = useMutation({
    mutationFn: (values: ApmSloBody) =>
      editTarget ? apmApi.updateSlo(editTarget.id, values) : apmApi.createSlo(values),
    onSuccess: () => {
      message.success(editTarget ? 'SLO 已更新' : 'SLO 已创建')
      setModalOpen(false)
      setEditTarget(null)
      form.resetFields()
      void queryClient.invalidateQueries({ queryKey: ['apm', 'slos'] })
    },
    onError,
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apmApi.deleteSlo(id),
    onSuccess: () => {
      message.success('SLO 已删除')
      void queryClient.invalidateQueries({ queryKey: ['apm', 'slos'] })
    },
    onError,
  })

  const openCreate = () => {
    setEditTarget(null)
    form.resetFields()
    setModalOpen(true)
  }

  const openEdit = (record: ApmSloItem) => {
    setEditTarget(record)
    form.setFieldsValue({
      name: record.name,
      service: record.service,
      metric_type: record.metric_type,
      target: record.target,
      window: record.window,
    })
    setModalOpen(true)
  }

  const columns: ColumnsType<ApmSloItem> = [
    { title: '名称', dataIndex: 'name', width: 160, ellipsis: true },
    {
      title: '服务',
      dataIndex: 'service',
      width: 140,
      ellipsis: true,
      render: (v: string) => (
        <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{v || '-'}</Typography.Text>
      ),
    },
    {
      title: '指标类型',
      dataIndex: 'metric_type',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={APM_SLO_METRIC_TYPE_META} />,
    },
    {
      title: '目标',
      dataIndex: 'target',
      width: 100,
      render: (v: number, r) => formatSloValue(r.metric_type, v),
    },
    {
      title: '当前值',
      dataIndex: 'current_value',
      width: 100,
      render: (v: number, r) => formatSloValue(r.metric_type, v),
    },
    {
      title: '达标率',
      dataIndex: 'compliance_ratio',
      width: 150,
      render: (v: number, r) => (
        <Progress
          percent={+(v * 100).toFixed(2)}
          size="small"
          status={r.status === 'BREACHED' ? 'exception' : undefined}
          strokeColor={r.status === 'AT_RISK' ? '#fa8c16' : undefined}
        />
      ),
    },
    {
      title: '剩余错误预算',
      dataIndex: 'error_budget_remaining',
      width: 110,
      render: (v: number) => (
        <Typography.Text type={v <= 0 ? 'danger' : undefined}>{formatPercent(v)}</Typography.Text>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={APM_SLO_STATUS_META} />,
    },
    {
      title: '更新时间',
      dataIndex: 'updated_at',
      width: 165,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: canManage ? 170 : 80,
      fixed: 'right',
      render: (_, record) => (
        <Space size={0}>
          <Button type="link" size="small" onClick={() => setDetailId(record.id)}>
            详情
          </Button>
          {canManage && (
            <>
              <Button type="link" size="small" onClick={() => openEdit(record)}>
                编辑
              </Button>
              <Popconfirm
                title="删除 SLO"
                description={`确定删除「${record.name}」吗？删除后不再评估该目标。`}
                okText="确认删除"
                okButtonProps={{ danger: true }}
                cancelText="取消"
                onConfirm={() => deleteMutation.mutate(record.id)}
              >
                <Button type="link" size="small" danger>
                  删除
                </Button>
              </Popconfirm>
            </>
          )}
        </Space>
      ),
    },
  ]

  return (
    <Card
      title="SLO 管理"
      extra={
        canManage && (
          <Button type="primary" onClick={openCreate}>
            新建 SLO
          </Button>
        )
      }
    >
      {listQuery.isError ? (
        <QueryErrorAlert error={listQuery.error} message="加载 SLO 列表失败" />
      ) : (
        <SmartTable<ApmSloItem>
          storageKey="apm-slos"
          rowKey="id"
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.list}
          scroll={{ x: 1330 }}
          locale={{ emptyText: '暂无 SLO，点击右上角「新建 SLO」创建' }}
          onRow={(record) => ({
            onDoubleClick: () => setDetailId(record.id),
            style: { cursor: 'pointer' },
          })}
          pagination={false}
        />
      )}

      <Modal
        title={editTarget ? '编辑 SLO' : '新建 SLO'}
        open={modalOpen}
        onCancel={() => {
          setModalOpen(false)
          setEditTarget(null)
          form.resetFields()
        }}
        onOk={() => form.submit()}
        okText={editTarget ? '保存' : '创建'}
        confirmLoading={saveMutation.isPending}
        destroyOnHidden
      >
        <Form<ApmSloBody>
          form={form}
          layout="vertical"
          initialValues={{ metric_type: 'availability', window: '30d', target: 0.999 }}
          onFinish={(values) => saveMutation.mutate(values)}
        >
          <Form.Item name="name" label="名称" rules={[{ required: true, message: '请填写名称' }]}>
            <Input placeholder="如：商城站点可用性 SLO" maxLength={64} />
          </Form.Item>
          <Form.Item name="service" label="服务" rules={[{ required: true, message: '请填写服务名' }]}>
            <AutoComplete
              placeholder="服务名（可从现有服务中选择）"
              options={(servicesQuery.data?.items ?? []).map((s) => ({
                value: s.app,
                label: `${s.name || s.app}（${s.app}）`,
              }))}
            />
          </Form.Item>
          <Form.Item
            name="metric_type"
            label="指标类型"
            rules={[{ required: true, message: '请选择指标类型' }]}
          >
            <Select options={METRIC_TYPE_OPTIONS} />
          </Form.Item>
          <Form.Item
            name="target"
            label={metricType === 'latency_p95' ? '目标（P95 毫秒阈值）' : '目标（0-1 比例，如 0.999）'}
            rules={[{ required: true, message: '请填写目标值' }]}
          >
            <InputNumber
              style={{ width: '100%' }}
              min={0}
              max={metricType === 'latency_p95' ? undefined : 1}
              step={metricType === 'latency_p95' ? 10 : 0.001}
              placeholder={metricType === 'latency_p95' ? '如 500' : '如 0.999'}
            />
          </Form.Item>
          <Form.Item name="window" label="评估窗口" rules={[{ required: true, message: '请选择评估窗口' }]}>
            <Select options={WINDOW_OPTIONS} />
          </Form.Item>
        </Form>
      </Modal>

      <Drawer
        title="SLO 详情"
        open={detailId !== null}
        onClose={() => setDetailId(null)}
        width={640}
      >
        {detailQuery.isLoading ? (
          <div style={{ textAlign: 'center', padding: 48 }}>
            <Spin />
          </div>
        ) : detailQuery.isError ? (
          <QueryErrorAlert error={detailQuery.error} message="加载 SLO 详情失败" />
        ) : detailQuery.data ? (
          <Space direction="vertical" size={16} style={{ display: 'flex' }}>
            <Descriptions column={2} size="small" bordered>
              <Descriptions.Item label="名称">{detailQuery.data.name}</Descriptions.Item>
              <Descriptions.Item label="服务">{detailQuery.data.service}</Descriptions.Item>
              <Descriptions.Item label="指标类型">
                <StatusTag value={detailQuery.data.metric_type} map={APM_SLO_METRIC_TYPE_META} />
              </Descriptions.Item>
              <Descriptions.Item label="评估窗口">{detailQuery.data.window}</Descriptions.Item>
              <Descriptions.Item label="目标">
                {formatSloValue(detailQuery.data.metric_type, detailQuery.data.target)}
              </Descriptions.Item>
              <Descriptions.Item label="当前值">
                {formatSloValue(detailQuery.data.metric_type, detailQuery.data.current_value)}
              </Descriptions.Item>
              <Descriptions.Item label="达标率">
                {formatPercent(detailQuery.data.compliance_ratio)}
              </Descriptions.Item>
              <Descriptions.Item label="剩余错误预算">
                {formatPercent(detailQuery.data.error_budget_remaining)}
              </Descriptions.Item>
              <Descriptions.Item label="状态">
                <StatusTag value={detailQuery.data.status} map={APM_SLO_STATUS_META} />
              </Descriptions.Item>
              <Descriptions.Item label="更新时间">
                {formatDateTime(detailQuery.data.updated_at)}
              </Descriptions.Item>
            </Descriptions>
            <Card size="small" title="达标率趋势">
              {(detailQuery.data.trend ?? []).length > 0 ? (
                <EChart option={apmSloTrendOption(detailQuery.data.trend)} height={260} ariaLabel="SLO 达标率趋势" />
              ) : (
                <Typography.Text type="secondary">暂无趋势数据</Typography.Text>
              )}
            </Card>
          </Space>
        ) : null}
      </Drawer>
    </Card>
  )
}
