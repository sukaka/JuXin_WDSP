import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  DatePicker,
  Descriptions,
  Drawer,
  Form,
  Input,
  Modal,
  Popconfirm,
  Select,
  Space,
  Table,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import dayjs, { type Dayjs } from 'dayjs'
import { PlusOutlined } from '@ant-design/icons'
import { ApiError } from '../../api/client'
import { vulnRefsApi, type VulnRefBody } from '../../api/vulnRefs'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import { isSafeHttpUrl } from '../../utils/url'
import { CNNVD_ID_PATTERN, CVE_ID_PATTERN } from '../../utils/vulnIds'
import { ATTACK_TYPE_META, EVENT_ACTION_META, RULE_SOURCE_META } from '../../utils/stage4'
import type { VulnRefItem, VulnRefRule, VulnRefSampleEvent } from '../../types'

/** CNNVD 危害等级（四级分类）；未命中时 StatusTag 原样展示 */
const VULN_SEVERITY_META: Record<string, { color: string; label: string }> = {
  CRITICAL: { color: '#7f1d1d', label: '超危' },
  HIGH: { color: 'red', label: '高危' },
  MEDIUM: { color: 'orange', label: '中危' },
  LOW: { color: 'blue', label: '低危' },
}

const SEVERITY_OPTIONS = Object.entries(VULN_SEVERITY_META).map(([value, meta]) => ({
  value,
  label: meta.label,
}))

/** 发布时间按日期粒度展示（后端可能返回日期或 RFC3339） */
const formatDate = (v?: string) => (v ? v.slice(0, 10) : '-')

interface VulnRefFormValues {
  cnnvd_id: string
  cve_id?: string
  title: string
  severity: string
  published_at?: Dayjs | null
  url?: string
}

const toBody = (v: VulnRefFormValues): VulnRefBody => ({
  cnnvd_id: v.cnnvd_id.trim().toUpperCase(),
  cve_id: v.cve_id?.trim().toUpperCase() || undefined,
  title: v.title.trim(),
  severity: v.severity,
  published_at: v.published_at ? v.published_at.format('YYYY-MM-DD') : undefined,
  url: v.url?.trim() || undefined,
})

/** 漏洞档案（CNNVD 兼容性 P1）：编号 ↔ 规则 ↔ 事件交叉关联的档案维护与交叉查询 */
export default function VulnRefsPage() {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canEdit = hasPermission(permissions, 'waf_rule.vuln_ref.edit')

  const [keyword, setKeyword] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [createOpen, setCreateOpen] = useState(false)
  const [editing, setEditing] = useState<VulnRefItem | null>(null)
  const [form] = Form.useForm<VulnRefFormValues>()
  // URL ?focus=<cnnvd_id> 驱动详情抽屉（事件详情/规则详情跳转入口）
  const [searchParams, setSearchParams] = useSearchParams()
  const focusId = searchParams.get('focus')

  const openDetail = (cnnvdId: string) => {
    const next = new URLSearchParams(searchParams)
    next.set('focus', cnnvdId)
    setSearchParams(next)
  }
  const closeDetail = () => {
    const next = new URLSearchParams(searchParams)
    next.delete('focus')
    setSearchParams(next)
  }

  const listQuery = useQuery({
    queryKey: ['vuln-refs', keyword, page, pageSize],
    queryFn: () => vulnRefsApi.list({ keyword, page, page_size: pageSize }),
  })

  const detailQuery = useQuery({
    queryKey: ['vuln-ref', focusId],
    queryFn: () => vulnRefsApi.get(focusId as string),
    enabled: focusId !== null,
  })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['vuln-refs'] })

  const onError = (e: unknown) => {
    if (e instanceof ApiError && e.status === 409) {
      message.error(e.message || '该 CNNVD 编号已存在档案')
      return
    }
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const createMutation = useMutation({
    mutationFn: (body: VulnRefBody) => vulnRefsApi.create(body),
    onSuccess: (data) => {
      setCreateOpen(false)
      form.resetFields()
      message.success(`漏洞档案「${data.cnnvd_id}」已创建`)
      void invalidate()
    },
    onError,
  })

  const updateMutation = useMutation({
    mutationFn: ({ cnnvdId, body }: { cnnvdId: string; body: VulnRefBody }) =>
      vulnRefsApi.update(cnnvdId, body),
    onSuccess: () => {
      setEditing(null)
      message.success('保存成功')
      void invalidate()
      if (focusId) void queryClient.invalidateQueries({ queryKey: ['vuln-ref', focusId] })
    },
    onError,
  })

  const deleteMutation = useMutation({
    mutationFn: (cnnvdId: string) => vulnRefsApi.remove(cnnvdId),
    onSuccess: () => {
      message.success('漏洞档案已删除')
      if (focusId) closeDetail()
      void invalidate()
    },
    onError,
  })

  const openEdit = (record: VulnRefItem) => {
    setEditing(record)
    form.setFieldsValue({
      cnnvd_id: record.cnnvd_id,
      cve_id: record.cve_id || undefined,
      title: record.title,
      severity: record.severity,
      published_at: record.published_at ? dayjs(record.published_at) : null,
      url: record.url || undefined,
    })
  }

  const columns: ColumnsType<VulnRefItem> = [
    {
      title: 'CNNVD 编号',
      dataIndex: 'cnnvd_id',
      width: 190,
      render: (v: string) => (
        <Button type="link" size="small" style={{ padding: 0, height: 'auto' }} onClick={() => openDetail(v)}>
          {v}
        </Button>
      ),
    },
    {
      title: 'CVE 编号',
      dataIndex: 'cve_id',
      width: 160,
      render: (v: string) => (v ? <Tag color="blue">{v}</Tag> : '-'),
    },
    {
      title: '规范名称',
      dataIndex: 'title',
      ellipsis: true,
    },
    {
      title: '危害等级',
      dataIndex: 'severity',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={VULN_SEVERITY_META} />,
    },
    {
      title: '发布时间',
      dataIndex: 'published_at',
      width: 120,
      render: (v: string) => formatDate(v),
    },
    {
      title: '关联规则数',
      dataIndex: 'rule_count',
      width: 110,
    },
    {
      title: '近30天事件数',
      dataIndex: 'event_count_30d',
      width: 120,
    },
    {
      title: '操作',
      key: 'actions',
      width: 170,
      fixed: 'right',
      render: (_, record) => (
        <Space>
          <Button type="link" size="small" onClick={() => openDetail(record.cnnvd_id)}>
            详情
          </Button>
          {canEdit && (
            <>
              <Button type="link" size="small" onClick={() => openEdit(record)}>
                编辑
              </Button>
              <Popconfirm
                title="删除确认"
                description={`确定删除漏洞档案「${record.cnnvd_id}」吗？删除后不可恢复。`}
                okButtonProps={{ danger: true }}
                onConfirm={() => deleteMutation.mutate(record.cnnvd_id)}
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

  const ruleColumns: ColumnsType<VulnRefRule> = [
    {
      title: '规则ID',
      dataIndex: 'rule_id',
      width: 110,
      render: (v: number) => <Typography.Text code>{v}</Typography.Text>,
    },
    { title: '名称', dataIndex: 'rule_name', ellipsis: true },
    {
      title: '来源',
      dataIndex: 'rule_source',
      width: 130,
      render: (v: string) => <StatusTag value={v} map={RULE_SOURCE_META} />,
    },
    {
      title: '启用',
      dataIndex: 'enabled',
      width: 90,
      render: (v: boolean) => (v ? <Tag color="green">启用</Tag> : <Tag>停用</Tag>),
    },
  ]

  const eventColumns: ColumnsType<VulnRefSampleEvent> = [
    {
      title: '时间',
      dataIndex: 'occurred_at',
      width: 180,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '攻击类型',
      dataIndex: 'attack_type',
      width: 130,
      render: (v: string) => <StatusTag value={v} map={ATTACK_TYPE_META} />,
    },
    { title: '客户端 IP', dataIndex: 'client_ip', width: 140 },
    { title: '请求路径', dataIndex: 'request_path', ellipsis: true },
    {
      title: '动作',
      dataIndex: 'action',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={EVENT_ACTION_META} />,
    },
  ]

  const detail = detailQuery.data

  const formModal = (
    <Form
      form={form}
      layout="vertical"
      initialValues={{ severity: 'HIGH' }}
      onFinish={(values) => {
        const body = toBody(values)
        if (editing) {
          updateMutation.mutate({ cnnvdId: editing.cnnvd_id, body })
        } else {
          createMutation.mutate(body)
        }
      }}
    >
      <Form.Item
        name="cnnvd_id"
        label="CNNVD 编号"
        rules={[
          { required: true, message: '请输入 CNNVD 编号' },
          { pattern: CNNVD_ID_PATTERN, message: '格式应为 CNNVD-YYYYMM-NNN（如 CNNVD-202401-2345）' },
        ]}
        extra={editing ? '档案编号创建后不可修改' : '格式 CNNVD-YYYYMM-NNN，创建后不可修改'}
      >
        <Input placeholder="如：CNNVD-202401-2345" disabled={editing !== null} />
      </Form.Item>
      <Form.Item
        name="cve_id"
        label="CVE 编号"
        rules={[{ pattern: CVE_ID_PATTERN, message: '格式应为 CVE-YYYY-NNNN（如 CVE-2024-0001）' }]}
      >
        <Input placeholder="如：CVE-2024-0001（可选）" />
      </Form.Item>
      <Form.Item
        name="title"
        label="规范名称"
        rules={[
          { required: true, message: '请输入规范名称' },
          { max: 256, message: '不超过 256 个字符' },
        ]}
      >
        <Input placeholder="如：Apache Struts2 远程代码执行漏洞" />
      </Form.Item>
      <Form.Item name="severity" label="危害等级" rules={[{ required: true, message: '请选择危害等级' }]}>
        <Select options={SEVERITY_OPTIONS} />
      </Form.Item>
      <Form.Item name="published_at" label="发布时间">
        <DatePicker style={{ width: '100%' }} />
      </Form.Item>
      <Form.Item name="url" label="官方条目链接" rules={[{ type: 'url', message: '请输入合法的 URL' }]}>
        <Input placeholder="https://www.cnnvd.org.cn/...（可选）" />
      </Form.Item>
    </Form>
  )

  return (
    <Card
      title="漏洞档案"
      extra={
        canEdit && (
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => {
              form.resetFields()
              setCreateOpen(true)
            }}
          >
            新建档案
          </Button>
        )
      }
    >
      <Space style={{ marginBottom: 16 }} wrap>
        <Input.Search
          placeholder="搜索编号或规范名称"
          allowClear
          style={{ width: 280 }}
          onSearch={(v) => {
            setKeyword(v.trim() || undefined)
            setPage(1)
          }}
        />
      </Space>

      {listQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="加载漏洞档案失败"
          description={listQuery.error instanceof ApiError ? listQuery.error.message : undefined}
        />
      ) : (
        <SmartTable<VulnRefItem>
          storageKey="vuln-refs"
          rowKey="id"
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          onRow={(record) => ({
            onDoubleClick: () => openDetail(record.cnnvd_id),
            style: { cursor: 'pointer' },
          })}
          scroll={{ x: 1100 }}
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

      <Modal
        title={editing ? `编辑漏洞档案：${editing.cnnvd_id}` : '新建漏洞档案'}
        open={createOpen || editing !== null}
        onCancel={() => {
          setCreateOpen(false)
          setEditing(null)
        }}
        onOk={() => form.submit()}
        confirmLoading={createMutation.isPending || updateMutation.isPending}
        destroyOnHidden
      >
        {formModal}
      </Modal>

      <Drawer
        title={`漏洞档案详情${detail ? `：${detail.ref.cnnvd_id}` : ''}`}
        open={focusId !== null}
        onClose={closeDetail}
        width={760}
      >
        {detailQuery.isLoading ? (
          <Typography.Text type="secondary">加载中...</Typography.Text>
        ) : detailQuery.isError ? (
          <Alert
            type="error"
            showIcon
            message="加载漏洞档案详情失败"
            description={
              detailQuery.error instanceof ApiError ? detailQuery.error.message : undefined
            }
          />
        ) : detail ? (
          <>
            <Descriptions column={2} size="small" bordered style={{ marginBottom: 16 }}>
              <Descriptions.Item label="CNNVD 编号">{detail.ref.cnnvd_id}</Descriptions.Item>
              <Descriptions.Item label="CVE 编号">
                {detail.ref.cve_id ? <Tag color="blue">{detail.ref.cve_id}</Tag> : '-'}
              </Descriptions.Item>
              <Descriptions.Item label="规范名称" span={2}>
                {detail.ref.title}
              </Descriptions.Item>
              <Descriptions.Item label="危害等级">
                <StatusTag value={detail.ref.severity} map={VULN_SEVERITY_META} />
              </Descriptions.Item>
              <Descriptions.Item label="发布时间">
                {formatDate(detail.ref.published_at)}
              </Descriptions.Item>
              <Descriptions.Item label="官方条目" span={2}>
                {detail.ref.url && isSafeHttpUrl(detail.ref.url) ? (
                  <Typography.Link href={detail.ref.url.trim()} target="_blank" rel="noopener noreferrer">
                    CNNVD 官方条目
                  </Typography.Link>
                ) : detail.ref.url ? (
                  <Typography.Text type="secondary">{detail.ref.url}</Typography.Text>
                ) : (
                  '-'
                )}
              </Descriptions.Item>
              <Descriptions.Item label="创建时间">
                {formatDateTime(detail.ref.created_at)}
              </Descriptions.Item>
              <Descriptions.Item label="更新时间">
                {formatDateTime(detail.ref.updated_at)}
              </Descriptions.Item>
            </Descriptions>

            <Typography.Title level={5}>关联规则（{detail.rules.length}）</Typography.Title>
            <Table<VulnRefRule>
              rowKey={(r) => `${r.rule_source}-${r.rule_id}`}
              size="small"
              columns={ruleColumns}
              dataSource={detail.rules}
              pagination={false}
              locale={{ emptyText: '暂无关联规则' }}
              style={{ marginBottom: 16 }}
            />

            <Typography.Title level={5}>
              近 30 天命中事件（{detail.event_count_30d}）
            </Typography.Title>
            <Table<VulnRefSampleEvent>
              rowKey="id"
              size="small"
              columns={eventColumns}
              dataSource={detail.sample_events}
              pagination={false}
              locale={{ emptyText: '近 30 天暂无命中事件' }}
            />
          </>
        ) : null}
      </Drawer>
    </Card>
  )
}
