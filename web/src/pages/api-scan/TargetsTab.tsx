import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  DatePicker,
  Form,
  Input,
  InputNumber,
  Modal,
  Select,
  Space,
  Switch,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import type { Dayjs } from 'dayjs'
import {
  API_SCAN_PROBE_SETS,
  apiScanApi,
  type ApiScanTarget,
  type ApiScanTargetStatus,
} from '../../api/apiScan'
import { applicationsApi } from '../../api/applications'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import { SCAN_PROBE_SET_META, SCAN_TARGET_STATUS_META } from './meta'

interface TargetFormValues {
  application_id?: string
  name: string
  base_url: string
  allowed_paths?: string[]
  /** 仅编辑态展示（创建默认 ENABLED） */
  enabled?: boolean
}

interface AuthorizeFormValues {
  allowlist?: string[]
  window?: [Dayjs | null, Dayjs | null] | null
  max_qps: number
  max_concurrency: number
  test_profile?: string[]
  expires_at: Dayjs
}

/**
 * 扫描目标 Tab：目标 CRUD 与启停（api_scan.manage），授权签发（api_scan.execute，双人分离）。
 */
export default function TargetsTab() {
  const { message, modal } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'api_scan.manage')
  const canExecute = hasPermission(permissions, 'api_scan.execute')

  const [appFilter, setAppFilter] = useState<string | undefined>()
  const [statusFilter, setStatusFilter] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [editing, setEditing] = useState<ApiScanTarget | null>(null)
  const [createOpen, setCreateOpen] = useState(false)
  const [authorizing, setAuthorizing] = useState<ApiScanTarget | null>(null)
  const [detailRecord, setDetailRecord] = useState<ApiScanTarget | null>(null)
  const [form] = Form.useForm<TargetFormValues>()
  const [authorizeForm] = Form.useForm<AuthorizeFormValues>()

  const modalOpen = createOpen || editing !== null

  const listQuery = useQuery({
    queryKey: ['api-scan-targets', appFilter, statusFilter, page, pageSize],
    queryFn: () =>
      apiScanApi.listTargets({
        application_id: appFilter,
        status: statusFilter,
        page,
        page_size: pageSize,
      }),
  })

  /** 应用选项（过滤与新建表单共用） */
  const appsQuery = useQuery({
    queryKey: ['applications', 'api-scan-options'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
  })
  const appOptions = (appsQuery.data?.items ?? []).map((a) => ({
    value: a.id,
    label: `${a.name}（${a.code}）`,
  }))
  const appNameById = new Map((appsQuery.data?.items ?? []).map((a) => [a.id, a.name]))

  const invalidate = () => void qc.invalidateQueries({ queryKey: ['api-scan-targets'] })

  const createMut = useMutation({
    mutationFn: (v: TargetFormValues) =>
      apiScanApi.createTarget({
        application_id: v.application_id as string,
        name: v.name.trim(),
        base_url: v.base_url.trim(),
        allowed_paths: (v.allowed_paths ?? []).map((p) => p.trim()),
      }),
    onSuccess: () => {
      message.success('已创建扫描目标')
      setCreateOpen(false)
      invalidate()
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '创建失败'),
  })

  const updateMut = useMutation({
    mutationFn: (vars: { id: string; body: { name: string; base_url: string; allowed_paths: string[]; status: ApiScanTargetStatus } }) =>
      apiScanApi.updateTarget(vars.id, vars.body),
    onSuccess: () => {
      message.success('已保存')
      setEditing(null)
      invalidate()
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '保存失败'),
  })

  const authorizeMut = useMutation({
    mutationFn: (vars: { targetId: string; v: AuthorizeFormValues }) => {
      const { v } = vars
      const [start, end] = v.window ?? [null, null]
      return apiScanApi.authorize(vars.targetId, {
        allowlist: (v.allowlist ?? []).map((s) => s.trim()).filter(Boolean),
        ...(start ? { window_start: start.toISOString() } : {}),
        ...(end ? { window_end: end.toISOString() } : {}),
        max_qps: v.max_qps,
        max_concurrency: v.max_concurrency,
        test_profile: (v.test_profile ?? []).join(','),
        expires_at: v.expires_at.toISOString(),
      })
    },
    onSuccess: () => {
      message.success('授权已签发')
      setAuthorizing(null)
      // 授权列表在授权 Tab / 建任务弹窗中消费，统一失效
      void qc.invalidateQueries({ queryKey: ['api-scan-authorizations'] })
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '签发授权失败'),
  })

  const openCreate = () => {
    form.resetFields()
    setCreateOpen(true)
  }

  const openEdit = (record: ApiScanTarget) => {
    setEditing(record)
    form.resetFields()
    form.setFieldsValue({
      name: record.name,
      base_url: record.base_url,
      allowed_paths: record.allowed_paths ?? [],
      enabled: record.status === 'ENABLED',
    })
  }

  /** 启停（PUT 全量替换：保留名称/地址/路径，仅翻转状态） */
  const toggleStatus = (record: ApiScanTarget) => {
    const next: ApiScanTargetStatus = record.status === 'ENABLED' ? 'DISABLED' : 'ENABLED'
    modal.confirm({
      title: next === 'ENABLED' ? '启用目标' : '停用目标',
      content:
        next === 'ENABLED'
          ? `确定启用扫描目标「${record.name}」吗？启用后可凭有效授权发起扫描。`
          : `确定停用扫描目标「${record.name}」吗？停用后不能再为该目标发起扫描任务。`,
      onOk: () =>
        updateMut.mutate({
          id: record.id,
          body: {
            name: record.name,
            base_url: record.base_url,
            allowed_paths: record.allowed_paths ?? [],
            status: next,
          },
        }),
    })
  }

  const openAuthorize = (record: ApiScanTarget) => {
    authorizeForm.resetFields()
    setAuthorizing(record)
  }

  const columns: ColumnsType<ApiScanTarget> = [
    {
      title: '目标',
      dataIndex: 'name',
      ellipsis: true,
      render: (v: string, record) => (
        <Space size={4} direction="vertical">
          <Typography.Text strong>{v}</Typography.Text>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {record.base_url}
          </Typography.Text>
        </Space>
      ),
    },
    {
      title: '所属应用',
      dataIndex: 'application_id',
      width: 180,
      ellipsis: true,
      render: (v: string) => appNameById.get(v) ?? v,
    },
    {
      title: '允许路径',
      dataIndex: 'allowed_paths',
      width: 110,
      render: (v: string[]) =>
        v && v.length > 0 ? (
          <Tooltip title={v.join('、')}>
            <Typography.Text>{v.length} 条</Typography.Text>
          </Tooltip>
        ) : (
          <Typography.Text type="secondary">未限制</Typography.Text>
        ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={SCAN_TARGET_STATUS_META} />,
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    ...(canManage || canExecute
      ? [
          {
            title: '操作',
            key: 'actions',
            width: 200,
            fixed: 'right' as const,
            render: (_: unknown, record: ApiScanTarget) => (
              <Space size={0} wrap>
                {canManage ? (
                  <>
                    <Button type="link" size="small" onClick={() => openEdit(record)}>
                      编辑
                    </Button>
                    <Button type="link" size="small" onClick={() => toggleStatus(record)}>
                      {record.status === 'ENABLED' ? '停用' : '启用'}
                    </Button>
                  </>
                ) : null}
                {canExecute ? (
                  <Button type="link" size="small" onClick={() => openAuthorize(record)}>
                    签发授权
                  </Button>
                ) : null}
              </Space>
            ),
          },
        ]
      : []),
  ]

  return (
    <>
      <QueryErrorAlert error={listQuery.error} />
      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          placeholder="所属应用"
          allowClear
          showSearch
          optionFilterProp="label"
          style={{ width: 220 }}
          value={appFilter}
          options={appOptions}
          onChange={(v) => {
            setAppFilter(v)
            setPage(1)
          }}
        />
        <Select
          placeholder="状态"
          allowClear
          style={{ width: 120 }}
          value={statusFilter}
          options={Object.entries(SCAN_TARGET_STATUS_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => {
            setStatusFilter(v)
            setPage(1)
          }}
        />
        {canManage ? (
          <Button type="primary" onClick={openCreate}>
            新建目标
          </Button>
        ) : null}
      </Space>
      <SmartTable<ApiScanTarget>
        storageKey="api-scan-targets"
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        scroll={{ x: 1100 }}
        onRow={(record) => ({
          onDoubleClick: () => setDetailRecord(record),
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

      <Modal
        title={editing ? '编辑扫描目标' : '新建扫描目标'}
        open={modalOpen}
        onCancel={() => {
          setCreateOpen(false)
          setEditing(null)
        }}
        onOk={() => form.submit()}
        confirmLoading={createMut.isPending || updateMut.isPending}
        destroyOnHidden
      >
        <Form<TargetFormValues>
          form={form}
          layout="vertical"
          onFinish={(v) => {
            if (editing) {
              updateMut.mutate({
                id: editing.id,
                body: {
                  name: v.name.trim(),
                  base_url: v.base_url.trim(),
                  allowed_paths: (v.allowed_paths ?? []).map((p) => p.trim()),
                  status: v.enabled === false ? 'DISABLED' : 'ENABLED',
                },
              })
            } else {
              createMut.mutate(v)
            }
          }}
        >
          {!editing ? (
            <Form.Item
              name="application_id"
              label="所属应用"
              rules={[{ required: true, message: '请选择所属应用' }]}
            >
              <Select
                placeholder="选择应用"
                showSearch
                optionFilterProp="label"
                options={appOptions}
                loading={appsQuery.isLoading}
              />
            </Form.Item>
          ) : null}
          <Form.Item
            name="name"
            label="目标名称"
            rules={[
              { required: true, message: '请填写目标名称' },
              { max: 128, message: '目标名称不超过 128 字符' },
            ]}
          >
            <Input placeholder="如：生产环境订单 API" allowClear autoComplete="off" />
          </Form.Item>
          <Form.Item
            name="base_url"
            label="基准地址"
            rules={[
              { required: true, message: '请填写基准地址' },
              { pattern: /^https?:\/\/[^\s/]+/, message: '基准地址必须为合法 http/https 地址' },
            ]}
          >
            <Input placeholder="如 https://api.example.com" allowClear autoComplete="off" />
          </Form.Item>
          <Form.Item
            name="allowed_paths"
            label="允许探测路径（留空 = 不限制）"
            rules={[
              {
                validator: (_, v?: string[]) => {
                  const bad = (v ?? []).find((p) => !p.trim().startsWith('/') || p.trim().length > 512)
                  return bad
                    ? Promise.reject(new Error('允许路径每项须以 / 开头且不超过 512 字符'))
                    : Promise.resolve()
                },
              },
            ]}
          >
            <Select
              mode="tags"
              open={false}
              placeholder="输入以 / 开头的路径后回车，如 /v1/orders"
              tokenSeparators={[',']}
            />
          </Form.Item>
          {editing ? (
            <Form.Item name="enabled" label="启用状态" valuePropName="checked">
              <Switch checkedChildren="启用" unCheckedChildren="停用" />
            </Form.Item>
          ) : null}
        </Form>
      </Modal>

      <Modal
        title={authorizing ? `签发扫描授权：${authorizing.name}` : '签发扫描授权'}
        open={authorizing !== null}
        onCancel={() => setAuthorizing(null)}
        onOk={() => authorizeForm.submit()}
        confirmLoading={authorizeMut.isPending}
        destroyOnHidden
      >
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 16 }}
          message="双人分离：目标创建人与授权人不得为同一人"
          description="扫描授权是高危操作：目标的创建人不能再为该目标签发授权（后端强制校验，建标人提交将返回 403）。授权仅在时间窗与有效期内生效，扫描引擎严格按白名单与限流参数执行。"
        />
        <Form<AuthorizeFormValues>
          form={authorizeForm}
          layout="vertical"
          initialValues={{ max_qps: 5, max_concurrency: 1 }}
          onFinish={(v) => {
            if (!authorizing) return
            authorizeMut.mutate({ targetId: authorizing.id, v })
          }}
        >
          <Form.Item
            name="allowlist"
            label="允许探测的域名/IP（白名单）"
            rules={[
              {
                validator: (_, v?: string[]) => {
                  if ((v ?? []).length > 64) {
                    return Promise.reject(new Error('白名单不能超过 64 条'))
                  }
                  const bad = (v ?? []).find((s) => s.trim().length === 0 || s.trim().length > 255)
                  return bad
                    ? Promise.reject(new Error('白名单每项须为 1~255 字符的域名/IP'))
                    : Promise.resolve()
                },
              },
            ]}
          >
            <Select
              mode="tags"
              open={false}
              placeholder="输入域名或 IP 后回车；须覆盖目标主机，否则建任务被拒"
              tokenSeparators={[',']}
            />
          </Form.Item>
          <Form.Item name="window" label="扫描时间窗（可选，仅窗内允许执行）">
            <DatePicker.RangePicker showTime style={{ width: '100%' }} />
          </Form.Item>
          <Space size={16} style={{ display: 'flex' }}>
            <Form.Item
              name="max_qps"
              label="最大 QPS"
              rules={[{ required: true, message: '请设置最大 QPS' }]}
            >
              <InputNumber min={1} max={100} precision={0} style={{ width: 160 }} />
            </Form.Item>
            <Form.Item
              name="max_concurrency"
              label="最大并发"
              rules={[{ required: true, message: '请设置最大并发' }]}
            >
              <InputNumber min={1} max={16} precision={0} style={{ width: 160 }} />
            </Form.Item>
          </Space>
          <Form.Item name="test_profile" label="探针集画像（留空 = 默认全集）">
            <Select
              mode="multiple"
              allowClear
              placeholder="选择允许的探针集"
              options={API_SCAN_PROBE_SETS.map((s) => ({
                value: s,
                label: SCAN_PROBE_SET_META[s] ?? s,
              }))}
            />
          </Form.Item>
          <Form.Item
            name="expires_at"
            label="授权截止时间"
            rules={[{ required: true, message: '请选择授权截止时间' }]}
          >
            <DatePicker showTime style={{ width: '100%' }} placeholder="须为未来时间" />
          </Form.Item>
        </Form>
      </Modal>

      <RecordDetailDrawer
        open={detailRecord !== null}
        title="扫描目标详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </>
  )
}
