import { useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Dropdown,
  Form,
  Input,
  Modal,
  Select,
  Space,
  Tag,
} from 'antd'
import type { MenuProps } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { DownOutlined, PlusOutlined } from '@ant-design/icons'
import { ApiError } from '../../api/client'
import { applicationsApi } from '../../api/applications'
import type { CreateApplicationBody } from '../../api/applications'
import ProtectionModeTag from '../../components/ProtectionModeTag'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import useBatchDelete from '../../hooks/useBatchDelete'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import {
  APP_STATUS_META,
  DEPLOYMENT_MODE_META,
  DEPLOYMENT_STATUS_META,
} from '../../utils/stage3'
import type { ApplicationItem, ProtectionMode } from '../../types'

interface Filters {
  keyword?: string
  status?: string
  protection_mode?: string
}

const CODE_PATTERN = /^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$/

/** 应用编码与后端一致的校验：小写字母数字开头结尾，中间可含短横线，禁止连续短横线 */
function validateCode(value: string): string | null {
  if (!CODE_PATTERN.test(value)) {
    return '3-64 位小写字母、数字或短横线，须以字母或数字开头结尾'
  }
  if (value.includes('--')) return '不允许包含连续的短横线'
  return null
}

/** 非默认部署模式说明：选中 ROUTED/MIRROR/TRANSPARENT 时展示在「部署模式」表单项下方 */
const DEPLOYMENT_MODE_HINTS: Record<string, string> = {
  ROUTED:
    '路由牵引：流量经三层路由送达本网关节点后转发源站；该模式下按直连对端识别真实客户端 IP，需在宿主机开启 ip_forward 并配置路由（见部署文档）',
  MIRROR:
    '镜像旁路：流量副本经镜像口到达节点，只检测不阻断。需在节点部署 mirrorcap 组件，并在『系统运维 → 网口管理』把镜像口角色设为「镜像」。',
  TRANSPARENT:
    '透明串接：二层桥接串接 + 流量牵引到本节点检测，可正常阻断。需先完成桥接与牵引安装（见部署文档），客户端与源站均无需改配置。' +
    'HTTPS 多虚拟主机说明：网关按 TLS SNI 域名自动分流，防护清单即本应用的域名，无需额外配置——仅本应用域名在网关上终结检测（需为本应用上传证书）；' +
    '若源站同一 IP 上还运行未纳入管理的其它站点，其加密流量端到端透传、不检测，也无需在网关部署它们的证书。',
}

export default function ApplicationsPage() {
  const { message, modal } = AntdApp.useApp()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)

  // 筛选/分页上下文挂在 URL 查询串上：进入详情（如 Bot 策略编辑）后返回列表
  // 保持筛选与分页不丢失（BOT-023），且可分享/刷新不丢状态
  const [searchParams, setSearchParams] = useSearchParams()
  const parsePage = (raw: string | null, def: number) => {
    const n = Number(raw)
    return Number.isInteger(n) && n >= 1 ? n : def
  }
  const filters: Filters = {
    keyword: searchParams.get('keyword') || undefined,
    status: searchParams.get('status') || undefined,
    protection_mode: searchParams.get('protection_mode') || undefined,
  }
  const page = parsePage(searchParams.get('page'), 1)
  const pageSize = parsePage(searchParams.get('page_size'), 20)
  const updateListQuery = (patch: Record<string, string | undefined>) => {
    const next = new URLSearchParams(searchParams)
    for (const [k, v] of Object.entries(patch)) {
      if (v) next.set(k, v)
      else next.delete(k)
    }
    setSearchParams(next, { replace: true })
  }
  const [createOpen, setCreateOpen] = useState(false)
  const [editing, setEditing] = useState<ApplicationItem | null>(null)
  const [createForm] = Form.useForm<CreateApplicationBody>()
  const [editForm] = Form.useForm<Omit<CreateApplicationBody, 'code'>>()
  const createDeploymentMode = Form.useWatch('deployment_mode', createForm)
  const editDeploymentMode = Form.useWatch('deployment_mode', editForm)

  const listQuery = useQuery({
    queryKey: ['applications', filters, page, pageSize],
    queryFn: () =>
      applicationsApi.list({ ...filters, page, page_size: pageSize }),
  })

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ['applications'] })

  const { rowSelection, batchDeleteButton } = useBatchDelete<ApplicationItem>({
    remove: applicationsApi.remove,
    invalidateKeys: [['applications']],
    entityName: '应用',
    canDelete: hasPermission(permissions, 'applications.delete'),
  })

  const onError = (e: unknown) => {
    if (e instanceof ApiError && e.code === 'RESOURCE_CONFLICT') {
      message.error(e.message || '数据已被他人修改或存在冲突，请刷新后重试')
      void invalidate()
      return
    }
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const createMutation = useMutation({
    mutationFn: (body: CreateApplicationBody) => applicationsApi.create(body),
    onSuccess: (data) => {
      setCreateOpen(false)
      createForm.resetFields()
      message.success(`应用「${data.name}」创建成功`)
      void invalidate()
    },
    onError,
  })

  const updateMutation = useMutation({
    mutationFn: ({
      id,
      body,
    }: {
      id: string
      body: Omit<CreateApplicationBody, 'code'> & { version: number }
    }) => applicationsApi.update(id, body),
    onSuccess: () => {
      setEditing(null)
      message.success('保存成功')
      void invalidate()
    },
    onError,
  })

  const actionMutation = useMutation({
    mutationFn: ({
      id,
      action,
    }: {
      id: string
      action: 'enable' | 'disable' | 'delete' | 'copy'
    }) => {
      const map: Record<typeof action, (id: string) => Promise<unknown>> = {
        enable: applicationsApi.enable,
        disable: applicationsApi.disable,
        delete: applicationsApi.remove,
        copy: applicationsApi.copy,
      }
      return map[action](id)
    },
    onSuccess: (_data, vars) => {
      message.success(
        vars.action === 'copy' ? '应用已复制（含域名与源站）' : '操作成功',
      )
      void invalidate()
    },
    onError,
  })

  const runAction = (
    action: 'enable' | 'disable' | 'delete' | 'copy',
    record: ApplicationItem,
  ) => {
    const exec = () => actionMutation.mutate({ id: record.id, action })
    const confirms: Partial<
      Record<
        typeof action,
        { title: string; content: string; danger?: boolean }
      >
    > = {
      disable: {
        title: '停用确认',
        content: `确定停用应用「${record.name}」吗？停用后该应用的防护与转发将失效。`,
        danger: true,
      },
      delete: {
        title: '删除确认',
        content: `确定删除应用「${record.name}」吗？删除后不可恢复。`,
        danger: true,
      },
      copy: {
        title: '复制确认',
        content: `确定复制应用「${record.name}」吗？将生成包含域名与源站的新应用（草稿状态）。`,
      },
    }
    const c = confirms[action]
    if (c) {
      modal.confirm({
        title: c.title,
        content: c.content,
        okButtonProps: c.danger ? { danger: true } : undefined,
        onOk: exec,
      })
    } else {
      exec()
    }
  }

  const actionMenuItems = (
    record: ApplicationItem,
  ): NonNullable<MenuProps['items']> => {
    const items: NonNullable<MenuProps['items']> = []
    if (hasPermission(permissions, 'applications.create')) {
      items.push({ key: 'copy', label: '复制' })
    }
    if (hasPermission(permissions, 'applications.disable')) {
      if (record.status === 'ACTIVE')
        items.push({ key: 'disable', label: '停用', danger: true })
      if (record.status === 'DRAFT' || record.status === 'DISABLED') {
        items.push({ key: 'enable', label: '启用' })
      }
    }
    if (hasPermission(permissions, 'applications.delete')) {
      items.push(
        { type: 'divider' },
        { key: 'delete', label: '删除', danger: true },
      )
    }
    return items
  }

  const columns: ColumnsType<ApplicationItem> = [
    { title: '应用编码', dataIndex: 'code', width: 140 },
    {
      title: '名称',
      dataIndex: 'name',
      width: 180,
      render: (v: string, record) => (
        <Link to={`/applications/${record.id}`}>{v}</Link>
      ),
    },
    {
      title: '防护模式',
      dataIndex: 'protection_mode',
      width: 130,
      render: (v: string) => <ProtectionModeTag mode={v} />,
    },
    {
      title: '部署模式',
      dataIndex: 'deployment_mode',
      width: 110,
      render: (v: string | undefined) => (
        <StatusTag value={v || 'REVERSE_PROXY'} map={DEPLOYMENT_MODE_META} />
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={APP_STATUS_META} />,
    },
    {
      title: '域名数',
      dataIndex: 'domain_count',
      width: 90,
    },
    {
      title: '源站数',
      dataIndex: 'upstream_count',
      width: 90,
    },
    {
      title: '健康状态',
      dataIndex: 'health_status',
      width: 100,
      render: (v: string) =>
        v === 'HEALTHY' ? (
          <Tag color="green">健康</Tag>
        ) : v === 'UNHEALTHY' ? (
          <Tag color="red">异常</Tag>
        ) : (
          <Tag>未知</Tag>
        ),
    },
    {
      title: '部署状态',
      dataIndex: 'deployment_status',
      width: 110,
      render: (v: string) => (
        <StatusTag value={v} map={DEPLOYMENT_STATUS_META} />
      ),
    },
    {
      title: '最后发布',
      key: 'last_publish',
      width: 180,
      render: (_, record) => (
        <span>
          {formatDateTime(record.last_publish_at)}
          {record.last_publish_result === 'SUCCESS' && (
            <Tag color="green" style={{ marginLeft: 4 }}>
              成功
            </Tag>
          )}
          {record.last_publish_result === 'FAILED' && (
            <Tag color="red" style={{ marginLeft: 4 }}>
              失败
            </Tag>
          )}
        </span>
      ),
    },
    {
      title: '操作',
      key: 'actions',
      width: 200,
      fixed: 'right',
      render: (_, record) => {
        const menuItems = actionMenuItems(record)
        return (
          <Space>
            <Button
              type="link"
              size="small"
              onClick={() => navigate(`/applications/${record.id}`)}
            >
              详情
            </Button>
            {hasPermission(permissions, 'applications.update') && (
              <Button
                type="link"
                size="small"
                onClick={() => {
                  setEditing(record)
                  editForm.setFieldsValue({
                    name: record.name,
                    description: record.description,
                    business_owner: record.business_owner,
                    technical_owner: record.technical_owner,
                    protection_mode: record.protection_mode,
                    deployment_mode: record.deployment_mode ?? 'REVERSE_PROXY',
                  })
                }}
              >
                编辑
              </Button>
            )}
            {menuItems.length > 0 && (
              <Dropdown
                menu={{
                  items: menuItems,
                  onClick: ({ key }) =>
                    runAction(
                      key as 'enable' | 'disable' | 'delete' | 'copy',
                      record,
                    ),
                }}
              >
                <Button type="link" size="small">
                  更多 <DownOutlined />
                </Button>
              </Dropdown>
            )}
          </Space>
        )
      },
    },
  ]

  const modeOptions = [
    { value: 'OFF', label: '关闭' },
    { value: 'OBSERVE', label: '观察' },
    { value: 'PROTECT', label: '防护' },
    { value: 'BYPASS', label: '透传（排障/应急）' },
  ]

  const deploymentModeOptions = [
    { value: 'REVERSE_PROXY', label: '反向代理' },
    { value: 'ROUTED', label: '路由牵引' },
    { value: 'MIRROR', label: '镜像' },
    { value: 'TRANSPARENT', label: '透明串接' },
  ]

  /** BYPASS 透传模式提交前二次确认（全量流量直通、全部检测失效），确认后才执行提交 */
  const submitWithBypassConfirm = (
    mode: string | undefined,
    exec: () => void,
  ) => {
    if (mode !== 'BYPASS') {
      exec()
      return
    }
    modal.confirm({
      title: '开启透传（BYPASS）确认',
      content:
        '开启后该应用全部流量直接透传至源站，WAF 检测、访问控制、CC 防护与 API 动态防护全部失效，请仅用于排障/应急。确定开启吗？',
      okText: '确认开启',
      okButtonProps: { danger: true },
      onOk: exec,
    })
  }

  return (
    <Card
      title="网站应用"
      extra={
        hasPermission(permissions, 'applications.create') && (
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => setCreateOpen(true)}
          >
            新建应用
          </Button>
        )
      }
    >
      <Space style={{ marginBottom: 16 }} wrap>
        <Input.Search
          placeholder="搜索编码或名称"
          allowClear
          style={{ width: 240 }}
          key={filters.keyword ?? ''}
          defaultValue={filters.keyword}
          onSearch={(v) => {
            updateListQuery({ keyword: v || undefined, page: undefined })
          }}
        />
        <Select
          placeholder="状态"
          allowClear
          style={{ width: 140 }}
          value={filters.status}
          options={[
            { value: 'DRAFT', label: '草稿' },
            { value: 'ACTIVE', label: '已启用' },
            { value: 'DISABLED', label: '已停用' },
          ]}
          onChange={(v) => {
            updateListQuery({ status: v, page: undefined })
          }}
        />
        <Select
          placeholder="防护模式"
          allowClear
          style={{ width: 150 }}
          value={filters.protection_mode}
          options={modeOptions}
          onChange={(v) => {
            updateListQuery({ protection_mode: v, page: undefined })
          }}
        />
        {batchDeleteButton}
      </Space>

      {listQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="加载应用列表失败"
          description={
            listQuery.error instanceof ApiError
              ? listQuery.error.message
              : undefined
          }
        />
      ) : (
        <SmartTable<ApplicationItem>
          storageKey="applications"
          rowKey="id"
          rowSelection={rowSelection}
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          scroll={{ x: 1300 }}
          onRow={(record) => ({
            onDoubleClick: () => navigate(`/applications/${record.id}`),
            style: { cursor: 'pointer' },
          })}
          pagination={{
            current: page,
            pageSize,
            total: listQuery.data?.total ?? 0,
            showSizeChanger: true,
            showTotal: (t) => `共 ${t} 条`,
            onChange: (p, ps) => {
              updateListQuery({ page: String(p), page_size: String(ps) })
            },
          }}
        />
      )}

      <Modal
        title="新建应用"
        open={createOpen}
        onCancel={() => setCreateOpen(false)}
        onOk={() => createForm.submit()}
        confirmLoading={createMutation.isPending}
        destroyOnHidden
      >
        <Form
          form={createForm}
          layout="vertical"
          initialValues={{
            protection_mode: 'OBSERVE',
            deployment_mode: 'REVERSE_PROXY',
          }}
          onFinish={(values) =>
            submitWithBypassConfirm(values.protection_mode, () =>
              createMutation.mutate(values),
            )
          }
        >
          <Form.Item
            name="code"
            label="应用编码"
            rules={[
              { required: true, message: '请输入应用编码' },
              {
                validator: (_, v: string) => {
                  if (!v) return Promise.resolve()
                  const err = validateCode(v)
                  return err
                    ? Promise.reject(new Error(err))
                    : Promise.resolve()
                },
              },
            ]}
            extra="创建后不可修改，用于标识应用（如 portal-web）"
          >
            <Input placeholder="小写字母、数字、短横线" autoComplete="off" />
          </Form.Item>
          <Form.Item
            name="name"
            label="应用名称"
            rules={[
              { required: true, message: '请输入应用名称' },
              { max: 128, message: '不超过 128 个字符' },
            ]}
          >
            <Input placeholder="应用显示名称" />
          </Form.Item>
          <Form.Item name="description" label="描述">
            <Input.TextArea rows={2} placeholder="应用用途说明（可选）" />
          </Form.Item>
          <Form.Item name="business_owner" label="业务负责人">
            <Input placeholder="可选" />
          </Form.Item>
          <Form.Item name="technical_owner" label="技术负责人">
            <Input placeholder="可选" />
          </Form.Item>
          <Form.Item
            name="protection_mode"
            label="防护模式"
            rules={[{ required: true }]}
          >
            <Select options={modeOptions} />
          </Form.Item>
          <Form.Item
            name="deployment_mode"
            label="部署模式"
            rules={[{ required: true }]}
            extra={DEPLOYMENT_MODE_HINTS[createDeploymentMode ?? '']}
          >
            <Select options={deploymentModeOptions} />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title={`编辑应用：${editing?.name ?? ''}`}
        open={editing !== null}
        onCancel={() => setEditing(null)}
        onOk={() => editForm.submit()}
        confirmLoading={updateMutation.isPending}
        destroyOnHidden
      >
        <Form
          form={editForm}
          layout="vertical"
          onFinish={(values) => {
            if (!editing) return
            submitWithBypassConfirm(values.protection_mode, () =>
              updateMutation.mutate({
                id: editing.id,
                body: {
                  name: values.name,
                  description: values.description ?? '',
                  business_owner: values.business_owner ?? '',
                  technical_owner: values.technical_owner ?? '',
                  protection_mode: values.protection_mode as ProtectionMode,
                  deployment_mode: values.deployment_mode,
                  version: editing.version,
                },
              }),
            )
          }}
        >
          <Form.Item
            name="name"
            label="应用名称"
            rules={[
              { required: true, message: '请输入应用名称' },
              { max: 128, message: '不超过 128 个字符' },
            ]}
          >
            <Input placeholder="应用显示名称" />
          </Form.Item>
          <Form.Item name="description" label="描述">
            <Input.TextArea rows={2} placeholder="应用用途说明（可选）" />
          </Form.Item>
          <Form.Item name="business_owner" label="业务负责人">
            <Input placeholder="可选" />
          </Form.Item>
          <Form.Item name="technical_owner" label="技术负责人">
            <Input placeholder="可选" />
          </Form.Item>
          <Form.Item
            name="protection_mode"
            label="防护模式"
            rules={[{ required: true }]}
          >
            <Select options={modeOptions} />
          </Form.Item>
          <Form.Item
            name="deployment_mode"
            label="部署模式"
            rules={[{ required: true }]}
            extra={DEPLOYMENT_MODE_HINTS[editDeploymentMode ?? '']}
          >
            <Select options={deploymentModeOptions} />
          </Form.Item>
        </Form>
      </Modal>
    </Card>
  )
}
