import { useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Button,
  Card,
  Form,
  Input,
  Modal,
  Select,
  Space,
  Switch,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { DownloadOutlined, ImportOutlined, PlusOutlined } from '@ant-design/icons'
import {
  apiSensitiveTypesApi,
  type ApiSensitiveDataType,
  type ApiSensitiveTypeBody,
} from '../../api/apiData'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import useBatchDelete from '../../hooks/useBatchDelete'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'

/** 五级敏感等级（与 server/internal/apidata level 枚举一致） */
const SENSITIVE_LEVEL_META: Record<string, { color: string; label: string }> = {
  NON_SENSITIVE: { color: 'default', label: '非敏感' },
  GENERAL: { color: 'blue', label: '一般' },
  SENSITIVE: { color: 'orange', label: '敏感' },
  IMPORTANT: { color: 'volcano', label: '重要' },
  CORE: { color: 'magenta', label: '核心' },
}

/** 类型状态 */
const TYPE_STATUS_META: Record<string, { color: string; label: string }> = {
  ENABLED: { color: 'green', label: '启用' },
  DISABLED: { color: 'default', label: '禁用' },
}

/** 可能出现位置（与 server/internal/apidata validLocations 白名单一致） */
const LOCATION_OPTIONS = [
  { value: 'query', label: '查询参数（query）' },
  { value: 'json', label: 'JSON 请求体（json）' },
  { value: 'form', label: '表单（form）' },
  { value: 'xml', label: 'XML（xml）' },
  { value: 'header', label: '请求头（header）' },
  { value: 'cookie', label: 'Cookie（cookie）' },
  { value: 'path', label: '路径（path）' },
  { value: 'response_body', label: '响应体（response_body）' },
  { value: 'file', label: '文件内容（file）' },
]

interface TypeFormValues {
  name: string
  data_type: string
  level: string
  category?: string
  description?: string
  locations?: string[]
  keywords?: string[]
  regex?: string
  validator?: string
  exclude_fields?: string[]
  enabled: boolean
}

/** 读取文件为文本（FileReader 实现，jsdom 兼容） */
function readFileAsText(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(String(reader.result ?? ''))
    reader.onerror = () => reject(reader.error)
    reader.readAsText(file)
  })
}

/** 敏感数据类型（WDSP / 阶段8）：敏感数据类型词根的登记、启停与导入导出 */
export default function ApiSensitiveTypesPage() {
  const { message, modal } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'api_data.manage')

  const [status, setStatus] = useState<string | undefined>()
  const [level, setLevel] = useState<string | undefined>()
  const [keyword, setKeyword] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [editing, setEditing] = useState<ApiSensitiveDataType | null>(null)
  const [createOpen, setCreateOpen] = useState(false)
  const [detailRecord, setDetailRecord] = useState<ApiSensitiveDataType | null>(null)
  const [form] = Form.useForm<TypeFormValues>()
  const importInputRef = useRef<HTMLInputElement>(null)

  const listQuery = useQuery({
    queryKey: ['api-sensitive-types', status, level, keyword, page, pageSize],
    queryFn: () =>
      apiSensitiveTypesApi.list({ status, level, keyword, page, page_size: pageSize }),
  })

  const invalidate = () => void qc.invalidateQueries({ queryKey: ['api-sensitive-types'] })

  const { rowSelection, batchDeleteButton } = useBatchDelete<ApiSensitiveDataType>({
    remove: (id) => apiSensitiveTypesApi.remove(id),
    invalidateKeys: [['api-sensitive-types']],
    entityName: '敏感数据类型',
    canDelete: canManage,
  })

  const createMut = useMutation({
    mutationFn: (body: ApiSensitiveTypeBody) => apiSensitiveTypesApi.create(body),
    onSuccess: () => {
      message.success('已创建')
      setCreateOpen(false)
      invalidate()
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '创建失败'),
  })

  const updateMut = useMutation({
    mutationFn: (vars: { id: string; body: ApiSensitiveTypeBody }) =>
      apiSensitiveTypesApi.update(vars.id, vars.body),
    onSuccess: () => {
      message.success('已保存')
      setEditing(null)
      invalidate()
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '保存失败'),
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => apiSensitiveTypesApi.remove(id),
    onSuccess: (r) => {
      message.success(r.message || '已删除')
      invalidate()
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '删除失败'),
  })

  const importMut = useMutation({
    mutationFn: (types: ApiSensitiveTypeBody[]) => apiSensitiveTypesApi.importTypes(types),
    onSuccess: (r) => {
      message.success(`导入完成：新建 ${r.created} 条，更新 ${r.updated} 条`)
      invalidate()
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '导入失败'),
  })

  /** 导出：拉取全量类型文档后落盘为 JSON 文件（与导入格式对称，可回灌） */
  const [exporting, setExporting] = useState(false)
  const doExport = async () => {
    setExporting(true)
    try {
      const doc = await apiSensitiveTypesApi.exportTypes()
      const blob = new Blob([JSON.stringify(doc, null, 2)], { type: 'application/json;charset=utf-8' })
      // jsdom 等环境无 createObjectURL 时仅完成拉取（测试场景）
      if (typeof URL.createObjectURL === 'function') {
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `api-sensitive-types-${doc.exported_at.slice(0, 10) || 'export'}.json`
        document.body.appendChild(a)
        a.click()
        a.remove()
        URL.revokeObjectURL(url)
      }
      message.success(`已导出 ${doc.types?.length ?? 0} 条类型定义`)
    } catch (e) {
      message.error(e instanceof ApiError ? e.message : '导出失败')
    } finally {
      setExporting(false)
    }
  }

  /** 导入：选择 JSON 文件 → 解析校验 → 二次确认 → 按名称 upsert */
  const onImportFile = async (file: File) => {
    let parsed: unknown
    try {
      parsed = JSON.parse(await readFileAsText(file))
    } catch {
      message.error('文件不是合法 JSON')
      return
    }
    const types = (parsed as { types?: unknown })?.types
    if (!Array.isArray(types) || types.length === 0) {
      message.error('文件内容不符合导入格式（期望 {"types": [...]} 且非空）')
      return
    }
    modal.confirm({
      title: '导入敏感数据类型',
      content: `文件「${file.name}」包含 ${types.length} 条类型定义，按名称 upsert（同名更新、不存在则新建，单事务整体生效）。确认导入吗？`,
      onOk: () => importMut.mutate(types as ApiSensitiveTypeBody[]),
    })
  }

  /** 表单值 → 提交体（创建/编辑同构：编辑为部分更新但全字段提交，服务端按提供字段合并） */
  const buildBody = (v: TypeFormValues): ApiSensitiveTypeBody => ({
    name: v.name.trim(),
    data_type: v.data_type.trim(),
    level: (v.level || 'GENERAL') as ApiSensitiveTypeBody['level'],
    category: v.category?.trim() ?? '',
    description: v.description?.trim() ?? '',
    locations: v.locations ?? [],
    keywords: v.keywords ?? [],
    regex: v.regex?.trim() ?? '',
    validator: v.validator ?? '',
    exclude_fields: v.exclude_fields ?? [],
    status: v.enabled ? 'ENABLED' : 'DISABLED',
  })

  const openCreate = () => {
    form.resetFields()
    setCreateOpen(true)
  }

  const openEdit = (record: ApiSensitiveDataType) => {
    setEditing(record)
    form.resetFields()
    form.setFieldsValue({
      name: record.name,
      data_type: record.data_type,
      level: record.level,
      category: record.category,
      description: record.description,
      locations: record.locations,
      keywords: record.keywords,
      regex: record.regex,
      validator: record.validator || undefined,
      exclude_fields: record.exclude_fields,
      enabled: record.status === 'ENABLED',
    })
  }

  const toggleStatus = (record: ApiSensitiveDataType) => {
    const next = record.status === 'ENABLED' ? 'DISABLED' : 'ENABLED'
    modal.confirm({
      title: next === 'DISABLED' ? '禁用类型' : '启用类型',
      content: `确定${next === 'DISABLED' ? '禁用' : '启用'}敏感数据类型「${record.name}」吗？禁用后不再参与网关敏感数据识别。`,
      onOk: () => updateMut.mutate({ id: record.id, body: { status: next } }),
    })
  }

  const confirmDelete = (record: ApiSensitiveDataType) => {
    modal.confirm({
      title: '删除类型',
      content: `确定删除敏感数据类型「${record.name}」吗？删除后不再参与识别，且不可恢复。`,
      okButtonProps: { danger: true },
      onOk: () => deleteMut.mutate(record.id),
    })
  }

  const columns: ColumnsType<ApiSensitiveDataType> = [
    {
      title: '名称',
      dataIndex: 'name',
      ellipsis: true,
      render: (v: string, record) => (
        <Space size={4}>
          <Typography.Text strong>{v}</Typography.Text>
          {record.is_builtin ? <Tag color="blue">内置</Tag> : null}
        </Space>
      ),
    },
    {
      title: '数据类型',
      dataIndex: 'data_type',
      width: 120,
      render: (v: string) => <Tag>{v}</Tag>,
    },
    {
      title: '等级',
      dataIndex: 'level',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={SENSITIVE_LEVEL_META} />,
    },
    { title: '分类', dataIndex: 'category', width: 110, render: (v: string) => v || '-' },
    {
      title: '位置',
      dataIndex: 'locations',
      width: 180,
      ellipsis: true,
      render: (v: string[]) => (v?.length ? v.map((l) => <Tag key={l}>{l}</Tag>) : '-'),
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 80,
      render: (v: string) => <StatusTag value={v} map={TYPE_STATUS_META} />,
    },
    { title: '版本', dataIndex: 'version', width: 70 },
    {
      title: '更新时间',
      dataIndex: 'updated_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 180,
      fixed: 'right',
      render: (_, record) =>
        canManage ? (
          <Space size={0}>
            <Button type="link" size="small" onClick={() => openEdit(record)}>
              编辑
            </Button>
            <Button type="link" size="small" onClick={() => toggleStatus(record)}>
              {record.status === 'ENABLED' ? '禁用' : '启用'}
            </Button>
            {record.is_builtin ? (
              <Tooltip title="内置类型不可删除">
                <Button type="link" size="small" danger disabled>
                  删除
                </Button>
              </Tooltip>
            ) : (
              <Button type="link" size="small" danger onClick={() => confirmDelete(record)}>
                删除
              </Button>
            )}
          </Space>
        ) : null,
    },
  ]

  const modalOpen = createOpen || editing !== null

  return (
    <Card
      title="敏感数据类型"
      extra={
        <Space>
          <Button icon={<DownloadOutlined />} loading={exporting} onClick={() => void doExport()}>
            导出
          </Button>
          {canManage ? (
            <>
              <Button icon={<ImportOutlined />} onClick={() => importInputRef.current?.click()}>
                导入
              </Button>
              <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>
                新建类型
              </Button>
            </>
          ) : null}
        </Space>
      }
    >
      <Typography.Paragraph type="secondary">
        登记敏感数据类型（字段词根、值级正则、位置与等级），网关据此在运行时识别敏感字段；
        内置类型与网关词表对齐，不可删除、名称不可改。导入导出为 JSON 文件，按名称 upsert。
      </Typography.Paragraph>
      {/* 导入文件选择（隐藏 input；JSON 文件，解析后经二次确认提交） */}
      <input
        ref={importInputRef}
        type="file"
        accept="application/json,.json"
        aria-label="选择导入文件"
        style={{ display: 'none' }}
        onChange={(e) => {
          const file = e.target.files?.[0]
          e.target.value = ''
          if (file) void onImportFile(file)
        }}
      />
      <QueryErrorAlert error={listQuery.error} />
      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          placeholder="状态"
          allowClear
          style={{ width: 120 }}
          value={status}
          options={Object.entries(TYPE_STATUS_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => {
            setStatus(v)
            setPage(1)
          }}
        />
        <Select
          placeholder="等级"
          allowClear
          style={{ width: 140 }}
          value={level}
          options={Object.entries(SENSITIVE_LEVEL_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => {
            setLevel(v)
            setPage(1)
          }}
        />
        <Input.Search
          placeholder="按名称搜索"
          allowClear
          style={{ width: 220 }}
          onSearch={(v) => {
            setKeyword(v.trim() || undefined)
            setPage(1)
          }}
        />
        {batchDeleteButton}
      </Space>
      <SmartTable<ApiSensitiveDataType>
        storageKey="api-sensitive-types"
        rowKey="id"
        rowSelection={rowSelection}
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        scroll={{ x: 1300 }}
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

      <RecordDetailDrawer
        open={detailRecord !== null}
        title="类型详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />

      <Modal
        title={editing ? `编辑类型：${editing.name}` : '新建敏感数据类型'}
        open={modalOpen}
        onCancel={() => {
          setCreateOpen(false)
          setEditing(null)
        }}
        onOk={() => form.submit()}
        confirmLoading={createMut.isPending || updateMut.isPending}
        width={640}
        destroyOnHidden
      >
        <Form<TypeFormValues>
          form={form}
          layout="vertical"
          initialValues={{ level: 'GENERAL', enabled: true }}
          onFinish={(v) => {
            const body = buildBody(v)
            if (editing) {
              updateMut.mutate({ id: editing.id, body })
            } else {
              createMut.mutate(body)
            }
          }}
        >
          <Form.Item
            name="name"
            label="类型名称"
            rules={[
              { required: true, message: '请填写类型名称' },
              { max: 128, message: '名称不超过 128 字符' },
            ]}
            extra={editing?.is_builtin ? '内置类型名称不可修改' : undefined}
          >
            <Input placeholder="如：手机号、身份证号" disabled={editing?.is_builtin} />
          </Form.Item>
          <Form.Item
            name="data_type"
            label="数据类型标签"
            rules={[
              { required: true, message: '请填写数据类型标签' },
              { max: 64, message: '数据类型标签不超过 64 字符' },
            ]}
            extra="与网关证据标签（evidence.data_type）对齐，如 phone、id_card"
          >
            <Input placeholder="如 phone" />
          </Form.Item>
          <Form.Item name="level" label="敏感等级" rules={[{ required: true, message: '请选择敏感等级' }]}>
            <Select
              options={Object.entries(SENSITIVE_LEVEL_META).map(([value, meta]) => ({
                value,
                label: `${meta.label}（${value}）`,
              }))}
            />
          </Form.Item>
          <Form.Item name="category" label="分类（可选）" rules={[{ max: 64, message: '分类不超过 64 字符' }]}>
            <Input placeholder="如：个人身份信息" />
          </Form.Item>
          <Form.Item
            name="description"
            label="描述（可选）"
            rules={[{ max: 512, message: '描述不超过 512 字符' }]}
          >
            <Input.TextArea rows={2} />
          </Form.Item>
          <Form.Item name="locations" label="可能出现位置（可选）">
            <Select mode="multiple" allowClear options={LOCATION_OPTIONS} placeholder="不限制" />
          </Form.Item>
          <Form.Item name="keywords" label="字段名词根（可选，回车添加）">
            <Select mode="tags" open={false} placeholder="如 phone、mobile" tokenSeparators={[',']} />
          </Form.Item>
          <Form.Item
            name="regex"
            label="值级正则（可选）"
            rules={[{ max: 1024, message: '正则不超过 1024 字符' }]}
            extra="对字段值做正则匹配；留空表示仅按字段名词根识别"
          >
            <Input placeholder="如 ^1[3-9]\d{9}$" style={{ fontFamily: 'monospace' }} />
          </Form.Item>
          <Form.Item name="validator" label="值校验器（可选）">
            <Select
              allowClear
              placeholder="无"
              options={[{ value: 'luhn', label: 'luhn（银行卡号校验）' }]}
            />
          </Form.Item>
          <Form.Item name="exclude_fields" label="排除字段名（可选，回车添加）">
            <Select mode="tags" open={false} placeholder="命名词根但需排除的字段名" tokenSeparators={[',']} />
          </Form.Item>
          <Form.Item name="enabled" label="启用状态" valuePropName="checked">
            <Switch checkedChildren="启用" unCheckedChildren="禁用" />
          </Form.Item>
        </Form>
      </Modal>
    </Card>
  )
}
