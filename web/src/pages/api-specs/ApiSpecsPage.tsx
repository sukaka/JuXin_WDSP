import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Drawer,
  Empty,
  Form,
  Input,
  Modal,
  Select,
  Space,
  Statistic,
  Tag,
  Typography,
  Upload,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import {
  DeleteOutlined,
  DownloadOutlined,
  FileTextOutlined,
  InboxOutlined,
  PlusOutlined,
} from '@ant-design/icons'
import {
  apiSpecsApi,
  type ApiImportSpec,
  type ApiSpecAuditItem,
  type ApiSpecChange,
  type ApiSpecDiff,
  type ApiSpecImportResult,
} from '../../api/apiSecurity'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatBytes, formatDateTime } from '../../utils/format'
import { SPEC_FORMAT_LABELS, formatLocation } from '../../utils/i18nLabels'
import { hasPermission } from '../../utils/permission'
import { API_SPEC_DIFF_TYPE_META } from '../../utils/stage8'
import { specAuditCSV } from './specAuditExport'

const SPEC_MAX_FILE_BYTES = 16 * 1024 * 1024

/** 支持上传的 API 规范扩展名集合（与服务端 ParseSpecContent 支持范围严格对齐） */
export const SPEC_ALLOWED_EXTENSIONS = [
  '.json',
  '.yaml',
  '.yml',
  '.graphql',
  '.gql',
  '.graphqls',
  '.sdl',
  '.proto',
  '.wsdl',
  '.xsd',
  '.xml',
  '.raml',
  '.apib',
  '.har',
  '.zip',
] as const

const SPEC_UPLOAD_ACCEPT = SPEC_ALLOWED_EXTENSIONS.join(',')

function hasAllowedSpecExtension(fileName: string): boolean {
  const lower = fileName.trim().toLowerCase()
  return SPEC_ALLOWED_EXTENSIONS.some((ext) => lower.endsWith(ext))
}

interface ImportFormValues {
  file_name?: string
  spec_json?: string
}

interface ImportUrlFormValues {
  url: string
  name?: string
  /** 可选认证头（单个键值对，如 Authorization: Bearer xxx；更多请走粘贴导入或后续扩展） */
  header_name?: string
  header_value?: string
}

/** 规范版本状态（与 apisecurity api_import_specs.status 枚举一致） */
const SPEC_STATUS_META: Record<string, { color: string; label: string }> = {
  DRAFT: { color: 'blue', label: '草稿' },
  ACTIVE: { color: 'green', label: '激活' },
  HISTORICAL: { color: 'default', label: '历史' },
  INVALID: { color: 'red', label: '无效' },
  ARCHIVED: { color: 'default', label: '归档' },
}

/** 跨版本 CHANGED 级变更类型（与 apisecurity.SpecChange.change_type 枚举一致） */
const SPEC_CHANGE_TYPE_META: Record<string, { color: string; label: string }> =
  {
    ENDPOINT_ADDED: { color: 'green', label: '新增 API' },
    ENDPOINT_REMOVED: { color: 'red', label: '移除 API' },
    PARAM_ADDED: { color: 'blue', label: '新增参数' },
    PARAM_REMOVED: { color: 'volcano', label: '移除参数' },
    TYPE_CHANGED: { color: 'gold', label: '类型变更' },
    REQUIRED_CHANGED: { color: 'orange', label: '必填变更' },
  }

const SPEC_AUDIT_RULE_META: Record<string, { color: string; label: string }> = {
  PATH_PARAMETER_MISSING: { color: 'red', label: '路径参数缺失' },
  PATH_PARAMETER_NOT_REQUIRED: { color: 'orange', label: '路径参数未标记必填' },
  PATH_PARAMETER_UNDECLARED: { color: 'red', label: '路径参数未声明' },
  SENSITIVE_QUERY_PARAMETER: { color: 'orange', label: '敏感查询参数' },
  SUCCESS_RESPONSE_MISSING: { color: 'red', label: '成功响应未声明' },
  ERROR_RESPONSE_MISSING: { color: 'orange', label: '错误响应未声明' },
  SECURITY_SCHEME_UNDEFINED: { color: 'red', label: '认证方案未定义' },
  API_KEY_IN_QUERY: { color: 'red', label: '查询参数传递 API Key' },
}

const SPEC_AUDIT_SEVERITY_META: Record<
  string,
  { color: string; label: string }
> = {
  HIGH: { color: 'red', label: '高' },
  MEDIUM: { color: 'orange', label: '中' },
}

/** 导入成功提示（粘贴/URL 导入同构） */
function importSummary(r: ApiSpecImportResult): string {
  return `导入成功：${r.spec.name} v${r.spec.version_no}（接口 ${r.spec.endpoint_count} 个）；运行时缺失 ${r.missing_in_runtime}，规范缺失 ${r.missing_in_spec}，定义变更 ${r.changed}，登记 API ${r.registered_endpoints}`
}

function auditFilenamePart(value: string, fallback: string): string {
  const cleaned = Array.from(value.trim(), (char) => {
    const code = char.charCodeAt(0)
    return /[<>:"/\\|?*]/.test(char) || code <= 31 || code === 127 ? '_' : char
  })
    .join('')
    .replace(/^\.+|[. ]+$/g, '')
    .slice(0, 80)
  return cleaned || fallback
}

/** 规范对比（WDSP / 阶段8）：导入 OpenAPI 规范并与运行时发现的接口对比差异；版本链激活与跨版本对比 */
export default function ApiSpecsPage() {
  const { message, modal } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canImport = hasPermission(permissions, 'api_spec.import')
  const canManage = hasPermission(permissions, 'api_spec.manage')

  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [importOpen, setImportOpen] = useState(false)
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [importUrlOpen, setImportUrlOpen] = useState(false)
  const [diffSpec, setDiffSpec] = useState<ApiImportSpec | null>(null)
  const [auditSpec, setAuditSpec] = useState<ApiImportSpec | null>(null)
  /** 版本对比抽屉：vdSpec 为基准版本，vdOtherId 为对比目标版本 */
  const [vdSpec, setVdSpec] = useState<ApiImportSpec | null>(null)
  const [vdOtherId, setVdOtherId] = useState<string | undefined>()
  const [form] = Form.useForm<ImportFormValues>()
  const [urlForm] = Form.useForm<ImportUrlFormValues>()

  const listQuery = useQuery({
    queryKey: ['api-specs', page, pageSize],
    queryFn: () => apiSpecsApi.list({ page, page_size: pageSize }),
  })

  const diffQuery = useQuery({
    queryKey: ['api-specs', 'diff', diffSpec?.id],
    queryFn: () => apiSpecsApi.diff(diffSpec?.id as string),
    enabled: !!diffSpec,
  })

  const auditQuery = useQuery({
    queryKey: ['api-specs', 'audit', auditSpec?.id],
    queryFn: () => apiSpecsApi.audit(auditSpec?.id as string),
    enabled: !!auditSpec,
  })

  /** 版本对比候选：同名版本链全部版本（排除基准自身） */
  const vdVersionsQuery = useQuery({
    queryKey: ['api-specs', 'versions', vdSpec?.name],
    queryFn: () =>
      apiSpecsApi.list({ name: vdSpec?.name, page: 1, page_size: 100 }),
    enabled: !!vdSpec,
  })

  const versionDiffQuery = useQuery({
    queryKey: ['api-specs', 'version-diff', vdSpec?.id, vdOtherId],
    queryFn: () =>
      apiSpecsApi.versionDiff(vdSpec?.id as string, vdOtherId as string),
    enabled: !!vdSpec && !!vdOtherId,
  })

  const closeImportModal = () => {
    setImportOpen(false)
    setSelectedFile(null)
    form.resetFields()
  }

  const importMut = useMutation({
    mutationFn: (
      payload:
        | { mode: 'file'; file: File; file_name?: string }
        | { mode: 'text'; file_name?: string; spec: Record<string, unknown> | string },
    ) =>
      payload.mode === 'file'
        ? apiSpecsApi.importFile(payload.file, { file_name: payload.file_name })
        : apiSpecsApi.import({
            file_name: payload.file_name,
            spec: payload.spec,
          }),
    onSuccess: (r) => {
      message.success(importSummary(r))
      closeImportModal()
      void qc.invalidateQueries({ queryKey: ['api-specs'] })
    },
    onError: (e: unknown) =>
      message.error(e instanceof ApiError ? e.message : '导入失败'),
  })

  const importUrlMut = useMutation({
    mutationFn: (body: {
      url: string
      name?: string
      headers?: Record<string, string>
    }) => apiSpecsApi.importUrl(body),
    onSuccess: (r) => {
      message.success(importSummary(r))
      setImportUrlOpen(false)
      urlForm.resetFields()
      void qc.invalidateQueries({ queryKey: ['api-specs'] })
    },
    onError: (e: unknown) =>
      message.error(e instanceof ApiError ? e.message : 'URL 导入失败'),
  })

  const activateMut = useMutation({
    mutationFn: (id: string) => apiSpecsApi.activate(id),
    onSuccess: (r) => {
      message.success(
        `已激活 ${r.spec.name} v${r.spec.version_no}，同名旧版降为历史`,
      )
      void qc.invalidateQueries({ queryKey: ['api-specs'] })
    },
    onError: (e: unknown) =>
      message.error(e instanceof ApiError ? e.message : '激活失败'),
  })

  const handleSelectSpecFile = (file: File) => {
    if (!hasAllowedSpecExtension(file.name)) {
      message.error(
        `不支持的文件扩展名，仅支持 ${SPEC_ALLOWED_EXTENSIONS.join(' / ')}`,
      )
      return Upload.LIST_IGNORE
    }
    if (file.size === 0) {
      message.error('规范文件不能为空')
      return Upload.LIST_IGNORE
    }
    if (file.size > SPEC_MAX_FILE_BYTES) {
      message.error('规范文件大小不能超过 16 MiB')
      return Upload.LIST_IGNORE
    }
    setSelectedFile(file)
    form.setFieldValue('file_name', file.name)
    form.setFields([{ name: 'spec_json', errors: [] }])
    return false
  }

  const handleImport = (v: ImportFormValues) => {
    const fileName = v.file_name?.trim() || undefined
    if (selectedFile) {
      importMut.mutate({ mode: 'file', file: selectedFile, file_name: fileName })
      return
    }
    const raw = (v.spec_json ?? '').trim()
    if (!raw) {
      message.error('请上传规范文件或粘贴规范内容')
      return
    }
    if (raw.startsWith('{') || raw.startsWith('[')) {
      try {
        const parsed: unknown = JSON.parse(raw)
        if (
          typeof parsed !== 'object' ||
          parsed === null ||
          Array.isArray(parsed)
        ) {
          message.error('规范内容须为 JSON 对象')
          return
        }
        importMut.mutate({
          mode: 'text',
          file_name: fileName,
          spec: parsed as Record<string, unknown>,
        })
      } catch {
        message.error('规范内容须为合法 JSON')
      }
      return
    }
    // YAML / GraphQL SDL / Protobuf / WSDL / XSD / RAML / API Blueprint 原文交由服务端统一解析
    importMut.mutate({ mode: 'text', file_name: fileName, spec: raw })
  }

  const handleImportUrl = (v: ImportUrlFormValues) => {
    const headerName = v.header_name?.trim()
    const headerValue = v.header_value?.trim()
    if (headerName && !headerValue) {
      message.error('认证头名称已填写时，认证头值不能为空')
      return
    }
    importUrlMut.mutate({
      url: v.url.trim(),
      name: v.name?.trim() || undefined,
      headers:
        headerName && headerValue ? { [headerName]: headerValue } : undefined,
    })
  }

  const openDiff = (record: ApiImportSpec) => {
    setDiffSpec(record)
  }

  const openVersionDiff = (record: ApiImportSpec) => {
    setVdSpec(record)
    setVdOtherId(undefined)
  }

  const confirmActivate = (record: ApiImportSpec) => {
    modal.confirm({
      title: '激活规范版本',
      content: `确定激活「${record.name} v${record.version_no}」吗？同名当前激活版本将降为历史。`,
      onOk: () => activateMut.mutate(record.id),
    })
  }

  const columns: ColumnsType<ApiImportSpec> = [
    {
      title: '规范',
      dataIndex: 'name',
      ellipsis: true,
      render: (v: string, record) =>
        v ? (
          <Space size={4}>
            <Typography.Text strong>{v}</Typography.Text>
            <Tag>v{record.version_no}</Tag>
          </Space>
        ) : (
          '-'
        ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={SPEC_STATUS_META} />,
    },
    {
      title: '文件名',
      dataIndex: 'file_name',
      ellipsis: true,
      render: (v?: string | null) => v || '-',
    },
    {
      title: '格式',
      dataIndex: 'format',
      width: 120,
      render: (v: string) => (v ? (SPEC_FORMAT_LABELS[v] ?? v) : '-'),
    },
    { title: '接口数', dataIndex: 'endpoint_count', width: 90 },
    {
      title: '内容哈希',
      dataIndex: 'content_hash',
      width: 140,
      render: (v: string) =>
        v ? <Typography.Text code>{v.slice(0, 10)}…</Typography.Text> : '-',
    },
    {
      title: '导入时间',
      dataIndex: 'created_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 300,
      fixed: 'right',
      render: (_, record) => (
        <Space size={0}>
          <Button type="link" size="small" onClick={() => openDiff(record)}>
            查看差异
          </Button>
          <Button
            type="link"
            size="small"
            onClick={() => openVersionDiff(record)}
          >
            版本对比
          </Button>
          <Button type="link" size="small" onClick={() => setAuditSpec(record)}>
            规范审计
          </Button>
          {canManage && record.status && record.status !== 'ACTIVE' ? (
            <Button
              type="link"
              size="small"
              onClick={() => confirmActivate(record)}
            >
              激活
            </Button>
          ) : null}
        </Space>
      ),
    },
  ]

  const diffColumns: ColumnsType<ApiSpecDiff> = [
    {
      title: '差异类型',
      dataIndex: 'diff_type',
      width: 120,
      render: (v: string) => (
        <StatusTag value={v} map={API_SPEC_DIFF_TYPE_META} />
      ),
    },
    {
      title: '接口键',
      dataIndex: 'endpoint_key',
      width: 220,
      ellipsis: true,
      render: (v: string) =>
        v ? <Typography.Text code>{v}</Typography.Text> : '-',
    },
    {
      title: '差异明细',
      dataIndex: 'detail',
      ellipsis: true,
      render: (v: Record<string, unknown>) => {
        const s = JSON.stringify(v)
        if (!s) return '-'
        return (
          <Typography.Text
            code
            ellipsis={{ tooltip: s }}
            style={{ maxWidth: 360 }}
          >
            {s}
          </Typography.Text>
        )
      },
    },
  ]

  const changeColumns: ColumnsType<ApiSpecChange> = [
    {
      title: '接口键',
      dataIndex: 'endpoint_key',
      width: 220,
      ellipsis: true,
      render: (v: string) =>
        v ? <Typography.Text code>{v}</Typography.Text> : '-',
    },
    {
      title: '变更类型',
      dataIndex: 'change_type',
      width: 110,
      render: (v: string) => (
        <StatusTag value={v} map={SPEC_CHANGE_TYPE_META} />
      ),
    },
    {
      title: '参数',
      key: 'param',
      width: 180,
      ellipsis: true,
      render: (_, record) =>
        record.param_name ? (
          <Space size={4}>
            {record.param_in ? <Tag>{formatLocation(record.param_in)}</Tag> : null}
            <Typography.Text code>{record.param_name}</Typography.Text>
          </Space>
        ) : (
          '-'
        ),
    },
    {
      title: '变更',
      key: 'change',
      width: 180,
      ellipsis: true,
      render: (_, record) =>
        record.before || record.after ? (
          <Typography.Text code>
            {record.before || '∅'} → {record.after || '∅'}
          </Typography.Text>
        ) : (
          '-'
        ),
    },
  ]

  const auditColumns: ColumnsType<ApiSpecAuditItem> = [
    {
      title: '规则',
      dataIndex: 'rule_id',
      width: 180,
      render: (v: string) => <StatusTag value={v} map={SPEC_AUDIT_RULE_META} />,
    },
    {
      title: '严重级别',
      dataIndex: 'severity',
      width: 100,
      render: (v: string) => (
        <StatusTag value={v} map={SPEC_AUDIT_SEVERITY_META} />
      ),
    },
    {
      title: '接口',
      dataIndex: 'endpoint_key',
      width: 210,
      ellipsis: true,
      render: (v: string) =>
        v ? <Typography.Text code>{v}</Typography.Text> : '-',
    },
    {
      title: '参数位置',
      dataIndex: 'param_in',
      width: 110,
      render: (v: string) => {
        if (!v) return '-'
        if (v.toUpperCase() === 'SECURITY') return '认证方案'
        return formatLocation(v)
      },
    },
    {
      title: '参数名称',
      dataIndex: 'param_name',
      width: 140,
      render: (v: string) =>
        v ? <Typography.Text code>{v}</Typography.Text> : '-',
    },
    { title: '说明', dataIndex: 'message', render: (v: string) => v || '-' },
  ]

  const versionDiffData = versionDiffQuery.data
  const auditData =
    auditQuery.data?.spec_id === auditSpec?.id ? auditQuery.data : undefined
  const auditExportDisabled =
    !auditData ||
    auditData.items.length === 0 ||
    auditQuery.isLoading ||
    auditQuery.isFetching ||
    !!auditQuery.error

  const handleAuditExport = () => {
    if (auditExportDisabled || !auditData || !auditSpec) return
    const csv = specAuditCSV(auditData)
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    try {
      link.href = url
      link.download = `api-spec-audit-${auditFilenamePart(auditSpec.name, 'spec')}-v${auditFilenamePart(String(auditSpec.version_no), 'unknown')}.csv`
      document.body.appendChild(link)
      link.click()
    } finally {
      link.remove()
      URL.revokeObjectURL(url)
    }
  }

  return (
    <Card
      title="规范对比"
      extra={
        canImport ? (
          <Space>
            <Button
              icon={<PlusOutlined />}
              onClick={() => setImportUrlOpen(true)}
            >
              URL 导入
            </Button>
            <Button
              type="primary"
              icon={<PlusOutlined />}
              onClick={() => setImportOpen(true)}
            >
              导入规范
            </Button>
          </Space>
        ) : undefined
      }
    >
      <Typography.Paragraph type="secondary">
        导入 API 规范（支持 OpenAPI 3 / Swagger 2.0 / AsyncAPI / Postman v2.1 /
        JSON Schema / GraphQL / Protobuf / WSDL / XSD / RAML / API Blueprint /
        HAR / ZIP
        规范包）后，系统自动与运行时发现的接口对比：规范缺失、运行时缺失与定义变更三类差异可用于发现影子
        API。同名再导入形成版本链（版本号自增），同名唯一激活版本，可跨版本对比定义变更。
      </Typography.Paragraph>
      <QueryErrorAlert error={listQuery.error} />
      <SmartTable<ApiImportSpec>
        storageKey="api-specs"
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        scroll={{ x: 1200 }}
        onRow={(record) => ({
          onDoubleClick: () => openDiff(record),
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
        title="导入规范"
        open={importOpen}
        onCancel={closeImportModal}
        onOk={() => form.submit()}
        confirmLoading={importMut.isPending}
        okText="导入"
        cancelText="取消"
        width={680}
        destroyOnHidden
      >
        <Form<ImportFormValues>
          form={form}
          layout="vertical"
          onFinish={handleImport}
        >
          <Form.Item label="上传规范文件">
            <Upload.Dragger
              accept={SPEC_UPLOAD_ACCEPT}
              maxCount={1}
              showUploadList={false}
              disabled={importMut.isPending}
              beforeUpload={handleSelectSpecFile}
            >
              <p className="ant-upload-drag-icon">
                <InboxOutlined />
              </p>
              <p className="ant-upload-text">
                点击或拖拽规范文件到此区域上传
              </p>
              <p className="ant-upload-hint">
                支持 OpenAPI 3 / Swagger 2.0 / AsyncAPI / Postman v2.1 / JSON
                Schema / GraphQL / Protobuf / WSDL / XSD / RAML / API Blueprint
                / HAR / ZIP 多文件包（
                {SPEC_ALLOWED_EXTENSIONS.join(' ')}，上限 16 MiB）
              </p>
            </Upload.Dragger>
            {selectedFile ? (
              <div
                style={{
                  marginTop: 8,
                  padding: '8px 12px',
                  border: '1px solid #d9d9d9',
                  borderRadius: 6,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: 8,
                }}
              >
                <Space size={8} style={{ minWidth: 0 }}>
                  <FileTextOutlined />
                  <Typography.Text ellipsis strong>
                    {selectedFile.name}
                  </Typography.Text>
                  <Tag>{formatBytes(selectedFile.size)}</Tag>
                </Space>
                <Button
                  type="text"
                  size="small"
                  danger
                  icon={<DeleteOutlined />}
                  onClick={() => setSelectedFile(null)}
                >
                  移除
                </Button>
              </div>
            ) : null}
          </Form.Item>
          <Form.Item name="file_name" label="文件名（可选）">
            <Input
              placeholder="如 openapi-payment.yaml（上传文件时自动填充）"
              autoComplete="off"
            />
          </Form.Item>
          <Form.Item
            name="spec_json"
            label="规范内容（可直接粘贴 JSON / YAML / GraphQL / Protobuf / WSDL / XSD / RAML / APIB / HAR）"
            rules={
              selectedFile
                ? []
                : [{ required: true, message: '请上传规范文件或粘贴规范内容' }]
            }
          >
            <Input.TextArea
              rows={8}
              disabled={!!selectedFile}
              style={{ fontFamily: 'monospace' }}
              placeholder={
                selectedFile
                  ? `已选择文件「${selectedFile.name}」，点击「导入」直接上传；移除文件后可改用粘贴导入`
                  : '{"openapi":"3.0.0",...} 或 openapi: 3.0.0 / type Query {...} / syntax = "proto3"; ...（.zip 包请通过上方上传）'
              }
            />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title="从 URL 导入规范"
        open={importUrlOpen}
        onCancel={() => setImportUrlOpen(false)}
        onOk={() => urlForm.submit()}
        confirmLoading={importUrlMut.isPending}
        okText="导入"
        cancelText="取消"
        width={560}
        destroyOnHidden
      >
        <Typography.Paragraph type="secondary">
          服务端拉取 URL 处的规范文档（支持 OpenAPI 3 / Swagger 2.0 / AsyncAPI /
          Postman v2.1 / JSON Schema / GraphQL / Protobuf / WSDL / XSD / RAML /
          API Blueprint / HAR / ZIP；仅 http/https，拒绝内网/保留地址，上限
          16MiB）。
        </Typography.Paragraph>
        <Form<ImportUrlFormValues>
          form={urlForm}
          layout="vertical"
          onFinish={handleImportUrl}
        >
          <Form.Item
            name="url"
            label="规范文档 URL"
            rules={[
              { required: true, message: '请输入规范文档 URL' },
              { max: 2048, message: 'URL 不超过 2048 字符' },
            ]}
          >
            <Input
              placeholder="https://example.com/openapi.json"
              autoComplete="off"
            />
          </Form.Item>
          <Form.Item
            name="name"
            label="规范名称（可选，缺省取 info.title / 文件名）"
          >
            <Input placeholder="如 payment-api" autoComplete="off" />
          </Form.Item>
          <Space.Compact block>
            <Form.Item
              name="header_name"
              label="认证头名称（可选）"
              style={{ width: '40%', marginRight: 8 }}
            >
              <Input placeholder="Authorization" autoComplete="off" />
            </Form.Item>
            <Form.Item
              name="header_value"
              label="认证头值"
              style={{ width: '60%' }}
            >
              <Input.Password
                placeholder="Bearer xxx"
                autoComplete="new-password"
              />
            </Form.Item>
          </Space.Compact>
        </Form>
      </Modal>

      <Drawer
        title={`规范差异：${diffSpec?.file_name ?? '-'}`}
        open={!!diffSpec}
        onClose={() => setDiffSpec(null)}
        width={760}
        destroyOnHidden
      >
        <QueryErrorAlert error={diffQuery.error} />
        <SmartTable<ApiSpecDiff>
          storageKey="api-specs-diff"
          rowKey="id"
          loading={diffQuery.isLoading}
          columns={diffColumns}
          dataSource={diffQuery.data?.diffs ?? []}
          scroll={{ x: 700 }}
          pagination={{
            pageSize: 20,
            showSizeChanger: true,
            showTotal: (t) => `共 ${t} 条`,
          }}
        />
      </Drawer>

      <Drawer
        title={`规范审计：${auditSpec?.name ?? '-'} v${auditSpec?.version_no ?? '-'}`}
        open={!!auditSpec}
        onClose={() => setAuditSpec(null)}
        width={1000}
        destroyOnHidden
        extra={
          <Button
            aria-label="导出当前结果"
            icon={<DownloadOutlined />}
            disabled={auditExportDisabled}
            onClick={handleAuditExport}
          >
            导出当前结果
          </Button>
        }
      >
        <QueryErrorAlert error={auditQuery.error} message="规范审计加载失败" />
        {auditData ? (
          <Space size="large" wrap style={{ margin: '16px 0' }}>
            <Statistic title="操作数" value={auditData.operation_count} />
            <Statistic title="问题数" value={auditData.issue_count} />
            <Statistic title="高危问题" value={auditData.high_count} />
            <Statistic title="中危问题" value={auditData.medium_count} />
          </Space>
        ) : null}
        {auditData?.truncated ? (
          <Alert
            type="warning"
            showIcon
            title="问题明细较多，只展示前 500 条；导出仅包含当前已返回明细"
            style={{ marginBottom: 16 }}
          />
        ) : null}
        {auditData?.items.length === 0 ? (
          <Empty description="未发现本批规则问题" style={{ padding: 48 }} />
        ) : (
          <SmartTable<ApiSpecAuditItem>
            storageKey="api-specs-audit"
            rowKey={(r) =>
              `${r.rule_id}|${r.endpoint_key}|${r.param_in}|${r.param_name}|${r.message}`
            }
            loading={auditQuery.isLoading || auditQuery.isFetching}
            columns={auditColumns}
            dataSource={auditData?.items ?? []}
            scroll={{ x: 900 }}
            pagination={false}
          />
        )}
      </Drawer>

      <Drawer
        title={`版本对比：${vdSpec?.name ?? '-'}`}
        open={!!vdSpec}
        onClose={() => setVdSpec(null)}
        width={820}
        destroyOnHidden
      >
        <Space style={{ marginBottom: 16 }} wrap align="center">
          <Tag>基准 v{vdSpec?.version_no}</Tag>
          <Typography.Text type="secondary">对比目标</Typography.Text>
          <Select
            placeholder="选择同链另一版本"
            style={{ width: 280 }}
            loading={vdVersionsQuery.isLoading}
            value={vdOtherId}
            options={(vdVersionsQuery.data?.items ?? [])
              .filter((s) => s.id !== vdSpec?.id)
              .map((s) => ({
                value: s.id,
                label: `v${s.version_no}（${SPEC_STATUS_META[s.status]?.label ?? s.status}）`,
              }))}
            onChange={(v) => setVdOtherId(v)}
          />
        </Space>
        <QueryErrorAlert error={versionDiffQuery.error} />
        {versionDiffData ? (
          <Typography.Paragraph type="secondary">
            v{versionDiffData.base.version_no} → v
            {versionDiffData.target.version_no}，共{' '}
            {versionDiffData.changes.length} 处定义变更
          </Typography.Paragraph>
        ) : null}
        <SmartTable<ApiSpecChange>
          storageKey="api-specs-version-diff"
          rowKey={(r) =>
            `${r.endpoint_key}|${r.change_type}|${r.param_name ?? ''}`
          }
          loading={versionDiffQuery.isLoading || versionDiffQuery.isFetching}
          columns={changeColumns}
          dataSource={versionDiffData?.changes ?? []}
          scroll={{ x: 720 }}
          pagination={false}
        />
      </Drawer>
    </Card>
  )
}
