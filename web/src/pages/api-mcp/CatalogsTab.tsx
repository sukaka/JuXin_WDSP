import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Alert,
  Button,
  Card,
  Drawer,
  Form,
  Input,
  InputNumber,
  Popconfirm,
  Select,
  Space,
  Switch,
  Tag,
  Typography,
} from 'antd'
import { PlusOutlined } from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'
import { ApiError } from '../../api/client'
import {
  mcpApi,
  type McpToolCatalogDetail,
  type McpToolCatalogInput,
  type McpToolCatalogSummary,
  type McpToolInput,
} from '../../api/mcp'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import {
  MCP_CATALOG_STATUS_META,
  MCP_DATA_CLASSIFICATION_META,
  MCP_RISK_LEVEL_META,
  parseArgConstraintsText,
  parseJsonText,
  shortMcpHash,
} from '../../utils/mcp'
import { hasPermission } from '../../utils/permission'
import CatalogDetailDrawer from './CatalogDetailDrawer'

/** 表单内单工具取值（schema/约束为 JSON 文本域，提交时解析校验） */
interface ToolFormValue {
  tool_name?: string
  tool_version?: string
  description?: string
  input_schema_text?: string
  output_schema_text?: string
  capability_tags?: string[]
  risk_level?: string
  data_classification?: string
  allowed_principals?: string[]
  allowed_roles?: string[]
  allowed_tenants?: string[]
  approval_required?: boolean
  max_calls_per_minute?: number
  arg_constraints_text?: string
}

interface CatalogFormValues {
  name: string
  service_identity: string
  protocol_version?: string
  tools: ToolFormValue[]
}

/** 详情工具行 → 表单回填 */
function toolToFormValue(t: McpToolCatalogDetail['tools'][number]): ToolFormValue {
  return {
    tool_name: t.tool_name,
    tool_version: t.tool_version,
    description: '',
    input_schema_text: t.input_schema ? JSON.stringify(t.input_schema) : '',
    output_schema_text: t.output_schema ? JSON.stringify(t.output_schema) : '',
    capability_tags: t.capability_tags ?? [],
    risk_level: t.risk_level,
    data_classification: t.data_classification,
    allowed_principals: t.allowed_principals ?? [],
    allowed_roles: t.allowed_roles ?? [],
    allowed_tenants: t.allowed_tenants ?? [],
    approval_required: t.approval_required,
    max_calls_per_minute: t.max_calls_per_minute,
    arg_constraints_text: t.arg_constraints && t.arg_constraints.length > 0 ? JSON.stringify(t.arg_constraints) : '',
  }
}

/** 表单值 → 导入载荷（JSON 文本域经字段级校验保证可解析；整体替换语义） */
function toCatalogPayload(values: CatalogFormValues, version?: number): McpToolCatalogInput {
  const tools: McpToolInput[] = (values.tools ?? []).map((t) => ({
    tool_name: (t.tool_name ?? '').trim(),
    tool_version: (t.tool_version ?? '').trim(),
    description: t.description ?? '',
    input_schema: parseJsonText(t.input_schema_text ?? '').value ?? null,
    output_schema: parseJsonText(t.output_schema_text ?? '').value ?? null,
    capability_tags: t.capability_tags ?? [],
    risk_level: t.risk_level ?? 'HIGH',
    data_classification: t.data_classification ?? 'UNKNOWN',
    allowed_principals: t.allowed_principals ?? [],
    allowed_roles: t.allowed_roles ?? [],
    allowed_tenants: t.allowed_tenants ?? [],
    approval_required: t.approval_required ?? false,
    max_calls_per_minute: t.max_calls_per_minute ?? 0,
    arg_constraints: parseArgConstraintsText(t.arg_constraints_text ?? '').value ?? [],
  }))
  return {
    name: values.name.trim(),
    service_identity: values.service_identity.trim(),
    protocol_version: (values.protocol_version ?? '').trim() || '2025-11-25',
    tools,
    ...(version !== undefined ? { version } : {}),
  }
}

/** 导入/再导入编辑抽屉（catalogId 非空=整体再导入，乐观锁 version 随行） */
function CatalogEditorDrawer({
  catalogId,
  onClose,
  onSaved,
}: {
  catalogId: string | null
  onClose: () => void
  onSaved: () => void
}) {
  const { message } = AntdApp.useApp()
  const [form] = Form.useForm<CatalogFormValues>()
  const isReimport = catalogId !== null
  const [submitError, setSubmitError] = useState<string | null>(null)

  const detailQuery = useQuery({
    queryKey: ['mcp-catalog', catalogId],
    queryFn: () => mcpApi.getCatalog(catalogId as string),
    enabled: isReimport,
  })
  const detail = detailQuery.data

  const saveMut = useMutation({
    mutationFn: (input: McpToolCatalogInput) =>
      isReimport ? mcpApi.updateCatalog(catalogId as string, input) : mcpApi.createCatalog(input),
    onSuccess: () => {
      message.success(
        isReimport
          ? '再导入完成：语义相等行保留审核态，变更/新增行已重置待审核（旧审批不继承）'
          : '目录已导入，全部工具行待审核',
      )
      onSaved()
      onClose()
    },
    onError: (e: unknown) => {
      if (e instanceof ApiError && e.status === 409) {
        setSubmitError(`版本冲突，请刷新后重试（${e.message}）`)
        return
      }
      setSubmitError(e instanceof ApiError ? e.message : '保存失败')
    },
  })

  const initialValues: CatalogFormValues = detail
    ? {
        name: detail.catalog.name,
        service_identity: detail.catalog.service_identity,
        protocol_version: detail.catalog.protocol_version,
        tools: detail.tools.map(toolToFormValue),
      }
    : {
        name: '',
        service_identity: '',
        protocol_version: '2025-11-25',
        tools: [{}],
      }

  return (
    <Drawer
      title={isReimport ? `再导入目录（版本 v${detail?.catalog.version ?? '-'}，整体替换）` : '导入 MCP 工具目录'}
      width={960}
      open
      onClose={onClose}
      destroyOnHidden
      extra={
        <Space>
          <Button onClick={onClose}>取消</Button>
          <Button type="primary" loading={saveMut.isPending} disabled={isReimport && !detail} onClick={() => form.submit()}>
            {isReimport ? '确认再导入' : '确认导入'}
          </Button>
        </Space>
      }
    >
      {submitError ? (
        <Alert type="error" showIcon style={{ marginBottom: 16 }} message="保存失败" description={submitError} closable onClose={() => setSubmitError(null)} />
      ) : null}
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        message={isReimport
          ? '整体再导入：语义相等行（名称+版本+描述+双 schema 一致）保留 tool_hash 与审核态；变更/新增行重算 tool_hash 并重置待审核，消失行删除。'
          : '导入后全部工具行落「待审核」；发布通道只下发「已通过」工具行。'}
      />
      {isReimport && detailQuery.error ? <QueryErrorAlert error={detailQuery.error} /> : null}
      {isReimport && !detail && !detailQuery.error ? (
        <Typography.Text type="secondary">加载中…</Typography.Text>
      ) : (
        <Form<CatalogFormValues>
          key={detail ? `${detail.catalog.id}:${detail.catalog.version}` : 'create'}
          form={form}
          layout="vertical"
          initialValues={initialValues}
          onFinish={(values) => {
            setSubmitError(null)
            saveMut.mutate(toCatalogPayload(values, detail?.catalog.version))
          }}
        >
          <Space size={16} wrap style={{ display: 'flex' }}>
            <Form.Item
              name="name"
              label="目录名"
              style={{ width: 280 }}
              rules={[{ required: true, whitespace: true, message: '目录名必填' }, { max: 128, message: '不超过 128 字符' }]}
              extra="全局唯一（同名 409）"
            >
              <Input placeholder="如：pay-mcp-tools" />
            </Form.Item>
            <Form.Item
              name="service_identity"
              label="服务身份"
              style={{ width: 360 }}
              rules={[{ required: true, whitespace: true, message: '服务身份必填' }, { max: 256, message: '不超过 256 字符' }]}
            >
              <Input placeholder="如：mcp://pay.example.com" />
            </Form.Item>
            <Form.Item name="protocol_version" label="协议版本" style={{ width: 200 }} rules={[{ max: 32, message: '不超过 32 字符' }]}>
              <Input placeholder="2025-11-25" />
            </Form.Item>
          </Space>

          <Typography.Title level={5}>工具集（整体提交；空数组=空目录合法）</Typography.Title>
          <Form.List name="tools">
            {(fields, { add, remove }) => (
              <>
                {fields.map((field) => (
                  <Card
                    key={field.key}
                    size="small"
                    style={{ marginBottom: 12 }}
                    title={`工具 ${field.name + 1}`}
                    extra={
                      <Button type="link" size="small" danger disabled={fields.length <= 1} onClick={() => remove(field.name)}>
                        删除工具
                      </Button>
                    }
                  >
                    <Space size={12} wrap style={{ display: 'flex' }}>
                      <Form.Item
                        name={[field.name, 'tool_name']}
                        label="工具名"
                        style={{ width: 220 }}
                        rules={[{ required: true, whitespace: true, message: '工具名必填' }, { max: 128, message: '不超过 128 字符' }]}
                      >
                        <Input placeholder="如：charge" />
                      </Form.Item>
                      <Form.Item name={[field.name, 'tool_version']} label="版本" style={{ width: 140 }} rules={[{ max: 128, message: '不超过 128 字符' }]}>
                        <Input placeholder="如：1.0.0" />
                      </Form.Item>
                      <Form.Item name={[field.name, 'risk_level']} label="风险等级" initialValue="HIGH">
                        <Select
                          style={{ width: 120 }}
                          options={Object.entries(MCP_RISK_LEVEL_META).map(([value, meta]) => ({ value, label: `${meta.label}（${value}）` }))}
                        />
                      </Form.Item>
                      <Form.Item name={[field.name, 'data_classification']} label="数据分级" initialValue="UNKNOWN">
                        <Select
                          style={{ width: 150 }}
                          options={Object.entries(MCP_DATA_CLASSIFICATION_META).map(([value, meta]) => ({ value, label: `${meta.label}（${value}）` }))}
                        />
                      </Form.Item>
                      <Form.Item name={[field.name, 'max_calls_per_minute']} label="调用预算/分钟" initialValue={0} extra="0=不限">
                        <InputNumber min={0} precision={0} style={{ width: 120 }} />
                      </Form.Item>
                      <Form.Item
                        name={[field.name, 'approval_required']}
                        label="需审批"
                        valuePropName="checked"
                        initialValue={false}
                        extra="G1 语义=默认拒绝（同 HIGH）"
                      >
                        <Switch />
                      </Form.Item>
                    </Space>
                    <Form.Item
                      name={[field.name, 'description']}
                      label="描述全文（入 tool_hash——同名变更将重置待审核）"
                      rules={[{ max: 65536, message: '不超过 65536 字符' }]}
                    >
                      <Input.TextArea rows={2} placeholder="工具描述（规范化全文参与不可变摘要）" />
                    </Form.Item>
                    <Space size={12} wrap style={{ display: 'flex' }}>
                      <Form.Item name={[field.name, 'capability_tags']} label="能力标签" style={{ width: 300 }}>
                        <Select mode="tags" placeholder="回车添加" open={false} suffixIcon={null} />
                      </Form.Item>
                      <Form.Item name={[field.name, 'allowed_principals']} label="允许主体" style={{ width: 260 }} extra="空=该维度不约束">
                        <Select mode="tags" placeholder="回车添加" open={false} suffixIcon={null} />
                      </Form.Item>
                      <Form.Item name={[field.name, 'allowed_roles']} label="允许角色" style={{ width: 220 }} extra="空=不约束">
                        <Select mode="tags" placeholder="回车添加" open={false} suffixIcon={null} />
                      </Form.Item>
                      <Form.Item name={[field.name, 'allowed_tenants']} label="允许租户" style={{ width: 220 }} extra="空=不约束">
                        <Select mode="tags" placeholder="回车添加" open={false} suffixIcon={null} />
                      </Form.Item>
                    </Space>
                    <Space size={12} wrap style={{ display: 'flex' }}>
                      <Form.Item
                        name={[field.name, 'input_schema_text']}
                        label="输入 JSON Schema（可空）"
                        style={{ width: 420 }}
                        rules={[{
                          validator: (_, v: string) => {
                            const r = parseJsonText(v ?? '')
                            return r.error ? Promise.reject(new Error(r.error)) : Promise.resolve()
                          },
                        }]}
                      >
                        <Input.TextArea rows={2} placeholder='如：{"type":"object","properties":{"amount":{"type":"number"}}}' />
                      </Form.Item>
                      <Form.Item
                        name={[field.name, 'output_schema_text']}
                        label="输出 JSON Schema（可空）"
                        style={{ width: 420 }}
                        rules={[{
                          validator: (_, v: string) => {
                            const r = parseJsonText(v ?? '')
                            return r.error ? Promise.reject(new Error(r.error)) : Promise.resolve()
                          },
                        }]}
                      >
                        <Input.TextArea rows={2} placeholder="可空" />
                      </Form.Item>
                      <Form.Item
                        name={[field.name, 'arg_constraints_text']}
                        label="参数约束（JSON 数组，可空）"
                        style={{ width: 420 }}
                        rules={[{
                          validator: (_, v: string) => {
                            const r = parseArgConstraintsText(v ?? '')
                            return r.error ? Promise.reject(new Error(r.error)) : Promise.resolve()
                          },
                        }]}
                      >
                        <Input.TextArea rows={2} placeholder='如：[{"field":"url","kind":"domain_suffix","allow":[".example.com"]}]' />
                      </Form.Item>
                    </Space>
                  </Card>
                ))}
                <Button block icon={<PlusOutlined />} onClick={() => add({ risk_level: 'HIGH', data_classification: 'UNKNOWN', max_calls_per_minute: 0 })}>
                  添加工具
                </Button>
              </>
            )}
          </Form.List>
        </Form>
      )}
    </Drawer>
  )
}

/**
 * MCP 工具目录列表（NG-MCP G1 §1.14 端点 1~5）：catalog_hash/审核统计/启停状态；
 * 导入与再导入后新工具与变更行恒落「待审核」（明确展示语，M02 红线）。
 */
export default function CatalogsTab() {
  const { message } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'api_spec.manage')
  const [detailId, setDetailId] = useState<string | null>(null)
  /** undefined 关闭；null 新建导入；字符串为再导入目录 id */
  const [editor, setEditor] = useState<string | null | undefined>(undefined)

  const listQuery = useQuery({
    queryKey: ['mcp-catalogs'],
    queryFn: () => mcpApi.listCatalogs(),
  })
  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ['mcp-catalogs'] })
    void qc.invalidateQueries({ queryKey: ['mcp-catalog'] })
  }

  const deleteMut = useMutation({
    mutationFn: (id: string) => mcpApi.deleteCatalog(id),
    onSuccess: () => {
      message.success('目录已删除')
      invalidate()
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '删除失败'),
  })

  const columns: ColumnsType<McpToolCatalogSummary> = [
    { title: '目录名', dataIndex: 'name', width: 180, ellipsis: true, render: (v: string) => <Typography.Text strong>{v}</Typography.Text> },
    { title: '服务身份', dataIndex: 'service_identity', width: 220, ellipsis: true, render: (v: string) => <Typography.Text code>{v}</Typography.Text> },
    { title: '协议版本', dataIndex: 'protocol_version', width: 110 },
    { title: '状态', dataIndex: 'status', width: 90, render: (v: string) => <StatusTag value={v} map={MCP_CATALOG_STATUS_META} /> },
    { title: '工具数', dataIndex: 'tool_count', width: 80 },
    {
      title: '审核统计', key: 'review', width: 220,
      render: (_, record) => (
        <Space size={4} wrap>
          <Tag color="green">通过 {record.approved_count}</Tag>
          <Tag color="gold">待审 {record.pending_count}</Tag>
          <Tag color="red">拒绝 {record.rejected_count}</Tag>
        </Space>
      ),
    },
    {
      title: 'catalog_hash', dataIndex: 'catalog_hash', width: 140,
      render: (v: string) => <Typography.Text code title={v}>{shortMcpHash(v)}</Typography.Text>,
    },
    { title: '更新时间', dataIndex: 'updated_at', width: 170, render: formatDateTime },
    {
      title: '操作', key: 'actions', width: 200, fixed: 'right',
      render: (_, record) => (
        <Space size={0}>
          <Button type="link" size="small" onClick={() => setDetailId(record.id)}>详情</Button>
          {canManage ? (
            <>
              <Button type="link" size="small" onClick={() => setEditor(record.id)}>再导入</Button>
              <Popconfirm
                title={`删除目录「${record.name}」？`}
                description="工具行级联删除；被绑定引用时将 409（先解绑再删除）。"
                okText="确认删除"
                okButtonProps={{ danger: true }}
                onConfirm={() => deleteMut.mutate(record.id)}
              >
                <Button type="link" size="small" danger>删除</Button>
              </Popconfirm>
            </>
          ) : null}
        </Space>
      ),
    },
  ]

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Space style={{ display: 'flex', justifyContent: 'space-between' }} wrap>
        <Typography.Text type="secondary">
          导入/再导入后，新工具与语义变更行恒落「待审核」（同名变更重算 tool_hash，旧审批不继承）；发布通道只下发「已通过」工具行。
        </Typography.Text>
        {canManage ? (
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setEditor(null)}>
            导入工具目录
          </Button>
        ) : null}
      </Space>
      <QueryErrorAlert error={listQuery.error} message="加载工具目录失败" />
      <SmartTable<McpToolCatalogSummary>
        storageKey="mcp-tool-catalogs"
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        scroll={{ x: 1450 }}
        pagination={false}
        locale={{ emptyText: '暂无工具目录——显式导入后逐行审核' }}
      />
      {detailId ? (
        <CatalogDetailDrawer id={detailId} canManage={canManage} onClose={() => setDetailId(null)} />
      ) : null}
      {editor !== undefined ? (
        <CatalogEditorDrawer catalogId={editor} onClose={() => setEditor(undefined)} onSaved={invalidate} />
      ) : null}
    </Space>
  )
}
