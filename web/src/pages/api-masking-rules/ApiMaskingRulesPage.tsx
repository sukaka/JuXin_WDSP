import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Form,
  Input,
  InputNumber,
  Modal,
  Select,
  Space,
  Switch,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { PlusOutlined } from '@ant-design/icons'
import {
  apiMaskingRulesApi,
  apiSensitiveTypesApi,
  type ApiMaskingAlgorithm,
  type ApiMaskingRule,
  type ApiMaskingRuleBody,
  type ApiMaskingScope,
} from '../../api/apiData'
import { applicationsApi } from '../../api/applications'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import useBatchDelete from '../../hooks/useBatchDelete'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { FILE_SENSITIVE_TYPE_LABELS } from '../../utils/i18nLabels'
import { hasPermission } from '../../utils/permission'
import { API_SENSITIVE_TYPE_META } from '../../utils/stage8'

/** 脱敏作用域（与 server/internal/apidata scope 枚举一致） */
const SCOPE_META: Record<string, { color: string; label: string }> = {
  GLOBAL: { color: 'purple', label: '全局' },
  APPLICATION: { color: 'blue', label: '应用级' },
  ENDPOINT: { color: 'geekblue', label: '接口级' },
}

/** 脱敏算法 */
const ALGORITHM_META: Record<string, { color: string; label: string }> = {
  MASK: { color: 'gold', label: '掩码' },
  HASH: { color: 'volcano', label: '散列' },
  REMOVE: { color: 'red', label: '移除' },
  ENCRYPT: { color: 'geekblue', label: '加密' },
  MAP: { color: 'purple', label: '映射' },
}

interface RuleFormValues {
  name: string
  enabled: boolean
  scope: ApiMaskingScope
  application_id?: string
  endpoint_key?: string
  field_path?: string
  data_type?: string
  algorithm: ApiMaskingAlgorithm
  /** MASK 算法参数（留空取网关默认 3/4） */
  keep_head?: number | null
  keep_tail?: number | null
  key_id?: string
  map_id?: string
  /** 排除对象（identity/role/ip 三键） */
  excl_identity?: string[]
  excl_role?: string[]
  excl_ip?: string[]
}

/** 表单值 → 提交体（创建/编辑同构；可空字段不适用时显式空串，服务端清除为 NULL） */
function buildBody(v: RuleFormValues): ApiMaskingRuleBody {
  const params: Record<string, unknown> = {}
  if (v.algorithm === 'MASK') {
    if (typeof v.keep_head === 'number') params.keep_head = v.keep_head
    if (typeof v.keep_tail === 'number') params.keep_tail = v.keep_tail
  }
  if (v.algorithm === 'ENCRYPT') params.key_id = v.key_id?.trim() ?? ''
  if (v.algorithm === 'MAP') params.map_id = v.map_id?.trim() ?? ''
  const exclusions: ApiMaskingRuleBody['exclusions_json'] = {}
  if (v.excl_identity?.length) exclusions.identity = v.excl_identity
  if (v.excl_role?.length) exclusions.role = v.excl_role
  if (v.excl_ip?.length) exclusions.ip = v.excl_ip
  return {
    name: v.name.trim(),
    enabled: v.enabled,
    scope: v.scope,
    application_id: v.scope === 'APPLICATION' ? (v.application_id ?? '') : '',
    endpoint_key: v.scope === 'ENDPOINT' ? (v.endpoint_key?.trim() ?? '') : '',
    field_path: v.field_path?.trim() ?? '',
    data_type: v.data_type ?? '',
    algorithm: v.algorithm,
    params_json: params,
    exclusions_json: exclusions,
  }
}

/** 脱敏规则（WDSP / 阶段8）：响应侧字段级脱敏规则的作用域、算法与排除对象管理 */
export default function ApiMaskingRulesPage() {
  const { message, modal } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'api_data.manage')

  const [scope, setScope] = useState<string | undefined>()
  const [enabledFilter, setEnabledFilter] = useState<boolean | undefined>()
  const [endpointKey, setEndpointKey] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [editing, setEditing] = useState<ApiMaskingRule | null>(null)
  const [createOpen, setCreateOpen] = useState(false)
  const [detailRecord, setDetailRecord] = useState<ApiMaskingRule | null>(null)
  const [decryptOpen, setDecryptOpen] = useState(false)
  const [plaintext, setPlaintext] = useState<string | null>(null)
  const [form] = Form.useForm<RuleFormValues>()
  const [decryptForm] = Form.useForm<{ ciphertext: string }>()

  const modalOpen = createOpen || editing !== null
  /** 弹窗内当前作用域/算法（联动字段显隐） */
  const formScope = Form.useWatch('scope', form)
  const formAlgorithm = Form.useWatch('algorithm', form)

  const listQuery = useQuery({
    queryKey: [
      'api-masking-rules',
      scope,
      enabledFilter,
      endpointKey,
      page,
      pageSize,
    ],
    queryFn: () =>
      apiMaskingRulesApi.list({
        scope,
        enabled: enabledFilter,
        endpoint_key: endpointKey,
        page,
        page_size: pageSize,
      }),
  })

  /** 应用选项（scope=APPLICATION 时选择目标应用；弹窗打开且需要时才拉取） */
  const appsQuery = useQuery({
    queryKey: ['applications', 'options'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
    enabled: modalOpen && formScope === 'APPLICATION',
  })

  /** 数据类型选项（来自敏感数据类型登记的 data_type 标签，去重） */
  const typesQuery = useQuery({
    queryKey: ['api-sensitive-types', 'options'],
    queryFn: () => apiSensitiveTypesApi.list({ page: 1, page_size: 100 }),
    enabled: modalOpen,
  })
  const dataTypeOptions = Array.from(
    new Set(
      (typesQuery.data?.items ?? []).map((t) => t.data_type).filter(Boolean),
    ),
  ).map((v) => ({
    value: v,
    label:
      API_SENSITIVE_TYPE_META[v]?.label ??
      API_SENSITIVE_TYPE_META[v.toLowerCase()]?.label ??
      FILE_SENSITIVE_TYPE_LABELS[v] ??
      FILE_SENSITIVE_TYPE_LABELS[v.toUpperCase()] ??
      v,
  }))

  const invalidate = () =>
    void qc.invalidateQueries({ queryKey: ['api-masking-rules'] })

  const { rowSelection, batchDeleteButton } = useBatchDelete<ApiMaskingRule>({
    remove: (id) => apiMaskingRulesApi.remove(id),
    invalidateKeys: [['api-masking-rules']],
    entityName: '脱敏规则',
    canDelete: canManage,
  })

  const createMut = useMutation({
    mutationFn: (body: ApiMaskingRuleBody) => apiMaskingRulesApi.create(body),
    onSuccess: () => {
      message.success('已创建')
      setCreateOpen(false)
      invalidate()
    },
    onError: (e: unknown) =>
      message.error(e instanceof ApiError ? e.message : '创建失败'),
  })

  const updateMut = useMutation({
    mutationFn: (vars: { id: string; body: ApiMaskingRuleBody }) =>
      apiMaskingRulesApi.update(vars.id, vars.body),
    onSuccess: () => {
      message.success('已保存')
      setEditing(null)
      invalidate()
    },
    onError: (e: unknown) =>
      message.error(e instanceof ApiError ? e.message : '保存失败'),
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => apiMaskingRulesApi.remove(id),
    onSuccess: (r) => {
      message.success(r.message || '已删除')
      invalidate()
    },
    onError: (e: unknown) =>
      message.error(e instanceof ApiError ? e.message : '删除失败'),
  })

  const decryptMut = useMutation({
    mutationFn: (ciphertext: string) => apiMaskingRulesApi.decrypt(ciphertext),
    onSuccess: (result) => setPlaintext(result.plaintext),
  })

  const openCreate = () => {
    form.resetFields()
    setCreateOpen(true)
  }

  const openDecrypt = () => {
    decryptForm.resetFields()
    decryptMut.reset()
    setPlaintext(null)
    setDecryptOpen(true)
  }

  const closeDecrypt = () => {
    setDecryptOpen(false)
    decryptForm.resetFields()
    decryptMut.reset()
    setPlaintext(null)
  }

  const openEdit = (record: ApiMaskingRule) => {
    setEditing(record)
    form.resetFields()
    const params = (record.params_json ?? {}) as Record<string, unknown>
    const exclusions = record.exclusions_json ?? {}
    form.setFieldsValue({
      name: record.name,
      enabled: record.enabled,
      scope: record.scope,
      application_id: record.application_id ?? undefined,
      endpoint_key: record.endpoint_key ?? undefined,
      field_path: record.field_path,
      data_type: record.data_type ?? undefined,
      algorithm: record.algorithm,
      keep_head:
        typeof params.keep_head === 'number' ? params.keep_head : undefined,
      keep_tail:
        typeof params.keep_tail === 'number' ? params.keep_tail : undefined,
      key_id: typeof params.key_id === 'string' ? params.key_id : undefined,
      map_id: typeof params.map_id === 'string' ? params.map_id : undefined,
      excl_identity: exclusions.identity ?? [],
      excl_role: exclusions.role ?? [],
      excl_ip: exclusions.ip ?? [],
    })
  }

  const toggleEnabled = (record: ApiMaskingRule) => {
    modal.confirm({
      title: record.enabled ? '禁用规则' : '启用规则',
      content: `确定${record.enabled ? '禁用' : '启用'}脱敏规则「${record.name}」吗？${
        record.enabled ? '禁用后该规则不再参与响应脱敏。' : ''
      }变更随配置发布下发网关后生效。`,
      onOk: () =>
        updateMut.mutate({ id: record.id, body: { enabled: !record.enabled } }),
    })
  }

  const confirmDelete = (record: ApiMaskingRule) => {
    modal.confirm({
      title: '删除规则',
      content: `确定删除脱敏规则「${record.name}」吗？删除后不再参与响应脱敏，且不可恢复。`,
      okButtonProps: { danger: true },
      onOk: () => deleteMut.mutate(record.id),
    })
  }

  const columns: ColumnsType<ApiMaskingRule> = [
    { title: '名称', dataIndex: 'name', ellipsis: true },
    {
      title: '状态',
      dataIndex: 'enabled',
      width: 80,
      render: (v: boolean) =>
        v ? <Tag color="green">启用</Tag> : <Tag>禁用</Tag>,
    },
    {
      title: '作用域',
      dataIndex: 'scope',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={SCOPE_META} />,
    },
    {
      title: '应用',
      dataIndex: 'application_id',
      width: 180,
      ellipsis: true,
      render: (v?: string | null) =>
        v ? (
          <Tooltip title={v}>
            <Typography.Text code>{v}</Typography.Text>
          </Tooltip>
        ) : (
          '-'
        ),
    },
    {
      title: '接口',
      dataIndex: 'endpoint_key',
      width: 200,
      ellipsis: true,
      render: (v?: string | null) =>
        v ? (
          <Tooltip title={v}>
            <Typography.Text code>{v}</Typography.Text>
          </Tooltip>
        ) : (
          '-'
        ),
    },
    {
      title: '目标字段',
      dataIndex: 'field_path',
      width: 180,
      ellipsis: true,
      render: (v: string, record) => (
        <Space size={4} wrap>
          {v ? <Typography.Text code>{v}</Typography.Text> : null}
          {record.data_type ? (
            <StatusTag value={record.data_type} map={API_SENSITIVE_TYPE_META} />
          ) : null}
          {!v && !record.data_type ? '-' : null}
        </Space>
      ),
    },
    {
      title: '算法',
      dataIndex: 'algorithm',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={ALGORITHM_META} />,
    },
    {
      title: '创建人',
      dataIndex: 'created_by',
      width: 100,
      render: (v?: string | null) => v || '-',
    },
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
            <Button
              type="link"
              size="small"
              onClick={() => toggleEnabled(record)}
            >
              {record.enabled ? '禁用' : '启用'}
            </Button>
            <Button
              type="link"
              size="small"
              danger
              onClick={() => confirmDelete(record)}
            >
              删除
            </Button>
          </Space>
        ) : null,
    },
  ]

  return (
    <Card
      title="脱敏规则"
      extra={
        canManage ? (
          <Space>
            <Button onClick={openDecrypt}>恢复验证</Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>
              新建规则
            </Button>
          </Space>
        ) : null
      }
    >
      <Typography.Paragraph type="secondary">
        配置响应侧字段级脱敏：按作用域（全局/应用/接口）圈定目标字段或数据类型，选择掩码、散列、移除、加密或映射算法；
        排除对象（身份/角色/IP）命中的请求不脱敏。规则随配置发布下发网关后生效。
      </Typography.Paragraph>
      <QueryErrorAlert error={listQuery.error} />
      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          placeholder="作用域"
          allowClear
          style={{ width: 140 }}
          value={scope}
          options={Object.entries(SCOPE_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => {
            setScope(v)
            setPage(1)
          }}
        />
        <Select
          placeholder="状态"
          allowClear
          style={{ width: 120 }}
          value={enabledFilter}
          options={[
            { value: true, label: '启用' },
            { value: false, label: '禁用' },
          ]}
          onChange={(v) => {
            setEnabledFilter(v)
            setPage(1)
          }}
        />
        <Input.Search
          placeholder="按接口精确过滤"
          allowClear
          style={{ width: 260 }}
          onSearch={(v) => {
            setEndpointKey(v.trim() || undefined)
            setPage(1)
          }}
        />
        {batchDeleteButton}
      </Space>
      <SmartTable<ApiMaskingRule>
        storageKey="api-masking-rules"
        rowKey="id"
        rowSelection={rowSelection}
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        scroll={{ x: 1500 }}
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
        title={editing ? `编辑规则：${editing.name}` : '新建脱敏规则'}
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
        <Form<RuleFormValues>
          form={form}
          layout="vertical"
          initialValues={{ enabled: true, scope: 'GLOBAL', algorithm: 'MASK' }}
          onFinish={(v) => {
            const body = buildBody(v)
            if (!body.field_path && !body.data_type) {
              message.error('字段路径与数据类型至少填写其一')
              return
            }
            if (editing) {
              updateMut.mutate({ id: editing.id, body })
            } else {
              createMut.mutate(body)
            }
          }}
        >
          <Form.Item
            name="name"
            label="规则名称"
            rules={[
              { required: true, message: '请填写规则名称' },
              { max: 128, message: '名称不超过 128 字符' },
            ]}
          >
            <Input placeholder="如：用户接口手机号掩码" />
          </Form.Item>
          <Form.Item name="enabled" label="启用状态" valuePropName="checked">
            <Switch checkedChildren="启用" unCheckedChildren="禁用" />
          </Form.Item>
          <Form.Item
            name="scope"
            label="作用域"
            rules={[{ required: true, message: '请选择作用域' }]}
          >
            <Select
              options={Object.entries(SCOPE_META).map(([value, meta]) => ({
                value,
                label: meta.label,
              }))}
            />
          </Form.Item>
          {formScope === 'APPLICATION' ? (
            <Form.Item
              name="application_id"
              label="目标应用"
              rules={[{ required: true, message: '应用级规则必须选择应用' }]}
            >
              <Select
                showSearch
                optionFilterProp="label"
                placeholder="选择应用"
                loading={appsQuery.isLoading}
                options={(appsQuery.data?.items ?? []).map((a) => ({
                  value: a.id,
                  label: `${a.name}（${a.code}）`,
                }))}
              />
            </Form.Item>
          ) : null}
          {formScope === 'ENDPOINT' ? (
            <Form.Item
              name="endpoint_key"
              label="目标接口"
              rules={[
                { required: true, message: '接口级规则必须填写接口' },
                { max: 560, message: '接口标识不超过 560 字符' },
              ]}
              extra="格式：请求方法 + 空格 + 路径模板，如 GET /v1/users/{id}"
            >
              <Input
                placeholder="GET /v1/users/{id}"
                style={{ fontFamily: 'monospace' }}
              />
            </Form.Item>
          ) : null}
          <Form.Item
            name="field_path"
            label="目标字段路径"
            rules={[{ max: 512, message: '字段路径不超过 512 字符' }]}
            extra="点路径，如 user.phone、users[].phone；与数据类型至少填写其一"
          >
            <Input
              placeholder="user.phone"
              style={{ fontFamily: 'monospace' }}
            />
          </Form.Item>
          <Form.Item
            name="data_type"
            label="目标数据类型（整类脱敏，可选）"
            extra="取值来自敏感数据类型登记的数据类型标签"
          >
            <Select
              allowClear
              showSearch
              optionFilterProp="label"
              placeholder="选择数据类型标签"
              loading={typesQuery.isLoading}
              options={dataTypeOptions}
            />
          </Form.Item>
          <Form.Item
            name="algorithm"
            label="脱敏算法"
            rules={[{ required: true, message: '请选择脱敏算法' }]}
          >
            <Select
              options={Object.entries(ALGORITHM_META).map(([value, meta]) => ({
                value,
                label: meta.label,
              }))}
            />
          </Form.Item>
          {formAlgorithm === 'MASK' ? (
            <Space.Compact block>
              <Form.Item
                name="keep_head"
                label="前保留字符数"
                style={{ width: '50%', marginRight: 8 }}
                extra="默认 3，0–64"
              >
                <InputNumber
                  min={0}
                  max={64}
                  precision={0}
                  style={{ width: '100%' }}
                  placeholder="3"
                />
              </Form.Item>
              <Form.Item
                name="keep_tail"
                label="后保留字符数"
                style={{ width: '50%' }}
                extra="默认 4，0–64；短于前后保留总长度的值整体替换为 ****"
              >
                <InputNumber
                  min={0}
                  max={64}
                  precision={0}
                  style={{ width: '100%' }}
                  placeholder="4"
                />
              </Form.Item>
            </Space.Compact>
          ) : null}
          {formAlgorithm === 'ENCRYPT' ? (
            <Form.Item
              name="key_id"
              label="密钥标识"
              rules={[
                { required: true, message: '请填写密钥标识' },
                {
                  pattern: /^[A-Za-z0-9_-]{1,64}$/,
                  message: '密钥标识须为 1–64 位字母、数字、下划线或连字符',
                },
              ]}
              extra="仅引用已登记的密钥标识，密钥材料由服务端管理"
            >
              <Input
                placeholder="如 key-prod-01"
                maxLength={64}
                autoComplete="off"
              />
            </Form.Item>
          ) : null}
          {formAlgorithm === 'MAP' ? (
            <Form.Item
              name="map_id"
              label="映射表标识"
              rules={[
                { required: true, message: '请填写映射表标识' },
                {
                  pattern: /^[A-Za-z0-9_-]{1,64}$/,
                  message: '映射表标识须为 1–64 位字母、数字、下划线或连字符',
                },
              ]}
            >
              <Input
                placeholder="如 map-prod-01"
                maxLength={64}
                autoComplete="off"
              />
            </Form.Item>
          ) : null}
          <Typography.Paragraph type="secondary" style={{ marginBottom: 8 }}>
            排除对象（可选）：命中的请求不脱敏（身份指纹/角色码精确匹配，IP 支持
            CIDR）。
          </Typography.Paragraph>
          <Form.Item
            name="excl_identity"
            label="身份指纹（回车添加）"
          >
            <Select
              mode="tags"
              open={false}
              tokenSeparators={[',']}
              placeholder="身份指纹精确匹配"
            />
          </Form.Item>
          <Form.Item name="excl_role" label="角色码（回车添加）">
            <Select
              mode="tags"
              open={false}
              tokenSeparators={[',']}
              placeholder="角色码精确匹配"
            />
          </Form.Item>
          <Form.Item name="excl_ip" label="IP / CIDR（回车添加）">
            <Select
              mode="tags"
              open={false}
              tokenSeparators={[',']}
              placeholder="如 10.0.0.8、10.0.0.0/24"
            />
          </Form.Item>
        </Form>
      </Modal>
      <Modal
        title="恢复验证"
        open={decryptOpen}
        onCancel={closeDecrypt}
        onOk={() => decryptForm.submit()}
        okText="验证"
        confirmLoading={decryptMut.isPending}
        width={560}
        destroyOnHidden
      >
        <Typography.Paragraph type="secondary">
          通过服务端接口验证密文可恢复性，页面不执行本地解密。
        </Typography.Paragraph>
        {decryptMut.isError ? (
          <Alert
            type="error"
            showIcon
            message={
              decryptMut.error instanceof ApiError
                ? decryptMut.error.message
                : '恢复验证失败'
            }
            style={{ marginBottom: 16 }}
          />
        ) : null}
        <Form<{ ciphertext: string }>
          form={decryptForm}
          layout="vertical"
          onFinish={(values) => {
            setPlaintext(null)
            decryptMut.mutate(values.ciphertext.trim())
          }}
        >
          <Form.Item
            name="ciphertext"
            label="密文"
            rules={[
              { required: true, message: '请输入待验证密文' },
              { whitespace: true, message: '请输入待验证密文' },
            ]}
          >
            <Input.TextArea
              rows={4}
              placeholder="请输入待验证密文"
              autoComplete="off"
            />
          </Form.Item>
        </Form>
        {plaintext !== null ? (
          <div>
            <Typography.Text strong>明文</Typography.Text>
            <Input.TextArea
              aria-label="明文"
              value={plaintext}
              readOnly
              rows={4}
              style={{ marginTop: 8, fontFamily: 'monospace' }}
            />
          </div>
        ) : null}
      </Modal>
      <RecordDetailDrawer
        open={detailRecord !== null}
        title="脱敏规则详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </Card>
  )
}
