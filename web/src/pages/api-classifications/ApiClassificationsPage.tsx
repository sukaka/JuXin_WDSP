import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Button,
  Card,
  Drawer,
  Form,
  Input,
  Select,
  Space,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { MinusCircleOutlined, PlusOutlined } from '@ant-design/icons'
import { apiEndpointsApi } from '../../api/apiAssets'
import {
  apiClassificationsApi,
  type ApiClassificationItem,
} from '../../api/apiSecurity'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'
import { useAuthStore } from '../../stores/auth'
import {
  ASSET_VALUE_LEVEL_META,
  CLASSIFICATION_ACCESS_LABELS,
  CLASSIFICATION_ACTION_LABELS,
  CLASSIFICATION_DATA_LEVEL_LABELS,
  CLASSIFICATION_DIRECTION_LABELS,
  CLASSIFICATION_DOMAIN_LABELS,
  CLASSIFICATION_LIFECYCLE_LABELS,
  CLASSIFICATION_PURPOSE_LABELS,
  ENVIRONMENT_LABELS,
  FILE_SENSITIVE_TYPE_LABELS,
} from '../../utils/i18nLabels'
import { hasPermission } from '../../utils/permission'
import {
  API_AUTH_TYPE_META,
  API_CLASSIFICATION_SOURCE_META,
  API_PROTOCOL_META,
  API_SENSITIVE_TYPE_META,
  apiClassificationSourceLabel,
  apiExposureLabel,
  getApiFindingTypeMeta,
} from '../../utils/stage8'
import './api-classifications.css'

interface CreateFormValues {
  dimension: string
  value: string
  description?: string
}

interface EndpointClassificationFormValues {
  dimensions?: { dimension: string; value: string }[]
}

/** 维度名中文映射（系统内置维度为英文编码，自定义维度已是中文则原样显示） */
const DIMENSION_LABELS: Record<string, string> = {
  PURPOSE: '用途',
  TECHNICAL_PROTOCOL: '技术协议',
  INTERACTION_MODE: '交互模式',
  ACCESS: '访问类型',
  ACTION: '操作动作',
  DATA_TYPE: '数据类型',
  DATA_LEVEL: '数据级别',
  DATA_SENSITIVITY: '数据敏感等级',
  EXPOSURE: '暴露范围',
  OPERATION: '操作类型',
  LIFECYCLE: '生命周期',
  DIRECTION: '调用方向',
  AUTH_TYPE: '认证方式',
  IDENTITY_REQUIREMENT: '身份要求',
  ENV: '环境',
  BU: '业务单元',
  BUSINESS_DOMAIN: '业务域',
  BUSINESS_FLOW_STAGE: '业务流程阶段',
  BUSINESS_OBJECT: '业务对象',
  COMPLIANCE_SCOPE: '合规范围',
  CRITICALITY: '重要级别',
  RISK_LABEL: '风险标签',
  OWNER_TEAM: '负责团队',
  DATA_CROSS_BORDER: '数据跨境',
}

const INTERACTION_MODE_LABELS: Record<string, string> = {
  REQUEST_RESPONSE: '请求响应',
  RPC: '远程调用',
  EVENT_CALLBACK: '事件回调',
  FILE_TRANSFER: '文件传输',
  SERVER_PUSH: '服务端推送',
  BIDIRECTIONAL_STREAM: '双向流',
}

const DATA_SENSITIVITY_LABELS: Record<string, string> = {
  HIGH: '高',
  MEDIUM: '中',
  LOW: '低',
  UNKNOWN: '未知',
}

const IDENTITY_REQUIREMENT_LABELS: Record<string, string> = {
  AUTH_REQUIRED: '需要认证（观测）',
  AUTH_OPTIONAL: '可选认证（观测）',
  ANONYMOUS_ALLOWED: '允许匿名（观测）',
  ANONYMOUS_REJECTED: '匿名被拒（观测）',
  AUTHENTICATED_OBSERVED: '仅观测到认证成功',
}

const BUSINESS_FLOW_STAGE_LABELS: Record<string, string> = {
  START: '开始',
  INTERMEDIATE: '中间',
  TERMINAL: '终点',
  START_AND_TERMINAL: '起止一体',
  MULTI_STAGE: '多阶段',
}

const RISK_LABEL_LABELS: Record<string, string> = {
  SHADOW: '影子API',
  ZOMBIE: '僵尸API',
  DEPRECATED: '已下线API',
  BOLA: '对象级越权',
  BFLA: '功能级越权',
  SCHEMA_DEVIATION: '模型偏离',
  SENSITIVE_LEAK: '敏感数据泄露',
  MASS_ASSIGNMENT: '批量赋值',
  BEHAVIOR_ANOMALY: '行为异常',
  MULTI_RISK: '多重风险',
}

const BUSINESS_OBJECT_LABELS: Record<string, string> = {
  MULTI_OBJECT: '多重业务对象',
}

const AUTH_TYPE_EXTRA_LABELS: Record<string, string> = {
  NONE: '无认证',
  ANONYMOUS: '匿名',
  JWT: 'JWT 令牌',
  BEARER: 'Bearer 令牌',
  BASIC: 'Basic 认证',
  OAUTH: 'OAuth 认证',
  OAUTH2: 'OAuth 2.0',
  MTLS: '双向 TLS',
  SESSION: '会话认证',
  API_KEY: 'API Key',
  COOKIE_SESSION: 'Cookie 会话',
  BEARER_OR_BASIC: '令牌/基本认证',
}

const DATA_CROSS_BORDER_LABELS: Record<string, string> = {
  YES: '涉及出境',
  NO: '未涉及出境',
  TRUE: '涉及出境',
  FALSE: '未涉及出境',
  CROSS_BORDER: '跨境传输',
  DOMESTIC: '境内传输',
  OUTBOUND: '出境',
  INBOUND: '入境',
  UNKNOWN: '未知',
}

/** 分类取值中文展示：内置词表翻译已知枚举，未知值原样展示 */
function classificationValueLabel(dimension: string, value: string): string {
  const normalizedDimension = dimension.trim().toUpperCase()
  if (normalizedDimension === 'EXPOSURE') {
    return apiExposureLabel(value)
  }
  const trimmed = value.trim()
  const normalizedValue = trimmed.toUpperCase()
  const lowerValue = trimmed.toLowerCase()
  if (normalizedDimension === 'TECHNICAL_PROTOCOL') {
    return API_PROTOCOL_META[normalizedValue]?.label ?? value
  }
  if (normalizedDimension === 'INTERACTION_MODE') {
    return INTERACTION_MODE_LABELS[normalizedValue] ?? value
  }
  if (normalizedDimension === 'DATA_SENSITIVITY') {
    return DATA_SENSITIVITY_LABELS[normalizedValue] ?? value
  }
  if (normalizedDimension === 'IDENTITY_REQUIREMENT') {
    return IDENTITY_REQUIREMENT_LABELS[normalizedValue] ?? value
  }
  if (normalizedDimension === 'BUSINESS_FLOW_STAGE') {
    return BUSINESS_FLOW_STAGE_LABELS[normalizedValue] ?? value
  }
  if (normalizedDimension === 'RISK_LABEL') {
    return RISK_LABEL_LABELS[normalizedValue] ?? getApiFindingTypeMeta(normalizedValue).label
  }
  if (normalizedDimension === 'BUSINESS_OBJECT') {
    return BUSINESS_OBJECT_LABELS[normalizedValue] ?? value
  }
  if (normalizedDimension === 'PURPOSE') {
    return CLASSIFICATION_PURPOSE_LABELS[normalizedValue] ?? value
  }
  if (normalizedDimension === 'ACCESS') {
    return CLASSIFICATION_ACCESS_LABELS[normalizedValue] ?? value
  }
  if (normalizedDimension === 'ACTION' || normalizedDimension === 'OPERATION') {
    return CLASSIFICATION_ACTION_LABELS[normalizedValue] ?? value
  }
  if (normalizedDimension === 'BUSINESS_DOMAIN') {
    return CLASSIFICATION_DOMAIN_LABELS[normalizedValue] ?? value
  }
  if (normalizedDimension === 'DATA_LEVEL') {
    return CLASSIFICATION_DATA_LEVEL_LABELS[normalizedValue] ?? value
  }
  if (normalizedDimension === 'LIFECYCLE') {
    return CLASSIFICATION_LIFECYCLE_LABELS[normalizedValue] ?? value
  }
  if (normalizedDimension === 'DIRECTION') {
    return CLASSIFICATION_DIRECTION_LABELS[normalizedValue] ?? value
  }
  if (normalizedDimension === 'AUTH_TYPE') {
    return (
      API_AUTH_TYPE_META[lowerValue]?.label ??
      API_AUTH_TYPE_META[normalizedValue]?.label ??
      AUTH_TYPE_EXTRA_LABELS[normalizedValue] ??
      value
    )
  }
  if (normalizedDimension === 'DATA_TYPE') {
    return (
      FILE_SENSITIVE_TYPE_LABELS[trimmed] ??
      FILE_SENSITIVE_TYPE_LABELS[normalizedValue] ??
      API_SENSITIVE_TYPE_META[lowerValue]?.label ??
      value
    )
  }
  if (normalizedDimension === 'ENV') {
    return ENVIRONMENT_LABELS[lowerValue] ?? value
  }
  if (normalizedDimension === 'CRITICALITY') {
    return ASSET_VALUE_LEVEL_META[normalizedValue]?.label ?? DATA_SENSITIVITY_LABELS[normalizedValue] ?? value
  }
  if (normalizedDimension === 'DATA_CROSS_BORDER') {
    return DATA_CROSS_BORDER_LABELS[normalizedValue] ?? value
  }
  return value
}

/** 分类来源中文展示：内置目录仍显示内置；自定义/接口分类优先按 source 词表翻译 */
function classificationSourceLabel(record: ApiClassificationItem): string {
  if (record.is_builtin) return '内置'
  const source = record.source?.trim()
  return source ? apiClassificationSourceLabel(source) : '自定义'
}

const PURPOSE_DESCRIPTION_COMPAT: Record<
  string,
  { legacy: string; label: string }
> = {
  ADMIN: {
    legacy: '后台管理、配置与运维操作接口（启发式命中 /admin /manage）',
    label: '后台管理、配置与运维操作接口',
  },
  AUTH: {
    legacy:
      '登录、登出、令牌签发/刷新、验证码等认证会话接口（启发式命中 /login /signin /auth /token /captcha）',
    label: '登录、登出、令牌签发/刷新、验证码等认证会话接口',
  },
  TRADE: {
    legacy: '支付、订单、交易、账务等资金交易接口（启发式命中 /pay /order /trade /billing）',
    label: '支付、订单、交易、账务等资金交易接口',
  },
  FILE: {
    legacy:
      '文件上传、下载、导入导出等文件传输接口（启发式命中 /upload /file /download /export）',
    label: '文件上传、下载、导入导出等文件传输接口',
  },
  USER_MGMT: {
    legacy:
      '用户资料、账户与密保管理等用户生命周期接口（启发式命中 /user /account /profile）',
    label: '用户资料、账户与密保管理等用户生命周期接口',
  },
  QUERY: {
    legacy: '搜索、查询、列表等只读检索接口（启发式命中 /search /query /list）',
    label: '搜索、查询、列表等只读检索接口',
  },
  GENERAL: {
    legacy: '未命中具体类别的一般业务接口（启发式兜底分类）',
    label: '未命中具体类别的一般业务接口',
  },
  AI_INTELLIGENCE: {
    legacy: '模型调用、智能分析、AI 辅助运营接口',
    label: '模型调用、智能分析与智能辅助运营接口',
  },
  DEVELOPER_PLATFORM: {
    legacy: '开放 API、应用凭证、SDK、沙箱与调用配额接口',
    label: '开放接口、应用凭证、开发工具包、沙箱与调用配额接口',
  },
  EXTERNAL_INTEGRATION: {
    legacy: 'Webhook、回调、第三方开放平台对接接口',
    label: '事件推送、回调、第三方开放平台对接接口',
  },
  PRODUCT_CATALOG: {
    legacy: '商品、服务、SKU、类目与价格管理接口',
    label: '商品、服务、规格库存、类目与价格管理接口',
  },
  PUBLIC: {
    legacy: '面向公网开放的接口（启发式命中 /public /openapi /webhook /callback）',
    label: '面向公网开放的接口',
  },
}

function classificationDescriptionLabel(record: ApiClassificationItem): string {
  const description = record.description || '-'
  if (
    !record.is_builtin ||
    record.dimension.trim().toUpperCase() !== 'PURPOSE'
  ) {
    return description
  }
  const compat = PURPOSE_DESCRIPTION_COMPAT[record.code?.trim().toUpperCase() ?? '']
  return compat && description.trim() === compat.legacy ? compat.label : description
}

/** 详情抽屉使用中文键名，避免通用明细直接暴露英文枚举/字段名 */
function classificationDetailRecord(
  record: ApiClassificationItem,
): Record<string, unknown> {
  return {
    维度: DIMENSION_LABELS[record.dimension] ?? record.dimension,
    分类名称: classificationValueLabel(record.dimension, record.value),
    分类说明: classificationDescriptionLabel(record),
    来源: classificationSourceLabel(record),
    内置: record.is_builtin ? '是' : '否',
    创建时间: record.created_at,
  }
}

/** 用途分类（WDSP / 阶段8）：维护分类体系，并为接口设置维度键值对分类 */
export default function ApiClassificationsPage() {
  const { message } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'api_classification.manage')

  const [createOpen, setCreateOpen] = useState(false)
  const [detailRecord, setDetailRecord] =
    useState<ApiClassificationItem | null>(null)
  const [endpointId, setEndpointId] = useState<string | undefined>()
  const [keyword, setKeyword] = useState('')
  const [sourceFilter, setSourceFilter] = useState<
    'ALL' | 'BUILTIN' | 'CUSTOM'
  >('ALL')
  const [createForm] = Form.useForm<CreateFormValues>()
  const [endpointForm] = Form.useForm<EndpointClassificationFormValues>()

  const listQuery = useQuery({
    queryKey: ['api-classifications'],
    queryFn: () => apiClassificationsApi.list(),
  })

  /** 接口选择器数据源（接口分类按接口设置） */
  const endpointsQuery = useQuery({
    queryKey: ['api-endpoints', 'options'],
    queryFn: () => apiEndpointsApi.list({ page: 1, page_size: 100 }),
  })

  const createMut = useMutation({
    mutationFn: (body: CreateFormValues) => apiClassificationsApi.create(body),
    onSuccess: () => {
      message.success('分类已创建')
      setCreateOpen(false)
      createForm.resetFields()
      void qc.invalidateQueries({ queryKey: ['api-classifications'] })
    },
    onError: (e: unknown) =>
      message.error(e instanceof ApiError ? e.message : '创建失败'),
  })

  const setEndpointMut = useMutation({
    mutationFn: (dimensions: { dimension: string; value: string }[]) =>
      apiClassificationsApi.setEndpointClassification(
        endpointId as string,
        dimensions,
      ),
    onSuccess: () => {
      message.success('接口分类已保存')
    },
    onError: (e: unknown) =>
      message.error(e instanceof ApiError ? e.message : '保存失败'),
  })

  const handleSaveEndpoint = (v: EndpointClassificationFormValues) => {
    if (!endpointId) {
      message.warning('请先选择接口')
      return
    }
    const dimensions = (v.dimensions ?? [])
      .map((d) => ({
        dimension: d.dimension?.trim() ?? '',
        value: d.value?.trim() ?? '',
      }))
      .filter((d) => d.dimension && d.value)
    setEndpointMut.mutate(dimensions)
  }

  const records = listQuery.data ?? []
  const showDimension = records.some(
    (record) => record.dimension.trim().toUpperCase() !== 'PURPOSE',
  )
  const normalizedKeyword = keyword.trim().toLowerCase()
  const filteredRecords = records.filter((record) => {
    if (
      sourceFilter === 'BUILTIN' && !record.is_builtin ||
      sourceFilter === 'CUSTOM' && record.is_builtin
    ) {
      return false
    }
    if (!normalizedKeyword) return true
    return [
      classificationValueLabel(record.dimension, record.value),
      classificationDescriptionLabel(record),
      DIMENSION_LABELS[record.dimension] ?? record.dimension,
    ].some((text) => text.toLowerCase().includes(normalizedKeyword))
  })

  const columns: ColumnsType<ApiClassificationItem> = [
    ...(showDimension
      ? [
          {
            title: '维度',
            dataIndex: 'dimension',
            width: 160,
            render: (v: string) => DIMENSION_LABELS[v] ?? v,
          },
        ]
      : []),
    {
      title: '分类名称',
      dataIndex: 'value',
      width: 200,
      render: (v: string, record) => classificationValueLabel(record.dimension, v),
    },
    {
      title: '分类说明',
      dataIndex: 'description',
      ellipsis: true,
      render: (_: unknown, record) => {
        const description = classificationDescriptionLabel(record)
        return description === '-' ? (
          '-'
        ) : (
          <Tooltip title={description} placement="topLeft">
            <span className="api-classification-description">{description}</span>
          </Tooltip>
        )
      },
    },
    {
      title: '来源',
      dataIndex: 'is_builtin',
      width: 110,
      render: (_: unknown, record) => {
        const meta = record.is_builtin
          ? { color: 'blue', label: '内置' }
          : (API_CLASSIFICATION_SOURCE_META[
              record.source?.trim().toUpperCase() ?? ''
            ] ?? { color: 'purple', label: '自定义' })
        return <Tag color={meta.color}>{meta.label}</Tag>
      },
    },
    {
      title: '操作',
      key: 'action',
      width: 80,
      render: (_: unknown, record) => (
        <Button
          type="link"
          size="small"
          className="api-classification-action"
          onClick={() => setDetailRecord(record)}
        >
          查看
        </Button>
      ),
    },
  ]

  return (
    <Card
      className="api-classifications-page"
      title="用途分类"
      extra={
        canManage ? (
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => setCreateOpen(true)}
          >
            新增分类
          </Button>
        ) : undefined
      }
    >
      <Typography.Paragraph type="secondary" className="api-classifications-intro">
        按业务用途对接口进行分类，用于分类统计和防护策略匹配。
      </Typography.Paragraph>
      <div className="api-classifications-filters">
        <Input.Search
          aria-label="搜索分类"
          placeholder="搜索分类名称或说明"
          allowClear
          className="api-classifications-search"
          value={keyword}
          onChange={(event) => setKeyword(event.target.value)}
        />
        <Select
          aria-label="来源筛选"
          className="api-classifications-source-filter"
          value={sourceFilter}
          options={[
            { value: 'ALL', label: '全部来源' },
            { value: 'BUILTIN', label: '内置' },
            { value: 'CUSTOM', label: '自定义' },
          ]}
          onChange={setSourceFilter}
        />
      </div>
      <QueryErrorAlert error={listQuery.error ?? endpointsQuery.error} />
      <SmartTable<ApiClassificationItem>
        storageKey="api-classifications"
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={filteredRecords}
        scroll={{ x: showDimension ? 960 : 760 }}
        hideRefresh
        onRow={(record) => ({
          onDoubleClick: () => setDetailRecord(record),
          style: { cursor: 'pointer' },
        })}
        pagination={{
          pageSize: 20,
          showSizeChanger: true,
          showTotal: (t) => `共 ${t} 条`,
        }}
      />

      <Card size="small" title="接口分类设置" style={{ marginTop: 16 }}>
        <Form<EndpointClassificationFormValues>
          form={endpointForm}
          layout="vertical"
          onFinish={handleSaveEndpoint}
        >
          <Form.Item label="目标接口" required>
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
              onChange={(v) => setEndpointId(v)}
            />
          </Form.Item>
          <Form.List name="dimensions">
            {(fields, { add, remove }) => (
              <>
                {fields.map((field) => (
                  <Space
                    key={field.key}
                    style={{ display: 'flex', marginBottom: 8 }}
                    align="baseline"
                  >
                    <Form.Item
                      name={[field.name, 'dimension']}
                      rules={[{ required: true, message: '请输入维度' }]}
                    >
                      <Input
                        placeholder="维度，如 业务域"
                        style={{ width: 240 }}
                        autoComplete="off"
                      />
                    </Form.Item>
                    <Form.Item
                      name={[field.name, 'value']}
                      rules={[{ required: true, message: '请输入分类名称' }]}
                    >
                      <Input
                        placeholder="分类名称，如 财务"
                        style={{ width: 240 }}
                        autoComplete="off"
                      />
                    </Form.Item>
                    {canManage ? (
                      <Tooltip title="删除此分类维度">
                        <Button
                          type="text"
                          danger
                          icon={<MinusCircleOutlined />}
                          aria-label="删除此分类维度"
                          onClick={() => remove(field.name)}
                        />
                      </Tooltip>
                    ) : null}
                  </Space>
                ))}
                {canManage ? (
                  <Button
                    block
                    type="dashed"
                    icon={<PlusOutlined />}
                    onClick={() => add()}
                  >
                    添加维度
                  </Button>
                ) : null}
              </>
            )}
          </Form.List>
          {canManage ? (
            <Button
              type="primary"
              style={{ marginTop: 16 }}
              loading={setEndpointMut.isPending}
              onClick={() => endpointForm.submit()}
            >
              保存
            </Button>
          ) : null}
        </Form>
      </Card>

      <Drawer
        title="新增分类"
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        width={480}
        destroyOnHidden
        footer={
          <Space style={{ display: 'flex', justifyContent: 'flex-end' }}>
            <Button onClick={() => setCreateOpen(false)}>取消</Button>
            <Button
              type="primary"
              loading={createMut.isPending}
              onClick={() => createForm.submit()}
            >
              创建
            </Button>
          </Space>
        }
      >
        <Form<CreateFormValues>
          form={createForm}
          layout="vertical"
          onFinish={(v) => createMut.mutate(v)}
        >
          <Form.Item
            name="dimension"
            label="维度"
            rules={[{ required: true, message: '请输入维度' }]}
          >
            <Input placeholder="如 业务域" autoComplete="off" />
          </Form.Item>
          <Form.Item
            name="value"
            label="分类名称"
            rules={[{ required: true, message: '请输入分类名称' }]}
          >
            <Input placeholder="如 财务" autoComplete="off" />
          </Form.Item>
          <Form.Item name="description" label="分类说明（可选）">
            <Input.TextArea rows={3} placeholder="该分类的业务含义" />
          </Form.Item>
        </Form>
      </Drawer>

      <RecordDetailDrawer
        open={detailRecord !== null}
        title="分类详情"
        record={detailRecord ? classificationDetailRecord(detailRecord) : null}
        onClose={() => setDetailRecord(null)}
      />
    </Card>
  )
}
