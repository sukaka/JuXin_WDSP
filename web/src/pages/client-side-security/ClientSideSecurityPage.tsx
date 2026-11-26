import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Descriptions,
  Drawer,
  Form,
  Input,
  Modal,
  Popconfirm,
  Select,
  Space,
  Tabs,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import {
  CheckCircleOutlined,
  CodeOutlined,
  DeleteOutlined,
  DownloadOutlined,
  EditOutlined,
  PlusOutlined,
  SafetyCertificateOutlined,
  WarningOutlined,
} from '@ant-design/icons'
import { ApiError } from '../../api/client'
import { applicationsApi } from '../../api/applications'
import {
  CLIENT_SIDE_LIMITS,
  clientSideApi,
  type ClientScriptCreateBody,
  type ClientScriptItem,
  type ClientScriptStatus,
  type ClientScriptType,
  type ClientScriptUpdateBody,
  type ClientSideViolationItem,
  type ClientSideViolationStatus,
} from '../../api/clientSide'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import {
  CLIENT_SCRIPT_STATUS_META,
  CLIENT_SCRIPT_TYPE_META,
  CLIENT_SIDE_ACTION_TAKEN_META,
  CLIENT_SIDE_VIOLATION_STATUS_META,
  CLIENT_SIDE_VIOLATION_TYPE_META,
  getScriptSriComparison,
  validateSriHash,
} from '../../utils/clientSide'

const SCRIPT_STATUS_OPTIONS = Object.entries(CLIENT_SCRIPT_STATUS_META).map(
  ([value, meta]) => ({ value, label: meta.label }),
)

const SCRIPT_TYPE_OPTIONS = Object.entries(CLIENT_SCRIPT_TYPE_META).map(
  ([value, meta]) => ({ value, label: meta.label }),
)

const VIOLATION_TYPE_OPTIONS = Object.entries(
  CLIENT_SIDE_VIOLATION_TYPE_META,
).map(([value, meta]) => ({ value, label: meta.label }))

const VIOLATION_STATUS_OPTIONS = Object.entries(
  CLIENT_SIDE_VIOLATION_STATUS_META,
).map(([value, meta]) => ({ value, label: meta.label }))

interface AppOption {
  value: string
  label: string
}

interface CreateScriptFormValues {
  application_id: string
  script_url: string
  script_type: ClientScriptType
  sri_hash: string
  status: ClientScriptStatus
  justification: string
}

interface EditScriptFormValues {
  sri_hash: string
  status: ClientScriptStatus
  justification: string
}

interface ViolationHandleFormValues {
  status: ClientSideViolationStatus
  note: string
}

/** 新增预授权脚本弹窗（PCI DSS 4.0 6.4.3） */
function CreateScriptModal({
  appOptions,
  defaultAppId,
  onClose,
  onCreated,
}: {
  appOptions: AppOption[]
  defaultAppId?: string
  onClose: () => void
  onCreated: () => void
}) {
  const { message } = AntdApp.useApp()
  const [form] = Form.useForm<CreateScriptFormValues>()
  const statusWatch = Form.useWatch('status', form) ?? 'AUTHORIZED'
  const [submitError, setSubmitError] = useState<string | null>(null)

  const createMut = useMutation({
    mutationFn: (body: ClientScriptCreateBody) =>
      clientSideApi.createScript(body),
    onSuccess: () => {
      message.success('脚本资产已新增；需经配置发布同步到网关节点')
      onCreated()
      onClose()
    },
    onError: (e: unknown) => {
      setSubmitError(e instanceof ApiError ? e.message : '新增失败')
    },
  })

  return (
    <Modal
      title="新增预授权脚本"
      open
      width={620}
      okText="确认新增"
      cancelText="取消"
      confirmLoading={createMut.isPending}
      onCancel={onClose}
      onOk={() => form.submit()}
    >
      {submitError && (
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 14 }}
          title={submitError}
        />
      )}
      <Form<CreateScriptFormValues>
        form={form}
        layout="vertical"
        initialValues={{
          application_id: defaultAppId ?? appOptions[0]?.value ?? '',
          script_url: '',
          script_type: 'EXTERNAL',
          sri_hash: '',
          status: 'AUTHORIZED',
          justification: '',
        }}
        onFinish={(values) => {
          setSubmitError(null)
          createMut.mutate({
            application_id: values.application_id.trim(),
            script_url: values.script_url.trim(),
            script_type: values.script_type,
            sri_hash: (values.sri_hash ?? '').trim(),
            status: values.status,
            justification: (values.justification ?? '').trim(),
          })
        }}
      >
        <Form.Item
          name="application_id"
          label="所属应用"
          rules={[{ required: true, message: '请选择所属应用' }]}
        >
          {appOptions.length > 0 ? (
            <Select
              showSearch
              optionFilterProp="label"
              placeholder="选择应用"
              options={appOptions}
            />
          ) : (
            <Input placeholder="输入应用 ID（UUID）" autoComplete="off" />
          )}
        </Form.Item>

        <Form.Item
          name="script_type"
          label="脚本类型"
          rules={[{ required: true, message: '请选择脚本类型' }]}
        >
          <Select options={SCRIPT_TYPE_OPTIONS} />
        </Form.Item>

        <Form.Item
          name="script_url"
          label="脚本 URL / 内联标识"
          extra="外部脚本填写完整 URL 或站内路径（如 https://cdn.example.com/pay.js）；内联哈希填写页面内联标识"
          rules={[
            { required: true, whitespace: true, message: '请输入脚本地址' },
            {
              max: CLIENT_SIDE_LIMITS.maxScriptUrlLen,
              message: `脚本地址不能超过 ${CLIENT_SIDE_LIMITS.maxScriptUrlLen} 字符`,
            },
          ]}
        >
          <Input
            placeholder="如 https://cdn.example.com/checkout.min.js"
            autoComplete="off"
          />
        </Form.Item>

        <Form.Item
          name="sri_hash"
          label="固定 SRI 完整性哈希（可选）"
          extra="如 sha384-...；设置后网关将比对 HTML 响应中的 integrity 属性，缺失或不匹配将触发篡改告警"
          rules={[
            {
              validator: (_, v?: string) => {
                const err = validateSriHash(v)
                return err ? Promise.reject(new Error(err)) : Promise.resolve()
              },
            },
          ]}
        >
          <Input
            placeholder="sha384-..."
            autoComplete="off"
            style={{ fontFamily: 'monospace' }}
          />
        </Form.Item>

        <Form.Item
          name="status"
          label="审批状态"
          rules={[{ required: true, message: '请选择审批状态' }]}
        >
          <Select options={SCRIPT_STATUS_OPTIONS} />
        </Form.Item>

        <Form.Item
          name="justification"
          label="业务授权依据（PCI DSS 4.0 6.4.3）"
          dependencies={['status']}
          extra={
            statusWatch === 'AUTHORIZED'
              ? '状态为「已授权」时必填：说明该脚本的业务必要性与安全评审依据'
              : '可选：补充脚本用途或封禁理由'
          }
          rules={[
            {
              validator: (_, v?: string) => {
                if (
                  form.getFieldValue('status') === 'AUTHORIZED' &&
                  !(v ?? '').trim()
                ) {
                  return Promise.reject(
                    new Error(
                      'PCI DSS 4.0 6.4.3 要求：设为「已授权」时必须填写业务授权依据',
                    ),
                  )
                }
                return Promise.resolve()
              },
            },
            {
              max: CLIENT_SIDE_LIMITS.maxJustificationLen,
              message: `授权依据不能超过 ${CLIENT_SIDE_LIMITS.maxJustificationLen} 字符`,
            },
          ]}
        >
          <Input.TextArea
            rows={3}
            placeholder="如：支付网关官方 SDK，用于 3DS 鉴权表单，已经安全团队代码审查与 SRI 锁定"
          />
        </Form.Item>
      </Form>
    </Modal>
  )
}

/** 脚本审批 / 编辑抽屉（PCI DSS 4.0 6.4.3） */
function ScriptReviewDrawer({
  script,
  appName,
  onClose,
  onSaved,
}: {
  script: ClientScriptItem
  appName: string
  onClose: () => void
  onSaved: () => void
}) {
  const { message } = AntdApp.useApp()
  const [form] = Form.useForm<EditScriptFormValues>()
  const statusWatch = Form.useWatch('status', form) ?? script.status
  const [submitError, setSubmitError] = useState<string | null>(null)

  const updateMut = useMutation({
    mutationFn: (body: ClientScriptUpdateBody) =>
      clientSideApi.updateScript(script.id, body),
    onSuccess: () => {
      message.success('脚本审批与配置已更新；发布后生效至网关')
      onSaved()
      onClose()
    },
    onError: (e: unknown) => {
      setSubmitError(e instanceof ApiError ? e.message : '更新失败')
    },
  })

  return (
    <Drawer
      title="脚本审批与 SRI 维护（PCI DSS 6.4.3）"
      open
      size="large"
      onClose={onClose}
      extra={
        <Space>
          <Button onClick={onClose}>取消</Button>
          <Button
            type="primary"
            loading={updateMut.isPending}
            onClick={() => form.submit()}
          >
            保存审批
          </Button>
        </Space>
      }
    >
      {submitError && (
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 16 }}
          title={submitError}
        />
      )}

      <Descriptions
        bordered
        size="small"
        column={1}
        style={{ marginBottom: 20 }}
      >
        <Descriptions.Item label="所属应用">{appName}</Descriptions.Item>
        <Descriptions.Item label="脚本地址">
          <Typography.Text code style={{ wordBreak: 'break-all' }}>
            {script.script_url}
          </Typography.Text>
        </Descriptions.Item>
        <Descriptions.Item label="脚本来源">
          {script.script_origin || '-'}
        </Descriptions.Item>
        <Descriptions.Item label="脚本类型">
          <StatusTag
            value={script.script_type}
            map={CLIENT_SCRIPT_TYPE_META}
          />
        </Descriptions.Item>
        <Descriptions.Item label="网关观测 SRI">
          {script.observed_sri ? (
            <Space wrap>
              <Typography.Text code style={{ wordBreak: 'break-all' }}>
                {script.observed_sri}
              </Typography.Text>
              <Button
                size="small"
                type="link"
                style={{ paddingInline: 0 }}
                onClick={() => form.setFieldValue('sri_hash', script.observed_sri)}
              >
                采纳为固定 SRI
              </Button>
            </Space>
          ) : (
            <Typography.Text type="secondary">暂未观测到 SRI</Typography.Text>
          )}
        </Descriptions.Item>
        <Descriptions.Item label="示例页面 / 观测次数">
          {`${script.sample_page_path || '-'}（累计 ${script.observed_count} 次）`}
        </Descriptions.Item>
        {script.approved_by && (
          <Descriptions.Item label="最近审批">
            {`${script.approved_by}${script.approved_at ? ` · ${formatDateTime(script.approved_at)}` : ''}`}
          </Descriptions.Item>
        )}
      </Descriptions>

      <Form<EditScriptFormValues>
        form={form}
        layout="vertical"
        initialValues={{
          status: (script.status as ClientScriptStatus) || 'DISCOVERED',
          sri_hash: script.sri_hash ?? '',
          justification: script.justification ?? '',
        }}
        onFinish={(values) => {
          setSubmitError(null)
          updateMut.mutate({
            status: values.status,
            sri_hash: (values.sri_hash ?? '').trim(),
            justification: (values.justification ?? '').trim(),
          })
        }}
      >
        <Form.Item
          name="status"
          label="审批状态"
          rules={[{ required: true, message: '请选择审批状态' }]}
        >
          <Select options={SCRIPT_STATUS_OPTIONS} />
        </Form.Item>

        <Form.Item
          name="sri_hash"
          label="固定 SRI 完整性哈希"
          extra="锁定预期完整性摘要；网关扫描到不同或缺失 SRI 时将上报篡改告警"
          rules={[
            {
              validator: (_, v?: string) => {
                const err = validateSriHash(v)
                return err ? Promise.reject(new Error(err)) : Promise.resolve()
              },
            },
          ]}
        >
          <Input
            placeholder="sha384-..."
            autoComplete="off"
            style={{ fontFamily: 'monospace' }}
          />
        </Form.Item>

        <Form.Item
          name="justification"
          label="业务授权依据（PCI DSS 4.0 6.4.3）"
          dependencies={['status']}
          extra={
            statusWatch === 'AUTHORIZED'
              ? '设为「已授权」时必填：审计导出将原样归档该业务授权理由'
              : '可记录待核查说明或封禁原因'
          }
          rules={[
            {
              validator: (_, v?: string) => {
                if (
                  form.getFieldValue('status') === 'AUTHORIZED' &&
                  !(v ?? '').trim()
                ) {
                  return Promise.reject(
                    new Error(
                      'PCI DSS 4.0 6.4.3 要求：设为「已授权」时必须填写业务授权依据',
                    ),
                  )
                }
                return Promise.resolve()
              },
            },
            {
              max: CLIENT_SIDE_LIMITS.maxJustificationLen,
              message: `授权依据不能超过 ${CLIENT_SIDE_LIMITS.maxJustificationLen} 字符`,
            },
          ]}
        >
          <Input.TextArea
            rows={4}
            placeholder="说明该脚本为什么必须加载在支付/登录等页面，以及安全验证方式"
          />
        </Form.Item>
      </Form>
    </Drawer>
  )
}

/** 违规告警处置弹窗（PCI DSS 4.0 11.6.1） */
function ViolationHandleModal({
  violation,
  onClose,
  onUpdated,
}: {
  violation: ClientSideViolationItem
  onClose: () => void
  onUpdated: () => void
}) {
  const { message } = AntdApp.useApp()
  const [form] = Form.useForm<ViolationHandleFormValues>()
  const [submitError, setSubmitError] = useState<string | null>(null)

  const handleMut = useMutation({
    mutationFn: (body: ViolationHandleFormValues) =>
      clientSideApi.updateViolationStatus(violation.id, {
        status: body.status,
        note: (body.note ?? '').trim(),
      }),
    onSuccess: () => {
      message.success('违规告警处置状态已更新')
      onUpdated()
      onClose()
    },
    onError: (e: unknown) => {
      setSubmitError(e instanceof ApiError ? e.message : '处置更新失败')
    },
  })

  return (
    <Modal
      title="处置篡改与 CSP 违规告警"
      open
      width={580}
      okText="保存处置"
      cancelText="取消"
      confirmLoading={handleMut.isPending}
      onCancel={onClose}
      onOk={() => form.submit()}
    >
      {submitError && (
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 14 }}
          title={submitError}
        />
      )}

      <Descriptions
        bordered
        size="small"
        column={1}
        style={{ marginBottom: 16 }}
      >
        <Descriptions.Item label="违规类型">
          <StatusTag
            value={violation.violation_type}
            map={CLIENT_SIDE_VIOLATION_TYPE_META}
          />
        </Descriptions.Item>
        <Descriptions.Item label="受影响页面">
          <Typography.Text code>{violation.page_path || '-'}</Typography.Text>
        </Descriptions.Item>
        <Descriptions.Item label="脚本 / 阻断地址">
          <Typography.Text code style={{ wordBreak: 'break-all' }}>
            {violation.script_url || violation.blocked_uri || '-'}
          </Typography.Text>
        </Descriptions.Item>
        {violation.violated_directive && (
          <Descriptions.Item label="违规指令">
            <Typography.Text code>{violation.violated_directive}</Typography.Text>
          </Descriptions.Item>
        )}
        {violation.reason && (
          <Descriptions.Item label="判定说明">{violation.reason}</Descriptions.Item>
        )}
      </Descriptions>

      <Form<ViolationHandleFormValues>
        form={form}
        layout="vertical"
        initialValues={{
          status:
            (violation.status as ClientSideViolationStatus) || 'ACKNOWLEDGED',
          note: violation.note ?? '',
        }}
        onFinish={(values) => {
          setSubmitError(null)
          handleMut.mutate(values)
        }}
      >
        <Form.Item
          name="status"
          label="处置状态"
          rules={[{ required: true, message: '请选择处置状态' }]}
        >
          <Select options={VIOLATION_STATUS_OPTIONS} />
        </Form.Item>
        <Form.Item
          name="note"
          label="处置备注"
          rules={[
            {
              max: CLIENT_SIDE_LIMITS.maxNoteLen,
              message: `处置备注不能超过 ${CLIENT_SIDE_LIMITS.maxNoteLen} 字符`,
            },
          ]}
        >
          <Input.TextArea
            rows={3}
            placeholder="记录排查结论、工单号或后续整改措施"
          />
        </Form.Item>
      </Form>
    </Modal>
  )
}

/**
 * 客户端供应链安全管理页（WDSP Phase 9B / PCI DSS 4.0 6.4.3 & 11.6.1）。
 * 路由：/client-side-security；权限：client_side.read（读/导出）/ client_side.manage（审批/新增/删除/处置）。
 */
export default function ClientSideSecurityPage() {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'client_side.manage')
  const canReadApps = hasPermission(permissions, 'applications.read')

  const [activeTab, setActiveTab] = useState<'scripts' | 'violations'>(
    'scripts',
  )

  // Tab 1 筛选与分页状态
  const [scriptAppId, setScriptAppId] = useState<string | undefined>(undefined)
  const [scriptStatus, setScriptStatus] = useState<string | undefined>(
    undefined,
  )
  const [scriptKeyword, setScriptKeyword] = useState('')
  const [scriptPage, setScriptPage] = useState(1)
  const [scriptPageSize, setScriptPageSize] = useState(20)
  const [createModalOpen, setCreateModalOpen] = useState(false)
  const [reviewingScript, setReviewingScript] =
    useState<ClientScriptItem | null>(null)
  const [exportingCsv, setExportingCsv] = useState(false)

  // Tab 2 筛选与分页状态
  const [violationAppId, setViolationAppId] = useState<string | undefined>(
    undefined,
  )
  const [violationType, setViolationType] = useState<string | undefined>(
    undefined,
  )
  const [violationStatus, setViolationStatus] = useState<string | undefined>(
    undefined,
  )
  const [violationPage, setViolationPage] = useState(1)
  const [violationPageSize, setViolationPageSize] = useState(20)
  const [handlingViolation, setHandlingViolation] =
    useState<ClientSideViolationItem | null>(null)

  const appsQuery = useQuery({
    queryKey: ['applications', 'client-side-options'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 200 }),
    enabled: canReadApps,
  })

  const appOptions = useMemo<AppOption[]>(
    () =>
      (appsQuery.data?.items ?? []).map((a) => ({
        value: a.id,
        label: a.name ? `${a.name} (${a.code})` : a.code,
      })),
    [appsQuery.data?.items],
  )

  const appNameMap = useMemo(() => {
    const map = new Map<string, string>()
    for (const a of appsQuery.data?.items ?? []) {
      map.set(a.id, a.name || a.code)
    }
    return map
  }, [appsQuery.data?.items])

  const resolveAppLabel = (
    appId: string,
    fallbackName?: string,
    fallbackCode?: string,
  ): string => fallbackName || appNameMap.get(appId) || fallbackCode || appId

  const scriptsQuery = useQuery({
    queryKey: [
      'client-side-scripts',
      scriptAppId,
      scriptStatus,
      scriptKeyword.trim(),
      scriptPage,
      scriptPageSize,
    ],
    queryFn: () =>
      clientSideApi.listScripts({
        application_id: scriptAppId,
        status: scriptStatus,
        keyword: scriptKeyword.trim() || undefined,
        page: scriptPage,
        page_size: scriptPageSize,
      }),
  })

  const violationsQuery = useQuery({
    queryKey: [
      'client-side-violations',
      violationAppId,
      violationType,
      violationStatus,
      violationPage,
      violationPageSize,
    ],
    queryFn: () =>
      clientSideApi.listViolations({
        application_id: violationAppId,
        violation_type: violationType,
        status: violationStatus,
        page: violationPage,
        page_size: violationPageSize,
      }),
    enabled: activeTab === 'violations',
  })

  const invalidateScripts = () =>
    void queryClient.invalidateQueries({ queryKey: ['client-side-scripts'] })

  const invalidateViolations = () =>
    void queryClient.invalidateQueries({ queryKey: ['client-side-violations'] })

  const deleteScriptMut = useMutation({
    mutationFn: (id: string) => clientSideApi.deleteScript(id),
    onSuccess: () => {
      message.success('脚本记录已删除')
      invalidateScripts()
    },
    onError: (e: unknown) =>
      message.error(e instanceof ApiError ? e.message : '删除失败'),
  })

  const handleExportCsv = async () => {
    setExportingCsv(true)
    try {
      const { blob, filename } =
        await clientSideApi.downloadComplianceExport(scriptAppId)
      if (typeof URL.createObjectURL === 'function') {
        const objectUrl = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = objectUrl
        a.download = filename
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
        URL.revokeObjectURL(objectUrl)
      }
      message.success('PCI DSS 合规证据 CSV 导出成功')
    } catch (e: unknown) {
      message.error(e instanceof ApiError ? e.message : '导出合规证据失败')
    } finally {
      setExportingCsv(false)
    }
  }

  const scriptColumns: ColumnsType<ClientScriptItem> = [
    {
      title: '脚本地址',
      dataIndex: 'script_url',
      key: 'script_url',
      width: 280,
      render: (_, record) => (
        <Space orientation="vertical" size={2} style={{ maxWidth: 260 }}>
          <Typography.Text
            code
            ellipsis={{ tooltip: record.script_url }}
            style={{ fontSize: 12, maxWidth: 260 }}
          >
            {record.script_url}
          </Typography.Text>
          <Space size={4} wrap>
            <Tag style={{ fontSize: 11, marginInlineEnd: 0 }}>
              {resolveAppLabel(
                record.application_id,
                record.application_name,
                record.application_code,
              )}
            </Tag>
            {record.sample_page_path && (
              <Typography.Text type="secondary" style={{ fontSize: 11 }}>
                {record.sample_page_path}
              </Typography.Text>
            )}
          </Space>
        </Space>
      ),
    },
    {
      title: '脚本来源',
      dataIndex: 'script_origin',
      key: 'script_origin',
      width: 180,
      ellipsis: true,
      render: (v: string) =>
        v ? (
          <Typography.Text
            style={{ fontSize: 12 }}
            ellipsis={{ tooltip: v }}
          >
            {v}
          </Typography.Text>
        ) : (
          '-'
        ),
    },
    {
      title: '类型',
      dataIndex: 'script_type',
      key: 'script_type',
      width: 105,
      render: (v: string) => (
        <StatusTag value={v} map={CLIENT_SCRIPT_TYPE_META} />
      ),
    },
    {
      title: 'SRI 完整性比对',
      key: 'sri_compare',
      width: 220,
      render: (_, record) => {
        const state = getScriptSriComparison(record)
        return (
          <Space orientation="vertical" size={2}>
            {state === 'MISMATCH' && (
              <Tag color="error" icon={<WarningOutlined />}>
                SRI 不匹配（疑似篡改）
              </Tag>
            )}
            {state === 'MISSING_OBSERVED' && (
              <Tag color="warning" icon={<WarningOutlined />}>
                观测缺失 SRI
              </Tag>
            )}
            {state === 'MATCHED' && (
              <Tag color="success" icon={<CheckCircleOutlined />}>
                SRI 一致
              </Tag>
            )}
            {state === 'PENDING_OBSERVATION' && (
              <Tag color="blue">已固定（待观测）</Tag>
            )}
            {state === 'UNPINNED' && <Tag>未固定 SRI</Tag>}
            {record.sri_hash && (
              <Tooltip title={`固定 SRI: ${record.sri_hash}`}>
                <Typography.Text
                  type="secondary"
                  style={{ fontSize: 11, fontFamily: 'monospace' }}
                  ellipsis
                >
                  固定: {record.sri_hash.slice(0, 22)}...
                </Typography.Text>
              </Tooltip>
            )}
            {record.observed_sri && record.observed_sri !== record.sri_hash && (
              <Tooltip title={`观测 SRI: ${record.observed_sri}`}>
                <Typography.Text
                  type={state === 'MISMATCH' ? 'danger' : 'secondary'}
                  style={{ fontSize: 11, fontFamily: 'monospace' }}
                  ellipsis
                >
                  观测: {record.observed_sri.slice(0, 22)}...
                </Typography.Text>
              </Tooltip>
            )}
          </Space>
        )
      },
    },
    {
      title: '审批状态',
      dataIndex: 'status',
      key: 'status',
      width: 115,
      render: (v: string) => (
        <StatusTag value={v} map={CLIENT_SCRIPT_STATUS_META} />
      ),
    },
    {
      title: '业务授权依据',
      dataIndex: 'justification',
      key: 'justification',
      width: 220,
      render: (v: string, record) => (
        <Space orientation="vertical" size={2} style={{ maxWidth: 205 }}>
          {v ? (
            <Typography.Text
              style={{ fontSize: 12 }}
              ellipsis={{ tooltip: v }}
            >
              {v}
            </Typography.Text>
          ) : (
            <Typography.Text type="secondary">-</Typography.Text>
          )}
          {record.approved_by && (
            <Typography.Text type="secondary" style={{ fontSize: 11 }}>
              审批人：{record.approved_by}
            </Typography.Text>
          )}
        </Space>
      ),
    },
    {
      title: '观测次数',
      dataIndex: 'observed_count',
      key: 'observed_count',
      width: 95,
      align: 'right',
    },
    {
      title: '最近观测时间',
      dataIndex: 'last_seen_at',
      key: 'last_seen_at',
      width: 170,
      render: (v?: string | null) => (v ? formatDateTime(v) : '-'),
    },
    ...(canManage
      ? [
          {
            title: '操作',
            key: 'actions',
            width: 155,
            fixed: 'right' as const,
            render: (_: unknown, record: ClientScriptItem) => (
              <Space size={0}>
                <Button
                  type="link"
                  size="small"
                  icon={<EditOutlined />}
                  onClick={() => setReviewingScript(record)}
                >
                  审批/编辑
                </Button>
                <Popconfirm
                  title="确定删除该脚本记录吗？"
                  description="删除后需经配置发布同步到网关节点。"
                  okText="确认删除"
                  okButtonProps={{ danger: true }}
                  onConfirm={() => deleteScriptMut.mutate(record.id)}
                >
                  <Button
                    type="link"
                    size="small"
                    danger
                    icon={<DeleteOutlined />}
                  >
                    删除
                  </Button>
                </Popconfirm>
              </Space>
            ),
          },
        ]
      : []),
  ]

  const violationColumns: ColumnsType<ClientSideViolationItem> = [
    {
      title: '发生时间',
      dataIndex: 'occurred_at',
      key: 'occurred_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '违规类型',
      dataIndex: 'violation_type',
      key: 'violation_type',
      width: 155,
      render: (v: string) => (
        <StatusTag value={v} map={CLIENT_SIDE_VIOLATION_TYPE_META} />
      ),
    },
    {
      title: '受影响页面',
      dataIndex: 'page_path',
      key: 'page_path',
      width: 185,
      render: (v: string, record) => (
        <Space orientation="vertical" size={2}>
          <Typography.Text
            code
            style={{ fontSize: 12, maxWidth: 170 }}
            ellipsis={{ tooltip: v }}
          >
            {v || '-'}
          </Typography.Text>
          <Tag style={{ fontSize: 11, marginInlineEnd: 0 }}>
            {resolveAppLabel(
              record.application_id,
              record.application_name,
              record.application_code,
            )}
          </Tag>
        </Space>
      ),
    },
    {
      title: '脚本 / 阻断地址',
      key: 'target',
      width: 250,
      render: (_, record) => {
        const primary = record.script_url || record.blocked_uri
        const secondary =
          record.script_url &&
          record.blocked_uri &&
          record.blocked_uri !== record.script_url
            ? record.blocked_uri
            : ''
        return (
          <Space orientation="vertical" size={2} style={{ maxWidth: 235 }}>
            {primary ? (
              <Typography.Text
                code
                style={{ fontSize: 12, maxWidth: 235 }}
                ellipsis={{ tooltip: primary }}
              >
                {primary}
              </Typography.Text>
            ) : (
              '-'
            )}
            {secondary && (
              <Typography.Text
                type="secondary"
                style={{ fontSize: 11, maxWidth: 235 }}
                ellipsis={{ tooltip: secondary }}
              >
                阻断: {secondary}
              </Typography.Text>
            )}
          </Space>
        )
      },
    },
    {
      title: '违规指令',
      dataIndex: 'violated_directive',
      key: 'violated_directive',
      width: 135,
      render: (v: string) =>
        v ? (
          <Typography.Text code style={{ fontSize: 12 }}>
            {v}
          </Typography.Text>
        ) : (
          '-'
        ),
    },
    {
      title: '网关动作',
      dataIndex: 'action_taken',
      key: 'action_taken',
      width: 125,
      render: (v: string) => (
        <StatusTag value={v} map={CLIENT_SIDE_ACTION_TAKEN_META} />
      ),
    },
    {
      title: '处置状态',
      dataIndex: 'status',
      key: 'status',
      width: 150,
      render: (v: string, record) => (
        <Space orientation="vertical" size={2}>
          <StatusTag value={v} map={CLIENT_SIDE_VIOLATION_STATUS_META} />
          {record.note && (
            <Typography.Text
              type="secondary"
              style={{ fontSize: 11, maxWidth: 135 }}
              ellipsis={{ tooltip: record.note }}
            >
              {record.note}
            </Typography.Text>
          )}
        </Space>
      ),
    },
    ...(canManage
      ? [
          {
            title: '操作',
            key: 'actions',
            width: 95,
            fixed: 'right' as const,
            render: (_: unknown, record: ClientSideViolationItem) => (
              <Button
                type="link"
                size="small"
                onClick={() => setHandlingViolation(record)}
              >
                处置
              </Button>
            ),
          },
        ]
      : []),
  ]

  return (
    <Card
      title={
        <Space>
          <CodeOutlined />
          <span>客户端供应链安全（PCI DSS 4.0）</span>
        </Space>
      }
      extra={
        <Tag color="blue" icon={<SafetyCertificateOutlined />}>
          PCI DSS 6.4.3 &amp; 11.6.1
        </Tag>
      }
    >
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        title="覆盖 PCI DSS 4.0 要求 6.4.3（支付/敏感页面加载脚本清点、完整性校验与书面业务授权）及 11.6.1（篡改、未授权外链脚本与 CSP 违规持续监测告警），支持一键导出合规审计 CSV 证据。"
      />

      <Tabs
        activeKey={activeTab}
        onChange={(k) => setActiveTab(k as 'scripts' | 'violations')}
        items={[
          {
            key: 'scripts',
            label: '脚本资产清单（PCI DSS 6.4.3）',
            children: (
              <>
                <Space
                  style={{
                    marginBottom: 16,
                    display: 'flex',
                    justifyContent: 'space-between',
                  }}
                  wrap
                >
                  <Space wrap>
                    {appOptions.length > 0 && (
                      <Select
                        allowClear
                        showSearch
                        optionFilterProp="label"
                        placeholder="按应用筛选"
                        value={scriptAppId}
                        onChange={(v) => {
                          setScriptAppId(v)
                          setScriptPage(1)
                        }}
                        options={appOptions}
                        style={{ width: 200 }}
                      />
                    )}
                    <Select
                      allowClear
                      placeholder="按审批状态筛选"
                      value={scriptStatus}
                      onChange={(v) => {
                        setScriptStatus(v)
                        setScriptPage(1)
                      }}
                      options={SCRIPT_STATUS_OPTIONS}
                      style={{ width: 150 }}
                    />
                    <Input.Search
                      allowClear
                      placeholder="搜索脚本地址、来源或授权依据"
                      value={scriptKeyword}
                      onChange={(e) => {
                        setScriptKeyword(e.target.value)
                        setScriptPage(1)
                      }}
                      style={{ width: 260 }}
                    />
                  </Space>
                  <Space wrap>
                    <Button
                      icon={<DownloadOutlined />}
                      loading={exportingCsv}
                      onClick={() => void handleExportCsv()}
                    >
                      导出 PCI DSS 合规证据 (CSV)
                    </Button>
                    {canManage && (
                      <Button
                        type="primary"
                        icon={<PlusOutlined />}
                        onClick={() => setCreateModalOpen(true)}
                      >
                        新增预授权脚本
                      </Button>
                    )}
                  </Space>
                </Space>

                {scriptsQuery.isError ? (
                  <QueryErrorAlert
                    error={scriptsQuery.error}
                    message="加载脚本资产清单失败"
                  />
                ) : (
                  <SmartTable<ClientScriptItem>
                    rowKey="id"
                    storageKey="client-side-scripts"
                    loading={scriptsQuery.isLoading}
                    columns={scriptColumns}
                    dataSource={scriptsQuery.data?.items ?? []}
                    scroll={{ x: 1480 }}
                    onRefresh={() => scriptsQuery.refetch()}
                    pagination={{
                      current: scriptPage,
                      pageSize: scriptPageSize,
                      total: scriptsQuery.data?.total ?? 0,
                      showSizeChanger: true,
                      showTotal: (t) => `共 ${t} 条脚本资产`,
                      onChange: (p, ps) => {
                        setScriptPage(p)
                        setScriptPageSize(ps)
                      },
                    }}
                  />
                )}
              </>
            ),
          },
          {
            key: 'violations',
            label: '篡改与 CSP 违规告警（PCI DSS 11.6.1）',
            children: (
              <>
                <Space
                  style={{
                    marginBottom: 16,
                    display: 'flex',
                    justifyContent: 'space-between',
                  }}
                  wrap
                >
                  <Space wrap>
                    {appOptions.length > 0 && (
                      <Select
                        allowClear
                        showSearch
                        optionFilterProp="label"
                        placeholder="按应用筛选"
                        value={violationAppId}
                        onChange={(v) => {
                          setViolationAppId(v)
                          setViolationPage(1)
                        }}
                        options={appOptions}
                        style={{ width: 200 }}
                      />
                    )}
                    <Select
                      allowClear
                      placeholder="按违规类型筛选"
                      value={violationType}
                      onChange={(v) => {
                        setViolationType(v)
                        setViolationPage(1)
                      }}
                      options={VIOLATION_TYPE_OPTIONS}
                      style={{ width: 185 }}
                    />
                    <Select
                      allowClear
                      placeholder="按处置状态筛选"
                      value={violationStatus}
                      onChange={(v) => {
                        setViolationStatus(v)
                        setViolationPage(1)
                      }}
                      options={VIOLATION_STATUS_OPTIONS}
                      style={{ width: 150 }}
                    />
                  </Space>
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                    共 {violationsQuery.data?.total ?? 0} 条违规告警
                  </Typography.Text>
                </Space>

                {violationsQuery.isError ? (
                  <QueryErrorAlert
                    error={violationsQuery.error}
                    message="加载篡改与 CSP 违规告警失败"
                  />
                ) : (
                  <SmartTable<ClientSideViolationItem>
                    rowKey="id"
                    storageKey="client-side-violations"
                    loading={violationsQuery.isLoading}
                    columns={violationColumns}
                    dataSource={violationsQuery.data?.items ?? []}
                    scroll={{ x: 1320 }}
                    onRefresh={() => violationsQuery.refetch()}
                    pagination={{
                      current: violationPage,
                      pageSize: violationPageSize,
                      total: violationsQuery.data?.total ?? 0,
                      showSizeChanger: true,
                      showTotal: (t) => `共 ${t} 条违规告警`,
                      onChange: (p, ps) => {
                        setViolationPage(p)
                        setViolationPageSize(ps)
                      },
                    }}
                  />
                )}
              </>
            ),
          },
        ]}
      />

      {createModalOpen && (
        <CreateScriptModal
          appOptions={appOptions}
          defaultAppId={scriptAppId}
          onClose={() => setCreateModalOpen(false)}
          onCreated={invalidateScripts}
        />
      )}

      {reviewingScript && (
        <ScriptReviewDrawer
          script={reviewingScript}
          appName={resolveAppLabel(
            reviewingScript.application_id,
            reviewingScript.application_name,
            reviewingScript.application_code,
          )}
          onClose={() => setReviewingScript(null)}
          onSaved={invalidateScripts}
        />
      )}

      {handlingViolation && (
        <ViolationHandleModal
          violation={handlingViolation}
          onClose={() => setHandlingViolation(null)}
          onUpdated={invalidateViolations}
        />
      )}
    </Card>
  )
}
