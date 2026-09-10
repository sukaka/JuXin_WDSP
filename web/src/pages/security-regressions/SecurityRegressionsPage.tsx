import { useMemo, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Descriptions,
  Form,
  Input,
  InputNumber,
  Modal,
  Select,
  Space,
  Tooltip,
  Typography,
} from 'antd'
import {
  CheckCircleOutlined,
  EditOutlined,
  ReloadOutlined,
  WarningOutlined,
} from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'
import { ApiError } from '../../api/client'
import { securityRegressionApi } from '../../api/securityRegression'
import type {
  RegressionGateMode,
  RegressionLevel,
  RegressionVerificationStatus,
  SecurityRegressionPolicyPutBody,
  SecurityRegressionRun,
} from '../../api/securityRegression'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import { useAuthStore } from '../../stores/auth'
import { hasPermission } from '../../utils/permission'
import { formatDateTime } from '../../utils/format'
import { truncateHash } from '../../utils/stage3'
import {
  REG_DECLARED_META,
  REG_GATE_MODE_META,
  REG_LEVEL_META,
  REG_VERIFY_META,
  previewPublishUsability,
} from '../../utils/securityRegression'

const LEVEL_OPTIONS = Object.entries(REG_LEVEL_META).map(([value, m]) => ({
  value,
  label: `${m.label}（${value}）`,
}))
const VERIFY_OPTIONS = Object.entries(REG_VERIFY_META).map(([value, m]) => ({
  value,
  label: `${m.label}（${value}）`,
}))
const GATE_MODE_OPTIONS = Object.entries(REG_GATE_MODE_META).map(([value, m]) => ({
  value,
  label: m.label,
}))

/** 证据新鲜度：登记时长 + 相对门禁有效期是否超期（未知有效期按不过期处理；登记时间缺失/非法时按未知处理，不展示 NaN） */
function freshnessOf(run: SecurityRegressionRun, maxAgeSeconds: number | undefined, nowMs: number) {
  const createdMs = Date.parse(run.created_at)
  if (!Number.isFinite(createdMs)) {
    return { ageSeconds: undefined, expired: false }
  }
  const ageSeconds = Math.max(0, Math.floor((nowMs - createdMs) / 1000))
  const expired = !!maxAgeSeconds && maxAgeSeconds > 0 && ageSeconds > maxAgeSeconds
  return { ageSeconds, expired }
}

function formatAge(ageSeconds: number): string {
  if (ageSeconds < 3600) return `${Math.floor(ageSeconds / 60)} 分钟前`
  if (ageSeconds < 86400) return `${Math.floor(ageSeconds / 3600)} 小时前`
  return `${Math.floor(ageSeconds / 86400)} 天前`
}

interface PolicyFormValues {
  mode: RegressionGateMode
  required_level: RegressionLevel
  required_corpus_id?: string
  evidence_max_age_seconds: number
  reason: string
}

export default function SecurityRegressionsPage() {
  const { message } = AntdApp.useApp()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canPolicy = hasPermission(permissions, 'security_regression.policy')

  // 筛选/分页上下文挂 URL 查询串：进入详情/用例页后返回列表不丢状态，可分享可刷新
  const [searchParams, setSearchParams] = useSearchParams()
  const parsePage = (raw: string | null, def: number) => {
    const n = Number(raw)
    return Number.isInteger(n) && n >= 1 ? n : def
  }
  const filters = {
    fingerprint: searchParams.get('fingerprint') || undefined,
    level: (searchParams.get('level') || undefined) as RegressionLevel | undefined,
    status: (searchParams.get('status') || undefined) as
      | RegressionVerificationStatus
      | undefined,
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

  const listQuery = useQuery({
    queryKey: ['security-regressions', filters, page, pageSize],
    queryFn: () =>
      securityRegressionApi.list({ ...filters, page, page_size: pageSize }),
  })
  // 门禁策略（read 权限即可读）：既用于顶部模式展示，也用于列表可用性预判
  const policyQuery = useQuery({
    queryKey: ['security-regression-policy'],
    queryFn: securityRegressionApi.getPolicy,
  })
  const policy = policyQuery.data

  const [policyOpen, setPolicyOpen] = useState(false)
  const [policyForm] = Form.useForm<PolicyFormValues>()

  const openPolicyModal = () => {
    if (!policy) return
    policyForm.setFieldsValue({
      mode: policy.mode,
      required_level: policy.required_level,
      required_corpus_id: policy.required_corpus_id || undefined,
      evidence_max_age_seconds: policy.evidence_max_age_seconds,
      reason: undefined,
    })
    setPolicyOpen(true)
  }

  const policyMutation = useMutation({
    mutationFn: (values: PolicyFormValues) => {
      const body: SecurityRegressionPolicyPutBody = {
        mode: values.mode,
        required_level: values.required_level,
        required_corpus_id: values.required_corpus_id ?? '',
        evidence_max_age_seconds: values.evidence_max_age_seconds,
        expected_version: policy?.version ?? 0,
        reason: values.reason,
      }
      return securityRegressionApi.updatePolicy(body)
    },
    onSuccess: () => {
      message.success('回归发布门禁策略已保存（已记录操作审计）')
      setPolicyOpen(false)
      void queryClient.invalidateQueries({ queryKey: ['security-regression-policy'] })
    },
    onError: (e) => {
      if (e instanceof ApiError && e.status === 409) {
        message.error('策略已被他人修改，请刷新后重试')
        void queryClient.invalidateQueries({ queryKey: ['security-regression-policy'] })
        return
      }
      if (e instanceof ApiError && Array.isArray(e.details)) {
        // 后端字段级校验错误回显（details = [{field, message}]；字段名与表单一一对应，
        // 未知字段不入表单，避免伪造路径）
        const known: (keyof PolicyFormValues)[] = [
          'mode',
          'required_level',
          'required_corpus_id',
          'evidence_max_age_seconds',
          'reason',
        ]
        const fields = (e.details as { field?: string; message?: string }[])
          .filter((d): d is { field: keyof PolicyFormValues; message?: string } =>
            known.includes(d.field as keyof PolicyFormValues),
          )
          .map((d) => ({ name: d.field, errors: [d.message || '校验未通过'] }))
        if (fields.length > 0) {
          policyForm.setFields(fields)
          return
        }
      }
      message.error(e instanceof ApiError ? e.message : '保存失败')
    },
  })

  const nowMs = Date.now()
  const columns: ColumnsType<SecurityRegressionRun> = useMemo(
    () => [
      {
        title: '运行 ID',
        dataIndex: 'run_id',
        width: 180,
        render: (v: string, record) => (
          <Link to={`/security-regressions/${record.id}`}>{v}</Link>
        ),
      },
      {
        title: '级别',
        dataIndex: 'level',
        width: 90,
        render: (v: string) => <StatusTag value={v} map={REG_LEVEL_META} />,
      },
      {
        title: '服务端核验',
        dataIndex: 'verification_status',
        width: 100,
        render: (v: string, record) => (
          <Space size={4}>
            <StatusTag value={v} map={REG_VERIFY_META} />
            {record.verification_reasons.length > 0 && (
              <Tooltip title={record.verification_reasons.join('；')}>
                <WarningOutlined style={{ color: '#faad14' }} aria-label="核验理由" />
              </Tooltip>
            )}
          </Space>
        ),
      },
      {
        title: '声明状态（不采信）',
        dataIndex: 'declared_status',
        width: 120,
        render: (v: string) => <StatusTag value={v} map={REG_DECLARED_META} />,
      },
      {
        title: '计划/实际/缺失',
        key: 'counts',
        width: 130,
        render: (_, record) => {
          const missing = Math.max(0, record.counts.planned - record.counts.executed)
          return (
            <Typography.Text type={missing > 0 ? 'danger' : undefined}>
              {record.counts.planned} / {record.counts.executed} / {missing}
            </Typography.Text>
          )
        },
      },
      {
        title: '候选配置指纹',
        dataIndex: 'config_fingerprint',
        width: 130,
        render: (v: string) => (
          <Typography.Text code copyable={{ text: v }}>
            {truncateHash(v)}
          </Typography.Text>
        ),
      },
      {
        title: '构建/计划指纹',
        key: 'build_plan',
        width: 150,
        render: (_, record) => (
          <Space direction="vertical" size={0}>
            <Typography.Text code>{truncateHash(record.build_digest)}</Typography.Text>
            <Typography.Text code>{truncateHash(record.plan_sha256)}</Typography.Text>
          </Space>
        ),
      },
      {
        title: '数据新鲜度',
        key: 'freshness',
        width: 130,
        render: (_, record) => {
          const { ageSeconds, expired } = freshnessOf(
            record,
            policy?.evidence_max_age_seconds,
            nowMs,
          )
          return (
            <Space size={4}>
              <Typography.Text type={expired ? 'danger' : 'secondary'}>
                {ageSeconds === undefined ? '-' : formatAge(ageSeconds)}
              </Typography.Text>
              {expired && <StatusTag value="EXPIRED" map={{ EXPIRED: { color: 'red', label: '已超期' } }} />}
            </Space>
          )
        },
      },
      {
        title: '可用于当前发布（预判）',
        key: 'usable',
        width: 150,
        render: (_, record) => {
          const { usable, reasons } = previewPublishUsability(record, policy, nowMs)
          if (usable) {
            return (
              <Tooltip title="证据本身满足当前门禁策略；发布时仍以发布器门禁对实际候选指纹的终判为准">
                <Typography.Text type="success">
                  <CheckCircleOutlined /> 可用
                </Typography.Text>
              </Tooltip>
            )
          }
          return (
            <Tooltip title={reasons.join('；')}>
              <Typography.Text type="danger">
                <WarningOutlined /> 不可用（{reasons.length} 项原因）
              </Typography.Text>
            </Tooltip>
          )
        },
      },
      {
        title: '登记时间',
        dataIndex: 'created_at',
        width: 170,
        render: (v: string) => formatDateTime(v),
      },
    ],
    [policy, nowMs],
  )

  return (
    <Space direction="vertical" size={16} style={{ display: 'flex' }}>
      <Card
        title="回归发布门禁策略"
        extra={
          canPolicy && (
            <Button
              icon={<EditOutlined />}
              onClick={openPolicyModal}
              disabled={!policy}
            >
              修改门禁策略
            </Button>
          )
        }
      >
        {policyQuery.isError ? (
          <QueryErrorAlert error={policyQuery.error} />
        ) : !policy ? (
          <Typography.Text type="secondary">加载中…</Typography.Text>
        ) : (
          <Space direction="vertical" size={8} style={{ display: 'flex' }}>
            <Descriptions column={{ xs: 1, sm: 2, md: 4 }} size="small">
              <Descriptions.Item label="门禁模式">
                <StatusTag value={policy.mode} map={REG_GATE_MODE_META} />
              </Descriptions.Item>
              <Descriptions.Item label="要求级别">
                <StatusTag value={policy.required_level} map={REG_LEVEL_META} />
              </Descriptions.Item>
              <Descriptions.Item label="要求语料">
                {policy.required_corpus_id || '不约束'}
              </Descriptions.Item>
              <Descriptions.Item label="证据有效期">
                {Math.floor(policy.evidence_max_age_seconds / 86400)} 天
              </Descriptions.Item>
            </Descriptions>
            {policy.mode === 'OFF' && (
              <Alert
                type="warning"
                showIcon
                message="回归门禁未强制（OFF）：发布不检查回归证据，规则/模型变更可在无回归证据下发布"
              />
            )}
            {policy.mode === 'OBSERVE' && (
              <Alert
                type="info"
                showIcon
                message="观察模式（OBSERVE）：发布时计算并记录门禁结论，但不阻断不合规发布"
              />
            )}
            {policy.mode === 'ENFORCE' && (
              <Alert
                type="success"
                showIcon
                message="强制模式（ENFORCE）：缺少绑定当前候选指纹且核验通过的回归证据时，发布将被拒绝"
              />
            )}
          </Space>
        )}
      </Card>

      <Card
        title="安全回归运行"
        extra={
          <Button icon={<ReloadOutlined />} onClick={() => void listQuery.refetch()}>
            刷新
          </Button>
        }
      >
        <Space wrap style={{ marginBottom: 16 }}>
          <Input.Search
            allowClear
            placeholder="候选配置指纹（cfgfpv1:…）"
            style={{ width: 280 }}
            defaultValue={filters.fingerprint}
            onSearch={(v) =>
              updateListQuery({ fingerprint: v || undefined, page: undefined })
            }
          />
          <Select
            allowClear
            placeholder="运行级别"
            style={{ width: 160 }}
            options={LEVEL_OPTIONS}
            value={filters.level}
            onChange={(v) => updateListQuery({ level: v, page: undefined })}
          />
          <Select
            allowClear
            placeholder="服务端核验状态"
            style={{ width: 170 }}
            options={VERIFY_OPTIONS}
            value={filters.status}
            onChange={(v) => updateListQuery({ status: v, page: undefined })}
          />
        </Space>
        {listQuery.isError ? (
          <QueryErrorAlert error={listQuery.error} />
        ) : (
          <SmartTable<SecurityRegressionRun>
            storageKey="security-regressions"
            rowKey="id"
            loading={listQuery.isLoading}
            columns={columns}
            dataSource={listQuery.data?.items}
            onRow={(record) => ({
              onDoubleClick: () => navigate(`/security-regressions/${record.id}`),
              style: { cursor: 'pointer' },
            })}
            pagination={{
              current: page,
              pageSize,
              total: listQuery.data?.total ?? 0,
              showTotal: (t) => `共 ${t} 条`,
              showSizeChanger: true,
              pageSizeOptions: [10, 20, 50, 100],
              onChange: (p, ps) =>
                updateListQuery({
                  page: String(p),
                  page_size: ps === pageSize ? undefined : String(ps),
                }),
            }}
          />
        )}
      </Card>

      <Modal
        title="修改回归发布门禁策略"
        open={policyOpen}
        confirmLoading={policyMutation.isPending}
        okText="保存"
        okButtonProps={{ danger: true }}
        onOk={() => policyForm.submit()}
        onCancel={() => setPolicyOpen(false)}
        destroyOnHidden
      >
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 16 }}
          message="高风险操作：启用或降级门禁都会记录操作审计；ENFORCE 下缺失/过期/不完整证据将拒绝新发布"
        />
        <Form
          form={policyForm}
          layout="vertical"
          onFinish={(values) => policyMutation.mutate(values)}
        >
          <Form.Item name="mode" label="门禁模式" rules={[{ required: true, message: '请选择门禁模式' }]}>
            <Select options={GATE_MODE_OPTIONS} />
          </Form.Item>
          <Form.Item
            name="required_level"
            label="要求运行级别"
            rules={[{ required: true, message: '请选择要求级别' }]}
            extra="低于该级别的回归证据不能支撑发布（SMOKE 不支撑 FULL/RELEASE 发布）"
          >
            <Select options={LEVEL_OPTIONS} />
          </Form.Item>
          <Form.Item
            name="required_corpus_id"
            label="要求语料 ID（留空 = 不约束）"
          >
            <Input allowClear placeholder="语料标识，如 corpus-2026q3" />
          </Form.Item>
          <Form.Item
            name="evidence_max_age_seconds"
            label="证据有效期（秒，86400~2592000）"
            rules={[{ required: true, message: '请填写证据有效期' }]}
            extra="默认 604800 秒（7 天）；相关内容变化立即失效，不等待到期"
          >
            <InputNumber min={86400} max={2592000} step={86400} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item
            name="reason"
            label="变更理由（进操作审计）"
            rules={[{ required: true, whitespace: true, message: '请填写变更理由' }]}
          >
            <Input.TextArea rows={2} maxLength={500} showCount placeholder="如：开启发布级强制门禁（P1-04 上线）" />
          </Form.Item>
        </Form>
      </Modal>
    </Space>
  )
}
