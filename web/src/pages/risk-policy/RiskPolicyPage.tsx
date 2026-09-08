import { useEffect } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  AutoComplete,
  Button,
  Card,
  Col,
  Divider,
  Form,
  InputNumber,
  Row,
  Select,
  Space,
  Spin,
  Switch,
  Tooltip,
  Typography,
} from 'antd'
import { MinusCircleOutlined, PlusOutlined } from '@ant-design/icons'
import { ApiError } from '../../api/client'
import { riskPolicyApi } from '../../api/riskPolicy'
import type { RiskPolicyBody } from '../../api/riskPolicy'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import { useAuthStore } from '../../stores/auth'
import { hasPermission } from '../../utils/permission'
import { formatDateTime } from '../../utils/format'

/** 常用信号类型下拉建议（键为大写蛇形 signal_type，允许自定义其他键） */
const SIGNAL_KEY_OPTIONS = [
  { value: 'RECON', label: 'RECON（侦察）' },
  { value: 'SENSITIVE_PATH_PROBE', label: 'SENSITIVE_PATH_PROBE（敏感路径探测）' },
  { value: 'AUTH_FAIL_PROBE', label: 'AUTH_FAIL_PROBE（认证探测）' },
  { value: 'WAF', label: 'WAF（WAF 攻击命中）' },
  { value: 'API_SCHEMA', label: 'API_SCHEMA（Schema 偏离）' },
  { value: 'API_PARSER', label: 'API_PARSER（解析异常）' },
  { value: 'HEADLESS', label: 'HEADLESS（无头浏览器）' },
  { value: 'AUTHENTICATION', label: 'AUTHENTICATION（认证失败）' },
]

const MODE_OPTIONS = [
  { value: 'OBSERVE', label: '观察（只记录不处置）' },
  { value: 'PROTECT', label: '防护（达阈限速/阻断）' },
]

interface ScoreEntry {
  key?: string
  value?: number
}

interface PolicyFormValues {
  enabled: boolean
  mode: string
  block_threshold: number
  rate_limit_threshold: number
  rate_limit_rps: number
  signal_window_seconds: number
  risk_levels: { medium: number; high: number; critical: number }
  score_entries?: ScoreEntry[]
}

export default function RiskPolicyPage() {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canEdit = hasPermission(permissions, 'risk_policy.edit')
  const [form] = Form.useForm<PolicyFormValues>()
  const mode = Form.useWatch('mode', form)

  const policyQuery = useQuery({
    queryKey: ['risk-policy'],
    queryFn: () => riskPolicyApi.get(),
  })
  const policy = policyQuery.data

  // GET 回填（含保存后重新拉取的新 version）；scores map 展开为键值对行
  useEffect(() => {
    if (!policy) return
    form.setFieldsValue({
      enabled: policy.enabled,
      mode: policy.mode,
      block_threshold: policy.block_threshold,
      rate_limit_threshold: policy.rate_limit_threshold,
      rate_limit_rps: policy.rate_limit_rps,
      signal_window_seconds: policy.signal_window_seconds,
      risk_levels: { ...policy.risk_levels },
      score_entries: Object.entries(policy.scores).map(([key, value]) => ({ key, value })),
    })
  }, [policy, form])

  /** 提交前检测信号分值表重复 signal_type：折叠回 map 时后者会静默覆盖前者，须拦截并定位到重复行 */
  const onFinish = (values: PolicyFormValues) => {
    const indexByKey = new Map<string, number[]>()
    ;(values.score_entries ?? []).forEach((entry, idx) => {
      if (!entry.key) return
      indexByKey.set(entry.key, [...(indexByKey.get(entry.key) ?? []), idx])
    })
    const duplicated = [...indexByKey.entries()].filter(([, idxs]) => idxs.length > 1)
    if (duplicated.length > 0) {
      form.setFields(
        duplicated.flatMap(([key, idxs]) =>
          idxs.map((idx) => ({
            name: ['score_entries', idx, 'key'] as (string | number)[],
            errors: [`信号类型「${key}」重复，请合并或删除重复行`],
          })),
        ) as Parameters<typeof form.setFields>[0],
      )
      message.error(`信号分值表存在重复信号类型：${duplicated.map(([key]) => key).join('、')}`)
      return
    }
    saveMutation.mutate(values)
  }

  const saveMutation = useMutation({
    mutationFn: (values: PolicyFormValues) => {
      // 键值对行折叠回 scores map（空键行忽略；重复键已在提交前拦截，见 onFinish）
      const scores: Record<string, number> = {}
      for (const entry of values.score_entries ?? []) {
        if (entry.key && entry.value !== undefined && entry.value !== null) {
          scores[entry.key] = entry.value
        }
      }
      const body: RiskPolicyBody = {
        scope: policy?.scope ?? 'GLOBAL',
        enabled: values.enabled ?? false,
        mode: values.mode ?? 'OBSERVE',
        version: policy?.version ?? 0,
        block_threshold: values.block_threshold,
        rate_limit_threshold: values.rate_limit_threshold,
        rate_limit_rps: values.rate_limit_rps,
        signal_window_seconds: values.signal_window_seconds,
        scores,
        risk_levels: values.risk_levels,
      }
      return riskPolicyApi.update(body)
    },
    onSuccess: () => {
      message.success('风险策略已保存')
      void queryClient.invalidateQueries({ queryKey: ['risk-policy'] })
    },
    onError: (e) => {
      if (e instanceof ApiError && e.status === 409) {
        message.error('策略已被他人修改，请刷新后重试')
        return
      }
      if (e instanceof ApiError && Array.isArray(e.details)) {
        // 后端字段级校验错误（ValidationError.details = [{field, message}]），回显到对应表单项；
        // scores.X 按信号键定位到对应键值对行，未匹配到的仅在提示中展示
        const details = e.details as { field?: string; message?: string }[]
        const entries = (form.getFieldValue('score_entries') ?? []) as ScoreEntry[]
        const fields: { name: string | (string | number)[]; errors: string[] }[] = []
        const unmapped: string[] = []
        for (const d of details) {
          if (!d.field) continue
          const errMsg = d.message ?? '取值不合法'
          if (d.field.startsWith('scores.')) {
            const key = d.field.slice('scores.'.length)
            const idx = entries.findIndex((entry) => entry.key === key)
            if (idx >= 0) {
              fields.push({ name: ['score_entries', idx, 'value'], errors: [errMsg] })
            } else {
              unmapped.push(`${d.field}: ${errMsg}`)
            }
          } else {
            fields.push({ name: d.field.includes('.') ? d.field.split('.') : d.field, errors: [errMsg] })
          }
        }
        if (fields.length > 0) {
          form.setFields(fields as Parameters<typeof form.setFields>[0])
        }
        message.error(
          unmapped.length > 0
            ? `${e.message}（${unmapped.join('；')}）`
            : e.message || '保存失败，请检查输入',
        )
        return
      }
      message.error(e instanceof ApiError ? e.message : '保存失败')
    },
  })

  return (
    <Card
      title="风险策略"
      extra={
        canEdit && (
          <Button
            type="primary"
            loading={saveMutation.isPending}
            disabled={!policy}
            onClick={() => form.submit()}
          >
            保存策略
          </Button>
        )
      }
    >
      {policyQuery.isLoading ? (
        <div style={{ padding: '64px 0', textAlign: 'center' }}>
          <Spin />
        </div>
      ) : policyQuery.isError ? (
        <QueryErrorAlert error={policyQuery.error} message="加载风险策略失败" />
      ) : (
        <>
          <Alert
            type="info"
            showIcon
            style={{ maxWidth: 1080, marginBottom: 16 }}
            message="风险分为身份级跨请求累计（24h 滑窗）：达限速阈值（rate_limit_threshold）限速、达阻断阈值（block_threshold）阻断；OBSERVE 模式只记录不处置。"
          />
          <Form<PolicyFormValues>
            form={form}
            layout="vertical"
            disabled={!canEdit}
            onFinish={onFinish}
            style={{ maxWidth: 1080 }}
          >
            <Divider titlePlacement="start" plain>
              基本设置
            </Divider>
            <Row gutter={[16, 0]}>
              <Col xs={24} sm={12} md={8}>
                <Form.Item name="enabled" label="启用风险策略" valuePropName="checked">
                  <Switch checkedChildren="启用" unCheckedChildren="停用" />
                </Form.Item>
              </Col>
              <Col xs={24} sm={12} md={8}>
                <Form.Item
                  name="mode"
                  label="防护模式"
                  extra={
                    mode === 'PROTECT' ? (
                      <Typography.Text type="warning">将对达阈身份实断</Typography.Text>
                    ) : undefined
                  }
                >
                  <Select options={MODE_OPTIONS} />
                </Form.Item>
              </Col>
            </Row>

            <Divider titlePlacement="start" plain>
              处置阈值
            </Divider>
            <Row gutter={[16, 0]}>
              <Col xs={24} sm={12} md={8}>
                <Form.Item
                  name="block_threshold"
                  label="阻断阈值（1-100）"
                  rules={[{ required: true, message: '请输入阻断阈值' }]}
                >
                  <InputNumber min={1} max={100} precision={0} style={{ width: '100%' }} />
                </Form.Item>
              </Col>
              <Col xs={24} sm={12} md={8}>
                <Form.Item
                  name="rate_limit_threshold"
                  label="限速阈值（1-100）"
                  dependencies={['block_threshold']}
                  rules={[
                    { required: true, message: '请输入限速阈值' },
                    ({ getFieldValue }) => ({
                      validator(_, value: number | undefined) {
                        const block = getFieldValue('block_threshold') as number | undefined
                        if (value === undefined || value === null || block === undefined || block === null) {
                          return Promise.resolve()
                        }
                        if (value >= block) {
                          return Promise.reject(new Error('限速阈值必须小于阻断阈值'))
                        }
                        return Promise.resolve()
                      },
                    }),
                  ]}
                >
                  <InputNumber min={1} max={100} precision={0} style={{ width: '100%' }} />
                </Form.Item>
              </Col>
              <Col xs={24} sm={12} md={8}>
                <Form.Item
                  name="rate_limit_rps"
                  label="限速速率（次/秒）"
                  rules={[{ required: true, message: '请输入限速速率' }]}
                >
                  <InputNumber min={1} max={100000} precision={0} style={{ width: '100%' }} />
                </Form.Item>
              </Col>
              <Col xs={24} sm={12} md={8}>
                <Form.Item
                  name="signal_window_seconds"
                  label="统计窗口（秒）"
                  extra="身份风险分累计滑窗，默认 86400（24h）"
                  rules={[{ required: true, message: '请输入统计窗口' }]}
                >
                  <InputNumber min={60} max={604800} precision={0} style={{ width: '100%' }} />
                </Form.Item>
              </Col>
            </Row>

            <Divider titlePlacement="start" plain>
              风险等级划分（起始分，1-100）
            </Divider>
            <Row gutter={[16, 0]}>
              <Col xs={24} sm={12} md={8}>
                <Form.Item
                  name={['risk_levels', 'medium']}
                  label="中风险下限（MEDIUM）"
                  rules={[{ required: true, message: '请输入中风险下限' }]}
                >
                  <InputNumber min={1} max={100} precision={0} style={{ width: '100%' }} />
                </Form.Item>
              </Col>
              <Col xs={24} sm={12} md={8}>
                <Form.Item
                  name={['risk_levels', 'high']}
                  label="高风险下限（HIGH）"
                  rules={[{ required: true, message: '请输入高风险下限' }]}
                >
                  <InputNumber min={1} max={100} precision={0} style={{ width: '100%' }} />
                </Form.Item>
              </Col>
              <Col xs={24} sm={12} md={8}>
                <Form.Item
                  name={['risk_levels', 'critical']}
                  label="严重风险下限（CRITICAL）"
                  rules={[{ required: true, message: '请输入严重风险下限' }]}
                >
                  <InputNumber min={1} max={100} precision={0} style={{ width: '100%' }} />
                </Form.Item>
              </Col>
            </Row>

            <Divider titlePlacement="start" plain>
              信号分值（各信号命中加分，0-100；键为大写蛇形 signal_type）
            </Divider>
            <Form.List name="score_entries">
              {(fields, { add, remove }) => (
                <>
                  {fields.map((field) => (
                    <Space key={field.key} style={{ display: 'flex', marginBottom: 8 }} align="baseline" wrap>
                      <Form.Item
                        name={[field.name, 'key']}
                        style={{ marginBottom: 0 }}
                        rules={[
                          { required: true, message: '请输入信号类型' },
                          { pattern: /^[A-Z][A-Z0-9_]*$/, message: '大写蛇形命名，如 RECON' },
                        ]}
                      >
                        <AutoComplete
                          options={SIGNAL_KEY_OPTIONS}
                          placeholder="信号类型，如 RECON"
                          style={{ width: 320 }}
                        />
                      </Form.Item>
                      <Form.Item
                        name={[field.name, 'value']}
                        style={{ marginBottom: 0 }}
                        rules={[{ required: true, message: '请输入分值' }]}
                      >
                        <InputNumber min={0} max={100} precision={0} placeholder="分值" style={{ width: 140 }} />
                      </Form.Item>
                      {canEdit && (
                        <Tooltip title="删除此信号分值">
                          <Button
                            type="text"
                            danger
                            icon={<MinusCircleOutlined />}
                            aria-label="删除此信号分值"
                            onClick={() => remove(field.name)}
                          />
                        </Tooltip>
                      )}
                    </Space>
                  ))}
                  {canEdit && (
                    <Button block type="dashed" icon={<PlusOutlined />} onClick={() => add({ value: 10 })}>
                      添加信号
                    </Button>
                  )}
                </>
              )}
            </Form.List>
          </Form>

          {policy && (
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              版本 v{policy.version}；最近更新：{policy.updated_by || '-'} ·{' '}
              {formatDateTime(policy.updated_at)}
            </Typography.Text>
          )}
        </>
      )}
    </Card>
  )
}
