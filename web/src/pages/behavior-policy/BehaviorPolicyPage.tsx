import { useEffect } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Button,
  Card,
  Col,
  Divider,
  Form,
  InputNumber,
  Row,
  Select,
  Spin,
  Switch,
  Typography,
} from 'antd'
import { ApiError } from '../../api/client'
import { behaviorPolicyApi } from '../../api/behaviorPolicy'
import type { BehaviorPolicyBody } from '../../api/behaviorPolicy'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import { useAuthStore } from '../../stores/auth'
import { hasPermission } from '../../utils/permission'
import { formatDateTime } from '../../utils/format'
import { SIGNAL_META } from '../../utils/identitySecurity'

interface PolicyFormValues {
  enabled: boolean
  uri_enum_unique_threshold: number
  uri_enum_new_ratio_threshold: number
  not_found_ratio_threshold: number
  not_found_min_requests: number
  method_enum_threshold: number
  param_mutation_threshold: number
  auth_fail_threshold: number
  low_slow_sensitive_min_hits: number
  account_enum_threshold: number
  object_enum_threshold: number
  account_identifier_fields?: string[]
  object_identifier_fields?: string[]
  sensitive_paths?: string[]
  scores: Record<string, number>
  whitelist_ips?: string[]
  whitelist_uas?: string[]
}

export default function BehaviorPolicyPage() {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canEdit = hasPermission(permissions, 'behavior_policy.edit')
  const [form] = Form.useForm<PolicyFormValues>()

  const policyQuery = useQuery({
    queryKey: ['behavior-policy'],
    queryFn: () => behaviorPolicyApi.get(),
  })
  const policy = policyQuery.data

  // GET 回填（含保存后重新拉取的新 version）
  useEffect(() => {
    if (!policy) return
    form.setFieldsValue({
      enabled: policy.enabled,
      uri_enum_unique_threshold: policy.uri_enum_unique_threshold,
      uri_enum_new_ratio_threshold: policy.uri_enum_new_ratio_threshold,
      not_found_ratio_threshold: policy.not_found_ratio_threshold,
      not_found_min_requests: policy.not_found_min_requests,
      method_enum_threshold: policy.method_enum_threshold,
      param_mutation_threshold: policy.param_mutation_threshold,
      auth_fail_threshold: policy.auth_fail_threshold,
      low_slow_sensitive_min_hits: policy.low_slow_sensitive_min_hits,
      account_enum_threshold: policy.account_enum_threshold,
      object_enum_threshold: policy.object_enum_threshold,
      account_identifier_fields: policy.account_identifier_fields,
      object_identifier_fields: policy.object_identifier_fields,
      sensitive_paths: policy.sensitive_paths,
      scores: { ...policy.scores },
      whitelist_ips: policy.whitelist_ips,
      whitelist_uas: policy.whitelist_uas,
    })
  }, [policy, form])

  const saveMutation = useMutation({
    mutationFn: (values: PolicyFormValues) => {
      const body: BehaviorPolicyBody = {
        scope: policy?.scope ?? 'GLOBAL',
        enabled: values.enabled ?? false,
        mode: policy?.mode ?? 'OBSERVE',
        version: policy?.version ?? 0,
        uri_enum_unique_threshold: values.uri_enum_unique_threshold,
        uri_enum_new_ratio_threshold: values.uri_enum_new_ratio_threshold,
        not_found_ratio_threshold: values.not_found_ratio_threshold,
        not_found_min_requests: values.not_found_min_requests,
        method_enum_threshold: values.method_enum_threshold,
        param_mutation_threshold: values.param_mutation_threshold,
        auth_fail_threshold: values.auth_fail_threshold,
        low_slow_sensitive_min_hits: values.low_slow_sensitive_min_hits,
        account_enum_threshold: values.account_enum_threshold,
        object_enum_threshold: values.object_enum_threshold,
        account_identifier_fields: values.account_identifier_fields ?? [],
        object_identifier_fields: values.object_identifier_fields ?? [],
        sensitive_paths: values.sensitive_paths ?? [],
        scores: values.scores ?? {},
        whitelist_ips: values.whitelist_ips ?? [],
        whitelist_uas: values.whitelist_uas ?? [],
      }
      return behaviorPolicyApi.update(body)
    },
    onSuccess: () => {
      message.success('行为策略已保存')
      void queryClient.invalidateQueries({ queryKey: ['behavior-policy'] })
    },
    onError: (e) => {
      if (e instanceof ApiError && e.status === 409) {
        message.error('策略已被他人修改，请刷新后重试')
        return
      }
      if (e instanceof ApiError && Array.isArray(e.details)) {
        // 后端字段级校验错误（ValidationError.details = [{field, message}]），回显到对应表单项；
        // 字段名由后端下发（可能为 scores.X 嵌套路径），此处按 NamePath 转换
        const details = e.details as { field?: string; message?: string }[]
        const fields = details
          .filter((d) => d.field)
          .map((d) => ({
            name: (d.field as string).includes('.') ? (d.field as string).split('.') : (d.field as string),
            errors: [d.message ?? '取值不合法'],
          }))
        form.setFields(fields as Parameters<typeof form.setFields>[0])
        message.error(e.message || '保存失败，请检查输入')
        return
      }
      message.error(e instanceof ApiError ? e.message : '保存失败')
    },
  })

  const requiredNumber = (label: string) => [{ required: true, message: `请输入${label}` }]

  return (
    <Card
      title="行为策略"
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
        <QueryErrorAlert error={policyQuery.error} message="加载行为策略失败" />
      ) : (
        <>
          <Form<PolicyFormValues>
            form={form}
            layout="vertical"
            disabled={!canEdit}
            onFinish={(values) => saveMutation.mutate(values)}
            style={{ maxWidth: 1080 }}
          >
            <Divider titlePlacement="start" plain>
              基本设置
            </Divider>
            <Row gutter={[16, 0]}>
              <Col xs={24} sm={12} md={8}>
                <Form.Item name="enabled" label="启用行为检测" valuePropName="checked">
                  <Switch checkedChildren="启用" unCheckedChildren="停用" />
                </Form.Item>
              </Col>
              <Col xs={24} sm={12} md={8}>
                <Form.Item label="防护模式" extra="阻断动作将在后续阶段开放">
                  <Select
                    disabled
                    value="OBSERVE"
                    options={[{ value: 'OBSERVE', label: '观察（仅计分记录，不阻断）' }]}
                  />
                </Form.Item>
              </Col>
            </Row>

            <Divider titlePlacement="start" plain>
              检测阈值
            </Divider>
            <Row gutter={[16, 0]}>
              <Col xs={24} sm={12} md={8}>
                <Form.Item
                  name="uri_enum_unique_threshold"
                  label="URI枚举阈值（唯一URI数）"
                  rules={requiredNumber('URI枚举阈值')}
                >
                  <InputNumber min={1} max={100000} precision={0} style={{ width: '100%' }} />
                </Form.Item>
              </Col>
              <Col xs={24} sm={12} md={8}>
                <Form.Item
                  name="uri_enum_new_ratio_threshold"
                  label="新URI比例（0-1）"
                  rules={requiredNumber('新URI比例')}
                >
                  <InputNumber min={0} max={1} step={0.05} style={{ width: '100%' }} />
                </Form.Item>
              </Col>
              <Col xs={24} sm={12} md={8}>
                <Form.Item
                  name="not_found_ratio_threshold"
                  label="404比例（0-1）"
                  rules={requiredNumber('404比例')}
                >
                  <InputNumber min={0} max={1} step={0.05} style={{ width: '100%' }} />
                </Form.Item>
              </Col>
              <Col xs={24} sm={12} md={8}>
                <Form.Item
                  name="not_found_min_requests"
                  label="404最小请求数"
                  rules={requiredNumber('404最小请求数')}
                >
                  <InputNumber min={1} max={1000000} precision={0} style={{ width: '100%' }} />
                </Form.Item>
              </Col>
              <Col xs={24} sm={12} md={8}>
                <Form.Item
                  name="method_enum_threshold"
                  label="方法枚举阈值"
                  rules={requiredNumber('方法枚举阈值')}
                >
                  <InputNumber min={1} max={1000} precision={0} style={{ width: '100%' }} />
                </Form.Item>
              </Col>
              <Col xs={24} sm={12} md={8}>
                <Form.Item
                  name="param_mutation_threshold"
                  label="参数变异阈值"
                  rules={requiredNumber('参数变异阈值')}
                >
                  <InputNumber min={1} max={100000} precision={0} style={{ width: '100%' }} />
                </Form.Item>
              </Col>
              <Col xs={24} sm={12} md={8}>
                <Form.Item
                  name="auth_fail_threshold"
                  label="认证失败阈值"
                  rules={requiredNumber('认证失败阈值')}
                >
                  <InputNumber min={1} max={100000} precision={0} style={{ width: '100%' }} />
                </Form.Item>
              </Col>
              <Col xs={24} sm={12} md={8}>
                <Form.Item
                  name="low_slow_sensitive_min_hits"
                  label="低慢敏感路径命中数"
                  rules={requiredNumber('低慢敏感路径命中数')}
                >
                  <InputNumber min={1} max={100000} precision={0} style={{ width: '100%' }} />
                </Form.Item>
              </Col>
              <Col xs={24} sm={12} md={8}>
                <Form.Item name="account_enum_threshold" label="账号枚举阈值" rules={requiredNumber('账号枚举阈值')}>
                  <InputNumber min={1} max={100000} precision={0} style={{ width: '100%' }} />
                </Form.Item>
              </Col>
              <Col xs={24} sm={12} md={8}>
                <Form.Item name="object_enum_threshold" label="对象枚举阈值" rules={requiredNumber('对象枚举阈值')}>
                  <InputNumber min={1} max={100000} precision={0} style={{ width: '100%' }} />
                </Form.Item>
              </Col>
              <Col xs={24} md={12}>
                <Form.Item name="account_identifier_fields" label="账号标识字段" extra="仅保存字段名，不保存字段值">
                  <Select mode="tags" open={false} placeholder="如 account_id、username" />
                </Form.Item>
              </Col>
              <Col xs={24} md={12}>
                <Form.Item name="object_identifier_fields" label="对象标识字段" extra="仅保存字段名，不保存字段值">
                  <Select mode="tags" open={false} placeholder="如 object_id、resource_id" />
                </Form.Item>
              </Col>
              <Col xs={24}>
                <Form.Item
                  name="sensitive_paths"
                  label="敏感路径"
                  extra="命中敏感路径计入低慢侦察与敏感路径探测信号"
                >
                  <Select mode="tags" open={false} placeholder="输入路径后回车，如 /admin、/backup" />
                </Form.Item>
              </Col>
            </Row>

            <Divider titlePlacement="start" plain>
              风险分值（各信号命中加分，0-100）
            </Divider>
            <Row gutter={[16, 0]}>
              {Object.entries(SIGNAL_META).map(([signal, meta]) => (
                <Col xs={24} sm={12} md={8} key={signal}>
                  <Form.Item
                    name={['scores', signal]}
                    label={`${meta.label}分值`}
                    rules={requiredNumber(`${meta.label}分值`)}
                  >
                    <InputNumber min={0} max={100} precision={0} style={{ width: '100%' }} />
                  </Form.Item>
                </Col>
              ))}
            </Row>

            <Divider titlePlacement="start" plain>
              白名单（命中后不参与行为计分）
            </Divider>
            <Row gutter={[16, 0]}>
              <Col xs={24} md={12}>
                <Form.Item name="whitelist_ips" label="IP 白名单">
                  <Select mode="tags" open={false} placeholder="输入 IP 后回车" />
                </Form.Item>
              </Col>
              <Col xs={24} md={12}>
                <Form.Item name="whitelist_uas" label="User-Agent 白名单">
                  <Select mode="tags" open={false} placeholder="输入 UA 特征串后回车" />
                </Form.Item>
              </Col>
            </Row>
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
