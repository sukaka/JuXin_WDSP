import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Form,
  Space,
  Spin,
  Typography,
} from 'antd'
import { QuestionCircleOutlined } from '@ant-design/icons'
import { ApiError } from '../../api/client'
import { riskPolicyApi } from '../../api/riskPolicy'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import { useAuthStore } from '../../stores/auth'
import { hasPermission } from '../../utils/permission'
import { formatDateTime } from '../../utils/format'
import ApplicationRiskOverridesPanel from './ApplicationRiskOverridesPanel'
import RiskPolicyFields from './RiskPolicyFields'
import {
  formatRiskPolicyField,
  formValuesToBody,
  policyToFormValues,
  type PolicyFormValues,
  type ScoreEntry,
} from './riskPolicyForm'

export default function RiskPolicyPage() {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canEdit = hasPermission(permissions, 'risk_policy.edit')
  const [form] = Form.useForm<PolicyFormValues>()
  const [advancedOpen, setAdvancedOpen] = useState(false)

  const hasAdvancedField = (fieldNames: string[]) =>
    fieldNames.some(
      (name) =>
        name === 'signal_window_seconds' ||
        name === 'risk_levels' ||
        name.startsWith('risk_levels.') ||
        name === 'scores' ||
        name.startsWith('scores.') ||
        name.startsWith('score_entries'),
    )

  const policyQuery = useQuery({
    queryKey: ['risk-policy'],
    queryFn: () => riskPolicyApi.get(),
  })
  const policy = policyQuery.data

  // GET 回填（含保存后重新拉取的新 version）；scores map 展开为键值对行
  useEffect(() => {
    if (!policy) return
    form.setFieldsValue(policyToFormValues(policy))
  }, [policy, form])

  /** 提交前检测信号分值表重复 signal_type：折叠回 map 时后者会静默覆盖前者，须拦截并定位到重复行 */
  const onFinish = (values: PolicyFormValues) => {
    const indexByKey = new Map<string, number[]>()
    ;(values.score_entries ?? []).forEach((entry, idx) => {
      if (!entry.key) return
      indexByKey.set(entry.key, [...(indexByKey.get(entry.key) ?? []), idx])
    })
    const duplicated = [...indexByKey.entries()].filter(
      ([, idxs]) => idxs.length > 1,
    )
    if (duplicated.length > 0) {
      setAdvancedOpen(true)
      form.setFields(
        duplicated.flatMap(([key, idxs]) =>
          idxs.map((idx) => ({
            name: ['score_entries', idx, 'key'] as (string | number)[],
            errors: [`信号类型「${key}」重复，请合并或删除重复行`],
          })),
        ) as Parameters<typeof form.setFields>[0],
      )
      message.error(
        `信号分值表存在重复信号类型：${duplicated.map(([key]) => key).join('、')}`,
      )
      return
    }
    saveMutation.mutate(values)
  }

  const saveMutation = useMutation({
    mutationFn: (values: PolicyFormValues) =>
      riskPolicyApi.update(
        formValuesToBody(
          values,
          policy?.scope ?? 'GLOBAL',
          policy?.version ?? 0,
        ),
      ),
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
        if (
          hasAdvancedField(
            details
              .map((d) => d.field)
              .filter((f): f is string => Boolean(f)),
          )
        ) {
          setAdvancedOpen(true)
        }
        const entries = (form.getFieldValue('score_entries') ??
          []) as ScoreEntry[]
        const fields: {
          name: string | (string | number)[]
          errors: string[]
        }[] = []
        const unmapped: string[] = []
        for (const d of details) {
          if (!d.field) continue
          const errMsg = d.message ?? '取值不合法'
          if (d.field.startsWith('scores.')) {
            const key = d.field.slice('scores.'.length)
            const idx = entries.findIndex((entry) => entry.key === key)
            if (idx >= 0) {
              fields.push({
                name: ['score_entries', idx, 'value'],
                errors: [errMsg],
              })
            } else {
              unmapped.push(`${formatRiskPolicyField(d.field)}：${errMsg}`)
            }
          } else {
            fields.push({
              name: d.field.includes('.') ? d.field.split('.') : d.field,
              errors: [errMsg],
            })
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
    <Space direction="vertical" size={16} style={{ display: 'flex' }}>
      <Card
        title="风险策略"
        extra={
          <Space>
            <Button
              icon={<QuestionCircleOutlined />}
              href="/risk-policy/guide"
              target="_blank"
              rel="noopener noreferrer"
            >
              使用说明
            </Button>
            {canEdit && (
              <Button
                type="primary"
                loading={saveMutation.isPending}
                disabled={!policy}
                onClick={() => form.submit()}
              >
                保存策略
              </Button>
            )}
          </Space>
        }
      >
        {policyQuery.isLoading ? (
          <div style={{ padding: '64px 0', textAlign: 'center' }}>
            <Spin />
          </div>
        ) : policyQuery.isError ? (
          <QueryErrorAlert
            error={policyQuery.error}
            message="加载风险策略失败"
          />
        ) : (
          <>
            <Alert
              type="info"
              showIcon
              style={{ maxWidth: 1080, marginBottom: 16 }}
              message="风险分为身份级跨请求累计（24h 滑窗）：达限速阈值时限速、达挑战阈值时发起 JS 挑战、达阻断阈值时阻断；挑战后仍执行后续防护，观察模式只记录不处置。"
            />
            <Form<PolicyFormValues>
              form={form}
              layout="vertical"
              disabled={!canEdit}
              onFinish={onFinish}
              onFinishFailed={({ errorFields }) => {
                const names = errorFields.map((item) =>
                  item.name.map(String).join('.'),
                )
                if (hasAdvancedField(names)) {
                  setAdvancedOpen(true)
                }
              }}
              style={{ maxWidth: 1080 }}
            >
              <RiskPolicyFields
                canEdit={canEdit}
                advancedOpen={advancedOpen}
                onAdvancedOpenChange={setAdvancedOpen}
              />
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
      {policy && <ApplicationRiskOverridesPanel globalPolicy={policy} />}
    </Space>
  )
}
