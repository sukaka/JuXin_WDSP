import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Descriptions,
  Drawer,
  Form,
  Popconfirm,
  Select,
  Space,
  Spin,
  Tag,
} from 'antd'
import { ApiError } from '../../api/client'
import { applicationsApi } from '../../api/applications'
import { riskPolicyApi, type RiskPolicy } from '../../api/riskPolicy'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import { useAuthStore } from '../../stores/auth'
import { hasPermission } from '../../utils/permission'
import RiskPolicyFields from './RiskPolicyFields'
import {
  duplicateScoreKeys,
  formValuesToBody,
  policyToFormValues,
  type PolicyFormValues,
} from './riskPolicyForm'

interface Props {
  globalPolicy: RiskPolicy
}

export default function ApplicationRiskOverridesPanel({ globalPolicy }: Props) {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((state) => state.user?.permissions)
  const canRead = hasPermission(permissions, 'risk_policy.read')
  const canEdit = hasPermission(permissions, 'risk_policy.edit')
  const [applicationId, setApplicationId] = useState('')
  const [editorOpen, setEditorOpen] = useState(false)
  const [form] = Form.useForm<PolicyFormValues>()

  const applicationsQuery = useQuery({
    queryKey: ['applications', 'risk-policy-overrides'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
    enabled: canRead,
  })
  const overrideQuery = useQuery({
    queryKey: ['risk-policy-application', applicationId],
    queryFn: () => riskPolicyApi.getApplicationOverride(applicationId),
    enabled: canRead && applicationId !== '',
  })
  const current = overrideQuery.data ?? null

  const invalidate = () =>
    void queryClient.invalidateQueries({
      queryKey: ['risk-policy-application', applicationId],
    })
  const errorText = (error: unknown, fallback: string) => {
    if (!(error instanceof ApiError)) return fallback
    if (error.status === 409) return '策略已被他人修改，请刷新后重试'
    if (Array.isArray(error.details)) {
      const details = error.details as { field?: string; message?: string }[]
      const text = details
        .map((item) => `${item.field ?? ''}: ${item.message ?? '取值不合法'}`)
        .join('；')
      if (text) return `${error.message}（${text}）`
    }
    return error.message || fallback
  }

  const saveMutation = useMutation({
    mutationFn: (values: PolicyFormValues) =>
      riskPolicyApi.putApplicationOverride(
        applicationId,
        formValuesToBody(values, 'APPLICATION', current?.version ?? 0),
      ),
    onSuccess: () => {
      message.success('应用风险覆盖已保存，发布结果以发布任务为准')
      setEditorOpen(false)
      invalidate()
    },
    onError: (error) => message.error(errorText(error, '保存应用覆盖失败')),
  })
  const deleteMutation = useMutation({
    mutationFn: () =>
      riskPolicyApi.deleteApplicationOverride(applicationId, current!.version),
    onSuccess: () => {
      message.success('已删除应用覆盖，将继承全局策略')
      setEditorOpen(false)
      invalidate()
    },
    onError: (error) => message.error(errorText(error, '删除应用覆盖失败')),
  })

  const openEditor = () => {
    const base = current ?? globalPolicy
    form.setFieldsValue({
      ...policyToFormValues(base),
      mode: current?.mode ?? 'OBSERVE',
    })
    setEditorOpen(true)
  }
  const submit = (values: PolicyFormValues) => {
    const duplicated = duplicateScoreKeys(values.score_entries)
    if (duplicated.length > 0) {
      message.error(
        `信号类型重复：${duplicated.join('、')}，请合并或删除重复行`,
      )
      return
    }
    saveMutation.mutate(values)
  }

  return (
    <Card title="按应用风险覆盖">
      <Alert
        type="info"
        showIcon
        message="未配置覆盖的应用继承全局策略；显式停用的覆盖不会继承全局处置。覆盖保存后由既有发布链下发。"
        style={{ marginBottom: 16 }}
      />
      <Space direction="vertical" size={12} style={{ width: '100%' }}>
        <Select
          showSearch
          optionFilterProp="label"
          aria-label="选择需要配置风险覆盖的应用"
          placeholder="选择应用"
          value={applicationId || undefined}
          loading={applicationsQuery.isLoading}
          disabled={!canRead}
          onChange={setApplicationId}
          style={{ width: 360, maxWidth: '100%' }}
          options={(applicationsQuery.data?.items ?? []).map((app) => ({
            value: app.id,
            label: `${app.name}（${app.code}）`,
          }))}
        />
        <QueryErrorAlert
          error={applicationsQuery.error}
          message="加载应用列表失败"
        />
        {applicationId && canRead ? (
          <>
            <QueryErrorAlert error={overrideQuery.error} />
            {overrideQuery.isLoading ? (
              <Spin size="small" />
            ) : overrideQuery.isError ? null : current ? (
              <Descriptions size="small" column={{ xs: 1, sm: 2, md: 4 }}>
                <Descriptions.Item label="覆盖状态">
                  <Tag color={current.enabled ? 'green' : 'default'}>
                    {current.enabled ? '已启用' : '已停用'}
                  </Tag>
                </Descriptions.Item>
                <Descriptions.Item label="模式">
                  {current.mode === 'PROTECT' ? '防护' : '观察'}
                </Descriptions.Item>
                <Descriptions.Item label="版本">
                  v{current.version}
                </Descriptions.Item>
                <Descriptions.Item label="阻断阈值">
                  {current.block_threshold}
                </Descriptions.Item>
              </Descriptions>
            ) : (
              <Alert
                type="info"
                showIcon
                message="当前应用未配置覆盖，将继承全局策略"
              />
            )}
            {canEdit && !overrideQuery.isError && (
              <Space wrap>
                <Button type="primary" onClick={openEditor}>
                  {current ? '编辑应用覆盖' : '新建应用覆盖'}
                </Button>
                {current && (
                  <Popconfirm
                    title="删除应用覆盖？"
                    description="删除后该应用将继承全局策略。"
                    onConfirm={() => deleteMutation.mutate()}
                  >
                    <Button danger loading={deleteMutation.isPending}>
                      删除覆盖并继承全局
                    </Button>
                  </Popconfirm>
                )}
              </Space>
            )}
          </>
        ) : null}
      </Space>

      <Drawer
        title={current ? '编辑应用风险覆盖' : '新建应用风险覆盖'}
        open={editorOpen}
        onClose={() => setEditorOpen(false)}
        width={720}
        destroyOnHidden
      >
        <Form<PolicyFormValues>
          form={form}
          layout="vertical"
          disabled={!canEdit}
          onFinish={submit}
        >
          <RiskPolicyFields canEdit={canEdit} showGroupControl />
          <Button
            type="primary"
            htmlType="submit"
            loading={saveMutation.isPending}
            block
          >
            保存应用覆盖
          </Button>
        </Form>
      </Drawer>
    </Card>
  )
}
