import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Drawer,
  Form,
  Input,
  InputNumber,
  List,
  Popconfirm,
  Radio,
  Select,
  Space,
  Switch,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { ApiError } from '../../api/client'
import { applicationsApi } from '../../api/applications'
import {
  apiLLMApi,
  type ApiLLMSecurityPolicy,
  type ApiLLMSecurityPolicyInput,
} from '../../api/apiLLM'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'

interface PolicyFormValues {
  application_id: string
  name: string
  mode: 'OBSERVE' | 'PROTECT'
  prompt_injection_enabled: boolean
  input_content_enabled: boolean
  pii_detection_enabled: boolean
  output_content_enabled: boolean
  output_pii_enabled: boolean
  blocked_topics?: string[]
  max_prompt_bytes: number
  max_output_tokens: number
}

export default function SecurityPoliciesTab() {
  const { message } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((state) => state.user?.permissions)
  const canManage = hasPermission(permissions, 'api_llm_security.manage')
  const [form] = Form.useForm<PolicyFormValues>()
  const [formOpen, setFormOpen] = useState(false)
  const [editing, setEditing] = useState<ApiLLMSecurityPolicy | null>(null)
  const [versionsFor, setVersionsFor] = useState<ApiLLMSecurityPolicy | null>(
    null,
  )

  const policiesQuery = useQuery({
    queryKey: ['api-llm-security-policies'],
    queryFn: () => apiLLMApi.listSecurityPolicies(),
  })
  const appsQuery = useQuery({
    queryKey: ['applications', 'api-llm-security-options'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
  })
  const versionsQuery = useQuery({
    queryKey: ['api-llm-security-policy-versions', versionsFor?.id],
    queryFn: () => apiLLMApi.listSecurityPolicyVersions(versionsFor!.id),
    enabled: versionsFor !== null,
  })

  const appOptions = (appsQuery.data?.items ?? []).map((app) => ({
    value: app.id,
    label: `${app.name}（${app.code}）`,
  }))
  const appNames = new Map(
    (appsQuery.data?.items ?? []).map((app) => [app.id, app.name]),
  )
  const invalidate = () =>
    void qc.invalidateQueries({ queryKey: ['api-llm-security-policies'] })
  const errorText = (error: unknown, fallback: string) =>
    error instanceof ApiError ? error.message : fallback

  const saveMutation = useMutation({
    mutationFn: (values: PolicyFormValues) => {
      const body: ApiLLMSecurityPolicyInput = {
        application_id: values.application_id,
        name: values.name.trim(),
        mode: values.mode,
        prompt_injection_enabled: values.prompt_injection_enabled,
        input_content_enabled: values.input_content_enabled,
        pii_detection_enabled: values.pii_detection_enabled,
        output_content_enabled: values.output_content_enabled,
        output_pii_enabled: values.output_pii_enabled,
        blocked_topics: (values.blocked_topics ?? [])
          .map((item) => item.trim())
          .filter(Boolean),
        max_prompt_bytes: values.max_prompt_bytes,
        max_output_tokens: values.max_output_tokens,
      }
      return editing
        ? apiLLMApi.updateSecurityPolicy(editing.id, body)
        : apiLLMApi.createSecurityPolicy(body)
    },
    onSuccess: () => {
      message.success('策略已保存，需通过配置发布生效')
      setFormOpen(false)
      setEditing(null)
      invalidate()
    },
    onError: (error) => message.error(errorText(error, '策略保存失败')),
  })
  const toggleMutation = useMutation({
    mutationFn: (policy: ApiLLMSecurityPolicy) =>
      apiLLMApi.updateSecurityPolicy(policy.id, { enabled: !policy.enabled }),
    onSuccess: () => {
      message.success('状态已更新，需通过配置发布生效')
      invalidate()
    },
    onError: (error) => message.error(errorText(error, '状态更新失败')),
  })
  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiLLMApi.deleteSecurityPolicy(id),
    onSuccess: () => {
      message.success('策略已删除，需通过配置发布生效')
      invalidate()
    },
    onError: (error) => message.error(errorText(error, '策略删除失败')),
  })

  const openCreate = () => {
    setEditing(null)
    form.resetFields()
    form.setFieldsValue({
      mode: 'OBSERVE',
      prompt_injection_enabled: true,
      input_content_enabled: true,
      pii_detection_enabled: true,
      output_content_enabled: true,
      output_pii_enabled: true,
      blocked_topics: [],
      max_prompt_bytes: 0,
      max_output_tokens: 0,
    })
    setFormOpen(true)
  }
  const openEdit = (policy: ApiLLMSecurityPolicy) => {
    setEditing(policy)
    form.resetFields()
    form.setFieldsValue({
      application_id: policy.application_id,
      name: policy.name,
      mode: policy.mode,
      prompt_injection_enabled: policy.prompt_injection_enabled,
      input_content_enabled: policy.input_content_enabled,
      pii_detection_enabled: policy.pii_detection_enabled,
      output_content_enabled: policy.output_content_enabled,
      output_pii_enabled: policy.output_pii_enabled,
      blocked_topics: policy.blocked_topics,
      max_prompt_bytes: policy.max_prompt_bytes,
      max_output_tokens: policy.max_output_tokens,
    })
    setFormOpen(true)
  }

  const columns: ColumnsType<ApiLLMSecurityPolicy> = [
    {
      title: '策略',
      dataIndex: 'name',
      render: (name, record) => (
        <Space direction="vertical" size={2}>
          <strong>{name}</strong>
          <Typography.Text type="secondary">v{record.version}</Typography.Text>
        </Space>
      ),
    },
    {
      title: '应用',
      dataIndex: 'application_id',
      render: (id) => appNames.get(id) ?? id,
      ellipsis: true,
    },
    {
      title: '模式',
      dataIndex: 'mode',
      width: 110,
      render: (mode) => (
        <Tag color={mode === 'PROTECT' ? 'red' : 'blue'}>
          {mode === 'PROTECT' ? '防护' : '观察'}
        </Tag>
      ),
    },
    {
      title: '输入保护',
      key: 'protection',
      width: 190,
      render: (_, record) => (
        <Space size={4} wrap>
          {record.prompt_injection_enabled && <Tag>提示词注入</Tag>}
          {record.input_content_enabled && <Tag>恶意内容</Tag>}
          {record.pii_detection_enabled && <Tag>敏感个人信息识别</Tag>}
          {record.max_prompt_bytes > 0 && <Tag>体量限制</Tag>}
        </Space>
      ),
    },
    {
      title: '输出保护',
      key: 'output_protection',
      width: 170,
      render: (_, record) => (
        <Space size={4} wrap>
          {record.output_content_enabled && <Tag>内容审核</Tag>}
          {record.output_pii_enabled && <Tag>输出敏感信息</Tag>}
          {!record.output_content_enabled && !record.output_pii_enabled && '—'}
        </Space>
      ),
    },
    {
      title: '受限话题关键词',
      dataIndex: 'blocked_topics',
      width: 200,
      render: (topics: string[]) =>
        topics.length ? (
          <Space size={4} wrap>
            {topics.map((topic) => (
              <Tag key={topic}>{topic}</Tag>
            ))}
          </Space>
        ) : (
          '—'
        ),
    },
    {
      title: '提示词上限',
      dataIndex: 'max_prompt_bytes',
      width: 120,
      render: (value) =>
        value > 0 ? `${value.toLocaleString()} 字节` : '不限制',
    },
    {
      title: 'Token 上限',
      dataIndex: 'max_output_tokens',
      width: 140,
      render: (value) =>
        value > 0 ? `${value.toLocaleString()} Token` : '不限制',
    },
    {
      title: '启用',
      dataIndex: 'enabled',
      width: 90,
      render: (enabled, record) => (
        <Switch
          checked={enabled}
          disabled={!canManage || toggleMutation.isPending}
          onChange={() => toggleMutation.mutate(record)}
          aria-label={`启停 ${record.name}`}
        />
      ),
    },
    {
      title: '更新时间',
      dataIndex: 'updated_at',
      width: 165,
      render: (value) => formatDateTime(value),
    },
  ]
  columns.push({
    title: '操作',
    key: 'actions',
    width: canManage ? 190 : 80,
    render: (_, record) => (
      <Space size={4} wrap>
        {canManage && (
          <Button type="link" size="small" onClick={() => openEdit(record)}>
            编辑
          </Button>
        )}
        <Button type="link" size="small" onClick={() => setVersionsFor(record)}>
          版本
        </Button>
        {canManage && (
          <Popconfirm
            title="删除该策略？"
            description="删除后仍需发布配置才能从网关停用该策略。"
            onConfirm={() => deleteMutation.mutate(record.id)}
          >
            <Button
              type="link"
              danger
              size="small"
              loading={deleteMutation.isPending}
            >
              删除
            </Button>
          </Popconfirm>
        )}
      </Space>
    ),
  })

  return (
    <>
      <Alert
        type="info"
        showIcon
        message="策略按应用配置；保存后需通过整站配置发布生效。防护模式下输入注入、恶意内容、受限话题及输出有害内容/敏感个人信息可阻断，超大体量或输出 Token 预算将限流；所有证据均不保存原始内容。"
        style={{ marginBottom: 16 }}
      />
      <QueryErrorAlert error={policiesQuery.error} />
      <QueryErrorAlert error={appsQuery.error} message="加载应用列表失败" />
      {canManage && (
        <Button
          type="primary"
          onClick={openCreate}
          style={{ marginBottom: 16 }}
        >
          新建策略
        </Button>
      )}
      <SmartTable<ApiLLMSecurityPolicy>
        storageKey="api-llm-security-policies"
        rowKey="id"
        loading={policiesQuery.isLoading}
        columns={columns}
        dataSource={policiesQuery.data?.items ?? []}
        scroll={{ x: 1320 }}
        pagination={false}
      />

      <Drawer
        title={editing ? '编辑 AI 安全策略' : '新建 AI 安全策略'}
        open={formOpen}
        onClose={() => {
          setFormOpen(false)
          setEditing(null)
        }}
        width={560}
      >
        <Form<PolicyFormValues>
          form={form}
          layout="vertical"
          preserve={false}
          onFinish={(values) => saveMutation.mutate(values)}
          initialValues={{
            mode: 'OBSERVE',
            prompt_injection_enabled: true,
            input_content_enabled: true,
            pii_detection_enabled: true,
            output_content_enabled: true,
            output_pii_enabled: true,
            max_prompt_bytes: 0,
            max_output_tokens: 0,
          }}
        >
          <Form.Item
            name="application_id"
            label="应用"
            rules={[{ required: true, message: '请选择应用' }]}
          >
            <Select
              showSearch
              optionFilterProp="label"
              options={appOptions}
              loading={appsQuery.isLoading}
              disabled={editing !== null}
              placeholder="选择需要保护的 AI 应用"
            />
          </Form.Item>
          <Form.Item
            name="name"
            label="策略名称"
            rules={[
              { required: true, message: '请输入策略名称' },
              { max: 128 },
            ]}
          >
            <Input placeholder="如：客服助手输入保护" maxLength={128} />
          </Form.Item>
          <Form.Item name="mode" label="运行模式" rules={[{ required: true }]}>
            <Radio.Group
              options={[
                { value: 'OBSERVE', label: '观察：只记录' },
                { value: 'PROTECT', label: '防护：执行处置' },
              ]}
              optionType="button"
            />
          </Form.Item>
          <Form.Item
            name="prompt_injection_enabled"
            label="提示词注入攻击防护"
            valuePropName="checked"
            extra="防护模式下，命中高置信注入规则时阻断。"
          >
            <Switch />
          </Form.Item>
          <Form.Item
            name="input_content_enabled"
            label="输入恶意内容过滤"
            valuePropName="checked"
            extra="采用高置信规则识别明确的有害请求，防护模式下命中阻断；沿用现有标量留存边界，不保存原文。"
          >
            <Switch />
          </Form.Item>
          <Form.Item
            name="pii_detection_enabled"
            label="敏感个人信息（PII）识别"
            valuePropName="checked"
            extra="识别邮箱、身份证号、手机号；事件不保存原始内容。"
          >
            <Switch />
          </Form.Item>
          <Form.Item
            name="output_content_enabled"
            label="输出有害内容过滤"
            valuePropName="checked"
            extra="采用高置信规则；完整非流式 JSON 响应才可判定，防护模式下命中阻断。"
          >
            <Switch />
          </Form.Item>
          <Form.Item
            name="output_pii_enabled"
            label="输出敏感个人信息（PII）识别"
            valuePropName="checked"
            extra="检测输出中的邮箱、身份证号、手机号；防护模式下命中阻断，不落原文。"
          >
            <Switch />
          </Form.Item>
          <Form.Item
            name="blocked_topics"
            label="受限话题关键词"
            extra="采用关键词匹配，不冒充语义分类；最多 32 项，每项不超过 64 字。"
          >
            <Select
              mode="tags"
              open={false}
              suffixIcon={null}
              maxCount={32}
              placeholder="输入关键词后回车，如：恶意爬虫"
            />
          </Form.Item>
          <Form.Item
            name="max_prompt_bytes"
            label="提示词体量上限（字节）"
            extra="0 表示不限制；其他取值须在 512～4194304 之间。"
          >
            <InputNumber min={0} max={4194304} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item
            name="max_output_tokens"
            label="单次输出 Token 上限"
            extra="限制请求声明的 max_tokens、max_completion_tokens 或 max_output_tokens；0 表示不限制，非实际消耗量。"
          >
            <InputNumber min={0} max={1000000} style={{ width: '100%' }} />
          </Form.Item>
          <Button
            type="primary"
            htmlType="submit"
            loading={saveMutation.isPending}
            block
          >
            保存策略
          </Button>
        </Form>
      </Drawer>

      <Drawer
        title={versionsFor ? `${versionsFor.name} · 版本快照` : '版本快照'}
        open={versionsFor !== null}
        onClose={() => setVersionsFor(null)}
        width={560}
      >
        <QueryErrorAlert error={versionsQuery.error} />
        <List
          loading={versionsQuery.isLoading}
          dataSource={versionsQuery.data?.items ?? []}
          renderItem={(version) => (
            <List.Item>
              <List.Item.Meta
                title={`v${version.version} · ${formatDateTime(version.created_at)}`}
                description={`${version.policy_snapshot.mode === 'PROTECT' ? '防护' : '观察'} · 注入防护 ${version.policy_snapshot.prompt_injection_enabled ? '开启' : '关闭'} · 输入内容 ${version.policy_snapshot.input_content_enabled ? '开启' : '关闭'} · 输入敏感信息 ${version.policy_snapshot.pii_detection_enabled ? '开启' : '关闭'} · 输出内容 ${version.policy_snapshot.output_content_enabled ? '开启' : '关闭'} · 输出敏感信息 ${version.policy_snapshot.output_pii_enabled ? '开启' : '关闭'} · 提示词上限 ${version.policy_snapshot.max_prompt_bytes || '不限制'} · 输出 Token 上限 ${version.policy_snapshot.max_output_tokens || '不限制'}`}
              />
            </List.Item>
          )}
        />
      </Drawer>
    </>
  )
}
