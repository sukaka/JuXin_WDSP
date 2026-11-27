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
  Input,
  InputNumber,
  List,
  Popconfirm,
  Radio,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { ApiError } from '../../api/client'
import { applicationsApi } from '../../api/applications'
import {
  apiLLMApi,
  type ApiLLMBuiltinRuleCategory,
  type ApiLLMBuiltinRuleItem,
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
  const [contentFor, setContentFor] = useState<ApiLLMSecurityPolicy | null>(
    null,
  )
  const [builtinRulesOpen, setBuiltinRulesOpen] = useState(false)

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
  const builtinRulesQuery = useQuery({
    queryKey: ['api-llm-security-builtin-rules'],
    queryFn: () => apiLLMApi.getBuiltinRules(),
    enabled: builtinRulesOpen || contentFor !== null,
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
    width: canManage ? 240 : 140,
    render: (_, record) => (
      <Space size={4} wrap>
        <Button type="link" size="small" onClick={() => setContentFor(record)}>
          策略内容
        </Button>
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

  const isCategoryActiveForPolicy = (
    policy: ApiLLMSecurityPolicy,
    cat: ApiLLMBuiltinRuleCategory,
  ): { active: boolean; summary: string } => {
    if (!policy.enabled) {
      return { active: false, summary: '策略未启用（不下发网关）' }
    }
    if (cat.key === 'prompt_injection') {
      if (!policy.prompt_injection_enabled) {
        return { active: false, summary: '已关闭' }
      }
      return {
        active: true,
        summary:
          policy.mode === 'PROTECT' ? '生效（命中阻断 403）' : '生效（仅观察记录）',
      }
    }
    if (cat.key === 'content_filter') {
      const parts: string[] = []
      if (policy.input_content_enabled) parts.push('输入过滤开启')
      if (policy.output_content_enabled) parts.push('输出过滤开启')
      if (parts.length === 0) return { active: false, summary: '输入与输出均关闭' }
      return {
        active: true,
        summary: `${parts.join(' / ')}（${policy.mode === 'PROTECT' ? '命中阻断 403' : '仅观察记录'}）`,
      }
    }
    if (cat.key === 'pii_detection') {
      const parts: string[] = []
      if (policy.pii_detection_enabled) parts.push('输入仅观察')
      if (policy.output_pii_enabled) {
        parts.push(policy.mode === 'PROTECT' ? '输出阻断 403' : '输出仅观察')
      }
      if (parts.length === 0) return { active: false, summary: '输入与输出均关闭' }
      return { active: true, summary: parts.join(' / ') }
    }
    return { active: true, summary: '生效' }
  }

  const renderBuiltinRuleTable = (
    rules: ApiLLMBuiltinRuleItem[],
    mode?: 'OBSERVE' | 'PROTECT',
  ) => (
    <Table<ApiLLMBuiltinRuleItem>
      rowKey="id"
      size="small"
      pagination={false}
      dataSource={rules}
      columns={[
        {
          title: '规则标识',
          dataIndex: 'id',
          width: 190,
          render: (v: string, rec) => (
            <Space direction="vertical" size={0}>
              <Typography.Text code>{v}</Typography.Text>
              <Typography.Text style={{ fontSize: 12 }}>{rec.name}</Typography.Text>
            </Space>
          ),
        },
        {
          title: '实际检测正则（RE2）',
          dataIndex: 'pattern',
          render: (pattern: string, rec) => (
            <Space direction="vertical" size={2} style={{ width: '100%' }}>
              <Typography.Text
                code
                copyable={{ text: pattern, tooltips: ['复制正则', '已复制'] }}
                style={{ fontSize: 12, wordBreak: 'break-all' }}
              >
                {pattern}
              </Typography.Text>
              {rec.description && (
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  {rec.description}
                </Typography.Text>
              )}
            </Space>
          ),
        },
        {
          title: mode ? '当前策略处置' : '观察 / 防护处置',
          key: 'action',
          width: 170,
          render: (_, rec) =>
            mode ? (
              <Typography.Text style={{ fontSize: 12 }}>
                {mode === 'PROTECT' ? rec.protect_action : rec.observe_action}
              </Typography.Text>
            ) : (
              <Space direction="vertical" size={2}>
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  观察：{rec.observe_action}
                </Typography.Text>
                <Typography.Text style={{ fontSize: 12 }}>
                  防护：{rec.protect_action}
                </Typography.Text>
              </Space>
            ),
        },
      ]}
    />
  )

  const buildGatewayPayload = (policy: ApiLLMSecurityPolicy) => ({
    id: policy.id,
    application_id: policy.application_id,
    name: policy.name,
    version: policy.version,
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
      <Space style={{ marginBottom: 16 }} wrap>
        {canManage && (
          <Button type="primary" onClick={openCreate}>
            新建策略
          </Button>
        )}
        <Button onClick={() => setBuiltinRulesOpen(true)}>
          查看内置检测规则
        </Button>
      </Space>
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

      <Drawer
        title="网关内置 AI 安全检测规则（真实正则）"
        open={builtinRulesOpen}
        onClose={() => setBuiltinRulesOpen(false)}
        width={880}
      >
        <QueryErrorAlert error={builtinRulesQuery.error} message="加载内置检测规则失败" />
        {builtinRulesQuery.isLoading ? (
          <Typography.Text type="secondary">加载中…</Typography.Text>
        ) : builtinRulesQuery.data ? (
          <Space direction="vertical" size={16} style={{ width: '100%' }}>
            <Alert
              type="info"
              showIcon
              message="以下全部正则表达式直接读取自网关实时运行期检测引擎（RE2 线性时间），与线上实际拦截完全一致。"
              description={`输入检查字段：${builtinRulesQuery.data.prompt_paths.join('、')}；输出检查上限：最多 ${builtinRulesQuery.data.max_output_texts} 段文本、单段 ${(builtinRulesQuery.data.max_output_text_bytes / 1024).toFixed(0)} KiB（仅完整非流式 JSON 响应）。`}
            />
            {builtinRulesQuery.data.categories.map((cat) => (
              <Card
                key={cat.key}
                size="small"
                title={`${cat.title}（${cat.rules.length} 条）`}
              >
                <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginBottom: 8 }}>
                  {cat.notes}
                </Typography.Paragraph>
                {renderBuiltinRuleTable(cat.rules)}
              </Card>
            ))}
          </Space>
        ) : null}
      </Drawer>

      <Drawer
        title={contentFor ? `AI 安全策略实际内容：${contentFor.name}` : 'AI 安全策略实际内容'}
        open={contentFor !== null}
        onClose={() => setContentFor(null)}
        width={880}
      >
        {contentFor && (
          <Space direction="vertical" size={16} style={{ width: '100%' }}>
            {!contentFor.enabled && (
              <Alert
                type="warning"
                showIcon
                message="该策略当前处于停用状态，不会随配置发布下发到网关生效。"
              />
            )}
            <Descriptions column={2} size="small" bordered>
              <Descriptions.Item label="策略名称">{contentFor.name}</Descriptions.Item>
              <Descriptions.Item label="版本">{`v${contentFor.version}`}</Descriptions.Item>
              <Descriptions.Item label="关联应用">
                {appNames.get(contentFor.application_id) ?? contentFor.application_id}
              </Descriptions.Item>
              <Descriptions.Item label="运行模式">
                <Tag color={contentFor.mode === 'PROTECT' ? 'red' : 'blue'}>
                  {contentFor.mode === 'PROTECT' ? '防护（PROTECT）' : '观察（OBSERVE）'}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="提示词体量上限">
                {contentFor.max_prompt_bytes > 0
                  ? `${contentFor.max_prompt_bytes.toLocaleString()} 字节（${contentFor.mode === 'PROTECT' ? '超限限流 429' : '超限仅观察'}）`
                  : '不限制'}
              </Descriptions.Item>
              <Descriptions.Item label="单次输出 Token 上限">
                {contentFor.max_output_tokens > 0
                  ? `${contentFor.max_output_tokens.toLocaleString()} Token（${contentFor.mode === 'PROTECT' ? '超限限流 429' : '超限仅观察'}）`
                  : '不限制'}
              </Descriptions.Item>
              <Descriptions.Item label="受限话题关键词" span={2}>
                {contentFor.blocked_topics.length > 0 ? (
                  <Space size={4} wrap>
                    {contentFor.blocked_topics.map((topic) => (
                      <Tag key={topic} color="volcano">
                        {topic}
                      </Tag>
                    ))}
                  </Space>
                ) : (
                  '未配置'
                )}
              </Descriptions.Item>
            </Descriptions>

            <QueryErrorAlert error={builtinRulesQuery.error} message="加载内置检测规则失败" />
            {builtinRulesQuery.isLoading ? (
              <Typography.Text type="secondary">正在加载网关内置检测规则…</Typography.Text>
            ) : builtinRulesQuery.data ? (
              builtinRulesQuery.data.categories.map((cat) => {
                const st = isCategoryActiveForPolicy(contentFor, cat)
                return (
                  <Card
                    key={cat.key}
                    size="small"
                    title={
                      <Space wrap>
                        <span>{`${cat.title}（${cat.rules.length} 条）`}</span>
                        <Tag color={st.active ? 'green' : 'default'}>{st.summary}</Tag>
                      </Space>
                    }
                  >
                    <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginBottom: 8 }}>
                      {cat.notes}
                    </Typography.Paragraph>
                    {renderBuiltinRuleTable(cat.rules, contentFor.mode)}
                  </Card>
                )
              })
            ) : null}

            <Card
              size="small"
              title="网关实际下发配置（api_llm_security JSON）"
              extra={
                <Typography.Text
                  copyable={{
                    text: JSON.stringify(buildGatewayPayload(contentFor), null, 2),
                    tooltips: ['复制下发 JSON', '已复制'],
                  }}
                >
                  复制 JSON
                </Typography.Text>
              }
            >
              <pre
                style={{
                  margin: 0,
                  maxHeight: 240,
                  overflow: 'auto',
                  background: '#f5f5f5',
                  padding: 12,
                  borderRadius: 6,
                  fontSize: 12,
                  fontFamily: 'monospace',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all',
                }}
              >
                {JSON.stringify(buildGatewayPayload(contentFor), null, 2)}
              </pre>
            </Card>
          </Space>
        )}
      </Drawer>
    </>
  )
}
