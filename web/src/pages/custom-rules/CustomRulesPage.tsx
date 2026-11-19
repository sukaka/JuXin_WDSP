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
  Modal,
  Select,
  Space,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { CheckCircleOutlined, PlusOutlined } from '@ant-design/icons'
import { ApiError } from '../../api/client'
import { customRulesApi } from '../../api/customRules'
import type { CustomRuleBody } from '../../api/customRules'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import VulnIdTags from '../../components/VulnIdTags'
import useBatchDelete from '../../hooks/useBatchDelete'
import { useAuthStore } from '../../stores/auth'
import { hasPermission } from '../../utils/permission'
import { CORAZA_VARIABLE_LABELS } from '../../utils/i18nLabels'
import { CNNVD_ID_PATTERN, CVE_ID_PATTERN, findInvalidVulnIds } from '../../utils/vulnIds'
import {
  ATTACK_TYPE_META,
  ATTACK_TYPE_OPTIONS,
  CUSTOM_RULE_ACTION_META,
  ENABLE_STATUS_META,
  EXCEPTION_SCOPE_META,
  RULE_SEVERITY_META,
} from '../../utils/stage4'
import type { CustomRuleItem, CustomRuleValidateResult } from '../../types'

interface Filters {
  keyword?: string
  status?: string
  cnnvd_id?: string
  cve_id?: string
}

const RULE_ID_MIN = 7100000
const RULE_ID_MAX = 7199999

/** 编号多值表单校验：非法值标红提示，提交时拦截（录入过程不拦截） */
const vulnIdsRule = (pattern: RegExp, label: string) => ({
  validator: (_: unknown, value?: string[]) => {
    const bad = findInvalidVulnIds(value, pattern)
    return bad.length === 0
      ? Promise.resolve()
      : Promise.reject(new Error(`${label}格式非法：${bad.join('、')}`))
  },
})

/** 后端 customrules.allowedOperators 白名单（pmFromFile 被后端禁用，不下放） */
const OPERATOR_OPTIONS = [
  { value: 'rx', label: '正则匹配' },
  { value: 'pm', label: '多关键词匹配' },
  { value: 'streq', label: '完全相等' },
  { value: 'contains', label: '包含' },
  { value: 'beginsWith', label: '开头匹配' },
  { value: 'endsWith', label: '结尾匹配' },
  { value: 'eq', label: '数值相等' },
  { value: 'ne', label: '数值不等' },
  { value: 'gt', label: '大于' },
  { value: 'lt', label: '小于' },
  { value: 'ge', label: '大于等于' },
  { value: 'le', label: '小于等于' },
  { value: 'ipMatch', label: 'IP 匹配' },
  { value: 'detectSQLi', label: 'SQL 注入检测' },
  { value: 'detectXSS', label: '跨站脚本检测' },
  { value: 'validateUrlEncoding', label: 'URL 编码校验' },
  { value: 'validateUtf8Encoding', label: 'UTF-8 编码校验' },
]

const OPERATOR_LABEL_MAP: Record<string, string> = Object.fromEntries(
  OPERATOR_OPTIONS.map((o) => [o.value, o.label]),
)

/** 无需匹配内容的操作符 */
const NO_VALUE_OPERATORS = ['detectSQLi', 'detectXSS', 'validateUrlEncoding', 'validateUtf8Encoding']

/** 后端 customrules.allowedVariables 白名单（展示中文名，提交值为 Coraza 变量名） */
const VARIABLE_OPTIONS = [
  'ARGS',
  'ARGS_GET',
  'ARGS_POST',
  'ARGS_NAMES',
  'QUERY_STRING',
  'REQUEST_URI',
  'REQUEST_METHOD',
  'REQUEST_HEADERS',
  'REQUEST_HEADERS_NAMES',
  'REQUEST_COOKIES',
  'REQUEST_BODY',
  'REQUEST_FILENAME',
  'REQUEST_BASENAME',
  'REMOTE_ADDR',
  'HTTP_USER_AGENT',
  'CONTENT_TYPE',
  'REQUEST_PROTOCOL',
  'REQUEST_LINE',
].map((v) => ({ value: v, label: CORAZA_VARIABLE_LABELS[v] ?? v }))

const PHASE_OPTIONS = [1, 2, 3, 4, 5].map((n) => ({
  value: n,
  label: `阶段 ${n}${n === 1 ? '（请求头）' : n === 2 ? '（请求体）' : n === 3 ? '（响应头）' : n === 4 ? '（响应体）' : '（日志）'}`,
}))

const SEVERITY_OPTIONS = ['CRITICAL', 'ERROR', 'WARNING', 'NOTICE'].map((v) => ({
  value: v,
  label: RULE_SEVERITY_META[v]?.label ?? v,
}))

const ACTION_OPTIONS = Object.entries(CUSTOM_RULE_ACTION_META).map(([value, meta]) => ({
  value,
  label: meta.label,
}))

type RuleFormValues = CustomRuleBody

export default function CustomRulesPage() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'custom_rules.manage')

  const [filters, setFilters] = useState<Filters>({})
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [createOpen, setCreateOpen] = useState(false)
  const [editing, setEditing] = useState<CustomRuleItem | null>(null)
  const [detailId, setDetailId] = useState<string | null>(null)
  const [validateResult, setValidateResult] = useState<CustomRuleValidateResult | null>(null)
  const [createForm] = Form.useForm<RuleFormValues>()
  const [editForm] = Form.useForm<RuleFormValues>()

  const listQuery = useQuery({
    queryKey: ['custom-rules', filters, page, pageSize],
    queryFn: () => customRulesApi.list({ ...filters, page, page_size: pageSize }),
  })

  const { rowSelection, batchDeleteButton } = useBatchDelete<CustomRuleItem>({
    remove: (id) => customRulesApi.remove(id),
    invalidateKeys: [['custom-rules']],
    entityName: '自定义规则',
    canDelete: canManage,
  })

  const detailQuery = useQuery({
    queryKey: ['custom-rule', detailId],
    queryFn: () => customRulesApi.get(detailId as string),
    enabled: detailId !== null,
  })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['custom-rules'] })

  const onError = (e: unknown) => {
    if (e instanceof ApiError && e.code === 'RESOURCE_CONFLICT') {
      message.error(e.message || '数据已被他人修改或存在冲突，请刷新后重试')
      void invalidate()
      return
    }
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const createMutation = useMutation({
    mutationFn: (body: CustomRuleBody) => customRulesApi.create(body),
    onSuccess: (data) => {
      setCreateOpen(false)
      setValidateResult(null)
      createForm.resetFields()
      message.success(`规则「${data.name}」创建成功`)
      void invalidate()
    },
    onError,
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: CustomRuleBody & { version: number } }) =>
      customRulesApi.update(id, body),
    onSuccess: () => {
      setEditing(null)
      setValidateResult(null)
      message.success('保存成功')
      void invalidate()
    },
    onError,
  })

  const statusMutation = useMutation({
    mutationFn: ({ id, action }: { id: string; action: 'enable' | 'disable' }) =>
      action === 'enable' ? customRulesApi.enable(id) : customRulesApi.disable(id),
    onSuccess: () => {
      message.success('操作成功')
      void invalidate()
    },
    onError,
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => customRulesApi.remove(id),
    onSuccess: () => {
      message.success('规则已删除')
      void invalidate()
    },
    onError,
  })

  const validateMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: CustomRuleBody }) =>
      customRulesApi.validate(id, body),
    onSuccess: (result) => setValidateResult(result),
    onError: (e) => {
      setValidateResult(null)
      message.error(e instanceof ApiError ? e.message : '校验失败')
    },
  })

  const runValidate = (form: typeof createForm, id: string) => {
    form
      .validateFields()
      .then((values) => {
        validateMutation.mutate({
          id,
          body: {
            ...values,
            operator_value: values.operator_value ?? '',
            cnnvd_ids: values.cnnvd_ids ?? [],
            cve_ids: values.cve_ids ?? [],
          },
        })
      })
      .catch(() => {
        message.warning('请先完整填写表单再校验')
      })
  }

  const confirmDelete = (record: CustomRuleItem) => {
    modal.confirm({
      title: '删除确认',
      content: `确定删除自定义规则「${record.name}」（ID ${record.rule_id}）吗？删除后不可恢复。`,
      okButtonProps: { danger: true },
      onOk: () => deleteMutation.mutate(record.id),
    })
  }

  const openEdit = (record: CustomRuleItem) => {
    setValidateResult(null)
    setEditing(record)
    editForm.setFieldsValue({
      rule_id: record.rule_id,
      name: record.name,
      description: record.description,
      attack_type: record.attack_type,
      severity: record.severity,
      phase: record.phase,
      operator: record.operator,
      operator_value: record.operator_value,
      target_variables: record.target_variables ?? [],
      action: record.action,
      tags: record.tags ?? [],
      cnnvd_ids: record.cnnvd_ids ?? [],
      cve_ids: record.cve_ids ?? [],
    })
  }

  const columns: ColumnsType<CustomRuleItem> = [
    {
      title: '规则ID',
      dataIndex: 'rule_id',
      width: 110,
      render: (v: number) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: '名称',
      dataIndex: 'name',
      width: 200,
      ellipsis: true,
      render: (v: string, record) => (
        <Button
          type="link"
          size="small"
          style={{ padding: 0, height: 'auto' }}
          onClick={() => setDetailId(record.id)}
        >
          {v}
        </Button>
      ),
    },
    {
      title: '攻击类型',
      dataIndex: 'attack_type',
      width: 150,
      render: (v: string) => <StatusTag value={v} map={ATTACK_TYPE_META} />,
    },
    {
      title: '漏洞编号',
      key: 'vuln_ids',
      width: 200,
      render: (_, record) =>
        (record.cnnvd_ids ?? []).length + (record.cve_ids ?? []).length === 0 ? (
          <Typography.Text type="secondary">-</Typography.Text>
        ) : (
          <VulnIdTags cnnvdIds={record.cnnvd_ids} cveIds={record.cve_ids} collapseAfter={2} />
        ),
    },
    {
      title: '风险等级',
      dataIndex: 'severity',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={RULE_SEVERITY_META} />,
    },
    {
      title: '动作',
      dataIndex: 'action',
      width: 140,
      render: (v: string) => <StatusTag value={v} map={CUSTOM_RULE_ACTION_META} />,
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={ENABLE_STATUS_META} />,
    },
    {
      title: '操作',
      key: 'actions',
      width: 230,
      fixed: 'right',
      render: (_, record) => (
        <Space>
          <Button type="link" size="small" onClick={() => setDetailId(record.id)}>
            详情
          </Button>
          {canManage && (
            <>
              <Button type="link" size="small" onClick={() => openEdit(record)}>
                编辑
              </Button>
              {record.status === 'ENABLED' ? (
                <Button
                  type="link"
                  size="small"
                  onClick={() => statusMutation.mutate({ id: record.id, action: 'disable' })}
                >
                  停用
                </Button>
              ) : (
                <Button
                  type="link"
                  size="small"
                  onClick={() => statusMutation.mutate({ id: record.id, action: 'enable' })}
                >
                  启用
                </Button>
              )}
              <Button type="link" size="small" danger onClick={() => confirmDelete(record)}>
                删除
              </Button>
            </>
          )}
        </Space>
      ),
    },
  ]

  const formFields = (form: typeof createForm, id: string, isCreate: boolean) => (
    <>
      <Form.Item
        name="rule_id"
        label="规则ID"
        rules={[
          { required: true, message: '请输入规则ID' },
          {
            validator: (_, v: number) => {
              if (v === undefined || v === null) return Promise.resolve()
              if (v < RULE_ID_MIN || v > RULE_ID_MAX) {
                return Promise.reject(new Error(`自定义规则ID必须在 ${RULE_ID_MIN}-${RULE_ID_MAX} 之间`))
              }
              return Promise.resolve()
            },
          },
        ]}
        extra={isCreate ? `${RULE_ID_MIN}-${RULE_ID_MAX}，创建后不可修改` : '创建后不可修改'}
      >
        <InputNumber min={RULE_ID_MIN} max={RULE_ID_MAX} style={{ width: '100%' }} disabled={!isCreate} />
      </Form.Item>
      <Form.Item
        name="name"
        label="规则名称"
        rules={[
          { required: true, message: '请输入规则名称' },
          { max: 128, message: '不超过 128 个字符' },
        ]}
      >
        <Input placeholder="如：拦截特定路径的SQL注入尝试" />
      </Form.Item>
      <Form.Item name="description" label="描述">
        <Input.TextArea rows={2} placeholder="规则用途说明（可选）" />
      </Form.Item>
      <Form.Item name="attack_type" label="攻击类型" rules={[{ required: true, message: '请选择攻击类型' }]}>
        <Select showSearch options={ATTACK_TYPE_OPTIONS} placeholder="选择攻击类型" />
      </Form.Item>
      <Form.Item name="severity" label="风险等级" rules={[{ required: true }]}>
        <Select options={SEVERITY_OPTIONS} />
      </Form.Item>
      <Form.Item
        name="phase"
        label="执行阶段"
        rules={[{ required: true }]}
        extra="阶段 2 的阻断规则可能被 CRS 阻断评估抢先而无法触发；期望首命中即拦截的规则建议选阶段 1"
      >
        <Select options={PHASE_OPTIONS} />
      </Form.Item>
      <Form.Item name="operator" label="操作符" rules={[{ required: true, message: '请选择操作符' }]}>
        <Select
          showSearch
          optionFilterProp="label"
          options={OPERATOR_OPTIONS}
          placeholder="选择匹配操作符"
          onChange={() => setValidateResult(null)}
        />
      </Form.Item>
      <Form.Item noStyle shouldUpdate={(prev, cur) => prev.operator !== cur.operator}>
        {({ getFieldValue }) =>
          NO_VALUE_OPERATORS.includes(getFieldValue('operator')) ? null : (
            <Form.Item
              name="operator_value"
              label="匹配内容"
              rules={[{ required: true, message: '请输入匹配内容' }]}
              extra="正则匹配需语法正确；禁止包含命令执行/文件读取等危险内容"
            >
              <Input.TextArea rows={2} placeholder="如：(?i)(union.*select)" autoComplete="off" />
            </Form.Item>
          )
        }
      </Form.Item>
      <Form.Item
        name="target_variables"
        label="检测变量"
        rules={[{ required: true, message: '至少选择一个检测变量' }]}
      >
        <Select mode="multiple" optionFilterProp="label" options={VARIABLE_OPTIONS} placeholder="选择要检测的请求变量" />
      </Form.Item>
      <Form.Item name="action" label="动作" rules={[{ required: true }]}>
        <Select
          options={ACTION_OPTIONS}
          onChange={(v) => {
            // BLOCK 规则默认落到阶段 1：阶段 2 会被 CRS 阻断评估（949110）抢先而永不触发；
            // 仅在用户尚未手动改过阶段（仍为默认 2）时联动，尊重显式选择
            if (v === 'BLOCK' && form.getFieldValue('phase') === 2) {
              form.setFieldValue('phase', 1)
            }
          }}
        />
      </Form.Item>
      <Form.Item name="tags" label="标签">
        <Select mode="tags" open={false} placeholder="输入后回车添加标签（可选）" />
      </Form.Item>
      <Form.Item
        name="cnnvd_ids"
        label="CNNVD 编号"
        rules={[vulnIdsRule(CNNVD_ID_PATTERN, 'CNNVD 编号')]}
        extra="格式 CNNVD-YYYYMM-NNN（如 CNNVD-202401-2345），输入后回车添加，可多个（可选）"
      >
        <Select mode="tags" open={false} placeholder="输入 CNNVD 编号后回车（可选）" />
      </Form.Item>
      <Form.Item
        name="cve_ids"
        label="CVE 编号"
        rules={[vulnIdsRule(CVE_ID_PATTERN, 'CVE 编号')]}
        extra="格式 CVE-YYYY-NNNN（如 CVE-2024-0001），输入后回车添加，可多个（可选）"
      >
        <Select mode="tags" open={false} placeholder="输入 CVE 编号后回车（可选）" />
      </Form.Item>
      <Form.Item label=" " colon={false}>
        <Space direction="vertical" style={{ width: '100%' }}>
          <Button
            icon={<CheckCircleOutlined />}
            loading={validateMutation.isPending}
            onClick={() => runValidate(form, id)}
          >
            校验规则并预览 SecLang
          </Button>
          {validateResult &&
            (validateResult.valid ? (
              <Alert
                type="success"
                showIcon
                message="校验通过"
                description={
                  <pre
                    style={{
                      margin: 0,
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-all',
                      fontFamily: 'monospace',
                      fontSize: 12,
                    }}
                  >
                    {validateResult.generated_rule}
                  </pre>
                }
              />
            ) : (
              <Alert type="error" showIcon message="校验未通过" description={validateResult.error} />
            ))}
        </Space>
      </Form.Item>
    </>
  )

  const detail = detailQuery.data

  return (
    <Card
      title="自定义规则"
      extra={
        canManage && (
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => {
              setValidateResult(null)
              setCreateOpen(true)
            }}
          >
            新建规则
          </Button>
        )
      }
    >
      <Space style={{ marginBottom: 16 }} wrap>
        <Input.Search
          placeholder="搜索规则ID/名称/CNNVD/CVE 编号"
          allowClear
          style={{ width: 280 }}
          onSearch={(v) => {
            const value = v.trim()
            setFilters((f) => {
              // 粘贴完整编号时按前缀识别走精确筛选，其余走关键词
              const next: Filters = { status: f.status }
              if (/^CNNVD-/i.test(value)) next.cnnvd_id = value.toUpperCase()
              else if (/^CVE-/i.test(value)) next.cve_id = value.toUpperCase()
              else if (value) next.keyword = value
              return next
            })
            setPage(1)
          }}
        />
        <Select
          placeholder="状态"
          allowClear
          style={{ width: 130 }}
          options={[
            { value: 'ENABLED', label: '已启用' },
            { value: 'DISABLED', label: '已停用' },
          ]}
          onChange={(v) => {
            setFilters((f) => ({ ...f, status: v }))
            setPage(1)
          }}
        />
        {batchDeleteButton}
      </Space>

      {listQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="加载自定义规则失败"
          description={listQuery.error instanceof ApiError ? listQuery.error.message : undefined}
        />
      ) : (
        <SmartTable<CustomRuleItem>
          storageKey="custom-rules"
          rowKey="id"
          rowSelection={rowSelection}
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          onRow={(record) => ({
            onDoubleClick: () => setDetailId(record.id),
            style: { cursor: 'pointer' },
          })}
          scroll={{ x: 1100 }}
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
      )}

      <Modal
        title="新建自定义规则"
        open={createOpen}
        onCancel={() => {
          setCreateOpen(false)
          setValidateResult(null)
        }}
        onOk={() => createForm.submit()}
        confirmLoading={createMutation.isPending}
        width={640}
        destroyOnHidden
      >
        <Form
          form={createForm}
          layout="vertical"
          initialValues={{
            attack_type: 'OTHER',
            severity: 'WARNING',
            phase: 2,
            operator: 'rx',
            action: 'LOG',
            target_variables: ['ARGS'],
            tags: [],
            cnnvd_ids: [],
            cve_ids: [],
          }}
          onFinish={(values) => {
            createMutation.mutate({
              ...values,
              operator_value: values.operator_value ?? '',
              cnnvd_ids: values.cnnvd_ids ?? [],
              cve_ids: values.cve_ids ?? [],
            })
          }}
        >
          {formFields(createForm, 'new', true)}
        </Form>
      </Modal>

      <Modal
        title={`编辑规则：${editing?.name ?? ''}`}
        open={editing !== null}
        onCancel={() => {
          setEditing(null)
          setValidateResult(null)
        }}
        onOk={() => editForm.submit()}
        confirmLoading={updateMutation.isPending}
        width={640}
        destroyOnHidden
      >
        <Form
          form={editForm}
          layout="vertical"
          onFinish={(values) => {
            if (!editing) return
            updateMutation.mutate({
              id: editing.id,
              body: {
                ...values,
                operator_value: values.operator_value ?? '',
                cnnvd_ids: values.cnnvd_ids ?? [],
                cve_ids: values.cve_ids ?? [],
                version: editing.version,
              },
            })
          }}
        >
          {formFields(editForm, editing?.id ?? 'new', false)}
        </Form>
      </Modal>

      <Drawer
        title="规则详情"
        open={detailId !== null}
        onClose={() => setDetailId(null)}
        width={640}
      >
        {detailQuery.isLoading ? (
          <Typography.Text type="secondary">加载中...</Typography.Text>
        ) : detailQuery.isError ? (
          <Alert
            type="error"
            showIcon
            message="加载规则详情失败"
            description={detailQuery.error instanceof ApiError ? detailQuery.error.message : undefined}
          />
        ) : detail ? (
          <>
            <Descriptions column={2} size="small" bordered style={{ marginBottom: 16 }}>
              <Descriptions.Item label="规则ID">{detail.rule_id}</Descriptions.Item>
              <Descriptions.Item label="名称">{detail.name}</Descriptions.Item>
              <Descriptions.Item label="描述" span={2}>
                {detail.description || '-'}
              </Descriptions.Item>
              <Descriptions.Item label="攻击类型">
                <StatusTag value={detail.attack_type} map={ATTACK_TYPE_META} />
              </Descriptions.Item>
              <Descriptions.Item label="风险等级">
                <StatusTag value={detail.severity} map={RULE_SEVERITY_META} />
              </Descriptions.Item>
              <Descriptions.Item label="执行阶段">{detail.phase}</Descriptions.Item>
              <Descriptions.Item label="动作">
                <StatusTag value={detail.action} map={CUSTOM_RULE_ACTION_META} />
              </Descriptions.Item>
              <Descriptions.Item label="状态">
                <StatusTag value={detail.status} map={ENABLE_STATUS_META} />
              </Descriptions.Item>
              <Descriptions.Item label="作用范围">
                <StatusTag value={detail.scope_type} map={EXCEPTION_SCOPE_META} />
              </Descriptions.Item>
              <Descriptions.Item label="操作符" span={2}>
                {OPERATOR_LABEL_MAP[detail.operator] ?? detail.operator}
              </Descriptions.Item>
              <Descriptions.Item label="匹配内容" span={2}>
                <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
                  {detail.operator_value || '-'}
                </Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label="检测变量" span={2}>
                <Space wrap>
                  {(detail.target_variables ?? []).map((v) => (
                    <Tag key={v}>{CORAZA_VARIABLE_LABELS[v] ?? v}</Tag>
                  ))}
                </Space>
              </Descriptions.Item>
              <Descriptions.Item label="标签" span={2}>
                <Space wrap>
                  {(detail.tags ?? []).length === 0 ? (
                    <Typography.Text type="secondary">无</Typography.Text>
                  ) : (
                    (detail.tags ?? []).map((t) => <Tag key={t}>{t}</Tag>)
                  )}
                </Space>
              </Descriptions.Item>
              <Descriptions.Item label="漏洞编号" span={2}>
                {(detail.cnnvd_ids ?? []).length + (detail.cve_ids ?? []).length === 0 ? (
                  <Typography.Text type="secondary">无</Typography.Text>
                ) : (
                  <Space wrap>
                    <VulnIdTags cnnvdIds={detail.cnnvd_ids} cveIds={detail.cve_ids} linkCnnvd />
                  </Space>
                )}
              </Descriptions.Item>
            </Descriptions>
            <Typography.Title level={5}>生成的 SecLang 规则</Typography.Title>
            <pre
              style={{
                background: '#f5f5f5',
                padding: 12,
                borderRadius: 6,
                fontSize: 12,
                fontFamily: 'monospace',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-all',
              }}
            >
              {detail.generated_rule || '-'}
            </pre>
          </>
        ) : null}
      </Drawer>
    </Card>
  )
}
