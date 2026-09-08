import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Col,
  Descriptions,
  Drawer,
  Form,
  Input,
  InputNumber,
  List,
  Popconfirm,
  Row,
  Select,
  Space,
  Statistic,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { PlusOutlined, SyncOutlined } from '@ant-design/icons'
import { ApiError } from '../../api/client'
import { applicationsApi } from '../../api/applications'
import { protectionPoliciesApi } from '../../api/protectionPolicies'
import { ruleOverridesApi } from '../../api/ruleOverrides'
import { securityEventsApi } from '../../api/securityEvents'
import { wafRulesApi } from '../../api/wafRules'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { ruleNameZh } from '../../utils/crsRuleNames'
import { hasPermission } from '../../utils/permission'
import {
  ATTACK_TYPE_META,
  parseWafRuleTags,
  RULE_DEFAULT_STATE_META,
  RULE_SEVERITY_META,
  RULE_SOURCE_META,
} from '../../utils/stage4'
import type { WafRuleItem } from '../../types'

interface Filters {
  rule_id?: number
  keyword?: string
  attack_type?: string
  severity?: string
  rule_source?: string
  tag?: string
}

const SEVERITY_OPTIONS = Object.entries(RULE_SEVERITY_META).map(([value, meta]) => ({
  value,
  label: `${meta.label}（${value}）`,
}))

export default function WafRulesPage() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)

  const [filters, setFilters] = useState<Filters>({})
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [detailRuleId, setDetailRuleId] = useState<number | null>(null)
  // 规则 ID 筛选为本地输入态，回车/失焦才提交查询（与同页 Input.Search 纪律一致，避免逐字符触发）
  const [ruleIdInput, setRuleIdInput] = useState<number | null>(null)

  const commitRuleId = () => {
    const next = ruleIdInput ?? undefined
    if (filters.rule_id === next) return
    setFilters((f) => ({ ...f, rule_id: next }))
    setPage(1)
  }

  const listQuery = useQuery({
    queryKey: ['waf-rules', filters, page, pageSize],
    queryFn: () => wafRulesApi.list({ ...filters, page, page_size: pageSize }),
  })

  const categoriesQuery = useQuery({
    queryKey: ['waf-rules', 'categories'],
    queryFn: () => wafRulesApi.categories(),
  })

  const versionsQuery = useQuery({
    queryKey: ['waf-rules', 'versions'],
    queryFn: () => wafRulesApi.versions(),
  })

  const detailQuery = useQuery({
    queryKey: ['waf-rule', detailRuleId],
    queryFn: () => wafRulesApi.get(detailRuleId as number),
    enabled: detailRuleId !== null,
  })

  const effectStatsQuery = useQuery({
    queryKey: ['waf-rule-effect-stats', detailRuleId],
    queryFn: () =>
      securityEventsApi.ruleEffectStatistics({
        rule_id: detailRuleId as number,
        page: 1,
        page_size: 30,
      }),
    enabled: detailRuleId !== null,
  })

  const canManageOverride = hasPermission(permissions, 'rule_overrides.manage')

  const overridesQuery = useQuery({
    queryKey: ['rule-overrides', detailRuleId],
    queryFn: () =>
      ruleOverridesApi.list({ rule_id: detailRuleId as number, page: 1, page_size: 50 }),
    enabled: detailRuleId !== null && canManageOverride,
  })

  const appsForOverride = useQuery({
    queryKey: ['applications', 'for-override'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
    enabled: canManageOverride,
  })

  const policiesForOverride = useQuery({
    queryKey: ['protection-policies', 'for-override'],
    queryFn: () => protectionPoliciesApi.list({ page: 1, page_size: 100 }),
    enabled: canManageOverride,
  })

  const [overrideForm] = Form.useForm()

  const createOverrideMut = useMutation({
    mutationFn: ruleOverridesApi.create,
    onSuccess: (r) => {
      message.success(r.message || '覆盖已创建，请发布配置后生效')
      overrideForm.resetFields()
      void queryClient.invalidateQueries({ queryKey: ['rule-overrides', detailRuleId] })
    },
    onError: (e: unknown) => {
      message.error(e instanceof ApiError ? e.message : '创建覆盖失败')
    },
  })

  const deleteOverrideMut = useMutation({
    mutationFn: (id: string) => ruleOverridesApi.remove(id),
    onSuccess: (r) => {
      message.success(r.message || '已删除')
      void queryClient.invalidateQueries({ queryKey: ['rule-overrides', detailRuleId] })
    },
    onError: (e: unknown) => {
      message.error(e instanceof ApiError ? e.message : '删除失败')
    },
  })

  const syncMutation = useMutation({
    mutationFn: () => wafRulesApi.sync(),
    onSuccess: (r) => {
      modal.info({
        title: '规则集同步完成',
        width: 520,
        content: (
          <div>
            <p>
              解析 {r.total_parsed} 条，库中共 {r.total_in_db} 条：新增 {r.added}、更新 {r.updated}、
              未变 {r.unchanged}、缺失 {r.missing}、解析失败 {r.parse_failed}、冲突 {r.conflicts}
            </p>
            {(r.failed_rules ?? []).length > 0 && (
              <Typography.Paragraph
                style={{ fontFamily: 'monospace', fontSize: 12, maxHeight: 200, overflow: 'auto' }}
              >
                失败规则：{(r.failed_rules ?? []).join('、')}
              </Typography.Paragraph>
            )}
          </div>
        ),
      })
      void queryClient.invalidateQueries({ queryKey: ['waf-rules'] })
    },
    onError: (e) => {
      message.error(e instanceof ApiError ? e.message : '同步失败')
    },
  })

  const columns: ColumnsType<WafRuleItem> = [
    {
      title: '规则ID',
      dataIndex: 'rule_id',
      width: 110,
      render: (v: number) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: '名称',
      dataIndex: 'name',
      ellipsis: true,
      render: (v: string, record) => (
        <Button
          type="link"
          size="small"
          style={{ padding: 0, height: 'auto' }}
          title={v}
          onClick={() => setDetailRuleId(record.rule_id)}
        >
          {ruleNameZh(record) || '-'}
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
      title: '风险等级',
      dataIndex: 'severity',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={RULE_SEVERITY_META} />,
    },
    {
      title: '来源',
      dataIndex: 'rule_source',
      width: 130,
      render: (v: string) => <StatusTag value={v} map={RULE_SOURCE_META} />,
    },
    { title: '阶段', dataIndex: 'phase', width: 70, align: 'center' },
    {
      title: '默认状态',
      dataIndex: 'default_state',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={RULE_DEFAULT_STATE_META} />,
    },
    { title: '规则集版本', dataIndex: 'crs_version', width: 100 },
    {
      title: '操作',
      key: 'actions',
      width: 80,
      fixed: 'right',
      render: (_, record) => (
        <Button type="link" size="small" onClick={() => setDetailRuleId(record.rule_id)}>
          详情
        </Button>
      ),
    },
  ]

  const categories = categoriesQuery.data?.items ?? []
  const totalRules = categories.reduce((sum, c) => sum + c.count, 0)
  const detail = detailQuery.data
  const detailTags = detail ? parseWafRuleTags(detail.tags) : []

  return (
    <Card
      title="防护规则库"
      extra={
        <Space>
          {(versionsQuery.data?.versions ?? []).length > 0 && (
            <Typography.Text type="secondary">
              CRS 版本：{(versionsQuery.data?.versions ?? []).join('、')}
            </Typography.Text>
          )}
          {hasPermission(permissions, 'waf_rules.sync') && (
            <Button
              type="primary"
              icon={<SyncOutlined />}
              loading={syncMutation.isPending}
              onClick={() => syncMutation.mutate()}
            >
              同步CRS规则
            </Button>
          )}
        </Space>
      }
    >
      <Row gutter={16} style={{ marginBottom: 16 }}>
        <Col span={4}>
          <Card size="small">
            <Statistic title="规则总数" value={totalRules} loading={categoriesQuery.isLoading} />
          </Card>
        </Col>
        {categories.slice(0, 5).map((c) => (
          <Col span={4} key={c.attack_type}>
            <Card size="small">
              <Statistic
                title={ATTACK_TYPE_META[c.attack_type]?.label ?? c.attack_type}
                value={c.count}
                loading={categoriesQuery.isLoading}
              />
            </Card>
          </Col>
        ))}
      </Row>

      <Space style={{ marginBottom: 16 }} wrap>
        <InputNumber
          placeholder="规则ID（回车生效）"
          style={{ width: 160 }}
          min={1}
          value={ruleIdInput}
          onChange={(v) => setRuleIdInput(v)}
          onPressEnter={commitRuleId}
          onBlur={commitRuleId}
        />
        <Input.Search
          placeholder="搜索名称或描述"
          allowClear
          style={{ width: 220 }}
          onSearch={(v) => {
            setFilters((f) => ({ ...f, keyword: v || undefined }))
            setPage(1)
          }}
        />
        <Select
          placeholder="攻击类型"
          allowClear
          showSearch
          style={{ width: 200 }}
          options={categories.map((c) => ({
            value: c.attack_type,
            label: `${ATTACK_TYPE_META[c.attack_type]?.label ?? c.attack_type}（${c.count}）`,
          }))}
          onChange={(v) => {
            setFilters((f) => ({ ...f, attack_type: v }))
            setPage(1)
          }}
        />
        <Select
          placeholder="风险等级"
          allowClear
          style={{ width: 150 }}
          options={SEVERITY_OPTIONS}
          onChange={(v) => {
            setFilters((f) => ({ ...f, severity: v }))
            setPage(1)
          }}
        />
        <Select
          placeholder="来源"
          allowClear
          style={{ width: 150 }}
          options={Object.entries(RULE_SOURCE_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => {
            setFilters((f) => ({ ...f, rule_source: v }))
            setPage(1)
          }}
        />
        <Input.Search
          placeholder="标签（如 attack-sqli）"
          allowClear
          style={{ width: 180 }}
          onSearch={(v) => {
            setFilters((f) => ({ ...f, tag: v || undefined }))
            setPage(1)
          }}
        />
      </Space>

      {listQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="加载防护规则失败"
          description={listQuery.error instanceof ApiError ? listQuery.error.message : undefined}
        />
      ) : (
        <SmartTable<WafRuleItem>
          storageKey="waf-rules"
          rowKey="id"
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          onRow={(record) => ({
            onDoubleClick: () => setDetailRuleId(record.rule_id),
            style: { cursor: 'pointer' },
          })}
          scroll={{ x: 1150 }}
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

      <Drawer
        title={`规则详情：${detail?.rule_id ?? detailRuleId ?? ''}`}
        open={detailRuleId !== null}
        onClose={() => setDetailRuleId(null)}
        width={560}
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
              <Descriptions.Item label="来源">
                <StatusTag value={detail.rule_source} map={RULE_SOURCE_META} />
              </Descriptions.Item>
              <Descriptions.Item label="中文名称" span={2}>
                {ruleNameZh(detail) || '-'}
              </Descriptions.Item>
              <Descriptions.Item label="名称" span={2}>
                {detail.name || '-'}
              </Descriptions.Item>
              <Descriptions.Item label="规则消息" span={2}>
                {detail.message || '-'}
              </Descriptions.Item>
              <Descriptions.Item label="攻击类型">
                <StatusTag value={detail.attack_type} map={ATTACK_TYPE_META} />
              </Descriptions.Item>
              <Descriptions.Item label="风险等级">
                <StatusTag value={detail.severity} map={RULE_SEVERITY_META} />
              </Descriptions.Item>
              <Descriptions.Item label="执行阶段">{detail.phase}</Descriptions.Item>
              <Descriptions.Item label="默认状态">
                <StatusTag value={detail.default_state} map={RULE_DEFAULT_STATE_META} />
              </Descriptions.Item>
              <Descriptions.Item label="规则文件" span={2}>
                <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
                  {detail.file_name || '-'}
                </Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label="规则集版本">{detail.crs_version || '-'}</Descriptions.Item>
            </Descriptions>
            <Typography.Title level={5}>标签（{detailTags.length}）</Typography.Title>
            <Space wrap>
              {detailTags.length === 0 ? (
                <Typography.Text type="secondary">无标签</Typography.Text>
              ) : (
                detailTags.map((t) => <Tag key={t}>{t}</Tag>)
              )}
            </Space>

            <Typography.Title level={5} style={{ marginTop: 24 }}>
              规则效果（按日）
            </Typography.Title>
            {effectStatsQuery.isError ? (
              <Alert
                type="warning"
                showIcon
                message="规则效果统计暂不可用"
                description={
                  effectStatsQuery.error instanceof ApiError
                    ? effectStatsQuery.error.message
                    : '请稍后重试'
                }
              />
            ) : (
              <List
                size="small"
                bordered
                loading={effectStatsQuery.isLoading}
                locale={{ emptyText: '暂无统计（异步聚合任务运行后显示）' }}
                dataSource={effectStatsQuery.data?.items ?? []}
                renderItem={(item) => {
                  const confirmationRate =
                    item.confirmation_rate == null
                      ? '—'
                      : `${(item.confirmation_rate * 100).toFixed(1)}%`
                  const fpRate = item.fp_rate == null ? '—' : `${(item.fp_rate * 100).toFixed(1)}%`
                  return (
                    <List.Item>
                      <Space direction="vertical" size={0} style={{ width: '100%' }}>
                        <Space wrap>
                          <Tag>{item.date.slice(0, 10)}</Tag>
                          <Typography.Text>命中 {item.hits}</Typography.Text>
                          <Typography.Text>阻断 {item.blocks}</Typography.Text>
                          <Typography.Text>确认攻击 {item.confirmed_attacks}</Typography.Text>
                          <Typography.Text>确认误报 {item.false_positives}</Typography.Text>
                          <Typography.Text>已研判 {item.reviewed}</Typography.Text>
                          <Typography.Text>未确认 {item.unresolved}</Typography.Text>
                          {item.protect_recommendation ? (
                            <Tag color="green">建议人工评估 PROTECT</Tag>
                          ) : null}
                        </Space>
                        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                          确认率 {confirmationRate} · 误报率 {fpRate}
                        </Typography.Text>
                        {item.protect_recommendation_reason ? (
                          <Typography.Text type="success" style={{ fontSize: 12 }}>
                            {item.protect_recommendation_reason}
                          </Typography.Text>
                        ) : null}
                      </Space>
                    </List.Item>
                  )
                }}
              />
            )}

            {canManageOverride && (
              <>
                <Typography.Title level={5} style={{ marginTop: 24 }}>
                  规则覆盖
                </Typography.Title>
                <Typography.Paragraph type="secondary">
                  优先级：应用级 &gt; 策略级 &gt; 全局。DISABLE 发布后通过 ctl:ruleRemoveById
                  停用该 CRS 规则；修改后需配置发布生效。
                </Typography.Paragraph>
                <List
                  size="small"
                  bordered
                  loading={overridesQuery.isLoading}
                  locale={{ emptyText: '暂无覆盖' }}
                  dataSource={overridesQuery.data?.items ?? []}
                  style={{ marginBottom: 16 }}
                  renderItem={(item) => (
                    <List.Item
                      actions={[
                        <Popconfirm
                          key="del"
                          title="删除此覆盖？"
                          onConfirm={() => deleteOverrideMut.mutate(item.id)}
                        >
                          <Button type="link" size="small" danger>
                            删除
                          </Button>
                        </Popconfirm>,
                      ]}
                    >
                      <Space wrap>
                        <Tag color={item.action === 'DISABLE' ? 'red' : 'green'}>{item.action}</Tag>
                        <Tag>{item.scope_type}</Tag>
                        {item.scope_id && (
                          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                            {item.scope_id.slice(0, 8)}…
                          </Typography.Text>
                        )}
                        {item.reason && <Typography.Text>{item.reason}</Typography.Text>}
                      </Space>
                    </List.Item>
                  )}
                />
                <Form
                  form={overrideForm}
                  layout="vertical"
                  initialValues={{ scope_type: 'GLOBAL', action: 'DISABLE' }}
                  onFinish={(values) => {
                    createOverrideMut.mutate({
                      rule_id: detail.rule_id,
                      scope_type: values.scope_type,
                      scope_id:
                        values.scope_type === 'GLOBAL' ? undefined : (values.scope_id as string),
                      action: values.action,
                      reason: values.reason ?? '',
                    })
                  }}
                >
                  <Form.Item name="action" label="动作" rules={[{ required: true }]}>
                    <Select
                      options={[
                        { value: 'DISABLE', label: '停用规则' },
                        { value: 'ENABLE', label: '启用（覆盖下层停用）' },
                      ]}
                    />
                  </Form.Item>
                  <Form.Item name="scope_type" label="生效范围" rules={[{ required: true }]}>
                    <Select
                      options={[
                        { value: 'GLOBAL', label: '全局' },
                        { value: 'POLICY', label: '防护策略' },
                        { value: 'APPLICATION', label: '应用' },
                      ]}
                    />
                  </Form.Item>
                  <Form.Item noStyle shouldUpdate={(a, b) => a.scope_type !== b.scope_type}>
                    {() => {
                      const st = overrideForm.getFieldValue('scope_type') as string
                      if (st === 'POLICY') {
                        return (
                          <Form.Item
                            name="scope_id"
                            label="防护策略"
                            rules={[{ required: true, message: '请选择策略' }]}
                          >
                            <Select
                              showSearch
                              optionFilterProp="label"
                              options={(policiesForOverride.data?.items ?? []).map((p) => ({
                                value: p.id,
                                label: `${p.name} (${p.code})`,
                              }))}
                            />
                          </Form.Item>
                        )
                      }
                      if (st === 'APPLICATION') {
                        return (
                          <Form.Item
                            name="scope_id"
                            label="应用"
                            rules={[{ required: true, message: '请选择应用' }]}
                          >
                            <Select
                              showSearch
                              optionFilterProp="label"
                              options={(appsForOverride.data?.items ?? []).map((a) => ({
                                value: a.id,
                                label: `${a.name} (${a.code})`,
                              }))}
                            />
                          </Form.Item>
                        )
                      }
                      return null
                    }}
                  </Form.Item>
                  <Form.Item name="reason" label="原因">
                    <Input.TextArea rows={2} placeholder="如：业务 API 误报，临时关闭该规则" />
                  </Form.Item>
                  <Button
                    type="primary"
                    icon={<PlusOutlined />}
                    htmlType="submit"
                    loading={createOverrideMut.isPending}
                  >
                    添加覆盖
                  </Button>
                </Form>
              </>
            )}
          </>
        ) : null}
      </Drawer>
    </Card>
  )
}
