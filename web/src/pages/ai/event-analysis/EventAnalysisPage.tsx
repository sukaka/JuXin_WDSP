import { useEffect, useState } from 'react'
import { App as AntdApp, Button, Card, Form, Input, InputNumber, Select, Tabs, Typography } from 'antd'
import { SearchOutlined } from '@ant-design/icons'
import { useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ApiError } from '../../../api/client'
import { aiAnalyzeApi } from '../../../api/ai'
import type { AiAnalyzeBody, AiAnalyzeResult } from '../../../api/ai'
import { applicationsApi } from '../../../api/applications'
import AnalyzeResultView from '../../../components/ai/AnalyzeResultView'
import RemediationCard from '../../../components/RemediationCard'
import { useAuthStore } from '../../../stores/auth'
import { parsePositiveRuleId } from '../../../utils/ai'
import { hasPermission } from '../../../utils/permission'

/** 结构化统计区间选项（与后端 time_range 白名单一致） */
const TIME_RANGE_OPTIONS = [
  { value: '1h', label: '近 1 小时' },
  { value: '6h', label: '近 6 小时' },
  { value: '24h', label: '近 24 小时' },
  { value: '7d', label: '近 7 天' },
  { value: '30d', label: '近 30 天' },
]

interface EventFormValues {
  event_id?: string
  question?: string
  time_range?: string
  application_id?: string
  ip?: string
  uri?: string
  rule_id?: number
  request_id?: string
}

/** 事件分析：输入事件 ID / 结构化过滤维度（或自然语言问题）发起 AI 分析；附误报研判入口 */
export default function EventAnalysisPage() {
  const { message } = AntdApp.useApp()
  const [searchParams] = useSearchParams()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canFalsePositive = hasPermission(permissions, 'ai.false_positive_analysis.use')

  const [eventForm] = Form.useForm<EventFormValues>()
  const [fpForm] = Form.useForm<{ event_id?: string; rule_id?: number }>()
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<AiAnalyzeResult | null>(null)
  const [lastEventId, setLastEventId] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState(searchParams.get('tab') === 'fp' ? 'fp' : 'event')

  // 结构化过滤的应用下拉（非关键控件，无权限时降级为手输 UUID）
  const appsQuery = useQuery({
    queryKey: ['applications', 'all-for-ai-event-analysis'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
    retry: false,
  })

  // 安全事件详情一键带入 event_id
  useEffect(() => {
    const eid = searchParams.get('event_id')?.trim()
    if (!eid) return
    eventForm.setFieldsValue({ event_id: eid })
    fpForm.setFieldsValue({ event_id: eid })
    if (searchParams.get('tab') === 'fp') setActiveTab('fp')
  }, [searchParams, eventForm, fpForm])

  const run = async (fn: () => Promise<AiAnalyzeResult>) => {
    setLoading(true)
    setResult(null)
    try {
      setResult(await fn())
    } catch (e) {
      message.error(e instanceof ApiError ? e.message : '分析执行失败')
    } finally {
      setLoading(false)
    }
  }

  const onEventAnalyze = async () => {
    const v = eventForm.getFieldsValue()
    const eventId = v.event_id?.trim()
    const question = v.question?.trim()
    const parsedRule = parsePositiveRuleId(v.rule_id)
    if (!parsedRule.valid) {
      message.warning('规则 ID 须为正整数')
      return
    }
    const body: AiAnalyzeBody = {
      event_id: eventId || undefined,
      question: question || undefined,
      time_range: v.time_range || undefined,
      application_id: v.application_id || undefined,
      ip: v.ip?.trim() || undefined,
      uri: v.uri?.trim() || undefined,
      rule_id: parsedRule.value,
      request_id: v.request_id?.trim() || undefined,
    }
    const hasFilter = body.application_id || body.ip || body.uri || body.rule_id || body.request_id
    if (!eventId && !question && !hasFilter) {
      message.warning('请输入事件 ID、至少一个过滤维度或分析问题')
      return
    }
    setLastEventId(eventId || null)
    await run(() => aiAnalyzeApi.event(body))
  }

  const onFpAnalyze = async () => {
    const v = fpForm.getFieldsValue()
    const eventId = v.event_id?.trim()
    const parsedRule = parsePositiveRuleId(v.rule_id)
    if (!parsedRule.valid) {
      message.warning('规则 ID 须为正整数')
      return
    }
    const ruleId = parsedRule.value
    if (!eventId && ruleId === undefined) {
      message.warning('请输入事件 ID 或规则 ID')
      return
    }
    setLastEventId(eventId || null)
    await run(() =>
      aiAnalyzeApi.falsePositive({ event_id: eventId || undefined, rule_id: ruleId }),
    )
  }

  return (
    <Card title="事件分析">
      <Typography.Paragraph type="secondary">
        对安全事件进行 AI 分析，给出攻击类型、命中规则、风险等级、是否阻断与排查建议；所有结论附证据引用。
        支持按时间范围、应用、IP、URI、规则、请求 ID 维度组合检索真实事件数据后分析。
      </Typography.Paragraph>
      <Tabs
        activeKey={activeTab}
        onChange={setActiveTab}
        items={[
          {
            key: 'event',
            label: '事件分析',
            children: (
              <Form form={eventForm} layout="inline" style={{ rowGap: 8 }} initialValues={{ time_range: '24h' }}>
                <Form.Item name="event_id" label="事件 ID">
                  <Input placeholder="安全事件 UUID" style={{ width: 300 }} allowClear />
                </Form.Item>
                <Form.Item name="question" label="分析问题">
                  <Input placeholder="可选，如：分析今天 ERP 应用的攻击" style={{ width: 280 }} allowClear />
                </Form.Item>
                <Form.Item name="time_range" label="时间范围">
                  <Select style={{ width: 130 }} options={TIME_RANGE_OPTIONS} />
                </Form.Item>
                <Form.Item name="application_id" label="应用">
                  <Select
                    placeholder="全部应用"
                    allowClear
                    showSearch
                    optionFilterProp="label"
                    style={{ width: 200 }}
                    loading={appsQuery.isLoading}
                    options={(appsQuery.data?.items ?? []).map((a) => ({
                      value: a.id,
                      label: `${a.name}（${a.code}）`,
                    }))}
                  />
                </Form.Item>
                <Form.Item name="ip" label="IP">
                  <Input placeholder="客户端 IP" style={{ width: 150 }} allowClear />
                </Form.Item>
                <Form.Item name="uri" label="URI">
                  <Input placeholder="如 /api/login" style={{ width: 170 }} allowClear />
                </Form.Item>
                <Form.Item name="rule_id" label="规则 ID">
                  <InputNumber placeholder="如 942100" style={{ width: 130 }} min={1} precision={0} />
                </Form.Item>
                <Form.Item name="request_id" label="请求 ID">
                  <Input placeholder="网关请求 ID" style={{ width: 200 }} allowClear />
                </Form.Item>
                <Form.Item>
                  <Button
                    type="primary"
                    icon={<SearchOutlined />}
                    loading={loading}
                    onClick={() => void onEventAnalyze()}
                  >
                    开始分析
                  </Button>
                </Form.Item>
              </Form>
            ),
          },
          ...(canFalsePositive
            ? [
                {
                  key: 'false-positive',
                  label: '误报研判',
                  children: (
                    <Form form={fpForm} layout="inline" style={{ rowGap: 8 }}>
                      <Form.Item name="event_id" label="事件 ID">
                        <Input placeholder="安全事件 UUID（可选）" style={{ width: 320 }} allowClear />
                      </Form.Item>
                      <Form.Item name="rule_id" label="规则 ID">
                        <InputNumber placeholder="如 942100（可选）" style={{ width: 180 }} min={1} precision={0} />
                      </Form.Item>
                      <Form.Item>
                        <Button
                          type="primary"
                          icon={<SearchOutlined />}
                          loading={loading}
                          onClick={() => void onFpAnalyze()}
                        >
                          开始研判
                        </Button>
                      </Form.Item>
                    </Form>
                  ),
                },
              ]
            : []),
        ]}
      />
      {loading && (
        <Typography.Paragraph type="secondary" style={{ marginTop: 16 }}>
          AI 正在分析，通常需要数秒到数十秒，请稍候...
        </Typography.Paragraph>
      )}
      {result && <AnalyzeResultView result={result} />}
      {result && lastEventId && <RemediationCard eventId={lastEventId} />}
    </Card>
  )
}
