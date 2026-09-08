import { useEffect, useState } from 'react'
import { App as AntdApp, Button, Card, Form, Input, Tabs, Typography } from 'antd'
import { SearchOutlined } from '@ant-design/icons'
import { useSearchParams } from 'react-router-dom'
import { ApiError } from '../../../api/client'
import { aiAnalyzeApi } from '../../../api/ai'
import type { AiAnalyzeResult } from '../../../api/ai'
import AnalyzeResultView from '../../../components/ai/AnalyzeResultView'
import RemediationCard from '../../../components/RemediationCard'
import { useAuthStore } from '../../../stores/auth'
import { hasPermission } from '../../../utils/permission'

/** 事件分析：输入事件 ID（或自然语言问题）发起 AI 分析；附误报研判入口 */
export default function EventAnalysisPage() {
  const { message } = AntdApp.useApp()
  const [searchParams] = useSearchParams()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canFalsePositive = hasPermission(permissions, 'ai.false_positive_analysis.use')

  const [eventForm] = Form.useForm<{ event_id?: string; question?: string }>()
  const [fpForm] = Form.useForm<{ event_id?: string; rule_id?: number }>()
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<AiAnalyzeResult | null>(null)
  const [lastEventId, setLastEventId] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState(searchParams.get('tab') === 'fp' ? 'fp' : 'event')

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
    if (!eventId && !question) {
      message.warning('请输入事件 ID 或分析问题')
      return
    }
    setLastEventId(eventId || null)
    await run(() => aiAnalyzeApi.event({ event_id: eventId || undefined, question: question || undefined }))
  }

  const onFpAnalyze = async () => {
    const v = fpForm.getFieldsValue()
    const eventId = v.event_id?.trim()
    if (!eventId && !v.rule_id) {
      message.warning('请输入事件 ID 或规则 ID')
      return
    }
    setLastEventId(eventId || null)
    await run(() =>
      aiAnalyzeApi.falsePositive({ event_id: eventId || undefined, rule_id: v.rule_id || undefined }),
    )
  }

  return (
    <Card title="事件分析">
      <Typography.Paragraph type="secondary">
        对安全事件进行 AI 分析，给出攻击类型、命中规则、风险等级、是否阻断与排查建议；所有结论附证据引用。
      </Typography.Paragraph>
      <Tabs
        activeKey={activeTab}
        onChange={setActiveTab}
        items={[
          {
            key: 'event',
            label: '事件分析',
            children: (
              <Form form={eventForm} layout="inline" style={{ rowGap: 8 }}>
                <Form.Item name="event_id" label="事件 ID">
                  <Input placeholder="安全事件 UUID" style={{ width: 360 }} allowClear />
                </Form.Item>
                <Form.Item name="question" label="分析问题">
                  <Input placeholder="可选，如：分析今天 ERP 应用的攻击" style={{ width: 320 }} allowClear />
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
                        <Input type="number" placeholder="如 942100（可选）" style={{ width: 180 }} allowClear />
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
