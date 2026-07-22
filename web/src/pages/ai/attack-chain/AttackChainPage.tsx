import { useState } from 'react'
import { App as AntdApp, Button, Card, Form, Input, Steps, Tabs, Typography } from 'antd'
import { SearchOutlined } from '@ant-design/icons'
import { ApiError } from '../../../api/client'
import { aiAnalyzeApi } from '../../../api/ai'
import type { AiAnalyzeResult, AiSseEvent } from '../../../api/ai'
import AnalyzeResultView from '../../../components/ai/AnalyzeResultView'
import { AI_AGENT_NAMES, visibleSteps } from '../../../utils/ai'

type ChainStepItem = {
  title: string
  description?: string
  status: 'finish' | 'error'
}

/** 将过程事件映射为纵向 Steps：plan→任务规划，agent_start→执行 xxx，agent_done→xxx 完成，error→错误 */
function toChainItems(events?: AiSseEvent[] | null): ChainStepItem[] {
  return visibleSteps(events ?? []).map((e) => {
    const name = e.text ? (AI_AGENT_NAMES[e.text] ?? e.text) : ''
    switch (e.type) {
      case 'plan':
        return { title: '任务规划', description: e.text, status: 'finish' }
      case 'agent_start':
        return { title: `执行 ${name || 'Agent'}`, status: 'finish' }
      case 'agent_done':
        return { title: `${name || 'Agent'} 完成`, status: 'finish' }
      case 'error':
        return { title: '执行出错', description: e.text, status: 'error' }
      default:
        return { title: e.text || e.type, status: 'finish' }
    }
  })
}

/** 攻击链分析：按攻击源 IP 或安全事件还原攻击链阶段与关键节点 */
export default function AttackChainPage() {
  const { message } = AntdApp.useApp()
  const [ipForm] = Form.useForm<{ ip?: string }>()
  const [eventForm] = Form.useForm<{ event_id?: string }>()
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<AiAnalyzeResult | null>(null)

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

  const onIpAnalyze = async () => {
    const ip = ipForm.getFieldsValue().ip?.trim()
    if (!ip) {
      message.warning('请输入 IP 地址')
      return
    }
    await run(() => aiAnalyzeApi.attackChain({ ip }))
  }

  const onEventAnalyze = async () => {
    const eventId = eventForm.getFieldsValue().event_id?.trim()
    if (!eventId) {
      message.warning('请输入事件 ID')
      return
    }
    await run(() => aiAnalyzeApi.attackChain({ event_id: eventId }))
  }

  const chainItems = toChainItems(result?.steps)

  return (
    <Card title="攻击链分析">
      <Typography.Paragraph type="secondary">
        还原攻击者从侦察探测、漏洞利用到横向移动的攻击链阶段，定位关键节点与受影响资产；攻击链阶段、置信度与排查建议见下方回答。AI
        结论需人工复核后方可作为处置依据。
      </Typography.Paragraph>
      <Tabs
        items={[
          {
            key: 'ip',
            label: '按 IP 分析',
            children: (
              <Form form={ipForm} layout="inline" style={{ rowGap: 8 }}>
                <Form.Item name="ip" label="IP 地址" required>
                  <Input placeholder="攻击源 IP，如 203.0.113.10" style={{ width: 320 }} allowClear />
                </Form.Item>
                <Form.Item>
                  <Button
                    type="primary"
                    icon={<SearchOutlined />}
                    loading={loading}
                    onClick={() => void onIpAnalyze()}
                  >
                    开始分析
                  </Button>
                </Form.Item>
              </Form>
            ),
          },
          {
            key: 'event',
            label: '按事件 ID 分析',
            children: (
              <Form form={eventForm} layout="inline" style={{ rowGap: 8 }}>
                <Form.Item name="event_id" label="事件 ID" required>
                  <Input placeholder="安全事件 UUID" style={{ width: 360 }} allowClear />
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
        ]}
      />
      {loading && (
        <Typography.Paragraph type="secondary" style={{ marginTop: 16 }}>
          AI 正在分析，通常需要数秒到数十秒，请稍候...
        </Typography.Paragraph>
      )}
      {result && (
        <>
          {chainItems.length > 0 && (
            <Card size="small" title="分析链路" style={{ marginTop: 16 }}>
              <Steps direction="vertical" size="small" items={chainItems} />
            </Card>
          )}
          <AnalyzeResultView result={result} />
        </>
      )}
    </Card>
  )
}
