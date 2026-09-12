import { useState } from 'react'
import { App as AntdApp, Button, Card, Form, Input, Select, Tabs, Typography } from 'antd'
import { SearchOutlined } from '@ant-design/icons'
import { ApiError } from '../../../api/client'
import { aiAnalyzeApi } from '../../../api/ai'
import type { AiAnalyzeResult } from '../../../api/ai'
import AnalyzeResultView from '../../../components/ai/AnalyzeResultView'
import { useAuthStore } from '../../../stores/auth'
import { hasPermission } from '../../../utils/permission'

/** 报告总结：按统计周期生成安全运营摘要；附根因分析次要入口（需 ai.root_cause.use 权限） */
export default function ReportSummaryPage() {
  const { message } = AntdApp.useApp()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canRootCause = hasPermission(permissions, 'ai.root_cause.use')

  const [summaryForm] = Form.useForm<{ period?: string; question?: string }>()
  const [rcForm] = Form.useForm<{ question?: string }>()
  const [summaryLoading, setSummaryLoading] = useState(false)
  const [summaryResult, setSummaryResult] = useState<AiAnalyzeResult | null>(null)
  const [rcLoading, setRcLoading] = useState(false)
  const [rcResult, setRcResult] = useState<AiAnalyzeResult | null>(null)

  const onSummary = async () => {
    const v = summaryForm.getFieldsValue()
    const period = v.period || '近7天'
    const question = v.question?.trim()
    setSummaryLoading(true)
    setSummaryResult(null)
    try {
      setSummaryResult(
        await aiAnalyzeApi.reportSummary({ period, question: question || undefined }),
      )
    } catch (e) {
      message.error(e instanceof ApiError ? e.message : '分析执行失败')
    } finally {
      setSummaryLoading(false)
    }
  }

  const onRootCause = async () => {
    const question = rcForm.getFieldsValue().question?.trim() || '当前系统运行状态'
    setRcLoading(true)
    setRcResult(null)
    try {
      setRcResult(await aiAnalyzeApi.rootCause({ question }))
    } catch (e) {
      message.error(e instanceof ApiError ? e.message : '分析执行失败')
    } finally {
      setRcLoading(false)
    }
  }

  const loadingHint = (
    <Typography.Paragraph type="secondary" style={{ marginTop: 16 }}>
      AI 正在分析，通常需要数秒到数十秒，请稍候...
    </Typography.Paragraph>
  )

  return (
    <Card title="报告总结">
      <Typography.Paragraph type="secondary">
        按统计周期汇总攻击态势、拦截效果与风险趋势，生成可用于安全运营汇报的摘要；所有结论附证据引用，AI
        结论需人工复核。
      </Typography.Paragraph>
      <Tabs
        items={[
          {
            key: 'summary',
            label: '报告总结',
            children: (
              <>
                <Form form={summaryForm} layout="inline" style={{ rowGap: 8 }}>
                  <Form.Item name="period" label="统计周期" initialValue="近7天">
                    <Select
                      style={{ width: 140 }}
                      options={[
                        { value: '今天', label: '今天' },
                        { value: '近7天', label: '近7天' },
                        { value: '近30天', label: '近30天' },
                      ]}
                    />
                  </Form.Item>
                  <Form.Item name="question" label="补充说明">
                    <Input
                      placeholder="可选，如：重点关注 ERP 应用的拦截情况"
                      style={{ width: 320 }}
                      allowClear
                    />
                  </Form.Item>
                  <Form.Item>
                    <Button
                      type="primary"
                      icon={<SearchOutlined />}
                      loading={summaryLoading}
                      onClick={() => void onSummary()}
                    >
                      生成总结
                    </Button>
                  </Form.Item>
                </Form>
                {summaryLoading && loadingHint}
                {summaryResult && <AnalyzeResultView result={summaryResult} />}
              </>
            ),
          },
          ...(canRootCause
            ? [
                {
                  key: 'root-cause',
                  label: '根因分析',
                  children: (
                    <>
                      <Form form={rcForm} layout="inline" style={{ rowGap: 8 }}>
                        <Form.Item name="question" label="异常描述" required>
                          <Input
                            placeholder="如：事件采集延迟升高 / 报告生成失败"
                            style={{ width: 360 }}
                            allowClear
                          />
                        </Form.Item>
                        <Form.Item>
                          <Button
                            type="primary"
                            icon={<SearchOutlined />}
                            loading={rcLoading}
                            onClick={() => void onRootCause()}
                          >
                            开始分析
                          </Button>
                        </Form.Item>
                      </Form>
                      {rcLoading && loadingHint}
                      {rcResult && <AnalyzeResultView result={rcResult} />}
                    </>
                  ),
                },
              ]
            : []),
        ]}
      />
    </Card>
  )
}
