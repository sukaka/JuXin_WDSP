import { useState } from 'react'
import { App as AntdApp, Button, Card, Form, Input, Typography } from 'antd'
import { SearchOutlined } from '@ant-design/icons'
import { ApiError } from '../../../api/client'
import { aiAnalyzeApi } from '../../../api/ai'
import type { AiAnalyzeResult } from '../../../api/ai'
import AnalyzeResultView from '../../../components/ai/AnalyzeResultView'

/** 简单校验 IPv4/IPv6 形态（仅拦截明显非法输入，不追求完整 RFC 覆盖） */
function isValidIp(value: string): boolean {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) {
    return value.split('.').every((seg) => Number(seg) <= 255)
  }
  // IPv6：允许 :: 缩写与前导零省略的十六进制分组
  return /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/.test(value)
}

/** 攻击画像：按攻击源 IP 聚合其行为特征，生成画像与处置建议 */
export default function AttackProfilePage() {
  const { message } = AntdApp.useApp()
  const [form] = Form.useForm<{ ip?: string; question?: string }>()
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<AiAnalyzeResult | null>(null)

  const onAnalyze = async () => {
    const v = form.getFieldsValue()
    const ip = v.ip?.trim()
    const question = v.question?.trim()
    if (!ip) {
      message.warning('请输入 IP 地址')
      return
    }
    if (!isValidIp(ip)) {
      message.warning('IP 地址格式不正确，请输入合法的 IPv4 或 IPv6 地址')
      return
    }
    setLoading(true)
    setResult(null)
    try {
      setResult(await aiAnalyzeApi.attackProfile({ ip, question: question || undefined }))
    } catch (e) {
      message.error(e instanceof ApiError ? e.message : '分析执行失败')
    } finally {
      setLoading(false)
    }
  }

  return (
    <Card title="攻击画像">
      <Typography.Paragraph type="secondary">
        基于攻击源 IP 聚合其攻击次数、攻击类型、目标应用、命中规则与时间规律，生成攻击者画像与处置建议；所有结论附证据引用。
      </Typography.Paragraph>
      <Form form={form} layout="inline" style={{ rowGap: 8 }}>
        <Form.Item name="ip" label="IP 地址" required>
          <Input placeholder="攻击源 IP，如 203.0.113.10" style={{ width: 280 }} allowClear />
        </Form.Item>
        <Form.Item name="question" label="分析问题">
          <Input
            placeholder="可选，如：该 IP 近一周的主要攻击手法"
            style={{ width: 320 }}
            allowClear
          />
        </Form.Item>
        <Form.Item>
          <Button
            type="primary"
            icon={<SearchOutlined />}
            loading={loading}
            onClick={() => void onAnalyze()}
          >
            开始画像
          </Button>
        </Form.Item>
      </Form>
      {loading && (
        <Typography.Paragraph type="secondary" style={{ marginTop: 16 }}>
          AI 正在分析，通常需要数秒到数十秒，请稍候...
        </Typography.Paragraph>
      )}
      {result && <AnalyzeResultView result={result} />}
    </Card>
  )
}
