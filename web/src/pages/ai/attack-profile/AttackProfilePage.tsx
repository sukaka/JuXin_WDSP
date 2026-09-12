import { useState } from 'react'
import { App as AntdApp, Button, Card, Form, Input, Select, Typography } from 'antd'
import { SearchOutlined } from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import { ApiError } from '../../../api/client'
import { aiAnalyzeApi } from '../../../api/ai'
import type { AiAnalyzeBody, AiAnalyzeResult } from '../../../api/ai'
import { applicationsApi } from '../../../api/applications'
import AnalyzeResultView from '../../../components/ai/AnalyzeResultView'

/** 简单校验 IPv4/IPv6 形态（仅拦截明显非法输入，不追求完整 RFC 覆盖） */
function isValidIp(value: string): boolean {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) {
    return value.split('.').every((seg) => Number(seg) <= 255)
  }
  // IPv6：允许 :: 缩写与前导零省略的十六进制分组
  return /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/.test(value)
}

/** 画像统计区间选项（与后端 time_range 白名单一致） */
const TIME_RANGE_OPTIONS = [
  { value: '24h', label: '近 24 小时' },
  { value: '7d', label: '近 7 天' },
  { value: '30d', label: '近 30 天' },
]

type ProfileTarget = 'ip' | 'uri' | 'application'

interface ProfileFormValues {
  target: ProfileTarget
  ip?: string
  uri?: string
  application_id?: string
  time_range?: string
  question?: string
}

/** 攻击画像：按攻击源 IP / URI / 应用聚合真实事件数据，生成画像与处置建议 */
export default function AttackProfilePage() {
  const { message } = AntdApp.useApp()
  const [form] = Form.useForm<ProfileFormValues>()
  const [target, setTarget] = useState<ProfileTarget>('ip')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<AiAnalyzeResult | null>(null)

  // 应用画像对象下拉（非关键控件，无权限时降级为隐藏，仅 IP/URI 可用）
  const appsQuery = useQuery({
    queryKey: ['applications', 'all-for-ai-attack-profile'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
    retry: false,
  })

  const onAnalyze = async () => {
    const v = form.getFieldsValue()
    const question = v.question?.trim()
    const body: AiAnalyzeBody = { question: question || undefined }
    if (v.target === 'ip') {
      const ip = v.ip?.trim()
      if (!ip) {
        message.warning('请输入 IP 地址')
        return
      }
      if (!isValidIp(ip)) {
        message.warning('IP 地址格式不正确，请输入合法的 IPv4 或 IPv6 地址')
        return
      }
      body.ip = ip
    } else if (v.target === 'uri') {
      const uri = v.uri?.trim()
      if (!uri || !uri.startsWith('/')) {
        message.warning('请输入以 / 开头的 URI，如 /api/login')
        return
      }
      body.uri = uri
      body.time_range = v.time_range || undefined
    } else {
      if (!v.application_id) {
        message.warning('请选择要画像的应用')
        return
      }
      body.application_id = v.application_id
      body.time_range = v.time_range || undefined
    }
    setLoading(true)
    setResult(null)
    try {
      setResult(await aiAnalyzeApi.attackProfile(body))
    } catch (e) {
      message.error(e instanceof ApiError ? e.message : '分析执行失败')
    } finally {
      setLoading(false)
    }
  }

  return (
    <Card title="攻击画像">
      <Typography.Paragraph type="secondary">
        基于真实安全事件聚合画像：按攻击源 IP 聚合攻击次数、类型、目标与封禁情况；按 URI
        聚合事件分布、攻击类型与来源 IP；按应用聚合攻击类型、来源 IP 与被攻击
        URI；所有结论附证据引用。
      </Typography.Paragraph>
      <Form
        form={form}
        layout="inline"
        style={{ rowGap: 8 }}
        initialValues={{ target: 'ip', time_range: '7d' }}
      >
        <Form.Item name="target" label="画像对象">
          <Select
            style={{ width: 130 }}
            options={[
              { value: 'ip', label: '攻击源 IP' },
              { value: 'uri', label: 'URI' },
              { value: 'application', label: '应用' },
            ]}
            onChange={(v: ProfileTarget) => setTarget(v)}
          />
        </Form.Item>
        {target === 'ip' && (
          <Form.Item name="ip" label="IP 地址" required>
            <Input placeholder="攻击源 IP，如 203.0.113.10" style={{ width: 240 }} allowClear />
          </Form.Item>
        )}
        {target === 'uri' && (
          <Form.Item name="uri" label="URI" required>
            <Input placeholder="请求路径，如 /api/login" style={{ width: 240 }} allowClear />
          </Form.Item>
        )}
        {target === 'application' && (
          <Form.Item name="application_id" label="应用" required>
            <Select
              placeholder="选择应用"
              showSearch
              optionFilterProp="label"
              style={{ width: 240 }}
              loading={appsQuery.isLoading}
              options={(appsQuery.data?.items ?? []).map((a) => ({
                value: a.id,
                label: `${a.name}（${a.code}）`,
              }))}
            />
          </Form.Item>
        )}
        {target !== 'ip' && (
          <Form.Item name="time_range" label="统计区间">
            <Select style={{ width: 130 }} options={TIME_RANGE_OPTIONS} />
          </Form.Item>
        )}
        <Form.Item name="question" label="分析问题">
          <Input placeholder="可选，如：重点关注撞库手法" style={{ width: 260 }} allowClear />
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
