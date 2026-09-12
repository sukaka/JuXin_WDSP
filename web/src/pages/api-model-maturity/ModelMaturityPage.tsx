import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { Button, Card, Col, Empty, Row, Space, Spin, Statistic, Typography } from 'antd'
import { ReloadOutlined } from '@ant-design/icons'
import { apiMaturityApi, type ApiModelMaturityItem } from '../../api/apiSecurity'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import StatusTag from '../../components/StatusTag'
import { formatDateTime } from '../../utils/format'
import { MODEL_MATURITY_STAGE_META } from '../../utils/stage8'

/** 成熟度卡片钻取：参数/身份 → 对应运营页 */
const MODEL_DRILLDOWN: Record<string, { path: string; label: string }> = {
  parameter: { path: '/api-parameters', label: '参数模型' },
  identity: { path: '/api-identity-profiles', label: '身份模型' },
}

/** 三微模型固定展示顺序（与 docs/API_MICRO_MODELS.md 一致） */
const MODEL_ORDER = ['parameter', 'identity', 'access_env', 'access_object']

/** 单个模型卡片：阶段徽章 + 关键指标网格 + 摘要文案 + 可选钻取 */
function ModelMaturityCard({ model }: { model: ApiModelMaturityItem }) {
  const navigate = useNavigate()
  const metrics = Object.entries(model.metrics ?? {})
  const drill = MODEL_DRILLDOWN[model.key]
  return (
    <Card
      size="small"
      title={model.name || model.key}
      extra={<StatusTag value={model.stage} map={MODEL_MATURITY_STAGE_META} />}
      style={{ height: '100%' }}
    >
      {metrics.length ? (
        <Row gutter={[8, 8]}>
          {metrics.map(([k, v]) => (
            <Col span={12} key={k}>
              <Statistic title={k} value={v} styles={{ content: { fontSize: 18 } }} />
            </Col>
          ))}
        </Row>
      ) : (
        <Typography.Text type="secondary">暂无指标数据</Typography.Text>
      )}
      <Typography.Paragraph type="secondary" style={{ marginTop: 12, marginBottom: 8 }}>
        {model.summary || '暂无摘要'}
      </Typography.Paragraph>
      {drill ? (
        <Button type="link" size="small" style={{ padding: 0 }} onClick={() => navigate(drill.path)}>
          查看{drill.label} →
        </Button>
      ) : null}
    </Card>
  )
}

/** 模型成熟度总览（WDSP / 阶段8 第三批）：参数/身份/访问环境/访问对象四个模型的阶段与关键指标 */
export default function ModelMaturityPage() {
  const query = useQuery({
    queryKey: ['api-model-maturity'],
    queryFn: () => apiMaturityApi.get(),
    refetchInterval: 30_000,
  })

  const models = [...(query.data?.models ?? [])].sort(
    (a, b) => MODEL_ORDER.indexOf(a.key) - MODEL_ORDER.indexOf(b.key),
  )

  return (
    <Card
      title="模型成熟度总览"
      extra={
        <Space>
          {query.data?.generated_at ? (
            <Typography.Text type="secondary">
              生成时间：{formatDateTime(query.data.generated_at)}
            </Typography.Text>
          ) : null}
          <Button
            icon={<ReloadOutlined />}
            onClick={() => void query.refetch()}
            loading={query.isFetching}
          >
            刷新
          </Button>
        </Space>
      }
    >
      <Typography.Paragraph type="secondary">
        汇总参数、身份、访问环境、访问对象四个模型的成熟度阶段（学习中 → 候选 → 已确认 → 已生效）与关键指标，每 30 秒自动刷新。
      </Typography.Paragraph>
      <QueryErrorAlert error={query.error} />
      <Spin spinning={query.isLoading}>
        {models.length ? (
          <Row gutter={[16, 16]}>
            {models.map((m) => (
              <Col xs={24} md={12} xl={6} key={m.key}>
                <ModelMaturityCard model={m} />
              </Col>
            ))}
          </Row>
        ) : (
          !query.isLoading && !query.error && <Empty description="暂无模型成熟度数据" />
        )}
      </Spin>
    </Card>
  )
}
