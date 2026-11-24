import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { Button, Empty, Spin } from 'antd'
import {
  ArrowRightOutlined,
  CheckOutlined,
  ReloadOutlined,
} from '@ant-design/icons'
import {
  apiMaturityApi,
  type ApiModelMaturityItem,
} from '../../api/apiSecurity'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import { formatDateTime } from '../../utils/format'
import { MODEL_MATURITY_METRIC_LABELS } from '../../utils/i18nLabels'
import { MODEL_MATURITY_STAGE_META } from '../../utils/stage8'
import './model-maturity.css'

const MODEL_NAME_LABELS: Record<string, string> = {
  parameter: '参数模型',
  identity: '身份模型',
  access_env: '访问环境模型',
  access_object: '访问对象模型',
}

const MODEL_DRILLDOWN: Record<string, { path: string; label: string }> = {
  parameter: { path: '/api-parameters', label: '参数模型' },
  identity: { path: '/api-identity-profiles', label: '身份模型' },
}

const MODEL_ORDER = ['parameter', 'identity', 'access_env', 'access_object']
const MODEL_STAGES = [
  'LEARNING',
  'CANDIDATE',
  'CONFIRMED',
  'ENFORCING',
] as const
const MODEL_PRIMARY_METRIC: Record<string, string> = {
  parameter: 'enforced_formal_constraints',
  identity: 'identity_coverage_24h',
  access_env: 'endpoint_coverage',
  access_object: 'object_endpoint_coverage',
}

const numberFormatter = new Intl.NumberFormat('zh-CN', {
  maximumFractionDigits: 4,
})
const percentFormatter = new Intl.NumberFormat('zh-CN', {
  style: 'percent',
  maximumFractionDigits: 2,
})

function formatMetricValue(key: string, value: number) {
  const isCoverage =
    key === 'coverage' ||
    key.endsWith('_coverage') ||
    key.endsWith('_coverage_24h')
  return isCoverage
    ? percentFormatter.format(value)
    : numberFormatter.format(value)
}

function ModelMaturityCard({ model }: { model: ApiModelMaturityItem }) {
  const navigate = useNavigate()
  const name = model.name || MODEL_NAME_LABELS[model.key] || model.key
  const drill = MODEL_DRILLDOWN[model.key]
  const metrics = Object.entries(model.metrics ?? {})
  const primaryMetric =
    metrics.find(([key]) => key === MODEL_PRIMARY_METRIC[model.key]) ??
    metrics[0]
  const secondaryMetrics = primaryMetric
    ? metrics.filter(([key]) => key !== primaryMetric[0])
    : []
  const currentStageIndex = MODEL_STAGES.indexOf(model.stage)

  return (
    <article
      className="model-maturity-card"
      data-stage={model.stage}
      aria-label={name}
    >
      <div className="model-maturity-card-header">
        <h2>{name}</h2>
        {drill ? (
          <Button
            type="link"
            size="small"
            icon={<ArrowRightOutlined />}
            iconPlacement="end"
            aria-label={`查看${drill.label}`}
            onClick={() => navigate(drill.path)}
          >
            查看{drill.label}
          </Button>
        ) : null}
      </div>

      <div className="model-maturity-stage-badge">
        <span className="model-maturity-stage-dot" aria-hidden="true" />
        {MODEL_MATURITY_STAGE_META[model.stage]?.label ?? model.stage}
      </div>

      <ol className="model-maturity-lifecycle" aria-label={`${name}成熟度阶段`}>
        {MODEL_STAGES.map((stage, index) => {
          const state =
            index < currentStageIndex
              ? 'is-complete'
              : index === currentStageIndex
                ? 'is-current'
                : ''
          return (
            <li
              className={state}
              key={stage}
              aria-current={index === currentStageIndex ? 'step' : undefined}
            >
              <span className="model-maturity-step-marker" aria-hidden="true">
                {index < currentStageIndex ? <CheckOutlined /> : null}
              </span>
              <span>{MODEL_MATURITY_STAGE_META[stage].label}</span>
            </li>
          )
        })}
      </ol>

      <div className="model-maturity-metrics">
        {primaryMetric ? (
          <>
            <div className="model-maturity-primary-metric">
              <span>
                {MODEL_MATURITY_METRIC_LABELS[primaryMetric[0]] ??
                  primaryMetric[0]}
              </span>
              <strong>
                {formatMetricValue(primaryMetric[0], primaryMetric[1])}
              </strong>
            </div>
            {secondaryMetrics.length ? (
              <dl className="model-maturity-secondary-metrics">
                {secondaryMetrics.map(([key, value]) => (
                  <div key={key}>
                    <dt>{MODEL_MATURITY_METRIC_LABELS[key] ?? key}</dt>
                    <dd>{formatMetricValue(key, value)}</dd>
                  </div>
                ))}
              </dl>
            ) : null}
          </>
        ) : (
          <p className="model-maturity-no-metrics">暂无指标数据</p>
        )}
      </div>

      <p className="model-maturity-summary">{model.summary || '暂无摘要'}</p>
    </article>
  )
}

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
    <div className="model-maturity-page">
      <header className="model-maturity-header">
        <div>
          <h1>模型成熟度</h1>
          <p>跟踪参数、身份、环境与对象模型的学习进展和生效情况</p>
        </div>
        <div className="model-maturity-refresh">
          <div className="model-maturity-refresh-meta">
            <span className="model-maturity-auto-refresh">
              <span aria-hidden="true" />每 30 秒自动刷新
            </span>
            {query.data?.generated_at ? (
              <time dateTime={query.data.generated_at}>
                更新于 {formatDateTime(query.data.generated_at)}
              </time>
            ) : null}
          </div>
          <Button
            icon={<ReloadOutlined />}
            onClick={() => void query.refetch()}
            loading={query.isFetching}
          >
            刷新
          </Button>
        </div>
      </header>

      <QueryErrorAlert error={query.error} />
      <Spin spinning={query.isLoading}>
        <div className="model-maturity-content">
          {models.length ? (
            <>
              <section
                className="model-maturity-overview"
                aria-label="成熟度阶段统计"
              >
                <div className="model-maturity-total">
                  <span>模型总数</span>
                  <strong>{models.length}</strong>
                </div>
                <dl className="model-maturity-stage-counts">
                  {MODEL_STAGES.map((stage) => (
                    <div key={stage} data-stage={stage}>
                      <dt>
                        <span
                          className="model-maturity-stage-dot"
                          aria-hidden="true"
                        />
                        {MODEL_MATURITY_STAGE_META[stage].label}
                      </dt>
                      <dd>
                        {models.filter((model) => model.stage === stage).length}
                      </dd>
                    </div>
                  ))}
                </dl>
              </section>
              <div className="model-maturity-grid">
                {models.map((model) => (
                  <ModelMaturityCard model={model} key={model.key} />
                ))}
              </div>
            </>
          ) : (
            !query.isLoading &&
            !query.error && <Empty description="暂无模型成熟度数据" />
          )}
        </div>
      </Spin>
    </div>
  )
}
