import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Card, Descriptions, Empty, Space, Steps, Tag, Timeline, Typography } from 'antd'
import { ArrowLeftOutlined } from '@ant-design/icons'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { ApiError } from '../../api/client'
import { attackSessionsApi } from '../../api/attackSessions'
import type { AttackSessionEventItem } from '../../api/attackSessions'
import StatusTag from '../../components/StatusTag'
import AutomationSuspectedTag from '../../components/AutomationSuspectedTag'
import { useBreadcrumbObjectName } from '../../stores/breadcrumb'
import { formatDateTime, formatDuration } from '../../utils/format'
import { formatAutomationBasis, SOURCE_TABLE_LABELS } from '../../utils/i18nLabels'
import { ATTACK_SESSION_STATUS_META, ATTACK_STAGE_META, RISK_LEVEL_META } from '../../utils/identitySecurity'

/** 攻击链标准阶段顺序（设计文档 #16.2/#17；UNKNOWN 不在进展链上） */
const STAGE_CHAIN = [
  'RECON',
  'DISCOVERY',
  'AUTH_PROBE',
  'AUTHORIZATION_PROBE',
  'EXPLOIT',
  'DATA_ACCESS',
  'PERSISTENCE',
] as const

/** 事件按时间升序（服务端已按时间序返回，此处防御性排序） */
function sortEvents(events: AttackSessionEventItem[]): AttackSessionEventItem[] {
  return [...events].sort((a, b) => (a.occurred_at < b.occurred_at ? -1 : 1))
}

/** 风险分组成：events 的阶段分布（按攻击链顺序排列，未知阶段排最后） */
function stageDistribution(events: AttackSessionEventItem[]): { stage: string; count: number }[] {
  const counts = new Map<string, number>()
  for (const e of events) {
    counts.set(e.stage, (counts.get(e.stage) ?? 0) + 1)
  }
  const order = (s: string) => {
    const i = STAGE_CHAIN.indexOf(s as (typeof STAGE_CHAIN)[number])
    return i === -1 ? STAGE_CHAIN.length : i
  }
  return [...counts.entries()]
    .map(([stage, count]) => ({ stage, count }))
    .sort((a, b) => order(a.stage) - order(b.stage))
}

/** Timeline 圆点颜色：沿用阶段色，非 CSS 色名的 antd 预设色（volcano/default 等）做兜底 */
function timelineDotColor(stage: string): string {
  const c = ATTACK_STAGE_META[stage]?.color
  if (!c || c === 'default') return 'gray'
  if (c === 'volcano') return '#fa541c'
  return c
}

export default function AttackSessionDetailPage() {
  const { id = '' } = useParams()
  const navigate = useNavigate()

  const detailQuery = useQuery({
    queryKey: ['attack-sessions', 'detail', id],
    queryFn: () => attackSessionsApi.get(id),
    enabled: !!id,
  })

  const events = useMemo(() => sortEvents(detailQuery.data?.events ?? []), [detailQuery.data])
  const distribution = useMemo(() => stageDistribution(events), [events])

  // 面包屑注入当前会话号（卸载时自动清理）
  useBreadcrumbObjectName(detailQuery.data?.session?.session_key)

  if (detailQuery.isError) {
    return (
      <Card>
        <Alert
          type="error"
          showIcon
          message="加载攻击活动详情失败"
          description={detailQuery.error instanceof ApiError ? detailQuery.error.message : undefined}
          action={<Button onClick={() => navigate('/attack-sessions')}>返回列表</Button>}
        />
      </Card>
    )
  }

  const session = detailQuery.data?.session
  const stageIndex = session ? STAGE_CHAIN.indexOf(session.attack_stage as (typeof STAGE_CHAIN)[number]) : -1

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Card
        title={
          <Space>
            <Button
              type="text"
              icon={<ArrowLeftOutlined />}
              aria-label="返回列表"
              onClick={() => navigate('/attack-sessions')}
            />
            <span>攻击活动详情</span>
            {session && <StatusTag value={session.risk_level} map={RISK_LEVEL_META} />}
            {session && <StatusTag value={session.attack_stage} map={ATTACK_STAGE_META} />}
            {session && (
              <AutomationSuspectedTag
                suspected={session.automation_suspected}
                basis={session.automation_basis}
              />
            )}
          </Space>
        }
        extra={<Button onClick={() => navigate('/attack-sessions')}>返回列表</Button>}
        loading={detailQuery.isLoading}
      >
        {session && (
          <Descriptions bordered size="small" column={{ xs: 1, sm: 2 }}>
            <Descriptions.Item label="会话号">
              <Typography.Text
                copyable={{ text: session.session_key, tooltips: ['复制会话号', '已复制'] }}
                style={{ fontFamily: 'monospace', fontSize: 12 }}
              >
                {session.session_key}
              </Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="身份">
              {session.identity_id ? (
                <Link to={`/risk-identities/${session.identity_id}`} style={{ fontFamily: 'monospace', fontSize: 12 }}>
                  {session.identity_id}
                </Link>
              ) : (
                '-'
              )}
            </Descriptions.Item>
            <Descriptions.Item label="攻击阶段">
              <StatusTag value={session.attack_stage} map={ATTACK_STAGE_META} />
            </Descriptions.Item>
            <Descriptions.Item label="自动化标注">
              {session.automation_suspected ? (
                <Space size={8} wrap>
                  <AutomationSuspectedTag suspected basis={session.automation_basis} />
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                    {formatAutomationBasis(session.automation_basis)}
                  </Typography.Text>
                </Space>
              ) : (
                <Typography.Text type="secondary">未标注</Typography.Text>
              )}
            </Descriptions.Item>
            <Descriptions.Item label="风险">
              <Space size={6}>
                <Typography.Text strong={session.risk_level === 'HIGH' || session.risk_level === 'CRITICAL'}>
                  {session.risk_score} / 100
                </Typography.Text>
                <StatusTag value={session.risk_level} map={RISK_LEVEL_META} />
              </Space>
            </Descriptions.Item>
            <Descriptions.Item label="状态">
              <StatusTag value={session.status} map={ATTACK_SESSION_STATUS_META} />
            </Descriptions.Item>
            <Descriptions.Item label="持续时长">
              {formatDuration(session.start_time, session.end_time)}
            </Descriptions.Item>
            <Descriptions.Item label="事件数">{session.event_count}</Descriptions.Item>
            <Descriptions.Item label="请求数">{session.request_count}</Descriptions.Item>
            <Descriptions.Item label="开始时间">{formatDateTime(session.start_time)}</Descriptions.Item>
            <Descriptions.Item label="结束时间">{formatDateTime(session.end_time)}</Descriptions.Item>
          </Descriptions>
        )}
      </Card>

      <Card title="阶段进展" loading={detailQuery.isLoading}>
        {session &&
          (stageIndex >= 0 ? (
            <Steps
              size="small"
              current={stageIndex}
              items={STAGE_CHAIN.map((s) => ({ title: ATTACK_STAGE_META[s]?.label ?? s }))}
            />
          ) : (
            <Typography.Text type="secondary">
              当前阶段未识别（{ATTACK_STAGE_META[session.attack_stage]?.label ?? session.attack_stage}
              ），无法定位到标准攻击链。
            </Typography.Text>
          ))}
        {distribution.length > 0 && (
          <div style={{ marginTop: 16 }}>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              风险分组成（关联事件阶段分布）：
            </Typography.Text>
            <Space size={8} wrap style={{ marginTop: 8 }}>
              {distribution.map((d) => (
                <Tag key={d.stage} color={ATTACK_STAGE_META[d.stage]?.color ?? 'default'}>
                  {ATTACK_STAGE_META[d.stage]?.label ?? d.stage} ×{d.count}
                </Tag>
              ))}
            </Space>
          </div>
        )}
      </Card>

      <Card title={`关联事件（${events.length}）`} loading={detailQuery.isLoading}>
        {events.length === 0 && !detailQuery.isLoading ? (
          <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无关联事件" style={{ margin: '48px 0' }} />
        ) : (
          <Timeline
            items={events.map((e) => ({
              color: timelineDotColor(e.stage),
              children: (
                <>
                  <Space size={8} wrap>
                    <StatusTag value={e.stage} map={ATTACK_STAGE_META} />
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                      {formatDateTime(e.occurred_at)}
                    </Typography.Text>
                  </Space>
                  <div>
                    <Typography.Text type="secondary" style={{ fontFamily: 'monospace', fontSize: 12 }}>
                      {SOURCE_TABLE_LABELS[e.source_table] ?? e.source_table}#{e.source_id}
                    </Typography.Text>
                  </div>
                </>
              ),
            }))}
          />
        )}
      </Card>
    </Space>
  )
}
