import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Card,
  Col,
  Drawer,
  Row,
  Select,
  Space,
  Statistic,
  Timeline,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { apiFindingsApi, apiLifecycleApi, type ApiFinding } from '../../api/apiSecurity'
import { ApiError } from '../../api/client'
import {
  ApiFindingActionModals,
  ApiFindingDetailDrawer,
  ApiFindingInlineActions,
  FindingTypeTag,
} from '../../components/ApiFindingHandling'
import { useApiFindingHandling } from '../../components/useApiFindingHandling'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { formatDateTime } from '../../utils/format'
import { API_LIFECYCLE_STATUS_META } from '../../utils/i18nLabels'
import {
  API_FINDING_SEVERITY_META,
  API_FINDING_STATUS_META,
  API_FINDING_TYPE_META,
  formatApiFindingTitle,
} from '../../utils/stage8'

/** 本页固定关注的三类风险：影子 / 僵尸 / 已下线 API */
const LIFECYCLE_FINDING_TYPES = ['SHADOW', 'ZOMBIE', 'DEPRECATED'] as const

const STAT_CARDS: Array<{ type: (typeof LIFECYCLE_FINDING_TYPES)[number]; title: string; color: string }> = [
  { type: 'SHADOW', title: '影子 API', color: '#d4380d' },
  { type: 'ZOMBIE', title: '僵尸 API', color: '#c41d7f' },
  { type: 'DEPRECATED', title: '已下线 API', color: '#d46b08' },
]

/** 指纹/ID 截断展示：保留首尾，中间省略（仅当 endpoint_key 缺失时降级展示 endpoint_id） */
function truncateMiddle(value: string, head = 8, tail = 4): string {
  if (!value) return '-'
  if (value.length <= head + tail + 3) return value
  return `${value.slice(0, head)}…${value.slice(-tail)}`
}

/** 单类风险计数（page_size=1 仅取 total） */
function useFindingTotal(findingType: string) {
  return useQuery({
    queryKey: ['api-findings', 'count', findingType],
    queryFn: () => apiFindingsApi.list({ finding_type: findingType, page: 1, page_size: 1 }),
  })
}

/** Shadow 与 Zombie API（WDSP / 阶段8）：影子/僵尸/已下线 API 计数、列表、风险处置与接口生命周期 */
export default function ApiShadowZombiePage() {
  const [findingType, setFindingType] = useState<string>('SHADOW')
  const [status, setStatus] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  /** 生命周期时间线抽屉选中的记录（与风险详情抽屉分离，互不干扰） */
  const [lifecycleTarget, setLifecycleTarget] = useState<ApiFinding | null>(null)

  const handling = useApiFindingHandling()

  const shadowTotal = useFindingTotal('SHADOW')
  const zombieTotal = useFindingTotal('ZOMBIE')
  const deprecatedTotal = useFindingTotal('DEPRECATED')
  const totalByType = {
    SHADOW: shadowTotal,
    ZOMBIE: zombieTotal,
    DEPRECATED: deprecatedTotal,
  } as const

  const listQuery = useQuery({
    queryKey: ['api-findings', 'lifecycle', findingType, status, page, pageSize],
    queryFn: () =>
      apiFindingsApi.list({
        finding_type: findingType,
        status,
        page,
        page_size: pageSize,
      }),
  })

  const lifecycleQuery = useQuery({
    queryKey: ['api-lifecycle-events', lifecycleTarget?.endpoint_id],
    queryFn: () => apiLifecycleApi.events(lifecycleTarget!.endpoint_id!, { page: 1, page_size: 50 }),
    enabled: lifecycleTarget?.endpoint_id != null,
  })

  const columns: ColumnsType<ApiFinding> = [
    {
      title: '类型',
      dataIndex: 'finding_type',
      width: 150,
      render: (v: string) => <FindingTypeTag value={v} />,
    },
    {
      title: '严重级别',
      dataIndex: 'severity',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={API_FINDING_SEVERITY_META} />,
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={API_FINDING_STATUS_META} />,
    },
    {
      title: '标题',
      dataIndex: 'title',
      ellipsis: true,
      render: (v: string, record) => {
        const display = formatApiFindingTitle(v, {
          findingType: record.finding_type,
          detail: record.detail,
        })
        return display ? <Tooltip title={display}>{display}</Tooltip> : '-'
      },
    },
    {
      title: '接口',
      dataIndex: 'endpoint_key',
      width: 220,
      ellipsis: true,
      render: (v: string | undefined, record) => {
        if (v) {
          return (
            <Tooltip title={record.endpoint_id ? `${v}（ID: ${record.endpoint_id}）` : v}>
              <Typography.Text code>{v}</Typography.Text>
            </Tooltip>
          )
        }
        if (record.endpoint_id) {
          return (
            <Tooltip title={record.endpoint_id}>
              <Typography.Text code>{truncateMiddle(record.endpoint_id)}</Typography.Text>
            </Tooltip>
          )
        }
        return '-'
      },
    },
    {
      title: '首次发现',
      dataIndex: 'first_seen_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '最近发现',
      dataIndex: 'last_seen_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: handling.canHandle ? 230 : 140,
      fixed: 'right',
      render: (_, record) => (
        <Space size={0} wrap>
          <Button type="link" size="small" onClick={() => handling.setSelected(record)}>
            详情
          </Button>
          <ApiFindingInlineActions
            record={record}
            canHandle={handling.canHandle}
            onAction={handling.runAction}
          />
          {record.endpoint_id ? (
            <Button type="link" size="small" onClick={() => setLifecycleTarget(record)}>
              生命周期
            </Button>
          ) : null}
        </Space>
      ),
    },
  ]

  const lifecycleLabel = lifecycleTarget
    ? lifecycleTarget.endpoint_key || truncateMiddle(lifecycleTarget.endpoint_id ?? '')
    : ''

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Row gutter={[16, 16]}>
        {STAT_CARDS.map((card) => {
          const q = totalByType[card.type]
          const active = findingType === card.type
          return (
            <Col xs={24} sm={8} key={card.type}>
              <Card
                size="small"
                hoverable
                style={active ? { borderColor: card.color } : undefined}
                onClick={() => {
                  setFindingType(card.type)
                  setPage(1)
                }}
              >
                <Statistic
                  title={card.title}
                  value={q.data?.total ?? 0}
                  loading={q.isLoading}
                  valueStyle={{ color: card.color }}
                />
              </Card>
            </Col>
          )
        })}
      </Row>
      <Card title="影子与僵尸 API">
        <Typography.Paragraph type="secondary">
          影子 API：运行时观测到但未登记的 API；僵尸 API：登记在册但长期无流量的 API；已下线 API：已废弃仍被调用的
          API。可直接在行内点击「确认」或「详情」完成风险确认与处置闭环；若需将新发现接口正式纳入基线（不再作为影子
          API 上报），请前往 <Link to="/api-endpoints">API 接口资产</Link> 确认接口并重新发布配置。
        </Typography.Paragraph>
        <QueryErrorAlert error={listQuery.error} />
        <Space style={{ marginBottom: 16 }} wrap>
          <Select
            style={{ width: 160 }}
            value={findingType}
            options={LIFECYCLE_FINDING_TYPES.map((value) => ({
              value,
              label: API_FINDING_TYPE_META[value]?.label ?? value,
            }))}
            onChange={(v) => {
              setFindingType(v)
              setPage(1)
            }}
          />
          <Select
            placeholder="处置状态"
            allowClear
            style={{ width: 140 }}
            value={status}
            options={Object.entries(API_FINDING_STATUS_META).map(([value, meta]) => ({
              value,
              label: meta.label,
            }))}
            onChange={(v) => {
              setStatus(v)
              setPage(1)
            }}
          />
        </Space>
        <SmartTable<ApiFinding>
          storageKey="api-shadow-zombie"
          rowKey="id"
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items ?? []}
          scroll={{ x: 1320 }}
          onRow={(record) => ({
            onDoubleClick: () => handling.setSelected(record),
            style: { cursor: 'pointer' },
          })}
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
      </Card>
      <ApiFindingDetailDrawer
        finding={handling.selected}
        onClose={() => handling.setSelected(null)}
        canViewRisk={handling.canViewRisk}
        canHandle={handling.canHandle}
        onAction={handling.runAction}
        drawerExtra={
          handling.selected?.endpoint_id ? (
            <Button
              size="small"
              onClick={() => {
                const target = handling.selected
                handling.setSelected(null)
                setLifecycleTarget(target)
              }}
            >
              查看生命周期
            </Button>
          ) : null
        }
      />
      <ApiFindingActionModals
        resolveTarget={handling.resolveTarget}
        onCloseResolve={() => handling.setResolveTarget(null)}
        resolveForm={handling.resolveForm}
        resolveLoading={handling.resolveMut.isPending}
        onSubmitResolve={(id, resolution) => handling.resolveMut.mutate({ id, resolution })}
        fpTarget={handling.fpTarget}
        onCloseFp={() => handling.setFpTarget(null)}
        fpForm={handling.fpForm}
        fpLoading={handling.falsePositiveMut.isPending}
        onSubmitFp={(id, reason) => handling.falsePositiveMut.mutate({ id, reason })}
      />
      <Drawer
        title={lifecycleTarget ? `接口生命周期：${lifecycleLabel}` : '接口生命周期'}
        open={lifecycleTarget !== null}
        onClose={() => setLifecycleTarget(null)}
        width={520}
      >
        {lifecycleQuery.isLoading ? (
          <Typography.Text type="secondary">加载中...</Typography.Text>
        ) : lifecycleQuery.isError ? (
          <Alert
            type="error"
            showIcon
            message="加载生命周期事件失败"
            description={lifecycleQuery.error instanceof ApiError ? lifecycleQuery.error.message : undefined}
          />
        ) : (lifecycleQuery.data?.items ?? []).length === 0 ? (
          <Typography.Text type="secondary">暂无生命周期事件</Typography.Text>
        ) : (
          <Timeline
            items={(lifecycleQuery.data?.items ?? []).map((e) => ({
              color:
                API_LIFECYCLE_STATUS_META[e.to_status]?.color === 'default'
                  ? 'gray'
                  : (API_LIFECYCLE_STATUS_META[e.to_status]?.color ?? 'blue'),
              children: (
                <>
                  <Space size={4}>
                    <StatusTag value={e.from_status} map={API_LIFECYCLE_STATUS_META} />
                    <Typography.Text type="secondary">→</Typography.Text>
                    <StatusTag value={e.to_status} map={API_LIFECYCLE_STATUS_META} />
                  </Space>
                  <div>{e.reason || '-'}</div>
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                    {e.actor === 'system' ? '系统' : e.actor || '-'} · {formatDateTime(e.created_at)}
                  </Typography.Text>
                </>
              ),
            }))}
          />
        )}
      </Drawer>
    </Space>
  )
}
