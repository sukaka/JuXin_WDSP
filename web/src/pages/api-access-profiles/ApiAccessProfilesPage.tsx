import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Button, Card, Descriptions, Drawer, Input, Select, Space, Tabs, Tag, Tooltip, Typography } from 'antd'
import { QuestionCircleOutlined } from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'
import { apiEndpointsApi } from '../../api/apiAssets'
import { apiAuthzApi, type ApiAuthzEnforcementReadinessItem } from '../../api/apiAuthz'
import {
  apiBehaviorProfilesApi,
  apiObjectModelsApi,
  type ApiBehaviorProfile,
  type ApiObjectModel,
} from '../../api/apiSecurity'
import { ReadinessBadge } from '../../components/AuthzEnforcement'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { ENFORCEMENT_VALUE_META } from '../../utils/authzEnforcement'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import ProtectWizard from '../api-authz/ProtectWizard'

/** 标识形态色阶与中文名（api_object_models.identifier_type 列口径） */
const IDENTIFIER_TYPE_META: Record<string, { color: string; label: string }> = {
  numeric: { color: 'blue', label: '数字' },
  uuid: { color: 'green', label: 'UUID' },
  hash: { color: 'purple', label: '哈希' },
  mixed: { color: 'orange', label: '混合' },
  unknown: { color: 'default', label: '未知' },
}

function identifierTypeTag(value: string) {
  const meta = IDENTIFIER_TYPE_META[value] ?? { color: 'default', label: value }
  return <Tag color={meta.color}>{meta.label}</Tag>
}

/** 端点列渲染（endpoint_key 缺失时回退端点 ID 前 8 位） */
function EndpointCell({ row }: { row: { endpoint_id: string; endpoint_key?: string } }) {
  return row.endpoint_key ? (
    <Typography.Text code>{row.endpoint_key}</Typography.Text>
  ) : (
    <Typography.Text type="secondary">{row.endpoint_id.slice(0, 8)}…</Typography.Text>
  )
}

/** 站点列渲染（主域名优先，其次站点名称，未归属置灰占位；与接口资产页口径一致） */
function SiteCell({ row }: { row: { application_name?: string; application_domain?: string } }) {
  const text = row.application_domain || row.application_name
  return text ? <span>{text}</span> : <Typography.Text type="secondary">未归属</Typography.Text>
}

/** 调用时段分布（UTC 0–23 小时桶，纯 div 简易柱状条，不引图表依赖） */
function HourDistChart({ dist }: { dist: Record<string, number> }) {
  const values = Array.from({ length: 24 }, (_, h) => dist[String(h)] ?? 0)
  const max = Math.max(1, ...values)
  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'flex-end', gap: 2, height: 72 }}>
        {values.map((v, h) => (
          <div
            key={h}
            title={`${h} 时（UTC）：${v} 次`}
            style={{
              flex: 1,
              height: `${Math.max(v > 0 ? 4 : 1, (v / max) * 100)}%`,
              background: v > 0 ? '#1677ff' : '#f0f0f0',
              borderRadius: 2,
            }}
          />
        ))}
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 4 }}>
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>0 时</Typography.Text>
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>12 时</Typography.Text>
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>23 时（UTC）</Typography.Text>
      </div>
    </div>
  )
}

/** 环境维度·行为画像（api_behavior_profiles：endpoint × 身份 × 窗口） */
function BehaviorProfilesTab({ applicationId }: { applicationId?: string }) {
  const [fingerprint, setFingerprint] = useState('')
  const [appliedFp, setAppliedFp] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [selected, setSelected] = useState<ApiBehaviorProfile | null>(null)

  // 站点过滤变化时回第一页（避免旧页码在新过滤结果中越界）
  const [prevApp, setPrevApp] = useState(applicationId)
  if (prevApp !== applicationId) {
    setPrevApp(applicationId)
    setPage(1)
  }

  const listQuery = useQuery({
    queryKey: ['api-behavior-profiles', appliedFp, applicationId, page, pageSize],
    queryFn: () =>
      apiBehaviorProfilesApi.list({
        page,
        page_size: pageSize,
        identity_fingerprint: appliedFp || undefined,
        application_id: applicationId || undefined,
      }),
  })

  const columns: ColumnsType<ApiBehaviorProfile> = [
    {
      title: 'API',
      dataIndex: 'endpoint_key',
      ellipsis: true,
      render: (_: string, r) => <EndpointCell row={r} />,
    },
    {
      title: '站点',
      key: 'site',
      width: 150,
      ellipsis: true,
      render: (_, r) => <SiteCell row={r} />,
    },
    {
      title: '身份指纹',
      dataIndex: 'identity_fingerprint',
      ellipsis: true,
      render: (v: string) =>
        v ? (
          <Typography.Text code copyable={{ text: v }}>{v}</Typography.Text>
        ) : (
          <Tag>API 级聚合</Tag>
        ),
    },
    {
      title: '窗口',
      dataIndex: 'window_seconds',
      width: 90,
      render: (v: number) => `${v}s`,
    },
    {
      title: (
        <Space size={4}>
          请求数（近1小时）
          <Tooltip title="统计最近 1 小时窗口内「值得关注」的请求（有检测明细或被拦截/观察的），每 30 秒重算覆盖；空档期显示 0 属正常。全量请求量见访问日志。">
            <QuestionCircleOutlined style={{ color: 'rgba(0,0,0,0.45)' }} />
          </Tooltip>
        </Space>
      ),
      dataIndex: 'request_count',
      width: 160,
      sorter: (a, b) => a.request_count - b.request_count,
    },
    {
      title: '平均速率',
      dataIndex: 'avg_rate',
      width: 110,
      render: (v: number) => `${v.toFixed(4)} 次/秒`,
    },
    {
      title: '更新时间',
      dataIndex: 'updated_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
  ]

  return (
    <>
      <Typography.Paragraph type="secondary">
        这次访问的环境，和他平时不一样吗
      </Typography.Paragraph>
      <QueryErrorAlert error={listQuery.error} />
      <Space style={{ marginBottom: 16 }} wrap>
        <Input.Search
          placeholder="身份指纹（精确匹配）"
          allowClear
          style={{ width: 360 }}
          value={fingerprint}
          onChange={(e) => setFingerprint(e.target.value)}
          onSearch={(v) => {
            setAppliedFp(v.trim())
            setPage(1)
          }}
        />
      </Space>
      <SmartTable<ApiBehaviorProfile>
        storageKey="api-behavior-profiles"
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        scroll={{ x: 1100 }}
        onRow={(r) => ({ onClick: () => setSelected(r), style: { cursor: 'pointer' } })}
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
      <Drawer
        title="行为画像详情"
        width={720}
        open={selected !== null}
        onClose={() => setSelected(null)}
        destroyOnHidden
      >
        {selected ? (
          <Space direction="vertical" size={16} style={{ width: '100%' }}>
            <Descriptions
              size="small"
              column={2}
              bordered
              items={[
                { key: 'ep', label: 'API', span: 2, children: <EndpointCell row={selected} /> },
                { key: 'site', label: '站点', span: 2, children: <SiteCell row={selected} /> },
                {
                  key: 'fp',
                  label: '身份指纹',
                  span: 2,
                  children: selected.identity_fingerprint ? (
                    <Typography.Text code copyable={{ text: selected.identity_fingerprint }}>{selected.identity_fingerprint}</Typography.Text>
                  ) : (
                    <Tag>API 级聚合</Tag>
                  ),
                },
                { key: 'win', label: '窗口', children: `${selected.window_seconds} 秒` },
                { key: 'count', label: '窗口内请求数', children: selected.request_count },
                { key: 'rate', label: '平均速率', children: `${selected.avg_rate.toFixed(4)} 次/秒` },
                { key: 'updated', label: '最近重算', children: formatDateTime(selected.updated_at) },
              ]}
            />
            <div>
              <Typography.Text strong>状态码分布</Typography.Text>
              <div style={{ marginTop: 8 }}>
                {Object.keys(selected.status_code_dist ?? {}).length > 0 ? (
                  Object.entries(selected.status_code_dist).map(([k, v]) => (
                    <Tag key={k} color={k === '2xx' ? 'green' : k === '4xx' ? 'orange' : k === '5xx' ? 'red' : 'default'}>
                      {k}：{v}
                    </Tag>
                  ))
                ) : (
                  <Typography.Text type="secondary">暂无数据</Typography.Text>
                )}
              </div>
            </div>
            <div>
              <Typography.Text strong>调用时段分布（UTC，按 24h 回看重算）</Typography.Text>
              <HourDistChart dist={selected.hour_dist ?? {}} />
            </div>
          </Space>
        ) : null}
      </Drawer>
    </>
  )
}

/** 对象维度·对象模型（api_object_models：endpoint × 对象段，BOLA 实体画像） */
function ObjectModelsTab({ applicationId }: { applicationId?: string }) {
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'api_authorization.manage')
  const [segment, setSegment] = useState('')
  const [appliedSegment, setAppliedSegment] = useState('')
  const [identifierType, setIdentifierType] = useState<string>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [selected, setSelected] = useState<ApiObjectModel | null>(null)
  const [wizardPreset, setWizardPreset] = useState<{ endpoint_id: string; object_segment: string } | null>(null)

  // 站点过滤变化时回第一页（避免旧页码在新过滤结果中越界）
  const [prevApp, setPrevApp] = useState(applicationId)
  if (prevApp !== applicationId) {
    setPrevApp(applicationId)
    setPage(1)
  }

  const listQuery = useQuery({
    queryKey: ['api-object-models', appliedSegment, identifierType, applicationId, page, pageSize],
    queryFn: () =>
      apiObjectModelsApi.list({
        page,
        page_size: pageSize,
        object_segment: appliedSegment || undefined,
        identifier_type: identifierType || undefined,
        application_id: applicationId || undefined,
      }),
  })
  // NG-AZ-04 §1.1：对象模型表格 readiness 徽章列（服务端派生；未选站点时无资格数据，置「—」）
  const readinessQuery = useQuery({
    queryKey: ['api-authz', 'enforcement-readiness', applicationId],
    queryFn: () => apiAuthzApi.listEnforcementReadiness({ application_id: applicationId! }),
    enabled: Boolean(applicationId),
  })
  const readinessMap = useMemo(() => {
    const map = new Map<string, ApiAuthzEnforcementReadinessItem>()
    for (const item of readinessQuery.data?.items ?? []) map.set(`${item.endpoint_id}:${item.object_segment}`, item)
    return map
  }, [readinessQuery.data])

  const columns: ColumnsType<ApiObjectModel> = [
    {
      title: 'API',
      dataIndex: 'endpoint_key',
      ellipsis: true,
      render: (_: string, r) => <EndpointCell row={r} />,
    },
    {
      title: '站点',
      key: 'site',
      width: 150,
      ellipsis: true,
      render: (_, r) => <SiteCell row={r} />,
    },
    {
      title: '对象段',
      dataIndex: 'object_segment',
      ellipsis: true,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: '能否实断',
      key: 'readiness',
      width: 160,
      render: (_, r) => {
        const item = readinessMap.get(`${r.endpoint_id}:${r.object_segment}`)
        return item ? (
          <ReadinessBadge readiness={item.readiness} reasons={item.reasons} />
        ) : (
          <Typography.Text type="secondary">—</Typography.Text>
        )
      },
    },
    {
      title: '标识形态',
      dataIndex: 'identifier_type',
      width: 100,
      render: (v: string) => identifierTypeTag(v),
    },
    {
      title: '样本数',
      dataIndex: 'sample_count',
      width: 100,
      sorter: (a, b) => a.sample_count - b.sample_count,
    },
    {
      title: '首见',
      dataIndex: 'first_seen',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '末见',
      dataIndex: 'last_seen',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
  ]

  return (
    <>
      <Typography.Paragraph type="secondary">
        他碰的是哪个对象？他该不该碰
      </Typography.Paragraph>
      <QueryErrorAlert error={listQuery.error} />
      <Space style={{ marginBottom: 16 }} wrap>
        <Input.Search
          placeholder="对象段（精确匹配，如 path:2 / query:account_id）"
          allowClear
          style={{ width: 360 }}
          value={segment}
          onChange={(e) => setSegment(e.target.value)}
          onSearch={(v) => {
            setAppliedSegment(v.trim())
            setPage(1)
          }}
        />
        <Select
          placeholder="标识形态"
          allowClear
          style={{ width: 140 }}
          value={identifierType}
          onChange={(v) => {
            setIdentifierType(v)
            setPage(1)
          }}
          options={Object.entries(IDENTIFIER_TYPE_META).map(([value, meta]) => ({ value, label: meta.label }))}
        />
      </Space>
      <SmartTable<ApiObjectModel>
        storageKey="api-object-models"
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        scroll={{ x: 1100 }}
        onRow={(r) => ({ onClick: () => setSelected(r), style: { cursor: 'pointer' } })}
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
      <Drawer
        title="对象模型详情"
        width={720}
        open={selected !== null}
        onClose={() => setSelected(null)}
        destroyOnHidden
      >
        {selected ? (
          <Space direction="vertical" size={16} style={{ width: '100%' }}>
            <Descriptions
              size="small"
              column={2}
              bordered
              items={[
                { key: 'ep', label: 'API', span: 2, children: <EndpointCell row={selected} /> },
                { key: 'site', label: '站点', span: 2, children: <SiteCell row={selected} /> },
                { key: 'seg', label: '对象段', children: <Typography.Text code>{selected.object_segment}</Typography.Text> },
                { key: 'type', label: '标识形态', children: identifierTypeTag(selected.identifier_type) },
                { key: 'count', label: '样本数', children: selected.sample_count },
                { key: 'updated', label: '行更新时间', children: formatDateTime(selected.updated_at) },
                { key: 'first', label: '首次观测', children: formatDateTime(selected.first_seen) },
                { key: 'last', label: '末次观测', children: formatDateTime(selected.last_seen) },
                {
                  key: 'hash',
                  label: '示例哈希',
                  span: 2,
                  children: selected.example_hash ? (
                    <Typography.Text code copyable={{ text: selected.example_hash }}>{selected.example_hash}</Typography.Text>
                  ) : (
                    <Typography.Text type="secondary">—</Typography.Text>
                  ),
                },
                {
                  key: 'note',
                  label: '脱敏说明',
                  span: 2,
                  children: (
                    <Typography.Text type="secondary">
                      观测原值不落库，仅保留 SHA-256 示例哈希；identifier_type 为启发式形态识别（只认形态不认语义）。
                    </Typography.Text>
                  ),
                },
              ]}
            />
            <div>
              <Space size={8} align="center" style={{ marginBottom: 8 }}>
                <Typography.Text strong>实断资格（NG-AZ-02/03/04）</Typography.Text>
                <ReadinessBadge
                  readiness={readinessMap.get(`${selected.endpoint_id}:${selected.object_segment}`)?.readiness}
                  reasons={readinessMap.get(`${selected.endpoint_id}:${selected.object_segment}`)?.reasons}
                />
              </Space>
              <Descriptions
                size="small"
                column={2}
                bordered
                items={[
                  {
                    key: 'enf',
                    label: '当前 enforcement',
                    children: <StatusTag value={selected.enforcement || 'OBSERVE'} map={ENFORCEMENT_VALUE_META} />,
                  },
                  {
                    key: 'pub',
                    label: '发布资格',
                    children:
                      selected.publishable === undefined ? '—' : selected.publishable ? <Tag color="green">publishable</Tag> : <Tag>未声明</Tag>,
                  },
                  { key: 'rel', label: '要求关系', children: selected.required_relation || '—' },
                  {
                    key: 'excl',
                    label: '排他所有权',
                    children:
                      selected.owner_exclusive === undefined ? '—' : selected.owner_exclusive ? <Tag color="green">是</Tag> : <Tag>否</Tag>,
                  },
                  { key: 'lease', label: '租约过期策略', children: selected.on_lease_expired || 'strict（缺省）' },
                  { key: 'unk', label: 'UNKNOWN 处理', children: selected.on_unknown || 'ALLOW_UNKNOWN（缺省）' },
                  { key: 'owner', label: '业务负责人', children: selected.enforcement_owner || '—' },
                  { key: 'evid', label: '证据来源', children: selected.evidence_source || '—' },
                ]}
              />
              {canManage && selected.enforcement !== 'PROTECT' ? (
                <Button
                  type="primary"
                  danger
                  style={{ marginTop: 12 }}
                  onClick={() => setWizardPreset({ endpoint_id: selected.endpoint_id, object_segment: selected.object_segment })}
                >
                  切换 PROTECT
                </Button>
              ) : null}
            </div>
          </Space>
        ) : null}
      </Drawer>
      <ProtectWizard
        open={wizardPreset !== null}
        onClose={() => setWizardPreset(null)}
        applicationId={applicationId}
        preset={wizardPreset ?? undefined}
        onSwitched={() => {
          void listQuery.refetch()
          void readinessQuery.refetch()
          setSelected(null)
        }}
      />
    </>
  )
}

/** 访问模型（WDSP / 三微模型·访问微模型）：环境维度行为画像 + 对象维度对象模型 */
export default function ApiAccessProfilesPage() {
  const [applicationId, setApplicationId] = useState<string>()
  const siteSummaryQuery = useQuery({
    queryKey: ['api-endpoints', 'site-summary'],
    queryFn: () => apiEndpointsApi.siteSummary(),
  })

  return (
    <Card title="访问模型">
      <Space style={{ marginBottom: 12 }} wrap>
        <Typography.Text>站点选择：</Typography.Text>
        <Select
          placeholder="全部站点"
          allowClear
          showSearch
          optionFilterProp="label"
          style={{ width: 260 }}
          value={applicationId}
          onChange={(v) => setApplicationId(v)}
          loading={siteSummaryQuery.isLoading}
          options={(siteSummaryQuery.data?.items ?? []).map((s) => ({
            value: s.application_id,
            label: `${s.application_domain || s.application_name}（${s.endpoint_count}）`,
          }))}
        />
      </Space>
      <Tabs
        items={[
          { key: 'env', label: '环境维度 · 行为画像', children: <BehaviorProfilesTab applicationId={applicationId} /> },
          { key: 'object', label: '对象维度 · 对象模型', children: <ObjectModelsTab applicationId={applicationId} /> },
        ]}
      />
    </Card>
  )
}
