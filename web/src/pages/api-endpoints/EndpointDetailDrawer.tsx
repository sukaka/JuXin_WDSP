import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Descriptions,
  Drawer,
  Empty,
  Radio,
  Select,
  Space,
  Spin,
  Table,
  Tag,
  Typography,
} from 'antd'
import { DownloadOutlined } from '@ant-design/icons'
import { useNavigate } from 'react-router-dom'
import type { ColumnsType } from 'antd/es/table'
import * as echarts from 'echarts/core'
import dayjs from 'dayjs'
import { ApiError } from '../../api/client'
import {
  API_BUSINESS_TYPE_META,
  apiEndpointsApi,
  apiModelsApi,
  assetProfileInput,
  type ApiEndpointItem,
  type ApiTrafficTrendRange,
} from '../../api/apiAssets'
import {
  apiClassificationsApi,
  apiExposureApi,
  apiParametersApi,
  type ApiParameter,
} from '../../api/apiSecurity'
import AssetProfileSection from './AssetProfileSection'
import ResponseSchemaPanel from './ResponseSchemaPanel'
import EChart, { type EChartOption } from '../../components/EChart'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime, formatJson } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import {
  API_BASE_TYPE_META,
  API_CLASSIFICATION_SOURCE_META,
  API_ENDPOINT_STATUS_META,
  API_EXPOSURE_META,
  API_LEARNING_STATUS_META,
  API_MODEL_VERSION_STATUS_META,
  API_PARAM_DIRECTION_META,
  API_PARAM_LOCATION_META,
  API_PROTOCOL_META,
  EXPOSURE_CONFIDENCE_META,
  apiExposureLabel,
} from '../../utils/stage8'

/** 参数敏感级别（与 ApiParametersPage 口径一致） */
const SENSITIVITY_LEVEL_META: Record<string, { color: string; label: string }> =
  {
    UNKNOWN: { color: 'default', label: '未知' },
    LOW: { color: 'blue', label: '低' },
    MEDIUM: { color: 'orange', label: '中' },
    HIGH: { color: 'red', label: '高' },
  }

/**
 * 长度约束展示：优先确认约束，其次推荐约束，最后观测约束。
 * 三层约束均为 JSONB，键集合已钉死为 snake_case 词汇
 * （min_length/max_length/minimum/maximum/enum），这里仅消费 min_length/max_length。
 */
function lengthConstraintText(p: ApiParameter): string {
  for (const c of [
    p.confirmed_constraints,
    p.recommended_constraints,
    p.observed_constraints,
  ]) {
    const min = c?.min_length
    const max = c?.max_length
    if (typeof min === 'number' || typeof max === 'number') {
      return `${typeof min === 'number' ? min : 0} ~ ${typeof max === 'number' ? max : '∞'}`
    }
  }
  return '-'
}

const FORMAT_CANDIDATE_LABELS: Record<string, string> = {
  UUID: 'UUID',
  EMAIL: '邮箱',
  IPV4: 'IPv4 地址',
  IPV6: 'IPv6 地址',
  DATE: '日期',
  DATETIME: '日期时间',
}

function formatCandidateText(p: ApiParameter): string {
  const candidate = p.observed_constraints?.format_candidate
  const ratio = p.observed_constraints?.format_candidate_ratio
  if (
    typeof candidate !== 'string' ||
    typeof ratio !== 'number' ||
    !Number.isFinite(ratio) ||
    ratio < 0 ||
    ratio > 1
  ) {
    return '-'
  }
  const label = FORMAT_CANDIDATE_LABELS[candidate]
  if (typeof label !== 'string') return '-'
  return `${label} ${Number((ratio * 100).toFixed(2))}%`
}

/** 访问趋势波形图主题色（与全局 primary 一致） */
const TRAFFIC_TREND_COLOR = '#1677ff'

const EMPTY_TREND_POINTS: { time: string; count: number }[] = []

/** 原始数据展示框样式（与扫描发现样本展示一致） */
const RAW_PRE_STYLE: React.CSSProperties = {
  background: '#fafafa',
  padding: 12,
  fontSize: 12,
  overflow: 'auto',
  margin: 0,
  whiteSpace: 'pre-wrap',
  wordBreak: 'break-all',
  maxHeight: 320,
}

/** 原始数据查看目标 */
type RawDataTarget = 'endpoint' | 'model'

/** x 轴时间格式：1h/24h 按 HH:mm，7d 按 MM-DD HH:mm */
function trafficTrendTimeFormat(range: ApiTrafficTrendRange): string {
  return range === '7d' ? 'MM-DD HH:mm' : 'HH:mm'
}

/** 访问趋势波形：平滑面积折线（主题色纵向渐变，写法参考大屏 trendOption） */
function trafficTrendOption(
  points: { time: string; count: number }[],
  range: ApiTrafficTrendRange,
): EChartOption {
  return {
    grid: { left: 48, right: 16, top: 24, bottom: 28 },
    tooltip: { trigger: 'axis' },
    xAxis: {
      type: 'category',
      boundaryGap: false,
      data: points.map((p) =>
        dayjs(p.time).format(trafficTrendTimeFormat(range)),
      ),
      axisLabel: { hideOverlap: true },
    },
    yAxis: { type: 'value', minInterval: 1 },
    series: [
      {
        name: '访问量',
        type: 'line',
        smooth: true,
        symbol: 'none',
        data: points.map((p) => p.count),
        itemStyle: { color: TRAFFIC_TREND_COLOR },
        lineStyle: { width: 2, color: TRAFFIC_TREND_COLOR },
        areaStyle: {
          color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: 'rgba(22, 119, 255, 0.33)' },
            { offset: 1, color: 'rgba(22, 119, 255, 0)' },
          ]),
        },
      },
    ],
  }
}

interface Props {
  endpoint: ApiEndpointItem | null
  onClose: () => void
}

/** 接口详情抽屉：基础信息 + 暴露面判定（当前维度/评估明细/重评/人工确认）+ 访问趋势波形 + 模型版本 + 参数约束（类型/必填/长度）+ 原始数据；无参数行时回退展示版本扁平 Schema */
export default function EndpointDetailDrawer({ endpoint, onClose }: Props) {
  const navigate = useNavigate()
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canEditAsset = hasPermission(permissions, 'api_asset.edit')
  const canExport = hasPermission(permissions, 'api_asset.export')
  const canManageClassification = hasPermission(
    permissions,
    'api_classification.manage',
  )
  const endpointId = endpoint?.id
  const [versionId, setVersionId] = useState<string | undefined>()
  const [trendRange, setTrendRange] = useState<ApiTrafficTrendRange>('24h')
  const [rawTarget, setRawTarget] = useState<RawDataTarget>('endpoint')
  /** 业务标签编辑态：businessType 为当前选择，savedBusinessType 为已保存值（决定保存按钮可用性） */
  const [businessType, setBusinessType] = useState<string | undefined>()
  const [savedBusinessType, setSavedBusinessType] = useState<
    string | undefined
  >()
  /** 暴露面人工确认编辑态（仅 api_classification.manage 可见；提交后清空） */
  const [exposureManual, setExposureManual] = useState<string | undefined>()

  /** 切换接口或外部数据更新时同步业务标签编辑态 */
  useEffect(() => {
    const v = endpoint?.business_type || undefined
    setBusinessType(v)
    setSavedBusinessType(v)
  }, [endpointId, endpoint?.business_type])

  /** 切换接口时清空暴露面人工确认选择 */
  useEffect(() => {
    setExposureManual(undefined)
  }, [endpointId])

  /** 接口详情：资产档案 + 日均调用量；档案表单与业务标签保存的数据源 */
  const detailQuery = useQuery({
    queryKey: ['api-endpoints', 'detail', endpointId],
    queryFn: () => apiEndpointsApi.get(endpointId as string),
    enabled: !!endpointId,
  })

  /** 保存业务标签（PATCH 全量替换语义：合并当前档案提交，避免清空其他档案字段） */
  const businessTypeMut = useMutation({
    mutationFn: (v: string) =>
      apiEndpointsApi.update(
        endpointId as string,
        assetProfileInput(detailQuery.data?.endpoint.asset, {
          business_type: v,
        }),
      ),
    onSuccess: (r) => {
      message.success(r.message || '业务标签已保存')
      const v = r.endpoint.business_type || undefined
      setBusinessType(v)
      setSavedBusinessType(v)
      void queryClient.invalidateQueries({ queryKey: ['api-endpoints'] })
    },
    onError: (e: unknown) =>
      message.error(e instanceof ApiError ? e.message : '业务标签保存失败'),
  })

  /** 访问趋势：抽屉打开（endpoint 非空）时才查询 */
  const trendQuery = useQuery({
    queryKey: ['api-endpoints', 'traffic-trend', endpointId, trendRange],
    queryFn: () =>
      apiEndpointsApi.trafficTrend(endpointId as string, trendRange),
    enabled: !!endpointId,
  })

  /** 暴露面判定：抽屉打开（endpoint 非空）时才查询 */
  const exposureQuery = useQuery({
    queryKey: ['api-endpoint-exposure', endpointId],
    queryFn: () => apiExposureApi.get(endpointId as string),
    enabled: !!endpointId,
  })

  /** 即时重评（api_asset.edit）：成功后刷新暴露面查询 */
  const exposureReassessMut = useMutation({
    mutationFn: () => apiExposureApi.reassess(endpointId as string),
    onSuccess: (r) => {
      message.success(r.message || '已完成重新评估')
      void queryClient.invalidateQueries({
        queryKey: ['api-endpoint-exposure', endpointId],
      })
    },
    onError: (e: unknown) =>
      message.error(e instanceof ApiError ? e.message : '重新评估失败'),
  })

  /** 人工确认暴露面（api_classification.manage）：PUT EXPOSURE 维度为逐维 upsert，
   *  服务端同事务锁定 classification_locked，引擎后续不再覆盖 */
  const exposureConfirmMut = useMutation({
    mutationFn: (value: string) =>
      apiClassificationsApi.setEndpointClassification(endpointId as string, [
        { dimension: 'EXPOSURE', value },
      ]),
    onSuccess: (r) => {
      message.success(r.message || '已人工确认，引擎不再自动覆盖')
      setExposureManual(undefined)
      void queryClient.invalidateQueries({
        queryKey: ['api-endpoint-exposure', endpointId],
      })
      void queryClient.invalidateQueries({ queryKey: ['api-endpoints'] })
    },
    onError: (e: unknown) =>
      message.error(e instanceof ApiError ? e.message : '人工确认保存失败'),
  })

  const versionsQuery = useQuery({
    queryKey: ['api-models', 'versions', endpointId],
    queryFn: () =>
      apiModelsApi.list(endpointId as string, { page: 1, page_size: 100 }),
    enabled: !!endpointId,
  })

  /** 默认版本：接口当前版本 → 首个正式版 → 列表第一项 */
  useEffect(() => {
    if (versionId || !versionsQuery.data?.items.length) return
    const items = versionsQuery.data.items
    const preferred =
      items.find((v) => v.id === endpoint?.current_model_version_id) ??
      items.find((v) => v.status === 'FORMAL') ??
      items[0]
    setVersionId(preferred.id)
  }, [versionId, versionsQuery.data, endpoint?.current_model_version_id])

  /** 切换接口时重置版本选择 */
  useEffect(() => {
    setVersionId(undefined)
  }, [endpointId])

  const paramsQuery = useQuery({
    queryKey: ['api-parameters', versionId, 'drawer'],
    queryFn: () =>
      apiParametersApi.listByModel(versionId as string, {
        page: 1,
        page_size: 100,
      }),
    enabled: !!versionId,
  })

  const currentVersion = useMemo(
    () => versionsQuery.data?.items.find((v) => v.id === versionId),
    [versionsQuery.data, versionId],
  )
  const parameters = paramsQuery.data?.items ?? []
  const schemaFields = useMemo(
    () =>
      Object.entries(currentVersion?.schema ?? {}).map(([field, type]) => ({
        field,
        type,
      })),
    [currentVersion],
  )

  /** 趋势数据：points 已由服务端补零升序；峰值取 count 最大的桶 */
  const trendPoints = trendQuery.data?.points ?? EMPTY_TREND_POINTS
  const trendPeak = useMemo(
    () =>
      trendPoints.reduce<{ time: string; count: number } | null>(
        (max, p) => (max && max.count >= p.count ? max : p),
        null,
      ),
    [trendPoints],
  )

  /** 原始数据：接口记录或当前选中模型版本的原始 JSON */
  const rawData = useMemo(() => {
    if (!endpoint) return null
    return rawTarget === 'endpoint' ? endpoint : (currentVersion ?? null)
  }, [endpoint, rawTarget, currentVersion])

  /** 暴露面视图派生：当前判定/来源优先取维度实时口径（人工/锁定后引擎不改维度），无维度行回退最近一次评估结论 */
  const exposureView = exposureQuery.data
  const exposureAssessment = exposureView?.assessment ?? null
  const exposureCurrentValue = exposureView?.current?.value?.trim() ?? ''
  const exposureVerdict = (
    exposureCurrentValue ||
    exposureAssessment?.verdict ||
    ''
  )
    .trim()
    .toUpperCase()
  const exposureSource =
    (exposureCurrentValue
      ? exposureView?.current?.source
      : exposureAssessment?.source) ?? ''

  /** 互联网暴露：由暴露面判定派生（PUBLIC=是，INTERNAL/PARTNER=否，未判定=未知）；只读，修改走暴露面人工确认 */
  const internetExposedVerdict =
    exposureVerdict || (detailQuery.data?.endpoint?.asset?.exposure ?? '')
  const internetExposed =
    internetExposedVerdict === 'PUBLIC'
      ? '是'
      : internetExposedVerdict === 'INTERNAL' ||
          internetExposedVerdict === 'PARTNER'
        ? '否'
        : '未知'

  const paramColumns: ColumnsType<ApiParameter> = [
    {
      title: '参数名',
      dataIndex: 'parameter_name',
      ellipsis: true,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: '方向',
      dataIndex: 'direction',
      width: 80,
      render: (v: string) => (
        <StatusTag value={v} map={API_PARAM_DIRECTION_META} />
      ),
    },
    {
      title: '位置',
      dataIndex: 'location',
      width: 90,
      render: (v: string) => (
        <StatusTag value={v} map={API_PARAM_LOCATION_META} />
      ),
    },
    {
      title: '基础类型',
      dataIndex: 'base_type',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={API_BASE_TYPE_META} />,
    },
    {
      title: '语义类型',
      dataIndex: 'semantic_type',
      width: 110,
      ellipsis: true,
      render: (v: string) => v || '-',
    },
    {
      title: '必填',
      dataIndex: 'required',
      width: 70,
      render: (v: boolean) => (v ? <Tag color="green">是</Tag> : <Tag>否</Tag>),
    },
    {
      title: '长度约束',
      key: 'length',
      width: 110,
      render: (_, record) => lengthConstraintText(record),
    },
    {
      title: '格式候选',
      key: 'format_candidate',
      width: 120,
      render: (_, record) => formatCandidateText(record),
    },
    {
      title: '敏感级别',
      dataIndex: 'sensitivity_level',
      width: 90,
      render: (v: string) => (
        <StatusTag value={v} map={SENSITIVITY_LEVEL_META} />
      ),
    },
  ]

  return (
    <Drawer
      title={
        endpoint
          ? `接口详情：${endpoint.http_method} ${endpoint.normalized_path}`
          : '接口详情'
      }
      open={!!endpoint}
      onClose={onClose}
      width={800}
      destroyOnHidden
      extra={
        endpoint && canExport ? (
          <Button
            size="small"
            icon={<DownloadOutlined />}
            onClick={() =>
              window.open(
                apiEndpointsApi.detailExportUrl(endpoint.id),
                '_blank',
              )
            }
          >
            导出档案
          </Button>
        ) : null
      }
    >
      {endpoint ? (
        <>
          <Descriptions column={2} size="small" bordered>
            <Descriptions.Item label="站点">
              {endpoint.application_domain ||
                endpoint.application_name ||
                '未归属'}
            </Descriptions.Item>
            <Descriptions.Item label="目录">
              {endpoint.directory_path || '-'}
            </Descriptions.Item>
            <Descriptions.Item label="协议">
              <StatusTag
                value={endpoint.protocol_type}
                map={API_PROTOCOL_META}
              />
            </Descriptions.Item>
            <Descriptions.Item label="资产状态">
              <StatusTag
                value={endpoint.asset_status}
                map={API_ENDPOINT_STATUS_META}
              />
            </Descriptions.Item>
            <Descriptions.Item label="学习状态">
              <StatusTag
                value={endpoint.learning_status}
                map={API_LEARNING_STATUS_META}
              />
            </Descriptions.Item>
            <Descriptions.Item label="业务标签">
              <Space size={8}>
                <Select
                  size="small"
                  style={{ width: 180 }}
                  placeholder="未标注"
                  disabled={!canEditAsset}
                  value={businessType}
                  options={Object.entries(API_BUSINESS_TYPE_META).map(
                    ([value, m]) => ({
                      value,
                      label: m.label,
                    }),
                  )}
                  onChange={(v) => setBusinessType(v)}
                />
                {canEditAsset && (
                  <Button
                    size="small"
                    type="primary"
                    loading={businessTypeMut.isPending}
                    disabled={
                      !businessType ||
                      businessType === savedBusinessType ||
                      !detailQuery.data
                    }
                    onClick={() =>
                      businessType && businessTypeMut.mutate(businessType)
                    }
                  >
                    保存
                  </Button>
                )}
              </Space>
            </Descriptions.Item>
            <Descriptions.Item label="置信度">
              {(endpoint.api_confidence * 100).toFixed(0)}%
            </Descriptions.Item>
            <Descriptions.Item label="命中次数">
              {endpoint.hit_count}
            </Descriptions.Item>
            <Descriptions.Item label="首次发现">
              {formatDateTime(endpoint.first_seen_at)}
            </Descriptions.Item>
            <Descriptions.Item label="最近访问">
              {formatDateTime(endpoint.last_seen_at)}
            </Descriptions.Item>
          </Descriptions>
          <QueryErrorAlert error={detailQuery.error} />

          <AssetProfileSection
            endpointId={endpoint.id}
            asset={detailQuery.data?.endpoint?.asset}
            detailReady={!!detailQuery.data}
            dailyRequests={detailQuery.data?.daily_requests}
            internetExposed={internetExposed}
            canEdit={canEditAsset}
          />

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 12,
              margin: '16px 0 12px',
              flexWrap: 'wrap',
            }}
          >
            <Typography.Title level={5} style={{ margin: 0 }}>
              暴露面判定
            </Typography.Title>
            {canEditAsset && (
              <Button
                size="small"
                loading={exposureReassessMut.isPending}
                onClick={() => exposureReassessMut.mutate()}
              >
                重新评估
              </Button>
            )}
            {canManageClassification && (
              <Space size={8} style={{ marginLeft: 'auto' }}>
                <Select
                  size="small"
                  style={{ width: 140 }}
                  placeholder="人工确认暴露面"
                  value={exposureManual}
                  options={['INTERNAL', 'PARTNER', 'PUBLIC'].map((v) => ({
                    value: v,
                    label: apiExposureLabel(v),
                  }))}
                  onChange={(v) => setExposureManual(v)}
                />
                <Button
                  size="small"
                  type="primary"
                  loading={exposureConfirmMut.isPending}
                  disabled={!exposureManual}
                  onClick={() =>
                    exposureManual && exposureConfirmMut.mutate(exposureManual)
                  }
                >
                  人工确认
                </Button>
              </Space>
            )}
          </div>
          <QueryErrorAlert error={exposureQuery.error} />
          {exposureQuery.isLoading ? (
            <div
              style={{
                display: 'flex',
                justifyContent: 'center',
                padding: '12px 0',
              }}
            >
              <Spin size="small" />
            </div>
          ) : exposureView ? (
            <>
              <Descriptions column={2} size="small" bordered>
                <Descriptions.Item label="当前判定">
                  <Space size={8} wrap>
                    {exposureVerdict ? (
                      <StatusTag
                        value={exposureVerdict}
                        map={API_EXPOSURE_META}
                      />
                    ) : (
                      '-'
                    )}
                    {exposureView.locked && (
                      <Tag color="gold">已人工确认，引擎不再自动覆盖</Tag>
                    )}
                  </Space>
                </Descriptions.Item>
                <Descriptions.Item label="来源">
                  {exposureSource ? (
                    <StatusTag
                      value={exposureSource.trim().toUpperCase()}
                      map={API_CLASSIFICATION_SOURCE_META}
                    />
                  ) : (
                    '-'
                  )}
                </Descriptions.Item>
                <Descriptions.Item label="置信度">
                  {exposureAssessment ? (
                    <StatusTag
                      value={exposureAssessment.confidence.trim().toUpperCase()}
                      map={EXPOSURE_CONFIDENCE_META}
                    />
                  ) : (
                    '-'
                  )}
                </Descriptions.Item>
                <Descriptions.Item label="最近评估时间">
                  {exposureAssessment
                    ? formatDateTime(exposureAssessment.assessed_at)
                    : '-'}
                </Descriptions.Item>
              </Descriptions>
              {exposureAssessment ? (
                exposureAssessment.evidence.length > 0 ? (
                  <ul style={{ margin: '12px 0 0', paddingLeft: 20 }}>
                    {exposureAssessment.evidence.map((ev, index) => (
                      <li key={index}>
                        <Typography.Text type="secondary">
                          {ev.summary}
                        </Typography.Text>
                      </li>
                    ))}
                  </ul>
                ) : null
              ) : (
                <Empty
                  image={Empty.PRESENTED_IMAGE_SIMPLE}
                  description="暂无评估结果"
                  style={{ margin: '12px 0' }}
                />
              )}
            </>
          ) : null}

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 12,
              margin: '16px 0 12px',
              flexWrap: 'wrap',
            }}
          >
            <Typography.Title level={5} style={{ margin: 0 }}>
              访问趋势
            </Typography.Title>
            <Radio.Group
              size="small"
              optionType="button"
              value={trendRange}
              onChange={(e) =>
                setTrendRange(e.target.value as ApiTrafficTrendRange)
              }
              options={[
                { value: '1h', label: '1小时' },
                { value: '24h', label: '24小时' },
                { value: '7d', label: '7天' },
              ]}
            />
            {trendQuery.data ? (
              <Typography.Text type="secondary" style={{ marginLeft: 'auto' }}>
                总访问量 {trendQuery.data.total}
                {trendPeak
                  ? ` · 峰值 ${trendPeak.count} 次（${dayjs(trendPeak.time).format(trafficTrendTimeFormat(trendRange))}）`
                  : ''}
              </Typography.Text>
            ) : null}
          </div>
          <QueryErrorAlert error={trendQuery.error} />
          {trendQuery.isLoading ? (
            <div
              style={{
                height: 220,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Spin />
            </div>
          ) : trendPoints.length > 0 ? (
            <EChart
              option={trafficTrendOption(trendPoints, trendRange)}
              height={220}
              ariaLabel="端点访问趋势"
            />
          ) : (
            <Empty
              image={Empty.PRESENTED_IMAGE_SIMPLE}
              description="暂无访问数据"
              style={{ margin: '24px 0' }}
            />
          )}

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 12,
              margin: '16px 0 12px',
            }}
          >
            <Typography.Title level={5} style={{ margin: 0 }}>
              参数约束
            </Typography.Title>
            <Select
              size="small"
              placeholder="模型版本"
              style={{ width: 220 }}
              loading={versionsQuery.isLoading}
              value={versionId}
              options={(versionsQuery.data?.items ?? []).map((m) => ({
                value: m.id,
                label: `v${m.version_number} ${API_MODEL_VERSION_STATUS_META[m.status]?.label ?? m.status}`,
              }))}
              onChange={(v) => setVersionId(v)}
            />
            <Button
              size="small"
              type="link"
              onClick={() => navigate('/api-parameters')}
            >
              前往参数模型页管理
            </Button>
          </div>
          <QueryErrorAlert error={versionsQuery.error ?? paramsQuery.error} />

          {parameters.length > 0 ? (
            <Table<ApiParameter>
              size="small"
              rowKey="id"
              loading={paramsQuery.isLoading}
              columns={paramColumns}
              dataSource={parameters}
              pagination={false}
            />
          ) : schemaFields.length > 0 ? (
            <>
              <Alert
                type="info"
                showIcon
                style={{ marginBottom: 12 }}
                message="学习管线尚未生成参数行，以下为该模型版本的扁平 Schema（字段名 → 类型）"
              />
              <Table
                size="small"
                rowKey="field"
                columns={[
                  {
                    title: '字段名',
                    dataIndex: 'field',
                    render: (v: string) => (
                      <Typography.Text code>{v}</Typography.Text>
                    ),
                  },
                  { title: '类型', dataIndex: 'type', width: 160 },
                ]}
                dataSource={schemaFields}
                pagination={false}
              />
            </>
          ) : (
            <Alert
              type="info"
              showIcon
              message={
                versionsQuery.data?.items.length
                  ? // GET/HEAD 无请求体，采样不到参数属正常情况，与「管线尚未生成」区分展示
                    ['GET', 'HEAD'].includes(endpoint.http_method)
                    ? `该接口为 ${endpoint.http_method} 请求，未观测到 PATH / QUERY / BODY 参数`
                    : '当前版本暂无参数数据'
                  : '该接口暂无模型版本，参数需经学习中心完成采样学习后生成'
              }
            />
          )}

          <ResponseSchemaPanel endpointId={endpoint.id} />

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 12,
              margin: '16px 0 12px',
            }}
          >
            <Typography.Title level={5} style={{ margin: 0 }}>
              原始数据
            </Typography.Title>
            <Radio.Group
              size="small"
              optionType="button"
              value={rawTarget}
              onChange={(e) => setRawTarget(e.target.value as RawDataTarget)}
              options={[
                { value: 'endpoint', label: '接口记录' },
                { value: 'model', label: '当前模型版本' },
              ]}
            />
          </div>
          <pre style={RAW_PRE_STYLE}>{formatJson(rawData)}</pre>
        </>
      ) : null}
    </Drawer>
  )
}
