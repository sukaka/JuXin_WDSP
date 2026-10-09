import { useMemo, useState, type ReactNode } from 'react'
import { useQueries, useQuery, type UseQueryResult } from '@tanstack/react-query'
import {
  Button,
  Card,
  InputNumber,
  Popover,
  Progress,
  Segmented,
  Space,
  Spin,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { apiAdmissionApi } from '../../api/apiAdmission'
import { applicationsApi } from '../../api/applications'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import type { ApiAdmissionCoverage, ApplicationItem } from '../../types'
import { hasPermission } from '../../utils/permission'
import AdmissionDetailDrawer from './AdmissionDetailDrawer'
import ModeSwitchModal from './ModeSwitchModal'
import {
  ADMISSION_MODE_META,
  CUSTOM_WINDOW_MAX_DAYS,
  CUSTOM_WINDOW_MIN_DAYS,
  DEFAULT_HITS_WINDOW_HOURS,
  WINDOW_PRESETS,
} from './admissionMeta'

/**
 * API 准入防护（docs/API_ADMISSION_CONTROL_DESIGN.md §6）：
 * 应用级准入模式总览（OFF/OBSERVE/PROTECT）+ 覆盖率与影响面评估 + 准入拦截处置。
 * 命中统计窗口作用于整页命中/拦截数字；确认/忽略/模式切换均随整站发布生效。
 */
export default function ApiAdmissionPage() {
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canUpdateApp = hasPermission(permissions, 'applications.update')

  const [hitsWindowHours, setHitsWindowHours] = useState(DEFAULT_HITS_WINDOW_HOURS)
  const [customOpen, setCustomOpen] = useState(false)
  const [customDays, setCustomDays] = useState<number>(7)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [modeTarget, setModeTarget] = useState<ApplicationItem | null>(null)
  const [detailApp, setDetailApp] = useState<ApplicationItem | null>(null)

  const appsQuery = useQuery({
    queryKey: ['applications', 'api-admission', page, pageSize],
    queryFn: () => applicationsApi.list({ page, page_size: pageSize }),
  })
  const apps = useMemo(() => appsQuery.data?.items ?? [], [appsQuery.data])

  // 覆盖率接口按应用维度（冻结契约），对当前页每个应用各发一次查询，共用 queryKey 缓存
  const coverageQueries = useQueries({
    queries: apps.map((app) => ({
      queryKey: ['api-admission', 'coverage', app.id, hitsWindowHours],
      queryFn: () =>
        apiAdmissionApi.coverage({ application_id: app.id, hits_window: hitsWindowHours }),
    })),
  })
  const coverageByApp = useMemo(() => {
    const map = new Map<string, UseQueryResult<ApiAdmissionCoverage, Error>>()
    apps.forEach((app, i) => {
      const q = coverageQueries[i]
      if (q) map.set(app.id, q)
    })
    return map
  }, [apps, coverageQueries])
  const coverageError = coverageQueries.find((q) => q.isError)?.error ?? null

  const presetLabel = WINDOW_PRESETS.find((p) => p.hours === hitsWindowHours)?.label
  const windowLabel = presetLabel ?? `${Math.round(hitsWindowHours / 24)}天`

  const applyCustomWindow = () => {
    const days = Math.min(
      Math.max(Math.round(customDays), CUSTOM_WINDOW_MIN_DAYS),
      CUSTOM_WINDOW_MAX_DAYS,
    )
    setHitsWindowHours(days * 24)
    setCustomOpen(false)
  }

  /** 覆盖率单元格统一渲染：加载中转圈、失败红字、成功交给内容渲染 */
  const renderCoverage = (
    record: ApplicationItem,
    render: (coverage: ApiAdmissionCoverage) => ReactNode,
  ) => {
    const q = coverageByApp.get(record.id)
    if (!q || q.isPending) return <Spin size="small" />
    if (q.isError || !q.data) return <Typography.Text type="danger">加载失败</Typography.Text>
    return render(q.data)
  }

  const columns: ColumnsType<ApplicationItem> = [
    {
      title: '应用',
      key: 'app',
      render: (_, record) => (
        <Space direction="vertical" size={0}>
          <Typography.Text strong>{record.name}</Typography.Text>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {record.code}
          </Typography.Text>
        </Space>
      ),
    },
    {
      title: '准入模式',
      key: 'api_admission_mode',
      width: 100,
      render: (_, record) => (
        <StatusTag value={record.api_admission_mode ?? 'OFF'} map={ADMISSION_MODE_META} />
      ),
    },
    {
      title: '确认覆盖率',
      key: 'confirm_rate',
      width: 300,
      render: (_, record) =>
        renderCoverage(record, (coverage) => (
          <Space size={8} wrap>
            <Progress
              percent={Math.round(coverage.confirm_rate * 100)}
              size="small"
              style={{ width: 150, minWidth: 150 }}
            />
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              已确认 {coverage.endpoints.confirmed} / 未确认 {coverage.endpoints.discovered}
            </Typography.Text>
          </Space>
        )),
    },
    {
      title: '窗口内未确认命中',
      key: 'unconfirmed_hits',
      width: 150,
      render: (_, record) =>
        renderCoverage(record, (coverage) => {
          const hits = coverage.unconfirmed_hot.reduce((sum, e) => sum + e.hits, 0)
          return hits > 0 ? (
            <Typography.Text type="danger" strong>
              {hits}
            </Typography.Text>
          ) : (
            <Typography.Text>0</Typography.Text>
          )
        }),
    },
    {
      title: '窗口内准入拦截',
      key: 'blocked',
      width: 140,
      render: (_, record) =>
        renderCoverage(record, (coverage) => <Typography.Text>{coverage.blocked}</Typography.Text>),
    },
    {
      title: '操作',
      key: 'actions',
      width: 190,
      render: (_, record) => (
        <Space size={0}>
          {canUpdateApp ? (
            <Button type="link" size="small" onClick={() => setModeTarget(record)}>
              切换模式
            </Button>
          ) : null}
          <Button type="link" size="small" onClick={() => setDetailApp(record)}>
            准入详情
          </Button>
        </Space>
      ),
    },
  ]

  return (
    <Card title="API 准入防护">
      <Typography.Paragraph type="secondary">
        应用级准入模式：观察期学习流量并确认接口资产，确认覆盖率达标后切换防护模式，此后仅已确认接口放行、未确认接口一律拒绝（403）。模式与确认集变更随整站发布生效。
      </Typography.Paragraph>
      <Space style={{ marginBottom: 16 }} wrap>
        <Typography.Text>命中窗口</Typography.Text>
        <Segmented<number>
          value={hitsWindowHours}
          onChange={setHitsWindowHours}
          options={WINDOW_PRESETS.map((p) => ({ value: p.hours, label: p.label }))}
        />
        <Popover
          open={customOpen}
          onOpenChange={setCustomOpen}
          trigger="click"
          placement="bottomLeft"
          content={
            <Space>
              <InputNumber
                min={CUSTOM_WINDOW_MIN_DAYS}
                max={CUSTOM_WINDOW_MAX_DAYS}
                precision={0}
                value={customDays}
                onChange={(v) =>
                  setCustomDays(typeof v === 'number' ? v : CUSTOM_WINDOW_MIN_DAYS)
                }
                addonAfter="天"
                style={{ width: 140 }}
              />
              <Button type="primary" size="small" onClick={applyCustomWindow}>
                确定
              </Button>
            </Space>
          }
        >
          <Button size="small">自定义</Button>
        </Popover>
        <Typography.Text type="secondary">当前：{windowLabel}</Typography.Text>
      </Space>
      <QueryErrorAlert error={appsQuery.error} />
      <QueryErrorAlert error={coverageError} message="加载覆盖率失败" />
      <SmartTable<ApplicationItem>
        storageKey="api-admission"
        rowKey="id"
        loading={appsQuery.isLoading}
        columns={columns}
        dataSource={apps}
        pagination={{
          current: page,
          pageSize,
          total: appsQuery.data?.total ?? 0,
          showSizeChanger: true,
          showTotal: (t) => `共 ${t} 条`,
          onChange: (p, ps) => {
            setPage(p)
            setPageSize(ps)
          },
        }}
      />
      {modeTarget ? (
        <ModeSwitchModal
          key={modeTarget.id}
          app={modeTarget}
          hitsWindowHours={hitsWindowHours}
          onClose={() => setModeTarget(null)}
        />
      ) : null}
      {detailApp ? (
        <AdmissionDetailDrawer
          key={detailApp.id}
          app={detailApp}
          hitsWindowHours={hitsWindowHours}
          onClose={() => setDetailApp(null)}
        />
      ) : null}
    </Card>
  )
}
