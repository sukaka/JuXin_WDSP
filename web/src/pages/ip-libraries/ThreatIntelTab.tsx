import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Col,
  Descriptions,
  Drawer,
  Form,
  Input,
  InputNumber,
  List,
  Modal,
  Popconfirm,
  Radio,
  Row,
  Select,
  Space,
  Statistic,
  Switch,
  Tag,
  Tooltip,
  Typography,
  Upload,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import {
  CloudSyncOutlined,
  DeleteOutlined,
  EditOutlined,
  HistoryOutlined,
  ImportOutlined,
  PlusOutlined,
  SafetyOutlined,
  UploadOutlined,
  WarningOutlined,
} from '@ant-design/icons'
import { ApiError } from '../../api/client'
import {
  ipLibrariesApi,
  type ThreatIntelFeed,
  type ThreatIntelFeedBody,
  type ThreatIntelImportBody,
  type ThreatIntelImportResult,
  type ThreatIntelSyncRun,
} from '../../api/ipLibraries'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { formatDateTime, formatDuration } from '../../utils/format'
import {
  DEFAULT_THREAT_PRESETS,
  SOURCE_MODE_META,
  SOURCE_MODE_OPTIONS,
  THREAT_FORMAT_META,
  THREAT_RUN_STATUS_META,
  THREAT_TRIGGER_META,
} from './meta'

const FEED_KEY_RE = /^[a-z0-9][a-z0-9_-]{0,31}$/

interface RunFilters {
  feed_key?: string
  trigger_type?: string
  status?: string
}

interface FeedFormValues {
  feed_key: string
  name: string
  description?: string
  enabled: boolean
  source_mode: 'OFFLINE_ONLY' | 'OFFICIAL' | 'CUSTOM_URL'
  official_preset?: string
  custom_url?: string
  format: 'text' | 'csv'
  allow_cidr: boolean
  ttl_days: number
  schedule_cron: string
  min_entries_guard: boolean
  max_drop_ratio: number
}

interface ImportFormValues {
  feed: string
  format: 'text' | 'csv'
  ttl_days: number
  content: string
}

export interface ThreatIntelTabProps {
  canManage: boolean
  canImport: boolean
}

export default function ThreatIntelTab({ canManage, canImport }: ThreatIntelTabProps) {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()

  const [runFilters, setRunFilters] = useState<RunFilters>({})
  const [runsPage, setRunsPage] = useState(1)
  const [runsPageSize, setRunsPageSize] = useState(10)

  // 全局定时与熔断设置草稿
  const [autoUpdateEnabled, setAutoUpdateEnabled] = useState(false)
  const [circuitThreshold, setCircuitThreshold] = useState(5)

  // 新建/编辑订阅源弹窗
  const [feedModalOpen, setFeedModalOpen] = useState(false)
  const [editingFeed, setEditingFeed] = useState<ThreatIntelFeed | null>(null)
  const [feedForm] = Form.useForm<FeedFormValues>()

  // 离线快照导入抽屉
  const [importOpen, setImportOpen] = useState(false)
  const [importResult, setImportResult] = useState<ThreatIntelImportResult | null>(null)
  const [importForm] = Form.useForm<ImportFormValues>()

  const [syncingFeedId, setSyncingFeedId] = useState<string | null>(null)

  const feedsQuery = useQuery({
    queryKey: ['ip-libraries', 'threat-intel', 'feeds'],
    queryFn: () => ipLibrariesApi.listThreatIntelFeeds(),
  })

  const runsQuery = useQuery({
    queryKey: ['ip-libraries', 'threat-intel', 'runs', runFilters, runsPage, runsPageSize],
    queryFn: () =>
      ipLibrariesApi.listThreatIntelRuns({
        ...runFilters,
        page: runsPage,
        page_size: runsPageSize,
      }),
  })

  const data = feedsQuery.data
  const feeds = useMemo(() => data?.feeds ?? [], [data?.feeds])
  const presets = useMemo(
    () => (data?.presets && data.presets.length > 0 ? data.presets : DEFAULT_THREAT_PRESETS),
    [data?.presets],
  )
  const presetMap = useMemo(() => new Map(presets.map((p) => [p.key, p])), [presets])
  const circuitOpenFeeds = useMemo(() => feeds.filter((f) => f.circuit_open), [feeds])

  useEffect(() => {
    if (!data?.settings) return
    setAutoUpdateEnabled(Boolean(data.settings.auto_update_enabled))
    setCircuitThreshold(data.settings.circuit_threshold || 5)
  }, [data?.settings])

  const invalidateThreat = () => {
    void queryClient.invalidateQueries({ queryKey: ['ip-libraries', 'threat-intel'] })
  }

  const onError = (e: unknown, fallback = '操作失败') => {
    message.error(e instanceof ApiError ? e.message : fallback)
  }

  const saveGlobalSettingsMutation = useMutation({
    mutationFn: () =>
      ipLibrariesApi.updateThreatIntelSettings({
        auto_update_enabled: autoUpdateEnabled,
        circuit_threshold: circuitThreshold,
      }),
    onSuccess: () => {
      message.success('威胁情报全局调度与熔断配置已保存')
      invalidateThreat()
    },
    onError: (e) => onError(e, '保存威胁情报全局设置失败'),
  })

  const saveFeedMutation = useMutation({
    mutationFn: (values: FeedFormValues) => {
      const body: ThreatIntelFeedBody = {
        feed_key: editingFeed ? editingFeed.feed_key : values.feed_key.trim().toLowerCase(),
        name: values.name.trim(),
        description: (values.description ?? '').trim(),
        enabled: Boolean(values.enabled),
        source_mode: values.source_mode,
        official_preset:
          values.source_mode === 'OFFICIAL' ? (values.official_preset ?? '').trim() : '',
        custom_url: values.source_mode === 'CUSTOM_URL' ? (values.custom_url ?? '').trim() : '',
        format: values.format,
        allow_cidr: Boolean(values.allow_cidr),
        ttl_days: values.ttl_days ?? 30,
        schedule_cron: (values.schedule_cron ?? '').trim() || '0 */6 * * *',
        min_entries_guard: Boolean(values.min_entries_guard),
        max_drop_ratio: values.max_drop_ratio ?? 0.8,
      }
      if (editingFeed) {
        return ipLibrariesApi.updateThreatIntelFeed(editingFeed.id, body)
      }
      return ipLibrariesApi.createThreatIntelFeed(body)
    },
    onSuccess: () => {
      message.success(editingFeed ? '订阅源配置已更新' : '自定义订阅源已创建')
      setFeedModalOpen(false)
      setEditingFeed(null)
      feedForm.resetFields()
      invalidateThreat()
    },
    onError: (e) => onError(e, '保存订阅源失败'),
  })

  const deleteFeedMutation = useMutation({
    mutationFn: (id: string) => ipLibrariesApi.deleteThreatIntelFeed(id),
    onSuccess: () => {
      message.success('自定义订阅源已删除')
      invalidateThreat()
    },
    onError: (e) => onError(e, '删除订阅源失败'),
  })

  const syncFeedMutation = useMutation({
    mutationFn: ({ id, force }: { id: string; force: boolean }) => {
      setSyncingFeedId(id)
      return ipLibrariesApi.syncThreatIntelFeed(id, force)
    },
    onSuccess: (res, vars) => {
      invalidateThreat()
      const run = res.run
      const feedKey = res.feed?.feed_key || run?.feed_key || vars.id
      if ((res.guard_triggered || run?.status === 'GUARD_ABORTED') && !vars.force) {
        modal.confirm({
          title: '安全护栏已中止对账，是否忽略保护强制同步？',
          icon: <WarningOutlined style={{ color: '#fa8c16' }} />,
          content: (
            <Space direction="vertical" size={4}>
              <Typography.Text>
                情报源 <Typography.Text code>{feedKey}</Typography.Text> 本次拉取触发安全护栏：
                {res.guard_reason ||
                  run?.error_message ||
                  '上游返回条目数量骤降或为空，已保护在册黑名单未被清空。'}
              </Typography.Text>
              <Typography.Text type="danger">
                确认上游数据源正常后，可点击「忽略保护强制同步」跳过骤降比例护栏并完成对账。
              </Typography.Text>
            </Space>
          ),
          okText: '忽略保护强制同步',
          okButtonProps: { danger: true },
          cancelText: '取消',
          onOk: () => syncFeedMutation.mutate({ id: vars.id, force: true }),
        })
        return
      }
      if (run?.status === 'SKIPPED_NOT_MODIFIED') {
        message.info(`情报源 ${feedKey} 上游无变化，已跳过对账与发布`)
      } else if (run?.status === 'FAILED') {
        const circuitHint = res.circuit_opened ? '（已触发连续失败熔断）' : ''
        message.error(
          `情报源 ${feedKey} 拉取失败${circuitHint}：${run.error_message || '未知错误'}`,
        )
      } else if (run) {
        message.success(
          `同步完成（${feedKey}）：新增 ${run.added}，刷新 ${run.refreshed}，过期 ${run.expired}${run.published ? '，已触发网关发布' : ''}`,
        )
      } else {
        message.success(`情报源 ${feedKey} 同步完成`)
      }
    },
    onError: (e) => onError(e, '触发威胁情报拉取失败'),
    onSettled: () => setSyncingFeedId(null),
  })

  const importMutation = useMutation({
    mutationFn: (body: ThreatIntelImportBody) => ipLibrariesApi.importThreatIntelSnapshot(body),
    onSuccess: (res) => {
      setImportResult(res)
      message.success(
        `离线快照对账完成（${res.feed}）：新增 ${res.added}，刷新 ${res.refreshed}，过期 ${res.expired}`,
      )
      invalidateThreat()
    },
    onError: (e) => onError(e, '离线导入威胁情报失败'),
  })

  const confirmForceSync = (feed: ThreatIntelFeed) => {
    modal.confirm({
      title: `强制同步「${feed.name}」`,
      icon: <WarningOutlined style={{ color: '#fa8c16' }} />,
      content: `该情报源最近一次拉取触发了防误清空/骤降保护（${feed.last_error || '条目数量异常缩水'}）。确定忽略保护并强制对账更新吗？`,
      okText: '确认强制同步',
      okButtonProps: { danger: true },
      onOk: () => syncFeedMutation.mutate({ id: feed.id, force: true }),
    })
  }

  const openCreateFeed = () => {
    setEditingFeed(null)
    feedForm.setFieldsValue({
      feed_key: '',
      name: '',
      description: '',
      enabled: false,
      source_mode: 'CUSTOM_URL',
      official_preset: '',
      custom_url: '',
      format: 'text',
      allow_cidr: false,
      ttl_days: 30,
      schedule_cron: '0 */6 * * *',
      min_entries_guard: true,
      max_drop_ratio: 0.8,
    })
    setFeedModalOpen(true)
  }

  const openEditFeed = (feed: ThreatIntelFeed) => {
    setEditingFeed(feed)
    feedForm.setFieldsValue({
      feed_key: feed.feed_key,
      name: feed.name,
      description: feed.description,
      enabled: feed.enabled,
      source_mode: (feed.source_mode as FeedFormValues['source_mode']) || 'OFFLINE_ONLY',
      official_preset: feed.official_preset || undefined,
      custom_url: feed.custom_url || '',
      format: (feed.format as 'text' | 'csv') || 'text',
      allow_cidr: feed.allow_cidr,
      ttl_days: feed.ttl_days,
      schedule_cron: feed.schedule_cron || '0 */6 * * *',
      min_entries_guard: feed.min_entries_guard,
      max_drop_ratio: feed.max_drop_ratio,
    })
    setFeedModalOpen(true)
  }

  const applyPresetDefaults = (presetKey: string) => {
    const preset = presetMap.get(presetKey)
    if (!preset) return
    const patch: Partial<FeedFormValues> = {
      format: preset.format === 'csv' ? 'csv' : 'text',
      allow_cidr: Boolean(preset.allow_cidr),
      ttl_days: preset.default_ttl_days ?? 30,
      schedule_cron: preset.default_cron || '0 */6 * * *',
    }
    if (!editingFeed) {
      const currentName = (feedForm.getFieldValue('name') as string | undefined)?.trim()
      const currentDesc = (feedForm.getFieldValue('description') as string | undefined)?.trim()
      if (!currentName || presets.some((p) => p.name === currentName)) {
        patch.name = preset.name
      }
      if (!currentDesc || presets.some((p) => (p.description ?? '') === currentDesc)) {
        patch.description = preset.description ?? ''
      }
    }
    feedForm.setFieldsValue(patch)
  }

  const openImportDrawer = (defaultFeedKey?: string) => {
    setImportResult(null)
    importForm.setFieldsValue({
      feed: defaultFeedKey || feeds[0]?.feed_key || 'ipsum_l5',
      format: 'text',
      ttl_days: 30,
      content: '',
    })
    setImportOpen(true)
  }

  const feedColumns: ColumnsType<ThreatIntelFeed> = [
    {
      title: '订阅源名称',
      key: 'name',
      width: 240,
      render: (_, record) => {
        const presetLicense =
          record.source_mode === 'OFFICIAL' ? presetMap.get(record.official_preset)?.license : undefined
        return (
          <Space direction="vertical" size={2}>
            <Space size={6} wrap>
              <Typography.Text strong>{record.name}</Typography.Text>
              <Tag color={record.is_builtin ? 'blue' : 'purple'}>
                {record.is_builtin ? '内置' : '自定义'}
              </Tag>
              {presetLicense && <Tag color="geekblue">{presetLicense}</Tag>}
            </Space>
            <Space size={6}>
              <Typography.Text code style={{ fontSize: 12 }}>
                {record.feed_key}
              </Typography.Text>
              {record.description && (
                <Tooltip title={record.description}>
                  <Typography.Text type="secondary" ellipsis style={{ fontSize: 12, maxWidth: 160 }}>
                    {record.description}
                  </Typography.Text>
                </Tooltip>
              )}
            </Space>
          </Space>
        )
      },
    },
    {
      title: '来源与格式',
      key: 'source',
      width: 220,
      render: (_, record) => (
        <Space direction="vertical" size={2}>
          <Space size={4} wrap>
            <StatusTag value={record.source_mode} map={SOURCE_MODE_META} />
            <StatusTag value={record.format} map={THREAT_FORMAT_META} />
            {record.allow_cidr ? (
              <Tag color="cyan">支持 CIDR (/16–/32)</Tag>
            ) : (
              <Tag>仅单 IP</Tag>
            )}
          </Space>
          {record.source_mode === 'CUSTOM_URL' && record.custom_url && (
            <Tooltip title={record.custom_url}>
              <Typography.Text type="secondary" ellipsis style={{ fontSize: 12, maxWidth: 205 }}>
                {record.custom_url}
              </Typography.Text>
            </Tooltip>
          )}
          {record.source_mode === 'OFFICIAL' && record.official_preset && (
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              预置源：{record.official_preset}
            </Typography.Text>
          )}
        </Space>
      ),
    },
    {
      title: 'TTL 与调度',
      key: 'policy',
      width: 170,
      render: (_, record) => (
        <Space direction="vertical" size={2}>
          <Typography.Text style={{ fontSize: 12 }}>
            TTL：{record.ttl_days === 0 ? '永久' : `${record.ttl_days} 天`}
          </Typography.Text>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            Cron：{record.schedule_cron || '-'}
          </Typography.Text>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            护栏：{record.min_entries_guard ? '空集保护 / ' : ''}骤降 &gt;
            {Math.round((record.max_drop_ratio ?? 0.8) * 100)}%
          </Typography.Text>
        </Space>
      ),
    },
    {
      title: '生效规则数',
      dataIndex: 'active_rule_count',
      width: 105,
      render: (v: number) => <Typography.Text strong>{v ?? 0}</Typography.Text>,
    },
    {
      title: '状态与最近同步',
      key: 'status',
      width: 220,
      render: (_, record) => (
        <Space direction="vertical" size={2}>
          <Space size={4} wrap>
            <Tag color={record.enabled ? 'green' : 'default'}>
              {record.enabled ? '已启用' : '已停用'}
            </Tag>
            {record.circuit_open && (
              <Tag color="red" icon={<WarningOutlined />}>
                已熔断（失败 {record.consecutive_failures} 次）
              </Tag>
            )}
            <StatusTag value={record.last_status} map={THREAT_RUN_STATUS_META} />
          </Space>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            最近同步：{formatDateTime(record.last_sync_at)}
          </Typography.Text>
          {record.last_error && (
            <Tooltip title={record.last_error}>
              <Typography.Text type="danger" ellipsis style={{ fontSize: 12, maxWidth: 205 }}>
                {record.last_error}
              </Typography.Text>
            </Tooltip>
          )}
        </Space>
      ),
    },
    ...(canManage
      ? [
          {
            title: '操作',
            key: 'actions',
            width: 260,
            fixed: 'right' as const,
            render: (_: unknown, record: ThreatIntelFeed) => (
              <Space size={0} wrap>
                <Tooltip
                  title={
                    record.source_mode === 'OFFLINE_ONLY'
                      ? '纯离线源无法在线拉取，请使用离线快照导入'
                      : '立即拉取并对账更新黑名单'
                  }
                >
                  <Button
                    type="link"
                    size="small"
                    disabled={record.source_mode === 'OFFLINE_ONLY'}
                    loading={syncFeedMutation.isPending && syncingFeedId === record.id}
                    onClick={() => syncFeedMutation.mutate({ id: record.id, force: false })}
                  >
                    立即拉取
                  </Button>
                </Tooltip>
                {record.last_status === 'GUARD_ABORTED' && record.source_mode !== 'OFFLINE_ONLY' && (
                  <Button
                    type="link"
                    size="small"
                    danger
                    loading={syncFeedMutation.isPending && syncingFeedId === record.id}
                    onClick={() => confirmForceSync(record)}
                  >
                    强制同步
                  </Button>
                )}
                <Button
                  type="link"
                  size="small"
                  icon={<EditOutlined />}
                  onClick={() => openEditFeed(record)}
                >
                  编辑
                </Button>
                {!record.is_builtin && (
                  <Popconfirm
                    title={`确认删除自定义订阅源「${record.name}」吗？`}
                    description="删除订阅源不会自动清理历史导入的在册黑名单规则。"
                    okButtonProps={{ danger: true }}
                    onConfirm={() => deleteFeedMutation.mutate(record.id)}
                  >
                    <Button type="link" size="small" danger icon={<DeleteOutlined />}>
                      删除
                    </Button>
                  </Popconfirm>
                )}
              </Space>
            ),
          },
        ]
      : []),
  ]

  const runColumns: ColumnsType<ThreatIntelSyncRun> = [
    {
      title: '订阅源',
      dataIndex: 'feed_key',
      width: 130,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: '触发方式',
      dataIndex: 'trigger_type',
      width: 110,
      render: (v: string) => <StatusTag value={v} map={THREAT_TRIGGER_META} />,
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 120,
      render: (v: string) => <StatusTag value={v} map={THREAT_RUN_STATUS_META} />,
    },
    {
      title: '批次号',
      dataIndex: 'batch_id',
      width: 160,
      ellipsis: true,
      render: (v: string) => (v ? <Typography.Text code>{v}</Typography.Text> : '-'),
    },
    {
      title: '对账统计（解析 / 新增 / 刷新 / 过期 / 跳过 / 无效）',
      key: 'counts',
      width: 280,
      render: (_, r) => (
        <Space size={4} wrap>
          <Tag>解析 {r.total_parsed}</Tag>
          <Tag color="green">+{r.added}</Tag>
          <Tag color="blue">刷新 {r.refreshed}</Tag>
          <Tag color="orange">过期 {r.expired}</Tag>
          {r.skipped_conflict > 0 && <Tag color="gold">冲突 {r.skipped_conflict}</Tag>}
          {r.invalid_count > 0 && <Tag color="red">无效 {r.invalid_count}</Tag>}
        </Space>
      ),
    },
    {
      title: '网关发布',
      dataIndex: 'published',
      width: 90,
      render: (v: boolean) => (v ? <Tag color="green">已触发</Tag> : <Tag>未触发</Tag>),
    },
    {
      title: '错误信息',
      dataIndex: 'error_message',
      width: 200,
      ellipsis: true,
      render: (v: string) =>
        v ? (
          <Tooltip title={v}>
            <Typography.Text type="danger">{v}</Typography.Text>
          </Tooltip>
        ) : (
          '-'
        ),
    },
    {
      title: '开始时间',
      dataIndex: 'started_at',
      width: 165,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '耗时',
      key: 'duration',
      width: 90,
      render: (_, r) => formatDuration(r.started_at, r.finished_at),
    },
  ]

  const settingsDirty =
    data?.settings !== undefined &&
    (autoUpdateEnabled !== Boolean(data.settings.auto_update_enabled) ||
      circuitThreshold !== (data.settings.circuit_threshold || 5))

  return (
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      {feedsQuery.isError && (
        <QueryErrorAlert error={feedsQuery.error} message="加载威胁情报订阅源失败" />
      )}

      {circuitOpenFeeds.length > 0 && (
        <Alert
          type="error"
          showIcon
          message={`共有 ${circuitOpenFeeds.length} 个威胁情报源处于熔断状态`}
          description={`已暂停自动定时拉取的情报源：${circuitOpenFeeds.map((f) => `${f.name}（${f.feed_key}）`).join('、')}。排查上游或代理问题后，手动执行「立即拉取」成功将自动闭合熔断恢复调度。`}
        />
      )}

      {/* 概览卡片与全局定时设置 */}
      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} lg={5}>
          <Card size="small" loading={feedsQuery.isLoading}>
            <Statistic
              title="已启用订阅源"
              value={data?.summary.enabled_count ?? 0}
              suffix={`/ ${feeds.length}`}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={5}>
          <Card size="small" loading={feedsQuery.isLoading}>
            <Statistic
              title="生效黑名单规则总数"
              value={data?.summary.total_active_rules ?? 0}
              valueStyle={{ color: '#cf1322' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={4}>
          <Card size="small" loading={feedsQuery.isLoading}>
            <Statistic
              title="熔断中情报源"
              value={data?.summary.circuit_open_count ?? circuitOpenFeeds.length}
              valueStyle={{
                color:
                  (data?.summary.circuit_open_count ?? circuitOpenFeeds.length) > 0
                    ? '#cf1322'
                    : '#389e0d',
              }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={10}>
          <Card size="small" loading={feedsQuery.isLoading} title="全局定时调度与熔断阈值">
            <Space wrap align="center" size={16}>
              <Space size={8}>
                <span>定时拉取总开关：</span>
                <Switch
                  checked={autoUpdateEnabled}
                  disabled={!canManage}
                  onChange={setAutoUpdateEnabled}
                />
              </Space>
              <Space size={8}>
                <span>连续失败熔断阈值：</span>
                <InputNumber
                  size="small"
                  min={1}
                  max={20}
                  disabled={!canManage}
                  value={circuitThreshold}
                  onChange={(v) => setCircuitThreshold(typeof v === 'number' ? v : 5)}
                  addonAfter="次"
                  style={{ width: 110 }}
                />
              </Space>
              {canManage && (
                <Button
                  type="primary"
                  size="small"
                  disabled={!settingsDirty}
                  loading={saveGlobalSettingsMutation.isPending}
                  onClick={() => saveGlobalSettingsMutation.mutate()}
                >
                  保存调度设置
                </Button>
              )}
            </Space>
          </Card>
        </Col>
      </Row>

      {/* 订阅源列表 */}
      <Card
        title={
          <Space>
            <SafetyOutlined />
            <span>威胁情报 IP 黑名单订阅源（仅宽松许可内置源 + 自定义扩展）</span>
          </Space>
        }
        size="small"
        extra={
          <Space wrap>
            {canImport && (
              <Button icon={<ImportOutlined />} onClick={() => openImportDrawer()}>
                离线快照导入
              </Button>
            )}
            {canManage && (
              <Button type="primary" icon={<PlusOutlined />} onClick={openCreateFeed}>
                新建自定义源
              </Button>
            )}
            {!canManage && !canImport && <Tag>只读视图</Tag>}
          </Space>
        }
      >
        <SmartTable<ThreatIntelFeed>
          rowKey="id"
          size="small"
          storageKey="ip-libraries-threat-feeds"
          refreshQueryKeys={[['ip-libraries', 'threat-intel', 'feeds']]}
          loading={feedsQuery.isLoading}
          columns={feedColumns}
          dataSource={feeds}
          pagination={false}
          scroll={{ x: 1180 }}
        />
      </Card>

      {/* 同步与导入对账历史 */}
      <Card
        title={
          <Space>
            <HistoryOutlined />
            <span>威胁情报拉取与离线导入对账历史</span>
          </Space>
        }
        size="small"
        extra={
          <Space wrap>
            <Select
              allowClear
              placeholder="全部订阅源"
              style={{ width: 150 }}
              value={runFilters.feed_key}
              options={feeds.map((f) => ({ value: f.feed_key, label: `${f.name} (${f.feed_key})` }))}
              onChange={(feed_key) => {
                setRunFilters((prev) => ({ ...prev, feed_key }))
                setRunsPage(1)
              }}
            />
            <Select
              allowClear
              placeholder="全部触发方式"
              style={{ width: 140 }}
              value={runFilters.trigger_type}
              options={Object.entries(THREAT_TRIGGER_META).map(([value, meta]) => ({
                value,
                label: meta.label,
              }))}
              onChange={(trigger_type) => {
                setRunFilters((prev) => ({ ...prev, trigger_type }))
                setRunsPage(1)
              }}
            />
            <Select
              allowClear
              placeholder="全部状态"
              style={{ width: 150 }}
              value={runFilters.status}
              options={Object.entries(THREAT_RUN_STATUS_META)
                .filter(([k]) => k !== 'IDLE')
                .map(([value, meta]) => ({ value, label: meta.label }))}
              onChange={(status) => {
                setRunFilters((prev) => ({ ...prev, status }))
                setRunsPage(1)
              }}
            />
          </Space>
        }
      >
        {runsQuery.isError && (
          <QueryErrorAlert error={runsQuery.error} message="加载威胁情报同步历史失败" />
        )}
        <SmartTable<ThreatIntelSyncRun>
          rowKey="id"
          size="small"
          storageKey="ip-libraries-threat-runs"
          refreshQueryKeys={[['ip-libraries', 'threat-intel', 'runs']]}
          loading={runsQuery.isLoading}
          columns={runColumns}
          dataSource={runsQuery.data?.items ?? []}
          scroll={{ x: 1320 }}
          pagination={{
            current: runsPage,
            pageSize: runsPageSize,
            total: runsQuery.data?.total ?? 0,
            showSizeChanger: true,
            showTotal: (t) => `共 ${t} 条`,
            onChange: (p, ps) => {
              setRunsPage(p)
              setRunsPageSize(ps)
            },
          }}
        />
      </Card>

      {/* 新建 / 编辑订阅源弹窗 */}
      <Modal
        title={editingFeed ? `编辑订阅源 — ${editingFeed.name}` : '新建自定义威胁情报订阅源'}
        open={feedModalOpen}
        width={660}
        onCancel={() => {
          setFeedModalOpen(false)
          setEditingFeed(null)
        }}
        onOk={() => feedForm.submit()}
        confirmLoading={saveFeedMutation.isPending}
        okText="保存"
        destroyOnHidden
      >
        <Form<FeedFormValues>
          form={feedForm}
          layout="vertical"
          onFinish={(values) => saveFeedMutation.mutate(values)}
        >
          <Row gutter={16}>
            <Col xs={24} sm={10}>
              <Form.Item
                name="feed_key"
                label="源标识（feed_key）"
                rules={[
                  { required: true, message: '请输入源标识' },
                  {
                    pattern: FEED_KEY_RE,
                    message: '仅允许小写字母或数字开头，可含 _ 与 -，长度 1–32',
                  },
                ]}
                extra="用于黑名单规则命名空间隔离，创建后不可修改"
              >
                <Input disabled={editingFeed !== null} placeholder="例如：corp_soc_blocklist" />
              </Form.Item>
            </Col>
            <Col xs={24} sm={14}>
              <Form.Item
                name="name"
                label="展示名称"
                rules={[{ required: true, message: '请输入展示名称' }]}
              >
                <Input placeholder="例如：企业 SOC 威胁情报黑名单" />
              </Form.Item>
            </Col>
          </Row>

          <Form.Item name="description" label="说明">
            <Input placeholder="可选：描述情报源用途与更新频率" />
          </Form.Item>

          <Row gutter={16}>
            <Col xs={24} sm={10}>
              <Form.Item
                name="source_mode"
                label="来源模式"
                rules={[{ required: true, message: '请选择来源模式' }]}
              >
                <Select
                  options={SOURCE_MODE_OPTIONS}
                  onChange={(mode: FeedFormValues['source_mode']) => {
                    if (mode === 'OFFICIAL') {
                      const currentPreset = feedForm.getFieldValue('official_preset') as
                        | string
                        | undefined
                      const nextPreset = currentPreset || presets[0]?.key
                      if (nextPreset) {
                        feedForm.setFieldValue('official_preset', nextPreset)
                        applyPresetDefaults(nextPreset)
                      }
                    }
                  }}
                />
              </Form.Item>
            </Col>
            <Form.Item
              noStyle
              shouldUpdate={(prev, cur) => prev.source_mode !== cur.source_mode}
            >
              {({ getFieldValue }) => {
                const mode = getFieldValue('source_mode') as string | undefined
                if (mode === 'OFFICIAL') {
                  return (
                    <Col xs={24} sm={14}>
                      <Form.Item
                        name="official_preset"
                        label="官方预置源（宽松许可）"
                        rules={[{ required: true, message: '请选择官方预置源' }]}
                      >
                        <Select
                          placeholder="请选择官方预置源"
                          onChange={(val: string) => applyPresetDefaults(val)}
                          options={presets.map((p) => ({
                            value: p.key,
                            label: p.license ? `${p.name}（${p.license}）` : p.name,
                          }))}
                        />
                      </Form.Item>
                    </Col>
                  )
                }
                if (mode === 'CUSTOM_URL') {
                  return (
                    <Col xs={24} sm={14}>
                      <Form.Item
                        name="custom_url"
                        label="自定义订阅 URL"
                        rules={[{ required: true, message: '请输入自定义订阅 URL' }]}
                        extra="内网地址须登记在「出站代理与镜像白名单」中"
                      >
                        <Input placeholder="https://intel.corp.local/feeds/blocklist.txt" />
                      </Form.Item>
                    </Col>
                  )
                }
                return null
              }}
            </Form.Item>
          </Row>

          <Row gutter={16}>
            <Col xs={24} sm={8}>
              <Form.Item
                name="format"
                label="内容格式"
                rules={[{ required: true, message: '请选择内容格式' }]}
              >
                <Select
                  options={[
                    { value: 'text', label: '纯文本 IP 清单（text）' },
                    { value: 'csv', label: 'Feodo CSV（csv）' },
                  ]}
                />
              </Form.Item>
            </Col>
            <Col xs={24} sm={8}>
              <Form.Item
                name="ttl_days"
                label="规则有效期（天，0=永久）"
                rules={[{ required: true, message: '请填写 TTL 天数' }]}
              >
                <InputNumber min={0} max={3650} style={{ width: '100%' }} />
              </Form.Item>
            </Col>
            <Col xs={24} sm={8}>
              <Form.Item
                name="schedule_cron"
                label="定时 Cron（5 位）"
                rules={[{ required: true, message: '请输入 Cron 表达式' }]}
              >
                <Input placeholder="0 */6 * * *" />
              </Form.Item>
            </Col>
          </Row>

          <Row gutter={16}>
            <Col xs={24} sm={8}>
              <Form.Item
                name="allow_cidr"
                label="允许解析 IPv4 CIDR"
                valuePropName="checked"
              >
                <Switch />
              </Form.Item>
            </Col>
            <Col xs={24} sm={8}>
              <Form.Item
                name="min_entries_guard"
                label="开启空集防误清保护"
                valuePropName="checked"
              >
                <Switch />
              </Form.Item>
            </Col>
            <Col xs={24} sm={8}>
              <Form.Item
                name="enabled"
                label="启用该订阅源"
                valuePropName="checked"
              >
                <Switch />
              </Form.Item>
            </Col>
          </Row>

          <Alert
            type="info"
            showIcon
            style={{ marginBottom: 16 }}
            message="CIDR 安全约束提示"
            description="开启「允许解析 IPv4 CIDR」后，仅接受公网 IPv4 /16 至 /32 网段；私网、回环、保留段及超宽网段（/0–/15）均自动拒绝，防止上游异常导致全站自断网。"
          />

          <Form.Item
            name="max_drop_ratio"
            label="骤降比例保护阈值（0.00–1.00）"
            rules={[{ required: true, message: '请输入骤降保护阈值' }]}
            extra="在册规则 ≥ 20 条且新批次条目数缩水比例超过该阈值（默认 0.80 即 80%）时自动中止对账并告警。"
          >
            <InputNumber min={0} max={1} step={0.05} style={{ width: 180 }} />
          </Form.Item>
        </Form>
      </Modal>

      {/* 离线快照导入抽屉 */}
      <Drawer
        title="离线导入威胁情报快照"
        open={importOpen}
        width={680}
        destroyOnHidden
        onClose={() => setImportOpen(false)}
        extra={
          <Space>
            <Button onClick={() => setImportOpen(false)}>关闭</Button>
            <Button
              type="primary"
              icon={<CloudSyncOutlined />}
              loading={importMutation.isPending}
              onClick={() => importForm.submit()}
            >
              执行对账导入
            </Button>
          </Space>
        }
      >
        <Space direction="vertical" size="middle" style={{ width: '100%' }}>
          <Alert
            type="info"
            showIcon
            message="集合对账语义说明"
            description="按 feed 命名空间独立对账：新 IP 自动新增全局黑名单，在册 IP 刷新有效期，本批消失 IP 标记过期；人工黑名单、人工停用规则及保护地址自动跳过不覆盖，变更生效后自动触发网关配置发布。"
          />

          <Form<ImportFormValues>
            form={importForm}
            layout="vertical"
            onFinish={(values) =>
              importMutation.mutate({
                feed: values.feed.trim().toLowerCase(),
                format: values.format,
                ttl_days: values.ttl_days ?? 30,
                content: values.content,
              })
            }
          >
            <Row gutter={16}>
              <Col xs={24} sm={10}>
                <Form.Item
                  name="feed"
                  label="目标情报源（feed）"
                  rules={[
                    { required: true, message: '请指定情报源标识' },
                    {
                      pattern: FEED_KEY_RE,
                      message: '仅允许小写字母/数字开头，可含 _ 与 -',
                    },
                  ]}
                >
                  <Input placeholder="例如：ipsum_l5 / spamhaus_drop / feodo / custom_feed" />
                </Form.Item>
                {feeds.length > 0 && (
                  <Space size={4} wrap style={{ marginTop: -12, marginBottom: 12 }}>
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                      快速选择：
                    </Typography.Text>
                    {feeds.map((f) => (
                      <Tag
                        key={f.feed_key}
                        style={{ cursor: 'pointer' }}
                        onClick={() => importForm.setFieldValue('feed', f.feed_key)}
                      >
                        {f.feed_key}
                      </Tag>
                    ))}
                  </Space>
                )}
              </Col>
              <Col xs={24} sm={8}>
                <Form.Item
                  name="format"
                  label="快照格式"
                  rules={[{ required: true }]}
                >
                  <Radio.Group>
                    <Radio.Button value="text">纯文本</Radio.Button>
                    <Radio.Button value="csv">CSV</Radio.Button>
                  </Radio.Group>
                </Form.Item>
              </Col>
              <Col xs={24} sm={6}>
                <Form.Item
                  name="ttl_days"
                  label="有效期（天）"
                  rules={[{ required: true }]}
                >
                  <InputNumber min={0} max={3650} style={{ width: '100%' }} />
                </Form.Item>
              </Col>
            </Row>

            <Form.Item label="从本地文件读取（可选，.txt / .csv，≤ 1MB）">
              <Upload
                accept=".txt,.csv"
                showUploadList={false}
                beforeUpload={(file) => {
                  const reader = new FileReader()
                  reader.onload = () => {
                    const text = typeof reader.result === 'string' ? reader.result : ''
                    importForm.setFieldValue('content', text)
                    if (file.name.toLowerCase().endsWith('.csv')) {
                      importForm.setFieldValue('format', 'csv')
                    }
                    message.success(`已读取文件 ${file.name}`)
                  }
                  reader.readAsText(file)
                  return false
                }}
              >
                <Button icon={<UploadOutlined />}>选择本地 .txt / .csv 文件填充</Button>
              </Upload>
            </Form.Item>

            <Form.Item
              name="content"
              label="情报快照内容（每行一个 IPv4，支持 # 或 ; 注释；或粘贴 Feodo CSV）"
              rules={[{ required: true, message: '请上传文件或粘贴情报内容' }]}
            >
              <Input.TextArea
                rows={8}
                placeholder={'# 每行一个 IPv4\n203.0.113.10\n198.51.100.25'}
              />
            </Form.Item>
          </Form>

          {importResult && (
            <Card size="small" title={`对账导入结果（批次 ${importResult.batch_id}）`}>
              <Descriptions size="small" column={3} bordered>
                <Descriptions.Item label="解析有效">{importResult.total_parsed}</Descriptions.Item>
                <Descriptions.Item label="新增黑名单">
                  <Typography.Text type="success">{importResult.added}</Typography.Text>
                </Descriptions.Item>
                <Descriptions.Item label="刷新有效期">{importResult.refreshed}</Descriptions.Item>
                <Descriptions.Item label="本批过期">{importResult.expired}</Descriptions.Item>
                <Descriptions.Item label="冲突/保护跳过">
                  {importResult.skipped_conflict}
                </Descriptions.Item>
                <Descriptions.Item label="无效行">
                  <Typography.Text type={importResult.invalid > 0 ? 'danger' : undefined}>
                    {importResult.invalid}
                  </Typography.Text>
                </Descriptions.Item>
              </Descriptions>

              {importResult.truncated && (
                <Alert
                  type="warning"
                  showIcon
                  style={{ marginTop: 12 }}
                  message="本次输入有效条目超过单批上限，已按上限截断处理"
                />
              )}

              {importResult.conflicts.length > 0 && (
                <List
                  size="small"
                  bordered
                  style={{ marginTop: 12 }}
                  header={
                    <Typography.Text strong>
                      跳过冲突 / 保护地址明细（{importResult.conflicts.length}）
                    </Typography.Text>
                  }
                  dataSource={importResult.conflicts}
                  renderItem={(item) => (
                    <List.Item key={`${item.address}-${item.reason}`}>
                      <Space>
                        <Typography.Text code>{item.address}</Typography.Text>
                        <Typography.Text type="secondary">{item.reason}</Typography.Text>
                      </Space>
                    </List.Item>
                  )}
                />
              )}

              {importResult.invalid_entries.length > 0 && (
                <List
                  size="small"
                  bordered
                  style={{ marginTop: 12 }}
                  header={
                    <Typography.Text type="danger">
                      解析无效行明细（{importResult.invalid_entries.length}）
                    </Typography.Text>
                  }
                  dataSource={importResult.invalid_entries}
                  renderItem={(item) => (
                    <List.Item key={`${item.line}-${item.content}`}>
                      <Typography.Text type="danger">
                        第 {item.line} 行「{item.content}」：{item.error}
                      </Typography.Text>
                    </List.Item>
                  )}
                />
              )}
            </Card>
          )}
        </Space>
      </Drawer>
    </Space>
  )
}
