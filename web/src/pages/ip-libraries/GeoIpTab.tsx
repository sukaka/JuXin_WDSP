import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Badge,
  Button,
  Card,
  Checkbox,
  Col,
  Divider,
  Drawer,
  Form,
  Input,
  Modal,
  Progress,
  Radio,
  Row,
  Select,
  Space,
  Statistic,
  Switch,
  Table,
  Tag,
  Tooltip,
  Typography,
  Upload,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import {
  CloudSyncOutlined,
  ClusterOutlined,
  HistoryOutlined,
  InboxOutlined,
  SettingOutlined,
  UploadOutlined,
} from '@ant-design/icons'
import { ApiError } from '../../api/client'
import {
  ipLibrariesApi,
  type GeoIpHANodeStatus,
  type GeoIpSlotSettingInput,
  type GeoIpSlotStatus,
  type GeoIpSyncRun,
  type UpdateGeoIpSettingsBody,
} from '../../api/ipLibraries'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { formatBytes, formatDateTime, formatDuration } from '../../utils/format'
import {
  DEFAULT_GEO_PRESETS,
  GEO_ACTIVE_ORIGIN_META,
  GEO_RUN_STATUS_META,
  GEO_SLOT_LABELS,
  GEO_SOURCE_TYPE_META,
  GEO_TRIGGER_META,
  HA_PUSH_STATUS_META,
  SOURCE_MODE_META,
  SOURCE_MODE_OPTIONS,
  shortSha256,
} from './meta'

const SHA256_RE = /^[0-9a-fA-F]{64}$/

interface RunFilters {
  slot?: string
  trigger_type?: string
  status?: string
}

interface UploadFormValues {
  slot: string
  expected_sha256?: string
}

interface GeoSettingsFormValues {
  auto_update_enabled: boolean
  schedule_cron: string
  ha_sync_enabled: boolean
  maxmind_account_id: string
  maxmind_license_key?: string
  clear_maxmind_license_key?: boolean
  slots: GeoIpSlotSettingInput[]
}

export interface GeoIpTabProps {
  canManage: boolean
}

function isPeerDrifted(node: GeoIpHANodeStatus, localRevision: string): boolean {
  if (node.reachable === false || node.error) return true
  if (node.consistent === false) return true
  if (localRevision && node.revision && node.revision !== localRevision) return true
  return false
}

export default function GeoIpTab({ canManage }: GeoIpTabProps) {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()

  const [runFilters, setRunFilters] = useState<RunFilters>({})
  const [runsPage, setRunsPage] = useState(1)
  const [runsPageSize, setRunsPageSize] = useState(10)

  // 离线上传弹窗
  const [uploadOpen, setUploadOpen] = useState(false)
  const [uploadFile, setUploadFile] = useState<File | null>(null)
  const [uploadPercent, setUploadPercent] = useState<number | null>(null)
  const [uploadForm] = Form.useForm<UploadFormValues>()

  // 历史回滚弹窗
  const [rollbackSlot, setRollbackSlot] = useState<GeoIpSlotStatus | null>(null)
  const [selectedBackupId, setSelectedBackupId] = useState<string>('')

  // 定时调度与 MaxMind 设置抽屉
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [settingsForm] = Form.useForm<GeoSettingsFormValues>()

  // 正在同步中的单个槽位
  const [syncingSlot, setSyncingSlot] = useState<string | null>(null)

  const statusQuery = useQuery({
    queryKey: ['ip-libraries', 'geoip', 'status'],
    queryFn: () => ipLibrariesApi.getGeoIpStatus(),
  })

  const runsQuery = useQuery({
    queryKey: ['ip-libraries', 'geoip', 'runs', runFilters, runsPage, runsPageSize],
    queryFn: () =>
      ipLibrariesApi.listGeoIpRuns({
        ...runFilters,
        page: runsPage,
        page_size: runsPageSize,
      }),
  })

  const status = statusQuery.data
  const slots = useMemo(() => status?.slots ?? [], [status?.slots])
  const haNodes = useMemo(() => status?.ha_nodes ?? [], [status?.ha_nodes])
  const presets = useMemo(
    () => (status?.presets && status.presets.length > 0 ? status.presets : DEFAULT_GEO_PRESETS),
    [status?.presets],
  )

  const driftedNodes = useMemo(
    () => haNodes.filter((n) => isPeerDrifted(n, status?.revision ?? '')),
    [haNodes, status?.revision],
  )

  const invalidateGeo = () => {
    void queryClient.invalidateQueries({ queryKey: ['ip-libraries', 'geoip'] })
  }

  const onError = (e: unknown, fallback = '操作失败') => {
    message.error(e instanceof ApiError ? e.message : fallback)
  }

  // 打开调度与 MaxMind 设置抽屉时回填（MaxMind License Key 绝不回填明文）
  useEffect(() => {
    if (!settingsOpen || !status) return
    settingsForm.setFieldsValue({
      auto_update_enabled: Boolean(status.schedule.auto_update_enabled),
      schedule_cron: status.schedule.schedule_cron || '0 3 2 * *',
      ha_sync_enabled: status.schedule.ha_sync_enabled ?? true,
      maxmind_account_id: status.schedule.maxmind_account_id ?? '',
      maxmind_license_key: '',
      clear_maxmind_license_key: false,
      slots: status.slots.map((s) => ({
        slot: s.slot,
        enabled: Boolean(s.enabled),
        source_mode: s.source_mode || 'OFFLINE_ONLY',
        official_preset: s.official_preset || '',
        custom_url: s.custom_url || '',
      })),
    })
  }, [settingsOpen, status, settingsForm])

  const syncMutation = useMutation({
    mutationFn: (slot: string) => {
      setSyncingSlot(slot || '__all__')
      return ipLibrariesApi.syncGeoIp(slot)
    },
    onSuccess: (res, slot) => {
      const target = slot ? GEO_SLOT_LABELS[slot] ?? slot : '全部启用槽位'
      if (res.failed > 0) {
        message.warning(`${target}同步完成：成功 ${res.succeeded}，跳过 ${res.skipped}，失败 ${res.failed}，请查看同步历史`)
      } else if (res.partial_ha_failed > 0) {
        message.warning(`${target}本机已热加载生效，但有 ${res.partial_ha_failed} 项 HA 备节点推送失败`)
      } else if (res.succeeded === 0 && res.skipped > 0) {
        message.info(`${target}已是最新版本，无需更新`)
      } else if (res.runs.length === 0) {
        message.info('当前没有已启用且配置了在线来源的槽位')
      } else {
        message.success(`${target}同步完成（成功 ${res.succeeded}，跳过 ${res.skipped}）`)
      }
      invalidateGeo()
    },
    onError: (e) => onError(e, '触发 GeoIP 同步失败'),
    onSettled: () => setSyncingSlot(null),
  })

  const haResyncMutation = useMutation({
    mutationFn: (slot: string) => ipLibrariesApi.haResyncGeoIp(slot),
    onSuccess: (res) => {
      if (res.failed > 0 || res.partial_ha_failed > 0) {
        message.warning(
          `HA 备节点重同步完成，但存在失败项（成功 ${res.succeeded}，部分失败 ${res.partial_ha_failed}，失败 ${res.failed}）`,
        )
      } else {
        message.success('已将运行期 GeoIP 库重新同步至 HA 备节点')
      }
      invalidateGeo()
    },
    onError: (e) => onError(e, 'HA 备节点重同步失败'),
  })

  const uploadMutation = useMutation({
    mutationFn: async (values: UploadFormValues) => {
      if (!uploadFile) {
        throw new ApiError('请先选择待上传的 GeoIP 文件', 'INVALID_ARGUMENT', 0)
      }
      setUploadPercent(0)
      return ipLibrariesApi.uploadGeoIp(
        values.slot,
        uploadFile,
        values.expected_sha256,
        (progress) => {
          if (progress.lengthComputable && progress.total > 0) {
            setUploadPercent(Math.min(100, Math.round((progress.loaded / progress.total) * 100)))
          }
        },
      )
    },
    onSuccess: (res) => {
      const hasHAFail = (res.ha_results ?? []).some((h) => h.status === 'FAILED')
      if (res.unchanged) {
        message.info(`槽位 ${res.slot} 内容与当前活跃文件一致，已跳过重复替换`)
      } else if (hasHAFail) {
        message.warning(`离线上传本机已热加载（版本 ${shortSha256(res.revision)}），但部分 HA 备节点同步失败`)
      } else {
        message.success(`离线上传成功：${res.filename} 已热加载生效（版本 ${shortSha256(res.revision)}）`)
      }
      setUploadOpen(false)
      setUploadFile(null)
      setUploadPercent(null)
      uploadForm.resetFields()
      invalidateGeo()
    },
    onError: (e) => {
      setUploadPercent(null)
      onError(e, 'GeoIP 离线上传失败')
    },
  })

  const rollbackMutation = useMutation({
    mutationFn: ({ slot, backupId }: { slot: string; backupId: string }) =>
      ipLibrariesApi.rollbackGeoIp(slot, backupId),
    onSuccess: (res) => {
      const hasHAFail = (res.ha_results ?? []).some((h) => h.status === 'FAILED')
      if (hasHAFail) {
        message.warning(`槽位 ${res.slot} 本机已回滚至 ${res.filename}，但部分 HA 备节点同步失败`)
      } else {
        message.success(`槽位 ${res.slot} 已回滚至 ${res.filename} 并热加载生效`)
      }
      setRollbackSlot(null)
      setSelectedBackupId('')
      invalidateGeo()
    },
    onError: (e) => onError(e, 'GeoIP 回滚失败'),
  })

  const saveSettingsMutation = useMutation({
    mutationFn: (values: GeoSettingsFormValues) => {
      const body: UpdateGeoIpSettingsBody = {
        auto_update_enabled: Boolean(values.auto_update_enabled),
        schedule_cron: (values.schedule_cron ?? '').trim() || '0 3 2 * *',
        ha_sync_enabled: Boolean(values.ha_sync_enabled),
        maxmind_account_id: (values.maxmind_account_id ?? '').trim(),
        slots: (values.slots ?? []).map((s) => ({
          slot: s.slot,
          enabled: Boolean(s.enabled),
          source_mode: s.source_mode || 'OFFLINE_ONLY',
          official_preset: (s.official_preset ?? '').trim(),
          custom_url: (s.custom_url ?? '').trim(),
        })),
      }
      if (values.clear_maxmind_license_key) {
        body.clear_maxmind_license_key = true
      } else if (values.maxmind_license_key && values.maxmind_license_key.trim() !== '') {
        body.maxmind_license_key = values.maxmind_license_key.trim()
      }
      return ipLibrariesApi.updateGeoIpSettings(body)
    },
    onSuccess: () => {
      message.success('GeoIP 调度与源配置已保存')
      setSettingsOpen(false)
      invalidateGeo()
    },
    onError: (e) => onError(e, '保存 GeoIP 配置失败'),
  })

  const openUploadModal = (slotKey?: string) => {
    const defaultSlot = slotKey || slots[0]?.slot || 'ip2region_v4'
    setUploadFile(null)
    setUploadPercent(null)
    uploadForm.setFieldsValue({ slot: defaultSlot, expected_sha256: '' })
    setUploadOpen(true)
  }

  const openRollbackModal = (record: GeoIpSlotStatus) => {
    setRollbackSlot(record)
    setSelectedBackupId(record.backups[0]?.backup_id ?? '')
  }

  const slotColumns: ColumnsType<GeoIpSlotStatus> = [
    {
      title: '槽位与格式',
      key: 'slot',
      width: 260,
      render: (_, record) => (
        <Space direction="vertical" size={2}>
          <Typography.Text strong>{record.display_name || GEO_SLOT_LABELS[record.slot] || record.slot}</Typography.Text>
          <Space size={4} wrap>
            <Typography.Text code>{record.slot}</Typography.Text>
            <Tag>{record.format.toUpperCase()}</Tag>
            {record.enabled && <Tag color="green">参与定时同步</Tag>}
          </Space>
        </Space>
      ),
    },
    {
      title: '来源模式',
      key: 'source_mode',
      width: 220,
      render: (_, record) => (
        <Space direction="vertical" size={2}>
          <StatusTag value={record.source_mode} map={SOURCE_MODE_META} />
          {record.source_mode === 'OFFICIAL' && record.official_preset && (
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              预置源：{record.official_preset}
            </Typography.Text>
          )}
          {record.source_mode === 'CUSTOM_URL' && record.custom_url && (
            <Tooltip title={record.custom_url}>
              <Typography.Text type="secondary" ellipsis style={{ fontSize: 12, maxWidth: 200 }}>
                {record.custom_url}
              </Typography.Text>
            </Tooltip>
          )}
        </Space>
      ),
    },
    {
      title: '当前活跃文件',
      key: 'active_file',
      width: 280,
      render: (_, record) => (
        <Space direction="vertical" size={2}>
          <Space size={4} wrap>
            <StatusTag value={record.active_origin} map={GEO_ACTIVE_ORIGIN_META} />
            {record.active_origin !== 'missing' && record.active_source_type && (
              <StatusTag value={record.active_source_type} map={GEO_SOURCE_TYPE_META} />
            )}
          </Space>
          {record.active_origin !== 'missing' ? (
            <Space size={6} wrap>
              <Typography.Text>{record.active_filename || record.canonical_file}</Typography.Text>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                {formatBytes(record.size_bytes)}
              </Typography.Text>
              {record.sha256 && (
                <Tooltip title={`SHA-256: ${record.sha256}`}>
                  <Typography.Text code style={{ fontSize: 12 }}>
                    {shortSha256(record.sha256)}
                  </Typography.Text>
                </Tooltip>
              )}
            </Space>
          ) : (
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              规范文件名：{record.canonical_file}（上限 {formatBytes(record.max_bytes)}）
            </Typography.Text>
          )}
        </Space>
      ),
    },
    {
      title: '最近更新与状态',
      key: 'last_status',
      width: 200,
      render: (_, record) => (
        <Space direction="vertical" size={2}>
          <Space size={6}>
            <StatusTag value={record.last_status} map={GEO_RUN_STATUS_META} />
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {formatDateTime(record.updated_at)}
            </Typography.Text>
          </Space>
          {record.last_error && (
            <Tooltip title={record.last_error}>
              <Typography.Text type="danger" ellipsis style={{ fontSize: 12, maxWidth: 185 }}>
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
            render: (_: unknown, record: GeoIpSlotStatus) => (
              <Space size={0} wrap>
                <Tooltip
                  title={
                    record.source_mode === 'OFFLINE_ONLY'
                      ? '当前槽位为纯离线模式，请先在配置中切换为官方源或内网镜像'
                      : '立即从上游拉取并热加载该槽位'
                  }
                >
                  <Button
                    type="link"
                    size="small"
                    disabled={record.source_mode === 'OFFLINE_ONLY'}
                    loading={syncMutation.isPending && syncingSlot === record.slot}
                    onClick={() => syncMutation.mutate(record.slot)}
                  >
                    立即同步
                  </Button>
                </Tooltip>
                <Button
                  type="link"
                  size="small"
                  onClick={() => openUploadModal(record.slot)}
                >
                  离线上传
                </Button>
                <Button
                  type="link"
                  size="small"
                  disabled={record.backups.length === 0}
                  onClick={() => openRollbackModal(record)}
                >
                  回滚历史{record.backups.length > 0 ? `(${record.backups.length})` : ''}
                </Button>
                <Button
                  type="link"
                  size="small"
                  onClick={() => setSettingsOpen(true)}
                >
                  配置
                </Button>
              </Space>
            ),
          },
        ]
      : []),
  ]

  const runColumns: ColumnsType<GeoIpSyncRun> = [
    {
      title: '槽位',
      dataIndex: 'slot',
      width: 140,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: '触发方式',
      dataIndex: 'trigger_type',
      width: 110,
      render: (v: string) => <StatusTag value={v} map={GEO_TRIGGER_META} />,
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 150,
      render: (v: string) => <StatusTag value={v} map={GEO_RUN_STATUS_META} />,
    },
    {
      title: '来源说明',
      dataIndex: 'source_label',
      width: 190,
      ellipsis: true,
      render: (v: string) => v || '-',
    },
    {
      title: 'SHA-256 变更',
      key: 'sha_change',
      width: 210,
      render: (_, r) =>
        r.new_sha256 ? (
          <Space size={4}>
            <Tooltip title={r.previous_sha256 || '无'}>
              <Typography.Text type="secondary" code style={{ fontSize: 12 }}>
                {shortSha256(r.previous_sha256)}
              </Typography.Text>
            </Tooltip>
            <span>→</span>
            <Tooltip title={r.new_sha256}>
              <Typography.Text code style={{ fontSize: 12 }}>
                {shortSha256(r.new_sha256)}
              </Typography.Text>
            </Tooltip>
          </Space>
        ) : (
          '-'
        ),
    },
    {
      title: '大小',
      dataIndex: 'file_size_bytes',
      width: 100,
      render: (v: number) => (v > 0 ? formatBytes(v) : '-'),
    },
    {
      title: 'HA 同步结果',
      key: 'ha_results',
      width: 190,
      render: (_, r) =>
        r.ha_results.length > 0 ? (
          <Space size={4} wrap>
            {r.ha_results.map((h) => (
              <Tooltip key={h.node_id || h.node_name} title={h.error || h.sha256 || h.status}>
                <Tag color={HA_PUSH_STATUS_META[h.status]?.color ?? 'default'}>
                  {h.node_name}: {HA_PUSH_STATUS_META[h.status]?.label ?? h.status}
                </Tag>
              </Tooltip>
            ))}
          </Space>
        ) : (
          '-'
        ),
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

  return (
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      {statusQuery.isError && (
        <QueryErrorAlert error={statusQuery.error} message="加载 GeoIP 归属地库状态失败" />
      )}

      {driftedNodes.length > 0 && (
        <Alert
          type="warning"
          showIcon
          message={`检测到 ${driftedNodes.length} 个 HA 备节点 GeoIP 库版本不一致或不可达`}
          description={`异常节点：${driftedNodes.map((n) => n.node_name).join('、')}。点击「重新同步备节点」可将主节点运行期 GeoIP 库经 HMAC 通道重新推送至备节点。`}
          action={
            canManage ? (
              <Button
                size="small"
                type="primary"
                loading={haResyncMutation.isPending}
                onClick={() => haResyncMutation.mutate('')}
              >
                重新同步备节点
              </Button>
            ) : undefined
          }
        />
      )}

      {/* 概览卡片 */}
      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} lg={6}>
          <Card size="small" loading={statusQuery.isLoading}>
            <Statistic
              title="GeoIP 融合引擎"
              value={status?.geo_enabled ? '已启用' : '未加载'}
              valueStyle={{ color: status?.geo_enabled ? '#389e0d' : '#8c8c8c', fontSize: 20 }}
            />
            <div style={{ marginTop: 8 }}>
              {status?.sources && status.sources.length > 0 ? (
                <Space size={4} wrap>
                  {status.sources.map((src) => (
                    <Tag key={src} color="blue">
                      {src}
                    </Tag>
                  ))}
                </Space>
              ) : (
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  上传或同步任意槽位后自动热激活
                </Typography.Text>
              )}
            </div>
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card size="small" loading={statusQuery.isLoading}>
            <Statistic
              title="热加载修订版本"
              value={status?.revision ? shortSha256(status.revision) : '内置/初始'}
              valueStyle={{ fontSize: 20 }}
            />
            <Typography.Text type="secondary" style={{ fontSize: 12, display: 'block', marginTop: 8 }}>
              最近加载：{formatDateTime(status?.loaded_at)}
            </Typography.Text>
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card size="small" loading={statusQuery.isLoading}>
            <Statistic
              title="在线定时更新"
              value={status?.schedule.auto_update_enabled ? '已开启' : '已关闭'}
              valueStyle={{
                color: status?.schedule.auto_update_enabled ? '#1677ff' : '#8c8c8c',
                fontSize: 20,
              }}
            />
            <Space size={6} wrap style={{ marginTop: 8 }}>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                Cron: {status?.schedule.schedule_cron || '0 3 2 * *'}
              </Typography.Text>
              {status?.schedule.has_maxmind_license_key && (
                <Tag color="green">已配 MaxMind</Tag>
              )}
            </Space>
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card size="small" loading={statusQuery.isLoading}>
            <Space style={{ width: '100%', justifyContent: 'space-between' }} align="start">
              <div>
                <Typography.Text type="secondary" style={{ fontSize: 14 }}>
                  HA 备节点一致性
                </Typography.Text>
                <div style={{ marginTop: 8 }}>
                  {haNodes.length === 0 ? (
                    <Badge status="default" text="单机模式 / 无备节点" />
                  ) : driftedNodes.length === 0 ? (
                    <Badge
                      status="success"
                      text={`全部一致（${haNodes.length}/${haNodes.length}）`}
                    />
                  ) : (
                    <Badge
                      status="warning"
                      text={`存在漂移（${haNodes.length - driftedNodes.length}/${haNodes.length} 一致）`}
                    />
                  )}
                </div>
              </div>
              {canManage && haNodes.length > 0 && (
                <Button
                  size="small"
                  icon={<ClusterOutlined />}
                  loading={haResyncMutation.isPending}
                  onClick={() => haResyncMutation.mutate('')}
                >
                  重新同步备节点
                </Button>
              )}
            </Space>
            {haNodes.length > 0 && (
              <Space size={4} wrap style={{ marginTop: 8 }}>
                {haNodes.map((n) => {
                  const drifted = isPeerDrifted(n, status?.revision ?? '')
                  return (
                    <Tooltip
                      key={n.node_id || n.node_name}
                      title={
                        n.error
                          ? `异常：${n.error}`
                          : `版本：${n.revision || '-'}；更新：${formatDateTime(n.updated_at)}`
                      }
                    >
                      <Tag color={drifted ? 'orange' : 'green'}>{n.node_name}</Tag>
                    </Tooltip>
                  )
                })}
              </Space>
            )}
          </Card>
        </Col>
      </Row>

      {/* 5 槽位管理卡片 */}
      <Card
        title="GeoIP 槽位状态（5 确定性槽位，零重启热加载）"
        size="small"
        extra={
          canManage ? (
            <Space wrap>
              <Button
                icon={<CloudSyncOutlined />}
                loading={syncMutation.isPending && syncingSlot === '__all__'}
                onClick={() => syncMutation.mutate('')}
              >
                同步全部启用槽位
              </Button>
              <Button
                type="primary"
                icon={<UploadOutlined />}
                onClick={() => openUploadModal()}
              >
                离线上传
              </Button>
              <Button
                icon={<SettingOutlined />}
                onClick={() => setSettingsOpen(true)}
              >
                定时与 MaxMind 设置
              </Button>
            </Space>
          ) : (
            <Tag>只读视图</Tag>
          )
        }
      >
        <Table<GeoIpSlotStatus>
          rowKey="slot"
          size="small"
          loading={statusQuery.isLoading}
          columns={slotColumns}
          dataSource={slots}
          pagination={false}
          scroll={{ x: 1080 }}
        />
      </Card>

      {/* 同步与上传历史 */}
      <Card
        title={
          <Space>
            <HistoryOutlined />
            <span>GeoIP 更新、上传与回滚历史</span>
          </Space>
        }
        size="small"
        extra={
          <Space wrap>
            <Select
              allowClear
              placeholder="全部槽位"
              style={{ width: 150 }}
              value={runFilters.slot}
              options={Object.entries(GEO_SLOT_LABELS).map(([value, label]) => ({
                value,
                label: `${value}`,
                title: label,
              }))}
              onChange={(slot) => {
                setRunFilters((prev) => ({ ...prev, slot }))
                setRunsPage(1)
              }}
            />
            <Select
              allowClear
              placeholder="全部触发方式"
              style={{ width: 140 }}
              value={runFilters.trigger_type}
              options={Object.entries(GEO_TRIGGER_META).map(([value, meta]) => ({
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
              style={{ width: 170 }}
              value={runFilters.status}
              options={Object.entries(GEO_RUN_STATUS_META)
                .filter(([k]) => k !== 'IDLE')
                .map(([value, meta]) => ({ value, label: meta.label }))}
              onChange={(st) => {
                setRunFilters((prev) => ({ ...prev, status: st }))
                setRunsPage(1)
              }}
            />
          </Space>
        }
      >
        {runsQuery.isError && (
          <QueryErrorAlert error={runsQuery.error} message="加载 GeoIP 运行历史失败" />
        )}
        <SmartTable<GeoIpSyncRun>
          rowKey="id"
          size="small"
          storageKey="ip-libraries-geoip-runs"
          refreshQueryKeys={[['ip-libraries', 'geoip', 'runs']]}
          loading={runsQuery.isLoading}
          columns={runColumns}
          dataSource={runsQuery.data?.items ?? []}
          scroll={{ x: 1360 }}
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

      {/* 离线上传弹窗 */}
      <Modal
        title="离线上传 GeoIP 数据文件"
        open={uploadOpen}
        onCancel={() => {
          setUploadOpen(false)
          setUploadFile(null)
          setUploadPercent(null)
        }}
        onOk={() => uploadForm.submit()}
        confirmLoading={uploadMutation.isPending}
        okText="上传并热加载"
        destroyOnHidden
      >
        <Space direction="vertical" size="middle" style={{ width: '100%' }}>
          <Alert
            type="info"
            showIcon
            message="支持自动解压与格式验真"
            description="支持 .xdb、.mmdb、.gz 及 MaxMind 官方 .tar.gz 压缩包；服务端自动校验结构与探针 IP，验真通过后原子替换并备份旧版本（每槽位保留最近 3 份）。"
          />
          <Form<UploadFormValues>
            form={uploadForm}
            layout="vertical"
            onFinish={(values) => uploadMutation.mutate(values)}
          >
            <Form.Item
              name="slot"
              label="目标槽位"
              rules={[{ required: true, message: '请选择目标槽位' }]}
            >
              <Select
                options={(slots.length > 0
                  ? slots.map((s) => ({
                      value: s.slot,
                      label: `${s.display_name}（${s.canonical_file}）`,
                    }))
                  : Object.entries(GEO_SLOT_LABELS).map(([value, label]) => ({
                      value,
                      label,
                    })))}
              />
            </Form.Item>

            <Form.Item noStyle shouldUpdate={(prev, cur) => prev.slot !== cur.slot}>
              {({ getFieldValue }) => {
                const selectedMeta = slots.find((s) => s.slot === getFieldValue('slot'))
                return (
                  <Form.Item
                    label={
                      selectedMeta
                        ? `数据文件（${selectedMeta.format.toUpperCase()}，解压上限 ${formatBytes(selectedMeta.max_bytes)}）`
                        : '数据文件'
                    }
                    required
                  >
                    <Upload.Dragger
                      maxCount={1}
                      accept=".xdb,.mmdb,.gz,.tar.gz"
                      fileList={
                        uploadFile
                          ? [
                              {
                                uid: '-1',
                                name: uploadFile.name,
                                size: uploadFile.size,
                                status: 'done',
                              },
                            ]
                          : []
                      }
                      beforeUpload={(file) => {
                        setUploadFile(file)
                        return false
                      }}
                      onRemove={() => {
                        setUploadFile(null)
                      }}
                    >
                      <p className="ant-upload-drag-icon">
                        <InboxOutlined />
                      </p>
                      <p className="ant-upload-text">点击或拖拽 GeoIP 文件到此区域</p>
                      <p className="ant-upload-hint">支持 .xdb / .mmdb / .xdb.gz / .mmdb.gz / .tar.gz</p>
                    </Upload.Dragger>
                  </Form.Item>
                )
              }}
            </Form.Item>

            <Form.Item
              name="expected_sha256"
              label="预期 SHA-256 摘要（可选）"
              rules={[
                {
                  validator: (_, value: string | undefined) => {
                    const trimmed = (value ?? '').trim()
                    if (!trimmed || SHA256_RE.test(trimmed)) return Promise.resolve()
                    return Promise.reject(new Error('请输入 64 位十六进制 SHA-256 摘要'))
                  },
                },
              ]}
              extra="填写后服务端将校验原始上传文件或解压后库文件的 SHA-256，不匹配将拒绝安装。"
            >
              <Input placeholder="可选：64 位十六进制 SHA-256" />
            </Form.Item>

            {uploadPercent !== null && <Progress percent={uploadPercent} size="small" />}
          </Form>
        </Space>
      </Modal>

      {/* 历史回滚弹窗 */}
      <Modal
        title={`回滚历史版本 — ${rollbackSlot?.display_name ?? rollbackSlot?.slot ?? ''}`}
        open={rollbackSlot !== null}
        onCancel={() => {
          setRollbackSlot(null)
          setSelectedBackupId('')
        }}
        onOk={() => {
          if (!rollbackSlot || !selectedBackupId) {
            message.warning('请选择要回滚的历史备份版本')
            return
          }
          rollbackMutation.mutate({ slot: rollbackSlot.slot, backupId: selectedBackupId })
        }}
        confirmLoading={rollbackMutation.isPending}
        okText="确认回滚并热加载"
        okButtonProps={{ danger: true, disabled: !selectedBackupId }}
        width={620}
        destroyOnHidden
      >
        {rollbackSlot && (
          <Space direction="vertical" size="middle" style={{ width: '100%' }}>
            <Alert
              type="warning"
              showIcon
              message="回滚可逆且零重启生效"
              description={`当前活跃文件：${rollbackSlot.active_filename || rollbackSlot.canonical_file}（SHA-256: ${shortSha256(rollbackSlot.sha256)}）。回滚前会自动将当前版本归档到备份目录。`}
            />
            {rollbackSlot.backups.length === 0 ? (
              <Typography.Text type="secondary">该槽位暂无可回滚的历史备份</Typography.Text>
            ) : (
              <Radio.Group
                style={{ width: '100%' }}
                value={selectedBackupId}
                onChange={(e) => setSelectedBackupId(e.target.value as string)}
              >
                <Space direction="vertical" style={{ width: '100%' }}>
                  {rollbackSlot.backups.map((b) => (
                    <Card key={b.backup_id} size="small">
                      <Radio value={b.backup_id}>
                        <Space direction="vertical" size={2}>
                          <Space size={8} wrap>
                            <Typography.Text strong>{b.backup_id}</Typography.Text>
                            <Tag>{formatBytes(b.size_bytes)}</Tag>
                            <Typography.Text code>{shortSha256(b.sha256)}</Typography.Text>
                          </Space>
                          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                            归档时间：{formatDateTime(b.created_at)}
                          </Typography.Text>
                        </Space>
                      </Radio>
                    </Card>
                  ))}
                </Space>
              </Radio.Group>
            )}
          </Space>
        )}
      </Modal>

      {/* 定时更新、MaxMind 凭据与槽位源配置抽屉 */}
      <Drawer
        title="GeoIP 定时更新、MaxMind 凭据与槽位源配置"
        open={settingsOpen}
        width={720}
        destroyOnHidden
        onClose={() => setSettingsOpen(false)}
        extra={
          <Space>
            <Button onClick={() => setSettingsOpen(false)}>取消</Button>
            <Button
              type="primary"
              loading={saveSettingsMutation.isPending}
              onClick={() => settingsForm.submit()}
            >
              保存设置
            </Button>
          </Space>
        }
      >
        <Form<GeoSettingsFormValues>
          form={settingsForm}
          layout="vertical"
          onFinish={(values) => saveSettingsMutation.mutate(values)}
        >
          <Alert
            type="info"
            showIcon
            style={{ marginBottom: 16 }}
            message="离线优先安全基线"
            description="在线定时更新默认关闭；仅开启总开关且将对应槽位设为官方源或内网镜像并启用后才会按 Cron 自动拉取。"
          />

          <Row gutter={16}>
            <Col xs={24} sm={8}>
              <Form.Item
                name="auto_update_enabled"
                label="开启在线定时更新"
                valuePropName="checked"
              >
                <Switch />
              </Form.Item>
            </Col>
            <Col xs={24} sm={8}>
              <Form.Item
                name="schedule_cron"
                label="定时 Cron（5 位表达式）"
                rules={[{ required: true, message: '请输入 5 位 Cron 表达式' }]}
                extra="默认 0 3 2 * *（每月 2 日 03:00）"
              >
                <Input placeholder="0 3 2 * *" />
              </Form.Item>
            </Col>
            <Col xs={24} sm={8}>
              <Form.Item
                name="ha_sync_enabled"
                label="自动同步至 HA 备节点"
                valuePropName="checked"
                extra="更新/上传/回滚后经 hasyncd 推送"
              >
                <Switch />
              </Form.Item>
            </Col>
          </Row>

          <Divider titlePlacement="start" plain>MaxMind GeoLite2 凭据（可选）</Divider>
          <Row gutter={16}>
            <Col xs={24} sm={10}>
              <Form.Item
                name="maxmind_account_id"
                label="MaxMind Account ID"
                extra="拉取官方 MaxMind GeoLite2 City/Country 时必填"
              >
                <Input placeholder="例如：123456" />
              </Form.Item>
            </Col>
            <Col xs={24} sm={14}>
              <Form.Item
                noStyle
                shouldUpdate={(prev, cur) =>
                  prev.clear_maxmind_license_key !== cur.clear_maxmind_license_key
                }
              >
                {({ getFieldValue }) => (
                  <Form.Item
                    name="maxmind_license_key"
                    label={
                      <Space size={8}>
                        <span>MaxMind License Key（仅写入，不回显）</span>
                        {status?.schedule.has_maxmind_license_key ? (
                          <Tag color="green">已配置密钥</Tag>
                        ) : (
                          <Tag>未配置</Tag>
                        )}
                      </Space>
                    }
                    extra="经系统主密钥加密落库，绝不明文回显或记入日志；留空表示保持现有密钥不变。"
                  >
                    <Input.Password
                      autoComplete="new-password"
                      disabled={Boolean(getFieldValue('clear_maxmind_license_key'))}
                      placeholder={
                        status?.schedule.has_maxmind_license_key
                          ? '已保存密钥（留空不修改，输入新密钥覆盖）'
                          : '输入 MaxMind License Key'
                      }
                    />
                  </Form.Item>
                )}
              </Form.Item>
              {status?.schedule.has_maxmind_license_key && (
                <Form.Item name="clear_maxmind_license_key" valuePropName="checked">
                  <Checkbox>清除已保存的 MaxMind License Key</Checkbox>
                </Form.Item>
              )}
            </Col>
          </Row>

          <Divider titlePlacement="start" plain>5 个槽位更新源配置</Divider>
          <Form.List name="slots">
            {(fields) => (
              <Space direction="vertical" size="small" style={{ width: '100%' }}>
                {fields.map((field) => {
                  const slotKey = settingsForm.getFieldValue(['slots', field.name, 'slot']) as
                    | string
                    | undefined
                  const slotPresets = presets.filter((p) => p.slot === slotKey)
                  return (
                    <Card
                      key={field.key}
                      size="small"
                      title={
                        <Space>
                          <span>{GEO_SLOT_LABELS[slotKey ?? ''] ?? slotKey}</span>
                          <Typography.Text code>{slotKey}</Typography.Text>
                        </Space>
                      }
                      extra={
                        <Form.Item
                          name={[field.name, 'enabled']}
                          valuePropName="checked"
                          noStyle
                        >
                          <Switch checkedChildren="启用" unCheckedChildren="停用" />
                        </Form.Item>
                      }
                    >
                      <Form.Item name={[field.name, 'slot']} hidden>
                        <Input />
                      </Form.Item>
                      <Form.Item
                        noStyle
                        shouldUpdate={(prev, cur) =>
                          prev?.slots?.[field.name]?.source_mode !==
                          cur?.slots?.[field.name]?.source_mode
                        }
                      >
                        {({ getFieldValue }) => {
                          const mode = getFieldValue(['slots', field.name, 'source_mode']) as
                            | string
                            | undefined
                          return (
                            <Row gutter={12}>
                              <Col xs={24} sm={10}>
                                <Form.Item
                                  name={[field.name, 'source_mode']}
                                  label="更新来源模式"
                                  style={{ marginBottom: 8 }}
                                >
                                  <Select options={SOURCE_MODE_OPTIONS} />
                                </Form.Item>
                              </Col>
                              {mode === 'OFFICIAL' && (
                                <Col xs={24} sm={14}>
                                  <Form.Item
                                    name={[field.name, 'official_preset']}
                                    label="官方预置源"
                                    style={{ marginBottom: 8 }}
                                    rules={
                                      slotPresets.length > 0
                                        ? [{ required: true, message: '请选择官方预置源' }]
                                        : undefined
                                    }
                                  >
                                    {slotPresets.length > 0 ? (
                                      <Select
                                        options={slotPresets.map((p) => ({
                                          value: p.id,
                                          label: p.name,
                                        }))}
                                      />
                                    ) : (
                                      <Input
                                        disabled
                                        placeholder="该槽位无官方预置源，请使用纯离线或内网镜像"
                                      />
                                    )}
                                  </Form.Item>
                                </Col>
                              )}
                              {mode === 'CUSTOM_URL' && (
                                <Col xs={24} sm={14}>
                                  <Form.Item
                                    name={[field.name, 'custom_url']}
                                    label="内网镜像 / 自定义下载 URL"
                                    style={{ marginBottom: 8 }}
                                    rules={[{ required: true, message: '请输入自定义下载 URL' }]}
                                  >
                                    <Input placeholder="https://mirror.corp.local/geoip/city.mmdb.gz" />
                                  </Form.Item>
                                </Col>
                              )}
                            </Row>
                          )
                        }}
                      </Form.Item>
                    </Card>
                  )
                })}
              </Space>
            )}
          </Form.List>
        </Form>
      </Drawer>
    </Space>
  )
}
