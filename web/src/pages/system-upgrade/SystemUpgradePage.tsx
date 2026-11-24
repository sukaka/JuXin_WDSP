import { useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import dayjs, { type Dayjs } from 'dayjs'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  DatePicker,
  Descriptions,
  Drawer,
  Form,
  Input,
  InputNumber,
  Modal,
  Popconfirm,
  Progress,
  Radio,
  Select,
  Space,
  Table,
  Tag,
  Typography,
  Upload,
} from 'antd'
import SmartTable from '../../components/SmartTable'
import type { ColumnsType } from 'antd/es/table'
import {
  InboxOutlined,
  PlusOutlined,
  ReloadOutlined,
  RollbackOutlined,
  UploadOutlined,
} from '@ant-design/icons'
import { ApiError, type UploadProgress } from '../../api/client'
import { upgradesApi, type UpgradePackageResp } from '../../api/upgrades'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatBytes, formatDateTime } from '../../utils/format'
import { PRECHECK_NAME_LABELS } from '../../utils/i18nLabels'
import { hasPermission } from '../../utils/permission'
import { truncateHash } from '../../utils/stage3'
import {
  CHECK_RESULT_META,
  UPGRADE_PACKAGE_STATUS_META,
  UPGRADE_STATUS_META,
  isTerminalUpgradeStatus,
} from '../../utils/stage6'
import type {
  UpgradeClusterMode,
  UpgradeClusterNode,
  UpgradeJobItem,
  UpgradeNodeExecution,
  UpgradePrecheckItem,
  UpgradePrecheckResult,
} from '../../types'

interface PackageFormValues {
  file_name: string
  version_from: string
  version_to: string
  file_hash: string
  file_size: number
}

/** 更新时机：立即更新 / 定时更新（定时需选择将来的开始时间） */
type UpgradeTiming = 'NOW' | 'SCHEDULED'

interface UpgradeManifestMeta {
  components: string[]
  hasLayerDelta: boolean
}

function parseUpgradeManifestMeta(manifest: unknown): UpgradeManifestMeta {
  if (!manifest || typeof manifest !== 'object') {
    return { components: [], hasLayerDelta: false }
  }
  const m = manifest as {
    components?: unknown
    images?: Array<{ delivery_mode?: unknown }>
  }
  const components = Array.isArray(m.components)
    ? m.components.filter((c): c is string => typeof c === 'string' && c.length > 0)
    : []
  const hasLayerDelta = Array.isArray(m.images)
    ? m.images.some((img) => Boolean(img && img.delivery_mode === 'layer-delta'))
    : false
  return { components, hasLayerDelta }
}

function formatManifestSuffix(manifest: unknown): string {
  const { components, hasLayerDelta } = parseUpgradeManifestMeta(manifest)
  if (components.length === 0) return ''
  return `（变更组件：${components.join('、')}${hasLayerDelta ? '，镜像层差量包' : ''}）`
}

/** 逐节点升级执行状态词表（upgrade_node_executions.status） */
const NODE_EXECUTION_STATUS_META: Record<string, { color: string; label: string }> = {
  PENDING: { color: 'default', label: '待执行' },
  TRANSFERRING: { color: 'cyan', label: '传输升级包' },
  APPLYING: { color: 'geekblue', label: '执行升级' },
  VERIFYING: { color: 'gold', label: '健康验证' },
  SUCCESS: { color: 'green', label: '成功' },
  FAILED: { color: 'red', label: '失败' },
  SKIPPED: { color: 'default', label: '已跳过' },
}

const CLUSTER_MODE_LABELS: Record<string, string> = {
  LOCAL: '仅升级本节点',
  HA_ROLLING: 'HA 集群滚动升级（先备后主）',
}

const CLUSTER_MODE_OPTIONS: { value: UpgradeClusterMode; label: string }[] = [
  { value: 'HA_ROLLING', label: 'HA 集群滚动升级（先备后主，推荐）' },
  { value: 'LOCAL', label: '仅升级本节点' },
]

const UPGRADE_PRECHECK_LABELS: Record<string, string> = {
  ...PRECHECK_NAME_LABELS,
  cluster_sync_configured: '集群同步通道配置检查',
  cluster_split_brain: '集群脑裂状态检查',
  cluster_standby_nodes: '备节点健康与数量检查',
}

function formatPrecheckName(name: string): string {
  if (UPGRADE_PRECHECK_LABELS[name]) return UPGRADE_PRECHECK_LABELS[name]
  if (name.startsWith('cluster_node_')) {
    return `备节点升级就绪检查（${name.slice('cluster_node_'.length)}）`
  }
  return name
}

/** 系统升级：升级包上传/登记 → 预检 → 执行升级（任务轮询）→ 失败回滚 */
export default function SystemUpgradePage() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canPrecheck = hasPermission(permissions, 'upgrades.precheck')
  const canExecute = hasPermission(permissions, 'upgrades.execute')
  const canRollback = hasPermission(permissions, 'upgrades.rollback')

  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [registerOpen, setRegisterOpen] = useState(false)
  const [uploadOpen, setUploadOpen] = useState(false)
  const [uploadFile, setUploadFile] = useState<File | null>(null)
  const [uploadTiming, setUploadTiming] = useState<UpgradeTiming>('NOW')
  const [uploadScheduledAt, setUploadScheduledAt] = useState<Dayjs | null>(null)
  const [uploadProgress, setUploadProgress] = useState<UploadProgress | null>(null)
  const [uploadResult, setUploadResult] = useState<UpgradePackageResp | null>(null)
  const [selectedPackageId, setSelectedPackageId] = useState<string>()
  const selectedPackageIdRef = useRef<string | undefined>(undefined)
  selectedPackageIdRef.current = selectedPackageId
  const [precheck, setPrecheck] = useState<UpgradePrecheckResult | null>(null)

  const selectPackage = (nextId: string | undefined) => {
    selectedPackageIdRef.current = nextId
    setSelectedPackageId(nextId)
    setPrecheck(null)
  }
  const [detailJob, setDetailJob] = useState<UpgradeJobItem | null>(null)
  const [detailPrecheck, setDetailPrecheck] = useState<UpgradePrecheckItem | null>(null)
  const [clusterModeChoice, setClusterModeChoice] = useState<UpgradeClusterMode | null>(null)
  const [uploadClusterModeChoice, setUploadClusterModeChoice] = useState<UpgradeClusterMode | null>(null)
  const [retryingNodeId, setRetryingNodeId] = useState<string | null>(null)
  const [form] = Form.useForm<PackageFormValues>()

  const clusterNodesQuery = useQuery({
    queryKey: ['upgrade-cluster-nodes'],
    queryFn: () => upgradesApi.listClusterNodes(),
    retry: false,
  })
  const clusterNodesData = clusterNodesQuery.data
  const clusterNodes = useMemo(() => clusterNodesData?.items ?? [], [clusterNodesData?.items])
  const remoteStandbyNodes = useMemo(
    () => clusterNodes.filter((n) => n.role === 'STANDBY'),
    [clusterNodes],
  )
  const hasClusterNodes = remoteStandbyNodes.length > 0
  const effectiveClusterMode: UpgradeClusterMode = hasClusterNodes
    ? (clusterModeChoice ?? 'HA_ROLLING')
    : 'LOCAL'
  const effectiveUploadClusterMode: UpgradeClusterMode = hasClusterNodes
    ? (uploadClusterModeChoice ?? 'HA_ROLLING')
    : 'LOCAL'

  const detailJobQuery = useQuery({
    queryKey: ['upgrade-job', detailJob?.id],
    queryFn: () => upgradesApi.get(detailJob!.id),
    enabled: detailJob !== null,
    retry: false,
    refetchInterval: (query) =>
      query.state.data && !isTerminalUpgradeStatus(query.state.data.status) ? 3000 : false,
  })
  const activeDetailJob = detailJobQuery.data ?? detailJob

  const packagesQuery = useQuery({
    queryKey: ['upgrade-packages'],
    queryFn: () => upgradesApi.listPackages({ page: 1, page_size: 50 }),
  })
  const packages = useMemo(() => packagesQuery.data?.items ?? [], [packagesQuery.data?.items])
  const packageMap = useMemo(() => new Map(packages.map((p) => [p.id, p])), [packages])
  const selectedPackage = selectedPackageId ? packageMap.get(selectedPackageId) : undefined
  const selectedManifestMeta = useMemo(
    () => parseUpgradeManifestMeta(selectedPackage?.manifest),
    [selectedPackage?.manifest],
  )
  const formatJobVersion = (job: UpgradeJobItem) => {
    const pkg = job.package_id ? packageMap.get(job.package_id) : undefined
    return pkg ? `${pkg.version_from} → ${pkg.version_to}` : '-'
  }

  const listQuery = useQuery({
    queryKey: ['upgrades', page, pageSize],
    queryFn: () => upgradesApi.list({ page, page_size: pageSize }),
    refetchInterval: (query) =>
      (query.state.data?.items ?? []).some((j) => !isTerminalUpgradeStatus(j.status)) ? 3000 : false,
  })

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ['upgrades'] })
    void queryClient.invalidateQueries({ queryKey: ['upgrade-job'] })
    void queryClient.invalidateQueries({ queryKey: ['upgrade-cluster-nodes'] })
  }
  const invalidatePackages = () => void queryClient.invalidateQueries({ queryKey: ['upgrade-packages'] })
  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  // 登记成功后处理：REJECTED 时后端带 message 说明原因
  const onPackageRegistered = (resp: UpgradePackageResp) => {
    const pkg = resp.package
    if (resp.message) {
      message.warning(resp.message)
    } else {
      message.success('升级包已登记，请执行升级前检查')
    }
    invalidatePackages()
    if (pkg.status !== 'REJECTED') {
      selectPackage(pkg.id)
    }
  }

  const registerMutation = useMutation({
    mutationFn: (values: PackageFormValues) => upgradesApi.registerPackage(values),
    onSuccess: (resp) => {
      onPackageRegistered(resp)
      setRegisterOpen(false)
      form.resetFields()
    },
    onError,
  })

  // 上传弹窗关闭/提交成功后统一复位，避免下次打开残留上次选择
  const resetUploadForm = () => {
    setUploadFile(null)
    setUploadTiming('NOW')
    setUploadScheduledAt(null)
    setUploadClusterModeChoice(null)
    setUploadProgress(null)
  }

  const uploadMutation = useMutation({
    mutationFn: (vars: { file: File; scheduledAt?: string; clusterMode?: UpgradeClusterMode }) =>
      upgradesApi.uploadPackage(vars.file, vars.scheduledAt, setUploadProgress, vars.clusterMode),
    onSuccess: (resp) => {
      // 上传响应即最终处置：execution 非空表示验证通过且已创建升级任务
      // （立即更新为执行态，定时更新为 SCHEDULED）；为 null 时 warning 说明原因
      setUploadResult(resp)
      setUploadOpen(false)
      resetUploadForm()
      invalidatePackages()
      invalidate()
      if (resp.package.status !== 'REJECTED') {
        selectPackage(resp.package.id)
      }
    },
    onError: (e) => {
      setUploadProgress(null)
      onError(e)
    },
  })

  const confirmUpload = () => {
    if (!uploadFile || uploadMutation.isPending) return
    setUploadProgress(null)
    const uploadMode =
      hasClusterNodes && effectiveUploadClusterMode === 'HA_ROLLING' ? 'HA_ROLLING' : undefined
    if (uploadTiming === 'SCHEDULED') {
      if (!uploadScheduledAt) {
        message.warning('请选择升级开始时间')
        return
      }
      uploadMutation.mutate({
        file: uploadFile,
        scheduledAt: uploadScheduledAt.toISOString(),
        clusterMode: uploadMode,
      })
      return
    }
    uploadMutation.mutate({ file: uploadFile, clusterMode: uploadMode })
  }

  const precheckMutation = useMutation({
    mutationFn: (vars: { packageId: string; clusterMode?: UpgradeClusterMode }) =>
      upgradesApi.precheck(vars.packageId, vars.clusterMode),
    onSuccess: (result, vars) => {
      const resultPackageId = result.package_id ?? vars.packageId
      // 防竞态：若用户在预检请求在途期间切换了升级包，丢弃过期的预检结果，避免跨包误启用执行按钮
      if (resultPackageId !== selectedPackageIdRef.current) return
      setPrecheck({ ...result, package_id: resultPackageId })
      if (result.overall_result === 'FAIL') message.error('预检存在失败项，禁止执行升级')
      else if (result.overall_result === 'WARNING') message.warning('预检存在警告项，请确认后再执行升级')
      else message.success('预检全部通过')
    },
    onError: (e, vars) => {
      if (vars.packageId !== selectedPackageIdRef.current) return
      onError(e)
    },
  })

  const executeMutation = useMutation({
    mutationFn: (vars: { packageId: string; clusterMode?: UpgradeClusterMode }) =>
      upgradesApi.execute(vars.packageId, vars.clusterMode),
    onSuccess: () => {
      message.success('升级任务已启动')
      invalidate()
    },
    onError,
  })

  const retryNodeMutation = useMutation({
    mutationFn: async (vars: { jobId: string; nodeId: string }) => {
      setRetryingNodeId(vars.nodeId)
      return upgradesApi.retryNode(vars.jobId, vars.nodeId)
    },
    onSuccess: (updatedExec) => {
      message.success(`节点「${updatedExec.node_name}」重试升级已触发`)
      invalidate()
    },
    onError,
    onSettled: () => setRetryingNodeId(null),
  })

  const rollbackMutation = useMutation({
    mutationFn: (id: string) => upgradesApi.rollback(id),
    onSuccess: () => {
      message.success('回滚任务已启动')
      invalidate()
    },
    onError,
  })

  const cancelMutation = useMutation({
    mutationFn: (id: string) => upgradesApi.cancelUpgrade(id),
    onSuccess: () => {
      message.success('定时升级已取消')
      invalidate()
    },
    onError,
  })

  const precheckMatchesSelected = Boolean(
    selectedPackageId && precheck && precheck.package_id === selectedPackageId,
  )
  const precheckBlocked = (precheck?.items ?? []).some((i) => i.result === 'FAIL')

  const confirmExecute = () => {
    if (!selectedPackageId || !precheckMatchesSelected || precheckBlocked) return
    const modeArg = hasClusterNodes ? effectiveClusterMode : undefined
    const isRolling = modeArg === 'HA_ROLLING'
    modal.confirm({
      title: '高风险操作确认',
      content: isRolling
        ? '将按「先备后主」顺序执行 HA 集群滚动升级：先推送并升级备节点，任一备节点失败立即中止且不触碰主节点；全部备节点验证通过后再升级主节点，升级前将自动执行全量备份。确定执行升级吗？'
        : '执行升级将进入维护窗口并更新系统组件与数据库，升级前将自动执行全量备份。确定执行升级吗？',
      okText: '确认升级',
      okButtonProps: { danger: true },
      onOk: () => executeMutation.mutate({ packageId: selectedPackageId, clusterMode: modeArg }),
    })
  }

  const confirmRollback = (record: UpgradeJobItem) => {
    const versionText = formatJobVersion(record)
    modal.confirm({
      title: '高风险操作确认',
      content: `确定回滚升级任务「${record.id.slice(0, 8)}」（版本：${versionText}）吗？回滚将恢复旧版本组件、数据库迁移与配置。`,
      okText: '确认回滚',
      okButtonProps: { danger: true },
      onOk: () => rollbackMutation.mutate(record.id),
    })
  }

  const clusterNodeColumns: ColumnsType<UpgradeClusterNode> = [
    {
      title: '节点',
      key: 'node',
      width: 200,
      render: (_, n) => (
        <Space size={6} wrap>
          <Typography.Text strong>{n.node_name}</Typography.Text>
          <Tag color={n.role === 'PRIMARY' ? 'gold' : 'blue'}>
            {n.role === 'PRIMARY' ? '主节点' : '备节点'}
          </Tag>
        </Space>
      ),
    },
    {
      title: '当前版本',
      dataIndex: 'reported_version',
      width: 170,
      render: (v: string, n) => (
        <Space size={6} wrap>
          <Typography.Text code>{v || '-'}</Typography.Text>
          <Tag color={n.version_aligned ? 'green' : 'orange'}>
            {n.version_aligned ? '版本一致' : '版本不一致'}
          </Tag>
        </Space>
      ),
    },
    {
      title: '通道与就绪态',
      key: 'readiness',
      render: (_, n) => (
        <Space size={6} wrap>
          <Tag color={n.reachable ? 'green' : 'red'}>{n.reachable ? '在线可达' : '不可达'}</Tag>
          <Tag color={n.caddy_reachable ? 'green' : 'red'}>
            Caddy {n.caddy_reachable ? '正常' : '异常'}
          </Tag>
          <Tag color={n.upgrade_ready ? 'green' : 'orange'}>
            执行器{n.upgrade_ready ? '就绪' : '未就绪'}
          </Tag>
          {n.error && (
            <Typography.Text type="danger" style={{ fontSize: 12 }}>
              {n.error}
            </Typography.Text>
          )}
        </Space>
      ),
    },
  ]

  const nodeExecutionColumns: ColumnsType<UpgradeNodeExecution> = [
    { title: '顺序', dataIndex: 'seq', width: 64 },
    {
      title: '节点',
      key: 'node',
      width: 160,
      render: (_, row) => (
        <Space size={4} wrap>
          <Typography.Text strong>{row.node_name}</Typography.Text>
          <Tag color={row.role === 'PRIMARY' ? 'gold' : 'blue'}>
            {row.role === 'PRIMARY' ? '主节点' : '备节点'}
          </Tag>
        </Space>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 110,
      render: (v: string) => <StatusTag value={v} map={NODE_EXECUTION_STATUS_META} />,
    },
    {
      title: '版本变更',
      key: 'versions',
      width: 140,
      render: (_, row) =>
        row.from_version || row.to_version ? `${row.from_version || '-'} → ${row.to_version || '-'}` : '-',
    },
    {
      title: '时间',
      key: 'time',
      width: 170,
      render: (_, row) => (
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          {row.finished_at
            ? formatDateTime(row.finished_at)
            : row.started_at
              ? formatDateTime(row.started_at)
              : '-'}
        </Typography.Text>
      ),
    },
    {
      title: '错误信息',
      key: 'error',
      render: (_, row) =>
        row.error_message || row.error_code ? (
          <Typography.Text type="danger" style={{ fontSize: 12 }}>
            {[row.error_code, row.error_message].filter(Boolean).join('：')}
          </Typography.Text>
        ) : (
          '-'
        ),
    },
    {
      title: '操作',
      key: 'action',
      width: 120,
      render: (_, row) => {
        const canRetryNode =
          canExecute &&
          activeDetailJob != null &&
          isTerminalUpgradeStatus(activeDetailJob.status) &&
          row.role === 'STANDBY' &&
          (row.status === 'FAILED' || row.status === 'SKIPPED') &&
          Boolean(row.node_id)
        if (!canRetryNode) return '-'
        return (
          <Button
            type="link"
            size="small"
            icon={<ReloadOutlined />}
            loading={retryingNodeId === row.node_id}
            onClick={() =>
              row.node_id &&
              retryNodeMutation.mutate({ jobId: activeDetailJob.id, nodeId: row.node_id })
            }
          >
            重试节点升级
          </Button>
        )
      },
    },
  ]

  const columns: ColumnsType<UpgradeJobItem> = [
    { title: '任务ID', dataIndex: 'id', width: 110, render: (v: string) => v.slice(0, 8) },
    {
      title: '版本',
      key: 'version',
      width: 160,
      render: (_, r) => <Typography.Text>{formatJobVersion(r)}</Typography.Text>,
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 150,
      render: (v: string, r) => (
        <Space size={4} wrap>
          <StatusTag value={v} map={UPGRADE_STATUS_META} />
          {r.cluster_mode === 'HA_ROLLING' && <Tag color="purple">HA滚动</Tag>}
        </Space>
      ),
    },
    {
      title: '计划时间',
      dataIndex: 'scheduled_at',
      width: 170,
      render: (v: string | null | undefined) => formatDateTime(v),
    },
    {
      title: '开始时间',
      dataIndex: 'started_at',
      width: 170,
      render: (v: string | null | undefined) => formatDateTime(v),
    },
    {
      title: '完成时间',
      dataIndex: 'finished_at',
      width: 170,
      render: (v: string | null | undefined) => formatDateTime(v),
    },
    {
      title: '创建时间',
      dataIndex: 'requested_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 180,
      fixed: 'right',
      render: (_, record) => (
        <Space size={0} wrap>
          {record.status === 'FAILED' && record.failure_message && (
            <Typography.Text type="danger" style={{ fontSize: 12 }} ellipsis={{ tooltip: record.failure_message }}>
              {record.failure_message}
            </Typography.Text>
          )}
          {canRollback && (record.status === 'FAILED' || record.status === 'SUCCESS') && (
            <Button type="link" size="small" danger icon={<RollbackOutlined />} onClick={() => confirmRollback(record)}>
              回滚
            </Button>
          )}
          {canExecute && record.status === 'SCHEDULED' && (
            <Popconfirm
              title="确定取消该定时升级？"
              okText="确定"
              onConfirm={() => cancelMutation.mutate(record.id)}
            >
              <Button type="link" size="small" danger>
                取消
              </Button>
            </Popconfirm>
          )}
          {(record.cluster_mode === 'HA_ROLLING' || (record.node_executions?.length ?? 0) > 0) && (
            <Button type="link" size="small" onClick={() => setDetailJob(record)}>
              节点明细
            </Button>
          )}
        </Space>
      ),
    },
  ]

  return (
    <Space direction="vertical" size={16} style={{ display: 'flex' }}>
      {hasClusterNodes && clusterNodesData && (
        <Card
          size="small"
          title="集群节点版本"
          extra={
            <Space size={8} wrap>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                主节点当前版本：{clusterNodesData.current_version}
              </Typography.Text>
              <Tag color={clusterNodesData.cluster_ready ? 'green' : 'orange'}>
                {clusterNodesData.cluster_ready ? '集群升级就绪' : '存在未就绪节点'}
              </Tag>
              <Button
                size="small"
                icon={<ReloadOutlined />}
                loading={clusterNodesQuery.isFetching}
                onClick={() => void clusterNodesQuery.refetch()}
              >
                刷新
              </Button>
            </Space>
          }
        >
          <Space direction="vertical" size={12} style={{ width: '100%' }}>
            {clusterNodesData.split_brain && (
              <Alert
                type="error"
                showIcon
                message="检测到主备双主脑裂（HA_SPLIT_BRAIN），已禁止启动 HA 集群滚动升级"
                description="请先在「主备高可用」页面排查并恢复单主状态后，再重新执行集群滚动升级。"
              />
            )}
            <Table<UpgradeClusterNode>
              size="small"
              rowKey={(n) => n.node_id || n.node_name}
              columns={clusterNodeColumns}
              dataSource={clusterNodes}
              pagination={false}
            />
          </Space>
        </Card>
      )}

      <Card
        title="升级包与预检"
        extra={
          canExecute && (
            <Space>
              <Button icon={<PlusOutlined />} onClick={() => setRegisterOpen(true)}>
                登记升级包
              </Button>
              <Button type="primary" icon={<UploadOutlined />} onClick={() => setUploadOpen(true)}>
                上传升级包
              </Button>
            </Space>
          )
        }
      >
        <Space direction="vertical" size={16} style={{ display: 'flex' }}>
          {uploadResult &&
            (uploadResult.execution?.status === 'SCHEDULED' ? (
              <Alert
                type="info"
                showIcon
                closable
                onClose={() => setUploadResult(null)}
                message={`已创建定时升级：检测版本 ${uploadResult.package.version_from} → ${uploadResult.package.version_to}`}
                description={`将于 ${formatDateTime(uploadResult.execution.scheduled_at)} 自动开始；开始升级前会自动创建全量备份${formatManifestSuffix(uploadResult.package.manifest)}`}
              />
            ) : (
              <Alert
                type={uploadResult.execution ? 'success' : 'warning'}
                showIcon
                closable
                onClose={() => setUploadResult(null)}
                message={`检测到的版本：从 ${uploadResult.package.version_from} → ${uploadResult.package.version_to}`}
                description={
                  uploadResult.execution
                    ? `已开始自动升级，可在下方列表查看进度${formatManifestSuffix(uploadResult.package.manifest)}`
                    : `${uploadResult.warning ?? '可稍后手动执行升级'}${formatManifestSuffix(uploadResult.package.manifest)}`
                }
              />
            ))}
          <Space wrap>
            <Select
              style={{ minWidth: 420 }}
              placeholder="选择升级包"
              loading={packagesQuery.isLoading}
              value={selectedPackageId}
              onChange={(v) => {
                selectPackage(v)
              }}
              options={packages.map((p) => {
                const meta = parseUpgradeManifestMeta(p.manifest)
                const diffInfo =
                  meta.components.length > 0
                    ? `，组件 ${meta.components.join('/')}${meta.hasLayerDelta ? '，层差量' : ''}`
                    : ''
                return {
                  value: p.id,
                  disabled: p.status === 'REJECTED',
                  label: `${p.file_name}（${p.version_from} → ${p.version_to}，${formatBytes(p.file_size)}${diffInfo}，哈希 ${truncateHash(p.file_hash, 8)}，${UPGRADE_PACKAGE_STATUS_META[p.status]?.label ?? p.status}）`,
                }
              })}
              notFoundContent="请先上传或登记升级包"
            />
            {canPrecheck && (
              <Button
                disabled={!selectedPackageId}
                loading={precheckMutation.isPending}
                onClick={() =>
                  selectedPackageId &&
                  precheckMutation.mutate({
                    packageId: selectedPackageId,
                    clusterMode: hasClusterNodes ? effectiveClusterMode : undefined,
                  })
                }
              >
                执行预检
              </Button>
            )}
            {canExecute && (
              <Button
                type="primary"
                danger
                disabled={!selectedPackageId || precheck?.package_id !== selectedPackageId || precheckBlocked}
                loading={executeMutation.isPending}
                onClick={confirmExecute}
              >
                执行升级
              </Button>
            )}
          </Space>

          {hasClusterNodes && (
            <Space wrap align="center">
              <Typography.Text strong>升级模式：</Typography.Text>
              <Radio.Group
                value={effectiveClusterMode}
                onChange={(e) => {
                  setClusterModeChoice(e.target.value as UpgradeClusterMode)
                  setPrecheck(null)
                }}
                options={CLUSTER_MODE_OPTIONS}
              />
            </Space>
          )}

          {selectedPackage && selectedManifestMeta.components.length > 0 && (
            <Space wrap size={6}>
              <Typography.Text type="secondary">
                精确差量路径：{selectedPackage.version_from} → {selectedPackage.version_to}
              </Typography.Text>
              {selectedManifestMeta.hasLayerDelta && <Tag color="blue">镜像层差量</Tag>}
              {selectedManifestMeta.components.map((comp) => (
                <Tag key={comp}>{comp}</Tag>
              ))}
            </Space>
          )}

          {precheckMatchesSelected && precheck && (
            <>
              <Alert
                type={precheck.overall_result === 'PASS' ? 'success' : precheck.overall_result === 'WARNING' ? 'warning' : 'error'}
                showIcon
                message={`预检结果：${CHECK_RESULT_META[precheck.overall_result]?.label ?? precheck.overall_result}`}
                description={precheckBlocked ? '存在失败项，禁止执行升级。' : undefined}
              />
              <SmartTable
                storageKey="system-upgrade"
                size="small"
                rowKey="name"
                pagination={false}
                dataSource={precheck.items ?? []}
                onRow={(record) => ({
                  onDoubleClick: () => setDetailPrecheck(record),
                  style: { cursor: 'pointer' },
                })}
                columns={[
                  {
                    title: '检查项',
                    dataIndex: 'name',
                    width: 220,
                    render: (v: string) => formatPrecheckName(v),
                  },
                  {
                    title: '结果',
                    dataIndex: 'result',
                    width: 100,
                    render: (v: string, record) => (
                      <Space size={4}>
                        <StatusTag value={v} map={CHECK_RESULT_META} />
                        {record.critical && <Tag color="red">关键项</Tag>}
                      </Space>
                    ),
                  },
                  { title: '说明', dataIndex: 'message', ellipsis: true, render: (v: string) => v || '-' },
                ]}
              />
            </>
          )}
        </Space>
      </Card>

      <Card title="升级任务">
        {listQuery.isError ? (
          <QueryErrorAlert error={listQuery.error} message="加载升级任务失败" />
        ) : (
          <SmartTable<UpgradeJobItem>
            storageKey="system-upgrade-2"
            rowKey="id"
            loading={listQuery.isLoading}
            columns={columns}
            dataSource={listQuery.data?.items}
            scroll={{ x: 1270 }}
            onRow={(record) => ({
              onDoubleClick: () => setDetailJob(record),
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
        )}
      </Card>

      <Modal
        title="上传升级包"
        open={uploadOpen}
        onCancel={() => {
          if (uploadMutation.isPending) return
          setUploadOpen(false)
          resetUploadForm()
        }}
        onOk={confirmUpload}
        okText="确认上传"
        okButtonProps={{ disabled: !uploadFile || uploadMutation.isPending }}
        cancelButtonProps={{ disabled: uploadMutation.isPending }}
        confirmLoading={uploadMutation.isPending}
        closable={!uploadMutation.isPending}
        maskClosable={false}
        keyboard={!uploadMutation.isPending}
        destroyOnHidden
      >
        <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
          升级仅可通过本页面发起，支持按起始版本→目标版本生成的精确差量升级包（仅含变更组件与差量镜像层）。上传后系统自动校验签名与版本；选择立即更新时校验通过将自动开始升级，选择定时更新时将创建定时任务，
          到达计划时间后自动开始；开始升级前会自动创建全量备份。上传大小上限默认 4GiB。
        </Typography.Paragraph>
        <Upload.Dragger
          accept=".tar.gz"
          maxCount={1}
          disabled={uploadMutation.isPending}
          beforeUpload={(file) => {
            if (uploadMutation.isPending) return Upload.LIST_IGNORE
            if (!file.name.toLowerCase().endsWith('.tar.gz')) {
              message.error('仅支持 .tar.gz 格式的升级包')
              return Upload.LIST_IGNORE
            }
            setUploadFile(file)
            return false
          }}
          onRemove={() => {
            if (uploadMutation.isPending) return false
            setUploadFile(null)
            return true
          }}
        >
          <p className="ant-upload-drag-icon">
            <InboxOutlined />
          </p>
          <p className="ant-upload-text">点击或拖拽升级包文件到此区域</p>
          <p className="ant-upload-hint">仅支持 .tar.gz 格式，如：jiuzhang-wdsp-upgrade-1.3.0-amd64.tar.gz</p>
        </Upload.Dragger>
        {uploadMutation.isPending && (
          <div style={{ marginTop: 16 }} role="status" aria-live="polite">
            <Progress
              percent={
                uploadProgress?.lengthComputable && uploadProgress.total > 0
                  ? Math.min(100, Math.round((uploadProgress.loaded / uploadProgress.total) * 100))
                  : 0
              }
              status="active"
            />
            <Typography.Text type="secondary">
              {uploadProgress?.lengthComputable && uploadProgress.total > 0 && uploadProgress.loaded >= uploadProgress.total
                ? '升级包已上传，正在等待服务端验签并创建升级任务…'
                : uploadProgress
                  ? `正在上传：${formatBytes(uploadProgress.loaded)}${uploadProgress.lengthComputable ? ` / ${formatBytes(uploadProgress.total)}` : ''}`
                  : '正在准备上传…'}
            </Typography.Text>
          </div>
        )}
        <div style={{ marginTop: 16 }}>
          <Typography.Text strong>更新时机</Typography.Text>
          <div style={{ marginTop: 8 }}>
            <Radio.Group
              value={uploadTiming}
              disabled={uploadMutation.isPending}
              onChange={(e) => setUploadTiming(e.target.value as UpgradeTiming)}
              options={[
                { value: 'NOW', label: '立即更新' },
                { value: 'SCHEDULED', label: '定时更新' },
              ]}
            />
          </div>
          {uploadTiming === 'SCHEDULED' && (
            <DatePicker
              showTime
              format="YYYY-MM-DD HH:mm"
              placeholder="选择升级开始时间"
              style={{ width: '100%', marginTop: 8 }}
              value={uploadScheduledAt}
              disabled={uploadMutation.isPending}
              onChange={(v) => setUploadScheduledAt(v)}
              disabledDate={(current) => current.isBefore(dayjs().startOf('day'))}
              disabledTime={(date) => {
                // 与后端「必须是将来的时间」约束对齐：今天禁选当前时刻之前的小时/分钟
                const now = dayjs()
                if (!date || !date.isSame(now, 'day')) return {}
                return {
                  disabledHours: () => Array.from({ length: now.hour() }, (_, i) => i),
                  disabledMinutes: (hour) =>
                    hour === now.hour() ? Array.from({ length: now.minute() }, (_, i) => i) : [],
                }
              }}
            />
          )}
        </div>
        {hasClusterNodes && (
          <div style={{ marginTop: 16 }}>
            <Typography.Text strong>升级模式</Typography.Text>
            <div style={{ marginTop: 8 }}>
              <Radio.Group
                value={effectiveUploadClusterMode}
                disabled={uploadMutation.isPending}
                onChange={(e) => setUploadClusterModeChoice(e.target.value as UpgradeClusterMode)}
                options={CLUSTER_MODE_OPTIONS}
              />
            </div>
          </div>
        )}
      </Modal>

      <Modal
        title="登记升级包"
        open={registerOpen}
        onCancel={() => setRegisterOpen(false)}
        onOk={() => form.submit()}
        confirmLoading={registerMutation.isPending}
        destroyOnHidden
      >
        <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
          适用于升级包已拷贝至服务端升级包目录的场景：仅登记元数据，登记时校验哈希与大小格式，
          升级前检查会核验目录中文件与登记信息一致。
        </Typography.Paragraph>
        <Form<PackageFormValues>
          form={form}
          layout="vertical"
          onFinish={(values) => registerMutation.mutate(values)}
        >
          <Form.Item name="file_name" label="文件名" rules={[{ required: true, message: '请输入文件名' }, { max: 200 }]}>
            <Input placeholder="如：jiuzhang-waf-v2.1.0-upgrade.tar.gz" />
          </Form.Item>
          <Space.Compact block>
            <Form.Item name="version_from" label="当前版本" style={{ width: '50%', marginRight: 8 }} rules={[{ required: true, message: '请输入当前版本' }, { max: 50 }]}>
              <Input placeholder="如：2.0.0" />
            </Form.Item>
            <Form.Item name="version_to" label="目标版本" style={{ width: '50%' }} rules={[{ required: true, message: '请输入目标版本' }, { max: 50 }]}>
              <Input placeholder="如：2.1.0" />
            </Form.Item>
          </Space.Compact>
          <Form.Item
            name="file_hash"
            label="文件哈希（SHA-256）"
            rules={[
              { required: true, message: '请输入文件哈希' },
              { pattern: /^[0-9a-fA-F]{64}$/, message: '须为 64 位十六进制摘要（SHA-256）' },
            ]}
          >
            <Input placeholder="64 位十六进制" autoComplete="off" />
          </Form.Item>
          <Form.Item name="file_size" label="文件大小（字节）" rules={[{ required: true, message: '请输入文件大小' }]}>
            <InputNumber min={1} precision={0} style={{ width: '100%' }} />
          </Form.Item>
        </Form>
      </Modal>

      <RecordDetailDrawer
        open={detailPrecheck !== null}
        title="预检项详情"
        record={
          detailPrecheck
            ? ({
                ...detailPrecheck,
                name: formatPrecheckName(detailPrecheck.name),
              } as Record<string, unknown>)
            : null
        }
        fieldLabels={{ name: '检查项', result: '结果', critical: '关键项', message: '说明' }}
        onClose={() => setDetailPrecheck(null)}
      />
      <Drawer
        title="升级任务详情"
        open={detailJob !== null}
        onClose={() => setDetailJob(null)}
        width={820}
        destroyOnHidden
      >
        {activeDetailJob && (
          <Space direction="vertical" size={16} style={{ width: '100%' }}>
            <Descriptions column={2} bordered size="small">
              <Descriptions.Item label="任务ID">{activeDetailJob.id}</Descriptions.Item>
              <Descriptions.Item label="版本">{formatJobVersion(activeDetailJob)}</Descriptions.Item>
              <Descriptions.Item label="升级模式">
                {CLUSTER_MODE_LABELS[activeDetailJob.cluster_mode ?? 'LOCAL'] ??
                  activeDetailJob.cluster_mode ??
                  '仅升级本节点'}
              </Descriptions.Item>
              <Descriptions.Item label="状态">
                <StatusTag value={activeDetailJob.status} map={UPGRADE_STATUS_META} />
              </Descriptions.Item>
              <Descriptions.Item label="创建时间">
                {formatDateTime(activeDetailJob.requested_at)}
              </Descriptions.Item>
              <Descriptions.Item label="计划时间">
                {formatDateTime(activeDetailJob.scheduled_at)}
              </Descriptions.Item>
              <Descriptions.Item label="开始时间">
                {formatDateTime(activeDetailJob.started_at)}
              </Descriptions.Item>
              <Descriptions.Item label="完成时间">
                {formatDateTime(activeDetailJob.finished_at)}
              </Descriptions.Item>
              {activeDetailJob.failure_code && (
                <Descriptions.Item label="失败码">{activeDetailJob.failure_code}</Descriptions.Item>
              )}
              {activeDetailJob.failure_message && (
                <Descriptions.Item label="失败原因" span={2}>
                  <Typography.Text type="danger">{activeDetailJob.failure_message}</Typography.Text>
                </Descriptions.Item>
              )}
            </Descriptions>

            {(activeDetailJob.node_executions?.length ?? 0) > 0 && (
              <div>
                <Typography.Title level={5} style={{ marginTop: 0 }}>
                  逐节点执行明细
                </Typography.Title>
                <Table<UpgradeNodeExecution>
                  size="small"
                  rowKey="id"
                  columns={nodeExecutionColumns}
                  dataSource={activeDetailJob.node_executions ?? []}
                  pagination={false}
                />
              </div>
            )}
          </Space>
        )}
      </Drawer>
    </Space>
  )
}
