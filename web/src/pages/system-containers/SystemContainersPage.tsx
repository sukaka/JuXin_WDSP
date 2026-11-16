import { useCallback, useEffect, useRef, useState, type CSSProperties, type ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Checkbox,
  Drawer,
  Select,
  Space,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { ReloadOutlined } from '@ant-design/icons'
import dayjs from 'dayjs'
import { ApiError } from '../../api/client'
import {
  CONTAINER_UPDATE_CONFIRM_TEXT,
  containerOpsApi,
  type ContainerActionKind,
  type ContainerInfo,
  type ContainerLogLine,
} from '../../api/containerOps'
import PasswordConfirmModal from '../../components/PasswordConfirmModal'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import { PRE_STYLE } from '../../utils/styles'

/** 容器状态展示（docker state；未命中时 StatusTag 原样展示） */
const CONTAINER_STATE_META: Record<string, { color: string; label: string }> = {
  running: { color: 'success', label: '运行中' },
  exited: { color: 'default', label: '已退出' },
  restarting: { color: 'processing', label: '重启中' },
  paused: { color: 'warning', label: '已暂停' },
  created: { color: 'default', label: '已创建' },
  removing: { color: 'warning', label: '移除中' },
  dead: { color: 'error', label: '已死亡' },
}

/** 健康检查展示（docker health；空串表示未配置探针，StatusTag 展示占位符） */
const CONTAINER_HEALTH_META: Record<string, { color: string; label: string }> = {
  healthy: { color: 'success', label: '健康' },
  unhealthy: { color: 'error', label: '不健康' },
  starting: { color: 'processing', label: '检查中' },
}

const ACTION_LABEL: Record<ContainerActionKind, string> = {
  start: '启动',
  stop: '停止',
  restart: '重启',
  update: '更新',
}

interface PendingAction {
  container: ContainerInfo
  action: ContainerActionKind
}

/** 操作确认弹窗的风险说明 */
function actionModalContent({ container, action }: PendingAction): ReactNode {
  const base: Record<ContainerActionKind, string> = {
    start: `确定启动容器「${container.name}」（服务 ${container.service}）吗？`,
    stop: `确定停止容器「${container.name}」（服务 ${container.service}）吗？停止期间该服务不可用。`,
    restart: `确定重启容器「${container.name}」（服务 ${container.service}）吗？重启期间该服务将短暂中断。`,
    update: `确定更新容器「${container.name}」（服务 ${container.service}）吗？更新将拉取最新镜像并重建容器，期间该服务将短暂中断。`,
  }
  return <>{base[action]}请输入当前账号密码以确认执行。</>
}

const LOG_TAIL_OPTIONS = [100, 200, 500, 1000]
const LOG_POLL_INTERVAL_MS = 2000

/** 终端风格日志样式：复用共享等宽 PRE_STYLE（utils/styles，与网络工具详情一致），覆写为深色终端底色 */
const LOG_PRE_STYLE: CSSProperties = {
  ...PRE_STYLE,
  background: '#101418',
  color: '#d6e2ee',
  border: '1px solid rgba(255, 255, 255, 0.14)',
  margin: 0,
  maxHeight: 'none',
  flex: 1,
  minHeight: 0,
}

function formatLogLine(line: ContainerLogLine): string {
  const d = dayjs(line.timestamp)
  const ts = d.isValid() ? d.format('YYYY-MM-DD HH:mm:ss') : line.timestamp
  return `${ts} [${line.stream || 'stdout'}] ${line.message}`
}

/** 容器日志抽屉：打开时拉取 tail 条快照，之后每 2 秒按 next_since 增量刷新；支持暂停/继续、自动滚动与 tail 切换 */
function ContainerLogsDrawer({
  container,
  onClose,
}: {
  container: ContainerInfo | null
  onClose: () => void
}) {
  const open = container !== null
  const service = container?.service
  const [lines, setLines] = useState<ContainerLogLine[]>([])
  const [tail, setTail] = useState(200)
  const [paused, setPaused] = useState(false)
  const [autoScroll, setAutoScroll] = useState(true)
  const [truncated, setTruncated] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const nextSinceRef = useRef<number | undefined>(undefined)
  const inflightRef = useRef(false)
  const pausedRef = useRef(paused)
  const preRef = useRef<HTMLPreElement | null>(null)

  useEffect(() => {
    pausedRef.current = paused
  }, [paused])

  const fetchLogs = useCallback(
    async (mode: 'reset' | 'more') => {
      if (!service || inflightRef.current) return
      inflightRef.current = true
      try {
        const resp = await containerOpsApi.logs(service, {
          tail,
          since: mode === 'reset' ? undefined : nextSinceRef.current,
        })
        if (mode === 'reset') {
          setLines(resp.lines ?? [])
        } else if ((resp.lines ?? []).length > 0) {
          setLines((prev) => [...prev, ...(resp.lines ?? [])])
        }
        nextSinceRef.current = resp.next_since
        setTruncated(Boolean(resp.truncated))
        setError(null)
      } catch (e) {
        setError(e instanceof ApiError ? e.message : '加载日志失败')
      } finally {
        inflightRef.current = false
      }
    },
    [service, tail],
  )

  // 打开抽屉或切换 tail 时重置为首屏快照（tail 条最新日志）
  useEffect(() => {
    if (!open) return
    setLines([])
    setError(null)
    setTruncated(false)
    nextSinceRef.current = undefined
    void fetchLogs('reset')
  }, [open, fetchLogs])

  // 每 2 秒按上次响应的 next_since 增量拉取；暂停时停止
  useEffect(() => {
    if (!open) return
    const timer = setInterval(() => {
      if (!pausedRef.current) void fetchLogs('more')
    }, LOG_POLL_INTERVAL_MS)
    return () => clearInterval(timer)
  }, [open, fetchLogs])

  // 自动滚动跟随最新日志
  useEffect(() => {
    if (autoScroll && preRef.current) {
      preRef.current.scrollTop = preRef.current.scrollHeight
    }
  }, [lines, autoScroll])

  return (
    <Drawer
      title={container ? `容器日志：${container.name}` : '容器日志'}
      open={open}
      width={760}
      onClose={onClose}
      destroyOnHidden
    >
      <Space direction="vertical" size={8} style={{ display: 'flex', height: '100%' }}>
        <Space wrap size={12}>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            服务 {service ?? '-'}
          </Typography.Text>
          <span>
            <Typography.Text type="secondary" style={{ fontSize: 12, marginRight: 4 }}>
              行数
            </Typography.Text>
            <Select
              size="small"
              aria-label="日志行数"
              value={tail}
              style={{ width: 96 }}
              onChange={(v) => setTail(v)}
              options={LOG_TAIL_OPTIONS.map((v) => ({ value: v, label: `tail ${v}` }))}
            />
          </span>
          <Button size="small" onClick={() => setPaused((p) => !p)}>
            {paused ? '继续' : '暂停'}
          </Button>
          <Button size="small" icon={<ReloadOutlined />} onClick={() => void fetchLogs('more')}>
            立即刷新
          </Button>
          <Checkbox checked={autoScroll} onChange={(e) => setAutoScroll(e.target.checked)}>
            自动滚动
          </Checkbox>
          {paused && <Tag color="warning">已暂停</Tag>}
        </Space>
        {truncated && (
          <Alert
            type="warning"
            showIcon
            message="日志达到返回上限，内容可能不完整；可调整行数重新加载，或到服务器上查看完整日志"
          />
        )}
        {error && <Alert type="error" showIcon message="加载日志失败" description={error} />}
        <pre ref={preRef} style={LOG_PRE_STYLE}>
          {lines.length === 0 ? '（暂无日志）' : lines.map(formatLogLine).join('\n')}
        </pre>
      </Space>
    </Drawer>
  )
}

/** 容器运维：容器状态总览（5 秒自动刷新）、日志查看与启动/停止/重启/更新（密码二次确认 + 任务轮询） */
export default function SystemContainersPage() {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canViewLogs = hasPermission(permissions, 'containers.logs')
  const canControl = hasPermission(permissions, 'containers.control')
  const canUpdate = hasPermission(permissions, 'containers.update')

  const [logTarget, setLogTarget] = useState<ContainerInfo | null>(null)
  const [pendingAction, setPendingAction] = useState<PendingAction | null>(null)
  const [trackingJobId, setTrackingJobId] = useState<string | null>(null)

  const listQuery = useQuery({
    queryKey: ['system-containers'],
    queryFn: () => containerOpsApi.list(),
    refetchInterval: 5000,
  })
  const containers = listQuery.data?.containers ?? []

  const refreshList = useCallback(
    () => void queryClient.invalidateQueries({ queryKey: ['system-containers'] }),
    [queryClient],
  )

  // 操作任务轮询：提交成功后每 1.5 秒查询一次直至终态（SUCCESS/FAILED）
  const jobQuery = useQuery({
    queryKey: ['system-containers-action', trackingJobId],
    queryFn: () => containerOpsApi.actionStatus(trackingJobId!),
    enabled: trackingJobId !== null,
    refetchInterval: (query) => {
      const status = query.state.data?.status
      return status === 'SUCCESS' || status === 'FAILED' ? false : 1500
    },
  })

  const job = jobQuery.data
  useEffect(() => {
    if (!trackingJobId || !job || job.job_id !== trackingJobId) return
    if (job.status === 'SUCCESS') {
      message.success(job.message || '容器操作执行成功')
      setTrackingJobId(null)
      refreshList()
    } else if (job.status === 'FAILED') {
      message.error(job.message || '容器操作执行失败')
      setTrackingJobId(null)
      refreshList()
    }
  }, [job, trackingJobId, message, refreshList])

  useEffect(() => {
    if (!trackingJobId || !jobQuery.isError) return
    message.error(jobQuery.error instanceof ApiError ? jobQuery.error.message : '查询操作结果失败')
    setTrackingJobId(null)
  }, [trackingJobId, jobQuery.isError, jobQuery.error, message])

  const actionMutation = useMutation({
    mutationFn: (vars: PendingAction & { password: string }) => {
      const { container, action, password } = vars
      switch (action) {
        case 'start':
          return containerOpsApi.start(container.service, password)
        case 'stop':
          return containerOpsApi.stop(container.service, password)
        case 'restart':
          return containerOpsApi.restart(container.service, password)
        case 'update':
          return containerOpsApi.update(container.service, password, CONTAINER_UPDATE_CONFIRM_TEXT)
      }
    },
    onSuccess: (resp, vars) => {
      setPendingAction(null)
      message.success(`${ACTION_LABEL[vars.action]}指令已受理，正在后台执行`)
      setTrackingJobId(resp.job_id)
      refreshList()
    },
    onError: (e: unknown) => {
      message.error(e instanceof ApiError ? e.message : '操作失败')
    },
  })

  const columns: ColumnsType<ContainerInfo> = [
    {
      title: '服务 / 容器',
      key: 'service',
      width: 220,
      render: (_, r) => (
        <>
          <Typography.Text strong code>
            {r.service}
          </Typography.Text>
          <br />
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {r.name}
          </Typography.Text>
        </>
      ),
    },
    {
      title: '镜像',
      dataIndex: 'image',
      ellipsis: true,
      render: (v: string) => (
        <Tooltip title={v}>
          <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{v}</Typography.Text>
        </Tooltip>
      ),
    },
    {
      title: '状态',
      dataIndex: 'state',
      width: 100,
      render: (v: string, r) => (
        <Tooltip title={r.status || undefined}>
          <span>
            <StatusTag value={v} map={CONTAINER_STATE_META} />
          </span>
        </Tooltip>
      ),
    },
    {
      title: '健康',
      dataIndex: 'health',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={CONTAINER_HEALTH_META} />,
    },
    { title: '重启次数', dataIndex: 'restart_count', width: 90 },
    {
      title: '启动时间',
      dataIndex: 'started_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    // 无任何操作权限（containers.logs/control/update）时隐藏整列
    ...(canViewLogs || canControl || canUpdate
      ? [
          {
            title: '操作',
            key: 'actions',
            width: 230,
            fixed: 'right' as const,
            render: (_: unknown, record: ContainerInfo) => (
              <Space size={0} wrap>
                {canViewLogs && (
                  <Button type="link" size="small" onClick={() => setLogTarget(record)}>
                    日志
                  </Button>
                )}
                {canControl && !record.running && record.service !== 'api' && (
                  <Button
                    type="link"
                    size="small"
                    onClick={() => setPendingAction({ container: record, action: 'start' })}
                  >
                    启动
                  </Button>
                )}
                {canControl && record.running && record.service !== 'api' && (
                  <Button
                    type="link"
                    size="small"
                    danger
                    onClick={() => setPendingAction({ container: record, action: 'stop' })}
                  >
                    停止
                  </Button>
                )}
                {canControl && (
                  <Button
                    type="link"
                    size="small"
                    onClick={() => setPendingAction({ container: record, action: 'restart' })}
                  >
                    重启
                  </Button>
                )}
                {canUpdate && record.service !== 'api' && (
                  <Button
                    type="link"
                    size="small"
                    danger
                    onClick={() => setPendingAction({ container: record, action: 'update' })}
                  >
                    更新
                  </Button>
                )}
                {/* 安全边界（docs/CONTAINER_OPS_DESIGN.md §7）：api 是请求发起方，
                    stop/update 会切断管理面会话，通道仅允许 restart */}
                {record.service === 'api' && (canControl || canUpdate) && (
                  <Tooltip title="api 容器是运维请求发起方，停止/更新会切断管理面会话，通道仅允许重启（Docker 自动拉起）；版本更新请走系统升级">
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                      仅支持重启
                    </Typography.Text>
                  </Tooltip>
                )}
              </Space>
            ),
          },
        ]
      : []),
  ]

  return (
    <Space direction="vertical" size={16} style={{ display: 'flex' }}>
      <Card
        title="容器运维"
        extra={
          <Space>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {listQuery.dataUpdatedAt > 0 ? `更新于 ${dayjs(listQuery.dataUpdatedAt).format('HH:mm:ss')}` : ''}
              （5 秒自动刷新）
            </Typography.Text>
            <Button
              size="small"
              icon={<ReloadOutlined />}
              loading={listQuery.isFetching}
              onClick={() => void listQuery.refetch()}
            >
              刷新
            </Button>
          </Space>
        }
      >
        {listQuery.isError ? (
          <QueryErrorAlert error={listQuery.error} message="加载容器列表失败" />
        ) : (
          <SmartTable<ContainerInfo>
            storageKey="system-containers"
            rowKey={(r) => r.id || r.service}
            loading={listQuery.isLoading}
            columns={columns}
            dataSource={containers}
            scroll={{ x: 1130 }}
            pagination={false}
            locale={{ emptyText: '暂无容器' }}
          />
        )}
      </Card>

      <ContainerLogsDrawer container={logTarget} onClose={() => setLogTarget(null)} />

      <PasswordConfirmModal
        open={pendingAction !== null}
        title={
          pendingAction
            ? `${pendingAction.action === 'start' ? '操作确认' : '高风险操作确认'}：${ACTION_LABEL[pendingAction.action]}容器`
            : '操作确认'
        }
        content={pendingAction ? actionModalContent(pendingAction) : ''}
        confirmText={pendingAction?.action === 'update' ? CONTAINER_UPDATE_CONFIRM_TEXT : undefined}
        loading={actionMutation.isPending}
        onOk={(password) => pendingAction && actionMutation.mutate({ ...pendingAction, password })}
        onCancel={() => setPendingAction(null)}
      />
    </Space>
  )
}
