import { useEffect, useMemo, useRef, useState } from 'react'
import {
  Alert,
  Button,
  Card,
  Descriptions,
  Result,
  Space,
  Spin,
  Steps,
  Table,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import {
  CheckCircleOutlined,
  CloudSyncOutlined,
  LoadingOutlined,
  SafetyCertificateOutlined,
  SyncOutlined,
} from '@ant-design/icons'
import { ApiError } from '../../api/client'
import { upgradesApi, type UpgradeServerStatus } from '../../api/upgrades'
import StatusTag from '../../components/StatusTag'
import { formatDateTime } from '../../utils/format'
import { UPGRADE_STATUS_META } from '../../utils/stage6'
import type { UpgradeJobItem, UpgradeNodeExecution } from '../../types'
import {
  clearActiveUpgrade,
  isTransientUpgradePollError,
  type ActiveUpgradeContext,
} from './upgradeProgressState'

function formatElapsed(seconds: number): string {
  const safe = Math.max(0, Math.floor(seconds))
  const m = Math.floor(safe / 60)
  const s = safe % 60
  return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`
}

function resolveStepIndex(status: string, reconnecting: boolean, verifiedSuccess: boolean): number {
  if (verifiedSuccess) return 4
  if (status === 'SUCCESS') return 3
  if (status === 'VERIFYING' || status === 'MIGRATING') return 3
  if (status === 'APPLYING' || status === 'RUNNING' || reconnecting) return 2
  if (status === 'BACKUP') return 1
  return 0
}

function stageHintText(status: string, isRolling: boolean, isRollback: boolean): string {
  if (isRollback) {
    return '正在恢复升级前加密全量备份与组件状态，请勿关闭页面，回滚完成后将展示最终结果。'
  }
  switch (status) {
    case 'PENDING':
    case 'PRECHECK':
      return '正在执行升级前环境、签名、磁盘与版本兼容性检查…'
    case 'BACKUP':
      return '正在创建并验证升级前加密全量备份，确保异常时可安全回滚…'
    case 'APPLYING':
    case 'RUNNING':
      return isRolling
        ? '正在按「先备后主」顺序推进节点镜像切换与服务重启，宿主机执行器正在校验所有组件健康状态…'
        : '宿主机升级执行器正在应用新版本镜像、重启受影响服务并执行 10 秒连续稳定性检查…'
    case 'MIGRATING':
      return '正在执行数据库结构迁移与初始化校验…'
    case 'VERIFYING':
      return '镜像已切换，后端正在自检数据库连接、缓存服务与迁移版本一致性…'
    default:
      return '升级任务已提交，后端将自动检测各阶段执行与健康状态，仅在确认升级成功后返回正常页面。'
  }
}

const NODE_STATUS_META: Record<string, { color: string; label: string }> = {
  PENDING: { color: 'default', label: '待执行' },
  TRANSFERRING: { color: 'cyan', label: '传输升级包' },
  APPLYING: { color: 'geekblue', label: '执行升级' },
  VERIFYING: { color: 'gold', label: '健康验证' },
  SUCCESS: { color: 'green', label: '成功' },
  FAILED: { color: 'red', label: '失败' },
  SKIPPED: { color: 'default', label: '已跳过' },
}

export interface UpgradeProgressScreenProps {
  context: ActiveUpgradeContext
  /** 状态探测轮询周期（毫秒，默认 2500） */
  pollIntervalMs?: number
  /** 后端确认升级成功后自动返回正常页的延迟（毫秒，默认 1500） */
  successRedirectDelayMs?: number
  /** 返回正常页回调：succeeded=true 表示后端已确认升级成功且核心服务健康就绪 */
  onFinish: (succeeded: boolean) => void
}

/**
 * 独立全页「系统正在升级」视图：
 * - 点击立即升级/立即更新后接管当前界面，暂停常规列表查询，避免重启期间出现红色网络报错；
 * - 持续轮询后端 GET /api/v1/upgrades/{id}（后端按需收敛执行器结果并实时核验 DB/Valkey/迁移版本）；
 * - 服务重启期间自动静默吸收 502/503/504/网络断开/超时并提示“服务正在重启切换中”；
 * - 仅在后端确认 status === SUCCESS 且 server_status.ready === true 时自动退回正常页并重载加载新版本前端；
 * - 若后端确认 FAILED / ROLLED_BACK / CANCELLED，如实展示原因并允许手动返回正常页。
 */
export default function UpgradeProgressScreen({
  context,
  pollIntervalMs = 2500,
  successRedirectDelayMs = 1500,
  onFinish,
}: UpgradeProgressScreenProps) {
  const [job, setJob] = useState<UpgradeJobItem | null>(null)
  const [serverStatus, setServerStatus] = useState<UpgradeServerStatus | null>(null)
  const [reconnecting, setReconnecting] = useState(false)
  const [reconnectAttempts, setReconnectAttempts] = useState(0)
  const [fatalPollError, setFatalPollError] = useState<string | null>(null)
  const [elapsedSec, setElapsedSec] = useState(() =>
    Math.max(0, Math.floor((Date.now() - context.startedAtMs) / 1000)),
  )

  const onFinishRef = useRef(onFinish)
  onFinishRef.current = onFinish
  const finishedTriggeredRef = useRef(false)

  const currentStatus = job?.status ?? context.initialStatus ?? 'PENDING'
  const isRollback = currentStatus === 'ROLLING_BACK'
  const isTerminalFailure =
    currentStatus === 'FAILED' || currentStatus === 'ROLLED_BACK' || currentStatus === 'CANCELLED'
  const isBackendVerifiedSuccess =
    currentStatus === 'SUCCESS' && (serverStatus == null || serverStatus.ready === true)
  const isAwaitingHealthAfterSuccess =
    currentStatus === 'SUCCESS' && serverStatus != null && serverStatus.ready === false
  const isStopped = isBackendVerifiedSuccess || isTerminalFailure || fatalPollError !== null

  // 已耗时秒表（进入终态后停止）
  useEffect(() => {
    if (isStopped) return
    const timer = window.setInterval(() => {
      setElapsedSec(Math.max(0, Math.floor((Date.now() - context.startedAtMs) / 1000)))
    }, 1000)
    return () => window.clearInterval(timer)
  }, [context.startedAtMs, isStopped])

  // 后端状态探测主循环（串行 setTimeout，杜绝并发堆叠；服务重启窗口静默重连）
  useEffect(() => {
    let cancelled = false
    let timer: number | undefined

    const pollOnce = async () => {
      try {
        const res = await upgradesApi.getStatus(context.jobId)
        if (cancelled) return
        setReconnecting(false)
        setReconnectAttempts(0)
        setFatalPollError(null)
        setJob(res.job)
        setServerStatus(res.server_status ?? null)

        const status = res.job.status
        const readySuccess =
          status === 'SUCCESS' && (res.server_status == null || res.server_status.ready === true)
        const terminalFail =
          status === 'FAILED' || status === 'ROLLED_BACK' || status === 'CANCELLED'
        if (readySuccess || terminalFail) {
          clearActiveUpgrade()
          return
        }
      } catch (err) {
        if (cancelled) return
        if (err instanceof ApiError && err.status === 401) {
          // 会话失效由全局 sessionExpiredHandler 跳转登录页，停止继续探测
          return
        }
        if (isTransientUpgradePollError(err)) {
          setReconnecting(true)
          setReconnectAttempts((n) => n + 1)
        } else {
          const msg = err instanceof ApiError ? err.message : '无法查询升级任务状态'
          clearActiveUpgrade()
          setFatalPollError(msg)
          return
        }
      }
      if (!cancelled) {
        timer = window.setTimeout(() => {
          void pollOnce()
        }, pollIntervalMs)
      }
    }

    void pollOnce()
    return () => {
      cancelled = true
      if (timer !== undefined) {
        window.clearTimeout(timer)
      }
    }
  }, [context.jobId, pollIntervalMs])

  // 仅在后端确认升级成功且核心服务健康就绪后，延迟自动返回正常页面
  useEffect(() => {
    if (!isBackendVerifiedSuccess || finishedTriggeredRef.current) return
    const timer = window.setTimeout(() => {
      if (finishedTriggeredRef.current) return
      finishedTriggeredRef.current = true
      clearActiveUpgrade()
      onFinishRef.current(true)
    }, successRedirectDelayMs)
    return () => window.clearTimeout(timer)
  }, [isBackendVerifiedSuccess, successRedirectDelayMs])

  const triggerExit = (succeeded: boolean) => {
    if (finishedTriggeredRef.current) return
    finishedTriggeredRef.current = true
    clearActiveUpgrade()
    onFinishRef.current(succeeded)
  }

  const effectiveClusterMode = job?.cluster_mode ?? context.clusterMode ?? 'LOCAL'
  const isRolling = effectiveClusterMode === 'HA_ROLLING'
  const displayVersion = serverStatus?.current_version || context.versionTo || ''
  const versionRangeText =
    context.versionFrom && context.versionTo
      ? `V${context.versionFrom} → V${context.versionTo}`
      : displayVersion
        ? `V${displayVersion}`
        : ''
  const currentStep = resolveStepIndex(currentStatus, reconnecting, isBackendVerifiedSuccess)

  const nodeColumns: ColumnsType<UpgradeNodeExecution> = useMemo(
    () => [
      { title: '顺序', dataIndex: 'seq', width: 64 },
      {
        title: '节点',
        key: 'node',
        width: 170,
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
        width: 120,
        render: (v: string) => <StatusTag value={v} map={NODE_STATUS_META} />,
      },
      {
        title: '版本',
        key: 'ver',
        width: 150,
        render: (_, row) =>
          row.from_version || row.to_version ? `${row.from_version || '-'} → ${row.to_version || '-'}` : '-',
      },
      {
        title: '说明',
        key: 'err',
        render: (_, row) =>
          row.error_message || row.error_code ? (
            <Typography.Text type="danger" style={{ fontSize: 12 }}>
              {[row.error_code, row.error_message].filter(Boolean).join('：')}
            </Typography.Text>
          ) : (
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {row.finished_at
                ? `完成于 ${formatDateTime(row.finished_at)}`
                : row.started_at
                  ? `开始于 ${formatDateTime(row.started_at)}`
                  : '等待调度'}
            </Typography.Text>
          ),
      },
    ],
    [],
  )

  return (
    <div
      data-testid="upgrade-progress-screen"
      role="status"
      aria-live="polite"
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 1000,
        background: 'linear-gradient(180deg, #eef4ff 0%, #f5f7fa 42%, #f5f7fa 100%)',
        overflowY: 'auto',
        padding: '48px 20px',
      }}
    >
      <div style={{ maxWidth: 820, margin: '0 auto' }}>
        <Card
          styles={{ body: { padding: '32px 36px' } }}
          style={{
            borderRadius: 12,
            boxShadow: '0 10px 30px rgba(15, 23, 42, 0.08)',
            borderColor: '#e2e8f0',
          }}
        >
          {isBackendVerifiedSuccess ? (
            <Result
              status="success"
              icon={<CheckCircleOutlined />}
              title="系统升级成功"
              subTitle={
                displayVersion
                  ? `系统已升级至 V${displayVersion}，后端健康检查与全部组件校验已通过，正在自动刷新并返回正常页面…`
                  : '后端健康检查与全部组件校验已通过，正在自动刷新并返回正常页面…'
              }
              extra={
                <Button type="primary" onClick={() => triggerExit(true)}>
                  立即返回正常页
                </Button>
              }
            />
          ) : isTerminalFailure ? (
            <Space direction="vertical" size={20} style={{ width: '100%' }}>
              <Result
                status={currentStatus === 'ROLLED_BACK' ? 'warning' : 'error'}
                title={
                  currentStatus === 'ROLLED_BACK'
                    ? '升级未成功，系统已自动回滚'
                    : currentStatus === 'CANCELLED'
                      ? '升级任务已取消'
                      : '系统升级失败'
                }
                subTitle={
                  job?.failure_message ||
                  (currentStatus === 'ROLLED_BACK'
                    ? '升级过程中检测到异常，系统已自动恢复至升级前状态。'
                    : '升级过程发生异常，请查看下方失败原因并排查后重试。')
                }
                extra={
                  <Button type="primary" onClick={() => triggerExit(false)}>
                    返回系统升级页
                  </Button>
                }
              />
              <Descriptions bordered size="small" column={2}>
                <Descriptions.Item label="任务 ID">{context.jobId}</Descriptions.Item>
                <Descriptions.Item label="最终状态">
                  <StatusTag value={currentStatus} map={UPGRADE_STATUS_META} />
                </Descriptions.Item>
                {versionRangeText && (
                  <Descriptions.Item label="目标版本">{versionRangeText}</Descriptions.Item>
                )}
                {job?.failure_code && (
                  <Descriptions.Item label="失败码">{job.failure_code}</Descriptions.Item>
                )}
                {job?.finished_at && (
                  <Descriptions.Item label="结束时间">{formatDateTime(job.finished_at)}</Descriptions.Item>
                )}
              </Descriptions>
              {(job?.node_executions?.length ?? 0) > 0 && (
                <Table<UpgradeNodeExecution>
                  size="small"
                  rowKey="id"
                  columns={nodeColumns}
                  dataSource={job?.node_executions ?? []}
                  pagination={false}
                />
              )}
            </Space>
          ) : fatalPollError ? (
            <Result
              status="error"
              title="无法继续获取升级任务状态"
              subTitle={fatalPollError}
              extra={
                <Button type="primary" onClick={() => triggerExit(false)}>
                  返回系统升级页
                </Button>
              }
            />
          ) : (
            <Space direction="vertical" size={24} style={{ width: '100%' }}>
              <div style={{ textAlign: 'center', paddingTop: 8 }}>
                <Spin indicator={<LoadingOutlined style={{ fontSize: 40, color: '#1677ff' }} spin />} />
                <Typography.Title level={3} style={{ marginTop: 16, marginBottom: 8 }}>
                  {isRollback ? '系统正在回滚，请稍候…' : '系统正在升级，请稍候…'}
                </Typography.Title>
                <Space size={8} wrap style={{ justifyContent: 'center' }}>
                  {versionRangeText && <Tag color="processing">{versionRangeText}</Tag>}
                  <Tag icon={<SyncOutlined spin />} color="blue">
                    {UPGRADE_STATUS_META[currentStatus]?.label ?? currentStatus}
                  </Tag>
                  <Tag color={isRolling ? 'purple' : 'default'}>
                    {isRolling ? 'HA 集群滚动升级（先备后主）' : '单节点升级'}
                  </Tag>
                  {context.hasLayerDelta && <Tag color="cyan">镜像层差量</Tag>}
                  <Tag>已用时 {formatElapsed(elapsedSec)}</Tag>
                </Space>
              </div>

              {reconnecting ? (
                <Alert
                  type="info"
                  showIcon
                  icon={<CloudSyncOutlined />}
                  message="服务正在重启切换中，请勿关闭页面"
                  description={`后端 API 与管理前端容器正在切换至新版本，出现短暂断连属于正常现象。页面将自动持续探测后端恢复与核验结果（已自动重连 ${reconnectAttempts} 次），仅在后端确认升级成功后返回正常页。`}
                />
              ) : isAwaitingHealthAfterSuccess ? (
                <Alert
                  type="info"
                  showIcon
                  icon={<SafetyCertificateOutlined />}
                  message="镜像切换已完成，正在等待后端健康自检通过"
                  description={
                    serverStatus?.health_detail
                      ? `后端正在等待核心依赖恢复就绪：${serverStatus.health_detail}`
                      : '后端正在复核数据库连接、缓存服务与迁移版本一致性，通过后将自动返回正常页。'
                  }
                />
              ) : (
                <Alert
                  type="info"
                  showIcon
                  message="升级期间请勿刷新或关闭页面"
                  description={stageHintText(currentStatus, isRolling, isRollback)}
                />
              )}

              {!isRollback && (
                <Steps
                  size="small"
                  current={currentStep}
                  items={[
                    { title: '升级前检查' },
                    { title: '全量备份' },
                    { title: '切换镜像与重启' },
                    { title: '迁移与后端自检' },
                    { title: '升级完成' },
                  ]}
                />
              )}

              <Descriptions bordered size="small" column={2}>
                <Descriptions.Item label="任务 ID">
                  <Typography.Text code>{context.jobId}</Typography.Text>
                </Descriptions.Item>
                <Descriptions.Item label="当前阶段">
                  <StatusTag value={currentStatus} map={UPGRADE_STATUS_META} />
                </Descriptions.Item>
                {context.components && context.components.length > 0 && (
                  <Descriptions.Item label="更新组件" span={2}>
                    <Space size={4} wrap>
                      {context.components.map((comp) => (
                        <Tag key={comp}>{comp}</Tag>
                      ))}
                    </Space>
                  </Descriptions.Item>
                )}
                <Descriptions.Item label="后端检测状态" span={2}>
                  {reconnecting
                    ? '等待服务重启完成并恢复连接…'
                    : isAwaitingHealthAfterSuccess
                      ? '等待核心服务健康检查通过…'
                      : '已连接后端，正在持续同步执行器与服务自检状态'}
                </Descriptions.Item>
              </Descriptions>

              {(job?.node_executions?.length ?? 0) > 0 && (
                <div>
                  <Typography.Text strong style={{ display: 'block', marginBottom: 8 }}>
                    集群逐节点升级进度
                  </Typography.Text>
                  <Table<UpgradeNodeExecution>
                    size="small"
                    rowKey="id"
                    columns={nodeColumns}
                    dataSource={job?.node_executions ?? []}
                    pagination={false}
                  />
                </div>
              )}
            </Space>
          )}
        </Card>
      </div>
    </div>
  )
}
