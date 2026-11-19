import { useCallback, useContext, useEffect, useRef, useState } from 'react'
import { Button, InputNumber, Popover, Space, Switch, Typography } from 'antd'
import { ClockCircleOutlined, ReloadOutlined } from '@ant-design/icons'
import { QueryClientContext } from '@tanstack/react-query'

const MIN_REFRESH_INTERVAL_SECONDS = 3
const MAX_REFRESH_INTERVAL_SECONDS = 3600
const DEFAULT_REFRESH_INTERVAL_SECONDS = 10
const PRESET_SECONDS = [5, 10, 30, 60] as const

function clampIntervalSeconds(raw: unknown, fallback: number): number {
  const num = typeof raw === 'number' ? raw : Number(raw)
  if (!Number.isFinite(num)) return fallback
  const rounded = Math.round(num)
  if (rounded < MIN_REFRESH_INTERVAL_SECONDS) return MIN_REFRESH_INTERVAL_SECONDS
  if (rounded > MAX_REFRESH_INTERVAL_SECONDS) return MAX_REFRESH_INTERVAL_SECONDS
  return rounded
}

function loadSavedInterval(storageKey: string | undefined, fallback: number): number {
  if (!storageKey) return fallback
  try {
    const raw = localStorage.getItem('smart-table-refresh:' + storageKey)
    if (!raw) return fallback
    const parsed = JSON.parse(raw) as { intervalSeconds?: unknown }
    return clampIntervalSeconds(parsed?.intervalSeconds, fallback)
  } catch {
    return fallback
  }
}

function saveInterval(storageKey: string | undefined, intervalSeconds: number) {
  if (!storageKey) return
  try {
    localStorage.setItem(
      'smart-table-refresh:' + storageKey,
      JSON.stringify({ intervalSeconds }),
    )
  } catch {
    // 隐私模式或存储受限时退化为会话内生效
  }
}

export interface TableRefreshControlProps {
  /** 自定义刷新回调；未传时默认刷新当前页全部活跃查询（排除全局 ai-status） */
  onRefresh?: () => void | Promise<unknown>
  /** 仅刷新指定 queryKey 前缀（未传 onRefresh 时生效） */
  refreshQueryKeys?: readonly (readonly unknown[])[]
  /** 用于在 localStorage 中记住用户自定义的自动刷新秒数 */
  storageKey?: string
  /** 默认自动刷新间隔秒数（默认 10 秒，范围 3~3600 秒） */
  defaultIntervalSeconds?: number
  /** 外部 loading 状态 */
  loading?: boolean
}

/**
 * 列表通用刷新与自定义秒数自动刷新控件：
 * - 手动「刷新」按钮；
 * - 旁边提供「自动刷新」弹窗：支持开关切换、自定义秒数（3~3600 秒）及快捷间隔；
 * - 具备防重入锁、后台标签页暂停、卸载自动清理定时器和可选 localStorage 间隔记忆。
 */
export default function TableRefreshControl({
  onRefresh,
  refreshQueryKeys,
  storageKey,
  defaultIntervalSeconds = DEFAULT_REFRESH_INTERVAL_SECONDS,
  loading = false,
}: TableRefreshControlProps) {
  const queryClient = useContext(QueryClientContext)
  const initialSeconds = clampIntervalSeconds(
    defaultIntervalSeconds,
    DEFAULT_REFRESH_INTERVAL_SECONDS,
  )

  const [autoEnabled, setAutoEnabled] = useState(false)
  const [intervalSeconds, setIntervalSeconds] = useState<number>(() =>
    loadSavedInterval(storageKey, initialSeconds),
  )
  const [draftSeconds, setDraftSeconds] = useState<number | null>(() =>
    loadSavedInterval(storageKey, initialSeconds),
  )
  const [refreshing, setRefreshing] = useState(false)

  const inFlightRef = useRef(false)
  const mountedRef = useRef(true)

  useEffect(() => {
    mountedRef.current = true
    return () => {
      mountedRef.current = false
    }
  }, [])

  const triggerRefresh = useCallback(async () => {
    if (inFlightRef.current) return
    inFlightRef.current = true
    if (mountedRef.current) setRefreshing(true)
    try {
      if (onRefresh) {
        await onRefresh()
      } else if (queryClient) {
        if (refreshQueryKeys && refreshQueryKeys.length > 0) {
          await Promise.all(
            refreshQueryKeys.map((queryKey) =>
              queryClient.refetchQueries({ queryKey, type: 'active' }),
            ),
          )
        } else {
          await queryClient.refetchQueries({
            type: 'active',
            predicate: (query) => query.queryKey[0] !== 'ai-status',
          })
        }
      }
    } catch {
      // 查询错误由页面自身的 QueryErrorAlert / 业务提示展示，避免未捕获拒绝
    } finally {
      inFlightRef.current = false
      if (mountedRef.current) setRefreshing(false)
    }
  }, [onRefresh, queryClient, refreshQueryKeys])

  const triggerRefreshRef = useRef(triggerRefresh)
  useEffect(() => {
    triggerRefreshRef.current = triggerRefresh
  }, [triggerRefresh])

  useEffect(() => {
    if (!autoEnabled) return
    const timer = window.setInterval(() => {
      if (typeof document !== 'undefined' && document.visibilityState === 'hidden') {
        return
      }
      void triggerRefreshRef.current()
    }, intervalSeconds * 1000)
    return () => {
      window.clearInterval(timer)
    }
  }, [autoEnabled, intervalSeconds])

  const applySeconds = (sec: number) => {
    const clamped = clampIntervalSeconds(sec, intervalSeconds)
    setDraftSeconds(clamped)
    setIntervalSeconds(clamped)
    saveInterval(storageKey, clamped)
  }

  const handleIntervalChange = (value: number | null) => {
    setDraftSeconds(value)
    if (value === null || !Number.isFinite(value)) return
    if (value >= MIN_REFRESH_INTERVAL_SECONDS && value <= MAX_REFRESH_INTERVAL_SECONDS) {
      const clamped = clampIntervalSeconds(value, intervalSeconds)
      setIntervalSeconds(clamped)
      saveInterval(storageKey, clamped)
    }
  }

  const handleIntervalBlur = () => {
    applySeconds(draftSeconds ?? intervalSeconds)
  }

  const popoverContent = (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10, width: 236 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Typography.Text>启用自动刷新</Typography.Text>
        <Switch
          size="small"
          checked={autoEnabled}
          onChange={setAutoEnabled}
          aria-label="自动刷新开关"
        />
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
        <Typography.Text>刷新间隔</Typography.Text>
        <InputNumber
          size="small"
          min={MIN_REFRESH_INTERVAL_SECONDS}
          max={MAX_REFRESH_INTERVAL_SECONDS}
          precision={0}
          step={1}
          value={draftSeconds}
          onChange={handleIntervalChange}
          onBlur={handleIntervalBlur}
          suffix="秒"
          style={{ width: 108 }}
          aria-label="自动刷新间隔（秒）"
        />
      </div>
      <Space size={4} wrap>
        {PRESET_SECONDS.map((sec) => (
          <Button
            key={sec}
            size="small"
            type={intervalSeconds === sec ? 'primary' : 'default'}
            ghost={intervalSeconds === sec}
            onClick={() => applySeconds(sec)}
          >
            {sec}秒
          </Button>
        ))}
      </Space>
      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
        支持自定义 {MIN_REFRESH_INTERVAL_SECONDS}–{MAX_REFRESH_INTERVAL_SECONDS} 秒，页面切到后台时自动暂停。
      </Typography.Text>
    </div>
  )

  return (
    <Space size={6} wrap align="center" data-testid="table-refresh-control">
      <Button
        size="small"
        icon={<ReloadOutlined />}
        loading={refreshing || loading}
        onClick={() => void triggerRefresh()}
        aria-label="刷新列表"
      >
        刷新
      </Button>
      <Popover
        content={popoverContent}
        trigger="click"
        placement="bottomRight"
        title="自动刷新设置"
      >
        <Button
          size="small"
          type={autoEnabled ? 'primary' : 'default'}
          ghost={autoEnabled}
          icon={<ClockCircleOutlined />}
          aria-label="自动刷新"
        >
          {autoEnabled ? `自动刷新 ${intervalSeconds}秒` : '自动刷新'}
        </Button>
      </Popover>
    </Space>
  )
}
