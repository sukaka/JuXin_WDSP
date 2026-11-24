import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Badge,
  Button,
  Empty,
  Popover,
  Space,
  Spin,
  Tag,
  Typography,
} from 'antd'
import { BellOutlined, ReloadOutlined } from '@ant-design/icons'
import { ApiError } from '../api/client'
import { systemAlertsApi } from '../api/systemAlerts'
import StatusTag from './StatusTag'
import { useAuthStore } from '../stores/auth'
import { formatDateTime } from '../utils/format'
import { hasAnyPermission } from '../utils/permission'
import { ALERT_SEVERITY_META, ALERT_STATUS_META, COMPONENT_NAME_META } from '../utils/stage6'
import type { SystemAlertItem } from '../types'

const HEADER_ALERT_LIMIT = 8
const HEADER_ALERT_STALE_MS = 30_000
const HEADER_ALERT_POLL_MS = 60_000

export interface HeaderAlertsPopoverProps {
  /** 授权锁定或退出登录期间暂停请求，避免登出清缓存后回灌 */
  disabled?: boolean
}

/**
 * 顶部导航栏站内告警铃铛：
 * - 展示未处理（status=OPEN）告警数量角标；确认/解决/忽略后角标立即消退；
 * - 点击展开告警预览面板（trigger="click"，不套 Tooltip 避免遮挡），支持快速确认与直达系统告警页。
 */
export default function HeaderAlertsPopover({ disabled = false }: HeaderAlertsPopoverProps) {
  const { message } = AntdApp.useApp()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canAcknowledge = hasAnyPermission(permissions, [
    'system_alerts.acknowledge',
    'system_alerts.acknowledge_security',
  ])
  const [open, setOpen] = useState(false)

  const openAlertsQuery = useQuery({
    queryKey: ['system-alerts', 'header-open'],
    queryFn: () =>
      systemAlertsApi.list({
        status: 'OPEN',
        page: 1,
        page_size: HEADER_ALERT_LIMIT,
      }),
    enabled: !disabled,
    staleTime: HEADER_ALERT_STALE_MS,
    refetchInterval: HEADER_ALERT_POLL_MS,
    retry: false,
  })

  const ackMutation = useMutation({
    mutationFn: (id: string) => systemAlertsApi.acknowledge(id),
    onSuccess: () => {
      message?.success('告警已确认')
      void queryClient.invalidateQueries({ queryKey: ['system-alerts'] })
    },
    onError: (e: unknown) => {
      message?.error(e instanceof ApiError ? e.message : '确认告警失败')
      if (e instanceof ApiError && e.status === 409) {
        void queryClient.invalidateQueries({ queryKey: ['system-alerts'] })
      }
    },
  })

  const items: SystemAlertItem[] = openAlertsQuery.data?.items ?? []
  const total = openAlertsQuery.data?.total ?? 0

  const handleOpenChange = (nextOpen: boolean) => {
    setOpen(nextOpen)
    if (nextOpen && !disabled) {
      void openAlertsQuery.refetch()
    }
  }

  const goToAlerts = () => {
    setOpen(false)
    navigate('/system-alerts')
  }

  const popoverTitle = (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
      <Space size={6} align="center">
        <span>站内告警</span>
        {total > 0 ? (
          <Tag color="red" style={{ marginInlineEnd: 0 }}>
            {total} 条未处理
          </Tag>
        ) : (
          <Tag color="green" style={{ marginInlineEnd: 0 }}>
            无未处理
          </Tag>
        )}
      </Space>
      <Button
        type="text"
        size="small"
        icon={<ReloadOutlined />}
        aria-label="刷新站内告警"
        loading={openAlertsQuery.isFetching}
        onClick={() => void openAlertsQuery.refetch()}
      />
    </div>
  )

  const popoverContent = (
    <div style={{ width: 360, maxWidth: 'calc(100vw - 32px)' }}>
      {openAlertsQuery.isLoading ? (
        <div style={{ padding: '24px 0', textAlign: 'center' }}>
          <Spin size="small" />
        </div>
      ) : openAlertsQuery.isError ? (
        <Alert
          type="error"
          showIcon
          title="加载站内告警失败"
          description={
            openAlertsQuery.error instanceof ApiError ? openAlertsQuery.error.message : undefined
          }
          style={{ marginBottom: 8 }}
        />
      ) : items.length === 0 ? (
        <Empty
          image={Empty.PRESENTED_IMAGE_SIMPLE}
          description="当前无未处理告警"
          style={{ margin: '16px 0' }}
        />
      ) : (
        <div style={{ maxHeight: 340, overflowY: 'auto' }}>
          {items.map((item, idx) => (
            <div
              key={item.id}
              style={{
                display: 'flex',
                alignItems: 'flex-start',
                justifyContent: 'space-between',
                gap: 8,
                padding: '10px 6px',
                borderBottom: idx < items.length - 1 ? '1px solid #f0f0f0' : undefined,
              }}
            >
              <div
                onClick={goToAlerts}
                role="link"
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault()
                    goToAlerts()
                  }
                }}
                style={{ minWidth: 0, flex: 1, cursor: 'pointer' }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                  <StatusTag value={item.severity} map={ALERT_SEVERITY_META} />
                  <Typography.Text
                    strong
                    ellipsis={{ tooltip: false }}
                    title={item.title}
                    style={{ maxWidth: 210 }}
                  >
                    {item.title}
                  </Typography.Text>
                </div>
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: 8,
                    fontSize: 12,
                    color: 'rgba(0, 0, 0, 0.45)',
                  }}
                >
                  <span>
                    {COMPONENT_NAME_META[item.component] ?? item.component}
                    {' · '}
                    {ALERT_STATUS_META[item.status]?.label ?? item.status}
                    {item.occurrence_count > 1 ? ` · ×${item.occurrence_count}` : ''}
                  </span>
                  <span style={{ flexShrink: 0 }}>{formatDateTime(item.last_seen_at)}</span>
                </div>
              </div>
              {canAcknowledge && item.status === 'OPEN' && (
                <Button
                  type="link"
                  size="small"
                  style={{ padding: 0, flexShrink: 0 }}
                  loading={ackMutation.isPending && ackMutation.variables === item.id}
                  onClick={() => ackMutation.mutate(item.id)}
                >
                  确认
                </Button>
              )}
            </div>
          ))}
        </div>
      )}
      <div
        style={{
          borderTop: '1px solid #f0f0f0',
          marginTop: 8,
          paddingTop: 8,
          textAlign: 'center',
        }}
      >
        <Button type="link" size="small" block onClick={goToAlerts}>
          查看全部系统告警{total > items.length ? `（共 ${total} 条未处理）` : ''}
        </Button>
      </div>
    </div>
  )

  return (
    <Popover
      open={open}
      onOpenChange={handleOpenChange}
      trigger="click"
      placement="bottomRight"
      title={popoverTitle}
      content={popoverContent}
    >
      <Badge count={total} size="small" overflowCount={99} offset={[-4, 6]}>
        <Button
          type="text"
          icon={<BellOutlined style={{ fontSize: 16 }} />}
          aria-label={total > 0 ? `站内告警（${total} 条未处理）` : '站内告警'}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            height: 36,
            width: 36,
          }}
        />
      </Badge>
    </Popover>
  )
}
