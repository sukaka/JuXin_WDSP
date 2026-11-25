import type { ReactNode } from 'react'
import { Alert, Card, Radio, Space, Tag, Tooltip, Typography } from 'antd'
import { InfoCircleOutlined, QuestionCircleOutlined } from '@ant-design/icons'
import StatusTag from '../../../components/StatusTag'

export interface SectionHeaderProps {
  title: ReactNode
  badge?: ReactNode
  description?: ReactNode
  tooltip?: ReactNode
  extra?: ReactNode
  spaced?: boolean
}

/** 页签内统一分区标题头（左侧色条 + 标题 + 可选计数/帮助提示 + 右侧操作槽） */
export function SectionHeader({
  title,
  badge,
  description,
  tooltip,
  extra,
  spaced = false,
}: SectionHeaderProps) {
  return (
    <div
      className={
        spaced
          ? 'jz-detail-section-header jz-detail-section-header--spaced'
          : 'jz-detail-section-header'
      }
    >
      <div className="jz-detail-section-title-group">
        <div className="jz-detail-section-title-row">
          <span className="jz-detail-section-accent" aria-hidden="true" />
          <span className="jz-detail-section-title">{title}</span>
          {badge}
          {tooltip && (
            <Tooltip title={tooltip}>
              <QuestionCircleOutlined
                style={{ color: '#94a3b8', fontSize: 13, cursor: 'help' }}
              />
            </Tooltip>
          )}
        </div>
        {description && <p className="jz-detail-section-desc">{description}</p>}
      </div>
      {extra && <div>{extra}</div>}
    </div>
  )
}

export interface ModeCardOption<T extends string> {
  value: T
  label: string
  description: string
  badge?: string
  badgeColor?: string
  tone?: 'neutral' | 'info' | 'success' | 'warning'
}

interface ModeCardGroupProps<T extends string> {
  value?: T
  onChange?: (value: T) => void
  disabled?: boolean
  options: ModeCardOption<T>[]
  columns?: 2 | 3
}

/**
 * 3 栏语义卡片单选组：内部保留原生 AntD Radio.Group 与 .ant-radio-wrapper 结构，
 * 确保键盘无障碍与现有 E2E 选择器完全兼容。
 */
export function ModeCardGroup<T extends string>({
  value,
  onChange,
  disabled,
  options,
  columns = 3,
}: ModeCardGroupProps<T>) {
  return (
    <Radio.Group
      value={value}
      disabled={disabled}
      onChange={(e) => onChange?.(e.target.value as T)}
      className={
        columns === 2
          ? 'jz-detail-mode-group jz-detail-mode-group--2col'
          : 'jz-detail-mode-group'
      }
    >
      {options.map((opt) => (
        <Radio
          key={opt.value}
          value={opt.value}
          className={`jz-detail-mode-card jz-detail-mode-card--${opt.tone ?? 'info'}`}
        >
          <div className="jz-detail-mode-card-body">
            <div className="jz-detail-mode-card-top">
              <span className="jz-detail-mode-card-label">{opt.label}</span>
              {opt.badge && (
                <Tag
                  color={opt.badgeColor}
                  style={{ marginInlineEnd: 0, fontSize: 11 }}
                >
                  {opt.badge}
                </Tag>
              )}
            </div>
            <span className="jz-detail-mode-card-desc">{opt.description}</span>
          </div>
        </Radio>
      ))}
    </Radio.Group>
  )
}

/** 轻量单行内联提示条（用于收敛背景说明，减少大块蓝色 Alert 视觉压迫） */
export function InlineNote({
  children,
  tooltip,
  compact = false,
}: {
  children: ReactNode
  tooltip?: ReactNode
  compact?: boolean
}) {
  return (
    <div
      className={
        compact
          ? 'jz-detail-inline-note jz-detail-inline-note--compact'
          : 'jz-detail-inline-note'
      }
    >
      <InfoCircleOutlined />
      <div style={{ flex: 1, minWidth: 0 }}>{children}</div>
      {tooltip && (
        <Tooltip title={tooltip}>
          <QuestionCircleOutlined
            style={{ color: '#64748b', fontSize: 13, cursor: 'help' }}
          />
        </Tooltip>
      )}
    </div>
  )
}

export interface PreflightCheckItem {
  name: string
  status: string
  message: string
}

export interface PreflightConflictItem {
  type: string
  status: string
  message: string
  ref?: string
}

interface PreflightResultCardProps {
  publishable: boolean
  summaryDescription: string
  checks: PreflightCheckItem[]
  checkNameLabels: Record<string, string>
  checkStatusMeta: Record<string, { color: string; label: string }>
  conflicts?: PreflightConflictItem[]
  conflictTypeLabels?: Record<string, string>
  footerNote?: ReactNode
  extra?: ReactNode
}

/**
 * JWT / Bot 共用的「发布预检结果」卡片：
 * 顶部聚合通过/警告/未通过计数，条目保留 .ant-list-item 类名以兼容 E2E 定位。
 */
export function PreflightResultCard({
  publishable,
  summaryDescription,
  checks,
  checkNameLabels,
  checkStatusMeta,
  conflicts = [],
  conflictTypeLabels = {},
  footerNote,
  extra,
}: PreflightResultCardProps) {
  const counts = checks.reduce(
    (acc, item) => {
      if (item.status === 'PASS') acc.pass += 1
      else if (item.status === 'FAIL') acc.fail += 1
      else if (item.status === 'WARN') acc.warn += 1
      else acc.skip += 1
      return acc
    },
    { pass: 0, fail: 0, warn: 0, skip: 0 },
  )

  return (
    <Card
      className="jz-detail-card"
      title="发布预检结果"
      extra={
        <Space size={6} wrap>
          {counts.pass > 0 && <Tag color="success">通过 {counts.pass}</Tag>}
          {counts.warn > 0 && <Tag color="warning">警告 {counts.warn}</Tag>}
          {counts.fail > 0 && <Tag color="error">未通过 {counts.fail}</Tag>}
          {counts.skip > 0 && <Tag>跳过 {counts.skip}</Tag>}
          {extra}
        </Space>
      }
    >
      <Alert
        type={publishable ? 'success' : 'error'}
        showIcon
        style={{ marginBottom: 16 }}
        title={
          publishable
            ? '预检通过，可经配置发布通道发布'
            : '存在未通过项，发布链路将以同口径拒绝'
        }
        description={summaryDescription}
      />

      <div className="jz-detail-preflight-list">
        {checks.map((c, idx) => (
          <div
            key={`${c.name}-${idx}`}
            className={`ant-list-item jz-detail-preflight-item jz-detail-preflight-item--${c.status}`}
          >
            <Space orientation="vertical" size={3} style={{ width: '100%' }}>
              <Space size={8} wrap>
                <StatusTag value={c.status} map={checkStatusMeta} />
                <Typography.Text strong style={{ fontSize: 13 }}>
                  {checkNameLabels[c.name] ?? c.name}
                </Typography.Text>
              </Space>
              <Typography.Text
                type="secondary"
                style={{
                  fontSize: 12,
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all',
                }}
              >
                {c.message}
              </Typography.Text>
            </Space>
          </div>
        ))}
      </div>

      {conflicts.length > 0 && (
        <div style={{ marginTop: 16 }}>
          <Typography.Text
            strong
            style={{ display: 'block', marginBottom: 8, fontSize: 13 }}
          >
            保留路由冲突（未通过阻断发布，警告仅提示）
          </Typography.Text>
          <div className="jz-detail-preflight-list">
            {conflicts.map((c, idx) => (
              <div
                key={`${c.type}-${c.ref ?? idx}-${idx}`}
                className={`ant-list-item jz-detail-preflight-item jz-detail-preflight-item--${c.status}`}
              >
                <Space orientation="vertical" size={3} style={{ width: '100%' }}>
                  <Space size={6} wrap>
                    <StatusTag value={c.status} map={checkStatusMeta} />
                    <Tag>{conflictTypeLabels[c.type] ?? c.type}</Tag>
                    {c.ref && (
                      <Typography.Text code style={{ fontSize: 12 }}>
                        {c.ref}
                      </Typography.Text>
                    )}
                  </Space>
                  <Typography.Text
                    type="secondary"
                    style={{
                      fontSize: 12,
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-all',
                    }}
                  >
                    {c.message}
                  </Typography.Text>
                </Space>
              </div>
            ))}
          </div>
        </div>
      )}

      {footerNote && (
        <Typography.Paragraph
          type="secondary"
          style={{ fontSize: 12, marginTop: 12, marginBottom: 0 }}
        >
          {footerNote}
        </Typography.Paragraph>
      )}
    </Card>
  )
}
