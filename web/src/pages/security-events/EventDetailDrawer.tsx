import { useState } from 'react'
import type { CSSProperties } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Descriptions,
  Drawer,
  Empty,
  Input,
  List,
  Space,
  Tag,
  Typography,
} from 'antd'
import { Link } from 'react-router-dom'
import { ApiError } from '../../api/client'
import { securityEventsApi } from '../../api/securityEvents'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import {
  ATTACK_TYPE_META,
  DISPOSITION_STATUS_META,
  EVENT_ACTION_META,
  EVENT_SEVERITY_META,
} from '../../utils/stage4'
import type { SecurityEventMatch } from '../../types'

const DISPOSITION_ACTION_META: Record<string, { color: string; label: string }> = {
  confirm_attack: { color: 'red', label: '确认攻击' },
  confirm_false_positive: { color: 'orange', label: '确认误报' },
  ignore: { color: 'default', label: '忽略' },
  resolve: { color: 'green', label: '标记已处置' },
  mark_analyzing: { color: 'processing', label: '标记分析中' },
  create_exception: { color: 'purple', label: '创建例外' },
}

/**
 * 规则匹配项渲染。
 * 安全要求：request_uri / matched_data 等攻击载荷一律作为 React 文本节点渲染
 * （React 默认转义），禁止使用 dangerouslySetInnerHTML。
 */
function MatchCard({ match }: { match: SecurityEventMatch }) {
  return (
    <div style={{ border: '1px solid #f0f0f0', borderRadius: 6, padding: 12, marginBottom: 8 }}>
      <Space wrap style={{ marginBottom: 8 }}>
        <Typography.Text code>{match.rule_id}</Typography.Text>
        <Typography.Text strong>{match.message || match.rule_name || '-'}</Typography.Text>
        <StatusTag value={match.severity} map={EVENT_SEVERITY_META} />
        <Tag>{`阶段 ${match.phase}`}</Tag>
      </Space>
      <div style={{ fontSize: 12, marginBottom: 4 }}>
        <Typography.Text type="secondary">匹配变量：</Typography.Text>
        <Typography.Text style={{ fontFamily: 'monospace' }}>
          {match.matched_variable || '-'}
        </Typography.Text>
      </div>
      <div style={{ fontSize: 12 }}>
        <Typography.Text type="secondary">匹配数据（已脱敏）：</Typography.Text>
        <pre
          style={{
            margin: '4px 0 0',
            background: '#f5f5f5',
            padding: 8,
            borderRadius: 4,
            fontSize: 12,
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-all',
          }}
        >
          {match.matched_data || '-'}
        </pre>
      </div>
      {(match.tags ?? []).length > 0 && (
        <Space wrap style={{ marginTop: 8 }}>
          {(match.tags ?? []).map((t) => (
            <Tag key={t}>{t}</Tag>
          ))}
        </Space>
      )}
    </div>
  )
}

const preStyle: CSSProperties = {
  margin: '4px 0 0',
  background: '#f5f5f5',
  padding: 8,
  borderRadius: 4,
  fontSize: 12,
  whiteSpace: 'pre-wrap',
  wordBreak: 'break-all',
  maxHeight: 240,
  overflow: 'auto',
}

/** 头体留痕渲染：全部按纯文本渲染（React 默认转义），防 XSS */
function PayloadSection({
  title,
  headers,
  body,
  truncated,
}: {
  title: string
  headers?: Record<string, string[]> | null
  body?: string
  truncated?: boolean
}) {
  const headerEntries = Object.entries(headers ?? {}).sort(([a], [b]) => a.localeCompare(b))
  return (
    <div style={{ marginBottom: 12 }}>
      <Typography.Text strong>{title}</Typography.Text>
      {truncated && (
        <Tag color="orange" style={{ marginLeft: 8 }}>
          体已截断（64KB）
        </Tag>
      )}
      {headerEntries.length === 0 && !body ? (
        <div>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            无记录
          </Typography.Text>
        </div>
      ) : (
        <>
          {headerEntries.length > 0 && (
            <pre style={preStyle}>
              {headerEntries.map(([k, vs]) => `${k}: ${(vs ?? []).join(', ')}`).join('\n')}
            </pre>
          )}
          {body && <pre style={preStyle}>{body}</pre>}
        </>
      )}
    </div>
  )
}

export default function EventDetailDrawer({
  eventId,
  onClose,
  onSelectEvent,
}: {
  eventId: string | null
  onClose: () => void
  onSelectEvent: (id: string) => void
}) {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canDispose = hasPermission(permissions, 'security_events.disposition')
  const canManageExceptions = hasPermission(permissions, 'exceptions.manage')
  const canAiAnalyze = hasPermission(permissions, 'ai.event_analysis.use')
  const canAiFp = hasPermission(permissions, 'ai.false_positive_analysis.use')
  const canNoiseReduction = hasPermission(permissions, 'ai.noise_reduction.use')
  const [noteText, setNoteText] = useState('')

  const detailQuery = useQuery({
    queryKey: ['security-event', eventId],
    queryFn: () => securityEventsApi.get(eventId as string),
    enabled: eventId !== null,
  })

  const invalidateDetail = () => {
    void queryClient.invalidateQueries({ queryKey: ['security-event', eventId] })
    void queryClient.invalidateQueries({ queryKey: ['security-events'] })
  }

  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const dispositionMutation = useMutation({
    mutationFn: ({
      action,
      note,
    }: {
      action: 'confirm-attack' | 'confirm-false-positive' | 'ignore' | 'resolve' | 'mark-analyzing'
      note?: string
    }) => {
      const id = eventId as string
      const body = note ? { note } : {}
      const map = {
        'confirm-attack': securityEventsApi.confirmAttack,
        'confirm-false-positive': securityEventsApi.confirmFalsePositive,
        ignore: securityEventsApi.ignore,
        resolve: securityEventsApi.resolve,
        'mark-analyzing': securityEventsApi.markAnalyzing,
      } as const
      return map[action](id, body)
    },
    onSuccess: () => {
      setNoteText('')
      message.success('处置完成')
      invalidateDetail()
    },
    onError,
  })

  const noteMutation = useMutation({
    mutationFn: (note: string) => securityEventsApi.addNote(eventId as string, note),
    onSuccess: () => {
      setNoteText('')
      message.success('备注已添加')
      invalidateDetail()
    },
    onError,
  })

  const createExceptionMutation = useMutation({
    mutationFn: () => securityEventsApi.createException(eventId as string),
    onSuccess: (data) => {
      modal.success({
        title: '例外草稿已创建',
        content: (
          <div>
            <p>{data.message}</p>
            <Link to="/exceptions" onClick={onClose}>
              前往例外策略页面查看
            </Link>
          </div>
        ),
      })
      invalidateDetail()
    },
    onError,
  })

  const runDisposition = (
    action: 'confirm-attack' | 'confirm-false-positive' | 'ignore' | 'resolve' | 'mark-analyzing',
    label: string,
  ) => {
    const note = noteText.trim()
    modal.confirm({
      title: `${label}确认`,
      content: `确定将该事件${label}吗？${note ? '（附带备注）' : ''}`,
      onOk: () => dispositionMutation.mutate({ action, note: note || undefined }),
    })
  }

  const detail = detailQuery.data
  const evt = detail?.event

  return (
    <Drawer
      title="安全事件详情"
      open={eventId !== null}
      onClose={onClose}
      width={720}
      destroyOnHidden={false}
    >
      {detailQuery.isLoading ? (
        <Typography.Text type="secondary">加载中...</Typography.Text>
      ) : detailQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="加载事件详情失败"
          description={detailQuery.error instanceof ApiError ? detailQuery.error.message : undefined}
        />
      ) : evt ? (
        <>
          {(canAiAnalyze || canAiFp || canNoiseReduction) && eventId && (
            <Space style={{ marginBottom: 16 }} wrap>
              {canAiAnalyze && (
                <Link to={`/ai/event-analysis?event_id=${encodeURIComponent(eventId)}`} onClick={onClose}>
                  <Button type="primary">AI 事件分析</Button>
                </Link>
              )}
              {canAiFp && (
                <Link
                  to={`/ai/event-analysis?event_id=${encodeURIComponent(eventId)}&tab=fp`}
                  onClick={onClose}
                >
                  <Button>AI 误报研判</Button>
                </Link>
              )}
              {canNoiseReduction && (
                <Link to="/ai/noise-reduction" onClick={onClose}>
                  <Button>查看降噪簇</Button>
                </Link>
              )}
            </Space>
          )}
          <Typography.Title level={5}>事件概览</Typography.Title>
          <Descriptions column={2} size="small" bordered style={{ marginBottom: 16 }}>
            <Descriptions.Item label="发生时间">{formatDateTime(evt.occurred_at)}</Descriptions.Item>
            <Descriptions.Item label="处置状态">
              <StatusTag value={evt.disposition_status} map={DISPOSITION_STATUS_META} />
            </Descriptions.Item>
            <Descriptions.Item label="攻击类型">
              <StatusTag value={evt.attack_type} map={ATTACK_TYPE_META} />
            </Descriptions.Item>
            <Descriptions.Item label="严重级别">
              <StatusTag value={evt.severity} map={EVENT_SEVERITY_META} />
            </Descriptions.Item>
            <Descriptions.Item label="动作">
              <StatusTag value={evt.action} map={EVENT_ACTION_META} />
            </Descriptions.Item>
            <Descriptions.Item label="异常评分">{evt.anomaly_score}</Descriptions.Item>
            <Descriptions.Item label="应用">
              {evt.application_name_snapshot || '-'}
            </Descriptions.Item>
            <Descriptions.Item label="域名">{evt.domain || '-'}</Descriptions.Item>
            <Descriptions.Item label="客户端 IP">{evt.client_ip || '-'}</Descriptions.Item>
            <Descriptions.Item label="网关节点">{evt.gateway_node_id || '-'}</Descriptions.Item>
            <Descriptions.Item label="响应状态码">{evt.response_status || '-'}</Descriptions.Item>
            <Descriptions.Item label="规则匹配数">{evt.rule_match_count}</Descriptions.Item>
          </Descriptions>

          <Typography.Title level={5}>请求信息</Typography.Title>
          <Descriptions column={2} size="small" bordered style={{ marginBottom: 16 }}>
            <Descriptions.Item label="请求 ID" span={2}>
              <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }} copyable>
                {evt.request_id}
              </Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="方法">{evt.request_method}</Descriptions.Item>
            <Descriptions.Item label="HTTP 版本">{evt.http_version || '-'}</Descriptions.Item>
            {/* 攻击载荷字段：纯文本渲染，React 自动转义，防 XSS */}
            <Descriptions.Item label="请求 URI" span={2}>
              <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12, wordBreak: 'break-all' }}>
                {evt.request_uri || '-'}
              </Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="查询摘要" span={2}>
              <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12, wordBreak: 'break-all' }}>
                {evt.query_summary || '-'}
              </Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="内容类型">{evt.content_type || '-'}</Descriptions.Item>
            <Descriptions.Item label="客户端端口">{evt.client_port || '-'}</Descriptions.Item>
            <Descriptions.Item label="用户代理" span={2}>
              {evt.user_agent_summary || '-'}
            </Descriptions.Item>
            <Descriptions.Item label="来源地址" span={2}>
              {evt.referer_summary || '-'}
            </Descriptions.Item>
          </Descriptions>

          <Typography.Title level={5}>请求/响应留痕</Typography.Title>
          <PayloadSection
            title="请求头"
            headers={evt.request_headers}
          />
          <PayloadSection
            title="请求体"
            body={evt.request_body}
            truncated={evt.request_body_truncated}
          />
          <PayloadSection
            title="响应头"
            headers={evt.response_headers}
          />
          <PayloadSection
            title="响应体"
            body={evt.response_body}
            truncated={evt.response_body_truncated}
          />

          <Typography.Title level={5}>规则匹配（{detail?.matches.length ?? 0}）</Typography.Title>
          {(detail?.matches ?? []).length === 0 ? (
            <Empty description="无规则匹配明细" style={{ marginBottom: 16 }} />
          ) : (
            <div style={{ marginBottom: 16, maxHeight: 360, overflow: 'auto' }}>
              {(detail?.matches ?? []).map((m, i) => (
                <MatchCard key={`${m.rule_id}-${i}`} match={m} />
              ))}
            </div>
          )}

          <Typography.Title level={5}>处置记录（{detail?.actions.length ?? 0}）</Typography.Title>
          {(detail?.actions ?? []).length === 0 ? (
            <Typography.Text type="secondary">暂无处置记录</Typography.Text>
          ) : (
            <List
              size="small"
              style={{ marginBottom: 16 }}
              dataSource={detail?.actions ?? []}
              renderItem={(a) => (
                <List.Item>
                  <Space direction="vertical" size={2} style={{ width: '100%' }}>
                    <Space>
                      <StatusTag
                        value={a.action_type}
                        map={DISPOSITION_ACTION_META}
                      />
                      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                        {a.operator_name} · {formatDateTime(a.created_at)}
                      </Typography.Text>
                    </Space>
                    {a.detail && (
                      <Typography.Text style={{ fontSize: 12 }}>{a.detail}</Typography.Text>
                    )}
                  </Space>
                </List.Item>
              )}
            />
          )}

          <Typography.Title level={5}>备注（{detail?.notes.length ?? 0}）</Typography.Title>
          {(detail?.notes ?? []).length === 0 ? (
            <Typography.Text type="secondary">暂无备注</Typography.Text>
          ) : (
            <List
              size="small"
              style={{ marginBottom: 16 }}
              dataSource={detail?.notes ?? []}
              renderItem={(n) => (
                <List.Item>
                  <Space direction="vertical" size={2} style={{ width: '100%' }}>
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                      {n.username} · {formatDateTime(n.created_at)}
                    </Typography.Text>
                    <Typography.Text style={{ fontSize: 12, whiteSpace: 'pre-wrap' }}>
                      {n.note}
                    </Typography.Text>
                  </Space>
                </List.Item>
              )}
            />
          )}

          <Typography.Title level={5}>相关事件（{detail?.related.length ?? 0}）</Typography.Title>
          {(detail?.related ?? []).length === 0 ? (
            <Typography.Text type="secondary">暂无相关事件</Typography.Text>
          ) : (
            <List
              size="small"
              style={{ marginBottom: 16 }}
              dataSource={detail?.related ?? []}
              renderItem={(r) => (
                <List.Item style={{ cursor: 'pointer' }} onClick={() => onSelectEvent(r.id)}>
                  <Space direction="vertical" size={2}>
                    <Space>
                      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                        {formatDateTime(r.occurred_at)}
                      </Typography.Text>
                      <StatusTag value={r.attack_type} map={ATTACK_TYPE_META} />
                      <StatusTag value={r.severity} map={EVENT_SEVERITY_META} />
                      <StatusTag value={r.action} map={EVENT_ACTION_META} />
                    </Space>
                    <Typography.Text style={{ fontSize: 12, fontFamily: 'monospace' }}>
                      {r.client_ip} {r.request_method} {r.request_uri}
                    </Typography.Text>
                  </Space>
                </List.Item>
              )}
            />
          )}

          {(canDispose || canManageExceptions) && (
            <>
              <Typography.Title level={5}>处置操作</Typography.Title>
              <Space direction="vertical" style={{ width: '100%' }}>
                <Input.TextArea
                  rows={2}
                  maxLength={1000}
                  placeholder="处置备注（可选，随处置动作一并记录；也可单独添加备注）"
                  value={noteText}
                  onChange={(e) => setNoteText(e.target.value)}
                />
                {canDispose && (
                  <Space wrap>
                    <Button
                      danger
                      loading={dispositionMutation.isPending}
                      onClick={() => runDisposition('confirm-attack', '确认为真实攻击')}
                    >
                      确认攻击
                    </Button>
                    <Button
                      loading={dispositionMutation.isPending}
                      onClick={() => runDisposition('confirm-false-positive', '确认为误报')}
                    >
                      确认误报
                    </Button>
                    <Button
                      loading={dispositionMutation.isPending}
                      onClick={() => runDisposition('ignore', '忽略')}
                    >
                      忽略
                    </Button>
                    <Button
                      type="primary"
                      loading={dispositionMutation.isPending}
                      onClick={() => runDisposition('resolve', '标记为已处置')}
                    >
                      标记已处置
                    </Button>
                    <Button
                      loading={dispositionMutation.isPending}
                      onClick={() => runDisposition('mark-analyzing', '标记为分析中')}
                    >
                      标记分析中
                    </Button>
                    <Button
                      loading={noteMutation.isPending}
                      onClick={() => {
                        const note = noteText.trim()
                        if (!note) {
                          message.warning('请先填写备注内容')
                          return
                        }
                        noteMutation.mutate(note)
                      }}
                    >
                      添加备注
                    </Button>
                  </Space>
                )}
                {canManageExceptions && (
                  <Button
                    loading={createExceptionMutation.isPending}
                    onClick={() =>
                      modal.confirm({
                        title: '从事件创建例外草稿',
                        content: '将基于该事件的域名、URI 与匹配规则生成例外草稿（停用前的草稿需到例外策略页面审核）。确定继续吗？',
                        onOk: () => createExceptionMutation.mutate(),
                      })
                    }
                  >
                    从事件创建例外草稿
                  </Button>
                )}
              </Space>
            </>
          )}
        </>
      ) : null}
    </Drawer>
  )
}
