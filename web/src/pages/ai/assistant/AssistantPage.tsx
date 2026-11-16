import { useEffect, useMemo, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Button,
  Card,
  Checkbox,
  Dropdown,
  Empty,
  Input,
  List,
  Modal,
  Space,
  Spin,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import {
  ApiOutlined,
  DeleteOutlined,
  DislikeOutlined,
  DownloadOutlined,
  EditOutlined,
  InboxOutlined,
  LikeOutlined,
  MoreOutlined,
  PlusOutlined,
  SendOutlined,
  StopOutlined,
  UserOutlined,
} from '@ant-design/icons'
import { ApiError } from '../../../api/client'
import { aiChatApi, renameAiSession } from '../../../api/ai'
import type { AiDonePayload, AiMessage, AiSession, AiSseEvent } from '../../../api/ai'
import AiRunSteps from '../../../components/ai/AiRunSteps'
import QueryErrorAlert from '../../../components/QueryErrorAlert'
import { useAuthStore } from '../../../stores/auth'
import { hasPermission } from '../../../utils/permission'

/** 本会话内一次流式问答的过程态（仅保留步骤事件快照，回答文本在 done 后从消息接口刷新） */
interface StreamState {
  /** 触发本轮的用户消息（发送场景本地展示；重试/继续场景为空） */
  pendingUserText: string | null
  events: AiSseEvent[]
  errorText: string | null
  /** done 事件的 finish_reason（cancelled 表示用户停止） */
  finishReason: string | null
}

/** 安全助手：多轮对话 + SSE 流式过程展示 + 停止/重试/继续 + 消息反馈 */
export default function AssistantPage() {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canDelete = hasPermission(permissions, 'ai.sessions.delete_own')

  const [searchParams] = useSearchParams()
  // 深链 ?session_id=xxx：定位已有会话（任务记录/审计等入口跳转）
  const deepLinkSessionId = searchParams.get('session_id')?.trim() || null

  const [sessionId, setSessionId] = useState<string | null>(deepLinkSessionId)
  const [keyword, setKeyword] = useState('')
  const [includeArchived, setIncludeArchived] = useState(false)
  const [input, setInput] = useState('')
  const [stream, setStream] = useState<StreamState | null>(null)
  const [feedbackGiven, setFeedbackGiven] = useState<Record<string, 1 | -1>>({})
  /** 最近一轮 done 结果（流收起后保留截断/自动续写提示；新一轮发送或切换会话时清除） */
  const [doneInfo, setDoneInfo] = useState<{ finishReason: string; autoContinues: number } | null>(null)

  const abortRef = useRef<AbortController | null>(null)
  const scrollRef = useRef<HTMLDivElement | null>(null)
  // 深链会话不在列表中时已提示过的会话 ID（避免重复弹错）
  const deepLinkNotifiedRef = useRef<string | null>(null)
  // 组件卸载时中断进行中的流式请求
  useEffect(() => () => abortRef.current?.abort(), [])

  const sessionsQuery = useQuery({
    queryKey: ['ai-sessions', includeArchived],
    queryFn: () => aiChatApi.listSessions({ page: 1, page_size: 50, include_archived: includeArchived }),
  })

  // 深链会话定位失败时显式报错，不静默：会话可能已删除，或因归档被默认列表过滤
  useEffect(() => {
    if (!deepLinkSessionId || deepLinkNotifiedRef.current === deepLinkSessionId) return
    if (!sessionsQuery.isSuccess) return
    const found = (sessionsQuery.data?.items ?? []).some((s) => s.id === deepLinkSessionId)
    if (!found) {
      deepLinkNotifiedRef.current = deepLinkSessionId
      message.error('未找到链接指定的会话：可能已删除，或已归档（可勾选「显示已归档」后重试）')
    }
  }, [deepLinkSessionId, sessionsQuery.isSuccess, sessionsQuery.data, message])

  const messagesQuery = useQuery({
    queryKey: ['ai-messages', sessionId],
    queryFn: () => aiChatApi.listMessages(sessionId as string),
    enabled: sessionId !== null,
  })

  const sessions = useMemo(() => {
    const items = sessionsQuery.data?.items ?? []
    const kw = keyword.trim().toLowerCase()
    return kw ? items.filter((s) => s.title.toLowerCase().includes(kw)) : items
  }, [sessionsQuery.data, keyword])

  const currentSession: AiSession | null = useMemo(
    () => (sessionsQuery.data?.items ?? []).find((s) => s.id === sessionId) ?? null,
    [sessionsQuery.data, sessionId],
  )

  const messages = useMemo(() => messagesQuery.data ?? [], [messagesQuery.data])

  // 新消息/新步骤时滚动到底部
  useEffect(() => {
    const el = scrollRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [messages, stream])

  /** 启动一条 SSE 流（发送/重试/继续共用） */
  const startStream = (
    sid: string,
    runner: (onEvent: (e: AiSseEvent) => void, signal: AbortSignal) => Promise<void>,
    pendingUserText: string | null,
  ) => {
    abortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller
    setStream({ pendingUserText, events: [], errorText: null, finishReason: null })
    setDoneInfo(null)
    runner(
      (e) => {
        if (e.type === 'done') {
          const payload = e.payload as AiDonePayload | undefined
          const fr = payload?.finish_reason ?? null
          const ac = payload?.auto_continues ?? 0
          // 截断（length）或发生过自动续写时保留提示；cancelled/正常结束不提示
          setDoneInfo(fr && (fr === 'length' || ac > 0) ? { finishReason: fr, autoContinues: ac } : null)
        }
        setStream((prev) =>
          prev
            ? {
                ...prev,
                events: [...prev.events, e],
                errorText: e.type === 'error' ? e.text || '分析执行失败' : prev.errorText,
                finishReason:
                  e.type === 'done'
                    ? ((e.payload as AiDonePayload | undefined)?.finish_reason ?? null)
                    : prev.finishReason,
              }
            : prev,
        )
      },
      controller.signal,
    )
      .catch((e: unknown) => {
        if (e instanceof DOMException && e.name === 'AbortError') return
        const text = e instanceof ApiError ? e.message : '流式请求异常'
        setStream((prev) => (prev ? { ...prev, errorText: text } : prev))
      })
      .finally(async () => {
        abortRef.current = null
        // 先刷新消息列表再收起过程区，避免用户消息/回答在流结束瞬间短暂消失
        try {
          await Promise.all([
            queryClient.refetchQueries({ queryKey: ['ai-messages', sid] }),
            queryClient.invalidateQueries({ queryKey: ['ai-sessions'] }),
          ])
        } finally {
          setStream(null)
        }
      })
  }

  const handleSend = async () => {
    const content = input.trim()
    if (!content || stream) return
    let sid = sessionId
    if (!sid) {
      // 未选择会话时自动新建
      try {
        const sess = await aiChatApi.createSession()
        sid = sess.id
        setSessionId(sid)
        void queryClient.invalidateQueries({ queryKey: ['ai-sessions'] })
      } catch (e) {
        message.error(e instanceof ApiError ? e.message : '创建会话失败')
        return
      }
    }
    if (currentSession && currentSession.status !== 'ACTIVE') {
      message.warning('会话已归档，无法继续对话')
      return
    }
    setInput('')
    startStream(sid, (onEvent, signal) => aiChatApi.streamMessage(sid as string, content, onEvent, signal), content)
  }

  const handleStop = async () => {
    if (!sessionId) return
    try {
      await aiChatApi.stop(sessionId)
    } catch (e) {
      // 409（无运行中任务）等情况本地直接中断即可
      if (!(e instanceof ApiError && e.status === 409)) {
        message.warning(e instanceof ApiError ? e.message : '停止失败')
      }
    } finally {
      abortRef.current?.abort()
    }
  }

  const handleRetry = () => {
    if (!sessionId || stream) return
    startStream(sessionId, (onEvent, signal) => aiChatApi.streamRetry(sessionId, onEvent, signal), null)
  }

  const handleContinue = () => {
    if (!sessionId || stream) return
    startStream(sessionId, (onEvent, signal) => aiChatApi.streamContinue(sessionId, onEvent, signal), null)
  }

  const handleFeedback = async (msg: AiMessage, rating: 1 | -1) => {
    try {
      await aiChatApi.feedback(msg.id, { rating })
      setFeedbackGiven((prev) => ({ ...prev, [msg.id]: rating }))
      message.success('反馈已记录')
    } catch (e) {
      message.error(e instanceof ApiError ? e.message : '反馈失败')
    }
  }

  const handleNewSession = async () => {
    try {
      const sess = await aiChatApi.createSession()
      void queryClient.invalidateQueries({ queryKey: ['ai-sessions'] })
      setSessionId(sess.id)
      setDoneInfo(null)
    } catch (e) {
      message.error(e instanceof ApiError ? e.message : '创建会话失败')
    }
  }

  const handleRename = (sess: AiSession) => {
    let title = sess.title
    Modal.confirm({
      title: '重命名会话',
      content: (
        <Input
          defaultValue={sess.title}
          maxLength={200}
          onChange={(e) => {
            title = e.target.value
          }}
        />
      ),
      okText: '保存',
      cancelText: '取消',
      onOk: async () => {
        try {
          await renameAiSession(sess.id, title.trim())
          void queryClient.invalidateQueries({ queryKey: ['ai-sessions'] })
          message.success('会话已重命名')
        } catch (e) {
          message.error(e instanceof ApiError ? e.message : '重命名失败')
          throw e
        }
      },
    })
  }

  const handleArchive = (sess: AiSession) => {
    Modal.confirm({
      title: '归档会话',
      content: '归档后无法继续对话，可在「显示已归档」中查看历史消息。确认归档？',
      okText: '归档',
      cancelText: '取消',
      onOk: async () => {
        try {
          await aiChatApi.archiveSession(sess.id)
          void queryClient.invalidateQueries({ queryKey: ['ai-sessions'] })
          message.success('会话已归档')
        } catch (e) {
          message.error(e instanceof ApiError ? e.message : '归档失败')
          throw e
        }
      },
    })
  }

  const handleDelete = (sess: AiSession) => {
    Modal.confirm({
      title: '删除会话',
      content: '删除后会话与全部消息不可恢复，确认删除？',
      okText: '删除',
      okButtonProps: { danger: true },
      cancelText: '取消',
      onOk: async () => {
        try {
          await aiChatApi.deleteSession(sess.id)
          if (sessionId === sess.id) setSessionId(null)
          void queryClient.invalidateQueries({ queryKey: ['ai-sessions'] })
          message.success('会话已删除')
        } catch (e) {
          message.error(e instanceof ApiError ? e.message : '删除失败')
          throw e
        }
      },
    })
  }

  const handleExport = () => {
    if (!currentSession || messages.length === 0) return
    const lines = messages.map(
      (m) => `[${m.created_at}] ${m.role === 'user' ? '我' : 'AI助手'}：\n${m.content}\n`,
    )
    const blob = new Blob([`会话：${currentSession.title}\n\n${lines.join('\n')}`], {
      type: 'text/plain;charset=utf-8',
    })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `ai-session-${currentSession.id.slice(0, 8)}.txt`
    a.click()
    URL.revokeObjectURL(url)
  }

  const lastMessage = messages[messages.length - 1]
  const canRetryOrContinue = !stream && lastMessage?.role === 'assistant' && currentSession?.status === 'ACTIVE'

  return (
    <Card title="安全助手" styles={{ body: { padding: 0 } }}>
      <div style={{ display: 'flex', height: 'calc(100vh - 200px)', minHeight: 480 }}>
        {/* 左侧会话列表 */}
        <div
          style={{
            width: 280,
            borderRight: '1px solid #f0f0f0',
            display: 'flex',
            flexDirection: 'column',
          }}
        >
          <div style={{ padding: 12, borderBottom: '1px solid #f0f0f0' }}>
            <Space direction="vertical" size={8} style={{ display: 'flex' }}>
              <Button type="primary" icon={<PlusOutlined />} block onClick={handleNewSession}>
                新建会话
              </Button>
              <Input.Search
                placeholder="搜索会话"
                allowClear
                size="small"
                onSearch={(v) => setKeyword(v)}
                onChange={(e) => setKeyword(e.target.value)}
              />
              <Checkbox
                checked={includeArchived}
                onChange={(e) => setIncludeArchived(e.target.checked)}
              >
                显示已归档
              </Checkbox>
            </Space>
          </div>
          <div style={{ flex: 1, overflow: 'auto' }}>
            {sessionsQuery.isLoading ? (
              <div style={{ textAlign: 'center', padding: 32 }}>
                <Spin />
              </div>
            ) : sessionsQuery.isError ? (
              <div style={{ padding: 12 }}>
                <QueryErrorAlert error={sessionsQuery.error} message="加载会话失败" />
              </div>
            ) : sessions.length === 0 ? (
              <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无会话" style={{ marginTop: 48 }} />
            ) : (
              <List
                dataSource={sessions}
                renderItem={(sess) => (
                  <List.Item
                    onClick={() => {
                      if (stream) return
                      setSessionId(sess.id)
                      setDoneInfo(null)
                    }}
                    style={{
                      cursor: 'pointer',
                      padding: '10px 12px',
                      background: sess.id === sessionId ? '#e6f4ff' : undefined,
                    }}
                  >
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <Typography.Text ellipsis style={{ display: 'block', fontSize: 13 }}>
                        {sess.title || '未命名会话'}
                      </Typography.Text>
                      {sess.status !== 'ACTIVE' && <Tag style={{ marginTop: 4 }}>已归档</Tag>}
                    </div>
                    <Dropdown
                      menu={{
                        items: [
                          { key: 'rename', icon: <EditOutlined />, label: '重命名' },
                          { key: 'archive', icon: <InboxOutlined />, label: '归档', disabled: sess.status !== 'ACTIVE' },
                          ...(canDelete
                            ? [{ key: 'delete', icon: <DeleteOutlined />, label: '删除', danger: true }]
                            : []),
                        ],
                        onClick: ({ key, domEvent }) => {
                          domEvent.stopPropagation()
                          if (key === 'rename') handleRename(sess)
                          else if (key === 'archive') handleArchive(sess)
                          else if (key === 'delete') handleDelete(sess)
                        },
                      }}
                      trigger={['click']}
                    >
                      <Button
                        type="text"
                        size="small"
                        icon={<MoreOutlined />}
                        onClick={(e) => e.stopPropagation()}
                      />
                    </Dropdown>
                  </List.Item>
                )}
              />
            )}
          </div>
        </div>

        {/* 右侧对话区 */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
          <div
            style={{
              padding: '10px 16px',
              borderBottom: '1px solid #f0f0f0',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
            }}
          >
            <Space>
              <Typography.Text strong>{currentSession?.title || '新会话'}</Typography.Text>
              {currentSession && (
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  上下文 Token：{currentSession.context_token_count}
                </Typography.Text>
              )}
            </Space>
            <Button
              size="small"
              icon={<DownloadOutlined />}
              disabled={!currentSession || messages.length === 0}
              onClick={handleExport}
            >
              导出
            </Button>
          </div>

          <div ref={scrollRef} style={{ flex: 1, overflow: 'auto', padding: 16 }}>
            {messagesQuery.isLoading && sessionId ? (
              <div style={{ textAlign: 'center', padding: 48 }}>
                <Spin />
              </div>
            ) : messagesQuery.isError && sessionId ? (
              <div style={{ maxWidth: 560, margin: '48px auto 0' }}>
                <QueryErrorAlert
                  error={messagesQuery.error}
                  message="加载会话消息失败，会话可能不存在或已删除"
                />
              </div>
            ) : messages.length === 0 && !stream ? (
              <Empty
                description={
                  <>
                    <div>向 安全助手提问，例如：</div>
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                      「今天为什么攻击增多？」「942100 为什么一直命中？」「哪些 IP 建议封禁？」
                    </Typography.Text>
                    <br />
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                      「发现了哪些影子
                      API？」「模型基线与实际调用有哪些差异？」「哪些接口参数偏离基线？」「哪些接口存在
                      BOLA/BFLA 越权风险？」
                    </Typography.Text>
                  </>
                }
                style={{ marginTop: 64 }}
              />
            ) : (
              <Space direction="vertical" size={16} style={{ display: 'flex' }}>
                {messages.map((m) =>
                  m.role === 'user' ? (
                    <div key={m.id} style={{ display: 'flex', justifyContent: 'flex-end' }}>
                      <div
                        style={{
                          maxWidth: '75%',
                          background: '#1677ff',
                          color: '#fff',
                          borderRadius: 8,
                          padding: '8px 12px',
                          whiteSpace: 'pre-wrap',
                          wordBreak: 'break-word',
                        }}
                      >
                        <UserOutlined style={{ marginRight: 6 }} />
                        {m.content}
                      </div>
                    </div>
                  ) : (
                    <div key={m.id} style={{ display: 'flex' }}>
                      <div
                        style={{
                          maxWidth: '85%',
                          background: '#f5f5f5',
                          borderRadius: 8,
                          padding: '8px 12px',
                        }}
                      >
                        <Space size={6} style={{ marginBottom: 4 }}>
                          <ApiOutlined />
                          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                            安全助手
                          </Typography.Text>
                        </Space>
                        <Typography.Paragraph
                          copyable={{ text: m.content }}
                          style={{ whiteSpace: 'pre-wrap', marginBottom: 4, wordBreak: 'break-word' }}
                        >
                          {m.content}
                        </Typography.Paragraph>
                        <Space size={4}>
                          <Tooltip title="有用">
                            <Button
                              type="text"
                              size="small"
                              icon={<LikeOutlined />}
                              disabled={feedbackGiven[m.id] !== undefined}
                              style={feedbackGiven[m.id] === 1 ? { color: '#1677ff' } : undefined}
                              onClick={() => void handleFeedback(m, 1)}
                            />
                          </Tooltip>
                          <Tooltip title="无用">
                            <Button
                              type="text"
                              size="small"
                              icon={<DislikeOutlined />}
                              disabled={feedbackGiven[m.id] !== undefined}
                              style={feedbackGiven[m.id] === -1 ? { color: '#ff4d4f' } : undefined}
                              onClick={() => void handleFeedback(m, -1)}
                            />
                          </Tooltip>
                        </Space>
                      </div>
                    </div>
                  ),
                )}

                {/* 流式进行中的过程区 */}
                {stream && (
                  <>
                    {stream.pendingUserText && (
                      <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                        <div
                          style={{
                            maxWidth: '75%',
                            background: '#1677ff',
                            color: '#fff',
                            borderRadius: 8,
                            padding: '8px 12px',
                            whiteSpace: 'pre-wrap',
                            wordBreak: 'break-word',
                          }}
                        >
                          <UserOutlined style={{ marginRight: 6 }} />
                          {stream.pendingUserText}
                        </div>
                      </div>
                    )}
                    <div style={{ display: 'flex' }}>
                      <div
                        style={{
                          maxWidth: '85%',
                          minWidth: 320,
                          background: '#f5f5f5',
                          borderRadius: 8,
                          padding: '8px 12px',
                        }}
                      >
                        <Space size={6} style={{ marginBottom: 4 }}>
                          <ApiOutlined spin />
                          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                            {stream.events.some((e) => e.type === 'composing')
                              ? '安全助手正在生成回答...'
                              : stream.events.some((e) => e.type === 'agent_start' || e.type === 'agent_done')
                                ? '安全助手正在执行分析...'
                                : '安全助手正在分析...'}
                          </Typography.Text>
                        </Space>
                        <AiRunSteps events={stream.events} running={!stream.errorText} defaultOpen />
                        {stream.errorText && (
                          <Typography.Text type="danger">{stream.errorText}</Typography.Text>
                        )}
                      </div>
                    </div>
                  </>
                )}
              </Space>
            )}
          </div>

          {/* 输入区 */}
          <div style={{ padding: 12, borderTop: '1px solid #f0f0f0' }}>
            <Space.Compact style={{ width: '100%' }}>
              <Input.TextArea
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onPressEnter={(e) => {
                  if (!e.shiftKey) {
                    e.preventDefault()
                    void handleSend()
                  }
                }}
                placeholder={
                  currentSession && currentSession.status !== 'ACTIVE'
                    ? '会话已归档，无法继续对话'
                    : '输入问题，Enter 发送，Shift+Enter 换行（≤4000 字）'
                }
                autoSize={{ minRows: 1, maxRows: 6 }}
                maxLength={4000}
                disabled={!!stream || (currentSession !== null && currentSession.status !== 'ACTIVE')}
              />
              {stream ? (
                <Button danger icon={<StopOutlined />} onClick={() => void handleStop()}>
                  停止
                </Button>
              ) : (
                <Button
                  type="primary"
                  icon={<SendOutlined />}
                  disabled={!input.trim() || (currentSession !== null && currentSession.status !== 'ACTIVE')}
                  onClick={() => void handleSend()}
                >
                  发送
                </Button>
              )}
            </Space.Compact>
            <Space style={{ marginTop: 8 }}>
              <Button size="small" disabled={!canRetryOrContinue} onClick={handleRetry}>
                重试
              </Button>
              <Button size="small" disabled={!canRetryOrContinue} onClick={handleContinue}>
                继续输出
              </Button>
              {doneInfo && (
                <Typography.Text
                  type={doneInfo.finishReason === 'length' ? 'warning' : 'secondary'}
                  style={{ fontSize: 12 }}
                >
                  {doneInfo.finishReason === 'length'
                    ? `输出达到长度上限${doneInfo.autoContinues > 0 ? `，已自动续写 ${doneInfo.autoContinues} 次仍未完` : ''}，可点击「继续输出」`
                    : `输出较长，已自动续写 ${doneInfo.autoContinues} 次`}
                </Typography.Text>
              )}
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                回答仅供辅助决策，涉及生产变更请走既有审核发布流程
              </Typography.Text>
            </Space>
          </div>
        </div>
      </div>
    </Card>
  )
}
