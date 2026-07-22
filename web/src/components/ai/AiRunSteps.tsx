import { Collapse, Timeline, Typography } from 'antd'
import { LoadingOutlined } from '@ant-design/icons'
import type { AiSseEvent } from '../../api/ai'
import { AI_STEP_META, visibleSteps } from '../../utils/ai'

/**
 * AI 执行过程区：将 plan/agent_start/agent_done/tool/error/compressed 等步骤事件
 * 以可折叠 Timeline 展示（不展示模型私有思维链，仅结构化步骤摘要）。
 */
export default function AiRunSteps({
  events,
  running = false,
  defaultOpen = false,
}: {
  events: AiSseEvent[]
  running?: boolean
  defaultOpen?: boolean
}) {
  const steps = visibleSteps(events)
  if (steps.length === 0 && !running) return null

  const lastType = steps.length > 0 ? steps[steps.length - 1].type : ''
  // 进行中的最后一步用旋转图标，避免额外再挂一条空白「正在分析」
  const activeRunningTypes = new Set(['agent_start', 'composing', 'tool'])
  const items = steps.map((e, i) => {
    const meta = AI_STEP_META[e.type] ?? { color: 'gray', label: e.type }
    const isActiveTail = running && i === steps.length - 1 && activeRunningTypes.has(e.type)
    return {
      key: String(i),
      color: meta.color === 'processing' ? 'blue' : meta.color,
      dot: isActiveTail ? <LoadingOutlined /> : undefined,
      children: (
        <Typography.Text type={e.type === 'error' ? 'danger' : undefined}>
          {meta.label}：{e.text || '-'}
        </Typography.Text>
      ),
    }
  })
  if (running && (steps.length === 0 || !activeRunningTypes.has(lastType))) {
    const waitingLabel =
      lastType === 'agent_done' || lastType === 'plan'
        ? '正在生成回答...'
        : '正在分析...'
    items.push({
      key: 'running',
      color: 'blue',
      dot: <LoadingOutlined />,
      children: <Typography.Text type="secondary">{waitingLabel}</Typography.Text>,
    })
  }

  return (
    <Collapse
      ghost
      size="small"
      // 运行中强制展开；结束后 remount 为用户可自由折叠的非受控状态
      key={running ? 'running' : 'idle'}
      defaultActiveKey={running || defaultOpen ? ['steps'] : []}
      items={[
        {
          key: 'steps',
          label: (
            <Typography.Text type="secondary" style={{ fontSize: 13 }}>
              执行过程（{steps.length} 步）
            </Typography.Text>
          ),
          children: <Timeline style={{ marginTop: 8 }} items={items} />,
        },
      ]}
    />
  )
}
