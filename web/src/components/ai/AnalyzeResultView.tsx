import { Card, Descriptions, Divider, Space, Tag, Typography } from 'antd'
import StatusTag from '../StatusTag'
import AiRunSteps from './AiRunSteps'
import EvidenceList from './EvidenceList'
import type { AiAnalyzeResult } from '../../api/ai'
import { AI_AGENT_NAMES, AI_RISK_META, AI_TASK_TYPE_META } from '../../utils/ai'

/**
 * 一次性 AI 分析结果展示：计划摘要 + 执行过程（可折叠）+ 主回答 + 证据引用。
 * 事件分析/误报/攻击画像/攻击链/策略建议/What-If/根因/报告总结各页共用。
 */
export default function AnalyzeResultView({ result }: { result: AiAnalyzeResult }) {
  return (
    <Card size="small" title="分析结果" style={{ marginTop: 16 }}>
      <Space direction="vertical" size={12} style={{ display: 'flex' }}>
        {result.plan && (
          <Descriptions size="small" column={3} bordered>
            <Descriptions.Item label="任务类型">
              <StatusTag value={result.plan.task_type} map={AI_TASK_TYPE_META} />
            </Descriptions.Item>
            <Descriptions.Item label="风险等级">
              <StatusTag value={result.plan.risk_level} map={AI_RISK_META} />
            </Descriptions.Item>
            <Descriptions.Item label="任务 ID">
              <Typography.Text copyable={{ text: result.task_id }} style={{ fontSize: 12 }}>
                {result.task_id.slice(0, 8)}...
              </Typography.Text>
            </Descriptions.Item>
            {result.plan.summary && (
              <Descriptions.Item label="计划摘要" span={3}>
                {result.plan.summary}
              </Descriptions.Item>
            )}
            {result.plan.agents && result.plan.agents.length > 0 && (
              <Descriptions.Item label="参与智能体" span={3}>
                {result.plan.agents.map((a) => (
                  <Tag key={a}>{AI_AGENT_NAMES[a] ?? a}</Tag>
                ))}
              </Descriptions.Item>
            )}
          </Descriptions>
        )}
        <AiRunSteps events={result.steps ?? []} defaultOpen={false} />
        <Divider style={{ margin: '4px 0' }} />
        <Typography.Paragraph
          style={{ whiteSpace: 'pre-wrap', marginBottom: 0, fontSize: 14, lineHeight: 1.8 }}
        >
          {result.answer}
        </Typography.Paragraph>
        <Divider style={{ margin: '4px 0' }} />
        <EvidenceList items={result.evidence} />
      </Space>
    </Card>
  )
}
