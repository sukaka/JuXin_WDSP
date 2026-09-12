import { Card, Tabs, Typography } from 'antd'
import RunsTab from './RunsTab'
import SchedulesTab from './SchedulesTab'

/**
 * AI 定时运营（WDSP / 阶段8 W15）：内置五种运营任务的计划管理与执行记录浏览。
 * 权限点：api_ai.read（查询）、api_ai.execute（计划创建/修改/启停/立即执行）。
 * 任务只产出报告与建议文本，不执行任何业务变更。
 */
export default function ApiAIOpsPage() {
  return (
    <Card title="AI 定时运营">
      <Typography.Paragraph type="secondary">
        按 cron 计划定期生成 API 安全运营报告（资产变化摘要、Shadow API 运营、弱点整改跟进、
        高风险发现摘要、涉敏概览变化），支持手动立即执行；报告含结构化明细，处置动作均为人工流程。
      </Typography.Paragraph>
      <Tabs
        items={[
          { key: 'schedules', label: '计划', children: <SchedulesTab /> },
          { key: 'runs', label: '运行记录', children: <RunsTab /> },
        ]}
      />
    </Card>
  )
}
