import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Select, Space, Typography } from 'antd'
import { apiAIOpsApi } from '../../api/apiAIOps'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import { taskTypeLabel } from './meta'
import RunsPanel from './RunsPanel'

/**
 * 运行记录 Tab：先选计划再浏览其执行记录（执行记录按计划维度归集，
 * 后端无跨计划列表接口）；行展开查看摘要与结构化报告。
 */
export default function RunsTab() {
  const [scheduleId, setScheduleId] = useState<string | undefined>()

  const schedulesQuery = useQuery({
    queryKey: ['api-ai-ops-schedules', 'options'],
    queryFn: () => apiAIOpsApi.listSchedules({ page: 1, page_size: 100 }),
  })
  const options = (schedulesQuery.data?.items ?? []).map((s) => ({
    value: s.id,
    label: `${s.name}（${taskTypeLabel(s.task_type)}）`,
  }))

  return (
    <>
      <QueryErrorAlert error={schedulesQuery.error} />
      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          placeholder="选择计划查看执行记录"
          showSearch
          optionFilterProp="label"
          style={{ width: 360 }}
          value={scheduleId}
          options={options}
          loading={schedulesQuery.isLoading}
          onChange={(v) => setScheduleId(v)}
        />
      </Space>
      {scheduleId ? (
        <RunsPanel scheduleId={scheduleId} />
      ) : (
        <Alert type="info" showIcon message="请先选择计划" description="执行记录按计划维度归集，选择计划后可查看其全部运行记录（含手动立即执行）。" />
      )}
      <Typography.Paragraph type="secondary" style={{ marginTop: 12, marginBottom: 0 }}>
        执行记录包含定时触发与手动立即执行；行展开可查看摘要与结构化执行报告。
      </Typography.Paragraph>
    </>
  )
}
