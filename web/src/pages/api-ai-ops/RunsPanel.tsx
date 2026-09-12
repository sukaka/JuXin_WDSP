import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { apiAIOpsApi, type ApiAIRun } from '../../api/apiAIOps'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { formatDateTime } from '../../utils/format'
import { AI_RUN_STATUS_META, runDuration } from './meta'
import ReportView from './ReportView'

/**
 * 执行记录面板（计划详情抽屉与「运行记录」Tab 共用）：
 * 给定 scheduleId 分页拉取 /schedules/{id}/runs，行展开显示摘要与 report_json 关键字段。
 */
export default function RunsPanel({ scheduleId }: { scheduleId: string }) {
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [detailRecord, setDetailRecord] = useState<ApiAIRun | null>(null)

  const runsQuery = useQuery({
    queryKey: ['api-ai-ops-runs', scheduleId, page, pageSize],
    queryFn: () => apiAIOpsApi.listRuns(scheduleId, { page, page_size: pageSize }),
  })

  const columns: ColumnsType<ApiAIRun> = [
    {
      title: '状态',
      dataIndex: 'status',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={AI_RUN_STATUS_META} />,
    },
    {
      title: '开始时间',
      dataIndex: 'started_at',
      width: 165,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '耗时',
      key: 'duration',
      width: 100,
      render: (_, record) => runDuration(record),
    },
    {
      title: '摘要',
      dataIndex: 'summary',
      ellipsis: true,
      render: (v: string) => v || '-',
    },
  ]

  return (
    <>
      <QueryErrorAlert error={runsQuery.error} />
      <SmartTable<ApiAIRun>
        storageKey={`api-ai-ops-runs-${scheduleId}`}
        rowKey="id"
        loading={runsQuery.isLoading}
        columns={columns}
        dataSource={runsQuery.data?.items ?? []}
        onRow={(record) => ({
          onDoubleClick: () => setDetailRecord(record),
          style: { cursor: 'pointer' },
        })}
        expandable={{
          expandedRowRender: (record) => (
            <div style={{ padding: '4px 0' }}>
              <Typography.Paragraph style={{ marginBottom: 12, whiteSpace: 'pre-wrap' }}>
                {record.summary || '无摘要'}
              </Typography.Paragraph>
              <ReportView report={record.report} />
            </div>
          ),
          rowExpandable: () => true,
        }}
        pagination={{
          current: page,
          pageSize,
          total: runsQuery.data?.total ?? 0,
          showSizeChanger: true,
          showTotal: (t) => `共 ${t} 条`,
          onChange: (p, ps) => {
            setPage(p)
            setPageSize(ps)
          },
        }}
      />
      <RecordDetailDrawer
        open={detailRecord !== null}
        title="执行记录详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </>
  )
}
