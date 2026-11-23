import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Card, Space, Tag, Typography } from 'antd'
import SmartTable from '../../components/SmartTable'
import type { ColumnsType } from 'antd/es/table'
import { reportArchivesApi } from '../../api/reports'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import StatusTag from '../../components/StatusTag'
import { formatBytes, formatDateTime } from '../../utils/format'
import { truncateHash } from '../../utils/stage3'
import { REPORT_FORMAT_META, REPORT_TYPE_META } from '../../utils/stage6'
import type { ReportArchiveItem } from '../../types'

/** 报告归档：只读归档记录列表（引用报告编号） */
export default function ReportArchivesPage() {
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [detailRecord, setDetailRecord] = useState<ReportArchiveItem | null>(null)

  const listQuery = useQuery({
    queryKey: ['report-archives', page, pageSize],
    queryFn: () => reportArchivesApi.list({ page, page_size: pageSize }),
  })

  const columns: ColumnsType<ReportArchiveItem> = [
    {
      title: '报告编号',
      dataIndex: 'report_no',
      width: 200,
      ellipsis: true,
      render: (v: string, record) => v || record.report_job_id.slice(0, 8),
    },
    {
      title: '类型',
      dataIndex: 'report_type',
      width: 90,
      render: (v: string) => (v ? <StatusTag value={v} map={REPORT_TYPE_META} /> : <Tag>-</Tag>),
    },
    {
      title: '格式',
      dataIndex: 'file_format',
      width: 80,
      render: (v: string) => (v ? <StatusTag value={v} map={REPORT_FORMAT_META} /> : <Tag>-</Tag>),
    },
    {
      title: '文件大小',
      dataIndex: 'file_size',
      width: 100,
      render: (v: number | null | undefined) => formatBytes(v),
    },
    {
      title: '文件哈希',
      dataIndex: 'file_hash',
      width: 150,
      render: (v: string) =>
        v ? <Typography.Text code>{truncateHash(v)}</Typography.Text> : '-',
    },
    { title: '归档人', dataIndex: 'archived_by', width: 110, render: (v: string) => v || '-' },
    {
      title: '归档时间',
      dataIndex: 'archived_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    { title: '备注', dataIndex: 'note', ellipsis: true, render: (v: string) => v || '-' },
  ]

  return (
    <Card title="报告归档">
      <Space direction="vertical" size={16} style={{ display: 'flex' }}>
        <Typography.Text type="secondary">
          归档记录为只读，保存报告编号、文件哈希等存档信息，用于合规追溯。
        </Typography.Text>
        {listQuery.isError ? (
          <QueryErrorAlert error={listQuery.error} message="加载报告归档失败" />
        ) : (
          <SmartTable<ReportArchiveItem>
            storageKey="report-archives"
            rowKey="archive_id"
            onRow={(record) => ({
              onDoubleClick: () => setDetailRecord(record),
              style: { cursor: 'pointer' },
            })}
            loading={listQuery.isLoading}
            columns={columns}
            dataSource={listQuery.data?.items}
            scroll={{ x: 1200 }}
            pagination={{
              current: page,
              pageSize,
              total: listQuery.data?.total ?? 0,
              showSizeChanger: true,
              showTotal: (t) => `共 ${t} 条`,
              onChange: (p, ps) => {
                setPage(p)
                setPageSize(ps)
              },
            }}
          />
        )}
      </Space>
      <RecordDetailDrawer
        open={detailRecord !== null}
        title="归档记录详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </Card>
  )
}
