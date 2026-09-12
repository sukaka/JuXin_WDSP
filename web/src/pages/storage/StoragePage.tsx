import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Card, Col, Progress, Row, Space, Statistic } from 'antd'
import SmartTable from '../../components/SmartTable'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import type { EChartOption } from '../../components/EChart'
import { systemHealthApi } from '../../api/systemHealth'
import EChart from '../../components/EChart'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import { formatBytes } from '../../utils/format'

function percent(used?: number, total?: number): number {
  if (!used || !total || total <= 0) return 0
  return Math.min(100, Math.round((used / total) * 100))
}

/** 存储容量：PG/分区/Valkey/磁盘/报告/备份占用 */
export default function StoragePage() {
  const storageQuery = useQuery({
    queryKey: ['system-health', 'storage'],
    queryFn: () => systemHealthApi.storage(),
    refetchInterval: 60000,
  })

  const [detailRecord, setDetailRecord] = useState<{ name: string; size_bytes: number } | null>(null)

  const s = storageQuery.data
  const partitions = useMemo(
    () => [...(s?.partitions ?? [])].sort((a, b) => b.size_bytes - a.size_bytes).slice(0, 10),
    [s],
  )

  const partitionOption = useMemo<EChartOption>(
    () => ({
      grid: { left: 8, right: 24, top: 8, bottom: 8, containLabel: true },
      tooltip: {
        formatter: (params: unknown) => {
          const p = params as { name: string; value: number }
          return `${p.name}: ${formatBytes(p.value)}`
        },
      },
      xAxis: { type: 'value', axisLabel: { formatter: (v: number) => formatBytes(v) } },
      yAxis: { type: 'category', data: partitions.map((p) => p.name).reverse() },
      series: [
        { type: 'bar', data: partitions.map((p) => p.size_bytes).reverse(), itemStyle: { color: '#1677ff' }, barMaxWidth: 18 },
      ],
    }),
    [partitions],
  )

  const diskUsed = (s?.disk_total_bytes ?? 0) - (s?.disk_free_bytes ?? 0)
  const valkeyPct = percent(s?.valkey_used_memory_bytes, s?.valkey_max_memory_bytes)
  const diskPct = percent(diskUsed, s?.disk_total_bytes)

  return (
    <Card title="存储容量">
      {storageQuery.isError ? (
        <QueryErrorAlert error={storageQuery.error} message="加载存储容量失败" />
      ) : (
        <Space direction="vertical" size={16} style={{ display: 'flex' }}>
          <Row gutter={[16, 16]}>
            <Col xs={12} md={8} lg={4}>
              <Card size="small">
                <Statistic title="数据库容量" value={formatBytes(s?.postgres_size_bytes)} loading={storageQuery.isLoading} />
              </Card>
            </Col>
            <Col xs={12} md={8} lg={4}>
              <Card size="small">
                <Statistic title="数据库连接数" value={s?.db_connections ?? 0} loading={storageQuery.isLoading} />
              </Card>
            </Col>
            <Col xs={12} md={8} lg={4}>
              <Card size="small">
                <Statistic
                  title="报告文件占用"
                  value={formatBytes(s?.reports_size_bytes)}
                  suffix={s?.reports_file_count != null ? `(${s.reports_file_count} 个)` : undefined}
                  loading={storageQuery.isLoading}
                />
              </Card>
            </Col>
            <Col xs={12} md={8} lg={4}>
              <Card size="small">
                <Statistic
                  title="备份文件占用"
                  value={formatBytes(s?.backups_size_bytes)}
                  suffix={s?.backups_file_count != null ? `(${s.backups_file_count} 个)` : undefined}
                  loading={storageQuery.isLoading}
                />
              </Card>
            </Col>
            <Col xs={12} md={8} lg={4}>
              <Card size="small" title="缓存内存">
                <Progress
                  percent={valkeyPct}
                  size="small"
                  status={valkeyPct >= 90 ? 'exception' : 'normal'}
                  format={() => `${formatBytes(s?.valkey_used_memory_bytes)} / ${formatBytes(s?.valkey_max_memory_bytes)}`}
                />
              </Card>
            </Col>
            <Col xs={12} md={8} lg={4}>
              <Card size="small" title="磁盘空间">
                <Progress
                  percent={diskPct}
                  size="small"
                  status={diskPct >= 90 ? 'exception' : 'normal'}
                  format={() => `剩余 ${formatBytes(s?.disk_free_bytes)}`}
                />
              </Card>
            </Col>
          </Row>

          <Row gutter={16}>
            <Col xs={24} lg={12}>
              <Card size="small" title="事件分区 TOP10">
                {partitions.length > 0 ? (
                  <EChart
                    option={partitionOption}
                    height={Math.max(240, partitions.length * 32)}
                    ariaLabel="事件分区占用 TOP10"
                  />
                ) : (
                  <Space style={{ padding: 24 }}>暂无分区数据</Space>
                )}
              </Card>
            </Col>
            <Col xs={24} lg={12}>
              <Card size="small" title="分区明细">
                <SmartTable
                  storageKey="storage"
                  size="small"
                  rowKey="name"
                  pagination={false}
                  loading={storageQuery.isLoading}
                  dataSource={partitions}
                  onRow={(record) => ({
                    onDoubleClick: () => setDetailRecord(record),
                    style: { cursor: 'pointer' },
                  })}
                  columns={[
                    { title: '分区', dataIndex: 'name', ellipsis: true },
                    {
                      title: '大小',
                      dataIndex: 'size_bytes',
                      width: 120,
                      render: (v: number) => formatBytes(v),
                    },
                  ]}
                />
              </Card>
            </Col>
          </Row>
        </Space>
      )}
      <RecordDetailDrawer
        open={detailRecord !== null}
        title="分区详情"
        record={detailRecord}
        onClose={() => setDetailRecord(null)}
      />
    </Card>
  )
}
