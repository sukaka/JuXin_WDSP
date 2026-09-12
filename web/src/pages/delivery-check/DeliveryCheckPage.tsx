import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { App as AntdApp, Alert, Button, Card, Col, Row, Space, Statistic, Tag, Typography } from 'antd'
import SmartTable from '../../components/SmartTable'
import type { ColumnsType } from 'antd/es/table'
import { DownloadOutlined, PlayCircleOutlined } from '@ant-design/icons'
import { ApiError } from '../../api/client'
import { deliveryChecksApi } from '../../api/deliveryChecks'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import { CHECK_RESULT_META, isTerminalDeliveryStatus } from '../../utils/stage6'
import type { DeliveryCheckItem, DeliveryCheckResultItem } from '../../types'

/** 交付检查：运行检查 → 总结果卡片 + 逐项表格（关键项标记）+ 导出 */
export default function DeliveryCheckPage() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canRun = hasPermission(permissions, 'delivery_checks.run')

  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [detailRecord, setDetailRecord] = useState<DeliveryCheckResultItem | null>(null)

  const listQuery = useQuery({
    queryKey: ['delivery-checks'],
    queryFn: () => deliveryChecksApi.list({ page: 1, page_size: 10 }),
    refetchInterval: (query) =>
      (query.state.data?.items ?? []).some((c) => !isTerminalDeliveryStatus(c.status)) ? 3000 : false,
  })

  const detailQuery = useQuery({
    queryKey: ['delivery-checks', 'detail', selectedId],
    queryFn: () => deliveryChecksApi.get(selectedId!),
    enabled: selectedId !== null,
    refetchInterval: (query) => {
      const check = query.state.data?.check
      return check && !isTerminalDeliveryStatus(check.status) ? 3000 : false
    },
  })

  const runMutation = useMutation({
    mutationFn: () => deliveryChecksApi.run(),
    onSuccess: (check) => {
      message.success('交付检查已启动')
      setSelectedId(check.id)
      void queryClient.invalidateQueries({ queryKey: ['delivery-checks'] })
    },
    onError: (e) => message.error(e instanceof ApiError ? e.message : '启动检查失败'),
  })

  const confirmRun = () => {
    modal.confirm({
      title: '运行检查确认',
      content: '将执行完整交付检查（组件状态、安全配置、备份恢复、合规材料等），期间会调用多项系统 API。确定运行吗？',
      onOk: () => runMutation.mutate(),
    })
  }

  const detail = detailQuery.data
  const check = detail?.check
  const results = detail?.results ?? []

  const historyColumns: ColumnsType<DeliveryCheckItem> = [
    { title: '任务ID', dataIndex: 'id', width: 110, render: (v: string) => v.slice(0, 8) },
    {
      title: '总结果',
      dataIndex: 'overall_result',
      width: 100,
      render: (v: string) => (v ? <StatusTag value={v} map={CHECK_RESULT_META} /> : <Tag>进行中</Tag>),
    },
    { title: '通过', dataIndex: 'pass_count', width: 70 },
    { title: '警告', dataIndex: 'warning_count', width: 70 },
    { title: '失败', dataIndex: 'fail_count', width: 70 },
    {
      title: '执行时间',
      dataIndex: 'created_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 150,
      render: (_, record) => (
        <Space size={0}>
          <Button type="link" size="small" onClick={() => setSelectedId(record.id)}>
            查看
          </Button>
          <Button
            type="link"
            size="small"
            icon={<DownloadOutlined />}
            onClick={() => window.open(deliveryChecksApi.exportUrl(record.id), '_blank')}
          >
            导出
          </Button>
        </Space>
      ),
    },
  ]

  const resultColumns: ColumnsType<DeliveryCheckResultItem> = [
    { title: '检查项', dataIndex: 'item', width: 220, ellipsis: true },
    { title: '分类', dataIndex: 'category', width: 120, render: (v: string) => v || '-' },
    {
      title: '结果',
      dataIndex: 'result',
      width: 110,
      render: (v: string, record) => (
        <Space size={4}>
          <StatusTag value={v} map={CHECK_RESULT_META} />
          {record.critical && <Tag color="red">关键项</Tag>}
        </Space>
      ),
    },
    { title: '说明', dataIndex: 'message', ellipsis: true, render: (v: string) => v || '-' },
  ]

  return (
    <Space direction="vertical" size={16} style={{ display: 'flex' }}>
      <Card
        title="交付检查"
        extra={
          canRun && (
            <Button type="primary" icon={<PlayCircleOutlined />} loading={runMutation.isPending} onClick={confirmRun}>
              运行检查
            </Button>
          )
        }
      >
        {listQuery.isError ? (
          <QueryErrorAlert error={listQuery.error} message="加载交付检查失败" />
        ) : (
          <SmartTable<DeliveryCheckItem>
            storageKey="delivery-check"
            rowKey="id"
            size="small"
            loading={listQuery.isLoading}
            columns={historyColumns}
            dataSource={listQuery.data?.items}
            onRow={(record) => ({
              onDoubleClick: () => setSelectedId(record.id),
              style: { cursor: 'pointer' },
            })}
            pagination={false}
          />
        )}
      </Card>

      {selectedId && (
        <Card
          title={`检查详情（${selectedId.slice(0, 8)}）`}
          extra={
            check && (
              <Button icon={<DownloadOutlined />} onClick={() => window.open(deliveryChecksApi.exportUrl(check.id), '_blank')}>
                导出报告
              </Button>
            )
          }
        >
          {detailQuery.isError ? (
            <QueryErrorAlert error={detailQuery.error} message="加载检查详情失败" />
          ) : check ? (
            <Space direction="vertical" size={16} style={{ display: 'flex' }}>
              {!isTerminalDeliveryStatus(check.status) && (
                <Alert type="info" showIcon message="检查执行中，结果将自动刷新…" />
              )}
              {check.overall_result === 'FAIL' && (
                <Alert type="error" showIcon message="存在关键检查项失败，不得标记正式交付" />
              )}
              <Row gutter={16}>
                <Col span={6}>
                  <Card size="small">
                    <Statistic title="总结果" value={CHECK_RESULT_META[check.overall_result ?? '']?.label ?? '进行中'} />
                  </Card>
                </Col>
                <Col span={6}>
                  <Card size="small">
                    <Statistic title="通过" value={check.pass_count ?? 0} valueStyle={{ color: '#3f8600' }} />
                  </Card>
                </Col>
                <Col span={6}>
                  <Card size="small">
                    <Statistic title="警告" value={check.warning_count ?? 0} valueStyle={{ color: '#d48806' }} />
                  </Card>
                </Col>
                <Col span={6}>
                  <Card size="small">
                    <Statistic title="失败" value={check.fail_count ?? 0} valueStyle={{ color: '#cf1322' }} />
                  </Card>
                </Col>
              </Row>
              <SmartTable<DeliveryCheckResultItem>
                storageKey="delivery-check-2"
                rowKey="item"
                size="small"
                columns={resultColumns}
                dataSource={results}
                onRow={(record) => ({
                  onDoubleClick: () => setDetailRecord(record),
                  style: { cursor: 'pointer' },
                })}
                pagination={false}
              />
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                执行时间：{formatDateTime(check.created_at)}
                {check.finished_at ? `；完成时间：${formatDateTime(check.finished_at)}` : ''}
              </Typography.Text>
            </Space>
          ) : (
            <Typography.Text type="secondary">加载中…</Typography.Text>
          )}
        </Card>
      )}

      <RecordDetailDrawer
        open={detailRecord !== null}
        title="检查项详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </Space>
  )
}
