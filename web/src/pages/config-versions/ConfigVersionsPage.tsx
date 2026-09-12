import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Descriptions,
  Drawer,
  Space,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { DiffOutlined, RollbackOutlined } from '@ant-design/icons'
import { ApiError } from '../../api/client'
import { configVersionsApi } from '../../api/gatewayConfig'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import { PUBLISH_RESULT_META, SMOKE_RESULT_META, parseBusinessSnapshot, truncateHash } from '../../utils/stage3'
import { PublishTaskProgress, SnapshotTable } from '../config-publish/ConfigPublishPage'
import type { ConfigVersionItem } from '../../types'

export default function ConfigVersionsPage() {
  const { message, modal } = AntdApp.useApp()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [diffId, setDiffId] = useState<string | null>(null)
  const [rollbackTaskId, setRollbackTaskId] = useState<string | null>(null)

  const listQuery = useQuery({
    queryKey: ['config-versions', page, pageSize],
    queryFn: () => configVersionsApi.list({ page, page_size: pageSize }),
  })

  const diffQuery = useQuery({
    queryKey: ['config-version-diff', diffId],
    queryFn: () => configVersionsApi.diff(diffId as string),
    enabled: diffId !== null,
  })

  const rollbackMutation = useMutation({
    mutationFn: (id: string) => configVersionsApi.rollback(id),
    onSuccess: (task) => {
      setRollbackTaskId(task.id)
      if (task.status === 'SUCCESS') message.success('回滚成功')
      else if (task.status === 'FAILED') message.error('回滚失败，请查看任务详情')
    },
    onError: (e) => message.error(e instanceof ApiError ? e.message : '回滚失败'),
  })

  const confirmRollback = (record: ConfigVersionItem) => {
    modal.confirm({
      title: '高风险操作确认',
      content: `确定将网关配置回滚到版本「${record.version_number}」吗？回滚会立即下发该版本配置到防护网关。`,
      okText: '确认回滚',
      okButtonProps: { danger: true },
      onOk: () => rollbackMutation.mutate(record.id),
    })
  }

  const columns: ColumnsType<ConfigVersionItem> = [
    {
      title: '版本号',
      dataIndex: 'version_number',
      width: 220,
      render: (v: string, record) => (
        <Space>
          <Typography.Text code>{v}</Typography.Text>
          {record.is_current && <Tag color="green">当前</Tag>}
        </Space>
      ),
    },
    {
      title: '配置哈希',
      dataIndex: 'configuration_hash',
      width: 140,
      render: (v: string) => (
        <Typography.Text copyable={{ text: v }} style={{ fontFamily: 'monospace', fontSize: 12 }}>
          {truncateHash(v)}
        </Typography.Text>
      ),
    },
    {
      title: '发布结果',
      dataIndex: 'publish_result',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={PUBLISH_RESULT_META} />,
    },
    {
      title: '流量验证',
      dataIndex: 'validation_result',
      width: 100,
      render: (v: string | undefined) =>
        v ? <StatusTag value={v} map={SMOKE_RESULT_META} /> : '-',
    },
    { title: '变更摘要', dataIndex: 'change_summary', ellipsis: true, render: (v: string) => v || '-' },
    {
      title: '创建人',
      dataIndex: 'created_by',
      width: 110,
      render: (v: string | null) => (v ? <Typography.Text code>{v.slice(0, 8)}</Typography.Text> : '-'),
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '发布时间',
      dataIndex: 'published_at',
      width: 170,
      render: (v: string | null) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 170,
      fixed: 'right',
      render: (_, record) => (
        <Space>
          <Button type="link" size="small" icon={<DiffOutlined />} onClick={() => setDiffId(record.id)}>
            差异
          </Button>
          {hasPermission(permissions, 'gateway_configs.rollback') && !record.is_current && (
            <Button
              type="link"
              size="small"
              danger
              icon={<RollbackOutlined />}
              disabled={record.publish_result !== 'SUCCESS'}
              onClick={() => confirmRollback(record)}
            >
              回滚
            </Button>
          )}
        </Space>
      ),
    },
  ]

  const diff = diffQuery.data

  return (
    <Card title="配置版本">
      {rollbackTaskId && (
        <div style={{ marginBottom: 16 }}>
          <PublishTaskProgress taskId={rollbackTaskId} />
        </div>
      )}

      {listQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="加载配置版本失败"
          description={listQuery.error instanceof ApiError ? listQuery.error.message : undefined}
        />
      ) : (
        <SmartTable<ConfigVersionItem>
          storageKey="config-versions"
          rowKey="id"
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          onRow={(record) => ({
            onDoubleClick: () => setDiffId(record.id),
            style: { cursor: 'pointer' },
          })}
          scroll={{ x: 1300 }}
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

      <Drawer title="与当前版本差异对比" open={diffId !== null} onClose={() => setDiffId(null)} width={640}>
        {diffQuery.isLoading && <Typography.Text type="secondary">加载中…</Typography.Text>}
        {diffQuery.isError && (
          <Alert
            type="error"
            showIcon
            message="加载差异信息失败"
            description={diffQuery.error instanceof ApiError ? diffQuery.error.message : undefined}
          />
        )}
        {diff && (
          <Space direction="vertical" size={16} style={{ display: 'flex' }}>
            <Alert
              type={diff.same ? 'success' : 'warning'}
              showIcon
              message={
                diff.same
                  ? '该版本与当前生效版本配置一致'
                  : '该版本与当前生效版本配置不同'
              }
            />
            <Descriptions column={1} size="small" bordered>
              <Descriptions.Item label="目标版本">{diff.target_version.version_number}</Descriptions.Item>
              <Descriptions.Item label="当前版本">
                {diff.current_version_number || '（无生效版本）'}
              </Descriptions.Item>
              <Descriptions.Item label="目标哈希">
                <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
                  {diff.target_hash || '-'}
                </Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label="当前哈希">
                <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
                  {diff.current_hash || '-'}
                </Typography.Text>
              </Descriptions.Item>
            </Descriptions>
            <div>
              <Typography.Title level={5}>目标版本业务摘要</Typography.Title>
              <SnapshotTable snapshot={parseBusinessSnapshot(diff.business_snapshot)} />
            </div>
          </Space>
        )}
      </Drawer>
    </Card>
  )
}
