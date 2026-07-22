import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Button, Card, Drawer, Space, Table, Tag, Typography } from 'antd'
import dayjs from 'dayjs'
import {
  accessControlVersionsApi,
  type AccessControlVersionItem,
} from '../../api/accessControlVersions'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'

const RESULT_COLOR: Record<string, string> = {
  SUCCESS: 'success',
  FAILED: 'error',
  PENDING: 'processing',
}

/** 访问控制配置版本：列表 / 差异 / 回滚 */
export default function AccessControlVersionsPage() {
  const { message, modal } = App.useApp()
  const qc = useQueryClient()
  const [page, setPage] = useState(1)
  const [diffOpen, setDiffOpen] = useState(false)
  const [diffLines, setDiffLines] = useState<string[]>([])
  const [diffTitle, setDiffTitle] = useState('')

  const listQuery = useQuery({
    queryKey: ['access-control-versions', page],
    queryFn: () => accessControlVersionsApi.list({ page, page_size: 20 }),
  })

  const rollbackMut = useMutation({
    mutationFn: (id: string) => accessControlVersionsApi.rollback(id),
    onSuccess: () => {
      message.success('回滚已提交，将触发配置重新发布')
      void qc.invalidateQueries({ queryKey: ['access-control-versions'] })
    },
    onError: (e: unknown) => {
      message.error(e instanceof ApiError ? e.message : '回滚失败')
    },
  })

  const onDiff = async (row: AccessControlVersionItem) => {
    try {
      const d = await accessControlVersionsApi.diff(row.id)
      setDiffTitle(`版本 v${d.version_no} vs v${d.compare_with_no}`)
      setDiffLines(d.differences ?? [])
      setDiffOpen(true)
    } catch (e) {
      message.error(e instanceof ApiError ? e.message : '获取差异失败')
    }
  }

  const onRollback = (row: AccessControlVersionItem) => {
    modal.confirm({
      title: `回滚到访问控制版本 v${row.version_no}？`,
      content: '将使用该版本的访问控制/CC 配置重新发布网关，需二次确认后执行。',
      okText: '确认回滚',
      okType: 'danger',
      onOk: () => rollbackMut.mutateAsync(row.id),
    })
  }

  const columns = [
    { title: '版本号', dataIndex: 'version_no', width: 90, render: (v: number) => `v${v}` },
    {
      title: '结果',
      dataIndex: 'publish_result',
      width: 100,
      render: (v: string) => <Tag color={RESULT_COLOR[v] ?? 'default'}>{v}</Tag>,
    },
    { title: '变更摘要', dataIndex: 'change_summary', ellipsis: true },
    {
      title: '配置哈希',
      dataIndex: 'config_hash',
      width: 120,
      render: (v: string) => (
        <Typography.Text code copyable={{ text: v }}>
          {v?.slice(0, 8)}…
        </Typography.Text>
      ),
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      width: 180,
      render: (v: string) => dayjs(v).format('YYYY-MM-DD HH:mm:ss'),
    },
    {
      title: '操作',
      width: 180,
      render: (_: unknown, row: AccessControlVersionItem) => (
        <Space>
          <Button type="link" size="small" onClick={() => void onDiff(row)}>
            差异
          </Button>
          <Button type="link" size="small" danger onClick={() => onRollback(row)}>
            回滚
          </Button>
        </Space>
      ),
    },
  ]

  return (
    <Card title="访问控制版本">
      <Typography.Paragraph type="secondary">
        访问控制与 CC 策略随配置发布产生版本快照。敏感凭据已脱敏，回滚时使用当前运行时密钥重新注入。
      </Typography.Paragraph>
      <QueryErrorAlert error={listQuery.error} />
      <Table
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        pagination={{
          current: page,
          pageSize: 20,
          total: listQuery.data?.total ?? 0,
          onChange: setPage,
        }}
      />
      <Drawer title={diffTitle} open={diffOpen} onClose={() => setDiffOpen(false)} width={560}>
        {diffLines.length === 0 ? (
          <Typography.Text type="secondary">无差异</Typography.Text>
        ) : (
          <ul>
            {diffLines.map((line) => (
              <li key={line}>
                <Typography.Text code>{line}</Typography.Text>
              </li>
            ))}
          </ul>
        )}
      </Drawer>
    </Card>
  )
}
