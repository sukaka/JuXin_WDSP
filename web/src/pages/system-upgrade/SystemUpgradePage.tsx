import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Form,
  Input,
  InputNumber,
  Modal,
  Progress,
  Select,
  Space,
  Table,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { PlusOutlined, RollbackOutlined } from '@ant-design/icons'
import { ApiError } from '../../api/client'
import { upgradesApi } from '../../api/upgrades'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatBytes, formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import { truncateHash } from '../../utils/stage3'
import { CHECK_RESULT_META, UPGRADE_STATUS_META, isTerminalUpgradeStatus } from '../../utils/stage6'
import type { UpgradeJobItem, UpgradePackageItem, UpgradePrecheckResult } from '../../types'

interface PackageFormValues {
  file_name: string
  version_from: string
  version_to: string
  file_hash: string
  file_size: number
}

/** 系统升级：升级包登记 → 预检 → 执行升级（任务轮询）→ 失败回滚 */
export default function SystemUpgradePage() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canPrecheck = hasPermission(permissions, 'upgrades.precheck')
  const canExecute = hasPermission(permissions, 'upgrades.execute')
  const canRollback = hasPermission(permissions, 'upgrades.rollback')

  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [registerOpen, setRegisterOpen] = useState(false)
  // 升级包无列表查询接口，登记记录保存在本地会话状态中
  const [packages, setPackages] = useState<UpgradePackageItem[]>([])
  const [selectedPackageId, setSelectedPackageId] = useState<string>()
  const [precheck, setPrecheck] = useState<UpgradePrecheckResult | null>(null)
  const [form] = Form.useForm<PackageFormValues>()

  const listQuery = useQuery({
    queryKey: ['upgrades', page, pageSize],
    queryFn: () => upgradesApi.list({ page, page_size: pageSize }),
    refetchInterval: (query) =>
      (query.state.data?.items ?? []).some((j) => !isTerminalUpgradeStatus(j.status)) ? 3000 : false,
  })

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: ['upgrades'] })
  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const registerMutation = useMutation({
    mutationFn: (values: PackageFormValues) => upgradesApi.registerPackage(values),
    onSuccess: (pkg) => {
      message.success('升级包已登记，请执行升级前检查')
      setPackages((list) => [...list.filter((p) => p.id !== pkg.id), pkg])
      setSelectedPackageId(pkg.id)
      setPrecheck(null)
      setRegisterOpen(false)
      form.resetFields()
    },
    onError,
  })

  const precheckMutation = useMutation({
    mutationFn: (packageId: string) => upgradesApi.precheck(packageId),
    onSuccess: (result) => {
      setPrecheck(result)
      if (result.overall_result === 'FAIL') message.error('预检存在失败项，禁止执行升级')
      else if (result.overall_result === 'WARNING') message.warning('预检存在警告项，请确认后再执行升级')
      else message.success('预检全部通过')
    },
    onError,
  })

  const executeMutation = useMutation({
    mutationFn: (packageId: string) => upgradesApi.execute(packageId),
    onSuccess: () => {
      message.success('升级任务已启动')
      invalidate()
    },
    onError,
  })

  const rollbackMutation = useMutation({
    mutationFn: (id: string) => upgradesApi.rollback(id),
    onSuccess: () => {
      message.success('回滚任务已启动')
      invalidate()
    },
    onError,
  })

  const precheckBlocked = (precheck?.items ?? []).some((i) => i.result === 'FAIL')

  const confirmExecute = () => {
    if (!selectedPackageId) return
    modal.confirm({
      title: '高风险操作确认',
      content:
        '执行升级将进入维护窗口并更新系统组件与数据库，升级前将自动执行全量备份。确定执行升级吗？',
      okText: '确认升级',
      okButtonProps: { danger: true },
      onOk: () => executeMutation.mutate(selectedPackageId),
    })
  }

  const confirmRollback = (record: UpgradeJobItem) => {
    modal.confirm({
      title: '高风险操作确认',
      content: `确定回滚升级任务「${record.id.slice(0, 8)}」（${record.version_from ?? '?'} → ${record.version_to ?? '?'}）吗？回滚将恢复旧版本组件、数据库迁移与配置。`,
      okText: '确认回滚',
      okButtonProps: { danger: true },
      onOk: () => rollbackMutation.mutate(record.id),
    })
  }

  const columns: ColumnsType<UpgradeJobItem> = [
    { title: '任务ID', dataIndex: 'id', width: 110, render: (v: string) => v.slice(0, 8) },
    {
      title: '版本',
      key: 'version',
      width: 160,
      render: (_, r) => (
        <Typography.Text>
          {r.version_from ?? '-'} → {r.version_to ?? '-'}
        </Typography.Text>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={UPGRADE_STATUS_META} />,
    },
    {
      title: '进度',
      dataIndex: 'progress',
      width: 150,
      render: (v: number | undefined, record) =>
        isTerminalUpgradeStatus(record.status) ? (
          <Progress
            percent={record.status === 'SUCCESS' ? 100 : (v ?? 0)}
            size="small"
            status={record.status === 'SUCCESS' ? 'success' : record.status === 'FAILED' ? 'exception' : 'normal'}
          />
        ) : (
          <Progress percent={v ?? 0} size="small" status="active" />
        ),
    },
    { title: '当前步骤', dataIndex: 'current_step', width: 160, ellipsis: true, render: (v: string) => v || '-' },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 140,
      fixed: 'right',
      render: (_, record) => (
        <Space size={0} wrap>
          {record.status === 'FAILED' && record.failure_message && (
            <Typography.Text type="danger" style={{ fontSize: 12 }} ellipsis={{ tooltip: record.failure_message }}>
              {record.failure_message}
            </Typography.Text>
          )}
          {canRollback && (record.status === 'FAILED' || record.status === 'SUCCESS') && (
            <Button type="link" size="small" danger icon={<RollbackOutlined />} onClick={() => confirmRollback(record)}>
              回滚
            </Button>
          )}
        </Space>
      ),
    },
  ]

  return (
    <Space direction="vertical" size={16} style={{ display: 'flex' }}>
      <Card
        title="升级包与预检"
        extra={
          canExecute && (
            <Button type="primary" icon={<PlusOutlined />} onClick={() => setRegisterOpen(true)}>
              登记升级包
            </Button>
          )
        }
      >
        <Space direction="vertical" size={16} style={{ display: 'flex' }}>
          <Space wrap>
            <Select
              style={{ minWidth: 360 }}
              placeholder="选择已登记的升级包"
              value={selectedPackageId}
              onChange={(v) => {
                setSelectedPackageId(v)
                setPrecheck(null)
              }}
              options={packages.map((p) => ({
                value: p.id,
                label: `${p.file_name}（${p.version_from} → ${p.version_to}，${formatBytes(p.file_size)}，哈希 ${truncateHash(p.file_hash, 8)}）`,
              }))}
              notFoundContent="请先登记升级包"
            />
            {canPrecheck && (
              <Button
                disabled={!selectedPackageId}
                loading={precheckMutation.isPending}
                onClick={() => selectedPackageId && precheckMutation.mutate(selectedPackageId)}
              >
                执行预检
              </Button>
            )}
            {canExecute && (
              <Button
                type="primary"
                danger
                disabled={!selectedPackageId || !precheck || precheckBlocked}
                loading={executeMutation.isPending}
                onClick={confirmExecute}
              >
                执行升级
              </Button>
            )}
          </Space>

          {precheck && (
            <>
              <Alert
                type={precheck.overall_result === 'PASS' ? 'success' : precheck.overall_result === 'WARNING' ? 'warning' : 'error'}
                showIcon
                message={`预检结果：${CHECK_RESULT_META[precheck.overall_result]?.label ?? precheck.overall_result}`}
                description={precheckBlocked ? '存在失败项，禁止执行升级。' : undefined}
              />
              <Table
                size="small"
                rowKey="name"
                pagination={false}
                dataSource={precheck.items ?? []}
                columns={[
                  { title: '检查项', dataIndex: 'name', width: 220 },
                  {
                    title: '结果',
                    dataIndex: 'result',
                    width: 100,
                    render: (v: string, record) => (
                      <Space size={4}>
                        <StatusTag value={v} map={CHECK_RESULT_META} />
                        {record.critical && <Tag color="red">关键项</Tag>}
                      </Space>
                    ),
                  },
                  { title: '说明', dataIndex: 'message', ellipsis: true, render: (v: string) => v || '-' },
                ]}
              />
            </>
          )}
        </Space>
      </Card>

      <Card title="升级任务">
        {listQuery.isError ? (
          <QueryErrorAlert error={listQuery.error} message="加载升级任务失败" />
        ) : (
          <Table<UpgradeJobItem>
            rowKey="id"
            loading={listQuery.isLoading}
            columns={columns}
            dataSource={listQuery.data?.items}
            scroll={{ x: 1100 }}
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
      </Card>

      <Modal
        title="登记升级包"
        open={registerOpen}
        onCancel={() => setRegisterOpen(false)}
        onOk={() => form.submit()}
        confirmLoading={registerMutation.isPending}
        destroyOnHidden
      >
        <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
          升级包需经离线介质拷贝至服务端指定目录后在此登记元数据，登记时校验哈希与大小。
        </Typography.Paragraph>
        <Form<PackageFormValues>
          form={form}
          layout="vertical"
          onFinish={(values) => registerMutation.mutate(values)}
        >
          <Form.Item name="file_name" label="文件名" rules={[{ required: true, message: '请输入文件名' }, { max: 200 }]}>
            <Input placeholder="如：jiuzhang-waf-v2.1.0-upgrade.tar.gz" />
          </Form.Item>
          <Space.Compact block>
            <Form.Item name="version_from" label="当前版本" style={{ width: '50%', marginRight: 8 }} rules={[{ required: true, message: '请输入当前版本' }, { max: 50 }]}>
              <Input placeholder="如：2.0.0" />
            </Form.Item>
            <Form.Item name="version_to" label="目标版本" style={{ width: '50%' }} rules={[{ required: true, message: '请输入目标版本' }, { max: 50 }]}>
              <Input placeholder="如：2.1.0" />
            </Form.Item>
          </Space.Compact>
          <Form.Item
            name="file_hash"
            label="文件哈希（SHA-256）"
            rules={[
              { required: true, message: '请输入文件哈希' },
              { pattern: /^[0-9a-fA-F]{64}$/, message: '须为 64 位十六进制摘要（SHA-256）' },
            ]}
          >
            <Input placeholder="64 位十六进制" autoComplete="off" />
          </Form.Item>
          <Form.Item name="file_size" label="文件大小（字节）" rules={[{ required: true, message: '请输入文件大小' }]}>
            <InputNumber min={1} precision={0} style={{ width: '100%' }} />
          </Form.Item>
        </Form>
      </Modal>
    </Space>
  )
}
