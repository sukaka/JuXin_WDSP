import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Modal,
  Radio,
  Result,
  Select,
  Space,
  Steps,
  Table,
  Tabs,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { DownloadOutlined, PlusOutlined, SafetyOutlined } from '@ant-design/icons'
import { ApiError } from '../../api/client'
import { backupsApi } from '../../api/backups'
import { restoresApi } from '../../api/restores'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatBytes, formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import { truncateHash } from '../../utils/stage3'
import {
  BACKUP_STATUS_META,
  BACKUP_TYPE_META,
  BACKUP_VERIFY_STATUS_META,
  RESTORE_SCOPE_META,
  RESTORE_STATUS_META,
  isTerminalBackupStatus,
  isTerminalRestoreStatus,
} from '../../utils/stage6'
import type { BackupJobItem, RestoreJobItem, RestorePreviewData } from '../../types'

/* -------------------- 备份管理 -------------------- */

function BackupPanel() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canCreate = hasPermission(permissions, 'backups.create')
  const canVerify = hasPermission(permissions, 'backups.verify')
  const canDelete = hasPermission(permissions, 'backups.delete')

  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [createOpen, setCreateOpen] = useState(false)
  const [createType, setCreateType] = useState<'FULL' | 'CONFIG_ONLY'>('FULL')

  const listQuery = useQuery({
    queryKey: ['backups', page, pageSize],
    queryFn: () => backupsApi.list({ page, page_size: pageSize }),
    refetchInterval: (query) =>
      (query.state.data?.items ?? []).some((b) => !isTerminalBackupStatus(b.status)) ? 3000 : false,
  })

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: ['backups'] })
  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const createMutation = useMutation({
    mutationFn: () => backupsApi.create({ backup_type: createType }),
    onSuccess: () => {
      message.success('备份任务已创建，正在后台执行')
      setCreateOpen(false)
      invalidate()
    },
    onError,
  })

  const verifyMutation = useMutation({
    mutationFn: (id: string) => backupsApi.verify(id),
    onSuccess: (data) => {
      message.success(`备份校验通过（${data.result?.tables_ok ?? 0} 张表 / ${data.result?.total_rows ?? 0} 行）`)
      invalidate()
    },
    onError,
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => backupsApi.remove(id),
    onSuccess: () => {
      message.success('备份已删除')
      invalidate()
    },
    onError,
  })

  const confirmCreate = () => {
    modal.confirm({
      title: '创建备份确认',
      content:
        createType === 'FULL'
          ? '全量备份包含数据库、配置、证书（加密）等全部数据，执行期间可能占用较多系统资源。确定创建全量备份吗？'
          : '配置备份包含应用、策略、访问控制等配置数据。确定创建配置备份吗？',
      onOk: () => createMutation.mutate(),
    })
  }

  const confirmVerify = (record: BackupJobItem) => {
    modal.confirm({
      title: '校验确认',
      content: `确定校验备份「${record.id.slice(0, 8)}」的完整性与哈希吗？将重新解密逐表比对，可能耗时较长。`,
      onOk: () => verifyMutation.mutate(record.id),
    })
  }

  const confirmDelete = (record: BackupJobItem) => {
    modal.confirm({
      title: '高风险操作确认',
      content: `确定删除备份「${record.id.slice(0, 8)}」（${BACKUP_TYPE_META[record.backup_type]?.label ?? record.backup_type}）吗？备份文件将一并删除，删除后无法用于恢复！`,
      okText: '确认删除',
      okButtonProps: { danger: true },
      onOk: () => deleteMutation.mutate(record.id),
    })
  }

  const columns: ColumnsType<BackupJobItem> = [
    { title: '任务ID', dataIndex: 'id', width: 110, render: (v: string) => v.slice(0, 8) },
    {
      title: '类型',
      dataIndex: 'backup_type',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={BACKUP_TYPE_META} />,
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={BACKUP_STATUS_META} />,
    },
    {
      title: '大小',
      dataIndex: 'file_size',
      width: 100,
      align: 'right',
      render: (v: number | null | undefined) => formatBytes(v),
    },
    {
      title: '哈希',
      dataIndex: 'file_hash',
      width: 140,
      render: (v: string) => (v ? <Typography.Text code>{truncateHash(v)}</Typography.Text> : '-'),
    },
    {
      title: '验证状态',
      dataIndex: 'verified',
      width: 100,
      render: (v: boolean) => <StatusTag value={v ? 'PASSED' : 'UNVERIFIED'} map={BACKUP_VERIFY_STATUS_META} />,
    },
    {
      title: '创建时间',
      dataIndex: 'requested_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 200,
      fixed: 'right',
      render: (_, record) => (
        <Space size={0} wrap>
          {record.status === 'SUCCESS' && canVerify && !record.verified && (
            <Button type="link" size="small" onClick={() => confirmVerify(record)}>
              验证
            </Button>
          )}
          {record.status === 'SUCCESS' && (
            <Button
              type="link"
              size="small"
              icon={<DownloadOutlined />}
              onClick={() => window.open(backupsApi.downloadUrl(record.id), '_blank')}
            >
              下载
            </Button>
          )}
          {canDelete && isTerminalBackupStatus(record.status) && (
            <Button type="link" size="small" danger onClick={() => confirmDelete(record)}>
              删除
            </Button>
          )}
          {record.status === 'FAILED' && record.failure_message && (
            <Typography.Text type="danger" style={{ fontSize: 12 }} ellipsis={{ tooltip: record.failure_message }}>
              {record.failure_message}
            </Typography.Text>
          )}
        </Space>
      ),
    },
  ]

  return (
    <>
      <Space style={{ marginBottom: 16 }}>
        {canCreate && (
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
            创建备份
          </Button>
        )}
      </Space>
      {listQuery.isError ? (
        <QueryErrorAlert error={listQuery.error} message="加载备份列表失败" />
      ) : (
        <Table<BackupJobItem>
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

      <Modal
        title="创建备份"
        open={createOpen}
        onCancel={() => setCreateOpen(false)}
        onOk={confirmCreate}
        okText="创建"
        confirmLoading={createMutation.isPending}
        destroyOnHidden
      >
        <Radio.Group
          value={createType}
          onChange={(e) => setCreateType(e.target.value as 'FULL' | 'CONFIG_ONLY')}
          options={Object.entries(BACKUP_TYPE_META).map(([value, meta]) => ({ value, label: meta.label }))}
          optionType="button"
        />
        <Typography.Paragraph type="secondary" style={{ marginTop: 12, fontSize: 12 }}>
          备份文件加密存储并生成清单与哈希；创建成功后建议执行一次校验，未通过校验的备份不可用于恢复。
        </Typography.Paragraph>
      </Modal>
    </>
  )
}

/* -------------------- 恢复管理 -------------------- */

function RestorePanel() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canRestore = hasPermission(permissions, 'backups.restore')

  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [wizardOpen, setWizardOpen] = useState(false)
  const [step, setStep] = useState(0)
  const [backupId, setBackupId] = useState<string>()
  const [scope, setScope] = useState('FULL')
  const [preview, setPreview] = useState<RestorePreviewData | null>(null)
  const [jobId, setJobId] = useState<string | null>(null)

  const listQuery = useQuery({
    queryKey: ['restores', page, pageSize],
    queryFn: () => restoresApi.list({ page, page_size: pageSize }),
    refetchInterval: (query) =>
      (query.state.data?.items ?? []).some((r) => !isTerminalRestoreStatus(r.status)) ? 3000 : false,
  })

  // 向导内可选备份（后端要求：仅成功且已通过完整性验证的备份可恢复）
  const backupsQuery = useQuery({
    queryKey: ['backups', 'for-restore'],
    queryFn: async () => {
      const data = await backupsApi.list({ status: 'SUCCESS', page: 1, page_size: 100 })
      return { ...data, items: data.items.filter((b) => b.verified) }
    },
    enabled: wizardOpen,
  })

  const jobQuery = useQuery({
    queryKey: ['restores', 'job', jobId],
    queryFn: () => restoresApi.get(jobId!),
    enabled: jobId !== null,
    refetchInterval: (query) =>
      query.state.data && isTerminalRestoreStatus(query.state.data.status) ? false : 2000,
  })

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: ['restores'] })
  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const validateMutation = useMutation({
    mutationFn: (id: string) => restoresApi.validate(id),
    onSuccess: (result) => {
      setPreview(result)
      if (result.compatible) setStep(2)
      else message.error('备份与当前系统版本不兼容，不可恢复')
    },
    onError,
  })

  const createMutation = useMutation({
    mutationFn: () => restoresApi.create({ backup_job_id: backupId!, scope }),
    onSuccess: (job) => {
      setJobId(job.id)
      setStep(3)
      invalidate()
    },
    onError,
  })

  const confirmMutation = useMutation({
    mutationFn: (id: string) => restoresApi.confirm(id),
    onSuccess: () => {
      message.success('恢复任务已确认执行，正在正式恢复')
      invalidate()
      if (jobId) void queryClient.invalidateQueries({ queryKey: ['restores', 'job', jobId] })
    },
    onError,
  })

  const cancelMutation = useMutation({
    mutationFn: (id: string) => restoresApi.cancel(id),
    onSuccess: () => {
      message.success('恢复任务已取消')
      invalidate()
    },
    onError,
  })

  const resetWizard = () => {
    setWizardOpen(false)
    setStep(0)
    setBackupId(undefined)
    setScope('FULL')
    setPreview(null)
    setJobId(null)
  }

  /** 确认执行恢复（高危操作，强制二次确认） */
  const confirmExecute = (id: string) => {
    modal.confirm({
      title: '高风险操作确认',
      content:
        '正式恢复将覆盖当前系统对应范围的数据，执行前请确认：隔离环境校验已通过、当前无进行中的发布任务、已有最新可用备份。恢复过程不可逆，确定执行恢复吗？',
      okText: '确认执行恢复',
      okButtonProps: { danger: true },
      onOk: () => confirmMutation.mutate(id),
    })
  }

  const confirmCancel = (id: string) => {
    modal.confirm({
      title: '取消确认',
      content: '确定取消该等待确认的恢复任务吗？隔离环境数据将被清理。',
      onOk: () => cancelMutation.mutate(id),
    })
  }

  const wizardJob = jobQuery.data

  const columns: ColumnsType<RestoreJobItem> = [
    { title: '任务ID', dataIndex: 'id', width: 110, render: (v: string) => v.slice(0, 8) },
    {
      title: '备份ID',
      dataIndex: 'backup_job_id',
      width: 110,
      render: (v: string | null) => (v ? v.slice(0, 8) : '-'),
    },
    {
      title: '恢复范围',
      dataIndex: 'restore_scope',
      width: 110,
      render: (v: string) => <StatusTag value={v} map={RESTORE_SCOPE_META} />,
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 120,
      render: (v: string) => <StatusTag value={v} map={RESTORE_STATUS_META} />,
    },
    {
      title: '创建时间',
      dataIndex: 'requested_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '完成时间',
      dataIndex: 'finished_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 190,
      fixed: 'right',
      render: (_, record) => (
        <Space size={0} wrap>
          {canRestore && record.status === 'AWAITING_CONFIRM' && (
            <>
              <Button type="link" size="small" danger icon={<SafetyOutlined />} onClick={() => confirmExecute(record.id)}>
                确认恢复
              </Button>
              <Button type="link" size="small" onClick={() => confirmCancel(record.id)}>
                取消
              </Button>
            </>
          )}
          {record.status === 'FAILED' && record.failure_message && (
            <Typography.Text type="danger" style={{ fontSize: 12 }} ellipsis={{ tooltip: record.failure_message }}>
              {record.failure_message}
            </Typography.Text>
          )}
        </Space>
      ),
    },
  ]

  const backupOptions = (backupsQuery.data?.items ?? []).map((b) => ({
    value: b.id,
    label: `${b.id.slice(0, 8)}｜${BACKUP_TYPE_META[b.backup_type]?.label ?? b.backup_type}｜${formatDateTime(b.requested_at)}｜${formatBytes(b.file_size)}`,
  }))

  return (
    <>
      <Space style={{ marginBottom: 16 }}>
        {canRestore && (
          <Button type="primary" icon={<SafetyOutlined />} onClick={() => setWizardOpen(true)}>
            发起恢复
          </Button>
        )}
      </Space>
      {listQuery.isError ? (
        <QueryErrorAlert error={listQuery.error} message="加载恢复任务失败" />
      ) : (
        <Table<RestoreJobItem>
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

      <Modal
        title="恢复向导"
        open={wizardOpen}
        onCancel={resetWizard}
        footer={null}
        width={760}
        destroyOnHidden
      >
        <Steps
          current={step}
          size="small"
          style={{ marginBottom: 24 }}
          items={[{ title: '选择备份' }, { title: '校验预览' }, { title: '确认恢复' }, { title: '完成' }]}
        />

        {step === 0 && (
          <Space direction="vertical" size={16} style={{ display: 'flex' }}>
            <Select
              style={{ width: '100%' }}
              placeholder="选择要恢复的备份（仅列出已成功且通过验证的备份）"
              loading={backupsQuery.isLoading}
              value={backupId}
              onChange={setBackupId}
              options={backupOptions}
              notFoundContent="无可用备份（须先创建备份并验证通过）"
            />
            <Radio.Group
              value={scope}
              onChange={(e) => setScope(e.target.value as string)}
              options={Object.entries(RESTORE_SCOPE_META).map(([value, meta]) => ({ value, label: meta.label }))}
              optionType="button"
            />
            <Button type="primary" disabled={!backupId} onClick={() => setStep(1)}>
              下一步
            </Button>
          </Space>
        )}

        {step === 1 && (
          <Space direction="vertical" size={16} style={{ display: 'flex' }}>
            <Typography.Text type="secondary">
              将对备份进行哈希、版本兼容性校验，并生成恢复预览，不会修改任何数据。
            </Typography.Text>
            {validateMutation.isPending && <Typography.Text>正在校验备份…</Typography.Text>}
            <Space>
              <Button onClick={() => setStep(0)}>上一步</Button>
              <Button
                type="primary"
                loading={validateMutation.isPending}
                onClick={() => backupId && validateMutation.mutate(backupId)}
              >
                开始校验
              </Button>
            </Space>
          </Space>
        )}

        {step === 2 && preview && (
          <Space direction="vertical" size={16} style={{ display: 'flex' }}>
            <Alert
              type={preview.compatible ? 'success' : 'error'}
              showIcon
              message={preview.compatible ? '备份校验通过' : '备份与当前系统不兼容'}
              description={
                <>
                  <div>备份类型：{BACKUP_TYPE_META[preview.backup_type]?.label ?? preview.backup_type}｜备份时间：{formatDateTime(preview.backup_time)}</div>
                  <div>
                    结构版本：备份 v{preview.schema_version ?? '-'} / 当前 v{preview.current_schema_version ?? '-'}
                  </div>
                  {preview.note && <div>说明：{preview.note}</div>}
                </>
              }
            />
            <Table
              size="small"
              rowKey="name"
              pagination={{ pageSize: 8 }}
              dataSource={(preview.tables ?? []).filter((t) => t.in_scope)}
              columns={[
                { title: '数据表', dataIndex: 'name', width: 220, ellipsis: true },
                { title: '分组', dataIndex: 'group', width: 120 },
                { title: '备份行数', dataIndex: 'backup_rows', width: 110, align: 'right' },
                {
                  title: '行数一致',
                  dataIndex: 'match',
                  width: 90,
                  render: (v: boolean) => (v ? <Tag color="green">一致</Tag> : <Tag color="orange">不一致</Tag>),
                },
              ]}
            />
            <Space>
              <Button onClick={() => setStep(0)}>重新选择</Button>
              <Button
                type="primary"
                danger
                disabled={!preview.compatible}
                loading={createMutation.isPending}
                onClick={() => createMutation.mutate()}
              >
                创建恢复任务（隔离恢复）
              </Button>
            </Space>
          </Space>
        )}

        {step === 3 && (
          <Space direction="vertical" size={16} style={{ display: 'flex' }}>
            {wizardJob ? (
              <>
                <Space>
                  <Typography.Text>任务状态：</Typography.Text>
                  <StatusTag value={wizardJob.status} map={RESTORE_STATUS_META} />
                  {!isTerminalRestoreStatus(wizardJob.status) && wizardJob.status !== 'AWAITING_CONFIRM' && (
                    <Typography.Text type="secondary">隔离恢复执行中，状态自动刷新…</Typography.Text>
                  )}
                </Space>
                {wizardJob.status === 'AWAITING_CONFIRM' && (
                  <Alert
                    type="warning"
                    showIcon
                    message="隔离恢复与完整性校验已通过，等待确认执行正式恢复"
                    description="正式恢复为高危操作，将覆盖目标范围的线上数据。"
                  />
                )}
                {wizardJob.status === 'FAILED' && wizardJob.failure_message && (
                  <Alert type="error" showIcon message="恢复失败" description={wizardJob.failure_message} />
                )}
                {wizardJob.status === 'SUCCESS' && (
                  <Result status="success" title="恢复完成" subTitle="请验证组件、配置和应用可用性。" />
                )}
                <Space>
                  {wizardJob.status === 'AWAITING_CONFIRM' && (
                    <Button type="primary" danger onClick={() => confirmExecute(wizardJob.id)}>
                      确认执行正式恢复
                    </Button>
                  )}
                  {isTerminalRestoreStatus(wizardJob.status) && (
                    <Button type="primary" onClick={resetWizard}>
                      关闭
                    </Button>
                  )}
                </Space>
              </>
            ) : (
              <Typography.Text type="secondary">加载任务状态…</Typography.Text>
            )}
          </Space>
        )}
      </Modal>
    </>
  )
}

/** 备份恢复：备份管理 + 恢复向导（选择备份→校验预览→确认恢复→完成） */
export default function BackupRestorePage() {
  return (
    <Card title="备份恢复">
      <Tabs
        items={[
          { key: 'backups', label: '备份管理', children: <BackupPanel /> },
          { key: 'restores', label: '恢复管理', children: <RestorePanel /> },
        ]}
      />
    </Card>
  )
}
