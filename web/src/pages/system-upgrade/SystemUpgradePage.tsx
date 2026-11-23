import { useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import dayjs, { type Dayjs } from 'dayjs'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  DatePicker,
  Form,
  Input,
  InputNumber,
  Modal,
  Popconfirm,
  Progress,
  Radio,
  Select,
  Space,
  Tag,
  Typography,
  Upload,
} from 'antd'
import SmartTable from '../../components/SmartTable'
import type { ColumnsType } from 'antd/es/table'
import { InboxOutlined, PlusOutlined, RollbackOutlined, UploadOutlined } from '@ant-design/icons'
import { ApiError, type UploadProgress } from '../../api/client'
import { upgradesApi, type UpgradePackageResp } from '../../api/upgrades'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatBytes, formatDateTime } from '../../utils/format'
import { PRECHECK_NAME_LABELS } from '../../utils/i18nLabels'
import { hasPermission } from '../../utils/permission'
import { truncateHash } from '../../utils/stage3'
import {
  CHECK_RESULT_META,
  UPGRADE_PACKAGE_STATUS_META,
  UPGRADE_STATUS_META,
  isTerminalUpgradeStatus,
} from '../../utils/stage6'
import type { UpgradeJobItem, UpgradePrecheckItem, UpgradePrecheckResult } from '../../types'

interface PackageFormValues {
  file_name: string
  version_from: string
  version_to: string
  file_hash: string
  file_size: number
}

/** 更新时机：立即更新 / 定时更新（定时需选择将来的开始时间） */
type UpgradeTiming = 'NOW' | 'SCHEDULED'

/** 系统升级：升级包上传/登记 → 预检 → 执行升级（任务轮询）→ 失败回滚 */
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
  const [uploadOpen, setUploadOpen] = useState(false)
  const [uploadFile, setUploadFile] = useState<File | null>(null)
  const [uploadTiming, setUploadTiming] = useState<UpgradeTiming>('NOW')
  const [uploadScheduledAt, setUploadScheduledAt] = useState<Dayjs | null>(null)
  const [uploadProgress, setUploadProgress] = useState<UploadProgress | null>(null)
  const [uploadResult, setUploadResult] = useState<UpgradePackageResp | null>(null)
  const [selectedPackageId, setSelectedPackageId] = useState<string>()
  const selectedPackageIdRef = useRef<string | undefined>(undefined)
  selectedPackageIdRef.current = selectedPackageId
  const [precheck, setPrecheck] = useState<UpgradePrecheckResult | null>(null)

  const selectPackage = (nextId: string | undefined) => {
    selectedPackageIdRef.current = nextId
    setSelectedPackageId(nextId)
    setPrecheck(null)
  }
  const [detailJob, setDetailJob] = useState<UpgradeJobItem | null>(null)
  const [detailPrecheck, setDetailPrecheck] = useState<UpgradePrecheckItem | null>(null)
  const [form] = Form.useForm<PackageFormValues>()

  const packagesQuery = useQuery({
    queryKey: ['upgrade-packages'],
    queryFn: () => upgradesApi.listPackages({ page: 1, page_size: 50 }),
  })
  const packages = useMemo(() => packagesQuery.data?.items ?? [], [packagesQuery.data?.items])
  const packageMap = useMemo(() => new Map(packages.map((p) => [p.id, p])), [packages])
  const formatJobVersion = (job: UpgradeJobItem) => {
    const pkg = job.package_id ? packageMap.get(job.package_id) : undefined
    return pkg ? `${pkg.version_from} → ${pkg.version_to}` : '-'
  }

  const listQuery = useQuery({
    queryKey: ['upgrades', page, pageSize],
    queryFn: () => upgradesApi.list({ page, page_size: pageSize }),
    refetchInterval: (query) =>
      (query.state.data?.items ?? []).some((j) => !isTerminalUpgradeStatus(j.status)) ? 3000 : false,
  })

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: ['upgrades'] })
  const invalidatePackages = () => void queryClient.invalidateQueries({ queryKey: ['upgrade-packages'] })
  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  // 登记成功后处理：REJECTED 时后端带 message 说明原因
  const onPackageRegistered = (resp: UpgradePackageResp) => {
    const pkg = resp.package
    if (resp.message) {
      message.warning(resp.message)
    } else {
      message.success('升级包已登记，请执行升级前检查')
    }
    invalidatePackages()
    if (pkg.status !== 'REJECTED') {
      selectPackage(pkg.id)
    }
  }

  const registerMutation = useMutation({
    mutationFn: (values: PackageFormValues) => upgradesApi.registerPackage(values),
    onSuccess: (resp) => {
      onPackageRegistered(resp)
      setRegisterOpen(false)
      form.resetFields()
    },
    onError,
  })

  // 上传弹窗关闭/提交成功后统一复位，避免下次打开残留上次选择
  const resetUploadForm = () => {
    setUploadFile(null)
    setUploadTiming('NOW')
    setUploadScheduledAt(null)
    setUploadProgress(null)
  }

  const uploadMutation = useMutation({
    mutationFn: (vars: { file: File; scheduledAt?: string }) =>
      upgradesApi.uploadPackage(vars.file, vars.scheduledAt, setUploadProgress),
    onSuccess: (resp) => {
      // 上传响应即最终处置：execution 非空表示验证通过且已创建升级任务
      // （立即更新为执行态，定时更新为 SCHEDULED）；为 null 时 warning 说明原因
      setUploadResult(resp)
      setUploadOpen(false)
      resetUploadForm()
      invalidatePackages()
      invalidate()
      if (resp.package.status !== 'REJECTED') {
        selectPackage(resp.package.id)
      }
    },
    onError: (e) => {
      setUploadProgress(null)
      onError(e)
    },
  })

  const confirmUpload = () => {
    if (!uploadFile || uploadMutation.isPending) return
    setUploadProgress(null)
    if (uploadTiming === 'SCHEDULED') {
      if (!uploadScheduledAt) {
        message.warning('请选择升级开始时间')
        return
      }
      uploadMutation.mutate({ file: uploadFile, scheduledAt: uploadScheduledAt.toISOString() })
      return
    }
    uploadMutation.mutate({ file: uploadFile })
  }

  const precheckMutation = useMutation({
    mutationFn: (packageId: string) => upgradesApi.precheck(packageId),
    onSuccess: (result, packageId) => {
      const resultPackageId = result.package_id ?? packageId
      // 防竞态：若用户在预检请求在途期间切换了升级包，丢弃过期的预检结果，避免跨包误启用执行按钮
      if (resultPackageId !== selectedPackageIdRef.current) return
      setPrecheck({ ...result, package_id: resultPackageId })
      if (result.overall_result === 'FAIL') message.error('预检存在失败项，禁止执行升级')
      else if (result.overall_result === 'WARNING') message.warning('预检存在警告项，请确认后再执行升级')
      else message.success('预检全部通过')
    },
    onError: (e, packageId) => {
      if (packageId !== selectedPackageIdRef.current) return
      onError(e)
    },
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

  const cancelMutation = useMutation({
    mutationFn: (id: string) => upgradesApi.cancelUpgrade(id),
    onSuccess: () => {
      message.success('定时升级已取消')
      invalidate()
    },
    onError,
  })

  const precheckMatchesSelected = Boolean(
    selectedPackageId && precheck && precheck.package_id === selectedPackageId,
  )
  const precheckBlocked = (precheck?.items ?? []).some((i) => i.result === 'FAIL')

  const confirmExecute = () => {
    if (!selectedPackageId || !precheckMatchesSelected || precheckBlocked) return
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
    const versionText = formatJobVersion(record)
    modal.confirm({
      title: '高风险操作确认',
      content: `确定回滚升级任务「${record.id.slice(0, 8)}」（版本：${versionText}）吗？回滚将恢复旧版本组件、数据库迁移与配置。`,
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
      render: (_, r) => <Typography.Text>{formatJobVersion(r)}</Typography.Text>,
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 110,
      render: (v: string) => <StatusTag value={v} map={UPGRADE_STATUS_META} />,
    },
    {
      title: '计划时间',
      dataIndex: 'scheduled_at',
      width: 170,
      render: (v: string | null | undefined) => formatDateTime(v),
    },
    {
      title: '开始时间',
      dataIndex: 'started_at',
      width: 170,
      render: (v: string | null | undefined) => formatDateTime(v),
    },
    {
      title: '完成时间',
      dataIndex: 'finished_at',
      width: 170,
      render: (v: string | null | undefined) => formatDateTime(v),
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
          {canExecute && record.status === 'SCHEDULED' && (
            <Popconfirm
              title="确定取消该定时升级？"
              okText="确定"
              onConfirm={() => cancelMutation.mutate(record.id)}
            >
              <Button type="link" size="small" danger>
                取消
              </Button>
            </Popconfirm>
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
            <Space>
              <Button icon={<PlusOutlined />} onClick={() => setRegisterOpen(true)}>
                登记升级包
              </Button>
              <Button type="primary" icon={<UploadOutlined />} onClick={() => setUploadOpen(true)}>
                上传升级包
              </Button>
            </Space>
          )
        }
      >
        <Space direction="vertical" size={16} style={{ display: 'flex' }}>
          {uploadResult &&
            (uploadResult.execution?.status === 'SCHEDULED' ? (
              <Alert
                type="info"
                showIcon
                closable
                onClose={() => setUploadResult(null)}
                message={`已创建定时升级：检测版本 ${uploadResult.package.version_from} → ${uploadResult.package.version_to}`}
                description={`将于 ${formatDateTime(uploadResult.execution.scheduled_at)} 自动开始；开始升级前会自动创建全量备份`}
              />
            ) : (
              <Alert
                type={uploadResult.execution ? 'success' : 'warning'}
                showIcon
                closable
                onClose={() => setUploadResult(null)}
                message={`检测到的版本：从 ${uploadResult.package.version_from} → ${uploadResult.package.version_to}`}
                description={
                  uploadResult.execution
                    ? '已开始自动升级，可在下方列表查看进度'
                    : (uploadResult.warning ?? '可稍后手动执行升级')
                }
              />
            ))}
          <Space wrap>
            <Select
              style={{ minWidth: 420 }}
              placeholder="选择升级包"
              loading={packagesQuery.isLoading}
              value={selectedPackageId}
              onChange={(v) => {
                selectPackage(v)
              }}
              options={packages.map((p) => ({
                value: p.id,
                disabled: p.status === 'REJECTED',
                label: `${p.file_name}（${p.version_from} → ${p.version_to}，${formatBytes(p.file_size)}，哈希 ${truncateHash(p.file_hash, 8)}，${UPGRADE_PACKAGE_STATUS_META[p.status]?.label ?? p.status}）`,
              }))}
              notFoundContent="请先上传或登记升级包"
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
                disabled={!selectedPackageId || precheck?.package_id !== selectedPackageId || precheckBlocked}
                loading={executeMutation.isPending}
                onClick={confirmExecute}
              >
                执行升级
              </Button>
            )}
          </Space>

          {precheckMatchesSelected && precheck && (
            <>
              <Alert
                type={precheck.overall_result === 'PASS' ? 'success' : precheck.overall_result === 'WARNING' ? 'warning' : 'error'}
                showIcon
                message={`预检结果：${CHECK_RESULT_META[precheck.overall_result]?.label ?? precheck.overall_result}`}
                description={precheckBlocked ? '存在失败项，禁止执行升级。' : undefined}
              />
              <SmartTable
                storageKey="system-upgrade"
                size="small"
                rowKey="name"
                pagination={false}
                dataSource={precheck.items ?? []}
                onRow={(record) => ({
                  onDoubleClick: () => setDetailPrecheck(record),
                  style: { cursor: 'pointer' },
                })}
                columns={[
                  {
                    title: '检查项',
                    dataIndex: 'name',
                    width: 220,
                    render: (v: string) => PRECHECK_NAME_LABELS[v] ?? v,
                  },
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
          <SmartTable<UpgradeJobItem>
            storageKey="system-upgrade-2"
            rowKey="id"
            loading={listQuery.isLoading}
            columns={columns}
            dataSource={listQuery.data?.items}
            scroll={{ x: 1270 }}
            onRow={(record) => ({
              onDoubleClick: () => setDetailJob(record),
              style: { cursor: 'pointer' },
            })}
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
        title="上传升级包"
        open={uploadOpen}
        onCancel={() => {
          if (uploadMutation.isPending) return
          setUploadOpen(false)
          resetUploadForm()
        }}
        onOk={confirmUpload}
        okText="确认上传"
        okButtonProps={{ disabled: !uploadFile || uploadMutation.isPending }}
        cancelButtonProps={{ disabled: uploadMutation.isPending }}
        confirmLoading={uploadMutation.isPending}
        closable={!uploadMutation.isPending}
        maskClosable={false}
        keyboard={!uploadMutation.isPending}
        destroyOnHidden
      >
        <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
          升级仅可通过本页面发起。上传后系统自动校验签名与版本；选择立即更新时校验通过将自动开始升级，选择定时更新时将创建定时任务，
          到达计划时间后自动开始；开始升级前会自动创建全量备份。上传大小上限默认 4GiB。
        </Typography.Paragraph>
        <Upload.Dragger
          accept=".tar.gz"
          maxCount={1}
          disabled={uploadMutation.isPending}
          beforeUpload={(file) => {
            if (uploadMutation.isPending) return Upload.LIST_IGNORE
            if (!file.name.toLowerCase().endsWith('.tar.gz')) {
              message.error('仅支持 .tar.gz 格式的升级包')
              return Upload.LIST_IGNORE
            }
            setUploadFile(file)
            return false
          }}
          onRemove={() => {
            if (uploadMutation.isPending) return false
            setUploadFile(null)
            return true
          }}
        >
          <p className="ant-upload-drag-icon">
            <InboxOutlined />
          </p>
          <p className="ant-upload-text">点击或拖拽升级包文件到此区域</p>
          <p className="ant-upload-hint">仅支持 .tar.gz 格式，如：jiuzhang-wdsp-upgrade-1.3.0-amd64.tar.gz</p>
        </Upload.Dragger>
        {uploadMutation.isPending && (
          <div style={{ marginTop: 16 }} role="status" aria-live="polite">
            <Progress
              percent={
                uploadProgress?.lengthComputable && uploadProgress.total > 0
                  ? Math.min(100, Math.round((uploadProgress.loaded / uploadProgress.total) * 100))
                  : 0
              }
              status="active"
            />
            <Typography.Text type="secondary">
              {uploadProgress?.lengthComputable && uploadProgress.total > 0 && uploadProgress.loaded >= uploadProgress.total
                ? '升级包已上传，正在等待服务端验签并创建升级任务…'
                : uploadProgress
                  ? `正在上传：${formatBytes(uploadProgress.loaded)}${uploadProgress.lengthComputable ? ` / ${formatBytes(uploadProgress.total)}` : ''}`
                  : '正在准备上传…'}
            </Typography.Text>
          </div>
        )}
        <div style={{ marginTop: 16 }}>
          <Typography.Text strong>更新时机</Typography.Text>
          <div style={{ marginTop: 8 }}>
            <Radio.Group
              value={uploadTiming}
              disabled={uploadMutation.isPending}
              onChange={(e) => setUploadTiming(e.target.value as UpgradeTiming)}
              options={[
                { value: 'NOW', label: '立即更新' },
                { value: 'SCHEDULED', label: '定时更新' },
              ]}
            />
          </div>
          {uploadTiming === 'SCHEDULED' && (
            <DatePicker
              showTime
              format="YYYY-MM-DD HH:mm"
              placeholder="选择升级开始时间"
              style={{ width: '100%', marginTop: 8 }}
              value={uploadScheduledAt}
              disabled={uploadMutation.isPending}
              onChange={(v) => setUploadScheduledAt(v)}
              disabledDate={(current) => current.isBefore(dayjs().startOf('day'))}
              disabledTime={(date) => {
                // 与后端「必须是将来的时间」约束对齐：今天禁选当前时刻之前的小时/分钟
                const now = dayjs()
                if (!date || !date.isSame(now, 'day')) return {}
                return {
                  disabledHours: () => Array.from({ length: now.hour() }, (_, i) => i),
                  disabledMinutes: (hour) =>
                    hour === now.hour() ? Array.from({ length: now.minute() }, (_, i) => i) : [],
                }
              }}
            />
          )}
        </div>
      </Modal>

      <Modal
        title="登记升级包"
        open={registerOpen}
        onCancel={() => setRegisterOpen(false)}
        onOk={() => form.submit()}
        confirmLoading={registerMutation.isPending}
        destroyOnHidden
      >
        <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
          适用于升级包已拷贝至服务端升级包目录的场景：仅登记元数据，登记时校验哈希与大小格式，
          升级前检查会核验目录中文件与登记信息一致。
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

      <RecordDetailDrawer
        open={detailPrecheck !== null}
        title="预检项详情"
        record={detailPrecheck as Record<string, unknown> | null}
        fieldLabels={{ name: '检查项', result: '结果', critical: '关键项', message: '说明' }}
        valueLabels={{ name: PRECHECK_NAME_LABELS }}
        onClose={() => setDetailPrecheck(null)}
      />
      <RecordDetailDrawer
        open={detailJob !== null}
        title="升级任务详情"
        record={detailJob as Record<string, unknown> | null}
        onClose={() => setDetailJob(null)}
      />
    </Space>
  )
}
