import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Checkbox,
  Modal,
  Radio,
  Space,
  Table,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import {
  apiEndpointsApi,
  type NoiseEndpointCandidate,
} from '../../api/apiAssets'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'

interface Props {
  open: boolean
  applicationId?: string
  applicationName?: string
  onClose: () => void
}

const REASON_BUCKET_LABELS: Record<string, { label: string; color: string }> = {
  static_extension: { label: '静态文件后缀', color: 'blue' },
  exclude_path_prefix: { label: '排除路径前缀', color: 'cyan' },
  static_well_known: { label: '静态元信息文件', color: 'geekblue' },
  non_api: { label: '非 API 流量', color: 'orange' },
}

function formatReason(reason: string): string {
  if (reason.startsWith('static_extension:')) {
    return `静态后缀 ${reason.slice('static_extension:'.length)}`
  }
  if (reason.startsWith('exclude_path_prefix:')) {
    return `排除前缀 ${reason.slice('exclude_path_prefix:'.length)}`
  }
  if (reason === 'static_well_known') return '静态元信息文件'
  if (reason === 'non_api') return '非 API（网页/普通资源）'
  return reason
}

/** 存量静态资源与非 API 噪声扫描预览与一键安全清理弹窗 */
export default function CleanupNoiseModal({
  open,
  applicationId,
  applicationName,
  onClose,
}: Props) {
  const { message, modal } = AntdApp.useApp()
  const qc = useQueryClient()

  const [action, setAction] = useState<'DELETE' | 'IGNORE'>('DELETE')
  const [includeIgnored, setIncludeIgnored] = useState(true)
  const [onlyCurrentSite, setOnlyCurrentSite] = useState(Boolean(applicationId))

  const effectiveAppId = onlyCurrentSite ? applicationId : undefined

  const previewQuery = useQuery({
    queryKey: ['api-endpoints', 'cleanup-noise-preview', effectiveAppId, includeIgnored],
    queryFn: () =>
      apiEndpointsApi.previewNoiseCleanup({
        application_id: effectiveAppId,
        include_ignored: includeIgnored,
        limit: 200,
      }),
    enabled: open,
  })

  const executeMut = useMutation({
    mutationFn: () =>
      apiEndpointsApi.executeNoiseCleanup({
        action,
        application_id: effectiveAppId,
        include_ignored: includeIgnored,
      }),
    onSuccess: (res) => {
      message.success(res.message || `已清理 ${res.result.affected} 条噪声端点`)
      void qc.invalidateQueries({ queryKey: ['api-endpoints'] })
      onClose()
    },
    onError: (e: unknown) =>
      message.error(e instanceof ApiError ? e.message : '清理失败'),
  })

  const preview = previewQuery.data
  const total = preview?.total ?? 0

  const handleConfirm = () => {
    if (total === 0) return
    modal.confirm({
      title: action === 'DELETE' ? '确认删除存量噪声端点' : '确认批量忽略存量噪声端点',
      content:
        action === 'DELETE'
          ? `即将彻底删除 ${total} 条命中的静态资源 / 非 API 噪声端点（已确认与已建模/绑定策略的正式资产会自动跳过保护）。删除后不可恢复，确定继续吗？`
          : `即将将 ${total} 条命中的静态资源 / 非 API 噪声端点批量标记为已忽略，确定继续吗？`,
      okText: action === 'DELETE' ? '确认删除' : '确认忽略',
      okButtonProps: { danger: action === 'DELETE' },
      cancelText: '取消',
      onOk: () => executeMut.mutateAsync(),
    })
  }

  const columns: ColumnsType<NoiseEndpointCandidate> = [
    { title: '方法', dataIndex: 'http_method', width: 80 },
    {
      title: '路径模板',
      dataIndex: 'normalized_path',
      ellipsis: true,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: '命中原因',
      dataIndex: 'reason',
      width: 190,
      render: (v: string) => <Tag>{formatReason(v)}</Tag>,
    },
    {
      title: '站点',
      dataIndex: 'application_name',
      width: 130,
      ellipsis: true,
      render: (v: string | undefined) => v || <Typography.Text type="secondary">未归属</Typography.Text>,
    },
    { title: '命中次数', dataIndex: 'hit_count', width: 90 },
  ]

  return (
    <Modal
      title="清理存量静态资源 / 非 API 噪声"
      open={open}
      width={820}
      onCancel={onClose}
      onOk={handleConfirm}
      okText={action === 'DELETE' ? `彻底删除（${total} 条）` : `批量忽略（${total} 条）`}
      cancelText="取消"
      okButtonProps={{
        danger: action === 'DELETE',
        loading: executeMut.isPending,
        disabled: previewQuery.isLoading || total === 0,
      }}
      destroyOnHidden
    >
      <Alert
        type="warning"
        showIcon
        style={{ marginBottom: 16 }}
        title="安全保护机制已开启：已确认（CONFIRMED）、学习中/已建模、或已绑定策略/授权/流程/分组的资产永不自动清理"
        description={
          preview && preview.protected_skipped > 0
            ? `本次扫描另有 ${preview.protected_skipped} 条命中静态/非 API 规则的端点因处于受保护状态而被自动跳过。`
            : '扫描依据当前「API 发现过滤规则」中的静态后缀、自定义排除前缀与 is_api=false 判定，命中白名单前缀的路径不会出现在待清理列表中。'
        }
      />

      <Space
        style={{ marginBottom: 12, width: '100%', justifyContent: 'space-between' }}
        wrap
      >
        <Space wrap>
          <Radio.Group
            value={action}
            onChange={(e) => setAction(e.target.value)}
            optionType="button"
            options={[
              { label: '彻底删除（推荐，释放配额）', value: 'DELETE' },
              { label: '仅标记为已忽略', value: 'IGNORE' },
            ]}
          />
          <Checkbox
            checked={includeIgnored}
            onChange={(e) => setIncludeIgnored(e.target.checked)}
          >
            包含历史已忽略项
          </Checkbox>
          {applicationId ? (
            <Checkbox
              checked={onlyCurrentSite}
              onChange={(e) => setOnlyCurrentSite(e.target.checked)}
            >
              仅当前站点（{applicationName || applicationId}）
            </Checkbox>
          ) : null}
        </Space>
      </Space>

      <QueryErrorAlert error={previewQuery.error} />

      {preview ? (
        <Space style={{ marginBottom: 12 }} wrap>
          <Typography.Text strong>待清理总数：{preview.total} 条</Typography.Text>
          {Object.entries(preview.by_reason ?? {}).map(([bucket, count]) => {
            const meta = REASON_BUCKET_LABELS[bucket] ?? { label: bucket, color: 'default' }
            return (
              <Tag key={bucket} color={meta.color}>
                {meta.label}：{count}
              </Tag>
            )
          })}
          {preview.total > (preview.items?.length ?? 0) ? (
            <Typography.Text type="secondary">
              （下方展示前 {preview.items.length} 条预览，执行将覆盖全部 {preview.total} 条）
            </Typography.Text>
          ) : null}
        </Space>
      ) : null}

      <Table<NoiseEndpointCandidate>
        size="small"
        rowKey="id"
        loading={previewQuery.isLoading}
        columns={columns}
        dataSource={preview?.items ?? []}
        scroll={{ y: 320 }}
        pagination={{ pageSize: 10, showSizeChanger: false }}
        locale={{ emptyText: '未发现符合清理条件的存量静态资源或非 API 噪声' }}
      />
    </Modal>
  )
}
