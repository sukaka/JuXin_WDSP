import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Checkbox,
  Modal,
  Progress,
  Radio,
  Space,
  Spin,
  Table,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { apiAdmissionApi } from '../../api/apiAdmission'
import { apiEndpointsApi } from '../../api/apiAssets'
import { apiPolicyApi } from '../../api/apiSecurity'
import { applicationsApi } from '../../api/applications'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import type { ApiAdmissionHotEndpoint, ApiAdmissionMode, ApplicationItem } from '../../types'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import { API_ENDPOINT_STATUS_META } from '../../utils/stage8'
import { ADMISSION_MODE_META } from './admissionMeta'
import PublishHint from './PublishHint'

/** 三态语义说明（docs/API_ADMISSION_CONTROL_DESIGN.md §3.1） */
const MODE_DESCRIPTIONS: Record<ApiAdmissionMode, string> = {
  OFF: '不做准入判定，所有 API 请求照常放行（现状行为）',
  OBSERVE: '未确认端点照常放行、仅记录观测；学习期内持续积累确认集',
  PROTECT: '仅已确认端点放行，未确认端点一律拒绝（403）',
}

/**
 * 切换准入模式弹窗：选 PROTECT 时内嵌覆盖率报告（unconfirmed_hot 可就地确认），
 * 必须勾选「我已知晓影响面」后才可提交（§5.1 软门禁）；切换成功提示发布。
 * 模式随应用更新接口提交（沿用应用更新权限与乐观锁 version）。
 */
export default function ModeSwitchModal({
  app,
  hitsWindowHours,
  onClose,
}: {
  app: ApplicationItem
  hitsWindowHours: number
  onClose: () => void
}) {
  const { message } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canConfirm = hasPermission(permissions, 'api_asset.confirm')
  const currentMode: ApiAdmissionMode = app.api_admission_mode ?? 'OFF'
  const [mode, setMode] = useState<ApiAdmissionMode>(currentMode)
  const [acknowledged, setAcknowledged] = useState(false)

  const coverageQuery = useQuery({
    queryKey: ['api-admission', 'coverage', app.id, hitsWindowHours],
    queryFn: () =>
      apiAdmissionApi.coverage({ application_id: app.id, hits_window: hitsWindowHours }),
    enabled: mode === 'PROTECT',
  })
  const coverage = coverageQuery.data

  // 覆盖率报告的未确认端点不含资产 id（冻结契约），按 endpoint_key 关联资产清单取得确认所需 id
  const endpointsQuery = useQuery({
    queryKey: ['api-admission', 'app-endpoint-keys', app.id],
    queryFn: () => apiEndpointsApi.list({ application_id: app.id, page: 1, page_size: 200 }),
    enabled: mode === 'PROTECT',
  })
  const idByKey = useMemo(
    () => new Map((endpointsQuery.data?.items ?? []).map((e) => [e.endpoint_key, e.id])),
    [endpointsQuery.data],
  )

  // 实断总阀门联动提示（§3.1）：准入 PROTECT 的 BLOCK 定案是否实际 403 由全局 api_protection.mode 决定。
  // 查询失败静默降级（不展示提示、不阻塞切换主流程）。
  const globalPolicyQuery = useQuery({
    queryKey: ['api-policy'],
    queryFn: () => apiPolicyApi.get(),
    retry: false,
  })
  const globalMode = globalPolicyQuery.data?.mode
  const showGlobalValveWarning =
    globalMode != null && globalMode !== 'PROTECT' && mode !== 'OFF'

  const hot = useMemo(
    () => [...(coverage?.unconfirmed_hot ?? [])].sort((a, b) => b.hits - a.hits),
    [coverage],
  )

  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ['api-admission'] })
    void qc.invalidateQueries({ queryKey: ['api-endpoints'] })
  }

  const confirmMut = useMutation({
    mutationFn: (ids: string[]) => apiEndpointsApi.confirm(ids),
    onSuccess: (r) => {
      if (r.failed && r.failed.length > 0) {
        message.error(r.failed[0].reason || '确认失败')
      } else {
        message.success({ content: <PublishHint prefix={`已确认 ${r.confirmed} 个接口`} />, duration: 6 })
      }
      invalidate()
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '确认失败'),
  })

  const switchMut = useMutation({
    mutationFn: (next: ApiAdmissionMode) =>
      applicationsApi.update(app.id, {
        name: app.name,
        description: app.description,
        business_owner: app.business_owner,
        technical_owner: app.technical_owner,
        protection_mode: app.protection_mode,
        deployment_mode: app.deployment_mode,
        api_admission_mode: next,
        version: app.version,
      }),
    onSuccess: (_data, next) => {
      message.success({
        content: <PublishHint prefix={`准入模式已切换为${ADMISSION_MODE_META[next].label}`} />,
        duration: 6,
      })
      invalidate()
      void qc.invalidateQueries({ queryKey: ['applications'] })
      onClose()
    },
    onError: (e: unknown) => {
      if (e instanceof ApiError && (e.status === 409 || e.code === 'RESOURCE_CONFLICT')) {
        message.error(e.message || '数据已被他人修改，请刷新后重试')
        return
      }
      message.error(e instanceof ApiError ? e.message : '切换失败')
    },
  })

  const confirmableIds = hot
    .map((e) => idByKey.get(e.endpoint_key))
    .filter((id): id is string => Boolean(id))

  const hotColumns: ColumnsType<ApiAdmissionHotEndpoint> = [
    { title: '方法', dataIndex: 'http_method', width: 70 },
    {
      title: '路径',
      dataIndex: 'normalized_path',
      ellipsis: true,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: '状态',
      dataIndex: 'asset_status',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={API_ENDPOINT_STATUS_META} />,
    },
    { title: '窗口命中', dataIndex: 'hits', width: 90 },
    {
      title: '最近访问',
      dataIndex: 'last_seen_at',
      width: 165,
      render: (v?: string | null) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 80,
      render: (_, record) => {
        if (!canConfirm) return null
        const id = idByKey.get(record.endpoint_key)
        if (!id) {
          return (
            <Tooltip title="未在资产清单匹配到该接口，请到 API 接口资产页确认">
              <Button type="link" size="small" disabled>
                确认
              </Button>
            </Tooltip>
          )
        }
        return (
          <Button type="link" size="small" onClick={() => confirmMut.mutate([id])}>
            确认
          </Button>
        )
      },
    },
  ]

  return (
    <Modal
      title={`切换准入模式：${app.name}`}
      open
      onCancel={onClose}
      onOk={() => switchMut.mutate(mode)}
      okText="确定"
      cancelText="取消"
      okButtonProps={{
        disabled: mode === currentMode || (mode === 'PROTECT' && !acknowledged),
        loading: switchMut.isPending,
      }}
      width={820}
      maskClosable={false}
    >
      <Typography.Paragraph type="secondary">
        当前模式：<StatusTag value={currentMode} map={ADMISSION_MODE_META} />
        。模式保存后随整站发布生效，未发布前网关仍按原模式执行。
      </Typography.Paragraph>
      <Radio.Group value={mode} onChange={(e) => setMode(e.target.value as ApiAdmissionMode)}>
        <Space direction="vertical">
          {(Object.keys(ADMISSION_MODE_META) as ApiAdmissionMode[]).map((value) => (
            <Radio key={value} value={value}>
              <Space size={4} wrap>
                <Typography.Text strong>
                  {ADMISSION_MODE_META[value].label}（{value}）
                </Typography.Text>
                <Typography.Text type="secondary">{MODE_DESCRIPTIONS[value]}</Typography.Text>
              </Space>
            </Radio>
          ))}
        </Space>
      </Radio.Group>
      {showGlobalValveWarning ? (
        <Alert
          type="warning"
          showIcon
          style={{ marginTop: 16 }}
          message="实断总阀门未开启"
          description={
            <>
              {`全局 API 防护模式当前为 ${globalMode}：准入拦截将只记录、不实际阻断。需实断请先在 API 防护策略中将全局模式设为 PROTECT。`}
              <Link to="/api-policy">前往 API 防护策略</Link>
            </>
          }
        />
      ) : null}
      {mode === 'PROTECT' ? (
        <Card size="small" title="覆盖率与影响面评估" style={{ marginTop: 16 }}>
          <QueryErrorAlert error={coverageQuery.error} message="加载覆盖率报告失败" />
          {coverageQuery.isPending ? (
            <Spin size="small" />
          ) : coverage ? (
            <Space direction="vertical" size={12} style={{ display: 'flex' }}>
              <Space size={12} wrap>
                <Typography.Text>确认覆盖率</Typography.Text>
                <Progress
                  percent={Math.round(coverage.confirm_rate * 100)}
                  size="small"
                  style={{ width: 160, minWidth: 160 }}
                />
                <Typography.Text type="secondary">
                  已确认 {coverage.endpoints.confirmed} / 未确认 {coverage.endpoints.discovered}
                </Typography.Text>
              </Space>
              {hot.length > 0 ? (
                <>
                  <Space style={{ display: 'flex', justifyContent: 'space-between' }} wrap>
                    <Typography.Text strong>窗口内未确认接口（按命中降序）</Typography.Text>
                    {canConfirm ? (
                      <Button
                        size="small"
                        disabled={confirmableIds.length === 0}
                        loading={confirmMut.isPending}
                        onClick={() => confirmMut.mutate(confirmableIds)}
                      >
                        全部确认
                      </Button>
                    ) : null}
                  </Space>
                  <Table<ApiAdmissionHotEndpoint>
                    rowKey="endpoint_key"
                    size="small"
                    columns={hotColumns}
                    dataSource={hot}
                    pagination={false}
                    scroll={{ y: 260 }}
                  />
                  <Typography.Text type="danger">
                    切换后以上 {hot.length} 个未确认接口访问将被拒绝（403）
                  </Typography.Text>
                </>
              ) : (
                <Typography.Text type="success">窗口内无未确认接口命中。</Typography.Text>
              )}
              <Checkbox
                checked={acknowledged}
                onChange={(e) => setAcknowledged(e.target.checked)}
              >
                我已知晓影响面
              </Checkbox>
            </Space>
          ) : null}
        </Card>
      ) : null}
    </Modal>
  )
}
