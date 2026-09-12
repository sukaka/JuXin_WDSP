import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CloudUploadOutlined } from '@ant-design/icons'
import { App as AntdApp, Button, Card, Descriptions, Radio, Space, Spin, Tag, Typography } from 'antd'
import { apiPolicyApi } from '../../api/apiSecurity'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatBytes } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import { API_POLICY_EDITION_META, API_PROTECTION_MODE_META } from '../../utils/stage8'

/** 防护模式来源（后端 env/db/default → 中文） */
const MODE_SOURCE_META: Record<string, string> = {
  env: '环境变量',
  db: '数据库',
  default: '系统默认',
}

/** API 动态防护策略（WDSP / 阶段8）：查看当前策略、修改防护模式、发布到网关 */
export default function ApiPolicyPage() {
  const { message, modal } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canEdit = hasPermission(permissions, 'api_policy.edit')
  const canPublish = hasPermission(permissions, 'api_policy.publish')

  /** 修改模式草稿：未改动时跟随当前策略 */
  const [modeDraft, setModeDraft] = useState<string | undefined>()

  const policyQuery = useQuery({
    queryKey: ['api-policy'],
    queryFn: () => apiPolicyApi.get(),
  })
  const policy = policyQuery.data
  const selectedMode = modeDraft ?? policy?.mode
  const modeDirty = policy != null && modeDraft != null && modeDraft !== policy.mode

  const updateModeMut = useMutation({
    mutationFn: (mode: string) => apiPolicyApi.updateMode(mode),
    onSuccess: (r) => {
      message.success(r.message || '防护模式已保存')
      setModeDraft(undefined)
      void qc.invalidateQueries({ queryKey: ['api-policy'] })
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '保存失败'),
  })

  const publishMut = useMutation({
    mutationFn: () => apiPolicyApi.publish(),
    onSuccess: (r) => message.success(r.message || '已发布'),
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '发布失败'),
  })

  const confirmSaveMode = () => {
    if (!policy || !modeDraft || modeDraft === policy.mode) return
    const from = API_PROTECTION_MODE_META[policy.mode]?.label ?? policy.mode
    const to = API_PROTECTION_MODE_META[modeDraft]?.label ?? modeDraft
    modal.confirm({
      title: '修改防护模式',
      content:
        `确定将防护模式从「${from}」切换为「${to}」吗？保存后仅写入数据库，需执行「发布到网关」下发后才在防护网关生效。` +
        (modeDraft === 'PROTECT' ? '防护模式会对偏离模型的请求执行阻断动作，请确认 API 模型已充分学习。' : ''),
      okText: '确认保存',
      onOk: () => updateModeMut.mutate(modeDraft),
    })
  }

  const confirmPublish = () => {
    modal.confirm({
      title: '高风险操作确认',
      content:
        '发布将把当前 API 动态防护策略（防护模式与解析限制）下发到全部防护网关并立即生效，可能直接影响线上流量处置。确定执行发布吗？',
      okText: '确认发布',
      okButtonProps: { danger: true },
      onOk: () => publishMut.mutate(),
    })
  }

  return (
    <Card
      title="API 动态防护策略"
      extra={
        canPublish ? (
          <Button
            icon={<CloudUploadOutlined />}
            loading={publishMut.isPending}
            onClick={confirmPublish}
          >
            发布到网关
          </Button>
        ) : null
      }
    >
      <Typography.Paragraph type="secondary">
        API 动态防护基于 API 学习模型检测偏离行为：关闭不检测，观察仅记录风险发现，防护对偏离请求执行阻断。修改模式保存后需发布到网关生效。
      </Typography.Paragraph>
      <QueryErrorAlert error={policyQuery.error} />
      <Spin spinning={policyQuery.isLoading}>
        <Descriptions column={2} size="small" style={{ marginBottom: 16 }}>
          <Descriptions.Item label="产品形态">
            {policy ? <StatusTag value={policy.edition} map={API_POLICY_EDITION_META} /> : '-'}
          </Descriptions.Item>
          <Descriptions.Item label="API 动态防护">
            {policy ? (
              policy.api_dynamic_protection ? (
                <Tag color="green">已启用</Tag>
              ) : (
                <Tag>未启用</Tag>
              )
            ) : (
              '-'
            )}
          </Descriptions.Item>
          <Descriptions.Item label="防护模式">
            {policy ? <StatusTag value={policy.mode} map={API_PROTECTION_MODE_META} /> : '-'}
          </Descriptions.Item>
          <Descriptions.Item label="模式来源">
            {policy ? (MODE_SOURCE_META[policy.mode_source] ?? policy.mode_source) : '-'}
          </Descriptions.Item>
        </Descriptions>
        <Typography.Title level={5}>解析限制</Typography.Title>
        <Descriptions column={2} size="small" style={{ marginBottom: 16 }}>
          <Descriptions.Item label="最大解析报文体">
            {policy ? formatBytes(policy.limits.max_body_parse_bytes) : '-'}
          </Descriptions.Item>
          <Descriptions.Item label="最大采样报文体">
            {policy ? formatBytes(policy.limits.max_body_sample_bytes) : '-'}
          </Descriptions.Item>
          <Descriptions.Item label="最大 JSON 深度">
            {policy ? policy.limits.max_json_depth : '-'}
          </Descriptions.Item>
          <Descriptions.Item label="最大字段数">
            {policy ? policy.limits.max_field_count : '-'}
          </Descriptions.Item>
        </Descriptions>
        {canEdit ? (
          <>
            <Typography.Title level={5}>修改防护模式</Typography.Title>
            <Space>
              <Radio.Group
                value={selectedMode}
                options={Object.entries(API_PROTECTION_MODE_META).map(([value, meta]) => ({
                  value,
                  label: meta.label,
                }))}
                onChange={(e) => setModeDraft(e.target.value as string)}
              />
              <Button
                type="primary"
                disabled={!modeDirty}
                loading={updateModeMut.isPending}
                onClick={confirmSaveMode}
              >
                保存
              </Button>
            </Space>
          </>
        ) : null}
      </Spin>
    </Card>
  )
}
