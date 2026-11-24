import type { ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Button,
  Descriptions,
  Drawer,
  Form,
  Input,
  Modal,
  Space,
  Tag,
  Typography,
} from 'antd'
import type { FormInstance } from 'antd'
import type { NamePath } from 'antd/es/form/interface'
import { apiFindingsApi, type ApiFinding } from '../api/apiSecurity'
import QueryErrorAlert from './QueryErrorAlert'
import StatusTag from './StatusTag'
import {
  availableFindingActions,
  FINDING_ACTION_LABEL,
  type FindingAction,
} from './useApiFindingHandling'
import { formatDateTime, formatJson } from '../utils/format'
import {
  API_FINDING_SEVERITY_META,
  API_FINDING_STATUS_META,
  API_SUBJECT_TYPE_META,
  formatApiFindingTitle,
  getApiFindingTypeMeta,
} from '../utils/stage8'

/** 动态兼容扩展风险类型（如 SCHEMA_*、LLM_* 等），避免页面回退原始英文码 */
export function FindingTypeTag({ value }: { value: string }) {
  const meta = getApiFindingTypeMeta(value)
  return <Tag color={meta.color}>{meta.label}</Tag>
}

/** 带必填文本域的处置弹窗（标记解决/标记误报共用）：关闭即销毁表单状态 */
function FindingActionModal<T extends Record<string, string>>({
  title,
  target,
  form,
  fieldName,
  fieldLabel,
  placeholder,
  loading,
  onCancel,
  onFinish,
}: {
  title: string
  target: ApiFinding | null
  form: FormInstance<T>
  fieldName: keyof T & string
  fieldLabel: string
  placeholder: string
  loading: boolean
  onCancel: () => void
  onFinish: (values: T) => void
}) {
  const targetTitle = target
    ? formatApiFindingTitle(target.title, {
        findingType: target.finding_type,
        detail: target.detail,
      })
    : ''
  return (
    <Modal
      title={target ? `${title}：${targetTitle}` : title}
      open={target !== null}
      onCancel={onCancel}
      confirmLoading={loading}
      okText="确定"
      cancelText="取消"
      onOk={() => form.submit()}
      destroyOnHidden
    >
      <Form<T> form={form} layout="vertical" onFinish={onFinish} preserve={false}>
        {/* keyof T & string 与 antd NamePath 条件类型不兼容；表单键恒为字符串，收窄为默认 NamePath */}
        <Form.Item
          name={fieldName as NamePath}
          label={fieldLabel}
          rules={[
            { required: true, whitespace: true, message: `请输入${fieldLabel}` },
            // 后端上限 512 字符（riskNoteMaxRunes），前端收紧到 500 留余量
            { max: 500, message: `${fieldLabel}不超过 500 字` },
          ]}
        >
          <Input.TextArea rows={4} maxLength={500} showCount placeholder={placeholder} />
        </Form.Item>
      </Form>
    </Modal>
  )
}

/** 表格行内前向快捷处置按钮（仅 confirm/start，完整动作见详情抽屉） */
export function ApiFindingInlineActions({
  record,
  canHandle,
  onAction,
}: {
  record: ApiFinding
  canHandle: boolean
  onAction: (record: ApiFinding, action: FindingAction) => void
}) {
  if (!canHandle) return null
  return (
    <>
      {availableFindingActions(record.status)
        .filter((a) => a === 'confirm' || a === 'start')
        .map((action) => (
          <Button key={action} type="link" size="small" onClick={() => onAction(record, action)}>
            {FINDING_ACTION_LABEL[action]}
          </Button>
        ))}
    </>
  )
}

/** 风险详情与处置抽屉（按权限增强加载 GET /findings/{id}，支持完整七态处置按钮） */
export function ApiFindingDetailDrawer({
  finding,
  onClose,
  canViewRisk,
  canHandle,
  onAction,
  drawerExtra,
}: {
  finding: ApiFinding | null
  onClose: () => void
  canViewRisk: boolean
  canHandle: boolean
  onAction: (record: ApiFinding, action: FindingAction) => void
  drawerExtra?: ReactNode
}) {
  const detailQuery = useQuery({
    queryKey: ['api-findings', 'detail', finding?.id],
    queryFn: () => apiFindingsApi.detail(finding?.id as string),
    enabled: finding !== null && canViewRisk,
  })

  const detail = detailQuery.data?.finding
  const relatedIds = detailQuery.data?.related_request_ids ?? []
  const evidenceEntries = Object.entries(detail?.evidence ?? {})
  const displayTitle = finding
    ? formatApiFindingTitle(finding.title, {
        findingType: finding.finding_type,
        detail: detail?.detail ?? finding.detail,
      })
    : ''

  return (
    <Drawer
      title={finding ? `风险详情：${displayTitle}` : '风险详情'}
      extra={drawerExtra}
      open={finding !== null}
      onClose={onClose}
      width={720}
    >
      {finding ? (
        <>
          <Descriptions column={2} size="small" style={{ marginBottom: 16 }}>
            <Descriptions.Item label="风险类型">
              <FindingTypeTag value={finding.finding_type} />
            </Descriptions.Item>
            <Descriptions.Item label="严重级别">
              <StatusTag value={finding.severity} map={API_FINDING_SEVERITY_META} />
            </Descriptions.Item>
            <Descriptions.Item label="处置状态">
              <StatusTag value={finding.status} map={API_FINDING_STATUS_META} />
            </Descriptions.Item>
            <Descriptions.Item label="接口">
              {finding.endpoint_key ? <Typography.Text code>{finding.endpoint_key}</Typography.Text> : '-'}
            </Descriptions.Item>
            <Descriptions.Item label="接口 ID">
              {finding.endpoint_id ? <Typography.Text code>{finding.endpoint_id}</Typography.Text> : '-'}
            </Descriptions.Item>
            <Descriptions.Item label="请求 ID">
              <Typography.Text code>{finding.request_id || '-'}</Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="发现 ID">
              <Typography.Text code>{finding.id}</Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="首次发现">{formatDateTime(finding.first_seen_at)}</Descriptions.Item>
            <Descriptions.Item label="最近发现">{formatDateTime(finding.last_seen_at)}</Descriptions.Item>
            {detail ? (
              <>
                <Descriptions.Item label="主体类型">
                  {detail.subject_type ? <StatusTag value={detail.subject_type} map={API_SUBJECT_TYPE_META} /> : '-'}
                </Descriptions.Item>
                <Descriptions.Item label="主体标识">
                  {detail.subject_id ? <Typography.Text code>{detail.subject_id}</Typography.Text> : '匿名主体'}
                </Descriptions.Item>
                <Descriptions.Item label="风险分">{detail.risk_score ?? '-'}</Descriptions.Item>
                <Descriptions.Item label="累计命中">{detail.count}</Descriptions.Item>
                <Descriptions.Item label="模型版本">{detail.model_version || '-'}</Descriptions.Item>
                <Descriptions.Item label="策略版本">{detail.policy_version || '-'}</Descriptions.Item>
              </>
            ) : null}
            <Descriptions.Item label="标题" span={2}>
              {displayTitle}
            </Descriptions.Item>
          </Descriptions>
          {canViewRisk ? <QueryErrorAlert error={detailQuery.error} /> : null}
          {canHandle ? (
            <>
              <Typography.Title level={5}>处置操作</Typography.Title>
              <Space style={{ marginBottom: 16 }} wrap>
                {availableFindingActions(finding.status).map((action) => (
                  <Button key={action} onClick={() => onAction(finding, action)}>
                    {FINDING_ACTION_LABEL[action]}
                  </Button>
                ))}
              </Space>
            </>
          ) : null}
          {detail ? (
            <>
              <Typography.Title level={5}>关联请求</Typography.Title>
              <Typography.Paragraph type="secondary" style={{ marginBottom: 8 }}>
                {detailQuery.data?.related_request_note ??
                  '同 API（同身份）近期运行时事件的请求 ID，近似关联，非精确命中回放'}
              </Typography.Paragraph>
              {relatedIds.length > 0 ? (
                <Space size={4} wrap style={{ marginBottom: 16 }}>
                  {relatedIds.map((rid) => (
                    <Typography.Text key={rid} code>
                      {rid}
                    </Typography.Text>
                  ))}
                </Space>
              ) : (
                <Typography.Paragraph type="secondary">暂无关联请求</Typography.Paragraph>
              )}
            </>
          ) : null}
          {evidenceEntries.length > 0 ? (
            <>
              <Typography.Title level={5}>证据（已脱敏）</Typography.Title>
              <Typography.Paragraph>
                <pre style={{ background: '#fafafa', padding: 12, fontSize: 12, overflow: 'auto', margin: 0 }}>
                  {formatJson(detail?.evidence)}
                </pre>
              </Typography.Paragraph>
            </>
          ) : null}
          <Typography.Title level={5}>风险明细</Typography.Title>
          <Typography.Paragraph>
            <pre style={{ background: '#fafafa', padding: 12, fontSize: 12, overflow: 'auto', margin: 0 }}>
              {formatJson(detail?.detail ?? finding.detail)}
            </pre>
          </Typography.Paragraph>
        </>
      ) : null}
    </Drawer>
  )
}

/** 标记解决 / 标记误报 必填弹窗组 */
export function ApiFindingActionModals({
  resolveTarget,
  onCloseResolve,
  resolveForm,
  resolveLoading,
  onSubmitResolve,
  fpTarget,
  onCloseFp,
  fpForm,
  fpLoading,
  onSubmitFp,
}: {
  resolveTarget: ApiFinding | null
  onCloseResolve: () => void
  resolveForm: FormInstance<{ resolution: string }>
  resolveLoading: boolean
  onSubmitResolve: (id: string, resolution: string) => void
  fpTarget: ApiFinding | null
  onCloseFp: () => void
  fpForm: FormInstance<{ reason: string }>
  fpLoading: boolean
  onSubmitFp: (id: string, reason: string) => void
}) {
  return (
    <>
      <FindingActionModal<{ resolution: string }>
        title="标记解决"
        target={resolveTarget}
        form={resolveForm}
        fieldName="resolution"
        fieldLabel="处置说明"
        placeholder="说明根因与修复方式，如：已下线该接口并回收密钥"
        loading={resolveLoading}
        onCancel={onCloseResolve}
        onFinish={(v) => resolveTarget && onSubmitResolve(resolveTarget.id, v.resolution.trim())}
      />
      <FindingActionModal<{ reason: string }>
        title="标记误报"
        target={fpTarget}
        form={fpForm}
        fieldName="reason"
        fieldLabel="误报原因"
        placeholder="说明判定为误报的依据，如：该字段为测试环境造数"
        loading={fpLoading}
        onCancel={onCloseFp}
        onFinish={(v) => fpTarget && onSubmitFp(fpTarget.id, v.reason.trim())}
      />
    </>
  )
}
