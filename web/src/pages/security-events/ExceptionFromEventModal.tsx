import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Checkbox,
  Descriptions,
  Input,
  InputNumber,
  Modal,
  Radio,
  Space,
  Switch,
  Tag,
  Typography,
} from 'antd'
import { ApiError } from '../../api/client'
import { exceptionsApi } from '../../api/exceptions'
import { gatewayConfigApi } from '../../api/gatewayConfig'
import { securityEventsApi } from '../../api/securityEvents'
import { useAuthStore } from '../../stores/auth'
import type { SecurityEventDetail } from '../../types'
import { ruleNameZh } from '../../utils/crsRuleNames'
import { generateIdempotencyKey } from '../../utils/idempotency'
import { hasPermission } from '../../utils/permission'

/**
 * OWASP CRS 异常评分汇总/阻断评估规则 ID：
 * 这些规则负责汇总入站/出站评分并执行最终拦截，不能作为例外目标（否则会放宽该接口全部 CRS 防护）。
 */
const BLOCKING_EVAL_RULE_IDS = new Set([949110, 949111, 959100, 959101, 9000102, 9000104, 980170])

const DURATION_PRESETS: { label: string; minutes: number }[] = [
  { label: '30 分钟', minutes: 30 },
  { label: '2 小时', minutes: 120 },
  { label: '24 小时', minutes: 24 * 60 },
  { label: '7 天', minutes: 7 * 24 * 60 },
  { label: '30 天', minutes: 30 * 24 * 60 },
]

function extractEventPath(requestPath?: string, requestUri?: string): string {
  const raw = (requestPath || requestUri || '').trim()
  if (!raw) return ''
  const idx = raw.search(/[?#]/)
  return idx >= 0 ? raw.slice(0, idx) : raw
}

interface CandidateRule {
  rule_id: number
  rule_name: string
}

type SubmitOutcome =
  | { stage: 'draft'; exceptionId: string }
  | { stage: 'enabled_only'; exceptionId: string }
  | { stage: 'published'; exceptionId: string; taskStatus: string; taskSummary?: string }
  | { stage: 'enable_failed'; exceptionId: string; errorMsg: string }
  | { stage: 'publish_failed'; exceptionId: string; errorMsg: string }

/**
 * 从安全事件创建例外弹窗：
 * - 应用、域名、精确路径、HTTP 方法与可信规则集均由服务端事件决定，前端仅作展示（防止扩大范围）；
 * - 自动过滤 949110 等评分汇总规则，避免误放宽该接口全部 CRS 防护；
 * - 允许管理员当场确认来源 IP 范围、有效期，并一键依次执行：创建草稿 → 服务端启用门禁 → 网关配置发布。
 */
export default function ExceptionFromEventModal({
  detail,
  open,
  onClose,
  onCreated,
}: {
  detail: SecurityEventDetail | null
  open: boolean
  onClose: () => void
  onCreated?: () => void
}) {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canPublish = hasPermission(permissions, 'gateway_configs.publish')

  const evt = detail?.event ?? null
  const eventPath = useMemo(
    () => (evt ? extractEventPath(evt.request_path, evt.request_uri) : ''),
    [evt],
  )

  const { candidateRules, excludedBlockingIds } = useMemo(() => {
    const matches = detail?.matches ?? []
    const seen = new Set<number>()
    const blockingSet = new Set<number>()
    const rules: CandidateRule[] = []
    for (const m of matches) {
      if (!m.rule_id || m.rule_id <= 0) continue
      if (BLOCKING_EVAL_RULE_IDS.has(m.rule_id)) {
        blockingSet.add(m.rule_id)
        continue
      }
      if (seen.has(m.rule_id)) continue
      seen.add(m.rule_id)
      rules.push({ rule_id: m.rule_id, rule_name: m.rule_name })
    }
    rules.sort((a, b) => a.rule_id - b.rule_id)
    return {
      candidateRules: rules,
      excludedBlockingIds: Array.from(blockingSet).sort((a, b) => a - b),
    }
  }, [detail])

  const missingEvidence = useMemo(() => {
    if (!evt) return ['事件信息未加载']
    const items: string[] = []
    if (!evt.application_id) items.push('缺少应用绑定')
    if (!eventPath) items.push('缺少请求路径')
    if (!evt.request_method) items.push('缺少 HTTP 方法')
    if (candidateRules.length === 0) items.push('缺少可例外的检测规则 ID')
    return items
  }, [evt, eventPath, candidateRules])

  const canEnableDirectly = missingEvidence.length === 0

  const [name, setName] = useState('')
  const [reason, setReason] = useState('')
  const [selectedRuleIds, setSelectedRuleIds] = useState<number[]>([])
  const [restrictSourceIP, setRestrictSourceIP] = useState(false)
  const [validityType, setValidityType] = useState<'TEMPORARY' | 'PERMANENT'>('TEMPORARY')
  const [durationMinutes, setDurationMinutes] = useState(30)
  const [applyImmediately, setApplyImmediately] = useState(true)

  useEffect(() => {
    if (!open || !evt) return
    setName(`事件例外-${evt.id.slice(0, 8)}`)
    setReason(`事件 ${evt.id} 误报处置`)
    setSelectedRuleIds(candidateRules.map((r) => r.rule_id))
    setRestrictSourceIP(false)
    setValidityType('TEMPORARY')
    setDurationMinutes(30)
    setApplyImmediately(canEnableDirectly)
  }, [open, evt, candidateRules, canEnableDirectly])

  const submitMutation = useMutation({
    mutationFn: async (): Promise<SubmitOutcome> => {
      if (!evt) throw new ApiError('事件信息缺失', 'INVALID', 0)
      const trimmedName = name.trim()
      if (!trimmedName) throw new ApiError('请输入例外名称', 'INVALID', 0)
      const trimmedReason = reason.trim()
      if (!trimmedReason) throw new ApiError('请输入例外原因', 'INVALID', 0)
      if (candidateRules.length > 0 && selectedRuleIds.length === 0) {
        throw new ApiError('请至少选择一条目标检测规则', 'INVALID', 0)
      }
      if (validityType === 'TEMPORARY' && (!Number.isInteger(durationMinutes) || durationMinutes < 1)) {
        throw new ApiError('临时有效期须为至少 1 分钟的正整数', 'INVALID', 0)
      }

      const created = await securityEventsApi.createException(evt.id, {
        name: trimmedName,
        reason: trimmedReason,
        restrict_source_ip: restrictSourceIP,
        is_temporary: validityType === 'TEMPORARY',
        ...(validityType === 'TEMPORARY' ? { duration_minutes: durationMinutes } : {}),
        ...(selectedRuleIds.length > 0 ? { rule_ids: selectedRuleIds } : {}),
      })
      const exceptionId = created.exception_id

      if (!applyImmediately || !canEnableDirectly) {
        return { stage: 'draft', exceptionId }
      }

      try {
        await exceptionsApi.enable(exceptionId)
      } catch (e) {
        const errorMsg = e instanceof ApiError ? e.message : '启用门禁校验失败'
        return { stage: 'enable_failed', exceptionId, errorMsg }
      }

      if (!canPublish) {
        return { stage: 'enabled_only', exceptionId }
      }

      try {
        const task = await gatewayConfigApi.publish({ idempotency_key: generateIdempotencyKey() })
        if (task.status === 'FAILED') {
          return {
            stage: 'publish_failed',
            exceptionId,
            errorMsg: task.failure_message || task.result_summary || '网关发布任务执行失败',
          }
        }
        return {
          stage: 'published',
          exceptionId,
          taskStatus: task.status,
          taskSummary: task.result_summary,
        }
      } catch (e) {
        const errorMsg = e instanceof ApiError ? e.message : '发布请求失败'
        return { stage: 'publish_failed', exceptionId, errorMsg }
      }
    },
    onSuccess: (outcome) => {
      void queryClient.invalidateQueries({ queryKey: ['exceptions'] })
      if (evt) {
        void queryClient.invalidateQueries({ queryKey: ['security-event', evt.id] })
      }
      void queryClient.invalidateQueries({ queryKey: ['security-events'] })
      if (outcome.stage === 'published' || outcome.stage === 'publish_failed') {
        void queryClient.invalidateQueries({ queryKey: ['gateway-config-current'] })
        void queryClient.invalidateQueries({ queryKey: ['publish-tasks'] })
        void queryClient.invalidateQueries({ queryKey: ['config-versions'] })
      }

      if (outcome.stage === 'published') {
        message.success(
          outcome.taskStatus === 'SUCCESS'
            ? '例外策略已创建、启用并发布到网关'
            : '例外策略已创建并启用，网关发布任务已提交',
        )
      } else if (outcome.stage === 'enabled_only') {
        message.success('例外策略已创建并启用，请前往「配置发布」页面发布后生效')
      } else if (outcome.stage === 'draft') {
        message.success('例外草稿已创建，请前往「例外策略」页面审核启用')
      } else if (outcome.stage === 'enable_failed') {
        let warningModal: ReturnType<typeof modal.warning> | null = null
        warningModal = modal.warning({
          title: '例外草稿已创建，但启用门禁未通过',
          content: (
            <div>
              <p>失败原因：{outcome.errorMsg}</p>
              <Link
                to="/exceptions"
                onClick={() => {
                  warningModal?.destroy()
                  onClose()
                }}
              >
                前往例外策略页面完善后启用
              </Link>
            </div>
          ),
        })
      } else if (outcome.stage === 'publish_failed') {
        let warningModal: ReturnType<typeof modal.warning> | null = null
        warningModal = modal.warning({
          title: '例外已创建并启用，但发布到网关失败',
          content: (
            <div>
              <p>失败原因：{outcome.errorMsg}</p>
              <Link
                to="/exceptions"
                onClick={() => {
                  warningModal?.destroy()
                  onClose()
                }}
              >
                前往例外策略页面重试发布
              </Link>
            </div>
          ),
        })
      }

      onCreated?.()
      onClose()
    },
    onError: (e) => {
      message.error(e instanceof ApiError ? e.message : '创建例外失败')
    },
  })

  const okText =
    applyImmediately && canEnableDirectly
      ? canPublish
        ? '创建并发布'
        : '创建并启用'
      : '仅保存草稿'

  return (
    <Modal
      title="从安全事件创建例外"
      open={open && evt !== null}
      onCancel={onClose}
      onOk={() => submitMutation.mutate()}
      okText={okText}
      cancelText="取消"
      confirmLoading={submitMutation.isPending}
      width={660}
      destroyOnHidden
    >
      {evt && (
        <Space direction="vertical" style={{ width: '100%' }} size={12}>
          {!canEnableDirectly && (
            <Alert
              type="warning"
              showIcon
              message="该事件缺少启用所需的精确范围证据，仅可保存为待审查草稿"
              description={`缺失项：${missingEvidence.join('、')}。创建后请前往「例外策略」补齐信息再启用发布。`}
            />
          )}

          <Descriptions column={2} size="small" bordered>
            <Descriptions.Item label="应用">
              {evt.application_name_snapshot || evt.application_id || <Tag color="red">未绑定</Tag>}
            </Descriptions.Item>
            <Descriptions.Item label="域名">{evt.domain || '-'}</Descriptions.Item>
            <Descriptions.Item label="HTTP 方法">
              {evt.request_method ? <Tag>{evt.request_method}</Tag> : '-'}
            </Descriptions.Item>
            <Descriptions.Item label="事件客户端 IP">
              {evt.client_ip ? <Typography.Text code>{evt.client_ip}</Typography.Text> : '-'}
            </Descriptions.Item>
            <Descriptions.Item label="精确路径（不含查询串）" span={2}>
              <Typography.Text code>{eventPath || '-'}</Typography.Text>
            </Descriptions.Item>
          </Descriptions>

          <div>
            <Typography.Text strong>目标排除规则</Typography.Text>
            <div style={{ marginTop: 6 }}>
              {candidateRules.length > 0 ? (
                <Checkbox.Group
                  value={selectedRuleIds}
                  onChange={(vals) => setSelectedRuleIds(vals as number[])}
                >
                  <Space direction="vertical" size={4}>
                    {candidateRules.map((r) => (
                      <Checkbox key={r.rule_id} value={r.rule_id}>
                        <Tag>{r.rule_id}</Tag>
                        {ruleNameZh({ rule_id: r.rule_id, name: r.rule_name })}
                      </Checkbox>
                    ))}
                  </Space>
                </Checkbox.Group>
              ) : (
                <Typography.Text type="secondary">
                  本事件未记录可例外的上游检测规则 ID
                </Typography.Text>
              )}
              {excludedBlockingIds.length > 0 && (
                <div style={{ marginTop: 4 }}>
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                    已自动排除异常评分汇总规则（{excludedBlockingIds.join(', ')}），避免放宽该接口的其他 CRS 防护。
                  </Typography.Text>
                </div>
              )}
            </div>
          </div>

          <div>
            <Typography.Text strong>来源 IP 范围</Typography.Text>
            <div style={{ marginTop: 4 }}>
              <Radio.Group
                value={restrictSourceIP ? 'SINGLE_IP' : 'ANY_IP'}
                onChange={(e) => setRestrictSourceIP(e.target.value === 'SINGLE_IP')}
                options={[
                  { value: 'ANY_IP', label: '不限来源 IP（所有访客生效）' },
                  {
                    value: 'SINGLE_IP',
                    label: evt.client_ip
                      ? `仅限本次客户端 IP（${evt.client_ip}）`
                      : '仅限本次客户端 IP（事件无 IP）',
                    disabled: !evt.client_ip,
                  },
                ]}
              />
            </div>
          </div>

          <div>
            <Typography.Text strong>有效期</Typography.Text>
            <div style={{ marginTop: 4 }}>
              <Space direction="vertical" size={8} style={{ width: '100%' }}>
                <Radio.Group
                  value={validityType}
                  onChange={(e) => setValidityType(e.target.value as 'TEMPORARY' | 'PERMANENT')}
                  options={[
                    { value: 'TEMPORARY', label: '临时例外（到期自动失效，无需再发布）' },
                    { value: 'PERMANENT', label: '永久（需人工确认）' },
                  ]}
                />
                {validityType === 'TEMPORARY' && (
                  <Space wrap>
                    <Radio.Group
                      optionType="button"
                      size="small"
                      value={
                        DURATION_PRESETS.some((p) => p.minutes === durationMinutes)
                          ? durationMinutes
                          : undefined
                      }
                      onChange={(e) => setDurationMinutes(Number(e.target.value))}
                      options={DURATION_PRESETS.map((p) => ({ label: p.label, value: p.minutes }))}
                    />
                    <InputNumber
                      size="small"
                      min={1}
                      max={365 * 24 * 60}
                      value={durationMinutes}
                      onChange={(v) => setDurationMinutes(typeof v === 'number' ? v : 30)}
                      addonAfter="分钟"
                      style={{ width: 140 }}
                    />
                  </Space>
                )}
              </Space>
            </div>
          </div>

          <div>
            <Typography.Text strong>例外名称</Typography.Text>
            <Input
              style={{ marginTop: 4 }}
              maxLength={128}
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>

          <div>
            <Typography.Text strong>例外原因</Typography.Text>
            <Input.TextArea
              style={{ marginTop: 4 }}
              rows={2}
              maxLength={500}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
          </div>

          <div>
            <Space>
              <Typography.Text strong>
                {canPublish ? '创建后立即启用并发布到网关' : '创建后立即启用'}
              </Typography.Text>
              <Switch
                checked={applyImmediately && canEnableDirectly}
                disabled={!canEnableDirectly}
                onChange={setApplyImmediately}
              />
            </Space>
            <div>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                {!canEnableDirectly
                  ? '缺失应用/路径/方法或检测规则证据时，服务端启用门禁不允许直接启用，只能先保存草稿。'
                  : canPublish
                    ? '开启后将依次执行：保存草稿 → 服务端启用门禁校验 → 网关配置发布；关闭则仅保存为草稿。'
                    : '当前账号无「配置发布」权限，开启后仅完成启用，仍需有发布权限的管理员发布后生效。'}
              </Typography.Text>
            </div>
          </div>
        </Space>
      )}
    </Modal>
  )
}
