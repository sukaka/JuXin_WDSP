import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
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
import { accessRulesApi } from '../../api/accessRules'
import { securityEventsApi } from '../../api/securityEvents'
import { formatDateTime } from '../../utils/format'
import { generateIdempotencyKey } from '../../utils/idempotency'
import { ATTACK_TYPE_META, EVENT_SEVERITY_META } from '../../utils/stage4'
import { ACCESS_RULE_STATUS_META } from '../../utils/stage5'
import StatusTag from '../../components/StatusTag'

/**
 * 从安全事件加入黑名单（阶段5 §十一）：
 * 打开时拉取预填数据（IP/建议时长/相关事件数/最近攻击时间/命中规则/共享出口与保护地址提示），
 * 管理员确认范围、时长与是否立即发布后调用现有创建接口（source_type=SECURITY_EVENT）。
 * 不得未经确认自动永久封禁——默认临时封禁，永久需管理员显式选择。
 */
export default function BlacklistFromEventModal({
  eventId,
  onClose,
  onCreated,
}: {
  eventId: string | null
  onClose: () => void
  onCreated?: () => void
}) {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const [name, setName] = useState('')
  const [reason, setReason] = useState('')
  const [scopeType, setScopeType] = useState<'GLOBAL' | 'APPLICATION'>('GLOBAL')
  const [validityType, setValidityType] = useState<'TEMPORARY' | 'PERMANENT'>('TEMPORARY')
  const [durationHours, setDurationHours] = useState(24)
  const [publishNow, setPublishNow] = useState(false)

  const prefillQuery = useQuery({
    queryKey: ['security-event-blacklist-prefill', eventId],
    queryFn: () => securityEventsApi.blacklistPrefill(eventId as string),
    enabled: eventId !== null,
  })
  const prefill = prefillQuery.data

  // 预填到达后初始化表单（切换事件时重置）
  useEffect(() => {
    if (!prefill) return
    setName(prefill.suggested_name)
    setReason(prefill.suggested_reason)
    setScopeType(prefill.application_id ? 'APPLICATION' : 'GLOBAL')
    setValidityType('TEMPORARY')
    setDurationHours(prefill.suggested_duration_hours)
    setPublishNow(false)
  }, [prefill])

  const createMutation = useMutation({
    mutationFn: async () => {
      const p = prefill
      if (!p || !eventId) throw new Error('预填数据缺失')
      const until =
        validityType === 'TEMPORARY'
          ? new Date(Date.now() + durationHours * 3600 * 1000).toISOString()
          : null
      const created = await accessRulesApi.create({
        name: name.trim(),
        rule_type: 'DENY',
        scope_type: scopeType,
        application_id: scopeType === 'APPLICATION' ? p.application_id : null,
        address: p.address,
        validity_type: validityType,
        effective_until: until,
        reason: reason.trim(),
        source_type: 'SECURITY_EVENT',
        source_event_id: eventId,
      })
      let publishError: string | null = null
      if (publishNow) {
        try {
          await accessRulesApi.publish(generateIdempotencyKey())
        } catch (e) {
          publishError = e instanceof ApiError ? e.message : '发布失败'
        }
      }
      return { created, publishError }
    },
    onSuccess: ({ publishError }) => {
      if (publishError) {
        message.warning(`黑名单规则已创建，但发布失败：${publishError}，请到访问控制页面手动发布`)
      } else {
        message.success(publishNow ? '黑名单规则已创建并发布' : '黑名单规则已创建')
      }
      void queryClient.invalidateQueries({ queryKey: ['access-rules'] })
      onCreated?.()
      onClose()
    },
    onError: (e) => {
      message.error(e instanceof ApiError ? e.message : '创建黑名单规则失败')
    },
  })

  const protectedHit = prefill?.protected_hit === true

  return (
    <Modal
      title="加入黑名单（来自安全事件）"
      open={eventId !== null}
      onCancel={onClose}
      onOk={() => createMutation.mutate()}
      okText="确认创建"
      cancelText="取消"
      confirmLoading={createMutation.isPending}
      okButtonProps={{ disabled: prefillQuery.isLoading || prefillQuery.isError || protectedHit }}
      width={640}
      destroyOnHidden
    >
      {prefillQuery.isLoading ? (
        <Typography.Text type="secondary">加载预填数据...</Typography.Text>
      ) : prefillQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="加载预填数据失败"
          description={
            prefillQuery.error instanceof ApiError ? prefillQuery.error.message : undefined
          }
        />
      ) : prefill ? (
        <Space direction="vertical" style={{ width: '100%' }} size={12}>
          {protectedHit && (
            <Alert
              type="error"
              showIcon
              message="该地址命中保护地址，禁止加入黑名单"
              description={`保护地址：${prefill.protected_name || '-'}`}
            />
          )}
          {prefill.shared_egress_hint?.suspected && (
            <Alert
              type="warning"
              showIcon
              message="疑似共享出口/代理"
              description={`近 24h 内该 IP 关联了 ${prefill.shared_egress_hint.identity_count} 个不同身份，封禁可能影响无关用户，请谨慎确认时长。`}
            />
          )}
          {prefill.existing_deny_rule && (
            <Alert
              type="info"
              showIcon
              message="该地址已存在黑名单规则"
              description={`规则「${prefill.existing_deny_rule.name}」（状态：${ACCESS_RULE_STATUS_META[prefill.existing_deny_rule.status]?.label ?? prefill.existing_deny_rule.status}），重复创建将返回冲突错误。`}
            />
          )}
          <Descriptions column={2} size="small" bordered>
            <Descriptions.Item label="客户端 IP" span={2}>
              <Typography.Text code>{prefill.address}</Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="应用">
              {prefill.application_name || '-'}
            </Descriptions.Item>
            <Descriptions.Item label="攻击类型">
              <StatusTag value={prefill.attack_type} map={ATTACK_TYPE_META} />
            </Descriptions.Item>
            <Descriptions.Item label="严重级别">
              <StatusTag value={prefill.severity} map={EVENT_SEVERITY_META} />
            </Descriptions.Item>
            <Descriptions.Item label="近 24h 相关事件">
              {prefill.related_event_count_24h} 次
            </Descriptions.Item>
            <Descriptions.Item label="最近攻击时间">
              {prefill.last_attack_at ? formatDateTime(prefill.last_attack_at) : '-'}
            </Descriptions.Item>
            <Descriptions.Item label="命中规则" span={2}>
              {prefill.hit_rules.length > 0 ? (
                <Space wrap size={4}>
                  {prefill.hit_rules.map((h) => (
                    <Tag key={h.rule_id}>{`${h.rule_id} ${h.rule_name || ''}（${h.hits} 次）`}</Tag>
                  ))}
                </Space>
              ) : (
                '-'
              )}
            </Descriptions.Item>
          </Descriptions>
          <div>
            <Typography.Text strong>规则名称</Typography.Text>
            <Input
              style={{ marginTop: 4 }}
              maxLength={200}
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>
          <div>
            <Typography.Text strong>封禁原因</Typography.Text>
            <Input.TextArea
              style={{ marginTop: 4 }}
              rows={2}
              maxLength={500}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
          </div>
          <div>
            <Typography.Text strong>生效范围</Typography.Text>
            <div style={{ marginTop: 4 }}>
              <Radio.Group
                value={scopeType}
                onChange={(e) => setScopeType(e.target.value as 'GLOBAL' | 'APPLICATION')}
                options={[
                  { value: 'GLOBAL', label: '全局' },
                  {
                    value: 'APPLICATION',
                    label: `应用级（${prefill.application_name || '未知应用'}）`,
                    disabled: !prefill.application_id,
                  },
                ]}
              />
            </div>
          </div>
          <div>
            <Typography.Text strong>封禁时长（建议 {prefill.suggested_duration_hours} 小时）</Typography.Text>
            <div style={{ marginTop: 4 }}>
              <Space wrap>
                <Radio.Group
                  value={validityType}
                  onChange={(e) => setValidityType(e.target.value as 'TEMPORARY' | 'PERMANENT')}
                  options={[
                    { value: 'TEMPORARY', label: '临时封禁' },
                    { value: 'PERMANENT', label: '永久（需人工确认）' },
                  ]}
                />
                {validityType === 'TEMPORARY' && (
                  <InputNumber
                    min={1}
                    max={24 * 365}
                    value={durationHours}
                    onChange={(v) => setDurationHours(typeof v === 'number' ? v : 24)}
                    addonAfter="小时"
                  />
                )}
              </Space>
            </div>
          </div>
          <div>
            <Space>
              <Typography.Text strong>创建后立即发布到网关</Typography.Text>
              <Switch checked={publishNow} onChange={setPublishNow} />
            </Space>
            <div>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                不发布时规则仅在管理面生效登记，需到访问控制页面手动发布后网关才执行。
              </Typography.Text>
            </div>
          </div>
        </Space>
      ) : null}
    </Modal>
  )
}
