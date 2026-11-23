import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Checkbox,
  Descriptions,
  Input,
  InputNumber,
  Modal,
  Radio,
  Select,
  Space,
  Switch,
  Tag,
  Typography,
} from 'antd'
import { ApiError } from '../../api/client'
import { accessRulesApi } from '../../api/accessRules'
import { securityEventsApi } from '../../api/securityEvents'
import { urlWhitelistsApi } from '../../api/urlWhitelists'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { ruleNameZh } from '../../utils/crsRuleNames'
import { formatDateTime } from '../../utils/format'
import { generateIdempotencyKey } from '../../utils/idempotency'
import { hasPermission } from '../../utils/permission'
import { ATTACK_TYPE_META, EVENT_SEVERITY_META } from '../../utils/stage4'
import { ACCESS_RULE_STATUS_META, URL_WHITELIST_MATCH_META } from '../../utils/stage5'

const HTTP_METHOD_OPTIONS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].map((m) => ({
  value: m,
  label: m,
}))

/**
 * 从安全事件加入白名单（支持 IP 白名单 / URL 白名单，并可一键勾选同步生成 WAF 精确例外草稿）：
 * - IP/URL 白名单仅跳过访问控制（黑名单/L7/自动封禁/风险策略/CC），不绕过 WAF（Coraza/CRS）安全底线；
 * - 若需跳过本事件命中的具体 WAF 规则，可勾选「同步创建 WAF 精确例外草稿」（30 分钟精确例外，仍需审核启用）。
 */
export default function WhitelistFromEventModal({
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
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManageExceptions = hasPermission(permissions, 'exceptions.manage')
  const canPublish = hasPermission(permissions, 'access_rules.publish')

  const [mode, setMode] = useState<'IP' | 'URL'>('IP')
  const [name, setName] = useState('')
  const [reason, setReason] = useState('')
  const [scopeType, setScopeType] = useState<'GLOBAL' | 'APPLICATION'>('GLOBAL')
  const [matchType, setMatchType] = useState<'EXACT' | 'PREFIX' | 'REGEX'>('EXACT')
  const [uriPattern, setUriPattern] = useState('')
  const [methods, setMethods] = useState<string[]>([])
  const [validityType, setValidityType] = useState<'TEMPORARY' | 'PERMANENT'>('TEMPORARY')
  const [durationHours, setDurationHours] = useState(24)
  const [alsoCreateException, setAlsoCreateException] = useState(false)
  const [publishNow, setPublishNow] = useState(false)

  const prefillQuery = useQuery({
    queryKey: ['security-event-whitelist-prefill', eventId],
    queryFn: () => securityEventsApi.whitelistPrefill(eventId as string),
    enabled: eventId !== null,
  })
  const prefill = prefillQuery.data

  useEffect(() => {
    if (!prefill) return
    const defaultMode: 'IP' | 'URL' = prefill.address ? 'IP' : 'URL'
    setMode(defaultMode)
    setName(defaultMode === 'IP' ? prefill.suggested_ip_name : prefill.suggested_url_name)
    setReason(prefill.suggested_reason)
    setScopeType(prefill.application_id ? 'APPLICATION' : 'GLOBAL')
    setMatchType('EXACT')
    setUriPattern(prefill.request_path || '')
    setMethods(prefill.request_method ? [prefill.request_method] : [])
    setValidityType('TEMPORARY')
    setDurationHours(24)
    setAlsoCreateException(false)
    setPublishNow(false)
  }, [prefill])

  const handleModeChange = (nextMode: 'IP' | 'URL') => {
    setMode(nextMode)
    if (!prefill) return
    // 若名称仍为另一模式的默认建议名，自动同步切换
    if (nextMode === 'IP' && (!name || name === prefill.suggested_url_name)) {
      setName(prefill.suggested_ip_name)
    } else if (nextMode === 'URL' && (!name || name === prefill.suggested_ip_name)) {
      setName(prefill.suggested_url_name)
    }
  }

  const createMutation = useMutation({
    mutationFn: async () => {
      const p = prefill
      if (!p || !eventId) throw new Error('预填数据缺失')
      const trimmedName = name.trim()
      if (!trimmedName) throw new ApiError('请输入规则名称', 'INVALID', 0)
      const until =
        validityType === 'TEMPORARY'
          ? new Date(Date.now() + durationHours * 3600 * 1000).toISOString()
          : null

      if (mode === 'IP') {
        if (!p.address) throw new ApiError('该事件无客户端 IP，请改用 URL 白名单', 'INVALID', 0)
        await accessRulesApi.create({
          name: trimmedName,
          rule_type: 'ALLOW',
          scope_type: scopeType,
          application_id: scopeType === 'APPLICATION' ? p.application_id : null,
          address: p.address,
          validity_type: validityType,
          effective_until: until,
          reason: reason.trim(),
          source_type: 'SECURITY_EVENT',
          source_event_id: eventId,
        })
      } else {
        const trimmedUri = uriPattern.trim()
        if (!trimmedUri) throw new ApiError('请输入 URL 路径或正则', 'INVALID', 0)
        await urlWhitelistsApi.create({
          name: trimmedName,
          scope_type: scopeType,
          application_id: scopeType === 'APPLICATION' ? p.application_id : null,
          match_type: matchType,
          uri_pattern: trimmedUri,
          methods,
          validity_type: validityType,
          effective_until: until,
          reason: reason.trim(),
          source_type: 'SECURITY_EVENT',
          source_event_id: eventId,
        })
      }

      let exceptionCreated = false
      let exceptionError: string | null = null
      if (alsoCreateException && p.can_create_waf_exception && canManageExceptions) {
        try {
          await securityEventsApi.createException(eventId)
          exceptionCreated = true
        } catch (e) {
          exceptionError = e instanceof ApiError ? e.message : '创建 WAF 精确例外草稿失败'
        }
      }

      let publishError: string | null = null
      if (publishNow && canPublish) {
        try {
          if (mode === 'IP') {
            await accessRulesApi.publish(generateIdempotencyKey())
          } else {
            await urlWhitelistsApi.publish(generateIdempotencyKey())
          }
        } catch (e) {
          publishError = e instanceof ApiError ? e.message : '发布失败'
        }
      }

      return { exceptionCreated, exceptionError, publishError }
    },
    onSuccess: ({ exceptionCreated, exceptionError, publishError }) => {
      const label = mode === 'IP' ? 'IP 白名单' : 'URL 白名单'
      const parts: string[] = [`${label}规则已创建`]
      if (publishNow && !publishError) parts[0] = `${label}规则已创建并发布`
      if (exceptionCreated) parts.push('已同步生成 WAF 精确例外草稿（请前往「例外策略」页审核启用）')

      const warnings: string[] = []
      if (exceptionError) warnings.push(`例外草稿失败：${exceptionError}`)
      if (publishError) warnings.push(`发布失败：${publishError}，请到白名单管理页面手动发布`)

      if (warnings.length > 0) {
        message.warning(`${parts.join('；')}；${warnings.join('；')}`)
      } else {
        message.success(parts.join('，'))
      }

      void queryClient.invalidateQueries({ queryKey: ['access-rules'] })
      void queryClient.invalidateQueries({ queryKey: ['url-whitelists'] })
      if (exceptionCreated) {
        void queryClient.invalidateQueries({ queryKey: ['exceptions'] })
        void queryClient.invalidateQueries({ queryKey: ['security-event', eventId] })
      }
      onCreated?.()
      onClose()
    },
    onError: (e) => {
      message.error(e instanceof ApiError ? e.message : '创建白名单规则失败')
    },
  })

  return (
    <Modal
      title="加入白名单（来自安全事件）"
      open={eventId !== null}
      onCancel={onClose}
      onOk={() => createMutation.mutate()}
      okText="确认创建"
      cancelText="取消"
      confirmLoading={createMutation.isPending}
      okButtonProps={{
        disabled:
          prefillQuery.isLoading ||
          prefillQuery.isError ||
          !prefill ||
          (mode === 'IP' ? !prefill.address : !uriPattern.trim()),
      }}
      width={680}
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
          <div>
            <Typography.Text strong>白名单类型</Typography.Text>
            <div style={{ marginTop: 6 }}>
              <Radio.Group
                value={mode}
                onChange={(e) => handleModeChange(e.target.value as 'IP' | 'URL')}
                optionType="button"
                buttonStyle="solid"
                options={[
                  { value: 'IP', label: 'IP 白名单', disabled: !prefill.address },
                  { value: 'URL', label: 'URL 白名单', disabled: !prefill.request_path },
                ]}
              />
            </div>
          </div>

          {mode === 'IP' && prefill.existing_allow_rule && (
            <Alert
              type="info"
              showIcon
              message="该地址已存在 IP 白名单规则"
              description={`规则「${prefill.existing_allow_rule.name}」（状态：${ACCESS_RULE_STATUS_META[prefill.existing_allow_rule.status]?.label ?? prefill.existing_allow_rule.status}），同范围重复创建将返回冲突错误。`}
            />
          )}
          {mode === 'IP' && prefill.existing_deny_rule && (
            <Alert
              type="info"
              showIcon
              message="该地址当前存在 IP 黑名单规则"
              description={`规则「${prefill.existing_deny_rule.name}」（状态：${ACCESS_RULE_STATUS_META[prefill.existing_deny_rule.status]?.label ?? prefill.existing_deny_rule.status}）；网关判定中白名单优先级高于黑名单。`}
            />
          )}
          {mode === 'IP' && prefill.shared_egress_hint?.suspected && (
            <Alert
              type="warning"
              showIcon
              message="疑似共享出口/代理"
              description={`近 24h 内该 IP 关联了 ${prefill.shared_egress_hint.identity_count} 个不同身份，加入 IP 白名单可能放行同出口其他用户，建议优先考虑应用级或改用 URL 白名单。`}
            />
          )}
          {mode === 'URL' && prefill.existing_url_whitelist && (
            <Alert
              type="info"
              showIcon
              message="该路径已存在 URL 白名单规则"
              description={`规则「${prefill.existing_url_whitelist.name}」（${URL_WHITELIST_MATCH_META[prefill.existing_url_whitelist.match_type]?.label ?? prefill.existing_url_whitelist.match_type}：${prefill.existing_url_whitelist.uri_pattern}），同范围同模式重复创建将返回冲突错误。`}
            />
          )}

          <Descriptions column={2} size="small" bordered>
            <Descriptions.Item label="客户端 IP">
              {prefill.address ? <Typography.Text code>{prefill.address}</Typography.Text> : '-'}
            </Descriptions.Item>
            <Descriptions.Item label="应用">
              {prefill.application_name || '-'}
            </Descriptions.Item>
            <Descriptions.Item label="请求路径" span={2}>
              {prefill.request_path ? (
                <Typography.Text code style={{ wordBreak: 'break-all' }}>
                  {prefill.request_method ? `${prefill.request_method} ` : ''}
                  {prefill.request_path}
                </Typography.Text>
              ) : (
                '-'
              )}
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
            {prefill.hit_rules.length > 0 && (
              <Descriptions.Item label="命中规则" span={2}>
                <Space wrap size={4}>
                  {prefill.hit_rules.map((h) => (
                    <Tag key={h.rule_id}>{`${h.rule_id} ${ruleNameZh({ rule_id: h.rule_id, name: h.rule_name })}（${h.hits} 次）`}</Tag>
                  ))}
                </Space>
              </Descriptions.Item>
            )}
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

          {mode === 'URL' && (
            <>
              <div>
                <Typography.Text strong>匹配方式</Typography.Text>
                <div style={{ marginTop: 4 }}>
                  <Radio.Group
                    value={matchType}
                    onChange={(e) => setMatchType(e.target.value as 'EXACT' | 'PREFIX' | 'REGEX')}
                    options={Object.entries(URL_WHITELIST_MATCH_META).map(([value, meta]) => ({
                      value,
                      label: meta.label,
                    }))}
                  />
                </div>
              </div>
              <div>
                <Typography.Text strong>URL 路径 / 正则</Typography.Text>
                <Input
                  style={{ marginTop: 4, fontFamily: 'monospace' }}
                  maxLength={512}
                  value={uriPattern}
                  onChange={(e) => setUriPattern(e.target.value)}
                  placeholder="如 /api/callback（不含查询参数）"
                />
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  精确/前缀匹配须以 / 开头且不含查询参数；前缀匹配按路径段边界生效。
                </Typography.Text>
              </div>
              <div>
                <Typography.Text strong>限定 HTTP 方法（留空匹配全部方法）</Typography.Text>
                <Select
                  mode="multiple"
                  allowClear
                  style={{ width: '100%', marginTop: 4 }}
                  placeholder="留空表示不限制方法"
                  value={methods}
                  onChange={setMethods}
                  options={HTTP_METHOD_OPTIONS}
                />
              </div>
            </>
          )}

          <div>
            <Typography.Text strong>放行原因</Typography.Text>
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
            <Typography.Text strong>有效期</Typography.Text>
            <div style={{ marginTop: 4 }}>
              <Space wrap>
                <Radio.Group
                  value={validityType}
                  onChange={(e) => setValidityType(e.target.value as 'TEMPORARY' | 'PERMANENT')}
                  options={[
                    { value: 'TEMPORARY', label: '临时白名单' },
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

          <Alert
            type="info"
            showIcon
            message="安全底线与 WAF 误报联动说明"
            description={
              <Space direction="vertical" size={6} style={{ width: '100%' }}>
                <span>
                  IP/URL 白名单仅跳过黑名单、L7 访问控制、自动封禁、身份风险策略与 CC，
                  <strong>不会绕过 WAF（Coraza/CRS）</strong>。
                </span>
                {prefill.can_create_waf_exception && canManageExceptions && (
                  <Checkbox
                    checked={alsoCreateException}
                    onChange={(e) => setAlsoCreateException(e.target.checked)}
                  >
                    同步创建 WAF 精确例外草稿（仅针对本事件路径、方法与命中规则{' '}
                    {prefill.event_rule_ids.join(', ')}，生成 30 分钟草稿，需到「例外策略」审核启用）
                  </Checkbox>
                )}
              </Space>
            }
          />

          {canPublish && (
            <div>
              <Space>
                <Typography.Text strong>创建后立即发布到网关</Typography.Text>
                <Switch checked={publishNow} onChange={setPublishNow} />
              </Space>
              <div>
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  不发布时规则仅在管理面登记，需到「白名单管理」页面手动发布后网关才执行。
                </Typography.Text>
              </div>
            </div>
          )}
        </Space>
      ) : null}
    </Modal>
  )
}
