import { useMutation } from '@tanstack/react-query'
import { Alert, App as AntdApp, Button, Descriptions, Space, Tag, Typography } from 'antd'
import { ApiError } from '../../api/client'
import { exceptionsApi } from '../../api/exceptions'
import type { ExceptionPreviewResult } from '../../types'
import { formatDateTime } from '../../utils/format'
import { COMMON_DETAIL_FIELD_LABELS } from '../../utils/i18nLabels'
import { EXCEPTION_ACTION_META } from '../../utils/stage4'
import { API_DETECTOR_META } from '../../utils/stage8'

/** 例外校验字段中文名兜底（补足 COMMON_DETAIL_FIELD_LABELS 中未列出的例外专属字段） */
const EXCEPTION_FIELD_LABELS: Record<string, string> = {
  uri_exact: '路径精确匹配',
  uri_prefix: '路径前缀匹配',
  uri_regex: '路径正则匹配',
  methods: 'HTTP 方法',
  source_ips: '来源 IP',
  content_types: '内容类型',
  param_names: '参数名',
  cookie_names: 'Cookie 名称',
  header_names: '请求头名',
  rule_ids: '规则 ID',
  rule_tags: '规则标签',
  attack_types: '攻击类型',
  exception_action: '例外动作',
  action_target: '动作目标',
  effective_from: '生效时间',
  effective_until: '失效时间',
  target_engine: '目标引擎',
  api_rule_refs: 'API 规则引用',
  risk_acknowledged: '风险确认',
}

function formatFieldLabel(key: string): string {
  return EXCEPTION_FIELD_LABELS[key] ?? COMMON_DETAIL_FIELD_LABELS[key] ?? key
}

function formatUnsupportedLabel(key: string): string {
  return (
    EXCEPTION_ACTION_META[key]?.label ??
    EXCEPTION_FIELD_LABELS[key] ??
    COMMON_DETAIL_FIELD_LABELS[key] ??
    key
  )
}

/** 受保护模块词表中文名（S4 §8 protected_modules_unchanged；例外不绕过这些模块） */
const PROTECTED_MODULE_LABELS: Record<string, string> = {
  JWT: 'JWT 信任链',
  ACCESS_CONTROL: '访问控制',
  CC: 'CC 频率限制',
  RATE_LIMIT_QUOTA: '授权配额限速',
  MANUAL_BAN: '人工临时封禁',
  PROTOCOL_LIMITS: '协议/大小底线',
  RISK_POLICY: '身份风险策略',
}

/**
 * 例外影响预览面板（P0-04 S4 §8）：
 * 调 POST /exceptions/{id}/preview（expected_version 乐观锁，409 提示刷新）。
 * 预览不启用、不发布、不回放真实请求；estimated_match_count 为 null 时显示「无法估算」，禁止显示 0。
 */
export default function ExceptionPreviewPanel({
  exceptionId,
  version,
}: {
  exceptionId: string
  version: number
}) {
  const { message } = AntdApp.useApp()

  const previewMutation = useMutation({
    mutationFn: () => exceptionsApi.preview(exceptionId, version),
    onError: (e) => {
      if (e instanceof ApiError && e.status === 409) {
        message.error('草稿已被其他人修改，请刷新后重试')
      } else {
        message.error(e instanceof ApiError ? e.message : '预览失败')
      }
    },
  })

  const p: ExceptionPreviewResult | undefined = previewMutation.data

  return (
    <div>
      <Space style={{ marginBottom: 8 }}>
        <Button onClick={() => previewMutation.mutate()} loading={previewMutation.isPending}>
          影响预览
        </Button>
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          预览不启用、不发布、不回放真实请求；校验结果最终以服务端为准
        </Typography.Text>
      </Space>
      {p && (
        <div>
          {p.validation_status === 'NEEDS_REVIEW' && (
            <Alert
              type="warning"
              showIcon
              style={{ marginBottom: 8 }}
              message="校验状态：待审查，达标前禁止启用"
            />
          )}
          {(p.field_errors ?? []).length > 0 && (
            <Alert
              type="error"
              showIcon
              style={{ marginBottom: 8 }}
              message="字段级错误"
              description={
                <ul style={{ margin: 0, paddingLeft: 18 }}>
                  {(p.field_errors ?? []).map((fe, i) => (
                    <li key={`${fe.field}-${i}`}>
                      <Typography.Text strong>{formatFieldLabel(fe.field)}</Typography.Text>：{fe.message}
                    </li>
                  ))}
                </ul>
              }
            />
          )}
          {(p.unsupported ?? []).length > 0 && (
            <Alert
              type="warning"
              showIcon
              style={{ marginBottom: 8 }}
              message="不支持项（需迁移）"
              description={
                <ul style={{ margin: 0, paddingLeft: 18 }}>
                  {(p.unsupported ?? []).map((u, i) => (
                    <li key={`${u.field_or_action}-${i}`}>
                      <Typography.Text strong>{formatUnsupportedLabel(u.field_or_action)}</Typography.Text>
                      {u.migration_preview ? `：${u.migration_preview}` : ''}
                    </li>
                  ))}
                </ul>
              }
            />
          )}
          <Descriptions column={1} size="small" bordered>
            <Descriptions.Item label="规范化范围">
              <Space wrap size={4}>
                {p.normalized_scope?.domain && <Tag>域名 {p.normalized_scope.domain}</Tag>}
                {p.normalized_scope?.uri_exact && <Tag>路径 {p.normalized_scope.uri_exact}</Tag>}
                {p.normalized_scope?.uri_prefix && (
                  <Tag>前缀 {p.normalized_scope.uri_prefix}</Tag>
                )}
                {p.normalized_scope?.uri_regex && (
                  <Tag>正则 {p.normalized_scope.uri_regex}</Tag>
                )}
                {(p.normalized_scope?.methods ?? []).map((m) => (
                  <Tag key={`m-${m}`}>{m}</Tag>
                ))}
                {(p.normalized_scope?.source_ips ?? []).map((ip) => (
                  <Tag key={`ip-${ip}`}>{ip}</Tag>
                ))}
                {(p.normalized_scope?.content_types ?? []).map((ct) => (
                  <Tag key={`ct-${ct}`}>{ct}</Tag>
                ))}
              </Space>
            </Descriptions.Item>
            <Descriptions.Item label="解析后规则引用">
              {(p.resolved_rule_refs ?? []).length > 0 ? (
                <Space wrap size={4}>
                  {(p.resolved_rule_refs ?? []).map((r, i) => (
                    <Tag key={`${r.engine}-${r.detector_id ?? ''}-${String(r.rule_id ?? '')}-${i}`}>
                      {r.engine === 'API'
                        ? `${API_DETECTOR_META[r.detector_id ?? '']?.label ?? r.detector_id ?? ''}/${String(r.rule_id ?? '')}`
                        : `WAF ${String(r.rule_id ?? '')}`}
                    </Tag>
                  ))}
                </Space>
              ) : (
                '-'
              )}
            </Descriptions.Item>
            <Descriptions.Item label="生效窗口">
              {p.effective_window ? (
                <>
                  {formatDateTime(p.effective_window.from)} ~{' '}
                  {p.effective_window.until ? formatDateTime(p.effective_window.until) : '永久'}
                  {p.effective_window.half_open && (
                    <Typography.Text type="secondary" style={{ fontSize: 12, marginLeft: 8 }}>
                      （半开区间：含起点，不含终点）
                    </Typography.Text>
                  )}
                </>
              ) : (
                '-'
              )}
            </Descriptions.Item>
            <Descriptions.Item label="预估影响请求数">
              {p.estimated_match_count === null || p.estimated_match_count === undefined ? (
                <Typography.Text type="secondary">无法估算（历史样本不足）</Typography.Text>
              ) : (
                p.estimated_match_count
              )}
            </Descriptions.Item>
            <Descriptions.Item label="不受例外影响的防护模块">
              <Space wrap size={4}>
                {(p.protected_modules_unchanged ?? []).map((m) => (
                  <Tag key={m} color="green">
                    {PROTECTED_MODULE_LABELS[m] ?? m}
                  </Tag>
                ))}
              </Space>
            </Descriptions.Item>
            <Descriptions.Item label="编译指纹">
              <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
                {p.compiled_fingerprint || '-'}
              </Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="需发布目标">
              {(p.required_publish_targets ?? []).length > 0 ? (
                <Space wrap size={4}>
                  {(p.required_publish_targets ?? []).map((t) => (
                    <Tag key={t}>{t}</Tag>
                  ))}
                </Space>
              ) : (
                '-'
              )}
            </Descriptions.Item>
          </Descriptions>
        </div>
      )}
    </div>
  )
}
