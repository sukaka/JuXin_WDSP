import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Input,
  InputNumber,
  Popconfirm,
  Select,
  Spin,
  Switch,
  Tabs,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import SmartTable from '../../components/SmartTable'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import { ApiError } from '../../api/client'
import {
  apmSettingsApi,
  settingsApi,
  type UpdateApmSettingsBody,
} from '../../api/settings'
import { useAuthStore } from '../../stores/auth'
import { useProductStore } from '../../stores/product'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import { isValidIPv4, isValidIPv6 } from '../../utils/stage5'
import type { SettingItem } from '../../types'

const GROUP_TABS = [
  { key: 'password', label: '密码策略' },
  { key: 'login', label: '登录安全' },
  { key: 'session', label: '会话管理' },
  { key: 'display', label: '界面显示' },
  { key: 'logging', label: '日志记录' },
  { key: 'block_response', label: '阻断响应页面' },
  { key: 'api_learning', label: 'API 学习' },
  { key: 'network', label: '网络' },
  { key: 'software_bypass', label: '软件旁路' },
  { key: 'gateway_runtime', label: '文件与水印' },
  { key: 'apm', label: 'APM 性能监控' },
]

/** 设置项前端扩展元数据：中文说明覆盖、数值范围约束与枚举选项（键为 setting_group:setting_key）。
 *  numeric 标记字符串型数值（后端 value_type='string'、内容为数字）使用数值输入框编辑。
 *  multiline/maxLength 用于长文本设置项（如自定义阻断页面正文）。 */
const SETTING_META: Record<
  string,
  {
    description?: string
    min?: number
    max?: number
    step?: number
    numeric?: boolean
    options?: { label: string; value: string }[]
    placeholder?: string
    multiline?: boolean
    maxLength?: number
  }
> = {
  'gateway_runtime:api_file_watermark_enabled': {
    description: '文件下载溯源水印总开关；启用前需填写模板，保存后需发布配置',
  },
  'gateway_runtime:api_file_watermark_template': {
    description: '水印模板，支持 {ip}/{identity}/{time}/{domain} 占位变量',
    placeholder: '例如：trace ip={ip} identity={identity} time={time}',
    maxLength: 256,
  },
  'gateway_runtime:api_file_watermark_content_types': {
    description: '允许水印的 Content-Type；内联 HTML 需显式加入 text/html',
    maxLength: 512,
  },
  'gateway_runtime:api_file_watermark_json_key': {
    description: 'JSON 顶层水印字段名，缺省为 _wm',
    maxLength: 64,
  },
  'gateway_runtime:api_file_watermark_include_inline_html': {
    description: '内联 HTML 追加不可见溯源注释；需同时启用水印并加入 text/html',
  },
  'software_bypass:enabled': {
    description: '资源超阈时自动纯透传，跳过全部检测与防护；保存后需发布配置',
  },
  'software_bypass:cpu_threshold_percent': {
    description: 'CPU 使用率超过该值触发旁路（%）',
    min: 1,
    max: 100,
  },
  'software_bypass:memory_threshold_percent': {
    description: '内存使用率超过该值触发旁路（%）',
    min: 1,
    max: 100,
  },
  'software_bypass:min_hold_seconds': {
    description: '旁路最短保持时间（秒）；恢复阈值比触发阈值低 5 个百分点',
    min: 1,
    max: 300,
  },
  'software_bypass:session_cookie_names': {
    description: '用于 HTTP 会话统计的 Cookie 名，逗号分隔；留空关闭会话统计',
    maxLength: 512,
  },
  // block_response 组：自定义 429/阻断响应页面（阶段5 §5.1，随发布下发网关生效；
  // 长度上限与后端 settingStringMaxLen 同口径）
  'block_response:html_title': {
    description:
      '429/阻断响应页面标题（留空使用内置默认「请求过于频繁」，渲染时整串转义）',
    maxLength: 128,
  },
  'block_response:html_body': {
    description:
      '429/阻断响应页面正文（留空使用内置默认；仅支持基础排版标签且无属性，其余内容自动转义）',
    multiline: true,
    maxLength: 4096,
  },
  'block_response:json_code': {
    description:
      'JSON 错误响应的错误码（留空使用内置默认 too_many_requests；仅允许字母数字与 _ . -）',
    maxLength: 128,
  },
  'block_response:json_message': {
    description:
      'JSON 错误响应的文案（留空使用内置默认「请求过于频繁，请稍后重试」）',
    maxLength: 512,
  },
  // api_learning 组：学习采样达标条件（消费侧 server/internal/learningjobs/conditions.go，
  // 数值范围与其校验区间一致，越界值后端会回落默认并告警）
  'api_learning:min_valid_samples': {
    description:
      '学习达标条件：有效样本数全局下限，与每个任务的样本目标取较大者',
    numeric: true,
    min: 1,
    max: 1000000,
  },
  'api_learning:min_unique_ips': {
    description:
      '学习达标条件：去重来源 IP 数下限，防止单一来源刷样本（0=不要求）',
    numeric: true,
    min: 0,
    max: 1000000,
  },
  'api_learning:min_unique_identities': {
    description:
      '学习达标条件：去重身份数下限（0=不要求；身份指纹常缺失时建议保持 0）',
    numeric: true,
    min: 0,
    max: 1000000,
  },
  'api_learning:min_learning_duration_seconds': {
    description:
      '学习达标条件：最短学习时长（秒，0=不要求；起点取首次落样时间）',
    numeric: true,
    min: 0,
    max: 31536000,
  },
  'api_learning:max_learning_duration_seconds': {
    description: '学习最长时限（秒）：超期仍未达标的学习任务置为失败并记录原因',
    numeric: true,
    min: 60,
    max: 31536000,
  },
  'api_learning:minimum_success_ratio': {
    description: '学习达标条件：有效样本 2xx/3xx 成功率下限（0~1，0=不要求）',
    numeric: true,
    min: 0,
    max: 1,
    step: 0.05,
  },
  'api_learning:auto_start_on_confirm': {
    description:
      '确认 API 接口为正式资产时默认自动启动模型学习（需具备学习启动权限；学习中或已完成学习的接口自动跳过）',
  },
  'logging:access_log_enabled': {
    description: '记录所有经过网关的访问日志（总开关，关闭后不再产生访问日志）',
  },
  'logging:capture_request_headers': {
    description: '记录请求头（敏感头自动掩码）',
  },
  'logging:capture_request_body': {
    description:
      '记录请求体（敏感键值自动脱敏，超限截断）；开启会增加存储占用，建议排障时临时开启',
  },
  'logging:capture_response_headers': {
    description: '记录响应头（敏感头自动掩码）',
  },
  'logging:capture_response_body': {
    description:
      '记录响应体（仅文本类，超限截断）；开启会增加存储占用，建议排障时临时开启',
  },
  'logging:body_limit_kb': {
    description: '单条日志请求/响应头体最大记录长度（KB），超出部分截断',
    min: 1,
    max: 1024,
  },
  'logging:retention_days': {
    description: '访问日志保留天数，到期自动清理',
    min: 1,
    max: 90,
  },
  'logging:syslog_enabled': {
    description: 'syslog 外发总开关，关闭后不再向 syslog 服务器外发任何日志',
  },
  'logging:syslog_protocol': {
    description: 'syslog 传输协议',
    options: [
      { label: 'UDP', value: 'udp' },
      { label: 'TCP', value: 'tcp' },
    ],
  },
  'logging:syslog_address': {
    description: 'syslog 服务器地址与端口（支持 IPv4/IPv6 或域名）',
  },
  'logging:syslog_facility': {
    description: 'RFC5424 日志设施号，默认 1（用户级）',
    min: 0,
    max: 23,
  },
  'logging:syslog_forward_security_events': {
    description: '外发安全事件到 syslog',
  },
  'logging:syslog_forward_access_control_events': {
    description: '外发访问控制事件到 syslog',
  },
  'logging:syslog_forward_access_logs': {
    description: '外发全量访问日志到 syslog（数据量大，谨慎开启）',
  },
  'logging:syslog_forward_operation_audits': {
    description: '外发操作审计到 syslog',
  },
  'logging:syslog_forward_login_logs': {
    description: '外发登录日志到 syslog',
  },
  'logging:syslog_forward_system_alerts': {
    description: '外发系统告警到 syslog',
  },
  // network 组：节点基础网络服务（NTP 时间同步 / DNS 解析），值为逗号分隔字符串，
  // 通用字符串输入框渲染，后端下发节点生效
  'network:ntp_servers': {
    description: 'NTP 时间同步服务器，逗号分隔，最多 4 个',
    placeholder: '如 pool.ntp.org,time.aliyun.com',
    maxLength: 256,
  },
  'network:dns_servers': {
    description: 'DNS 服务器，逗号分隔，最多 4 个，留空继承宿主机',
    placeholder: '如 223.5.5.5,223.6.6.6',
    maxLength: 256,
  },
}

/**
 * 拆分 syslog_address（host:port，IPv6 为 [host]:port）。
 * 无法识别端口时整体作为 host 返回，port 为空串（交由保存前校验拦截）。
 */
function splitSyslogAddress(value: string): { host: string; port: string } {
  const v = value.trim()
  const m = /^\[(.*)]:(\d*)$/.exec(v)
  if (m) return { host: m[1], port: m[2] }
  // 仅含一个冒号时按 host:port 拆分；多个冒号（裸 IPv6 等）视为无端口
  const idx = v.lastIndexOf(':')
  if (idx >= 0 && v.indexOf(':') === idx)
    return { host: v.slice(0, idx), port: v.slice(idx + 1) }
  return { host: v, port: '' }
}

/** 组合 host:port，IPv6 字面量自动加方括号（已带括号的不重复添加） */
function joinSyslogAddress(host: string, port: string): string {
  const h = host.trim()
  const wrapped = h.startsWith('[') && h.endsWith(']')
  return `${h.includes(':') && !wrapped ? `[${h}]` : h}:${port}`
}

/** syslog 服务器地址校验：IPv4/IPv6 字面量或合法域名，禁止协议/路径/端口/空白 */
function validateSyslogHost(raw: string): string | null {
  const v = raw.trim()
  if (!v) return '请输入 syslog 服务器地址'
  if (/\s/.test(v)) return '服务器地址不能包含空白字符'
  if (v.includes('://') || v.includes('/'))
    return '服务器地址不能包含协议或路径'
  // 允许用户输入带方括号的 IPv6，校验前去掉
  const bare = v.startsWith('[') && v.endsWith(']') ? v.slice(1, -1) : v
  if (isValidIPv4(bare) || isValidIPv6(bare)) return null
  if (bare.includes(':')) return 'IPv6 地址格式不正确'
  if (v.includes('*')) return '服务器地址不支持通配符'
  const label = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/
  const ok = v
    .toLowerCase()
    .split('.')
    .every((l) => label.test(l))
  return ok ? null : '服务器地址需为 IPv4/IPv6 地址或合法域名'
}

function SettingGroupPanel({ group }: { group: string }) {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canUpdate = hasPermission(permissions, 'system_settings.update')
  const canSyslogTest = hasPermission(permissions, 'logging.syslog_test')
  // 每行的本地编辑值：key 为设置项 id
  const [drafts, setDrafts] = useState<Record<string, string>>({})
  const [detailRecord, setDetailRecord] = useState<SettingItem | null>(null)

  const listQuery = useQuery({
    queryKey: ['settings', group],
    queryFn: () => settingsApi.list(group),
  })
  const visibleItems = (listQuery.data?.items ?? []).filter(
    (item) =>
      group !== 'gateway_runtime' ||
      item.setting_key.startsWith('api_file_watermark_'),
  )

  useEffect(() => {
    setDrafts({})
  }, [group])

  // 草稿统一按字符串存储（Switch/Input 同构），提交时按后端 value_type 还原 JSON 类型
  const coerceValue = (
    item: SettingItem,
    raw: string,
  ): string | number | boolean => {
    if (item.value_type === 'boolean') return raw === 'true'
    if (item.value_type === 'integer') return Number(raw)
    return raw
  }

  const draftValue = (item: SettingItem): string =>
    drafts[item.id] ?? String(item.setting_value ?? '')
  const isDirty = (item: SettingItem): boolean =>
    drafts[item.id] !== undefined && drafts[item.id] !== String(item.setting_value ?? '')

  const updateMutation = useMutation({
    mutationFn: (item: SettingItem) =>
      settingsApi.update({
        setting_group: item.setting_group,
        setting_key: item.setting_key,
        setting_value: coerceValue(item, draftValue(item)),
        version: item.version,
      }),
    onSuccess: () => {
      message.success('保存成功')
      void queryClient.invalidateQueries({ queryKey: ['settings', group] })
    },
    onError: (e) => {
      if (e instanceof ApiError && e.code === 'RESOURCE_CONFLICT') {
        message.error('该设置已被他人修改，请刷新后重试')
        void queryClient.invalidateQueries({ queryKey: ['settings', group] })
        return
      }
      message.error(e instanceof ApiError ? e.message : '保存失败')
    },
  })

  const syslogTestMutation = useMutation({
    mutationFn: () => settingsApi.syslogTest(),
    onSuccess: (data) => {
      message.success(data.message)
    },
    onError: (e) => {
      message.error(e instanceof ApiError ? e.message : '发送测试消息失败')
    },
  })

  const handleSave = (item: SettingItem) => {
    const meta = SETTING_META[`${item.setting_group}:${item.setting_key}`]
    if (item.value_type === 'integer' || meta?.numeric) {
      const raw = draftValue(item).trim()
      const n = Number(raw)
      if (raw === '' || !Number.isFinite(n)) {
        message.error('请输入数值')
        return
      }
      if (item.value_type === 'integer' && !Number.isInteger(n)) {
        message.error('请输入整数')
        return
      }
      if (
        (meta?.min !== undefined && n < meta.min) ||
        (meta?.max !== undefined && n > meta.max)
      ) {
        message.error(`取值需在 ${meta?.min ?? '-∞'}~${meta?.max ?? '+∞'} 之间`)
        return
      }
    }
    if (
      item.setting_group === 'logging' &&
      item.setting_key === 'syslog_address'
    ) {
      const { host, port } = splitSyslogAddress(draftValue(item))
      const hostError = validateSyslogHost(host)
      if (hostError) {
        message.error(hostError)
        return
      }
      const portNum = /^\d+$/.test(port) ? Number(port) : NaN
      if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
        message.error('端口必须为 1-65535 的整数')
        return
      }
    }
    if (group === 'gateway_runtime') {
      if (
        item.setting_key === 'api_file_watermark_enabled' &&
        draftValue(item) === 'true'
      ) {
        const template = visibleItems.find(
          (entry) => entry.setting_key === 'api_file_watermark_template',
        )
        if (!template || draftValue(template).trim() === '') {
          message.error('启用水印前请先填写水印模板')
          return
        }
      }
      if (
        item.setting_key === 'api_file_watermark_include_inline_html' &&
        draftValue(item) === 'true'
      ) {
        const contentTypes = visibleItems.find(
          (entry) => entry.setting_key === 'api_file_watermark_content_types',
        )
        const allowsHTML =
          contentTypes !== undefined &&
          draftValue(contentTypes)
            .split(',')
            .some((value) => value.trim().toLowerCase() === 'text/html')
        if (!allowsHTML) {
          message.error('内联 HTML 需将 text/html 加入 Content-Type 白名单')
          return
        }
      }
    }
    updateMutation.mutate(item)
  }

  const renderEditor = (item: SettingItem) => {
    if (item.is_sensitive) {
      return <Typography.Text type="secondary">********</Typography.Text>
    }
    const meta = SETTING_META[`${item.setting_group}:${item.setting_key}`]
    const value = draftValue(item)
    const setValue = (v: string) => setDrafts((d) => ({ ...d, [item.id]: v }))
    if (!canUpdate) {
      if (item.value_type === 'boolean') {
        return (
          <Tag color={value === 'true' ? 'green' : 'default'}>
            {value === 'true' ? '已开启' : '已关闭'}
          </Tag>
        )
      }
      if (meta?.options) {
        const matched = meta.options.find((opt) => opt.value === value)
        return <Typography.Text>{matched?.label ?? value}</Typography.Text>
      }
      return <Typography.Text>{value}</Typography.Text>
    }
    // syslog_address 存储契约仍是 host:port，前端拆为「服务器地址 + 端口」两个控件编辑
    if (
      item.setting_group === 'logging' &&
      item.setting_key === 'syslog_address'
    ) {
      const { host, port } = splitSyslogAddress(value)
      return (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            flexWrap: 'wrap',
          }}
        >
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            服务器地址
          </Typography.Text>
          <Input
            value={host}
            placeholder="IPv4/IPv6 或域名"
            onChange={(e) => setValue(joinSyslogAddress(e.target.value, port))}
            style={{ width: 220 }}
          />
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            端口
          </Typography.Text>
          <InputNumber
            value={/^\d+$/.test(port) ? Number(port) : null}
            min={1}
            max={65535}
            placeholder="1-65535"
            onChange={(v) =>
              setValue(joinSyslogAddress(host, v === null ? '' : String(v)))
            }
            style={{ width: 110 }}
          />
        </div>
      )
    }
    if (item.value_type === 'boolean') {
      return (
        <Switch
          checked={value === 'true'}
          onChange={(checked) => setValue(checked ? 'true' : 'false')}
        />
      )
    }
    if (item.value_type === 'integer' || meta?.numeric) {
      return (
        <InputNumber
          value={value === '' ? null : Number(value)}
          min={meta?.min}
          max={meta?.max}
          step={meta?.step}
          onChange={(v) => setValue(v === null ? '' : String(v))}
          style={{ width: 160 }}
        />
      )
    }
    if (meta?.options) {
      return (
        <Select
          value={value}
          options={meta.options}
          onChange={(v) => setValue(v)}
          style={{ width: 160 }}
        />
      )
    }
    if (meta?.multiline) {
      return (
        <Input.TextArea
          value={value}
          placeholder={meta?.placeholder}
          maxLength={meta?.maxLength}
          rows={5}
          onChange={(e) => setValue(e.target.value)}
          style={{ width: 480 }}
        />
      )
    }
    return (
      <Input
        value={value}
        placeholder={meta?.placeholder}
        maxLength={meta?.maxLength}
        onChange={(e) => setValue(e.target.value)}
        style={{ width: 280 }}
      />
    )
  }

  const columns: ColumnsType<SettingItem> = [
    {
      title: '设置项',
      key: 'name',
      width: 320,
      render: (_, item) => (
        <div>
          <div style={{ color: 'rgba(0, 0, 0, 0.88)', fontWeight: 500 }}>
            {SETTING_META[`${item.setting_group}:${item.setting_key}`]
              ?.description ?? item.description}
            {item.is_sensitive && <Tag style={{ marginLeft: 8 }}>敏感</Tag>}
          </div>
          <div style={{ marginTop: 4 }}>
            <Typography.Text code style={{ fontSize: 12 }}>
              {item.setting_key}
            </Typography.Text>
          </div>
        </div>
      ),
    },
    {
      title: '当前值',
      key: 'value',
      render: (_, item) => renderEditor(item),
    },
    {
      title: '更新时间',
      dataIndex: 'updated_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    ...(canUpdate
      ? [
          {
            title: '操作',
            key: 'actions',
            width: 100,
            render: (_: unknown, item: SettingItem) => (
              <Button
                type="link"
                size="small"
                disabled={item.is_sensitive || !isDirty(item)}
                loading={
                  updateMutation.isPending &&
                  updateMutation.variables?.id === item.id
                }
                onClick={() => handleSave(item)}
              >
                保存
              </Button>
            ),
          } satisfies ColumnsType<SettingItem>[number],
        ]
      : []),
  ]

  if (listQuery.isError) {
    return (
      <Alert
        type="error"
        showIcon
        message="加载系统设置失败"
        description={
          listQuery.error instanceof ApiError
            ? listQuery.error.message
            : undefined
        }
      />
    )
  }

  return (
    <>
      {group === 'logging' && (
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
          message="开启请求/响应体记录会显著增加存储占用，建议仅在排障时临时开启，用完及时关闭。"
        />
      )}
      {group === 'block_response' && (
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
          message="自定义 CC 限速（429）/阻断时的响应页面与 JSON 错误文案，全部留空时使用内置默认。保存后需在「配置发布」执行发布才下发网关生效；HTML 正文仅保留基础排版标签（自动过滤脚本与属性），请求编号与 Retry-After 行为不变。如需维护多套自定义样式、多历史版本、覆盖 403 拦截页或按应用/场景分别绑定，请前往「应用防护策略 → 拦截页面」。"
        />
      )}
      {group === 'software_bypass' && (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 16 }}
          message="自动旁路优先保障业务连通性：任一资源超过阈值后，新请求将跳过全部检测与防护。CPU/内存需低于各自恢复阈值（触发值减 5 个百分点）且达到最短保持时间后恢复。保存后需在「配置发布」执行发布。"
        />
      )}
      {group === 'api_learning' && (
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
          message="以上条件全部满足才判定采样完成，并自动生成参数模型候选版本；样本目标可在批量启动学习或学习中心设置，也可开启「确认资产时自动启动学习」默认开关。"
        />
      )}
      {group === 'logging' && canSyslogTest && (
        <Button
          style={{ marginBottom: 16 }}
          loading={syslogTestMutation.isPending}
          onClick={() => syslogTestMutation.mutate()}
        >
          发送测试消息
        </Button>
      )}
      {group === 'gateway_runtime' && (
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
          message="水印用于外发内容溯源；默认关闭。启用前需配置模板，内联 HTML 还需显式加入 text/html；逐项保存后需在「配置发布」执行发布。"
        />
      )}
      <SmartTable<SettingItem>
        storageKey="system-settings"
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={visibleItems}
        pagination={false}
        onRow={(record) => ({
          onDoubleClick: () => setDetailRecord(record),
          style: { cursor: 'pointer' },
        })}
      />
      <RecordDetailDrawer
        open={detailRecord !== null}
        title="设置项详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </>
  )
}

/** 设置来源标签：界面设置 / 环境变量 / 未配置 */
function SourceTag({ source }: { source: 'ui' | 'env' | '' }) {
  if (source === 'ui') return <Tag color="blue">界面设置</Tag>
  if (source === 'env') return <Tag>环境变量</Tag>
  return <Tag>未配置</Tag>
}

/**
 * APM 性能监控面板（自定义卡片，非通用设置列表：enabled / clickhouse_dsn 无数据库种子行，
 * 由 GET/PUT /apm/settings 承载，界面设置优先于 .env 且立即生效）。
 */
function ApmSettingsPanel() {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canUpdate = hasPermission(permissions, 'system_settings.update')
  // enabledDraft 为 null 表示未改动；dsnTouched 区分「未触碰（留空=不变）」与「显式清空」
  const [enabledDraft, setEnabledDraft] = useState<boolean | null>(null)
  const [dsnDraft, setDsnDraft] = useState('')
  const [dsnTouched, setDsnTouched] = useState(false)

  const settingsQuery = useQuery({
    queryKey: ['apm-settings'],
    queryFn: () => apmSettingsApi.get(),
  })
  const settings = settingsQuery.data

  const updateMutation = useMutation({
    mutationFn: (body: UpdateApmSettingsBody) => apmSettingsApi.update(body),
    onSuccess: () => {
      message.success('保存成功')
      setEnabledDraft(null)
      setDsnDraft('')
      setDsnTouched(false)
      void queryClient.invalidateQueries({ queryKey: ['apm-settings'] })
      // apm_enabled 门控 APM 菜单，保存后立即刷新产品能力状态
      void useProductStore.getState().load()
    },
    onError: (e) => {
      message.error(e instanceof ApiError ? e.message : '保存失败')
    },
  })

  if (settingsQuery.isError) {
    return (
      <Alert
        type="error"
        showIcon
        message="加载 APM 设置失败"
        description={
          settingsQuery.error instanceof ApiError
            ? settingsQuery.error.message
            : undefined
        }
      />
    )
  }
  if (!settings) {
    return <Spin />
  }

  // 显式清空（当前已配置界面覆盖时）= 提交 clickhouse_dsn:"" 回退环境变量，需二次确认
  const clearingDsn =
    dsnTouched && dsnDraft === '' && settings.clickhouse_dsn_set
  const dirty =
    enabledDraft !== null || (dsnTouched && dsnDraft !== '') || clearingDsn

  const handleSave = () => {
    const body: UpdateApmSettingsBody = {}
    if (enabledDraft !== null) body.enabled = enabledDraft
    if (dsnTouched && dsnDraft !== '') body.clickhouse_dsn = dsnDraft
    else if (clearingDsn) body.clickhouse_dsn = ''
    updateMutation.mutate(body)
  }

  const saveButton = (
    <Button
      type="primary"
      disabled={!canUpdate || !dirty}
      loading={updateMutation.isPending}
      onClick={clearingDsn ? undefined : handleSave}
    >
      保存
    </Button>
  )

  return (
    <>
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        message="界面设置优先于 .env 环境变量（APM_ENABLED / APM_CLICKHOUSE_DSN）；修改立即生效，无需重启。"
      />
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          gap: 16,
          maxWidth: 560,
        }}
      >
        <div>
          <div style={{ marginBottom: 8, fontWeight: 500 }}>
            启用 APM 业务性能监控
          </div>
          <Switch
            checked={enabledDraft ?? settings.enabled}
            disabled={!canUpdate}
            onChange={(checked) => setEnabledDraft(checked)}
          />
          <Typography.Text
            type="secondary"
            style={{ marginLeft: 8, fontSize: 12 }}
          >
            立即生效，无需重启服务
          </Typography.Text>
        </div>
        <div>
          <div style={{ marginBottom: 8, fontWeight: 500 }}>
            ClickHouse 连接串
          </div>
          <Input.Password
            value={dsnDraft}
            allowClear
            disabled={!canUpdate}
            placeholder={
              settings.clickhouse_dsn_set
                ? '已配置（留空保持不变）'
                : 'clickhouse://apm_writer:密码@主机:9000/apm'
            }
            onChange={(e) => {
              setDsnDraft(e.target.value)
              setDsnTouched(true)
            }}
          />
        </div>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            flexWrap: 'wrap',
          }}
        >
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            总开关来源
          </Typography.Text>
          <SourceTag source={settings.enabled_source} />
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            连接串来源
          </Typography.Text>
          <SourceTag source={settings.clickhouse_dsn_source} />
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            ClickHouse 状态
          </Typography.Text>
          {settings.ch_connected ? (
            <Tag color="success">已连接</Tag>
          ) : (
            <Tag>未连接</Tag>
          )}
        </div>
        <div>
          {clearingDsn ? (
            <Popconfirm
              title="清除 ClickHouse 连接串"
              description="清除后将回退到环境变量 APM_CLICKHOUSE_DSN"
              okText="清除"
              cancelText="取消"
              onConfirm={handleSave}
            >
              {saveButton}
            </Popconfirm>
          ) : (
            saveButton
          )}
        </div>
      </div>
    </>
  )
}

export default function SystemSettingsPage() {
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canRead = hasPermission(permissions, 'system_settings.read')
  // APM tab 为敏感运维配置，仅 system_settings.read 可见
  const tabs = GROUP_TABS.filter((t) => t.key !== 'apm' || canRead)
  return (
    <Card title="系统设置">
      <Tabs
        defaultActiveKey="password"
        items={tabs.map((t) => ({
          key: t.key,
          label: t.label,
          children:
            t.key === 'apm' ? (
              <ApmSettingsPanel />
            ) : (
              <SettingGroupPanel group={t.key} />
            ),
        }))}
      />
    </Card>
  )
}
