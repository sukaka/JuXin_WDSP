import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Button, Card, Descriptions, Drawer, Input, Select, Space, Table, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { apiRuntimeEventsApi } from '../../api/apiAssets'
import type { ApiRuntimeEvent, ApiRuntimeEventDetail } from '../../api/apiSecurity'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { AuthzEnforcementBlock } from '../../components/AuthzEnforcement'
import { extractAuthzEnforcement } from '../../utils/authzEnforcement'
import { formatDateTime } from '../../utils/format'
import { API_DETECTOR_META } from '../../utils/stage8'
import {
  JWT_REASON_CODE_LABELS,
  JWT_UNVERIFIED_HINT,
  JWT_VERIFICATION_STATUS_META,
} from '../../utils/jwtTrust'
import type { JwtVerificationInfo } from '../../types'

/**
 * 运行时事件记录（含迁移 000127 的 jwt_verification 投影）。
 * ApiRuntimeEvent 契约定义在 api/apiSecurity.ts（本次改动范围外），
 * JWT 验证摘要在此本地扩展；字段形态与 api_runtime_events.jwt_verification 列
 * （网关 dynamic_security/events.JWTVerification JSON，可空）一致。
 */
type RuntimeEventRecord = ApiRuntimeEvent & {
  /** JWT 信任链验证摘要（WDSP P0-03；历史事件/未评估请求为 NULL，空态不渲染） */
  jwt_verification?: JwtVerificationInfo | null
  /** 最终处置记录（WDSP P0-04，迁移 000131 可空列；NG-AZ-03 起可内嵌
      authz_enforcement 实断证据——空态不渲染，消费端容忍缺失） */
  final_decision?: Record<string, unknown> | null
}

/** 最终动作展示映射（与网关决策动作枚举一致；MASK_RESPONSE 为响应脱敏动作） */
const FINAL_ACTION_META: Record<string, { color: string; label: string }> = {
  ALLOW: { color: 'green', label: '放行' },
  OBSERVE: { color: 'gold', label: '观察' },
  BLOCK: { color: 'red', label: '阻断' },
  RATE_LIMIT: { color: 'orange', label: '限速' },
  TEMP_BLOCK: { color: 'volcano', label: '临时封禁' },
  MASK_RESPONSE: { color: 'purple', label: '响应脱敏' },
}

/** 风险级别展示映射（与网关风险分级枚举一致） */
const RISK_LEVEL_META: Record<string, { color: string; label: string }> = {
  NONE: { color: 'default', label: '无' },
  LOW: { color: 'blue', label: '低' },
  MEDIUM: { color: 'orange', label: '中' },
  HIGH: { color: 'red', label: '高' },
  CRITICAL: { color: 'magenta', label: '严重' },
  INFO: { color: 'default', label: '信息' },
}

/** 认证方式展示名（空串 = 匿名或未识别） */
const AUTH_TYPE_LABEL: Record<string, string> = {
  bearer_or_basic: 'Bearer/Basic',
  api_key: 'API Key',
  cookie_session: 'Cookie 会话',
}

/** 可空文本展示：NULL/空串统一占位符 */
function dash(v?: string | number | null): string | number {
  return v === null || v === undefined || v === '' ? '-' : v
}

/** 检测明细表格列（details 数组表格化；证据键值逐行展示） */
const detailColumns: ColumnsType<ApiRuntimeEventDetail> = [
  { title: '检测器', dataIndex: 'detector', width: 130, render: (v: string) => <StatusTag value={v} map={API_DETECTOR_META} /> },
  { title: '规则 ID', dataIndex: 'rule_id', width: 120, render: dash },
  { title: '类别', dataIndex: 'category', width: 130, render: dash },
  {
    title: '级别',
    dataIndex: 'severity',
    width: 90,
    render: (v: string) => (v ? <StatusTag value={v} map={RISK_LEVEL_META} /> : '-'),
  },
  { title: '加分', dataIndex: 'score_delta', width: 70, render: dash },
  { title: '信息', dataIndex: 'message', ellipsis: true, render: dash },
  {
    title: '证据（已脱敏）',
    key: 'evidence',
    ellipsis: true,
    render: (_, r) => {
      const entries = Object.entries(r.evidence ?? {})
      if (entries.length === 0) return '-'
      return (
        <div style={{ fontSize: 12, lineHeight: '20px' }}>
          {entries.map(([k, v]) => (
            <div key={k}>
              <Typography.Text code style={{ fontSize: 12 }}>
                {k}
              </Typography.Text>
              <Typography.Text style={{ fontSize: 12 }}>: {v}</Typography.Text>
            </div>
          ))}
        </div>
      )
    },
  },
]

/**
 * API 运行时事件（WDSP / 阶段8 + P0 审计溯源）：统一主事件列表与详情。
 * client 为 apiAssets.ts 的 apiRuntimeEventsApi（分页项按 ApiRuntimeEvent 解读，
 * 迁移 000030/000035 的审计维度列在旧版网关事件上可能为 NULL）。
 */
export default function ApiRuntimeEventsPage() {
  const [endpointKey, setEndpointKey] = useState('')
  const [appliedEndpointKey, setAppliedEndpointKey] = useState('')
  const [finalAction, setFinalAction] = useState<string | undefined>()
  const [fingerprint, setFingerprint] = useState('')
  const [appliedFp, setAppliedFp] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [selected, setSelected] = useState<RuntimeEventRecord | null>(null)

  const listQuery = useQuery({
    queryKey: ['api-runtime-events', appliedEndpointKey, finalAction, appliedFp, page, pageSize],
    queryFn: () =>
      apiRuntimeEventsApi.list({
        endpoint_key: appliedEndpointKey || undefined,
        final_action: finalAction,
        identity_fingerprint: appliedFp || undefined,
        page,
        page_size: pageSize,
      }),
  })

  // apiRuntimeEventsApi 分页项为 Record<string, unknown>，按 RuntimeEventRecord 契约解读
  const items = (listQuery.data?.items ?? []) as unknown as RuntimeEventRecord[]

  const columns: ColumnsType<RuntimeEventRecord> = [
    {
      title: '时间',
      dataIndex: 'occurred_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '接口',
      dataIndex: 'endpoint_key',
      ellipsis: true,
      render: (v: string) => (v ? <Typography.Text code>{v}</Typography.Text> : '-'),
    },
    { title: '方法', dataIndex: 'method', width: 80, render: dash },
    { title: '客户端 IP', dataIndex: 'client_ip', width: 130, render: dash },
    { title: '风险分', dataIndex: 'risk_score', width: 80 },
    {
      title: '风险级',
      dataIndex: 'risk_level',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={RISK_LEVEL_META} />,
    },
    {
      title: '最终动作',
      dataIndex: 'final_action',
      width: 110,
      render: (v: string) => <StatusTag value={v} map={FINAL_ACTION_META} />,
    },
    {
      title: '耗时',
      dataIndex: 'latency_ms',
      width: 90,
      render: (v: number | null) => (v === null || v === undefined ? '-' : `${v} ms`),
    },
    {
      title: '操作',
      key: 'actions',
      width: 80,
      fixed: 'right',
      render: (_, record) => (
        <Button type="link" size="small" onClick={() => setSelected(record)}>
          详情
        </Button>
      ),
    },
  ]

  const details = selected?.details ?? []
  const jwt = selected?.jwt_verification
  const authzEnforcement = extractAuthzEnforcement(selected?.final_decision)

  return (
    <Card title="API 运行时事件">
      <Typography.Paragraph type="secondary">
        统一 API 运行时主事件（按请求幂等，一请求一事件），按发生时间倒序；详情含客户端
        IP/方法/原始路径/耗时/模型与策略版本等审计维度及检测明细。
      </Typography.Paragraph>
      <QueryErrorAlert error={listQuery.error} />
      <Space style={{ marginBottom: 16 }} wrap>
        <Input.Search
          placeholder="接口键（精确匹配，如 GET /v1/users/{id}）"
          allowClear
          style={{ width: 340 }}
          value={endpointKey}
          onChange={(e) => setEndpointKey(e.target.value)}
          onSearch={(v) => {
            setAppliedEndpointKey(v.trim())
            setPage(1)
          }}
        />
        <Select
          placeholder="最终动作"
          allowClear
          style={{ width: 150 }}
          value={finalAction}
          options={Object.entries(FINAL_ACTION_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => {
            setFinalAction(v)
            setPage(1)
          }}
        />
        <Input.Search
          placeholder="身份指纹（精确匹配）"
          allowClear
          style={{ width: 320 }}
          value={fingerprint}
          onChange={(e) => setFingerprint(e.target.value)}
          onSearch={(v) => {
            setAppliedFp(v.trim())
            setPage(1)
          }}
        />
      </Space>
      <SmartTable<RuntimeEventRecord>
        storageKey="api-runtime-events"
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={items}
        scroll={{ x: 1400 }}
        onRow={(record) => ({
          onDoubleClick: () => setSelected(record),
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
      <Drawer
        title="运行时事件详情"
        open={selected !== null}
        onClose={() => setSelected(null)}
        width={760}
        destroyOnHidden
      >
        {selected ? (
          <Space direction="vertical" size={16} style={{ width: '100%' }}>
            <Descriptions column={2} size="small" bordered>
              <Descriptions.Item label="请求 ID" span={2}>
                <Typography.Text code>{selected.request_id || '-'}</Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label="接口" span={2}>
                {selected.endpoint_key ? <Typography.Text code>{selected.endpoint_key}</Typography.Text> : '-'}
              </Descriptions.Item>
              <Descriptions.Item label="方法">{dash(selected.method)}</Descriptions.Item>
              <Descriptions.Item label="原始路径">
                {selected.raw_path ? <Typography.Text code>{selected.raw_path}</Typography.Text> : '-'}
              </Descriptions.Item>
              <Descriptions.Item label="客户端 IP">{dash(selected.client_ip)}</Descriptions.Item>
              <Descriptions.Item label="响应状态码">{dash(selected.response_status)}</Descriptions.Item>
              <Descriptions.Item label="风险分">{selected.risk_score}</Descriptions.Item>
              <Descriptions.Item label="风险级">
                <StatusTag value={selected.risk_level} map={RISK_LEVEL_META} />
              </Descriptions.Item>
              <Descriptions.Item label="最终动作">
                <StatusTag value={selected.final_action} map={FINAL_ACTION_META} />
              </Descriptions.Item>
              <Descriptions.Item label="耗时">
                {selected.latency_ms === null || selected.latency_ms === undefined ? '-' : `${selected.latency_ms} ms`}
              </Descriptions.Item>
              <Descriptions.Item label="身份指纹" span={2}>
                {selected.identity_fingerprint ? (
                  <Typography.Text code copyable={{ text: selected.identity_fingerprint }}>
                    {selected.identity_fingerprint}
                  </Typography.Text>
                ) : (
                  '匿名'
                )}
              </Descriptions.Item>
              <Descriptions.Item label="认证方式">
                {AUTH_TYPE_LABEL[selected.auth_type] ?? dash(selected.auth_type)}
              </Descriptions.Item>
              <Descriptions.Item label="发生时间">{formatDateTime(selected.occurred_at)}</Descriptions.Item>
              <Descriptions.Item label="模型版本">{dash(selected.model_version)}</Descriptions.Item>
              <Descriptions.Item label="策略版本">{dash(selected.policy_version)}</Descriptions.Item>
              <Descriptions.Item label="事件 ID" span={2}>
                <Typography.Text code>{selected.id}</Typography.Text>
              </Descriptions.Item>
            </Descriptions>
            {/* JWT 验证信息（WDSP P0-03，迁移 000127）：仅当 jwt_verification 非空时渲染，
                历史事件/未评估请求不显示该区块；UNVERIFIED 表示策略关闭或不在校验范围，
                配合 JWT_UNVERIFIED_HINT 说明，不得解读为「非法用户」 */}
            {jwt ? (
              <div>
                <Typography.Title level={5}>JWT 验证信息</Typography.Title>
                <Descriptions column={2} size="small" bordered style={{ marginBottom: 16 }}>
                  <Descriptions.Item label="验证状态">
                    <StatusTag value={jwt.status} map={JWT_VERIFICATION_STATUS_META} />
                  </Descriptions.Item>
                  <Descriptions.Item label="原因">
                    {jwt.reason_code ? (
                      <Typography.Text>
                        {JWT_REASON_CODE_LABELS[jwt.reason_code] ?? jwt.reason_code}
                        <Typography.Text code style={{ marginLeft: 6, fontSize: 12 }}>
                          {jwt.reason_code}
                        </Typography.Text>
                      </Typography.Text>
                    ) : (
                      '-'
                    )}
                  </Descriptions.Item>
                  <Descriptions.Item label="策略版本">{jwt.policy_version ?? '-'}</Descriptions.Item>
                  <Descriptions.Item label="密钥集版本">{jwt.keyset_version || '-'}</Descriptions.Item>
                  <Descriptions.Item label="可信主体指纹" span={2}>
                    {jwt.verified_principal_id ? (
                      <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }} copyable>
                        {jwt.verified_principal_id}
                      </Typography.Text>
                    ) : (
                      '-'
                    )}
                  </Descriptions.Item>
                  <Descriptions.Item label="可信租户指纹" span={2}>
                    {jwt.verified_tenant_id ? (
                      <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }} copyable>
                        {jwt.verified_tenant_id}
                      </Typography.Text>
                    ) : (
                      '-'
                    )}
                  </Descriptions.Item>
                  <Descriptions.Item label="验证时间">
                    {jwt.evaluated_at ? formatDateTime(jwt.evaluated_at) : '-'}
                  </Descriptions.Item>
                </Descriptions>
                {jwt.status === 'UNVERIFIED' && (
                  <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginTop: -8, marginBottom: 16 }}>
                    {JWT_UNVERIFIED_HINT}
                  </Typography.Paragraph>
                )}
              </div>
            ) : null}
            {/* NG-AZ-03 D7：VERIFIED_VIOLATION 实断证据（final_decision.authz_enforcement
                内嵌；BOLA 八因子/BFLA 实评键集如实呈现；历史事件无此键不渲染） */}
            {authzEnforcement ? (
              <div>
                <Typography.Title level={5}>授权实断证据</Typography.Title>
                <AuthzEnforcementBlock evidence={authzEnforcement} />
              </div>
            ) : null}
            <Typography.Title level={5} style={{ margin: 0 }}>
              检测明细（details）
            </Typography.Title>
            <Table<ApiRuntimeEventDetail>
              rowKey={(_, i) => String(i)}
              size="small"
              columns={detailColumns}
              dataSource={details}
              pagination={false}
              locale={{ emptyText: '无检测明细' }}
            />
          </Space>
        ) : null}
      </Drawer>
    </Card>
  )
}
