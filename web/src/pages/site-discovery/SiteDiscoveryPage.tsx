import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { App as AntdApp, Button, Card, Input, Select, Space, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import {
  siteDiscoveryApi,
  type SiteDiscoveryItem,
  type SiteDiscoveryProtocol,
  type SiteDiscoverySourceMode,
  type SiteDiscoveryStatus,
} from '../../api/siteDiscovery'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'

/** 处置状态展示映射（三态状态机：NEW→CONFIRMED；NEW/CONFIRMED→IGNORED；任意→NEW） */
const STATUS_META: Record<string, { color: string; label: string }> = {
  NEW: { color: 'gold', label: '新发现' },
  CONFIRMED: { color: 'green', label: '已确认' },
  IGNORED: { color: 'default', label: '已忽略' },
}

const PROTOCOL_META: Record<string, { color: string; label: string }> = {
  HTTP: { color: 'blue', label: 'HTTP' },
  HTTPS: { color: 'green', label: 'HTTPS' },
}

/** 发现来源部署模式中文映射 */
const SOURCE_MODE_META: Record<string, { color: string; label: string }> = {
  MIRROR: { color: 'blue', label: '镜像旁路' },
  ROUTED: { color: 'purple', label: '路由牵引' },
  TRANSPARENT: { color: 'cyan', label: '透明串接' },
}

/** 行内处置动作（按状态机给出；非法流转由后端最终裁决） */
type DiscoveryAction = 'confirm' | 'ignore' | 'restore'

function availableActions(status: string): DiscoveryAction[] {
  switch ((status || '').toUpperCase()) {
    case 'NEW':
      return ['confirm', 'ignore']
    case 'CONFIRMED':
      return ['ignore', 'restore']
    case 'IGNORED':
      return ['restore']
    default:
      return []
  }
}

const ACTION_LABEL: Record<DiscoveryAction, string> = {
  confirm: '确认',
  ignore: '忽略',
  restore: '恢复',
}

/**
 * 站点资产发现（docs/SITE_DISCOVERY_DESIGN.md §5）：
 * 从镜像旁路/路由牵引/透明串接流量中被动学习出的站点清单（域名+IP+端口+协议），
 * 管理员人工确认后可到「网站应用」手动接入防护；不做一键转应用、不做自动接入。
 */
export default function SiteDiscoveryPage() {
  const { message } = AntdApp.useApp()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  /** 处置按钮显隐：site_discovery.manage */
  const canManage = hasPermission(permissions, 'site_discovery.manage')

  const [status, setStatus] = useState<SiteDiscoveryStatus | undefined>('NEW')
  const [protocol, setProtocol] = useState<SiteDiscoveryProtocol | undefined>()
  const [sourceMode, setSourceMode] = useState<SiteDiscoverySourceMode | undefined>()
  const [keyword, setKeyword] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [detailRecord, setDetailRecord] = useState<SiteDiscoveryItem | null>(null)

  const listQuery = useQuery({
    queryKey: ['site-discoveries', status, protocol, sourceMode, keyword, page, pageSize],
    queryFn: () =>
      siteDiscoveryApi.list({
        status,
        protocol,
        source_mode: sourceMode,
        keyword,
        page,
        page_size: pageSize,
      }),
  })

  const actionMut = useMutation({
    mutationFn: ({ id, action }: { id: string; action: DiscoveryAction }) =>
      action === 'confirm'
        ? siteDiscoveryApi.confirm(id)
        : action === 'ignore'
          ? siteDiscoveryApi.ignore(id)
          : siteDiscoveryApi.restore(id),
    onSuccess: (_item, vars) => {
      message.success(
        vars.action === 'confirm'
          ? '已确认，可前往网站应用手动接入该站点'
          : `${ACTION_LABEL[vars.action]}成功`,
      )
      void qc.invalidateQueries({ queryKey: ['site-discoveries'] })
    },
    onError: (e) => {
      message.error(e instanceof ApiError ? e.message : '操作失败')
    },
  })

  const columns: ColumnsType<SiteDiscoveryItem> = [
    {
      title: '域名',
      dataIndex: 'domain',
      ellipsis: true,
      render: (v: string) =>
        v ? (
          <Typography.Text strong>{v}</Typography.Text>
        ) : (
          <Typography.Text type="secondary">未识别</Typography.Text>
        ),
    },
    {
      title: 'IP',
      dataIndex: 'ip',
      width: 140,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    { title: '端口', dataIndex: 'port', width: 80 },
    {
      title: '协议',
      dataIndex: 'protocol',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={PROTOCOL_META} />,
    },
    {
      title: '来源模式',
      dataIndex: 'source_mode',
      width: 110,
      render: (v: string) => <StatusTag value={v} map={SOURCE_MODE_META} />,
    },
    { title: '网关节点', dataIndex: 'gateway_node', width: 110, ellipsis: true },
    { title: '命中次数', dataIndex: 'seen_count', width: 100 },
    { title: '客户端数', dataIndex: 'client_count', width: 90 },
    {
      title: '首次发现',
      dataIndex: 'first_seen',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '最近发现',
      dataIndex: 'last_seen',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={STATUS_META} />,
    },
    {
      title: '操作',
      key: 'actions',
      width: 130,
      fixed: 'right',
      render: (_, record) =>
        canManage ? (
          <Space size={0} wrap>
            {availableActions(record.status).map((action) => (
              <Button
                key={action}
                type="link"
                size="small"
                onClick={() => actionMut.mutate({ id: record.id, action })}
              >
                {ACTION_LABEL[action]}
              </Button>
            ))}
          </Space>
        ) : (
          '-'
        ),
    },
  ]

  return (
    <Card title="站点发现">
      <Typography.Paragraph type="secondary">
        站点发现通过镜像旁路/路由牵引/透明串接流量自动学习网络中开放的站点（HTTPS 经 TLS SNI 识别域名，无需解密流量）。
        人工确认后可前往「网站应用」手动接入防护；命中次数与客户端数为近似统计指标。
      </Typography.Paragraph>
      <QueryErrorAlert error={listQuery.error} />
      <Space style={{ marginBottom: 16 }} wrap>
        <Select<SiteDiscoveryStatus>
          placeholder="状态"
          allowClear
          style={{ width: 120 }}
          value={status}
          options={Object.entries(STATUS_META).map(([value, meta]) => ({ value, label: meta.label }))}
          onChange={(v) => {
            setStatus(v)
            setPage(1)
          }}
        />
        <Select<SiteDiscoveryProtocol>
          placeholder="协议"
          allowClear
          style={{ width: 110 }}
          value={protocol}
          options={Object.keys(PROTOCOL_META).map((value) => ({ value, label: value }))}
          onChange={(v) => {
            setProtocol(v)
            setPage(1)
          }}
        />
        <Select<SiteDiscoverySourceMode>
          placeholder="来源模式"
          allowClear
          style={{ width: 130 }}
          value={sourceMode}
          options={Object.entries(SOURCE_MODE_META).map(([value, meta]) => ({ value, label: meta.label }))}
          onChange={(v) => {
            setSourceMode(v)
            setPage(1)
          }}
        />
        <Input.Search
          placeholder="搜索域名或 IP"
          allowClear
          style={{ width: 240 }}
          onSearch={(v) => {
            setKeyword(v.trim() ? v.trim() : undefined)
            setPage(1)
          }}
        />
        <Button type="link" onClick={() => navigate('/applications')}>
          前往网站应用接入
        </Button>
      </Space>
      <SmartTable<SiteDiscoveryItem>
        storageKey="site-discovery"
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        onRow={(record) => ({
          onDoubleClick: () => setDetailRecord(record),
          style: { cursor: 'pointer' },
        })}
        scroll={{ x: 1400 }}
        locale={{
          emptyText: (
            <>
              <div>暂无站点发现</div>
              <Typography.Text type="secondary">
                站点发现通过镜像旁路/路由牵引/透明串接流量自动学习网络中开放的站点
              </Typography.Text>
            </>
          ),
        }}
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
      <RecordDetailDrawer
        open={detailRecord !== null}
        title="站点发现详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </Card>
  )
}
