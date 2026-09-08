import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Select, Space, Tag, Tooltip, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { trafficAgentsApi } from '../../api/trafficAgents'
import type { TrafficHttpAssetSource } from '../../api/trafficAgents'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import { formatDateTime } from '../../utils/format'
import { ASSET_LINK_STATE_META, SOURCE_TYPE_META } from './meta'

/** 资产来源关联状态 Tag（v2 契约 §5：LINKED/UNASSIGNED/QUOTA_REJECTED/FAILED 各自成行可查） */
export function AssetLinkStateTag({ value }: { value: string }) {
  const meta = ASSET_LINK_STATE_META[value]
  const tag = <Tag color={meta?.color}>{meta?.label ?? value}</Tag>
  return meta?.tooltip ? <Tooltip title={meta.tooltip}>{tag}</Tooltip> : tag
}

const STATE_OPTIONS = Object.entries(ASSET_LINK_STATE_META).map(
  ([value, meta]) => ({ value, label: meta.label }),
)

/** 资产来源关系面板（任务书 P1-03 §4.3）：事件入库 ≠ 资产关联成功——
 * 来源三元组、绑定版本、首/末次观测与关联状态（配额拒绝/未绑定/失败）独立展示 */
export default function HttpAssetSourcesPanel({
  agentId,
  enabled = true,
}: {
  agentId: string
  enabled?: boolean
}) {
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [state, setState] = useState<string | undefined>()

  const listQuery = useQuery({
    queryKey: ['traffic-agents', 'http-asset-sources', agentId, page, pageSize, state],
    queryFn: () =>
      trafficAgentsApi.agentHttpAssetSources(agentId, {
        page,
        page_size: pageSize,
        state,
      }),
    enabled: enabled && !!agentId,
  })

  const columns: ColumnsType<TrafficHttpAssetSource> = [
    {
      title: '资产键（Host + Method + 路径模板）',
      key: 'asset',
      ellipsis: true,
      render: (_, r) => (
        <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
          {`${r.host || '-'} ${r.method} ${r.path_template}`}
        </Typography.Text>
      ),
    },
    {
      title: '来源',
      key: 'source',
      width: 200,
      render: (_, r) => {
        const meta = SOURCE_TYPE_META[r.source_type]
        return (
          <Tooltip
            title={`实例: ${r.source_instance || '-'}；代次: ${r.source_epoch}`}
          >
            <Tag color={meta?.color}>{meta?.label ?? r.source_type}</Tag>
          </Tooltip>
        )
      },
    },
    {
      title: '关联状态',
      key: 'association_state',
      width: 110,
      render: (_, r) => (
        <Space size={4} wrap>
          <AssetLinkStateTag value={r.association_state} />
          {r.last_error ? (
            <Tooltip title={r.last_error}>
              <Typography.Text type="danger" style={{ fontSize: 12 }}>
                原因
              </Typography.Text>
            </Tooltip>
          ) : null}
        </Space>
      ),
    },
    {
      title: '来源绑定',
      key: 'binding',
      width: 150,
      render: (_, r) =>
        r.application_binding_id ? (
          <Tooltip title={r.application_binding_id}>
            <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
              {`${r.application_binding_id.slice(0, 8)}…（v${r.binding_version ?? '-'}）`}
            </Typography.Text>
          </Tooltip>
        ) : (
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            未声明绑定
          </Typography.Text>
        ),
    },
    {
      title: '关联端点',
      dataIndex: 'endpoint_id',
      width: 110,
      render: (v: string | null) =>
        v ? (
          <Tooltip title={v}>
            <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
              {`${v.slice(0, 8)}…`}
            </Typography.Text>
          </Tooltip>
        ) : (
          '-'
        ),
    },
    {
      title: '首次观测',
      dataIndex: 'first_seen_at',
      width: 160,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '最后观测',
      dataIndex: 'last_seen_at',
      width: 160,
      render: (v: string) => formatDateTime(v),
    },
  ]

  return (
    <>
      <Space style={{ marginBottom: 12 }} wrap>
        <Select
          placeholder="按关联状态过滤"
          allowClear
          style={{ width: 160 }}
          options={STATE_OPTIONS}
          value={state}
          onChange={(v) => {
            setState(v)
            setPage(1)
          }}
        />
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          HTTP 事件成功入库不等于资产关联成功；未绑定/配额拒绝/关联失败在此可查
        </Typography.Text>
      </Space>
      {listQuery.isError ? (
        <QueryErrorAlert error={listQuery.error} message="加载资产来源失败" />
      ) : (
        <SmartTable<TrafficHttpAssetSource>
          storageKey="traffic-agent-http-asset-sources"
          rowKey="id"
          size="small"
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          scroll={{ x: 1080 }}
          locale={{ emptyText: '暂无资产来源记录（v2 事件产生后自动出现）' }}
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
      )}
    </>
  )
}
