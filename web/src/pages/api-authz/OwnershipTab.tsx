import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Input, Space, Tooltip, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { apiAuthzApi, type ApiObjectOwnership } from '../../api/apiAuthz'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'
import { formatDateTime } from '../../utils/format'
import EndpointSelect from './EndpointSelect'
import { useEndpointOptions } from './useEndpointOptions'

/** 对象权属（BOLA 基线，只读）：由权属清扫作业从运行时流量生产，按最近访问倒序 */
export default function OwnershipTab() {
  const [endpointId, setEndpointId] = useState<string | undefined>()
  const [identity, setIdentity] = useState<string | undefined>()
  const [objectId, setObjectId] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [detailRecord, setDetailRecord] = useState<ApiObjectOwnership | null>(null)

  const { labelOf } = useEndpointOptions()

  const listQuery = useQuery({
    queryKey: ['api-authz', 'ownership', endpointId, identity, objectId, page, pageSize],
    queryFn: () =>
      apiAuthzApi.listOwnership({
        endpoint_id: endpointId,
        identity,
        object_id: objectId,
        page,
        page_size: pageSize,
      }),
  })

  const columns: ColumnsType<ApiObjectOwnership> = [
    {
      title: '身份指纹',
      dataIndex: 'identity_fingerprint',
      width: 200,
      ellipsis: true,
      render: (v: string) => (
        <Tooltip title={v}>
          <Typography.Text code>{v}</Typography.Text>
        </Tooltip>
      ),
    },
    {
      title: '接口',
      dataIndex: 'endpoint_id',
      width: 220,
      ellipsis: true,
      render: (v: string) => {
        const label = labelOf(v)
        return (
          <Tooltip title={label ? undefined : v}>
            <Typography.Text code>{label ?? v}</Typography.Text>
          </Tooltip>
        )
      },
    },
    {
      title: '对象类型',
      dataIndex: 'object_type',
      width: 120,
      ellipsis: true,
      render: (v: string) => v || '-',
    },
    {
      title: '对象 ID',
      dataIndex: 'object_id',
      ellipsis: true,
      render: (v: string) => (
        <Tooltip title={v}>
          <Typography.Text code>{v}</Typography.Text>
        </Tooltip>
      ),
    },
    { title: '访问次数', dataIndex: 'access_count', width: 100 },
    {
      title: '首次访问',
      dataIndex: 'first_seen',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '最近访问',
      dataIndex: 'last_seen',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
  ]

  return (
    <>
      <Typography.Paragraph type="secondary">
        权属基线由系统从运行时流量自动生产（只读）：记录「身份指纹 ↔ 对象」的归属关系，是 BOLA 评估的证据来源。
      </Typography.Paragraph>
      <Space style={{ marginBottom: 16 }} wrap>
        <div style={{ width: 260 }}>
          <EndpointSelect
            allowClear
            placeholder="按接口过滤"
            value={endpointId}
            onChange={(v) => {
              setEndpointId(v)
              setPage(1)
            }}
          />
        </div>
        <Input.Search
          placeholder="身份指纹"
          allowClear
          style={{ width: 240 }}
          onSearch={(v) => {
            setIdentity(v.trim() || undefined)
            setPage(1)
          }}
        />
        <Input.Search
          placeholder="对象 ID"
          allowClear
          style={{ width: 240 }}
          onSearch={(v) => {
            setObjectId(v.trim() || undefined)
            setPage(1)
          }}
        />
      </Space>
      <QueryErrorAlert error={listQuery.error} />
      <SmartTable<ApiObjectOwnership>
        storageKey="api-authz-ownership"
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        scroll={{ x: 1300 }}
        onRow={(record) => ({ onDoubleClick: () => setDetailRecord(record), style: { cursor: 'pointer' } })}
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
        title="权属详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </>
  )
}
