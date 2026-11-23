import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Button, Card, Descriptions, Drawer, Select, Space, Tooltip, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { apiSensitiveFieldsApi, type ApiSensitiveField } from '../../api/apiSecurity'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import useBatchDelete from '../../hooks/useBatchDelete'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { formatLocation } from '../../utils/i18nLabels'
import { hasPermission } from '../../utils/permission'
import { API_SENSITIVE_TYPE_META } from '../../utils/stage8'

/** 方向词表（api_sensitive_fields.direction） */
const DIRECTION_LABEL: Record<string, string> = { REQUEST: '请求', RESPONSE: '响应' }

/** 识别来源词表（api_sensitive_fields.detection_source） */
const DETECTION_SOURCE_META: Record<string, { color: string; label: string }> = {
  AUTO: { color: 'cyan', label: '自动识别' },
  MANUAL: { color: 'purple', label: '人工标记' },
  RUNTIME: { color: 'blue', label: '运行时识别' },
}

/** 取最新脱敏样本（优先独立列，兼容旧版 source_detail） */
function getMaskedSample(record: ApiSensitiveField): string {
  return (record.masked_sample || record.source_detail?.masked_sample || '').trim()
}

/** 置信度展示（0-1 → 百分比）与口径说明 */
function ConfidenceCell({ value }: { value: number }) {
  return (
    <Tooltip title="置信度口径：字段名词表命中约 80%；值级正则验证命中 100%；同一字段重复命中取较高值">
      <span>{(value * 100).toFixed(0)}%</span>
    </Tooltip>
  )
}

/** 敏感数据（WDSP / 阶段8）：学习过程中识别出的敏感字段，按方向与数据类型筛选；
 *  支持详情查看与批量删除（api_data.manage）。 */
export default function ApiSensitiveFieldsPage() {
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'api_data.manage')

  const [direction, setDirection] = useState<string | undefined>()
  const [dataType, setDataType] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [selected, setSelected] = useState<ApiSensitiveField | null>(null)

  const listQuery = useQuery({
    queryKey: ['api-sensitive-fields', direction, dataType, page, pageSize],
    queryFn: () =>
      apiSensitiveFieldsApi.list({ direction, data_type: dataType, page, page_size: pageSize }),
  })

  const { rowSelection, batchDeleteButton } = useBatchDelete<ApiSensitiveField>({
    removeMany: (ids) => apiSensitiveFieldsApi.batchDelete(ids),
    invalidateKeys: [['api-sensitive-fields']],
    entityName: '敏感字段',
    canDelete: canManage,
  })

  const columns: ColumnsType<ApiSensitiveField> = [
    {
      title: '接口',
      dataIndex: 'endpoint_key',
      width: 200,
      ellipsis: true,
      render: (v: string, record) =>
        v ? (
          <Tooltip title={`接口 ID：${record.endpoint_id}`}>
            <Typography.Text code>{v}</Typography.Text>
          </Tooltip>
        ) : (
          <Tooltip title={`接口 ID：${record.endpoint_id}`}>
            <Typography.Text type="secondary">未知接口</Typography.Text>
          </Tooltip>
        ),
    },
    {
      title: '方向',
      dataIndex: 'direction',
      width: 80,
      render: (v: string) => DIRECTION_LABEL[v] ?? v,
    },
    {
      title: '字段路径',
      dataIndex: 'structured_path',
      ellipsis: true,
      render: (v: string) => (v ? <Typography.Text code>{v}</Typography.Text> : '-'),
    },
    {
      title: '数据类型',
      dataIndex: 'data_type',
      width: 110,
      render: (v: string) => <StatusTag value={v} map={API_SENSITIVE_TYPE_META} />,
    },
    {
      title: '脱敏样本',
      dataIndex: 'masked_sample',
      width: 170,
      ellipsis: true,
      render: (_: string | undefined, record) => {
        const sample = getMaskedSample(record)
        return sample ? (
          <Tooltip title="网关内存脱敏后的最新 1 条值级命中样本（原始明文不落库）">
            <Typography.Text code>{sample}</Typography.Text>
          </Tooltip>
        ) : (
          <Tooltip title="当前仅通过字段名匹配识别，未捕获到值级样本">
            <Typography.Text type="secondary">仅字段名识别</Typography.Text>
          </Tooltip>
        )
      },
    },
    {
      title: '置信度',
      dataIndex: 'confidence',
      width: 90,
      render: (v: number) => <ConfidenceCell value={v} />,
    },
    {
      title: '识别来源',
      dataIndex: 'detection_source',
      width: 110,
      render: (v: string) => (v ? <StatusTag value={v} map={DETECTION_SOURCE_META} /> : '-'),
    },
    {
      title: '命中次数',
      dataIndex: 'occurrence_count',
      width: 90,
    },
    {
      title: '最近发现',
      dataIndex: 'last_seen',
      width: 170,
      render: (v: string | null, record) => formatDateTime(v ?? record.updated_at),
    },
    {
      title: '操作',
      key: 'actions',
      width: 70,
      fixed: 'right',
      render: (_, record) => (
        <Button type="link" size="small" onClick={() => setSelected(record)}>
          详情
        </Button>
      ),
    },
  ]

  return (
    <Card title="敏感数据">
      <Typography.Paragraph type="secondary">
        学习过程中从请求与响应样本里识别出的敏感字段（手机号、证件号、凭据等），供脱敏与泄露检测策略参考。
      </Typography.Paragraph>
      <QueryErrorAlert error={listQuery.error} />
      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          placeholder="方向"
          allowClear
          style={{ width: 140 }}
          value={direction}
          options={[
            { value: 'REQUEST', label: '请求' },
            { value: 'RESPONSE', label: '响应' },
          ]}
          onChange={(v) => {
            setDirection(v)
            setPage(1)
          }}
        />
        <Select
          placeholder="数据类型"
          allowClear
          style={{ width: 160 }}
          value={dataType}
          options={Object.entries(API_SENSITIVE_TYPE_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => {
            setDataType(v)
            setPage(1)
          }}
        />
        {batchDeleteButton}
      </Space>
      <SmartTable<ApiSensitiveField>
        storageKey="api-sensitive-fields"
        rowKey="id"
        rowSelection={rowSelection}
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        scroll={{ x: 1420 }}
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
        title="敏感字段详情"
        open={selected !== null}
        onClose={() => setSelected(null)}
        width={640}
      >
        {selected ? (
          <Descriptions column={2} size="small" bordered>
            <Descriptions.Item label="接口" span={2}>
              {selected.endpoint_key ? (
                <Typography.Text code>{selected.endpoint_key}</Typography.Text>
              ) : (
                <Typography.Text type="secondary">未知接口</Typography.Text>
              )}
            </Descriptions.Item>
            <Descriptions.Item label="接口 ID" span={2}>
              <Typography.Text code>{selected.endpoint_id}</Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="方向">
              {DIRECTION_LABEL[selected.direction] ?? selected.direction}
            </Descriptions.Item>
            <Descriptions.Item label="数据类型">
              <StatusTag value={selected.data_type} map={API_SENSITIVE_TYPE_META} />
            </Descriptions.Item>
            <Descriptions.Item label="字段路径" span={2}>
              <Typography.Text code>{selected.structured_path}</Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="脱敏样本（最新）" span={2}>
              {getMaskedSample(selected) ? (
                <Space size={8} wrap>
                  <Typography.Text code>{getMaskedSample(selected)}</Typography.Text>
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                    已脱敏（保留最新 1 条值级命中样本，原始明文不落库）
                  </Typography.Text>
                </Space>
              ) : (
                <Typography.Text type="secondary">仅字段名识别，暂无值级脱敏样本</Typography.Text>
              )}
            </Descriptions.Item>
            <Descriptions.Item label="置信度">
              <ConfidenceCell value={selected.confidence} />
            </Descriptions.Item>
            <Descriptions.Item label="识别来源">
              {selected.detection_source ? (
                <StatusTag value={selected.detection_source} map={DETECTION_SOURCE_META} />
              ) : (
                '-'
              )}
            </Descriptions.Item>
            <Descriptions.Item label="累计命中">{selected.occurrence_count}</Descriptions.Item>
            <Descriptions.Item label="记录 ID">
              <Typography.Text code>{selected.id}</Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="首次发现">{formatDateTime(selected.first_seen)}</Descriptions.Item>
            <Descriptions.Item label="最近发现">
              {formatDateTime(selected.last_seen ?? selected.updated_at)}
            </Descriptions.Item>
            <Descriptions.Item label="创建时间">{formatDateTime(selected.created_at)}</Descriptions.Item>
            <Descriptions.Item label="更新时间">{formatDateTime(selected.updated_at)}</Descriptions.Item>
            <Descriptions.Item label="命中规则">
              {selected.source_detail?.rule_id ? (
                <Typography.Text code>{selected.source_detail.rule_id}</Typography.Text>
              ) : (
                '-'
              )}
            </Descriptions.Item>
            <Descriptions.Item label="命中位置">
              {formatLocation(selected.source_detail?.location)}
            </Descriptions.Item>
            <Descriptions.Item label="来源事件 ID" span={2}>
              {selected.source_detail?.event_id ? (
                <Typography.Text code>{selected.source_detail.event_id}</Typography.Text>
              ) : (
                '-'
              )}
            </Descriptions.Item>
          </Descriptions>
        ) : null}
      </Drawer>
    </Card>
  )
}
