import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  App as AntdApp,
  Button,
  Card,
  Col,
  Drawer,
  Input,
  Radio,
  Row,
  Select,
  Space,
  Statistic,
  Switch,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { apiFileAssetsApi, type ApiFileAsset } from '../../api/apiFileAssets'
import FileLineagePanel from '../api-file-compliance/FileLineagePanel'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { formatDateTime } from '../../utils/format'

const DIRECTION_META = {
  UPLOAD: { color: 'blue', label: '上传' },
  DOWNLOAD: { color: 'purple', label: '下载' },
}

function formatBytes(size: number): string {
  if (size < 1024) return `${size} B`
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KiB`
  return `${(size / (1024 * 1024)).toFixed(1)} MiB`
}

export default function ApiFileAssetsPage() {
  const { message } = AntdApp.useApp()
  const [days, setDays] = useState(7)
  const [direction, setDirection] = useState<
    'UPLOAD' | 'DOWNLOAD' | undefined
  >()
  const [sensitiveOnly, setSensitiveOnly] = useState(false)
  const [hashInput, setHashInput] = useState('')
  const [extensionInput, setExtensionInput] = useState('')
  const [identityInput, setIdentityInput] = useState('')
  const [appliedHash, setAppliedHash] = useState('')
  const [appliedExtension, setAppliedExtension] = useState('')
  const [appliedIdentity, setAppliedIdentity] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [selectedHash, setSelectedHash] = useState('')

  const listQuery = useQuery({
    queryKey: [
      'api-file-assets',
      days,
      direction,
      sensitiveOnly,
      appliedHash,
      appliedExtension,
      appliedIdentity,
      page,
      pageSize,
    ],
    queryFn: () =>
      apiFileAssetsApi.list({
        days,
        direction,
        sensitive_only: sensitiveOnly,
        sha256: appliedHash || undefined,
        extension: appliedExtension || undefined,
        identity_fingerprint: appliedIdentity || undefined,
        page,
        page_size: pageSize,
      }),
  })
  const statsQuery = useQuery({
    queryKey: ['api-file-assets-stats', days],
    queryFn: () => apiFileAssetsApi.stats(days),
  })
  const summary = statsQuery.data?.summary

  const applyFilters = () => {
    const hash = hashInput.trim().toLowerCase()
    if (hash && !/^[0-9a-f]{64}$/.test(hash)) {
      message.warning('SHA-256 需为 64 位十六进制字符串')
      return
    }
    setAppliedHash(hash)
    setAppliedExtension(extensionInput.trim().replace(/^\./, '').toLowerCase())
    setAppliedIdentity(identityInput.trim())
    setPage(1)
  }

  const resetFilters = () => {
    setHashInput('')
    setExtensionInput('')
    setIdentityInput('')
    setAppliedHash('')
    setAppliedExtension('')
    setAppliedIdentity('')
    setDirection(undefined)
    setSensitiveOnly(false)
    setPage(1)
  }

  const columns: ColumnsType<ApiFileAsset> = [
    {
      title: '方向',
      dataIndex: 'direction',
      width: 82,
      render: (value: string) => (
        <StatusTag value={value} map={DIRECTION_META} />
      ),
    },
    {
      title: '文件名',
      dataIndex: 'filename',
      width: 190,
      ellipsis: true,
      render: (value: string) => (
        <Typography.Text strong>{value}</Typography.Text>
      ),
    },
    {
      title: '端点',
      dataIndex: 'endpoint_key',
      width: 250,
      ellipsis: true,
      render: (value: string) => (
        <Typography.Text code>{value}</Typography.Text>
      ),
    },
    { title: '类型', dataIndex: 'mime', width: 190, ellipsis: true },
    {
      title: '大小',
      dataIndex: 'size_bytes',
      width: 100,
      align: 'right',
      render: formatBytes,
    },
    {
      title: '内容指纹',
      dataIndex: 'sha256',
      width: 150,
      render: (value: string | null | undefined) =>
        value ? (
          <Typography.Text code title={value}>
            {value.slice(0, 12)}…
          </Typography.Text>
        ) : (
          <Typography.Text type="secondary">未完整观测</Typography.Text>
        ),
    },
    {
      title: '敏感标签',
      dataIndex: 'sensitive_types',
      width: 180,
      render: (value: string[]) =>
        value.length > 0
          ? value.map((item) => <Tag key={item}>{item}</Tag>)
          : '-',
    },
    {
      title: '传输次数',
      dataIndex: 'transfer_count',
      width: 100,
      align: 'right',
    },
    {
      title: '最近观测',
      dataIndex: 'last_seen',
      width: 170,
      render: (value: string) => formatDateTime(value),
    },
    {
      title: '操作',
      key: 'actions',
      width: 110,
      fixed: 'right',
      render: (_, record) => (
        <Button
          type="link"
          size="small"
          disabled={!record.sha256}
          onClick={() => setSelectedHash(record.sha256 ?? '')}
        >
          内容关联
        </Button>
      ),
    },
  ]

  return (
    <Card title="文件资产台账">
      <Typography.Paragraph type="secondary">
        汇总真实文件上传与下载观测，按完整内容指纹检索相同字节内容；截断或流式观测不生成指纹，关联不代表业务所有权。
      </Typography.Paragraph>
      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col flex="1 1 160px">
          <Card size="small">
            <Statistic
              title="上传资产"
              value={summary?.upload_assets ?? 0}
              loading={statsQuery.isLoading}
            />
          </Card>
        </Col>
        <Col flex="1 1 160px">
          <Card size="small">
            <Statistic
              title="下载资产"
              value={summary?.download_assets ?? 0}
              loading={statsQuery.isLoading}
            />
          </Card>
        </Col>
        <Col flex="1 1 160px">
          <Card size="small">
            <Statistic
              title="敏感文件"
              value={summary?.sensitive_file_count ?? 0}
              loading={statsQuery.isLoading}
            />
          </Card>
        </Col>
        <Col flex="1 1 160px">
          <Card size="small">
            <Statistic
              title="传输总次数"
              value={
                (summary?.upload_transfers ?? 0) +
                (summary?.download_transfers ?? 0)
              }
              loading={statsQuery.isLoading}
            />
          </Card>
        </Col>
      </Row>
      <QueryErrorAlert error={statsQuery.error} />
      <QueryErrorAlert error={listQuery.error} />
      <Space wrap size={12} style={{ marginBottom: 16 }}>
        <Select
          allowClear
          placeholder="传输方向"
          value={direction}
          style={{ width: 130 }}
          options={[
            { value: 'UPLOAD', label: '上传' },
            { value: 'DOWNLOAD', label: '下载' },
          ]}
          onChange={(value) => {
            setDirection(value)
            setPage(1)
          }}
        />
        <Input
          allowClear
          aria-label="文件内容 SHA-256"
          placeholder="完整文件 SHA-256"
          value={hashInput}
          onChange={(event) => setHashInput(event.target.value)}
          onPressEnter={applyFilters}
          style={{ width: 340, fontFamily: 'monospace' }}
        />
        <Input
          allowClear
          aria-label="文件扩展名"
          placeholder="扩展名，如 docx"
          value={extensionInput}
          onChange={(event) => setExtensionInput(event.target.value)}
          onPressEnter={applyFilters}
          style={{ width: 160 }}
        />
        <Input
          allowClear
          aria-label="身份指纹"
          placeholder="身份指纹"
          value={identityInput}
          onChange={(event) => setIdentityInput(event.target.value)}
          onPressEnter={applyFilters}
          style={{ width: 280, fontFamily: 'monospace' }}
        />
        <Button type="primary" onClick={applyFilters}>
          查询
        </Button>
        <Button onClick={resetFilters}>重置</Button>
        <Space size={8}>
          <Typography.Text type="secondary">仅敏感文件</Typography.Text>
          <Switch
            checked={sensitiveOnly}
            aria-label="仅敏感文件"
            onChange={(checked) => {
              setSensitiveOnly(checked)
              setPage(1)
            }}
          />
        </Space>
        <Radio.Group
          value={days}
          optionType="button"
          size="small"
          options={[
            { value: 7, label: '近 7 天' },
            { value: 14, label: '近 14 天' },
            { value: 30, label: '近 30 天' },
          ]}
          onChange={(event) => {
            setDays(event.target.value as number)
            setPage(1)
          }}
        />
      </Space>
      <SmartTable<ApiFileAsset>
        storageKey="api-file-assets"
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        locale={{ emptyText: '当前条件下暂无真实文件传输记录' }}
        scroll={{ x: 1720 }}
        pagination={{
          current: page,
          pageSize,
          total: listQuery.data?.total ?? 0,
          showSizeChanger: true,
          showTotal: (total) => `共 ${total} 条`,
          onChange: (nextPage, nextPageSize) => {
            setPage(nextPage)
            setPageSize(nextPageSize)
          },
        }}
      />
      <Drawer
        title="同内容文件传输关联"
        open={selectedHash !== ''}
        onClose={() => setSelectedHash('')}
        size="large"
      >
        {selectedHash ? <FileLineagePanel sha256={selectedHash} /> : null}
      </Drawer>
    </Card>
  )
}
