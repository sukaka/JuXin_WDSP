import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  App as AntdApp,
  Button,
  Card,
  Col,
  DatePicker,
  Descriptions,
  Drawer,
  Form,
  Input,
  List,
  Modal,
  Row,
  Select,
  Space,
  Statistic,
  Switch,
  Table,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import {
  BellOutlined,
  CloudSyncOutlined,
  DatabaseOutlined,
  ImportOutlined,
  SettingOutlined,
} from '@ant-design/icons'
import type { Dayjs } from 'dayjs'
import { ApiError } from '../../api/client'
import {
  parseImportJson,
  vulnIntelApi,
  type VulnAdvisory,
  type VulnImportAdvisoryInput,
  type VulnImportResult,
  type VulnIntelSettings,
  type VulnTechAssetItem,
} from '../../api/vulnIntel'
import SmartTable from '../../components/SmartTable'
import { isSafeHttpUrl } from '../../utils/url'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'

/** 漏洞危害等级（与漏洞档案页口径一致）；NONE 为 CVSS 缺失时的占位级 */
const SEVERITY_META: Record<string, { color: string; label: string }> = {
  CRITICAL: { color: '#7f1d1d', label: '超危' },
  HIGH: { color: 'red', label: '高危' },
  MEDIUM: { color: 'orange', label: '中危' },
  LOW: { color: 'blue', label: '低危' },
  NONE: { color: 'default', label: '未定级' },
}

const SEVERITY_OPTIONS = Object.entries(SEVERITY_META).map(([value, meta]) => ({
  value,
  label: meta.label,
}))

/** 最低提醒级别（NONE 不参与订阅门槛） */
const MIN_SEVERITY_OPTIONS = SEVERITY_OPTIONS.filter((o) => o.value !== 'NONE')

const SOURCE_META: Record<string, { color: string; label: string }> = {
  NVD: { color: 'geekblue', label: 'NVD' },
  MANUAL: { color: 'purple', label: '手工导入' },
}

const SYNC_STATUS_META: Record<string, { color: string; label: string }> = {
  SUCCESS: { color: 'green', label: '成功' },
  FAILED: { color: 'red', label: '失败' },
  RUNNING: { color: 'blue', label: '同步中' },
  NEVER: { color: 'default', label: '未同步' },
}

/** 发布时间按日期粒度展示（后端可能返回日期或 RFC3339） */
const formatDate = (v?: string | null) => (v ? v.slice(0, 10) : '-')

interface Filters {
  keyword?: string
  severity?: string
  tech?: string
  source?: string
  published_start?: string
  published_end?: string
}

/** 订阅设置表单值 */
interface SettingsFormValues {
  watch_techs: string[]
  min_severity: string
  sync_enabled: boolean
}

/** 漏洞情报：PHP 漏洞每日同步/导入 + 订阅提醒的情报检索与运营页面 */
export default function VulnIntelPage() {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'vuln_intel.manage')

  const [filters, setFilters] = useState<Filters>({})
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [detailId, setDetailId] = useState<string | null>(null)
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [assetsOpen, setAssetsOpen] = useState(false)
  const [importOpen, setImportOpen] = useState(false)
  const [importText, setImportText] = useState('')
  const [importError, setImportError] = useState<string | null>(null)
  const [importResult, setImportResult] = useState<VulnImportResult | null>(null)
  // 技术资产编辑草稿：application_id → 是否标记 PHP
  const [assetDraft, setAssetDraft] = useState<Record<string, boolean>>({})
  const [settingsForm] = Form.useForm<SettingsFormValues>()

  const overviewQuery = useQuery({
    queryKey: ['vuln-intel', 'overview'],
    queryFn: () => vulnIntelApi.overview(),
  })

  const listQuery = useQuery({
    queryKey: ['vuln-intel', 'advisories', filters, page, pageSize],
    queryFn: () => vulnIntelApi.list({ ...filters, page, page_size: pageSize }),
  })

  const detailQuery = useQuery({
    queryKey: ['vuln-intel', 'advisory', detailId],
    queryFn: () => vulnIntelApi.get(detailId as string),
    enabled: detailId !== null,
  })

  const settingsQuery = useQuery({
    queryKey: ['vuln-intel', 'settings'],
    queryFn: () => vulnIntelApi.settings(),
    enabled: canManage && settingsOpen,
  })

  const assetsQuery = useQuery({
    queryKey: ['vuln-intel', 'tech-assets'],
    queryFn: () => vulnIntelApi.techAssets(),
    enabled: canManage && assetsOpen,
  })

  // 弹层打开后查询就绪即回填表单/草稿，避免手动 refetch 与 enabled 翻转竞争
  useEffect(() => {
    if (settingsOpen && settingsQuery.data) {
      settingsForm.setFieldsValue(settingsQuery.data)
    }
  }, [settingsOpen, settingsQuery.data, settingsForm])

  useEffect(() => {
    if (!assetsOpen || !assetsQuery.data) return
    const draft: Record<string, boolean> = {}
    for (const item of assetsQuery.data) {
      draft[item.application_id] = item.tech_tags.includes('php')
    }
    setAssetDraft(draft)
  }, [assetsOpen, assetsQuery.data])

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ['vuln-intel'] })
  }

  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const syncMutation = useMutation({
    mutationFn: () => vulnIntelApi.sync(),
    onSuccess: (data) => {
      if (data.status === 'FAILED') {
        message.warning(data.message || '同步失败，请查看情报源状态')
      } else {
        message.success(`同步完成，新增/更新 ${data.records_upserted} 条`)
      }
      invalidate()
    },
    onError,
  })

  const settingsMutation = useMutation({
    mutationFn: (body: VulnIntelSettings) => vulnIntelApi.updateSettings(body),
    onSuccess: () => {
      message.success('订阅设置已保存')
      setSettingsOpen(false)
      void queryClient.invalidateQueries({ queryKey: ['vuln-intel', 'settings'] })
    },
    onError,
  })

  const assetsMutation = useMutation({
    mutationFn: (items: { application_id: string; tech_tags: string[] }[]) =>
      vulnIntelApi.updateTechAssets(items),
    onSuccess: () => {
      message.success('技术资产标记已保存')
      setAssetsOpen(false)
      void queryClient.invalidateQueries({ queryKey: ['vuln-intel', 'tech-assets'] })
    },
    onError,
  })

  const importMutation = useMutation({
    mutationFn: (advisories: VulnImportAdvisoryInput[]) =>
      vulnIntelApi.importAdvisories(advisories),
    onSuccess: (data) => {
      setImportResult(data)
      setImportError(null)
      invalidate()
    },
    onError: (e) => {
      setImportResult(null)
      setImportError(e instanceof ApiError ? e.message : '导入失败')
    },
  })

  const openAssets = () => {
    setAssetDraft({})
    setAssetsOpen(true)
  }

  const saveAssets = () => {
    const items = (assetsQuery.data ?? []).map((item) => ({
      application_id: item.application_id,
      tech_tags: assetDraft[item.application_id] ? ['php'] : [],
    }))
    assetsMutation.mutate(items)
  }

  const submitImport = () => {
    setImportResult(null)
    let advisories: VulnImportAdvisoryInput[]
    try {
      advisories = parseImportJson(importText)
    } catch (e) {
      setImportError(e instanceof Error ? e.message : 'JSON 解析失败')
      return
    }
    setImportError(null)
    importMutation.mutate(advisories)
  }

  const applyFilters = (next: Partial<Filters>) => {
    setFilters((f) => ({ ...f, ...next }))
    setPage(1)
  }

  const onRangeChange = (range: [Dayjs | null, Dayjs | null] | null) => {
    applyFilters({
      published_start: range?.[0] ? range[0].format('YYYY-MM-DD') : undefined,
      published_end: range?.[1] ? range[1].format('YYYY-MM-DD') : undefined,
    })
  }

  // 技术筛选选项：订阅技术栈 + 常见的 php，去重
  const techOptions = Array.from(
    new Set([...(settingsQuery.data?.watch_techs ?? []), 'php']),
  ).map((t) => ({ value: t, label: t.toUpperCase() }))

  const overview = overviewQuery.data

  const columns: ColumnsType<VulnAdvisory> = [
    {
      title: 'CVE 编号',
      dataIndex: 'cve_id',
      width: 170,
      render: (v: string) => (
        <Button
          type="link"
          size="small"
          style={{ padding: 0, height: 'auto' }}
          onClick={() => setDetailId(v)}
        >
          {v}
        </Button>
      ),
    },
    { title: '标题', dataIndex: 'title', ellipsis: true },
    {
      title: '级别',
      dataIndex: 'severity',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={SEVERITY_META} />,
    },
    {
      title: 'CVSS',
      dataIndex: 'cvss_score',
      width: 80,
      render: (v: number | null) => (v == null ? '-' : v.toFixed(1)),
    },
    {
      title: '技术标签',
      dataIndex: 'tech_tags',
      width: 130,
      render: (tags: string[]) =>
        tags.length ? tags.map((t) => <Tag key={t}>{t.toUpperCase()}</Tag>) : '-',
    },
    {
      title: '发布日期',
      dataIndex: 'published_at',
      width: 120,
      render: (v: string) => formatDate(v),
    },
    {
      title: '来源',
      dataIndex: 'source',
      width: 110,
      render: (v: string) => <StatusTag value={v} map={SOURCE_META} />,
    },
    {
      title: '操作',
      key: 'actions',
      width: 80,
      fixed: 'right',
      render: (_, record) => (
        <Button type="link" size="small" onClick={() => setDetailId(record.cve_id)}>
          详情
        </Button>
      ),
    },
  ]

  const assetColumns: ColumnsType<VulnTechAssetItem> = [
    { title: '应用编码', dataIndex: 'code', width: 160 },
    { title: '应用名称', dataIndex: 'name', ellipsis: true },
    {
      title: 'PHP',
      key: 'php',
      width: 100,
      render: (_, record) => (
        <Switch
          checked={assetDraft[record.application_id] ?? record.tech_tags.includes('php')}
          onChange={(checked) =>
            setAssetDraft((prev) => ({ ...prev, [record.application_id]: checked }))
          }
          aria-label={`标记 ${record.name} 为 PHP 应用`}
        />
      ),
    },
  ]

  const detail = detailQuery.data

  return (
    <Space direction="vertical" size={16} style={{ display: 'flex' }}>
      <Card
        title="漏洞情报"
        extra={
          <Space wrap>
            <Link to="/system-alerts">
              <Button icon={<BellOutlined />}>漏洞情报告警</Button>
            </Link>
            {canManage && (
              <>
                <Button icon={<ImportOutlined />} onClick={() => setImportOpen(true)}>
                  手动导入
                </Button>
                <Button icon={<DatabaseOutlined />} onClick={openAssets}>
                  技术资产
                </Button>
                <Button icon={<SettingOutlined />} onClick={() => setSettingsOpen(true)}>
                  订阅设置
                </Button>
                <Button
                  type="primary"
                  icon={<CloudSyncOutlined />}
                  loading={syncMutation.isPending}
                  onClick={() => syncMutation.mutate()}
                >
                  手动同步
                </Button>
              </>
            )}
          </Space>
        }
      >
        {overviewQuery.isError ? (
          <QueryErrorAlert error={overviewQuery.error} message="加载漏洞情报概览失败" />
        ) : (
          <>
            <Row gutter={[16, 16]}>
              <Col xs={12} md={6}>
                <Card size="small">
                  <Statistic title="漏洞总数" value={overview?.total ?? 0} />
                </Card>
              </Col>
              <Col xs={12} md={6}>
                <Card size="small">
                  <Statistic title="近 7 日新增" value={overview?.recent_7d ?? 0} />
                </Card>
              </Col>
              <Col xs={12} md={6}>
                <Card size="small">
                  <Statistic
                    title="超危"
                    value={overview?.critical ?? 0}
                    valueStyle={{ color: '#7f1d1d' }}
                  />
                </Card>
              </Col>
              <Col xs={12} md={6}>
                <Card size="small">
                  <Statistic
                    title="高危"
                    value={overview?.high ?? 0}
                    valueStyle={{ color: '#cf1322' }}
                  />
                </Card>
              </Col>
            </Row>
            <Space style={{ marginTop: 16 }} wrap align="center">
              <Typography.Text type="secondary">情报源：</Typography.Text>
              {(overview?.sources ?? []).map((s) => (
                <Tooltip
                  key={s.source}
                  title={
                    s.status === 'FAILED' && s.failure_message
                      ? `失败原因：${s.failure_message}`
                      : `最近同步：${formatDateTime(s.last_sync_at)}`
                  }
                >
                  <Tag color={SYNC_STATUS_META[s.status]?.color ?? 'default'}>
                    {s.source} {SYNC_STATUS_META[s.status]?.label ?? s.status}
                    {`（${s.records_upserted} 条）`}
                  </Tag>
                </Tooltip>
              ))}
              {overview && overview.sources.length === 0 && (
                <Typography.Text type="secondary">暂无同步记录</Typography.Text>
              )}
            </Space>
            {overview?.sources.some((s) => s.status === 'FAILED' && s.failure_message) && (
              <Typography.Paragraph type="danger" style={{ marginTop: 8, marginBottom: 0 }}>
                {overview.sources
                  .filter((s) => s.status === 'FAILED' && s.failure_message)
                  .map((s) => `${s.source} 同步失败：${s.failure_message}`)
                  .join('；')}
              </Typography.Paragraph>
            )}
          </>
        )}
      </Card>

      <Card title="漏洞列表">
        <Space style={{ marginBottom: 16 }} wrap>
          <Input.Search
            placeholder="搜索 CVE 编号或标题"
            allowClear
            style={{ width: 240 }}
            onSearch={(v) => applyFilters({ keyword: v.trim() || undefined })}
          />
          <Select
            placeholder="级别"
            allowClear
            style={{ width: 110 }}
            options={SEVERITY_OPTIONS}
            onChange={(v) => applyFilters({ severity: v })}
          />
          <Select
            placeholder="技术栈"
            allowClear
            style={{ width: 130 }}
            options={techOptions}
            onChange={(v) => applyFilters({ tech: v })}
          />
          <Select
            placeholder="来源"
            allowClear
            style={{ width: 130 }}
            options={Object.entries(SOURCE_META).map(([value, meta]) => ({
              value,
              label: meta.label,
            }))}
            onChange={(v) => applyFilters({ source: v })}
          />
          <DatePicker.RangePicker onChange={onRangeChange} placeholder={['发布开始', '发布结束']} />
        </Space>

        {listQuery.isError ? (
          <QueryErrorAlert error={listQuery.error} message="加载漏洞情报列表失败" />
        ) : (
          <SmartTable<VulnAdvisory>
            storageKey="vuln-intel"
            rowKey="cve_id"
            loading={listQuery.isLoading}
            columns={columns}
            dataSource={listQuery.data?.items}
            onRow={(record) => ({
              onDoubleClick: () => setDetailId(record.cve_id),
              style: { cursor: 'pointer' },
            })}
            scroll={{ x: 1000 }}
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
      </Card>

      <Drawer
        title={`漏洞详情${detail ? `：${detail.advisory.cve_id}` : ''}`}
        open={detailId !== null}
        onClose={() => setDetailId(null)}
        width={720}
      >
        {detailQuery.isLoading ? (
          <Typography.Text type="secondary">加载中...</Typography.Text>
        ) : detailQuery.isError ? (
          <QueryErrorAlert error={detailQuery.error} message="加载漏洞详情失败" />
        ) : detail ? (
          <>
            <Descriptions column={2} size="small" bordered style={{ marginBottom: 16 }}>
              <Descriptions.Item label="CVE 编号">{detail.advisory.cve_id}</Descriptions.Item>
              <Descriptions.Item label="级别">
                <StatusTag value={detail.advisory.severity} map={SEVERITY_META} />
              </Descriptions.Item>
              <Descriptions.Item label="标题" span={2}>
                {detail.advisory.title}
              </Descriptions.Item>
              <Descriptions.Item label="CVSS 评分">
                {detail.advisory.cvss_score == null ? '-' : detail.advisory.cvss_score.toFixed(1)}
              </Descriptions.Item>
              <Descriptions.Item label="来源">
                <StatusTag value={detail.advisory.source} map={SOURCE_META} />
              </Descriptions.Item>
              <Descriptions.Item label="发布时间">
                {formatDate(detail.advisory.published_at)}
              </Descriptions.Item>
              <Descriptions.Item label="最后更新">
                {formatDate(detail.advisory.last_modified_at)}
              </Descriptions.Item>
              <Descriptions.Item label="技术标签" span={2}>
                {detail.advisory.tech_tags.length
                  ? detail.advisory.tech_tags.map((t) => <Tag key={t}>{t.toUpperCase()}</Tag>)
                  : '-'}
              </Descriptions.Item>
            </Descriptions>

            <Typography.Title level={5}>漏洞描述</Typography.Title>
            <Typography.Paragraph style={{ whiteSpace: 'pre-wrap' }}>
              {detail.advisory.summary || '暂无描述'}
            </Typography.Paragraph>

            <Typography.Title level={5}>
              受影响应用（{detail.applications.length}）
            </Typography.Title>
            {detail.applications.length ? (
              <List
                size="small"
                bordered
                dataSource={detail.applications}
                renderItem={(app) => (
                  <List.Item>
                    <Typography.Text>{app.name}</Typography.Text>
                    <Typography.Text type="secondary">{app.code}</Typography.Text>
                  </List.Item>
                )}
                style={{ marginBottom: 16 }}
              />
            ) : (
              <Typography.Paragraph type="secondary">
                暂无受影响应用，可在「技术资产」中标记 PHP 应用
              </Typography.Paragraph>
            )}

            <Typography.Title level={5}>
              参考链接（{detail.advisory.references.length}）
            </Typography.Title>
            {detail.advisory.references.length ? (
              <List
                size="small"
                dataSource={detail.advisory.references}
                renderItem={(url) => (
                  <List.Item style={{ padding: '4px 0' }}>
                    {isSafeHttpUrl(url) ? (
                      <Typography.Link href={url.trim()} target="_blank" rel="noopener noreferrer">
                        {url}
                      </Typography.Link>
                    ) : (
                      <Typography.Text type="secondary">{url}</Typography.Text>
                    )}
                  </List.Item>
                )}
              />
            ) : (
              <Typography.Paragraph type="secondary">暂无参考链接</Typography.Paragraph>
            )}
          </>
        ) : null}
      </Drawer>

      <Modal
        title="订阅设置"
        open={settingsOpen}
        onCancel={() => setSettingsOpen(false)}
        onOk={() => settingsForm.submit()}
        confirmLoading={settingsMutation.isPending}
        destroyOnHidden
      >
        {settingsQuery.isError ? (
          <QueryErrorAlert error={settingsQuery.error} message="加载订阅设置失败" />
        ) : (
          <Form<SettingsFormValues>
            form={settingsForm}
            layout="vertical"
            initialValues={{ watch_techs: ['php'], min_severity: 'LOW', sync_enabled: true }}
            onFinish={(values) =>
              settingsMutation.mutate({
                watch_techs: values.watch_techs ?? [],
                min_severity: values.min_severity,
                sync_enabled: values.sync_enabled ?? false,
              })
            }
          >
            <Form.Item
              name="watch_techs"
              label="订阅技术栈"
              extra="命中订阅技术栈的新漏洞会产生系统告警；首版聚焦 PHP"
            >
              <Select
                mode="tags"
                placeholder="输入技术栈名称后回车，如 php"
                tokenSeparators={[',', ' ']}
                open={false}
                suffixIcon={null}
              />
            </Form.Item>
            <Form.Item
              name="min_severity"
              label="最低提醒级别"
              rules={[{ required: true, message: '请选择最低提醒级别' }]}
              extra="达到该级别及以上的新漏洞才会提醒"
            >
              <Select options={MIN_SEVERITY_OPTIONS} />
            </Form.Item>
            <Form.Item
              name="sync_enabled"
              label="在线同步（NVD 每日同步）"
              valuePropName="checked"
              extra="离线环境请关闭在线同步，改用「手动导入」录入情报"
            >
              <Switch />
            </Form.Item>
          </Form>
        )}
      </Modal>

      <Modal
        title="技术资产（应用 PHP 标记）"
        open={assetsOpen}
        onCancel={() => setAssetsOpen(false)}
        onOk={saveAssets}
        confirmLoading={assetsMutation.isPending}
        okText="保存"
        width={640}
        destroyOnHidden
      >
        {assetsQuery.isError ? (
          <QueryErrorAlert error={assetsQuery.error} message="加载应用技术栈失败" />
        ) : (
          <>
            <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
              标记使用 PHP 的应用；新漏洞告警文案会列出受影响应用名称。
            </Typography.Paragraph>
            <Table<VulnTechAssetItem>
              rowKey="application_id"
              size="small"
              loading={assetsQuery.isLoading}
              columns={assetColumns}
              dataSource={assetsQuery.data}
              pagination={false}
              locale={{ emptyText: '暂无应用' }}
            />
          </>
        )}
      </Modal>

      <Modal
        title="手动导入漏洞情报"
        open={importOpen}
        onCancel={() => {
          setImportOpen(false)
          setImportText('')
          setImportError(null)
          setImportResult(null)
        }}
        onOk={submitImport}
        confirmLoading={importMutation.isPending}
        okText="导入"
        width={720}
        destroyOnHidden
      >
        <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
          粘贴 JSON 数组（或 {'{'}"advisories": [...]{'}'}），字段：cve_id、title、severity、
          cvss_score、published_at、tech_tags、references、summary。导入条目来源标记为「手工导入」。
        </Typography.Paragraph>
        <Input.TextArea
          rows={10}
          value={importText}
          onChange={(e) => setImportText(e.target.value)}
          placeholder='[{"cve_id":"CVE-2024-0001","title":"PHP ...","severity":"HIGH","cvss_score":7.5,"published_at":"2024-01-15","tech_tags":["php"],"references":["https://..."]}]'
          aria-label="导入 JSON 内容"
        />
        {importError && (
          <Typography.Paragraph type="danger" style={{ marginTop: 8, marginBottom: 0 }}>
            {importError}
          </Typography.Paragraph>
        )}
        {importResult && (
          <Typography.Paragraph type="success" style={{ marginTop: 8, marginBottom: 0 }}>
            导入完成：共 {importResult.imported} 条，新增 {importResult.added} 条，更新{' '}
            {importResult.updated} 条，触发告警 {importResult.alerts} 条。
          </Typography.Paragraph>
        )}
      </Modal>
    </Space>
  )
}
