import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Col,
  Drawer,
  Form,
  Input,
  Modal,
  Popconfirm,
  Row,
  Select,
  Space,
  Switch,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import {
  CloudSyncOutlined,
  DeleteOutlined,
  EditOutlined,
  ImportOutlined,
  KeyOutlined,
  MinusCircleOutlined,
  PlusOutlined,
  RobotOutlined,
} from '@ant-design/icons'
import { ApiError } from '../../api/client'
import {
  AI_CRAWL_LIMITS,
  aiCrawlApi,
  type AiCrawlerDirectory,
  type AiCrawlerDirectoryInput,
  type AiCrawlerDirectoryKey,
} from '../../api/aiCrawl'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import {
  AI_CRAWL_CATEGORY_META,
  AI_CRAWL_KEY_ALG_OPTIONS,
} from '../../utils/aiCrawl'

const CATEGORY_OPTIONS = Object.entries(AI_CRAWL_CATEGORY_META).map(
  ([value, meta]) => ({
    value,
    label: meta.label,
  }),
)

const IMPORT_PLACEHOLDER = JSON.stringify(
  {
    directories: [
      {
        slug: 'custom-ai-crawler',
        name: '示例 AI 爬虫',
        category: 'AI_ASSISTANT',
        signature_agent: 'https://bot.example.com',
        directory_url: '',
        enabled: true,
        keys: [
          {
            kid: 'key-2026-01',
            alg: 'ed25519',
            public_key_pem:
              '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----',
          },
        ],
      },
    ],
  },
  null,
  2,
)

interface DirectoryFormValues {
  slug: string
  name: string
  category: string
  signature_agent?: string
  directory_url?: string
  enabled: boolean
  keys: AiCrawlerDirectoryKey[]
}

function hasPrivatePemBlock(pem: string): boolean {
  return /BEGIN\s+[A-Z0-9 ]*PRIVATE KEY/i.test(pem)
}

/** 爬虫目录新建/编辑抽屉 */
function DirectoryEditorDrawer({
  editing,
  onClose,
  onSaved,
}: {
  editing: AiCrawlerDirectory | null
  onClose: () => void
  onSaved: () => void
}) {
  const { message } = AntdApp.useApp()
  const [form] = Form.useForm<DirectoryFormValues>()
  const [submitError, setSubmitError] = useState<string | null>(null)

  const saveMut = useMutation({
    mutationFn: (body: AiCrawlerDirectoryInput) =>
      editing
        ? aiCrawlApi.updateDirectory(editing.id, body)
        : aiCrawlApi.createDirectory(body),
    onSuccess: () => {
      message.success(editing ? '爬虫目录已更新' : '爬虫目录已创建')
      onSaved()
      onClose()
    },
    onError: (e: unknown) => {
      setSubmitError(e instanceof ApiError ? e.message : '保存失败')
    },
  })

  return (
    <Drawer
      title={editing ? `编辑爬虫目录：${editing.name}` : '新建 Web Bot Auth 爬虫目录'}
      open
      size="large"
      onClose={onClose}
      extra={
        <Space>
          <Button onClick={onClose}>取消</Button>
          <Button
            type="primary"
            loading={saveMut.isPending}
            onClick={() => form.submit()}
          >
            {editing ? '保存修改' : '创建目录'}
          </Button>
        </Space>
      }
    >
      {submitError && (
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 16 }}
          title="保存失败"
          description={submitError}
        />
      )}
      <Form<DirectoryFormValues>
        form={form}
        layout="vertical"
        initialValues={{
          slug: editing?.slug ?? '',
          name: editing?.name ?? '',
          category: editing?.category ?? 'AI_ASSISTANT',
          signature_agent: editing?.signature_agent ?? '',
          directory_url: editing?.directory_url ?? '',
          enabled: editing?.enabled ?? true,
          keys: editing?.keys ?? [],
        }}
        onFinish={(values) => {
          setSubmitError(null)
          saveMut.mutate({
            slug: values.slug.trim(),
            name: values.name.trim(),
            category: values.category,
            signature_agent: (values.signature_agent ?? '').trim(),
            directory_url: values.directory_url?.trim() ?? '',
            enabled: Boolean(values.enabled),
            keys: (values.keys ?? []).map((k) => ({
              kid: (k.kid ?? '').trim(),
              alg: k.alg,
              public_key_pem: (k.public_key_pem ?? '').trim(),
            })),
          })
        }}
      >
        <Row gutter={16}>
          <Col xs={24} sm={12}>
            <Form.Item
              name="slug"
              label="目录标识（Slug）"
              extra="全局唯一小写标识，供应用策略规则 agent_id 引用"
              rules={[
                { required: true, whitespace: true, message: '请输入目录标识' },
                {
                  pattern: /^[a-z0-9][a-z0-9_-]{0,63}$/,
                  message: '仅限小写字母、数字、短横线或下划线',
                },
              ]}
            >
              <Input
                placeholder="如 openai-searchbot"
                disabled={Boolean(editing?.is_builtin)}
                autoComplete="off"
              />
            </Form.Item>
          </Col>
          <Col xs={24} sm={12}>
            <Form.Item
              name="name"
              label="爬虫名称"
              rules={[
                { required: true, whitespace: true, message: '请输入爬虫名称' },
                { max: 128, message: '名称不能超过 128 字符' },
              ]}
            >
              <Input placeholder="如 OpenAI SearchBot" autoComplete="off" />
            </Form.Item>
          </Col>
        </Row>

        <Row gutter={16}>
          <Col xs={24} sm={12}>
            <Form.Item
              name="category"
              label="爬虫类别"
              rules={[{ required: true, message: '请选择爬虫类别' }]}
            >
              <Select options={CATEGORY_OPTIONS} />
            </Form.Item>
          </Col>
          <Col xs={24} sm={12}>
            <Form.Item
              name="enabled"
              label="启用状态"
              valuePropName="checked"
              extra="停用后不再随配置下发至网关验证快照"
            >
              <Switch checkedChildren="已启用" unCheckedChildren="已停用" />
            </Form.Item>
          </Col>
        </Row>

        <Form.Item
          name="signature_agent"
          label="Signature-Agent 标识（可选）"
          extra="RFC 9421 Signature-Agent 请求头声明值（通常为爬虫服务 HTTPS 源地址）"
          rules={[
            {
              max: AI_CRAWL_LIMITS.maxSignatureAgentLen,
              message: `不能超过 ${AI_CRAWL_LIMITS.maxSignatureAgentLen} 字符`,
            },
          ]}
        >
          <Input placeholder="如 https://chatgpt.com" autoComplete="off" />
        </Form.Item>

        <Form.Item
          name="directory_url"
          label="远程公钥目录地址（可选）"
          extra="仅 HTTPS（/.well-known/http-message-signatures-directory）；离线环境请留空并在下方维护静态公钥"
          rules={[
            {
              validator: (_, v?: string) => {
                if (!v || !v.trim()) return Promise.resolve()
                if (!/^https:\/\//i.test(v.trim())) {
                  return Promise.reject(new Error('远程目录地址仅允许 HTTPS'))
                }
                return Promise.resolve()
              },
            },
          ]}
        >
          <Input
            placeholder="留空 = 纯离线静态公钥，或填写 https://.../.well-known/http-message-signatures-directory"
            autoComplete="off"
          />
        </Form.Item>

        <Form.List name="keys">
          {(fields, { add, remove }) => (
            <div>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  marginBottom: 8,
                }}
              >
                <Typography.Text strong>
                  <KeyOutlined style={{ marginRight: 6 }} />
                  静态验证公钥列表（{fields.length}）
                </Typography.Text>
                <Button
                  size="small"
                  type="dashed"
                  icon={<PlusOutlined />}
                  onClick={() =>
                    add({ kid: '', alg: 'ed25519', public_key_pem: '' })
                  }
                >
                  添加公钥
                </Button>
              </div>
              {fields.length === 0 && (
                <Typography.Paragraph
                  type="secondary"
                  style={{ fontSize: 12, marginBottom: 12 }}
                >
                  暂无静态公钥；可通过上方「添加公钥」手工录入，或在列表页执行离线导入 /
                  远程同步。
                </Typography.Paragraph>
              )}
              {fields.map((field) => (
                <Card
                  key={field.key}
                  size="small"
                  style={{ marginBottom: 12 }}
                  title={`公钥 #${field.name + 1}`}
                  extra={
                    <Button
                      type="text"
                      danger
                      size="small"
                      icon={<MinusCircleOutlined />}
                      aria-label={`删除公钥 #${field.name + 1}`}
                      onClick={() => remove(field.name)}
                    />
                  }
                >
                  <Row gutter={12}>
                    <Col xs={24} sm={12}>
                      <Form.Item
                        name={[field.name, 'kid']}
                        label="密钥标识（kid）"
                        rules={[
                          {
                            required: true,
                            whitespace: true,
                            message: '请输入 kid',
                          },
                        ]}
                      >
                        <Input
                          placeholder="如 jwk-thumbprint-or-kid"
                          autoComplete="off"
                        />
                      </Form.Item>
                    </Col>
                    <Col xs={24} sm={12}>
                      <Form.Item
                        name={[field.name, 'alg']}
                        label="签名算法"
                        rules={[{ required: true, message: '请选择算法' }]}
                      >
                        <Select options={AI_CRAWL_KEY_ALG_OPTIONS} />
                      </Form.Item>
                    </Col>
                  </Row>
                  <Form.Item
                    name={[field.name, 'public_key_pem']}
                    label="公钥 PEM"
                    style={{ marginBottom: 0 }}
                    rules={[
                      {
                        required: true,
                        whitespace: true,
                        message: '请输入公钥 PEM',
                      },
                      {
                        validator: (_, v?: string) => {
                          if (!v) return Promise.resolve()
                          if (hasPrivatePemBlock(v)) {
                            return Promise.reject(
                              new Error('禁止粘贴私钥材料，仅允许公钥 PEM'),
                            )
                          }
                          return Promise.resolve()
                        },
                      },
                    ]}
                  >
                    <Input.TextArea
                      rows={3}
                      placeholder="-----BEGIN PUBLIC KEY-----&#10;...&#10;-----END PUBLIC KEY-----"
                      style={{ fontFamily: 'monospace', fontSize: 12 }}
                    />
                  </Form.Item>
                </Card>
              ))}
            </div>
          )}
        </Form.List>
      </Form>
    </Drawer>
  )
}

/** 离线 JSON 密钥包导入弹窗 */
function OfflineImportModal({
  onClose,
  onImported,
}: {
  onClose: () => void
  onImported: () => void
}) {
  const { message } = AntdApp.useApp()
  const [jsonText, setJsonText] = useState('')
  const [parseError, setParseError] = useState<string | null>(null)

  const importMut = useMutation({
    mutationFn: (directories: AiCrawlerDirectoryInput[]) =>
      aiCrawlApi.importDirectories({ directories }),
    onSuccess: (res) => {
      message.success(`成功导入 ${res.imported} 条爬虫公钥目录`)
      onImported()
      onClose()
    },
    onError: (e: unknown) => {
      setParseError(e instanceof ApiError ? e.message : '导入失败')
    },
  })

  const handleOk = () => {
    setParseError(null)
    const trimmed = jsonText.trim()
    if (!trimmed) {
      setParseError('请粘贴离线 JSON 目录包内容')
      return
    }
    let parsed: unknown
    try {
      parsed = JSON.parse(trimmed)
    } catch {
      setParseError('JSON 格式不合法，请检查语法')
      return
    }
    const directories = Array.isArray(parsed)
      ? parsed
      : parsed &&
          typeof parsed === 'object' &&
          Array.isArray((parsed as { directories?: unknown }).directories)
        ? (parsed as { directories: unknown[] }).directories
        : null
    if (!directories || directories.length === 0) {
      setParseError('JSON 必须包含非空的 directories 数组或直接为目录数组')
      return
    }
    importMut.mutate(directories as AiCrawlerDirectoryInput[])
  }

  return (
    <Modal
      title="导入离线 Web Bot Auth 爬虫密钥包"
      open
      width={680}
      okText="确认导入"
      cancelText="取消"
      confirmLoading={importMut.isPending}
      onCancel={onClose}
      onOk={handleOk}
    >
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 12 }}
        title="适用于无外网隔离环境：支持粘贴含 directories 数组的 JSON 离线包，按 slug 幂等新增或更新目录与公钥。"
      />
      {parseError && (
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 12 }}
          title={parseError}
        />
      )}
      <Input.TextArea
        aria-label="离线密钥包 JSON"
        rows={12}
        value={jsonText}
        onChange={(e) => setJsonText(e.target.value)}
        placeholder={IMPORT_PLACEHOLDER}
        style={{ fontFamily: 'monospace', fontSize: 12 }}
      />
    </Modal>
  )
}

/**
 * Web Bot Auth 爬虫公钥目录管理页（WDSP Phase 9A-2）。
 * 路由：/ai-crawl；权限：ai_crawl.read（读）/ ai_crawl.manage（增删改/离线导入/手动同步）。
 */
export default function AiCrawlPage() {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'ai_crawl.manage')

  const [keyword, setKeyword] = useState('')
  const [categoryFilter, setCategoryFilter] = useState<string | undefined>(
    undefined,
  )
  /** undefined 关闭；null 新建；非空对象 编辑 */
  const [editor, setEditor] = useState<AiCrawlerDirectory | null | undefined>(
    undefined,
  )
  const [importOpen, setImportOpen] = useState(false)
  const [syncingId, setSyncingId] = useState<string | null>(null)

  const listQuery = useQuery({
    queryKey: ['ai-crawl-directories'],
    queryFn: () => aiCrawlApi.listDirectories(),
  })

  const invalidate = () =>
    void queryClient.invalidateQueries({ queryKey: ['ai-crawl-directories'] })

  const deleteMut = useMutation({
    mutationFn: (id: string) => aiCrawlApi.deleteDirectory(id),
    onSuccess: () => {
      message.success('爬虫目录已删除')
      invalidate()
    },
    onError: (e: unknown) =>
      message.error(e instanceof ApiError ? e.message : '删除失败'),
  })

  const syncMut = useMutation({
    mutationFn: (id: string) => aiCrawlApi.syncDirectory(id),
    onMutate: (id) => setSyncingId(id),
    onSuccess: (res) => {
      message.success(
        `同步完成：${res.directory.name}（共 ${res.keys_count} 个公钥）`,
      )
      invalidate()
    },
    onError: (e: unknown) =>
      message.error(e instanceof ApiError ? e.message : '同步失败'),
    onSettled: () => setSyncingId(null),
  })

  const filteredItems = useMemo(() => {
    const all = listQuery.data?.items ?? []
    const kw = keyword.trim().toLowerCase()
    return all.filter((item) => {
      if (categoryFilter && item.category !== categoryFilter) return false
      if (!kw) return true
      return (
        item.name.toLowerCase().includes(kw) ||
        item.slug.toLowerCase().includes(kw) ||
        item.signature_agent.toLowerCase().includes(kw)
      )
    })
  }, [listQuery.data?.items, keyword, categoryFilter])

  const columns: ColumnsType<AiCrawlerDirectory> = [
    {
      title: '爬虫目录',
      dataIndex: 'name',
      key: 'name',
      width: 220,
      render: (_, record) => (
        <Space orientation="vertical" size={2}>
          <Space size={6} wrap>
            <Typography.Text strong>{record.name}</Typography.Text>
            {record.is_builtin && <Tag color="geekblue">内置</Tag>}
          </Space>
          <Typography.Text code style={{ fontSize: 12 }}>
            {record.slug}
          </Typography.Text>
        </Space>
      ),
    },
    {
      title: '爬虫类别',
      dataIndex: 'category',
      key: 'category',
      width: 140,
      render: (v: string) => (
        <StatusTag value={v} map={AI_CRAWL_CATEGORY_META} />
      ),
    },
    {
      title: 'Signature-Agent',
      dataIndex: 'signature_agent',
      key: 'signature_agent',
      width: 220,
      ellipsis: true,
      render: (v: string) =>
        v ? (
          <Typography.Text code style={{ fontSize: 12 }}>
            {v}
          </Typography.Text>
        ) : (
          '-'
        ),
    },
    {
      title: '公钥数量',
      key: 'keys',
      width: 140,
      render: (_, record) => {
        const count = record.keys?.length ?? 0
        const algs = Array.from(new Set((record.keys ?? []).map((k) => k.alg)))
        return (
          <Space size={4} wrap>
            <Tag color={count > 0 ? 'green' : 'default'}>{count} 把</Tag>
            {algs.map((a) => (
              <Tag key={a} style={{ fontSize: 11 }}>
                {a}
              </Tag>
            ))}
          </Space>
        )
      },
    },
    {
      title: '来源与同步',
      key: 'sync',
      width: 230,
      render: (_, record) => (
        <Space orientation="vertical" size={2}>
          {record.directory_url ? (
            <Typography.Text
              type="secondary"
              style={{ fontSize: 12, maxWidth: 210 }}
              ellipsis={{ tooltip: record.directory_url }}
            >
              {record.directory_url}
            </Typography.Text>
          ) : (
            <Tag>离线静态密钥</Tag>
          )}
          {record.last_sync_error ? (
            <Tooltip title={record.last_sync_error}>
              <Tag color="error">最近同步异常</Tag>
            </Tooltip>
          ) : record.last_synced_at ? (
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              同步于 {formatDateTime(record.last_synced_at)}
            </Typography.Text>
          ) : null}
        </Space>
      ),
    },
    {
      title: '状态',
      dataIndex: 'enabled',
      key: 'enabled',
      width: 90,
      render: (v: boolean) => (
        <Tag color={v ? 'green' : 'default'}>{v ? '已启用' : '已停用'}</Tag>
      ),
    },
    {
      title: '更新时间',
      dataIndex: 'updated_at',
      key: 'updated_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    ...(canManage
      ? [
          {
            title: '操作',
            key: 'actions',
            width: 210,
            fixed: 'right' as const,
            render: (_: unknown, record: AiCrawlerDirectory) => (
              <Space size={0}>
                <Button
                  type="link"
                  size="small"
                  icon={<EditOutlined />}
                  onClick={() => setEditor(record)}
                >
                  编辑
                </Button>
                {record.directory_url ? (
                  <Button
                    type="link"
                    size="small"
                    icon={<CloudSyncOutlined />}
                    loading={syncingId === record.id}
                    onClick={() => syncMut.mutate(record.id)}
                  >
                    同步
                  </Button>
                ) : (
                  <Tooltip title="未配置远程目录地址，请使用编辑或离线导入维护公钥">
                    <Button
                      type="link"
                      size="small"
                      icon={<CloudSyncOutlined />}
                      disabled
                    >
                      同步
                    </Button>
                  </Tooltip>
                )}
                {record.is_builtin ? (
                  <Tooltip title="内置爬虫目录不可删除，可通过编辑停用">
                    <Button
                      type="link"
                      size="small"
                      danger
                      icon={<DeleteOutlined />}
                      disabled
                    >
                      删除
                    </Button>
                  </Tooltip>
                ) : (
                  <Popconfirm
                    title={`确定删除爬虫目录「${record.name}」吗？`}
                    description="删除后需经配置发布同步到网关节点。"
                    okText="确认删除"
                    okButtonProps={{ danger: true }}
                    onConfirm={() => deleteMut.mutate(record.id)}
                  >
                    <Button
                      type="link"
                      size="small"
                      danger
                      icon={<DeleteOutlined />}
                    >
                      删除
                    </Button>
                  </Popconfirm>
                )}
              </Space>
            ),
          },
        ]
      : []),
  ]

  return (
    <Card
      title={
        <Space>
          <RobotOutlined />
          <span>AI 爬虫目录（Web Bot Auth）</span>
        </Space>
      }
      extra={
        canManage ? (
          <Space wrap>
            <Button
              icon={<ImportOutlined />}
              onClick={() => setImportOpen(true)}
            >
              导入离线密钥包
            </Button>
            <Button
              type="primary"
              icon={<PlusOutlined />}
              onClick={() => setEditor(null)}
            >
              新建爬虫目录
            </Button>
          </Space>
        ) : undefined
      }
    >
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        title="基于 RFC 9421 Web Bot Auth（tag=web-bot-auth）统一管理可信搜索引擎与 AI 爬虫验证公钥。网关热路径零外部网络 IO，所有公钥经配置发布通道以只读快照下发；远程同步严格执行 SSRF 防护，隔离环境支持离线 JSON 包导入。"
      />

      <Space
        style={{
          marginBottom: 16,
          display: 'flex',
          justifyContent: 'space-between',
        }}
        wrap
      >
        <Space wrap>
          <Input.Search
            allowClear
            placeholder="按名称、Slug 或 Signature-Agent 搜索"
            value={keyword}
            onChange={(e) => setKeyword(e.target.value)}
            style={{ width: 280 }}
          />
          <Select
            allowClear
            placeholder="按爬虫类别筛选"
            value={categoryFilter}
            onChange={setCategoryFilter}
            options={CATEGORY_OPTIONS}
            style={{ width: 180 }}
          />
        </Space>
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          共 {filteredItems.length} 条目录记录
        </Typography.Text>
      </Space>

      <QueryErrorAlert
        error={listQuery.error}
        message="加载 AI 爬虫目录失败"
      />

      <SmartTable<AiCrawlerDirectory>
        storageKey="ai-crawl-directories"
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={filteredItems}
        refreshQueryKeys={[['ai-crawl-directories']]}
        scroll={{ x: 1280 }}
        pagination={{ pageSize: 20, showSizeChanger: false }}
        locale={{ emptyText: '暂无爬虫公钥目录' }}
      />

      {editor !== undefined && (
        <DirectoryEditorDrawer
          editing={editor}
          onClose={() => setEditor(undefined)}
          onSaved={invalidate}
        />
      )}

      {importOpen && (
        <OfflineImportModal
          onClose={() => setImportOpen(false)}
          onImported={invalidate}
        />
      )}
    </Card>
  )
}
