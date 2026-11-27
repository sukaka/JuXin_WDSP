import { useCallback, useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  Alert,
  App as AntdApp,
  Badge,
  Button,
  Card,
  Col,
  Collapse,
  Divider,
  Drawer,
  Empty,
  Form,
  Input,
  InputNumber,
  Modal,
  Popconfirm,
  Row,
  Segmented,
  Select,
  Space,
  Spin,
  Switch,
  Table,
  Tabs,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import {
  CloudUploadOutlined,
  CodeOutlined,
  CopyOutlined,
  DeleteOutlined,
  DesktopOutlined,
  EditOutlined,
  EyeOutlined,
  HistoryOutlined,
  LinkOutlined,
  MobileOutlined,
  PlusOutlined,
  ReloadOutlined,
  RollbackOutlined,
  SkinOutlined,
} from '@ant-design/icons'
import { ApiError } from '../../api/client'
import { applicationsApi } from '../../api/applications'
import {
  BLOCK_PAGE_LIMITS,
  DEFAULT_VISUAL_CONFIG,
  blockPagesApi,
  type BlockPageBindingItem,
  type BlockPageEditorMode,
  type BlockPageItem,
  type BlockPageScene,
  type BlockPageVersionItem,
  type PlaceholderInfo,
  type PreviewBlockPageResult,
  type SceneInfo,
  type ThemePreset,
  type VisualConfig,
} from '../../api/blockPages'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'

const { Text, Paragraph } = Typography

const SCENE_META: Record<BlockPageScene, { label: string; color: string }> = {
  DEFAULT: { label: '通用默认', color: 'blue' },
  WAF: { label: 'WAF 攻击拦截', color: 'red' },
  ACCESS_CONTROL: { label: '访问控制与封禁', color: 'volcano' },
  RATE_LIMIT: { label: 'CC 与频率限制', color: 'orange' },
}

const DEFAULT_HTML_STARTER = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>请求已被拦截</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: "PingFang SC", "Microsoft YaHei", sans-serif;
      background: #1b2431;
      color: #e6e9ef;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }
    .card {
      max-width: 560px;
      width: 100%;
      background: #232f42;
      border: 1px solid #33415c;
      border-radius: 10px;
      padding: 36px;
    }
    h1 { font-size: 22px; margin-bottom: 12px; color: #f8fafc; }
    p { font-size: 14px; line-height: 1.7; color: #9aa7bd; margin-bottom: 16px; }
    .meta { background: #1b2431; border-radius: 6px; padding: 12px 16px; font-size: 13px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>{{scene_label}}（HTTP {{status_code}}）</h1>
    <p>您的请求触发了站点安全防护策略，已被拦截。</p>
    <div class="meta">
      <div>请求编号：{{request_id}}</div>
      <div>发生时间：{{time}}</div>
      <div>客户端 IP：{{client_ip}}</div>
      <div>访问站点：{{domain}}</div>
    </div>
  </div>
</body>
</html>`

const FALLBACK_THEMES: ThemePreset[] = [
  {
    key: 'classic_dark',
    label: '经典深空暗色',
    description: '深蓝暗色高对比卡片，稳重专业',
    bg_color: '#1b2431',
    card_color: '#232f42',
    primary_color: '#e06c75',
    text_color: '#e6e9ef',
  },
  {
    key: 'clean_light',
    label: '极简企业浅色',
    description: '明净留白卡片风格，适合品牌化对外站点',
    bg_color: '#f3f5f9',
    card_color: '#ffffff',
    primary_color: '#1d4ed8',
    text_color: '#1f2937',
  },
  {
    key: 'enterprise_blue',
    label: '政企蓝盾风格',
    description: '庄重深蓝顶栏与清晰公告区，适合政企机构',
    bg_color: '#edf2f7',
    card_color: '#ffffff',
    primary_color: '#0f2d52',
    text_color: '#1a202c',
  },
  {
    key: 'alert_red',
    label: '高危安全警示',
    description: '强对比赤红警戒条，突出恶意攻击拦截',
    bg_color: '#181216',
    card_color: '#241a20',
    primary_color: '#dc2626',
    text_color: '#f5e9ec',
  },
  {
    key: 'amber_limit',
    label: '温和限流提示',
    description: '柔和琥珀色卡片，专为 CC 限速 429 场景设计',
    bg_color: '#fffbeb',
    card_color: '#ffffff',
    primary_color: '#d97706',
    text_color: '#451a03',
  },
]

const FALLBACK_PLACEHOLDERS: PlaceholderInfo[] = [
  { token: '{{request_id}}', label: '请求编号', description: '本次拦截唯一追踪 ID', example: 'req-8f2a9c41' },
  { token: '{{time}}', label: '发生时间（UTC）', description: '拦截 UTC 时间', example: '2026-11-26 15:30:00 UTC' },
  { token: '{{time_local}}', label: '北京时间', description: '拦截东八区时间', example: '2026-11-26 23:30:00 +0800' },
  { token: '{{client_ip}}', label: '客户端 IP', description: '真实客户端 IP', example: '203.0.113.42' },
  { token: '{{domain}}', label: '访问域名', description: '请求 Host 域名', example: 'shop.example.com' },
  { token: '{{path}}', label: '请求路径', description: 'URL 路径', example: '/api/v1/orders' },
  { token: '{{status_code}}', label: '状态码', description: 'HTTP 状态码', example: '403' },
  { token: '{{scene_label}}', label: '场景名称', description: '拦截场景中文名', example: 'WAF 安全拦截' },
  { token: '{{app_code}}', label: '应用编码', description: '受保护应用编码', example: 'shop' },
  { token: '{{retry_after}}', label: '等待秒数', description: '429 限速重试秒数', example: '60' },
  { token: '{{message}}', label: '补充说明', description: 'L7 规则提示文案', example: '触发访问控制规则' },
]

const FALLBACK_SCENES: SceneInfo[] = [
  { key: 'DEFAULT', label: '通用默认', description: '未单独配置具体场景时的统一兜底页面' },
  { key: 'WAF', label: 'WAF 攻击拦截', description: 'Coraza/CRS 规则拦截与 API 通用 403 阻断' },
  { key: 'ACCESS_CONTROL', label: '访问控制与封禁', description: 'IP 黑名单、临时封禁、身份封禁、风险 403 与 L7 阻止' },
  { key: 'RATE_LIMIT', label: 'CC 与频率限制', description: 'CC 限速、授权配额限速、风险 429 与 API 限速' },
]

function utf8ByteLength(s: string): number {
  return new TextEncoder().encode(s).length
}

/**
 * 自定义拦截页面与多版本管理页。
 * 路由：/block-pages；权限：block_pages.read（查看/预览/历史）/ block_pages.manage（增删改/回滚/绑定）。
 */
export default function BlockPagesPage() {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'block_pages.manage')
  const canReadApps = hasPermission(permissions, 'applications.read')

  const [activeTab, setActiveTab] = useState<'templates' | 'bindings'>('templates')
  const [keyword, setKeyword] = useState('')
  const [modeFilter, setModeFilter] = useState<string>('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)

  const [bindingScopeFilter, setBindingScopeFilter] = useState<string>('')
  const [bindingSceneFilter, setBindingSceneFilter] = useState<string>('')

  // 编辑器抽屉状态
  const [editorOpen, setEditorOpen] = useState(false)
  const [editingPage, setEditingPage] = useState<BlockPageItem | null>(null)
  const [nameInput, setNameInput] = useState('')
  const [descInput, setDescInput] = useState('')
  const [editorMode, setEditorMode] = useState<BlockPageEditorMode>('VISUAL')
  const [themeKey, setThemeKey] = useState<string>('classic_dark')
  const [visualCfg, setVisualCfg] = useState<VisualConfig>(DEFAULT_VISUAL_CONFIG)
  const [htmlContent, setHtmlContent] = useState(DEFAULT_HTML_STARTER)
  const [statusCode, setStatusCode] = useState<number>(0)
  const [jsonCode, setJsonCode] = useState('')
  const [jsonMessage, setJsonMessage] = useState('')
  const [changeNote, setChangeNote] = useState('')
  const [previewScene, setPreviewScene] = useState<BlockPageScene>('WAF')
  const [previewDevice, setPreviewDevice] = useState<'desktop' | 'mobile'>('desktop')
  const [previewResult, setPreviewResult] = useState<PreviewBlockPageResult | null>(null)
  const [previewLoading, setPreviewLoading] = useState(false)
  const [previewError, setPreviewError] = useState<string | null>(null)

  // 版本历史抽屉状态
  const [historyPageId, setHistoryPageId] = useState<string | null>(null)
  const [selectedVersion, setSelectedVersion] = useState<BlockPageVersionItem | null>(null)
  const [historyPreviewHtml, setHistoryPreviewHtml] = useState<string>('')
  const [historyPreviewScene, setHistoryPreviewScene] = useState<BlockPageScene>('WAF')

  // 快速预览弹窗状态
  const [quickPreviewTarget, setQuickPreviewTarget] = useState<{
    title: string
    pageId: string
    version?: number
    scene?: BlockPageScene
  } | null>(null)
  const [quickPreviewHtml, setQuickPreviewHtml] = useState('')
  const [quickPreviewScene, setQuickPreviewScene] = useState<BlockPageScene>('WAF')
  const [quickPreviewLoading, setQuickPreviewLoading] = useState(false)

  // 复制模板弹窗状态
  const [cloneSource, setCloneSource] = useState<BlockPageItem | null>(null)
  const [cloneName, setCloneName] = useState('')

  // 生效绑定弹窗状态
  const [bindingModalOpen, setBindingModalOpen] = useState(false)
  const [bindingForm] = Form.useForm<{
    scope: string
    scene: BlockPageScene
    block_page_id: string
    version_mode: 'latest' | 'pinned'
    pinned_version?: number
    enabled: boolean
  }>()
  const watchedBindingPageId = Form.useWatch('block_page_id', bindingForm)
  const watchedVersionMode = Form.useWatch('version_mode', bindingForm)

  // ---------- 查询 ----------

  const listQuery = useQuery({
    queryKey: ['block-pages', keyword, modeFilter, page, pageSize],
    queryFn: () =>
      blockPagesApi.list({
        keyword: keyword.trim() || undefined,
        editor_mode: modeFilter || undefined,
        page,
        page_size: pageSize,
      }),
  })

  const allPagesQuery = useQuery({
    queryKey: ['block-pages-all'],
    queryFn: () => blockPagesApi.list({ page: 1, page_size: 100 }),
    enabled: bindingModalOpen || activeTab === 'bindings',
  })

  const bindingsQuery = useQuery({
    queryKey: ['block-page-bindings', bindingScopeFilter, bindingSceneFilter],
    queryFn: () =>
      blockPagesApi.listBindings({
        application_id: bindingScopeFilter || undefined,
        scene: bindingSceneFilter || undefined,
      }),
  })

  const appsQuery = useQuery({
    queryKey: ['block-pages-applications'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 200 }),
    enabled: canReadApps && (canManage || activeTab === 'bindings'),
  })

  const historyDetailQuery = useQuery({
    queryKey: ['block-page-detail', historyPageId],
    queryFn: () => blockPagesApi.get(historyPageId!),
    enabled: Boolean(historyPageId),
  })

  const bindingPageDetailQuery = useQuery({
    queryKey: ['block-page-detail-for-bind', watchedBindingPageId],
    queryFn: () => blockPagesApi.get(watchedBindingPageId!),
    enabled: bindingModalOpen && Boolean(watchedBindingPageId),
  })

  const themes = useMemo(
    () =>
      listQuery.data?.themes && listQuery.data.themes.length > 0
        ? listQuery.data.themes
        : FALLBACK_THEMES,
    [listQuery.data?.themes],
  )
  const placeholders = useMemo(
    () =>
      listQuery.data?.placeholders && listQuery.data.placeholders.length > 0
        ? listQuery.data.placeholders
        : FALLBACK_PLACEHOLDERS,
    [listQuery.data?.placeholders],
  )
  const scenes = useMemo(
    () =>
      listQuery.data?.scenes && listQuery.data.scenes.length > 0
        ? listQuery.data.scenes
        : FALLBACK_SCENES,
    [listQuery.data?.scenes],
  )

  const themeMap = useMemo(() => {
    const m = new Map<string, ThemePreset>()
    for (const t of themes) m.set(t.key, t)
    return m
  }, [themes])

  // ---------- 实时预览 ----------

  const runDraftPreview = useCallback(async () => {
    setPreviewLoading(true)
    setPreviewError(null)
    try {
      const res = await blockPagesApi.preview({
        editor_mode: editorMode,
        theme: themeKey,
        visual_config: editorMode === 'VISUAL' ? visualCfg : undefined,
        html_content: editorMode === 'HTML' ? htmlContent : undefined,
        status_code: statusCode,
        scene: previewScene,
      })
      setPreviewResult(res)
    } catch (err) {
      setPreviewError(err instanceof ApiError ? err.message : '预览渲染失败')
    } finally {
      setPreviewLoading(false)
    }
  }, [editorMode, themeKey, visualCfg, htmlContent, statusCode, previewScene])

  useEffect(() => {
    if (!editorOpen) return
    const timer = window.setTimeout(() => {
      void runDraftPreview()
    }, 300)
    return () => window.clearTimeout(timer)
  }, [editorOpen, runDraftPreview])

  // 历史版本选中后刷新沙箱预览
  useEffect(() => {
    if (!historyDetailQuery.data) return
    const versions = historyDetailQuery.data.versions
    if (versions.length > 0 && (!selectedVersion || selectedVersion.block_page_id !== historyDetailQuery.data.block_page.id)) {
      setSelectedVersion(versions[0])
    }
  }, [historyDetailQuery.data, selectedVersion])

  useEffect(() => {
    if (!historyPageId || !selectedVersion) {
      setHistoryPreviewHtml('')
      return
    }
    let cancelled = false
    void blockPagesApi
      .preview({
        block_page_id: historyPageId,
        version: selectedVersion.version,
        scene: historyPreviewScene,
      })
      .then((res) => {
        if (!cancelled) setHistoryPreviewHtml(res.rendered_html)
      })
      .catch(() => {
        if (!cancelled) setHistoryPreviewHtml(selectedVersion.rendered_html)
      })
    return () => {
      cancelled = true
    }
  }, [historyPageId, selectedVersion, historyPreviewScene])

  // 快速预览弹窗加载
  useEffect(() => {
    if (!quickPreviewTarget) {
      setQuickPreviewHtml('')
      return
    }
    let cancelled = false
    setQuickPreviewLoading(true)
    void blockPagesApi
      .preview({
        block_page_id: quickPreviewTarget.pageId,
        version: quickPreviewTarget.version,
        scene: quickPreviewScene,
      })
      .then((res) => {
        if (!cancelled) setQuickPreviewHtml(res.rendered_html)
      })
      .catch((err) => {
        if (!cancelled) {
          message.error(err instanceof ApiError ? err.message : '加载预览失败')
        }
      })
      .finally(() => {
        if (!cancelled) setQuickPreviewLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [quickPreviewTarget, quickPreviewScene, message])

  // ---------- 变更操作 ----------

  const invalidateAll = () => {
    void queryClient.invalidateQueries({ queryKey: ['block-pages'] })
    void queryClient.invalidateQueries({ queryKey: ['block-pages-all'] })
    void queryClient.invalidateQueries({ queryKey: ['block-page-bindings'] })
    if (historyPageId) {
      void queryClient.invalidateQueries({ queryKey: ['block-page-detail', historyPageId] })
    }
  }

  const saveMutation = useMutation({
    mutationFn: async () => {
      const trimmedName = nameInput.trim()
      if (!trimmedName) {
        throw new Error('请填写模板名称')
      }
      if (editingPage) {
        return blockPagesApi.update(editingPage.id, {
          expected_version: editingPage.version,
          name: trimmedName,
          description: descInput.trim(),
          editor_mode: editorMode,
          theme: themeKey,
          visual_config: visualCfg,
          html_content: editorMode === 'HTML' ? htmlContent : '',
          status_code: statusCode,
          json_code: jsonCode.trim(),
          json_message: jsonMessage.trim(),
          change_note: changeNote.trim(),
        })
      }
      return blockPagesApi.create({
        name: trimmedName,
        description: descInput.trim(),
        editor_mode: editorMode,
        theme: themeKey,
        visual_config: visualCfg,
        html_content: editorMode === 'HTML' ? htmlContent : '',
        status_code: statusCode,
        json_code: jsonCode.trim(),
        json_message: jsonMessage.trim(),
        change_note: changeNote.trim(),
      })
    },
    onSuccess: (res) => {
      const warnSuffix =
        res.warnings && res.warnings.length > 0
          ? `（已自动安全过滤 ${res.warnings.length} 项不安全内容）`
          : ''
      message.success(
        editingPage
          ? `已保存为新版本 v${res.block_page.version}${warnSuffix}`
          : `已创建拦截页模板 v1${warnSuffix}`,
      )
      setEditorOpen(false)
      invalidateAll()
    },
    onError: (err) => {
      message.error(err instanceof ApiError || err instanceof Error ? err.message : '保存失败')
    },
  })

  const cloneMutation = useMutation({
    mutationFn: async () => {
      if (!cloneSource) return
      const name = cloneName.trim()
      if (!name) throw new Error('请输入新模板名称')
      return blockPagesApi.create({
        name,
        clone_from_id: cloneSource.id,
        change_note: `复制自「${cloneSource.name}」v${cloneSource.version}`,
      })
    },
    onSuccess: () => {
      message.success('模板复制成功')
      setCloneSource(null)
      setCloneName('')
      invalidateAll()
    },
    onError: (err) => {
      message.error(err instanceof ApiError || err instanceof Error ? err.message : '复制失败')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => blockPagesApi.remove(id),
    onSuccess: () => {
      message.success('已删除拦截页模板')
      invalidateAll()
    },
    onError: (err) => {
      message.error(err instanceof ApiError ? err.message : '删除失败')
    },
  })

  const rollbackMutation = useMutation({
    mutationFn: ({
      pageId,
      expectedVersion,
      targetVersion,
    }: {
      pageId: string
      expectedVersion: number
      targetVersion: number
    }) =>
      blockPagesApi.rollback(pageId, {
        expected_version: expectedVersion,
        target_version: targetVersion,
        change_note: `从历史面板回滚至 v${targetVersion}`,
      }),
    onSuccess: (res) => {
      message.success(`已回滚并生成新版本 v${res.block_page.version}，请前往「配置发布」下发生效`)
      setSelectedVersion(res.version)
      invalidateAll()
    },
    onError: (err) => {
      message.error(err instanceof ApiError ? err.message : '回滚失败')
    },
  })

  const upsertBindingMutation = useMutation({
    mutationFn: async () => {
      const vals = await bindingForm.validateFields()
      return blockPagesApi.upsertBinding({
        application_id: vals.scope === 'global' ? null : vals.scope,
        scene: vals.scene,
        block_page_id: vals.block_page_id,
        pinned_version:
          vals.version_mode === 'pinned' && vals.pinned_version
            ? vals.pinned_version
            : null,
        enabled: vals.enabled,
      })
    },
    onSuccess: () => {
      message.success('生效绑定已保存，请前往「配置发布」同步至网关生效')
      setBindingModalOpen(false)
      invalidateAll()
    },
    onError: (err) => {
      if (err instanceof ApiError) {
        message.error(err.message)
      }
    },
  })

  const deleteBindingMutation = useMutation({
    mutationFn: (id: string) => blockPagesApi.deleteBinding(id),
    onSuccess: () => {
      message.success('已解除绑定，配置发布后将回退上级或系统默认拦截页')
      invalidateAll()
    },
    onError: (err) => {
      message.error(err instanceof ApiError ? err.message : '解除绑定失败')
    },
  })

  // ---------- 辅助操作 ----------

  const openCreateEditor = () => {
    setEditingPage(null)
    setNameInput('')
    setDescInput('')
    setEditorMode('VISUAL')
    setThemeKey('classic_dark')
    setVisualCfg({ ...DEFAULT_VISUAL_CONFIG })
    setHtmlContent(DEFAULT_HTML_STARTER)
    setStatusCode(0)
    setJsonCode('')
    setJsonMessage('')
    setChangeNote('初始创建版本')
    setPreviewScene('WAF')
    setPreviewResult(null)
    setEditorOpen(true)
  }

  const openEditEditor = (record: BlockPageItem) => {
    setEditingPage(record)
    setNameInput(record.name)
    setDescInput(record.description)
    setEditorMode(record.editor_mode)
    setThemeKey(record.theme || 'classic_dark')
    setVisualCfg({ ...DEFAULT_VISUAL_CONFIG, ...(record.visual_config ?? {}) })
    setHtmlContent(record.html_content || record.rendered_html || DEFAULT_HTML_STARTER)
    setStatusCode(record.status_code ?? 0)
    setJsonCode(record.json_code ?? '')
    setJsonMessage(record.json_message ?? '')
    setChangeNote('')
    setPreviewScene(record.status_code === 429 ? 'RATE_LIMIT' : 'WAF')
    setPreviewResult(null)
    setEditorOpen(true)
  }

  const convertVisualToHtml = async () => {
    try {
      const res = await blockPagesApi.preview({
        editor_mode: 'VISUAL',
        theme: themeKey,
        visual_config: visualCfg,
        status_code: statusCode,
        scene: previewScene,
      })
      setHtmlContent(res.sanitized_template_html || DEFAULT_HTML_STARTER)
      setEditorMode('HTML')
      message.info('已将当前可视化配置转换为可自由微调的 HTML/CSS 源码')
    } catch (err) {
      message.error(err instanceof ApiError ? err.message : '转换源码失败')
    }
  }

  const insertPlaceholder = (token: string) => {
    setHtmlContent((prev) => `${prev}${token}`)
  }

  const openBindingModal = (preset?: {
    scope?: string
    scene?: BlockPageScene
    pageId?: string
    pinnedVersion?: number | null
    enabled?: boolean
  }) => {
    bindingForm.setFieldsValue({
      scope: preset?.scope ?? 'global',
      scene: preset?.scene ?? 'DEFAULT',
      block_page_id: preset?.pageId ?? listQuery.data?.items[0]?.id,
      version_mode: preset?.pinnedVersion ? 'pinned' : 'latest',
      pinned_version: preset?.pinnedVersion ?? undefined,
      enabled: preset?.enabled ?? true,
    })
    setBindingModalOpen(true)
  }

  // ---------- 表格列定义 ----------

  const templateColumns: ColumnsType<BlockPageItem> = [
    {
      title: '模板名称',
      dataIndex: 'name',
      width: 240,
      render: (_: unknown, record) => (
        <Space direction="vertical" size={2}>
          <Space size={6}>
            <Text strong>{record.name}</Text>
            {record.is_builtin && <Tag color="geekblue">内置预设</Tag>}
          </Space>
          {record.description && (
            <Text type="secondary" style={{ fontSize: 12 }}>
              {record.description}
            </Text>
          )}
        </Space>
      ),
    },
    {
      title: '编辑模式 / 皮肤',
      key: 'mode',
      width: 170,
      render: (_, record) => {
        const theme = themeMap.get(record.theme)
        return (
          <Space direction="vertical" size={4}>
            <Tag
              icon={record.editor_mode === 'VISUAL' ? <SkinOutlined /> : <CodeOutlined />}
              color={record.editor_mode === 'VISUAL' ? 'cyan' : 'purple'}
            >
              {record.editor_mode === 'VISUAL' ? '可视化配置' : 'HTML 源码'}
            </Tag>
            {record.editor_mode === 'VISUAL' && (
              <Space size={6}>
                <span
                  style={{
                    display: 'inline-block',
                    width: 10,
                    height: 10,
                    borderRadius: 2,
                    background: theme?.primary_color ?? '#1d4ed8',
                    border: '1px solid rgba(0,0,0,0.15)',
                  }}
                />
                <Text type="secondary" style={{ fontSize: 12 }}>
                  {theme?.label ?? record.theme}
                </Text>
              </Space>
            )}
          </Space>
        )
      },
    },
    {
      title: '最新版本',
      dataIndex: 'version',
      width: 96,
      render: (v: number) => <Tag color="blue">v{v}</Tag>,
    },
    {
      title: '响应状态码',
      dataIndex: 'status_code',
      width: 110,
      render: (code: number) =>
        code === 0 ? (
          <Tag>沿用拦截码</Tag>
        ) : (
          <Tag color={code === 429 ? 'orange' : 'red'}>HTTP {code}</Tag>
        ),
    },
    {
      title: '生效绑定',
      dataIndex: 'binding_count',
      width: 100,
      render: (cnt: number) =>
        cnt > 0 ? (
          <Badge status="processing" text={`${cnt} 处生效`} />
        ) : (
          <Text type="secondary">未绑定</Text>
        ),
    },
    {
      title: '最后更新',
      dataIndex: 'updated_at',
      width: 180,
      render: (ts: string, record) => (
        <Space direction="vertical" size={0}>
          <Text style={{ fontSize: 12 }}>{formatDateTime(ts)}</Text>
          <Text type="secondary" style={{ fontSize: 12 }}>
            {record.updated_by || '-'}
          </Text>
        </Space>
      ),
    },
    {
      title: '操作',
      key: 'actions',
      width: 310,
      render: (_, record) => (
        <Space size={4} wrap>
          <Button
            type="link"
            size="small"
            icon={<EyeOutlined />}
            onClick={() => {
              const sc: BlockPageScene = record.status_code === 429 ? 'RATE_LIMIT' : 'WAF'
              setQuickPreviewScene(sc)
              setQuickPreviewTarget({
                title: `${record.name}（v${record.version}）`,
                pageId: record.id,
                version: record.version,
                scene: sc,
              })
            }}
          >
            预览
          </Button>
          <Button
            type="link"
            size="small"
            icon={<HistoryOutlined />}
            onClick={() => {
              setSelectedVersion(null)
              setHistoryPreviewScene(record.status_code === 429 ? 'RATE_LIMIT' : 'WAF')
              setHistoryPageId(record.id)
            }}
          >
            版本历史
          </Button>
          {canManage && (
            <>
              <Button
                type="link"
                size="small"
                icon={<EditOutlined />}
                onClick={() => openEditEditor(record)}
              >
                编辑
              </Button>
              <Button
                type="link"
                size="small"
                icon={<CopyOutlined />}
                onClick={() => {
                  setCloneSource(record)
                  setCloneName(`${record.name} - 副本`)
                }}
              >
                复制
              </Button>
              <Button
                type="link"
                size="small"
                icon={<LinkOutlined />}
                onClick={() =>
                  openBindingModal({
                    scope: 'global',
                    scene: record.status_code === 429 ? 'RATE_LIMIT' : 'DEFAULT',
                    pageId: record.id,
                  })
                }
              >
                设为生效
              </Button>
              {record.is_builtin || record.binding_count > 0 ? (
                <Tooltip
                  title={
                    record.is_builtin
                      ? '内置预设模板不可删除'
                      : '模板仍存在生效绑定，请先解除绑定'
                  }
                >
                  <Button type="link" size="small" danger disabled icon={<DeleteOutlined />}>
                    删除
                  </Button>
                </Tooltip>
              ) : (
                <Popconfirm
                  title={`确认删除模板「${record.name}」及其全部版本历史？`}
                  onConfirm={() => deleteMutation.mutate(record.id)}
                >
                  <Button type="link" size="small" danger icon={<DeleteOutlined />}>
                    删除
                  </Button>
                </Popconfirm>
              )}
            </>
          )}
        </Space>
      ),
    },
  ]

  const bindingColumns: ColumnsType<BlockPageBindingItem> = [
    {
      title: '生效范围',
      key: 'scope',
      width: 210,
      render: (_, record) =>
        record.application_id ? (
          <Space direction="vertical" size={0}>
            <Text strong>{record.application_name || record.application_code}</Text>
            <Text type="secondary" style={{ fontSize: 12 }}>
              应用覆盖（{record.application_code}）
            </Text>
          </Space>
        ) : (
          <Tag color="blue">全局默认</Tag>
        ),
    },
    {
      title: '拦截场景',
      dataIndex: 'scene',
      width: 160,
      render: (sc: BlockPageScene) => {
        const meta = SCENE_META[sc] ?? { label: sc, color: 'default' }
        return <Tag color={meta.color}>{meta.label}</Tag>
      },
    },
    {
      title: '绑定模板',
      dataIndex: 'block_page_name',
      render: (name: string) => <Text strong>{name}</Text>,
    },
    {
      title: '版本策略',
      key: 'version',
      width: 190,
      render: (_, record) =>
        record.pinned_version ? (
          <Space size={6}>
            <Tag color="gold">锁定 v{record.pinned_version}</Tag>
            {record.pinned_version < record.block_page_latest_version && (
              <Text type="secondary" style={{ fontSize: 12 }}>
                最新 v{record.block_page_latest_version}
              </Text>
            )}
          </Space>
        ) : (
          <Tag color="green">跟随最新（当前 v{record.effective_version}）</Tag>
        ),
    },
    {
      title: '状态',
      dataIndex: 'enabled',
      width: 90,
      render: (enabled: boolean) =>
        enabled ? <Badge status="success" text="已启用" /> : <Badge status="default" text="已停用" />,
    },
    {
      title: '更新时间',
      dataIndex: 'updated_at',
      width: 170,
      render: (ts: string) => <Text style={{ fontSize: 12 }}>{formatDateTime(ts)}</Text>,
    },
    {
      title: '操作',
      key: 'actions',
      width: 210,
      render: (_, record) => (
        <Space size={4}>
          <Button
            type="link"
            size="small"
            icon={<EyeOutlined />}
            onClick={() => {
              const sc: BlockPageScene = record.scene === 'DEFAULT' ? 'WAF' : record.scene
              setQuickPreviewScene(sc)
              setQuickPreviewTarget({
                title: `${record.block_page_name}（生效 v${record.effective_version}）`,
                pageId: record.block_page_id,
                version: record.effective_version,
                scene: sc,
              })
            }}
          >
            预览
          </Button>
          {canManage && (
            <>
              <Button
                type="link"
                size="small"
                icon={<EditOutlined />}
                onClick={() =>
                  openBindingModal({
                    scope: record.application_id ?? 'global',
                    scene: record.scene,
                    pageId: record.block_page_id,
                    pinnedVersion: record.pinned_version,
                    enabled: record.enabled,
                  })
                }
              >
                调整版本
              </Button>
              <Popconfirm
                title="确认解除该绑定？解除并发布后将自动回退上级或系统默认拦截页。"
                onConfirm={() => deleteBindingMutation.mutate(record.id)}
              >
                <Button type="link" size="small" danger icon={<DeleteOutlined />}>
                  解除
                </Button>
              </Popconfirm>
            </>
          )}
        </Space>
      ),
    },
  ]

  const htmlByteLen = utf8ByteLength(htmlContent)
  const historyDetail = historyDetailQuery.data
  const selectablePages = allPagesQuery.data?.items ?? listQuery.data?.items ?? []

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Alert
        type="info"
        showIcon
        message="自定义拦截页面与多版本管理"
        description={
          <Space wrap align="center" size={12}>
            <span>
              支持维护多套可视化或 HTML/CSS 拦截页模板及不可变历史版本，可按全局默认、应用站点及拦截场景（WAF 攻击 403 / 访问控制封禁 403 / CC 限速 429）灵活绑定或锁定指定版本。修改后需执行配置发布才会同步至网关生效。
            </span>
            <Link to="/config-publish">
              <Button size="small" type="primary" ghost icon={<CloudUploadOutlined />}>
                前往配置发布
              </Button>
            </Link>
          </Space>
        }
      />

      <Card>
        <Tabs
          activeKey={activeTab}
          onChange={(k) => setActiveTab(k as 'templates' | 'bindings')}
          items={[
            {
              key: 'templates',
              label: `拦截页模板库（${listQuery.data?.total ?? 0}）`,
              children: (
                <Space direction="vertical" size={16} style={{ width: '100%' }}>
                  <Space
                    style={{ width: '100%', justifyContent: 'space-between' }}
                    wrap
                  >
                    <Space wrap>
                      <Input.Search
                        placeholder="搜索模板名称或描述"
                        allowClear
                        value={keyword}
                        onChange={(e) => {
                          setKeyword(e.target.value)
                          setPage(1)
                        }}
                        style={{ width: 240 }}
                      />
                      <Select
                        style={{ width: 150 }}
                        value={modeFilter}
                        onChange={(v) => {
                          setModeFilter(v)
                          setPage(1)
                        }}
                        options={[
                          { label: '全部编辑模式', value: '' },
                          { label: '可视化配置', value: 'VISUAL' },
                          { label: 'HTML 源码', value: 'HTML' },
                        ]}
                      />
                    </Space>
                    <Space>
                      <Button
                        icon={<ReloadOutlined />}
                        onClick={() => void listQuery.refetch()}
                      >
                        刷新
                      </Button>
                      {canManage && (
                        <Button
                          type="primary"
                          icon={<PlusOutlined />}
                          onClick={openCreateEditor}
                        >
                          新建拦截页
                        </Button>
                      )}
                    </Space>
                  </Space>

                  {listQuery.isError && (
                    <Alert
                      type="error"
                      showIcon
                      message="加载拦截页模板失败"
                      description={
                        listQuery.error instanceof ApiError
                          ? listQuery.error.message
                          : undefined
                      }
                    />
                  )}

                  <Table<BlockPageItem>
                    rowKey="id"
                    loading={listQuery.isLoading}
                    columns={templateColumns}
                    dataSource={listQuery.data?.items ?? []}
                    scroll={{ x: 1050 }}
                    pagination={{
                      current: page,
                      pageSize,
                      total: listQuery.data?.total ?? 0,
                      showSizeChanger: true,
                      showTotal: (t) => `共 ${t} 套模板`,
                      onChange: (p, ps) => {
                        setPage(p)
                        setPageSize(ps)
                      },
                    }}
                  />
                </Space>
              ),
            },
            {
              key: 'bindings',
              label: `生效绑定策略（${bindingsQuery.data?.items.length ?? 0}）`,
              children: (
                <Space direction="vertical" size={16} style={{ width: '100%' }}>
                  <Alert
                    type="info"
                    showIcon
                    message="生效优先级：应用 + 具体场景 > 应用 + 通用默认 > 全局 + 具体场景 > 全局 + 通用默认 > 系统内置默认页"
                    description="未配置任何绑定时，网关保持原有内置 403 blockpage.html 与 429 限速响应页；API 协议专有返回（JSON 准入/GraphQL/gRPC/MCP/JWT 401/Bot 挑战页）不受影响。"
                  />
                  <Space
                    style={{ width: '100%', justifyContent: 'space-between' }}
                    wrap
                  >
                    <Space wrap>
                      <Select
                        style={{ width: 220 }}
                        value={bindingScopeFilter}
                        onChange={setBindingScopeFilter}
                        options={[
                          { label: '全部范围', value: '' },
                          { label: '仅全局默认', value: 'global' },
                          ...(appsQuery.data?.items ?? []).map((a) => ({
                            label: `${a.name} (${a.code})`,
                            value: a.id,
                          })),
                        ]}
                      />
                      <Select
                        style={{ width: 180 }}
                        value={bindingSceneFilter}
                        onChange={setBindingSceneFilter}
                        options={[
                          { label: '全部拦截场景', value: '' },
                          ...scenes.map((s) => ({ label: s.label, value: s.key })),
                        ]}
                      />
                    </Space>
                    {canManage && (
                      <Button
                        type="primary"
                        icon={<PlusOutlined />}
                        onClick={() => openBindingModal()}
                      >
                        新增 / 修改绑定
                      </Button>
                    )}
                  </Space>

                  <Table<BlockPageBindingItem>
                    rowKey="id"
                    loading={bindingsQuery.isLoading}
                    columns={bindingColumns}
                    dataSource={bindingsQuery.data?.items ?? []}
                    pagination={false}
                    locale={{
                      emptyText: (
                        <Empty description="暂未配置自定义生效绑定，当前使用系统内置默认拦截页" />
                      ),
                    }}
                  />
                </Space>
              ),
            },
          ]}
        />
      </Card>

      {/* 新建 / 编辑双栏实时预览抽屉 */}
      <Drawer
        title={
          editingPage
            ? `编辑拦截页「${editingPage.name}」（保存将生成 v${editingPage.version + 1}）`
            : '新建自定义拦截页（v1）'
        }
        open={editorOpen}
        onClose={() => setEditorOpen(false)}
        width="92%"
        styles={{ wrapper: { maxWidth: 1320 } }}
        destroyOnClose
        extra={
          <Space>
            <Button onClick={() => setEditorOpen(false)}>取消</Button>
            <Button
              type="primary"
              loading={saveMutation.isPending}
              onClick={() => saveMutation.mutate()}
            >
              {editingPage ? `保存为 v${editingPage.version + 1}` : '创建模板 v1'}
            </Button>
          </Space>
        }
      >
        <Row gutter={20}>
          {/* 左侧：配置表单 / 源码编辑 */}
          <Col xs={24} lg={12}>
            <Space direction="vertical" size={14} style={{ width: '100%' }}>
              <Row gutter={12}>
                <Col span={14}>
                  <Text strong>模板名称 *</Text>
                  <Input
                    style={{ marginTop: 4 }}
                    maxLength={BLOCK_PAGE_LIMITS.maxNameLen}
                    placeholder="例如：集团官网品牌 403 拦截页"
                    value={nameInput}
                    onChange={(e) => setNameInput(e.target.value)}
                  />
                </Col>
                <Col span={10}>
                  <Text strong>响应状态码覆盖</Text>
                  <Select
                    style={{ width: '100%', marginTop: 4 }}
                    value={statusCode}
                    onChange={setStatusCode}
                    options={[
                      { label: '0 — 沿用原拦截码（推荐）', value: 0 },
                      { label: '403 Forbidden', value: 403 },
                      { label: '429 Too Many Requests', value: 429 },
                      { label: '451 Unavailable For Legal Reasons', value: 451 },
                      { label: '503 Service Unavailable', value: 503 },
                    ]}
                  />
                </Col>
              </Row>

              <div>
                <Text strong>模板描述</Text>
                <Input
                  style={{ marginTop: 4 }}
                  maxLength={BLOCK_PAGE_LIMITS.maxDescriptionLen}
                  placeholder="简要说明适用业务或视觉风格"
                  value={descInput}
                  onChange={(e) => setDescInput(e.target.value)}
                />
              </div>

              <Space style={{ width: '100%', justifyContent: 'space-between' }} wrap>
                <Segmented<BlockPageEditorMode>
                  value={editorMode}
                  onChange={(v) => setEditorMode(v)}
                  options={[
                    { label: '可视化配置', value: 'VISUAL', icon: <SkinOutlined /> },
                    { label: '自定义 HTML/CSS 源码', value: 'HTML', icon: <CodeOutlined /> },
                  ]}
                />
                {editorMode === 'VISUAL' && (
                  <Button
                    size="small"
                    icon={<CodeOutlined />}
                    onClick={() => void convertVisualToHtml()}
                  >
                    转为 HTML 源码微调
                  </Button>
                )}
              </Space>

              {editorMode === 'VISUAL' ? (
                <Space direction="vertical" size={12} style={{ width: '100%' }}>
                  <div>
                    <Text strong>选择预设皮肤主题</Text>
                    <Row gutter={[8, 8]} style={{ marginTop: 6 }}>
                      {themes.map((t) => {
                        const selected = themeKey === t.key
                        return (
                          <Col span={8} key={t.key}>
                            <Card
                              size="small"
                              hoverable
                              onClick={() => setThemeKey(t.key)}
                              style={{
                                borderColor: selected ? '#1677ff' : undefined,
                                borderWidth: selected ? 2 : 1,
                              }}
                              styles={{ body: { padding: '8px 10px' } }}
                            >
                              <Space size={6}>
                                <span
                                  style={{
                                    display: 'inline-block',
                                    width: 14,
                                    height: 14,
                                    borderRadius: 3,
                                    background: t.bg_color,
                                    border: `2px solid ${t.primary_color}`,
                                  }}
                                />
                                <Text strong style={{ fontSize: 12 }}>
                                  {t.label}
                                </Text>
                              </Space>
                            </Card>
                          </Col>
                        )
                      })}
                    </Row>
                  </div>

                  <Row gutter={10}>
                    <Col span={10}>
                      <Text>角标文案</Text>
                      <Input
                        style={{ marginTop: 4 }}
                        value={visualCfg.badge}
                        onChange={(e) =>
                          setVisualCfg((v) => ({ ...v, badge: e.target.value }))
                        }
                      />
                    </Col>
                    <Col span={14}>
                      <Text>主标题 *</Text>
                      <Input
                        style={{ marginTop: 4 }}
                        value={visualCfg.title}
                        onChange={(e) =>
                          setVisualCfg((v) => ({ ...v, title: e.target.value }))
                        }
                      />
                    </Col>
                  </Row>

                  <Row gutter={10}>
                    <Col span={12}>
                      <Text>副标题（可选）</Text>
                      <Input
                        style={{ marginTop: 4 }}
                        value={visualCfg.subtitle ?? ''}
                        onChange={(e) =>
                          setVisualCfg((v) => ({ ...v, subtitle: e.target.value }))
                        }
                      />
                    </Col>
                    <Col span={12}>
                      <Text>品牌 / 机构落款</Text>
                      <Input
                        style={{ marginTop: 4 }}
                        value={visualCfg.brand_name ?? ''}
                        onChange={(e) =>
                          setVisualCfg((v) => ({ ...v, brand_name: e.target.value }))
                        }
                      />
                    </Col>
                  </Row>

                  <div>
                    <Text>拦截说明正文</Text>
                    <Input.TextArea
                      style={{ marginTop: 4 }}
                      rows={3}
                      value={visualCfg.description}
                      onChange={(e) =>
                        setVisualCfg((v) => ({ ...v, description: e.target.value }))
                      }
                    />
                  </div>

                  <div>
                    <Text>联系管理员提示</Text>
                    <Input.TextArea
                      style={{ marginTop: 4 }}
                      rows={2}
                      value={visualCfg.contact_info ?? ''}
                      onChange={(e) =>
                        setVisualCfg((v) => ({ ...v, contact_info: e.target.value }))
                      }
                    />
                  </div>

                  <Row gutter={10}>
                    <Col span={12}>
                      <Text>Logo 图片地址（可选）</Text>
                      <Input
                        style={{ marginTop: 4 }}
                        placeholder="https://... 或 /logo.png"
                        value={visualCfg.logo_url ?? ''}
                        onChange={(e) =>
                          setVisualCfg((v) => ({ ...v, logo_url: e.target.value }))
                        }
                      />
                    </Col>
                    <Col span={12}>
                      <Text>自定义主色调（留空随主题）</Text>
                      <Input
                        style={{ marginTop: 4 }}
                        placeholder="例如 #2563eb"
                        value={visualCfg.primary_color ?? ''}
                        onChange={(e) =>
                          setVisualCfg((v) => ({ ...v, primary_color: e.target.value }))
                        }
                      />
                    </Col>
                  </Row>

                  <Card size="small" title="显示诊断信息项">
                    <Space wrap size={[16, 8]}>
                      <Space size={6}>
                        <Switch
                          size="small"
                          checked={visualCfg.show_request_id}
                          onChange={(c) =>
                            setVisualCfg((v) => ({ ...v, show_request_id: c }))
                          }
                        />
                        <span>请求编号</span>
                      </Space>
                      <Space size={6}>
                        <Switch
                          size="small"
                          checked={visualCfg.show_timestamp}
                          onChange={(c) =>
                            setVisualCfg((v) => ({ ...v, show_timestamp: c }))
                          }
                        />
                        <span>发生时间</span>
                      </Space>
                      <Space size={6}>
                        <Switch
                          size="small"
                          checked={visualCfg.show_client_ip}
                          onChange={(c) =>
                            setVisualCfg((v) => ({ ...v, show_client_ip: c }))
                          }
                        />
                        <span>客户端 IP</span>
                      </Space>
                      <Space size={6}>
                        <Switch
                          size="small"
                          checked={visualCfg.show_domain}
                          onChange={(c) =>
                            setVisualCfg((v) => ({ ...v, show_domain: c }))
                          }
                        />
                        <span>访问站点</span>
                      </Space>
                      <Space size={6}>
                        <Switch
                          size="small"
                          checked={visualCfg.show_status_code}
                          onChange={(c) =>
                            setVisualCfg((v) => ({ ...v, show_status_code: c }))
                          }
                        />
                        <span>状态码</span>
                      </Space>
                      <Space size={6}>
                        <Switch
                          size="small"
                          checked={Boolean(visualCfg.show_retry_after)}
                          onChange={(c) =>
                            setVisualCfg((v) => ({ ...v, show_retry_after: c }))
                          }
                        />
                        <span>建议等待秒数（429）</span>
                      </Space>
                    </Space>
                  </Card>
                </Space>
              ) : (
                <Space direction="vertical" size={10} style={{ width: '100%' }}>
                  <Alert
                    type="info"
                    showIcon
                    message="允许自定义 HTML 与内联 <style>/class/style 及静态 SVG；保存与下发网关时自动移除 <script>、on* 事件属性、javascript: 链接及外部 CSS @import/url() 防 XSS。"
                  />
                  <div>
                    <Text type="secondary" style={{ fontSize: 12 }}>
                      点击插入动态变量（运行时自动 HTML 转义）：
                    </Text>
                    <div style={{ marginTop: 6, display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                      {placeholders.map((p) => (
                        <Tooltip key={p.token} title={`${p.description}（示例：${p.example}）`}>
                          <Tag
                            color="blue"
                            style={{ cursor: 'pointer', margin: 0 }}
                            onClick={() => insertPlaceholder(p.token)}
                          >
                            {p.label} {p.token}
                          </Tag>
                        </Tooltip>
                      ))}
                    </div>
                  </div>
                  <div>
                    <Space style={{ width: '100%', justifyContent: 'space-between', marginBottom: 4 }}>
                      <Text strong>HTML / CSS 源码 *</Text>
                      <Text
                        type={htmlByteLen > BLOCK_PAGE_LIMITS.maxHtmlBytes ? 'danger' : 'secondary'}
                        style={{ fontSize: 12 }}
                      >
                        {htmlByteLen} / {BLOCK_PAGE_LIMITS.maxHtmlBytes} 字节
                      </Text>
                    </Space>
                    <Input.TextArea
                      rows={16}
                      value={htmlContent}
                      onChange={(e) => setHtmlContent(e.target.value)}
                      style={{
                        fontFamily: '"SF Mono", Menlo, Consolas, monospace',
                        fontSize: 12,
                      }}
                    />
                  </div>
                </Space>
              )}

              <Collapse
                size="small"
                items={[
                  {
                    key: 'json',
                    label: 'JSON 客户端响应文案覆盖（可选，Accept: application/json 时生效）',
                    children: (
                      <Row gutter={10}>
                        <Col span={10}>
                          <Text>JSON 错误码（error）</Text>
                          <Input
                            style={{ marginTop: 4 }}
                            placeholder="留空沿用默认错误码"
                            maxLength={BLOCK_PAGE_LIMITS.maxJsonCodeBytes}
                            value={jsonCode}
                            onChange={(e) => setJsonCode(e.target.value)}
                          />
                        </Col>
                        <Col span={14}>
                          <Text>JSON 提示文案（message）</Text>
                          <Input
                            style={{ marginTop: 4 }}
                            placeholder="留空沿用默认中文文案"
                            maxLength={BLOCK_PAGE_LIMITS.maxJsonMessageBytes}
                            value={jsonMessage}
                            onChange={(e) => setJsonMessage(e.target.value)}
                          />
                        </Col>
                      </Row>
                    ),
                  },
                ]}
              />

              <div>
                <Text strong>本次版本变更说明</Text>
                <Input
                  style={{ marginTop: 4 }}
                  maxLength={BLOCK_PAGE_LIMITS.maxChangeNoteLen}
                  placeholder="例如：更新客服热线电话与品牌配色"
                  value={changeNote}
                  onChange={(e) => setChangeNote(e.target.value)}
                />
              </div>
            </Space>
          </Col>

          {/* 右侧：沙箱实时预览 */}
          <Col xs={24} lg={12}>
            <Card
              size="small"
              title="实时安全预览（沙箱隔离）"
              extra={
                <Space size={8}>
                  <Select<BlockPageScene>
                    size="small"
                    style={{ width: 140 }}
                    value={previewScene}
                    onChange={setPreviewScene}
                    options={[
                      { label: 'WAF 攻击 403', value: 'WAF' },
                      { label: '访问控制 403', value: 'ACCESS_CONTROL' },
                      { label: 'CC 限速 429', value: 'RATE_LIMIT' },
                    ]}
                  />
                  <Segmented<'desktop' | 'mobile'>
                    size="small"
                    value={previewDevice}
                    onChange={setPreviewDevice}
                    options={[
                      { value: 'desktop', icon: <DesktopOutlined /> },
                      { value: 'mobile', icon: <MobileOutlined /> },
                    ]}
                  />
                  <Button
                    size="small"
                    icon={<ReloadOutlined />}
                    loading={previewLoading}
                    onClick={() => void runDraftPreview()}
                  >
                    刷新
                  </Button>
                </Space>
              }
            >
              <Space direction="vertical" size={10} style={{ width: '100%' }}>
                {previewError && <Alert type="error" showIcon message={previewError} />}
                {previewResult?.warnings && previewResult.warnings.length > 0 && (
                  <Alert
                    type="warning"
                    showIcon
                    message={`安全净化提示（已过滤 ${previewResult.warnings.length} 项）`}
                    description={previewResult.warnings.join('；')}
                  />
                )}
                <div
                  style={{
                    background: '#f0f2f5',
                    borderRadius: 6,
                    padding: 12,
                    display: 'flex',
                    justifyContent: 'center',
                    minHeight: 540,
                  }}
                >
                  <Spin spinning={previewLoading}>
                    <iframe
                      title="拦截页实时预览"
                      sandbox=""
                      srcDoc={previewResult?.rendered_html ?? ''}
                      style={{
                        width: previewDevice === 'mobile' ? 375 : 580,
                        maxWidth: '100%',
                        height: 520,
                        border: '1px solid #d9d9d9',
                        borderRadius: 6,
                        background: '#ffffff',
                      }}
                    />
                  </Spin>
                </div>
                {previewResult && (
                  <Text type="secondary" style={{ fontSize: 12 }}>
                    模拟响应状态码：HTTP {previewResult.effective_status_code} · 净化后模板大小：
                    {previewResult.byte_size} / {previewResult.max_bytes} 字节
                  </Text>
                )}
              </Space>
            </Card>
          </Col>
        </Row>
      </Drawer>

      {/* 版本历史与回滚抽屉 */}
      <Drawer
        title={
          historyDetail
            ? `版本历史 — ${historyDetail.block_page.name}（当前 v${historyDetail.block_page.version}）`
            : '拦截页版本历史'
        }
        open={Boolean(historyPageId)}
        onClose={() => {
          setHistoryPageId(null)
          setSelectedVersion(null)
        }}
        width="88%"
        styles={{ wrapper: { maxWidth: 1180 } }}
      >
        <Spin spinning={historyDetailQuery.isLoading}>
          {historyDetail && (
            <Row gutter={20}>
              <Col xs={24} lg={11}>
                <Space direction="vertical" size={12} style={{ width: '100%' }}>
                  {historyDetail.bindings.length > 0 && (
                    <Alert
                      type="info"
                      showIcon
                      message={`当前有 ${historyDetail.bindings.length} 处生效绑定引用此模板`}
                      description={historyDetail.bindings
                        .map(
                          (b) =>
                            `${b.application_code || '全局默认'}/${SCENE_META[b.scene]?.label ?? b.scene}（${
                              b.pinned_version ? `锁定 v${b.pinned_version}` : '跟随最新'
                            }）`,
                        )
                        .join('、')}
                    />
                  )}
                  <Table<BlockPageVersionItem>
                    rowKey="id"
                    size="small"
                    pagination={false}
                    dataSource={historyDetail.versions}
                    rowClassName={(r) =>
                      selectedVersion?.id === r.id ? 'ant-table-row-selected' : ''
                    }
                    onRow={(r) => ({
                      onClick: () => setSelectedVersion(r),
                      style: { cursor: 'pointer' },
                    })}
                    columns={[
                      {
                        title: '版本',
                        dataIndex: 'version',
                        width: 72,
                        render: (v: number) => (
                          <Tag color={v === historyDetail.block_page.version ? 'blue' : 'default'}>
                            v{v}
                          </Tag>
                        ),
                      },
                      {
                        title: '变更说明 / 模式',
                        key: 'note',
                        render: (_, r) => (
                          <Space direction="vertical" size={0}>
                            <Text>{r.change_note || '-'}</Text>
                            <Text type="secondary" style={{ fontSize: 12 }}>
                              {r.editor_mode === 'VISUAL' ? '可视化' : 'HTML 源码'} ·{' '}
                              {r.created_by || '-'} · {formatDateTime(r.created_at)}
                            </Text>
                          </Space>
                        ),
                      },
                      {
                        title: '操作',
                        key: 'ops',
                        width: 110,
                        render: (_, r) =>
                          canManage && r.version !== historyDetail.block_page.version ? (
                            <Popconfirm
                              title={`确认将模板回滚到 v${r.version}？`}
                              description={`系统将以不可变方式追加生成 v${historyDetail.block_page.version + 1}，不覆盖旧记录。`}
                              onConfirm={() =>
                                rollbackMutation.mutate({
                                  pageId: historyDetail.block_page.id,
                                  expectedVersion: historyDetail.block_page.version,
                                  targetVersion: r.version,
                                })
                              }
                            >
                              <Button
                                type="link"
                                size="small"
                                icon={<RollbackOutlined />}
                                onClick={(e) => e.stopPropagation()}
                              >
                                回滚
                              </Button>
                            </Popconfirm>
                          ) : (
                            <Text type="secondary" style={{ fontSize: 12 }}>
                              {r.version === historyDetail.block_page.version ? '当前版本' : '-'}
                            </Text>
                          ),
                      },
                    ]}
                  />
                </Space>
              </Col>
              <Col xs={24} lg={13}>
                {selectedVersion ? (
                  <Card
                    size="small"
                    title={`历史版本 v${selectedVersion.version} 效果预览`}
                    extra={
                      <Select<BlockPageScene>
                        size="small"
                        style={{ width: 140 }}
                        value={historyPreviewScene}
                        onChange={setHistoryPreviewScene}
                        options={[
                          { label: 'WAF 攻击 403', value: 'WAF' },
                          { label: '访问控制 403', value: 'ACCESS_CONTROL' },
                          { label: 'CC 限速 429', value: 'RATE_LIMIT' },
                        ]}
                      />
                    }
                  >
                    <iframe
                      title={`历史版本 v${selectedVersion.version} 预览`}
                      sandbox=""
                      srcDoc={historyPreviewHtml || selectedVersion.rendered_html}
                      style={{
                        width: '100%',
                        height: 440,
                        border: '1px solid #d9d9d9',
                        borderRadius: 6,
                        background: '#ffffff',
                      }}
                    />
                    <Divider style={{ margin: '12px 0' }} />
                    <Collapse
                      size="small"
                      items={[
                        {
                          key: 'src',
                          label: `查看 v${selectedVersion.version} 净化后 HTML 源码（${utf8ByteLength(selectedVersion.rendered_html)} 字节）`,
                          children: (
                            <Paragraph
                              code
                              copyable
                              style={{
                                maxHeight: 200,
                                overflow: 'auto',
                                whiteSpace: 'pre-wrap',
                                fontSize: 12,
                                marginBottom: 0,
                              }}
                            >
                              {selectedVersion.rendered_html}
                            </Paragraph>
                          ),
                        },
                      ]}
                    />
                  </Card>
                ) : (
                  <Empty description="点击左侧版本号预览该历史版本" />
                )}
              </Col>
            </Row>
          )}
        </Spin>
      </Drawer>

      {/* 快速预览弹窗 */}
      <Modal
        title={quickPreviewTarget?.title ?? '拦截页预览'}
        open={Boolean(quickPreviewTarget)}
        onCancel={() => setQuickPreviewTarget(null)}
        footer={null}
        width={760}
      >
        <Space direction="vertical" size={12} style={{ width: '100%' }}>
          <Space>
            <Text>模拟拦截场景：</Text>
            <Select<BlockPageScene>
              size="small"
              style={{ width: 160 }}
              value={quickPreviewScene}
              onChange={setQuickPreviewScene}
              options={[
                { label: 'WAF 攻击 403', value: 'WAF' },
                { label: '访问控制 403', value: 'ACCESS_CONTROL' },
                { label: 'CC 限速 429', value: 'RATE_LIMIT' },
              ]}
            />
          </Space>
          <Spin spinning={quickPreviewLoading}>
            <iframe
              title="拦截页快速预览"
              sandbox=""
              srcDoc={quickPreviewHtml}
              style={{
                width: '100%',
                height: 480,
                border: '1px solid #d9d9d9',
                borderRadius: 6,
                background: '#ffffff',
              }}
            />
          </Spin>
        </Space>
      </Modal>

      {/* 复制模板弹窗 */}
      <Modal
        title={cloneSource ? `复制模板「${cloneSource.name}」` : '复制模板'}
        open={Boolean(cloneSource)}
        onCancel={() => setCloneSource(null)}
        onOk={() => cloneMutation.mutate()}
        confirmLoading={cloneMutation.isPending}
      >
        <Space direction="vertical" size={8} style={{ width: '100%' }}>
          <Text>新模板名称</Text>
          <Input
            maxLength={BLOCK_PAGE_LIMITS.maxNameLen}
            value={cloneName}
            onChange={(e) => setCloneName(e.target.value)}
            placeholder="请输入新模板名称"
          />
        </Space>
      </Modal>

      {/* 新增 / 修改生效绑定弹窗 */}
      <Modal
        title="配置拦截页生效绑定"
        open={bindingModalOpen}
        onCancel={() => setBindingModalOpen(false)}
        onOk={() => upsertBindingMutation.mutate()}
        confirmLoading={upsertBindingMutation.isPending}
        width={540}
      >
        <Form form={bindingForm} layout="vertical">
          <Form.Item
            name="scope"
            label="生效范围"
            rules={[{ required: true, message: '请选择生效范围' }]}
          >
            <Select
              showSearch
              optionFilterProp="label"
              options={[
                { label: '全局默认（全部未单独覆盖的应用）', value: 'global' },
                ...(appsQuery.data?.items ?? []).map((a) => ({
                  label: `应用：${a.name} (${a.code})`,
                  value: a.id,
                })),
              ]}
            />
          </Form.Item>
          <Form.Item
            name="scene"
            label="拦截场景"
            rules={[{ required: true, message: '请选择拦截场景' }]}
          >
            <Select
              options={scenes.map((s) => ({
                label: `${s.label} — ${s.description}`,
                value: s.key,
              }))}
            />
          </Form.Item>
          <Form.Item
            name="block_page_id"
            label="拦截页模板"
            rules={[{ required: true, message: '请选择拦截页模板' }]}
          >
            <Select
              showSearch
              optionFilterProp="label"
              options={selectablePages.map((p) => ({
                label: `${p.name}（最新 v${p.version}）`,
                value: p.id,
              }))}
            />
          </Form.Item>
          <Form.Item
            name="version_mode"
            label="版本追踪策略"
            rules={[{ required: true }]}
          >
            <Segmented
              options={[
                { label: '跟随模板最新版', value: 'latest' },
                { label: '锁定指定历史版本', value: 'pinned' },
              ]}
            />
          </Form.Item>
          {watchedVersionMode === 'pinned' && (
            <Form.Item
              name="pinned_version"
              label="锁定版本号"
              rules={[{ required: true, message: '请选择要锁定的历史版本' }]}
            >
              {bindingPageDetailQuery.data?.versions?.length ? (
                <Select
                  options={bindingPageDetailQuery.data.versions.map((v) => ({
                    label: `v${v.version} — ${v.change_note || formatDateTime(v.created_at)}`,
                    value: v.version,
                  }))}
                />
              ) : (
                <InputNumber min={1} style={{ width: '100%' }} placeholder="输入版本号" />
              )}
            </Form.Item>
          )}
          <Form.Item name="enabled" label="启用该绑定" valuePropName="checked">
            <Switch />
          </Form.Item>
        </Form>
      </Modal>
    </Space>
  )
}
