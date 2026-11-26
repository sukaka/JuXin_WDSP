import { useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Col,
  Descriptions,
  Drawer,
  Form,
  Input,
  InputNumber,
  Modal,
  Popconfirm,
  Radio,
  Row,
  Select,
  Space,
  Spin,
  Table,
  Tag,
  Tooltip,
  Typography,
  Upload,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import {
  CheckCircleFilled,
  CodeSandboxOutlined,
  DeleteOutlined,
  EditOutlined,
  HistoryOutlined,
  InboxOutlined,
  PlusOutlined,
  RollbackOutlined,
  SafetyCertificateOutlined,
  SwapOutlined,
} from '@ant-design/icons'
import { applicationsApi } from '../../api/applications'
import { ApiError } from '../../api/client'
import {
  WASM_PLUGIN_GLOBAL_SCOPE_QUERY,
  WASM_PLUGIN_LIMITS,
  wasmPluginsApi,
  type WasmPluginCreateBody,
  type WasmPluginFailPolicy,
  type WasmPluginItem,
  type WasmPluginMode,
  type WasmPluginRollbackBody,
  type WasmPluginUpdateBody,
  type WasmPluginVersionItem,
} from '../../api/wasmPlugins'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import {
  arrayBufferToBase64,
  formatShortSha256,
  formatWasmSizeKiB,
  mapWasmPluginFieldErrorPath,
  normalizePathPrefixes,
  validateExpectedSha256,
  validateWasmBinaryBuffer,
  validateWasmPathPrefixes,
  validateWasmPluginName,
  WASM_PLUGIN_FAIL_POLICY_META,
  WASM_PLUGIN_FAIL_POLICY_SHORT_META,
  WASM_PLUGIN_MODE_META,
} from '../../utils/wasmPlugins'

type ScopeFilterMode = 'ALL' | 'GLOBAL' | 'APPLICATION'
type EditorScopeType = 'GLOBAL' | 'APPLICATION'

interface AppOption {
  value: string
  label: string
}

const MODE_OPTIONS: { value: WasmPluginMode; label: string }[] = [
  { value: 'OFF', label: WASM_PLUGIN_MODE_META.OFF.label },
  { value: 'OBSERVE', label: WASM_PLUGIN_MODE_META.OBSERVE.label },
  { value: 'PROTECT', label: WASM_PLUGIN_MODE_META.PROTECT.label },
]

const FAIL_POLICY_OPTIONS: { value: WasmPluginFailPolicy; label: string }[] = [
  { value: 'FAIL_OPEN', label: WASM_PLUGIN_FAIL_POLICY_META.FAIL_OPEN.label },
  {
    value: 'FAIL_CLOSED',
    label: WASM_PLUGIN_FAIL_POLICY_META.FAIL_CLOSED.label,
  },
]

const SCOPE_FILTER_OPTIONS: { value: ScopeFilterMode; label: string }[] = [
  { value: 'ALL', label: '全部作用域' },
  { value: 'GLOBAL', label: '全局' },
  { value: 'APPLICATION', label: '指定应用' },
]

interface PluginFormValues {
  scope_type: EditorScopeType
  application_id?: string
  name: string
  description: string
  wasm_base64: string
  expected_sha256: string
  mode: WasmPluginMode
  priority: number
  timeout_ms: number
  max_memory_kb: number
  max_body_bytes: number
  fail_policy: WasmPluginFailPolicy
  path_prefixes: string[]
  reason: string
}

interface SelectedWasmFileInfo {
  name: string
  size: number
  sha256Preview?: string
}

async function readFileAsArrayBuffer(file: File): Promise<ArrayBuffer> {
  if (typeof file.arrayBuffer === 'function') {
    return file.arrayBuffer()
  }
  return new Promise<ArrayBuffer>((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => {
      if (reader.result instanceof ArrayBuffer) {
        resolve(reader.result)
      } else {
        reject(new Error('读取文件内容失败'))
      }
    }
    reader.onerror = () => reject(new Error('读取文件内容失败'))
    reader.readAsArrayBuffer(file)
  })
}

async function computeSha256HexBestEffort(
  buffer: ArrayBuffer,
): Promise<string | undefined> {
  try {
    const subtle = globalThis.crypto?.subtle
    if (!subtle || typeof subtle.digest !== 'function') return undefined
    const hash = await subtle.digest('SHA-256', buffer)
    return Array.from(new Uint8Array(hash))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
  } catch {
    return undefined
  }
}

interface WasmBinaryFieldProps {
  id?: string
  value?: string
  onChange?: (base64: string) => void
  editing?: WasmPluginItem | null
  disabled?: boolean
  onReadingChange?: (reading: boolean) => void
}

/** .wasm 二进制文件上传控件：纯内存读取并校验魔数头（\x00asm\x01\x00\x00\x00）与 4 MiB 上限 */
function WasmBinaryField({
  id,
  value,
  onChange,
  editing,
  disabled,
  onReadingChange,
}: WasmBinaryFieldProps) {
  const { message } = AntdApp.useApp()
  const [selectedFile, setSelectedFile] = useState<SelectedWasmFileInfo | null>(
    null,
  )
  const [localError, setLocalError] = useState<string | null>(null)
  const [reading, setReading] = useState(false)
  const readSeqRef = useRef(0)

  const handleBeforeUpload = (file: File) => {
    setLocalError(null)
    if (file.size === 0) {
      const err = 'Wasm 文件内容不能为空'
      setLocalError(err)
      setSelectedFile(null)
      onChange?.('')
      message.error(err)
      return false
    }
    if (file.size > WASM_PLUGIN_LIMITS.maxBinaryBytes) {
      const err = `Wasm 二进制大小不能超过 ${Math.round(WASM_PLUGIN_LIMITS.maxBinaryBytes / (1024 * 1024))} MiB`
      setLocalError(err)
      setSelectedFile(null)
      onChange?.('')
      message.error(err)
      return false
    }

    const seq = ++readSeqRef.current
    setReading(true)
    onReadingChange?.(true)

    void (async () => {
      try {
        const buffer = await readFileAsArrayBuffer(file)
        if (seq !== readSeqRef.current) return
        const validationErr = validateWasmBinaryBuffer(buffer)
        if (validationErr) {
          setLocalError(validationErr)
          setSelectedFile(null)
          onChange?.('')
          message.error(validationErr)
          return
        }
        const base64 = arrayBufferToBase64(buffer)
        const sha256Preview = await computeSha256HexBestEffort(buffer)
        if (seq !== readSeqRef.current) return
        setSelectedFile({
          name: file.name,
          size: buffer.byteLength,
          sha256Preview,
        })
        onChange?.(base64)
      } catch {
        if (seq !== readSeqRef.current) return
        const err = '读取 Wasm 文件失败，请重新选择'
        setLocalError(err)
        setSelectedFile(null)
        onChange?.('')
        message.error(err)
      } finally {
        if (seq === readSeqRef.current) {
          setReading(false)
          onReadingChange?.(false)
        }
      }
    })()

    return false
  }

  return (
    <div>
      {selectedFile && value ? (
        <div
          style={{
            padding: '10px 12px',
            border: '1px solid #b7eb8f',
            background: '#f6ffed',
            borderRadius: 8,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 8,
          }}
        >
          <Space size={8} style={{ minWidth: 0, flex: 1 }}>
            <CheckCircleFilled
              style={{ color: '#52c41a', fontSize: 16, flexShrink: 0 }}
            />
            <div style={{ minWidth: 0, flex: 1 }}>
              <Typography.Text
                strong
                ellipsis={{ tooltip: selectedFile.name }}
                style={{ display: 'block', lineHeight: 1.4 }}
              >
                {selectedFile.name}
              </Typography.Text>
              <Space size={6} wrap style={{ marginTop: 4 }}>
                <Tag color="green" style={{ marginInlineEnd: 0 }}>
                  {formatWasmSizeKiB(selectedFile.size)}
                </Tag>
                <Tag color="geekblue" style={{ marginInlineEnd: 0 }}>
                  WebAssembly 1.0 魔数校验通过
                </Tag>
                {selectedFile.sha256Preview && (
                  <Tooltip title={selectedFile.sha256Preview}>
                    <Typography.Text code style={{ fontSize: 11 }}>
                      SHA-256: {formatShortSha256(selectedFile.sha256Preview)}
                    </Typography.Text>
                  </Tooltip>
                )}
              </Space>
            </div>
          </Space>
          <Space size={0} style={{ flexShrink: 0 }}>
            <Upload
              id={id}
              accept=".wasm,application/wasm"
              maxCount={1}
              showUploadList={false}
              disabled={disabled || reading}
              beforeUpload={handleBeforeUpload}
            >
              <Button
                type="link"
                size="small"
                icon={<SwapOutlined />}
                disabled={disabled || reading}
              >
                更换
              </Button>
            </Upload>
            <Button
              type="link"
              size="small"
              danger
              icon={<DeleteOutlined />}
              disabled={disabled || reading}
              aria-label={`移除 ${selectedFile.name}`}
              onClick={() => {
                readSeqRef.current += 1
                setSelectedFile(null)
                setLocalError(null)
                onChange?.('')
              }}
            >
              移除
            </Button>
          </Space>
        </div>
      ) : (
        <Upload.Dragger
          id={id}
          accept=".wasm,application/wasm"
          maxCount={1}
          showUploadList={false}
          disabled={disabled || reading}
          beforeUpload={handleBeforeUpload}
          styles={{ root: { padding: 0 } }}
          style={{ padding: '14px 12px' }}
        >
          <p className="ant-upload-drag-icon" style={{ marginBottom: 4 }}>
            <InboxOutlined style={{ fontSize: 24 }} />
          </p>
          <p className="ant-upload-text" style={{ fontSize: 13, marginBottom: 2 }}>
            {reading
              ? '正在读取并校验 WebAssembly 模块…'
              : editing
                ? `点击或拖拽新的 .wasm 文件替换二进制（留空则保留当前 v${editing.version} 模块）`
                : '点击或拖拽 .wasm 插件二进制文件到此区域'}
          </p>
          <p className="ant-upload-hint" style={{ fontSize: 12, marginBottom: 0 }}>
            仅支持 WebAssembly 1.0（\0asm 魔数头），≤ 4 MiB，须导出 memory 与
            wdsp_on_request 且不得导入 WASI
          </p>
        </Upload.Dragger>
      )}
      {editing && !selectedFile && (
        <Typography.Paragraph
          type="secondary"
          style={{ fontSize: 12, marginTop: 6, marginBottom: 0 }}
        >
          当前线上模块：v{editing.version} · {formatWasmSizeKiB(editing.wasm_size)}{' '}
          · SHA-256{' '}
          <Typography.Text code style={{ fontSize: 11 }}>
            {formatShortSha256(editing.sha256)}
          </Typography.Text>
        </Typography.Paragraph>
      )}
      {localError && (
        <Alert
          type="error"
          showIcon
          style={{ marginTop: 8 }}
          title={localError}
        />
      )}
    </div>
  )
}

/** 插件上传/新建与编辑抽屉 */
function PluginEditorDrawer({
  editing,
  appOptions,
  appLabelMap,
  onClose,
  onSaved,
}: {
  editing: WasmPluginItem | null
  appOptions: AppOption[]
  appLabelMap: Map<string, string>
  onClose: () => void
  onSaved: () => void
}) {
  const { message } = AntdApp.useApp()
  const [form] = Form.useForm<PluginFormValues>()
  const [submitError, setSubmitError] = useState<string | null>(null)
  const [readingFile, setReadingFile] = useState(false)

  const scopeTypeWatch = Form.useWatch('scope_type', form) ?? 'GLOBAL'
  const modeWatch = Form.useWatch('mode', form) ?? 'OFF'
  const failPolicyWatch = Form.useWatch('fail_policy', form) ?? 'FAIL_OPEN'

  const handleApiError = (e: unknown) => {
    if (
      e instanceof ApiError &&
      (e.status === 409 || e.code === 'RESOURCE_CONFLICT')
    ) {
      const conflictMsg =
        e.message || '插件版本已变更或名称存在冲突，请刷新后重试'
      setSubmitError(conflictMsg)
      message.warning(conflictMsg)
      onSaved()
      return
    }
    if (e instanceof ApiError && Array.isArray(e.details)) {
      const details = e.details as { field?: string; message?: string }[]
      const fields: { name: (string | number)[]; errors: string[] }[] = []
      const unmapped: string[] = []
      for (const d of details) {
        if (!d.field) continue
        const errMsg = d.message ?? '取值不合法'
        const name = mapWasmPluginFieldErrorPath(d.field)
        if (name) {
          fields.push({ name, errors: [errMsg] })
        } else {
          unmapped.push(`${d.field}: ${errMsg}`)
        }
      }
      if (fields.length > 0) {
        form.setFields(fields as Parameters<typeof form.setFields>[0])
      }
      setSubmitError(
        unmapped.length > 0
          ? `${e.message}（${unmapped.join('；')}）`
          : e.message || '提交校验失败，请检查表单输入',
      )
      return
    }
    setSubmitError(e instanceof ApiError ? e.message : '保存插件失败')
  }

  const createMut = useMutation({
    mutationFn: (body: WasmPluginCreateBody) => wasmPluginsApi.create(body),
    onSuccess: (created) => {
      message.success(
        `Wasm 插件「${created.name}」已创建（v${created.version}）；需经配置发布同步到网关节点`,
      )
      onSaved()
      onClose()
    },
    onError: handleApiError,
  })

  const updateMut = useMutation({
    mutationFn: ({ id, body }: { id: string; body: WasmPluginUpdateBody }) =>
      wasmPluginsApi.update(id, body),
    onSuccess: (updated) => {
      message.success(
        `Wasm 插件「${updated.name}」已更新至 v${updated.version}；需经配置发布同步到网关节点`,
      )
      onSaved()
      onClose()
    },
    onError: handleApiError,
  })

  const isPending = createMut.isPending || updateMut.isPending

  const handleFinish = (values: PluginFormValues) => {
    setSubmitError(null)
    const prefixes = normalizePathPrefixes(values.path_prefixes)
    const expectedSha = (values.expected_sha256 ?? '').trim().toLowerCase()
    const reason = (values.reason ?? '').trim()
    const description = (values.description ?? '').trim()

    if (editing) {
      const body: WasmPluginUpdateBody = {
        expected_version: editing.version,
        description,
        mode: values.mode,
        priority: values.priority,
        timeout_ms: values.timeout_ms,
        max_memory_kb: values.max_memory_kb,
        max_body_bytes: values.max_body_bytes,
        fail_policy: values.fail_policy,
        path_prefixes: prefixes,
        reason,
      }
      if (values.wasm_base64) {
        body.wasm_base64 = values.wasm_base64
      }
      if (expectedSha) {
        body.expected_sha256 = expectedSha
      }
      updateMut.mutate({ id: editing.id, body })
      return
    }

    const body: WasmPluginCreateBody = {
      name: values.name.trim(),
      application_id:
        values.scope_type === 'APPLICATION'
          ? (values.application_id ?? '').trim() || null
          : null,
      description,
      mode: values.mode,
      wasm_base64: values.wasm_base64,
      priority: values.priority,
      timeout_ms: values.timeout_ms,
      max_memory_kb: values.max_memory_kb,
      max_body_bytes: values.max_body_bytes,
      fail_policy: values.fail_policy,
      path_prefixes: prefixes,
      reason,
    }
    if (expectedSha) {
      body.expected_sha256 = expectedSha
    }
    createMut.mutate(body)
  }

  return (
    <Drawer
      title={
        editing ? `编辑 Wasm 检测插件：${editing.name}` : '上传 Wasm 检测插件'
      }
      open
      size="large"
      onClose={onClose}
      extra={
        <Space>
          <Button onClick={onClose} disabled={isPending}>
            取消
          </Button>
          <Button
            type="primary"
            loading={isPending}
            disabled={readingFile}
            onClick={() => form.submit()}
          >
            {editing ? '保存更新' : '上传并创建'}
          </Button>
        </Space>
      }
    >
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        title="零权限 WebAssembly 沙箱安全声明（ABI: wdsp_v1）"
        description="所有自定义检测插件在 wazero 纯解释器沙箱中运行，零 WASI、零网络、零文件与环境变量权限，每次请求创建独立实例并强制执行硬超时与内存上限；宿主严格屏蔽 Authorization、Cookie、Proxy-Authorization、DPoP、X-Api-Key 等敏感凭据请求头，插件无法读取用户凭据，且返回 ALLOW 绝不绕过下游 API 防护与 Coraza WAF。"
      />

      {submitError && (
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 16 }}
          title="提交失败"
          description={submitError}
        />
      )}

      <Form<PluginFormValues>
        form={form}
        layout="vertical"
        initialValues={{
          scope_type: editing?.application_id ? 'APPLICATION' : 'GLOBAL',
          application_id: editing?.application_id ?? undefined,
          name: editing?.name ?? '',
          description: editing?.description ?? '',
          wasm_base64: '',
          expected_sha256: '',
          mode: editing?.mode ?? 'OBSERVE',
          priority: editing?.priority ?? WASM_PLUGIN_LIMITS.defaultPriority,
          timeout_ms: editing?.timeout_ms ?? WASM_PLUGIN_LIMITS.defaultTimeoutMs,
          max_memory_kb:
            editing?.max_memory_kb ?? WASM_PLUGIN_LIMITS.defaultMaxMemoryKb,
          max_body_bytes:
            editing?.max_body_bytes ?? WASM_PLUGIN_LIMITS.defaultMaxBodyBytes,
          fail_policy: editing?.fail_policy ?? 'FAIL_OPEN',
          path_prefixes: editing?.path_prefixes ?? [],
          reason: '',
        }}
        onFinish={handleFinish}
      >
        <Row gutter={16}>
          <Col xs={24} sm={12}>
            <Form.Item
              name="name"
              label="插件名称"
              extra="仅限字母、数字、点、下划线和短横线，创建后不可修改"
              rules={[
                {
                  validator: (_, v?: string) => {
                    const err = validateWasmPluginName(v)
                    return err
                      ? Promise.reject(new Error(err))
                      : Promise.resolve()
                  },
                },
              ]}
            >
              <Input
                placeholder="如 custom-graphql-guard"
                maxLength={WASM_PLUGIN_LIMITS.maxNameLen}
                disabled={Boolean(editing)}
                autoComplete="off"
              />
            </Form.Item>
          </Col>
          <Col xs={24} sm={12}>
            <Form.Item
              name="scope_type"
              label="生效作用域"
              extra={
                editing
                  ? '编辑模式不支持变更生效作用域'
                  : `同一作用域最多可注册 ${WASM_PLUGIN_LIMITS.maxPluginsPerScope} 个插件`
              }
            >
              {editing ? (
                <Tag color={editing.application_id ? 'blue' : 'purple'}>
                  {editing.application_id
                    ? appLabelMap.get(editing.application_id) ||
                      editing.application_id
                    : '全局（所有应用）'}
                </Tag>
              ) : (
                <Radio.Group optionType="button" buttonStyle="solid">
                  <Radio.Button value="GLOBAL">全局生效</Radio.Button>
                  <Radio.Button value="APPLICATION">指定应用</Radio.Button>
                </Radio.Group>
              )}
            </Form.Item>
          </Col>
        </Row>

        {!editing && scopeTypeWatch === 'APPLICATION' && (
          <Form.Item
            name="application_id"
            label="所属应用"
            rules={[{ required: true, whitespace: true, message: '请选择所属应用' }]}
          >
            {appOptions.length > 0 ? (
              <Select
                showSearch
                optionFilterProp="label"
                placeholder="请选择指定应用"
                options={appOptions}
              />
            ) : (
              <Input placeholder="输入应用 ID（UUID）" autoComplete="off" />
            )}
          </Form.Item>
        )}

        <Form.Item name="description" label="插件说明（可选）">
          <Input
            placeholder="简要说明该 Wasm 检测插件的检测逻辑与适用业务场景"
            maxLength={500}
            autoComplete="off"
          />
        </Form.Item>

        <Form.Item
          name="wasm_base64"
          label={editing ? '更新 Wasm 模块文件（可选）' : '上传 Wasm 模块文件（.wasm）'}
          rules={
            editing
              ? []
              : [{ required: true, message: '请上传有效的 .wasm 插件文件' }]
          }
        >
          <WasmBinaryField
            id="wasm-binary-upload"
            editing={editing}
            disabled={isPending}
            onReadingChange={setReadingFile}
          />
        </Form.Item>

        <Form.Item
          name="expected_sha256"
          label="预期 SHA-256 校验值（可选）"
          extra="可选：填写构建流水线输出的 64 位十六进制 SHA-256 摘要，服务端将在编译校验前执行恒定时间完整性比对"
          rules={[
            {
              validator: (_, v?: string) => {
                const err = validateExpectedSha256(v)
                return err ? Promise.reject(new Error(err)) : Promise.resolve()
              },
            },
          ]}
        >
          <Input
            placeholder="64 位十六进制 SHA-256（留空则由服务端自动计算并固定）"
            maxLength={64}
            autoComplete="off"
            style={{ fontFamily: 'monospace' }}
          />
        </Form.Item>

        <Row gutter={16}>
          <Col xs={24} sm={12}>
            <Form.Item
              name="mode"
              label="运行模式"
              extra="建议先使用「观察中」验证误报与耗时后再切换至「强制执行」"
              rules={[{ required: true, message: '请选择运行模式' }]}
            >
              <Select options={MODE_OPTIONS} />
            </Form.Item>
          </Col>
          <Col xs={24} sm={12}>
            <Form.Item
              name="priority"
              label="执行优先级"
              extra={`范围 ${WASM_PLUGIN_LIMITS.minPriority}~${WASM_PLUGIN_LIMITS.maxPriority}（默认 ${WASM_PLUGIN_LIMITS.defaultPriority}，数值越小越先执行）`}
              rules={[
                { required: true, message: '请填写执行优先级' },
                {
                  type: 'number',
                  min: WASM_PLUGIN_LIMITS.minPriority,
                  max: WASM_PLUGIN_LIMITS.maxPriority,
                  message: `优先级须在 ${WASM_PLUGIN_LIMITS.minPriority} 到 ${WASM_PLUGIN_LIMITS.maxPriority} 之间`,
                },
              ]}
            >
              <InputNumber
                min={WASM_PLUGIN_LIMITS.minPriority}
                max={WASM_PLUGIN_LIMITS.maxPriority}
                precision={0}
                style={{ width: '100%' }}
              />
            </Form.Item>
          </Col>
        </Row>

        <Row gutter={16}>
          <Col xs={24} sm={8}>
            <Form.Item
              name="timeout_ms"
              label="单请求超时（ms）"
              extra={`范围 ${WASM_PLUGIN_LIMITS.minTimeoutMs}~${WASM_PLUGIN_LIMITS.maxTimeoutMs} ms（默认 ${WASM_PLUGIN_LIMITS.defaultTimeoutMs}）`}
              rules={[
                { required: true, message: '请填写单请求超时' },
                {
                  type: 'number',
                  min: WASM_PLUGIN_LIMITS.minTimeoutMs,
                  max: WASM_PLUGIN_LIMITS.maxTimeoutMs,
                  message: `超时须在 ${WASM_PLUGIN_LIMITS.minTimeoutMs} 到 ${WASM_PLUGIN_LIMITS.maxTimeoutMs} ms 之间`,
                },
              ]}
            >
              <InputNumber
                min={WASM_PLUGIN_LIMITS.minTimeoutMs}
                max={WASM_PLUGIN_LIMITS.maxTimeoutMs}
                precision={0}
                style={{ width: '100%' }}
              />
            </Form.Item>
          </Col>
          <Col xs={24} sm={8}>
            <Form.Item
              name="max_memory_kb"
              label="最大内存上限（KiB）"
              extra={`范围 ${WASM_PLUGIN_LIMITS.minMaxMemoryKb}~${WASM_PLUGIN_LIMITS.maxMaxMemoryKb} KiB（默认 ${WASM_PLUGIN_LIMITS.defaultMaxMemoryKb}）`}
              rules={[
                { required: true, message: '请填写最大内存上限' },
                {
                  type: 'number',
                  min: WASM_PLUGIN_LIMITS.minMaxMemoryKb,
                  max: WASM_PLUGIN_LIMITS.maxMaxMemoryKb,
                  message: `内存上限须在 ${WASM_PLUGIN_LIMITS.minMaxMemoryKb} 到 ${WASM_PLUGIN_LIMITS.maxMaxMemoryKb} KiB 之间`,
                },
              ]}
            >
              <InputNumber
                min={WASM_PLUGIN_LIMITS.minMaxMemoryKb}
                max={WASM_PLUGIN_LIMITS.maxMaxMemoryKb}
                precision={0}
                style={{ width: '100%' }}
              />
            </Form.Item>
          </Col>
          <Col xs={24} sm={8}>
            <Form.Item
              name="max_body_bytes"
              label="请求体读取上限（字节）"
              extra={`范围 ${WASM_PLUGIN_LIMITS.minMaxBodyBytes}~${WASM_PLUGIN_LIMITS.maxMaxBodyBytes} B（0=不读取，默认 ${WASM_PLUGIN_LIMITS.defaultMaxBodyBytes}）`}
              rules={[
                { required: true, message: '请填写请求体读取上限' },
                {
                  type: 'number',
                  min: WASM_PLUGIN_LIMITS.minMaxBodyBytes,
                  max: WASM_PLUGIN_LIMITS.maxMaxBodyBytes,
                  message: `请求体上限须在 ${WASM_PLUGIN_LIMITS.minMaxBodyBytes} 到 ${WASM_PLUGIN_LIMITS.maxMaxBodyBytes} 字节之间`,
                },
              ]}
            >
              <InputNumber
                min={WASM_PLUGIN_LIMITS.minMaxBodyBytes}
                max={WASM_PLUGIN_LIMITS.maxMaxBodyBytes}
                precision={0}
                style={{ width: '100%' }}
              />
            </Form.Item>
          </Col>
        </Row>

        <Form.Item
          name="fail_policy"
          label="异常降级策略"
          extra="当插件执行超时、内存超限或触发运行时异常时的处置方式"
          rules={[{ required: true, message: '请选择异常降级策略' }]}
        >
          <Select options={FAIL_POLICY_OPTIONS} />
        </Form.Item>

        {modeWatch === 'PROTECT' && failPolicyWatch === 'FAIL_CLOSED' && (
          <Alert
            type="warning"
            showIcon
            style={{ marginBottom: 16 }}
            title="强制执行 + 故障闭环（FAIL_CLOSED）提示"
            description="插件发生死循环超时、内存超限或运行时异常时，网关将返回 HTTP 503 并记录 WASM_PLUGIN_ERROR 事件，绝不伪装为 403 攻击阻断。"
          />
        )}

        <Form.Item
          name="path_prefixes"
          label="生效路径前缀（可选）"
          extra={`留空表示匹配作用域内全部路径；最多 ${WASM_PLUGIN_LIMITS.maxPathPrefixes} 条，每条须以 / 开头且不含 ?# 或空白，回车添加`}
          rules={[
            {
              validator: (_, v?: string[]) => {
                const err = validateWasmPathPrefixes(v)
                return err ? Promise.reject(new Error(err)) : Promise.resolve()
              },
            },
          ]}
        >
          <Select
            mode="tags"
            open={false}
            tokenSeparators={[',']}
            placeholder="例如 /api/v1/orders、/graphql（留空表示全路径生效）"
          />
        </Form.Item>

        <Form.Item
          name="reason"
          label={editing ? `变更理由（基于当前版本 v${editing.version}）` : '创建理由'}
          extra="写入不可变版本历史与操作审计日志，便于后续溯源与一键回滚"
          rules={[
            { required: true, whitespace: true, message: '请填写变更理由' },
            {
              max: WASM_PLUGIN_LIMITS.maxReasonLen,
              message: `变更理由不能超过 ${WASM_PLUGIN_LIMITS.maxReasonLen} 字符`,
            },
          ]}
        >
          <Input.TextArea
            rows={2}
            maxLength={WASM_PLUGIN_LIMITS.maxReasonLen}
            showCount
            placeholder={
              editing
                ? '说明本次配置或模块升级原因，如：调优检测逻辑并开启强制执行'
                : '说明插件用途与上线原因，如：上线自定义业务签名校验插件（观察模式）'
            }
          />
        </Form.Item>
      </Form>
    </Drawer>
  )
}

/** 版本历史与一键回滚抽屉 */
function PluginVersionsDrawer({
  pluginId,
  canManage,
  appLabelMap,
  onClose,
  onRolledBack,
}: {
  pluginId: string
  canManage: boolean
  appLabelMap: Map<string, string>
  onClose: () => void
  onRolledBack: () => void
}) {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const [rollbackTarget, setRollbackTarget] =
    useState<WasmPluginVersionItem | null>(null)
  const [rollbackReason, setRollbackReason] = useState('')
  const [rollbackError, setRollbackError] = useState<string | null>(null)

  const detailQuery = useQuery({
    queryKey: ['wasm-plugin-detail', pluginId],
    queryFn: () => wasmPluginsApi.get(pluginId),
  })

  const rollbackMut = useMutation({
    mutationFn: (body: WasmPluginRollbackBody) =>
      wasmPluginsApi.rollback(pluginId, body),
    onSuccess: (updated) => {
      message.success(
        `已回滚至历史快照并生成新版本 v${updated.version}；需经配置发布同步到网关节点`,
      )
      setRollbackTarget(null)
      setRollbackReason('')
      setRollbackError(null)
      void queryClient.invalidateQueries({
        queryKey: ['wasm-plugin-detail', pluginId],
      })
      onRolledBack()
    },
    onError: (e: unknown) => {
      if (
        e instanceof ApiError &&
        (e.status === 409 || e.code === 'RESOURCE_CONFLICT')
      ) {
        const msg = e.message || '插件版本已发生变更，请刷新后重试回滚'
        setRollbackError(msg)
        message.warning(msg)
        void queryClient.invalidateQueries({
          queryKey: ['wasm-plugin-detail', pluginId],
        })
        onRolledBack()
        return
      }
      setRollbackError(e instanceof ApiError ? e.message : '回滚失败')
    },
  })

  const plugin = detailQuery.data?.plugin
  const versions = detailQuery.data?.versions ?? []

  const versionColumns: ColumnsType<WasmPluginVersionItem> = [
    {
      title: '版本',
      dataIndex: 'version',
      key: 'version',
      width: 120,
      render: (ver: number) => (
        <Space size={4}>
          <Tag color="cyan" style={{ marginInlineEnd: 0 }}>
            v{ver}
          </Tag>
          {plugin && ver === plugin.version && (
            <Tag color="green" style={{ marginInlineEnd: 0 }}>
              当前
            </Tag>
          )}
        </Space>
      ),
    },
    {
      title: '运行模式',
      dataIndex: 'mode',
      key: 'mode',
      width: 100,
      render: (mode: string) => (
        <StatusTag value={mode} map={WASM_PLUGIN_MODE_META} />
      ),
    },
    {
      title: 'SHA-256',
      dataIndex: 'sha256',
      key: 'sha256',
      width: 170,
      render: (sha: string) =>
        sha ? (
          <Tooltip title={sha}>
            <Typography.Text code copyable={{ text: sha }}>
              {formatShortSha256(sha)}
            </Typography.Text>
          </Tooltip>
        ) : (
          '-'
        ),
    },
    {
      title: '体积',
      dataIndex: 'wasm_size',
      key: 'wasm_size',
      width: 100,
      render: (size: number) => formatWasmSizeKiB(size),
    },
    {
      title: '变更理由',
      dataIndex: 'reason',
      key: 'reason',
      ellipsis: true,
      render: (v: string) => v || '-',
    },
    {
      title: '操作人',
      dataIndex: 'created_by',
      key: 'created_by',
      width: 110,
      render: (v: string) => v || '-',
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    ...(canManage
      ? [
          {
            title: '操作',
            key: 'actions',
            width: 130,
            fixed: 'right' as const,
            render: (_: unknown, record: WasmPluginVersionItem) =>
              plugin && record.version === plugin.version ? (
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  当前版本
                </Typography.Text>
              ) : (
                <Button
                  type="link"
                  size="small"
                  icon={<RollbackOutlined />}
                  onClick={() => {
                    setRollbackTarget(record)
                    setRollbackReason('')
                    setRollbackError(null)
                  }}
                >
                  回滚到此版本
                </Button>
              ),
          },
        ]
      : []),
  ]

  const handleConfirmRollback = () => {
    if (!plugin || !rollbackTarget) return
    const trimmed = rollbackReason.trim()
    if (!trimmed) {
      setRollbackError('请填写回滚理由')
      return
    }
    if (trimmed.length > WASM_PLUGIN_LIMITS.maxReasonLen) {
      setRollbackError(
        `回滚理由不能超过 ${WASM_PLUGIN_LIMITS.maxReasonLen} 字符`,
      )
      return
    }
    setRollbackError(null)
    rollbackMut.mutate({
      target_version: rollbackTarget.version,
      expected_version: plugin.version,
      reason: trimmed,
    })
  }

  return (
    <>
      <Drawer
        title={
          plugin
            ? `版本历史与回滚：${plugin.name}`
            : '插件版本历史与回滚'
        }
        open
        size={880}
        onClose={onClose}
      >
        {detailQuery.isLoading ? (
          <div
            style={{ display: 'flex', justifyContent: 'center', padding: 48 }}
          >
            <Spin />
          </div>
        ) : detailQuery.isError || !plugin ? (
          <QueryErrorAlert
            error={detailQuery.error}
            message="加载 Wasm 插件版本历史失败"
          />
        ) : (
          <Space orientation="vertical" size={16} style={{ width: '100%' }}>
            <Alert
              type="info"
              showIcon
              title="版本历史不可篡改，回滚采用前向追加模式"
              description="每次创建、更新或回滚均保留完整不可变快照（含二进制摘要与护栏配置）；执行回滚时会将目标历史版本克隆为 version + 1，不影响既有审计记录。"
            />
            <Descriptions bordered size="small" column={{ xs: 1, sm: 3 }}>
              <Descriptions.Item label="插件名称">
                <Typography.Text strong>{plugin.name}</Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label="生效作用域">
                {plugin.application_id ? (
                  <Tag color="blue">
                    {appLabelMap.get(plugin.application_id) ||
                      plugin.application_id}
                  </Tag>
                ) : (
                  <Tag color="purple">全局</Tag>
                )}
              </Descriptions.Item>
              <Descriptions.Item label="当前版本">
                <Tag color="cyan">v{plugin.version}</Tag>
              </Descriptions.Item>
              <Descriptions.Item label="ABI 协议">
                <Tag color="geekblue">{plugin.abi_version}</Tag>
              </Descriptions.Item>
              <Descriptions.Item label="当前模式">
                <StatusTag value={plugin.mode} map={WASM_PLUGIN_MODE_META} />
              </Descriptions.Item>
              <Descriptions.Item label="当前 SHA-256">
                <Tooltip title={plugin.sha256}>
                  <Typography.Text code copyable={{ text: plugin.sha256 }}>
                    {formatShortSha256(plugin.sha256)}
                  </Typography.Text>
                </Tooltip>
              </Descriptions.Item>
            </Descriptions>

            <Table<WasmPluginVersionItem>
              rowKey="id"
              size="small"
              columns={versionColumns}
              dataSource={versions}
              pagination={false}
              scroll={{ x: 820 }}
            />
          </Space>
        )}
      </Drawer>

      <Modal
        title={
          rollbackTarget && plugin
            ? `确认回滚「${plugin.name}」至 v${rollbackTarget.version}`
            : '确认回滚插件版本'
        }
        open={Boolean(rollbackTarget)}
        okText="确认回滚"
        cancelText="取消"
        confirmLoading={rollbackMut.isPending}
        onCancel={() => {
          setRollbackTarget(null)
          setRollbackReason('')
          setRollbackError(null)
        }}
        onOk={handleConfirmRollback}
        destroyOnHidden
      >
        {rollbackTarget && plugin && (
          <Space orientation="vertical" size={12} style={{ width: '100%' }}>
            <Alert
              type="warning"
              showIcon
              title={`将把 v${rollbackTarget.version} 的模块与配置克隆为新版本 v${plugin.version + 1}`}
              description={`目标版本 SHA-256：${formatShortSha256(rollbackTarget.sha256)}（${formatWasmSizeKiB(rollbackTarget.wasm_size)}），模式：${WASM_PLUGIN_MODE_META[rollbackTarget.mode]?.label ?? rollbackTarget.mode}。回滚完成后请前往「配置发布」下发至网关节点。`}
            />
            {rollbackError && (
              <Alert type="error" showIcon title={rollbackError} />
            )}
            <div>
              <Typography.Text strong style={{ display: 'block', marginBottom: 6 }}>
                回滚理由（必填）
              </Typography.Text>
              <Input.TextArea
                aria-label="回滚理由"
                rows={3}
                value={rollbackReason}
                maxLength={WASM_PLUGIN_LIMITS.maxReasonLen}
                showCount
                placeholder="请说明回滚原因，例如：新版本存在误报，临时回退至稳定版本"
                onChange={(e) => {
                  setRollbackReason(e.target.value)
                  if (rollbackError) setRollbackError(null)
                }}
              />
            </div>
          </Space>
        )}
      </Modal>
    </>
  )
}

/**
 * Wasm 热插拔自定义检测插件沙箱管理页（WDSP Phase 9D-1）。
 * 路由：/wasm-plugins；权限：wasm_plugins.read（查看与版本历史）/ wasm_plugins.manage（上传/编辑/回滚/删除）。
 */
export default function WasmPluginsPage() {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'wasm_plugins.manage')
  const canReadApps = hasPermission(permissions, 'applications.read')

  const [scopeFilter, setScopeFilter] = useState<ScopeFilterMode>('ALL')
  const [selectedAppId, setSelectedAppId] = useState<string | undefined>(
    undefined,
  )
  const [modeFilter, setModeFilter] = useState<WasmPluginMode | undefined>(
    undefined,
  )
  const [keyword, setKeyword] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)

  /** undefined 关闭；null 新建；非空对象 编辑 */
  const [editor, setEditor] = useState<WasmPluginItem | null | undefined>(
    undefined,
  )
  const [versionsPluginId, setVersionsPluginId] = useState<string | null>(null)

  const applicationsQuery = useQuery({
    queryKey: ['applications', 'wasm-plugins-selector'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 200 }),
    enabled: canReadApps,
    staleTime: 60_000,
  })

  const appOptions = useMemo<AppOption[]>(
    () =>
      (applicationsQuery.data?.items ?? []).map((app) => ({
        value: app.id,
        label: app.code ? `${app.name} (${app.code})` : app.name,
      })),
    [applicationsQuery.data?.items],
  )

  const appLabelMap = useMemo(() => {
    const map = new Map<string, string>()
    for (const opt of appOptions) {
      map.set(opt.value, opt.label)
    }
    return map
  }, [appOptions])

  const applicationIdQuery = useMemo(() => {
    if (scopeFilter === 'GLOBAL') return WASM_PLUGIN_GLOBAL_SCOPE_QUERY
    if (scopeFilter === 'APPLICATION') return selectedAppId || undefined
    return undefined
  }, [scopeFilter, selectedAppId])

  const listQuery = useQuery({
    queryKey: [
      'wasm-plugins',
      applicationIdQuery ?? '',
      modeFilter ?? '',
      keyword.trim(),
      page,
      pageSize,
    ],
    queryFn: () =>
      wasmPluginsApi.list({
        application_id: applicationIdQuery,
        mode: modeFilter,
        keyword: keyword.trim() || undefined,
        page,
        page_size: pageSize,
      }),
  })

  const invalidate = () =>
    void queryClient.invalidateQueries({ queryKey: ['wasm-plugins'] })

  const deleteMut = useMutation({
    mutationFn: (id: string) => wasmPluginsApi.remove(id),
    onSuccess: () => {
      message.success('Wasm 插件已删除；需经配置发布同步到网关节点')
      invalidate()
    },
    onError: (e: unknown) =>
      message.error(e instanceof ApiError ? e.message : '删除插件失败'),
  })

  const columns: ColumnsType<WasmPluginItem> = [
    {
      title: '插件名称',
      dataIndex: 'name',
      key: 'name',
      width: 210,
      render: (_, record) => (
        <Space orientation="vertical" size={2}>
          <Typography.Text strong>{record.name}</Typography.Text>
          {record.description ? (
            <Typography.Text
              type="secondary"
              style={{ fontSize: 12, maxWidth: 190 }}
              ellipsis={{ tooltip: record.description }}
            >
              {record.description}
            </Typography.Text>
          ) : null}
        </Space>
      ),
    },
    {
      title: '作用域 / 应用',
      dataIndex: 'application_id',
      key: 'application_id',
      width: 170,
      render: (appId?: string | null) => {
        if (!appId) {
          return <Tag color="purple">全局</Tag>
        }
        const label = appLabelMap.get(appId)
        return (
          <Tooltip title={appId}>
            <Tag color="blue">{label || formatShortSha256(appId, 8)}</Tag>
          </Tooltip>
        )
      },
    },
    {
      title: '版本',
      dataIndex: 'version',
      key: 'version',
      width: 80,
      render: (ver: number) => <Tag color="cyan">v{ver}</Tag>,
    },
    {
      title: 'ABI 协议',
      dataIndex: 'abi_version',
      key: 'abi_version',
      width: 100,
      render: (abi: string) => <Tag color="geekblue">{abi || 'wdsp_v1'}</Tag>,
    },
    {
      title: '运行模式',
      dataIndex: 'mode',
      key: 'mode',
      width: 100,
      render: (mode: string) => (
        <StatusTag value={mode} map={WASM_PLUGIN_MODE_META} />
      ),
    },
    {
      title: 'SHA-256 摘要',
      dataIndex: 'sha256',
      key: 'sha256',
      width: 170,
      render: (sha: string) =>
        sha ? (
          <Tooltip title={sha}>
            <Typography.Text code copyable={{ text: sha }}>
              {formatShortSha256(sha)}
            </Typography.Text>
          </Tooltip>
        ) : (
          '-'
        ),
    },
    {
      title: '模块体积',
      dataIndex: 'wasm_size',
      key: 'wasm_size',
      width: 100,
      render: (size: number) => formatWasmSizeKiB(size),
    },
    {
      title: '沙箱护栏',
      key: 'guardrails',
      width: 220,
      render: (_, record) => (
        <Tooltip
          title={`超时 ${record.timeout_ms} ms · 内存上限 ${record.max_memory_kb} KiB · 请求体上限 ${record.max_body_bytes} B · ${WASM_PLUGIN_FAIL_POLICY_META[record.fail_policy]?.label ?? record.fail_policy}`}
        >
          <Space size={4} wrap>
            <Tag style={{ marginInlineEnd: 0 }}>{record.timeout_ms}ms</Tag>
            <Tag style={{ marginInlineEnd: 0 }}>
              {record.max_memory_kb} KiB
            </Tag>
            <StatusTag
              value={record.fail_policy}
              map={WASM_PLUGIN_FAIL_POLICY_SHORT_META}
            />
          </Space>
        </Tooltip>
      ),
    },
    {
      title: '优先级',
      dataIndex: 'priority',
      key: 'priority',
      width: 85,
    },
    {
      title: '更新时间',
      dataIndex: 'updated_at',
      key: 'updated_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: canManage ? 240 : 120,
      fixed: 'right',
      render: (_, record) => (
        <Space size={0}>
          {canManage && (
            <Button
              type="link"
              size="small"
              icon={<EditOutlined />}
              onClick={() => setEditor(record)}
            >
              编辑
            </Button>
          )}
          <Button
            type="link"
            size="small"
            icon={<HistoryOutlined />}
            onClick={() => setVersionsPluginId(record.id)}
          >
            {canManage ? '版本与回滚' : '版本历史'}
          </Button>
          {canManage && (
            <Popconfirm
              title={`确定删除 Wasm 插件「${record.name}」吗？`}
              description="删除后该插件及其全部历史版本将被移除，并需经配置发布同步到网关节点。"
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

  return (
    <Card
      title={
        <Space>
          <CodeSandboxOutlined />
          <span>Wasm 热插拔检测插件</span>
          <Tag color="geekblue" icon={<SafetyCertificateOutlined />}>
            wazero 零权限沙箱 · wdsp_v1
          </Tag>
        </Space>
      }
      extra={
        canManage ? (
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => setEditor(null)}
          >
            上传插件
          </Button>
        ) : undefined
      }
    >
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        title="支持按全局或应用粒度热插拔自定义 WebAssembly 检测插件（ABI: wdsp_v1）。插件运行于纯解释器沙箱，无 WASI/网络/文件访问权限且无法读取 Authorization、Cookie、DPoP 等凭据请求头；任何插件返回 ALLOW 均不会绕过下游 API 防护与 Coraza WAF，变更需经配置发布通道生效。"
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
          <Select<ScopeFilterMode>
            aria-label="作用域筛选"
            value={scopeFilter}
            options={SCOPE_FILTER_OPTIONS}
            style={{ width: 140 }}
            onChange={(next) => {
              setScopeFilter(next)
              if (next !== 'APPLICATION') {
                setSelectedAppId(undefined)
              }
              setPage(1)
            }}
          />
          {scopeFilter === 'APPLICATION' && (
            <Select
              aria-label="指定应用筛选"
              allowClear
              showSearch
              optionFilterProp="label"
              placeholder="选择指定应用"
              value={selectedAppId}
              options={appOptions}
              style={{ width: 220 }}
              onChange={(val) => {
                setSelectedAppId(val)
                setPage(1)
              }}
            />
          )}
          <Select<WasmPluginMode>
            aria-label="运行模式筛选"
            allowClear
            placeholder="按运行模式筛选"
            value={modeFilter}
            options={MODE_OPTIONS}
            style={{ width: 150 }}
            onChange={(val) => {
              setModeFilter(val)
              setPage(1)
            }}
          />
          <Input.Search
            allowClear
            placeholder="按插件名称或说明搜索"
            value={keyword}
            onChange={(e) => {
              setKeyword(e.target.value)
              setPage(1)
            }}
            onSearch={(val) => {
              setKeyword(val)
              setPage(1)
            }}
            style={{ width: 240 }}
          />
        </Space>
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          共 {listQuery.data?.total ?? 0} 个插件
        </Typography.Text>
      </Space>

      {listQuery.isError ? (
        <QueryErrorAlert
          error={listQuery.error}
          message="加载 Wasm 检测插件列表失败"
        />
      ) : (
        <SmartTable<WasmPluginItem>
          storageKey="wasm-plugins"
          refreshQueryKeys={[['wasm-plugins']]}
          rowKey="id"
          columns={columns}
          dataSource={listQuery.data?.items ?? []}
          loading={listQuery.isLoading}
          scroll={{ x: 1420 }}
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
      )}

      {editor !== undefined && (
        <PluginEditorDrawer
          editing={editor}
          appOptions={appOptions}
          appLabelMap={appLabelMap}
          onClose={() => setEditor(undefined)}
          onSaved={invalidate}
        />
      )}

      {versionsPluginId && (
        <PluginVersionsDrawer
          pluginId={versionsPluginId}
          canManage={canManage}
          appLabelMap={appLabelMap}
          onClose={() => setVersionsPluginId(null)}
          onRolledBack={invalidate}
        />
      )}
    </Card>
  )
}
