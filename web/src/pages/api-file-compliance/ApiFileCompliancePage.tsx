import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Button,
  Card,
  Form,
  Input,
  Modal,
  Select,
  Space,
  Switch,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { PlusOutlined } from '@ant-design/icons'
import {
  apiFileComplianceApi,
  type ApiFileComplianceRule,
  type ApiFileComplianceRuleBody,
  type ApiFileMatchType,
} from '../../api/apiFileCompliance'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import useBatchDelete from '../../hooks/useBatchDelete'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import SignatureVerificationCard from './SignatureVerificationCard'

/** 传输方向展示映射（api_file_compliance_rules.direction CHECK 对齐） */
const DIRECTION_META: Record<string, { color: string; label: string }> = {
  UPLOAD: { color: 'blue', label: '上传' },
  DOWNLOAD: { color: 'purple', label: '下载' },
}

/** 匹配类型展示映射（match_type CHECK 对齐） */
const MATCH_TYPE_META: Record<string, { color: string; label: string }> = {
  EXT: { color: 'geekblue', label: '扩展名' },
  MIME: { color: 'cyan', label: 'MIME 类型' },
  FILENAME_REGEX: { color: 'orange', label: '文件名正则' },
}

/** 命中动作展示映射（action CHECK 对齐） */
const ACTION_META: Record<string, { color: string; label: string }> = {
  OBSERVE: { color: 'gold', label: '观察' },
  BLOCK: { color: 'red', label: '阻断' },
}

/** match_type 联动的 match_value 输入提示（与服务端 normalize/validate 口径一致） */
const MATCH_VALUE_HINT: Record<
  ApiFileMatchType,
  { placeholder: string; extra: string }
> = {
  EXT: {
    placeholder: '.exe',
    extra:
      '扩展名，如 .exe（小写字母数字，可含 _+-，1-16 字符；服务端自动剥离前导点并转小写）',
  },
  MIME: {
    placeholder: 'application/pdf',
    extra:
      'MIME 类型，如 application/pdf（type/subtype，小写；参数部分自动剥离）',
  },
  FILENAME_REGEX: {
    placeholder: '.*\\.sql$',
    extra:
      '文件名正则（RE2 语法），如 .*\\.sql$（服务端试编译，非法形态不落库）',
  },
}

/** EXT 形态（服务端 extValuePattern：小写字母数字开头，可含 _+-，1-16 字符，不含点） */
const EXT_PATTERN = /^[a-z0-9][a-z0-9_+-]{0,15}$/

/** MIME 形态（服务端 mimeValuePattern：type/subtype，小写，不含参数） */
const MIME_PATTERN =
  /^[a-z0-9][a-z0-9!#$&^_+.-]{0,126}\/[a-z0-9][a-z0-9!#$&^_+.-]{0,126}$/

/**
 * match_value 前端校验（镜像服务端 normalize 后再 validate，仅作输入提示；
 * 最终口径以服务端校验为准——服务端拒绝时展示其错误信息）。
 */
function validateMatchValue(
  matchType: ApiFileMatchType | undefined,
  raw: string,
): string | null {
  const value = raw.trim()
  if (!value) return '请填写匹配值'
  if (value.length > 256) return '匹配值长度不能超过 256'
  switch (matchType) {
    case 'EXT': {
      // 与服务端归一一致：剥离前导点 + 转小写后校验
      const normalized = value.replace(/^\.+/, '').toLowerCase()
      if (!EXT_PATTERN.test(normalized)) {
        return '扩展名格式非法（小写字母数字，可含 _+-，1-16 字符，不含点），如 .exe'
      }
      return null
    }
    case 'MIME': {
      // 与服务端归一一致：转小写 + 剥离参数后校验
      const normalized = value.split(';')[0].trim().toLowerCase()
      if (normalized.length > 128 || !MIME_PATTERN.test(normalized)) {
        return 'MIME 形式非法（type/subtype，小写，不含参数），如 application/pdf'
      }
      return null
    }
    case 'FILENAME_REGEX': {
      try {
        new RegExp(value)
      } catch {
        return '正则无法编译（RE2 语法），如 .*\\.sql$'
      }
      return null
    }
    default:
      return '请先选择匹配类型'
  }
}

interface RuleFormValues {
  direction: string
  match_type: ApiFileMatchType
  match_value: string
  action: string
  reason?: string
  enabled: boolean
}

/**
 * 文件合规规则（WDSP / 阶段8 P2-03 管理面）：上传/下载方向的文件类型管控。
 * 规则随配置发布下发网关生效（OBSERVE 命中仅记录，BLOCK 命中阻断）。
 */
export default function ApiFileCompliancePage() {
  const { message, modal } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'api_data.manage')

  const [direction, setDirection] = useState<string | undefined>()
  const [matchType, setMatchType] = useState<string | undefined>()
  const [action, setAction] = useState<string | undefined>()
  const [enabledFilter, setEnabledFilter] = useState<boolean | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [editing, setEditing] = useState<ApiFileComplianceRule | null>(null)
  const [createOpen, setCreateOpen] = useState(false)
  const [detailRecord, setDetailRecord] =
    useState<ApiFileComplianceRule | null>(null)
  const [form] = Form.useForm<RuleFormValues>()

  const modalOpen = createOpen || editing !== null
  /** 弹窗内当前匹配类型（联动 match_value 占位/提示/校验） */
  const formMatchType = Form.useWatch('match_type', form)
  const hint = MATCH_VALUE_HINT[formMatchType as ApiFileMatchType] ?? {
    placeholder: '',
    extra: '请先选择匹配类型',
  }

  const listQuery = useQuery({
    queryKey: [
      'api-file-compliance-rules',
      direction,
      matchType,
      action,
      enabledFilter,
      page,
      pageSize,
    ],
    queryFn: () =>
      apiFileComplianceApi.list({
        direction,
        match_type: matchType,
        action,
        enabled: enabledFilter,
        page,
        page_size: pageSize,
      }),
  })

  const invalidate = () =>
    void qc.invalidateQueries({ queryKey: ['api-file-compliance-rules'] })

  const { rowSelection, batchDeleteButton } =
    useBatchDelete<ApiFileComplianceRule>({
      remove: (id) => apiFileComplianceApi.remove(id),
      invalidateKeys: [['api-file-compliance-rules']],
      entityName: '文件合规规则',
      canDelete: canManage,
    })

  const createMut = useMutation({
    mutationFn: (body: ApiFileComplianceRuleBody) =>
      apiFileComplianceApi.create(body),
    onSuccess: () => {
      message.success('已创建')
      setCreateOpen(false)
      invalidate()
    },
    onError: (e: unknown) =>
      message.error(e instanceof ApiError ? e.message : '创建失败'),
  })

  const updateMut = useMutation({
    mutationFn: (vars: {
      id: string
      body: Partial<ApiFileComplianceRuleBody>
    }) => apiFileComplianceApi.update(vars.id, vars.body),
    onSuccess: () => {
      message.success('已保存')
      setEditing(null)
      invalidate()
    },
    onError: (e: unknown) =>
      message.error(e instanceof ApiError ? e.message : '保存失败'),
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => apiFileComplianceApi.remove(id),
    onSuccess: () => {
      message.success('已删除')
      invalidate()
    },
    onError: (e: unknown) =>
      message.error(e instanceof ApiError ? e.message : '删除失败'),
  })

  const openCreate = () => {
    form.resetFields()
    setCreateOpen(true)
  }

  const openEdit = (record: ApiFileComplianceRule) => {
    setEditing(record)
    form.resetFields()
    form.setFieldsValue({
      direction: record.direction,
      match_type: record.match_type,
      match_value: record.match_value,
      action: record.action,
      reason: record.reason,
      enabled: record.enabled,
    })
  }

  /** 规则名称（审计/确认弹窗用）：匹配类型中文名:match_value */
  const ruleName = (r: ApiFileComplianceRule) =>
    `${MATCH_TYPE_META[r.match_type]?.label ?? r.match_type}:${r.match_value}`

  const toggleEnabled = (record: ApiFileComplianceRule) => {
    modal.confirm({
      title: record.enabled ? '停用规则' : '启用规则',
      content: `确定${record.enabled ? '停用' : '启用'}文件合规规则「${ruleName(record)}」吗？${
        record.enabled ? '停用后该规则不再参与文件合规判定。' : ''
      }变更随配置发布下发网关后生效。`,
      onOk: () =>
        updateMut.mutate({ id: record.id, body: { enabled: !record.enabled } }),
    })
  }

  const confirmDelete = (record: ApiFileComplianceRule) => {
    modal.confirm({
      title: '删除规则',
      content: `确定删除文件合规规则「${ruleName(record)}」吗？删除后不可恢复。`,
      okButtonProps: { danger: true },
      onOk: () => deleteMut.mutate(record.id),
    })
  }

  const columns: ColumnsType<ApiFileComplianceRule> = [
    {
      title: '方向',
      dataIndex: 'direction',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={DIRECTION_META} />,
    },
    {
      title: '匹配类型',
      dataIndex: 'match_type',
      width: 120,
      render: (v: string) => <StatusTag value={v} map={MATCH_TYPE_META} />,
    },
    {
      title: '匹配值',
      dataIndex: 'match_value',
      ellipsis: true,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: '动作',
      dataIndex: 'action',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={ACTION_META} />,
    },
    {
      title: '理由',
      dataIndex: 'reason',
      ellipsis: true,
      render: (v: string) => v || '-',
    },
    {
      title: '启用',
      dataIndex: 'enabled',
      width: 80,
      render: (v: boolean, record) => (
        <Switch
          checked={v}
          disabled={!canManage}
          onChange={() => toggleEnabled(record)}
          aria-label={`启停规则 ${ruleName(record)}`}
        />
      ),
    },
    {
      title: '更新时间',
      dataIndex: 'updated_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 130,
      fixed: 'right',
      render: (_, record) =>
        canManage ? (
          <Space size={0}>
            <Button type="link" size="small" onClick={() => openEdit(record)}>
              编辑
            </Button>
            <Button
              type="link"
              size="small"
              danger
              onClick={() => confirmDelete(record)}
            >
              删除
            </Button>
          </Space>
        ) : null,
    },
  ]

  return (
    <Space orientation="vertical" size={16} style={{ width: '100%' }}>
      <Card
        title="文件合规规则"
        extra={
          canManage ? (
            <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>
              新建规则
            </Button>
          ) : null
        }
      >
        <Typography.Paragraph type="secondary">
          按传输方向（上传/下载）管控文件类型：匹配方式支持扩展名、MIME
          类型与文件名正则；
          命中动作可选观察（仅记录）或阻断。规则随配置发布下发网关后生效。
        </Typography.Paragraph>
        <QueryErrorAlert error={listQuery.error} />
        <Space style={{ marginBottom: 16 }} wrap>
          <Select
            placeholder="方向"
            allowClear
            style={{ width: 120 }}
            value={direction}
            options={Object.entries(DIRECTION_META).map(([value, meta]) => ({
              value,
              label: meta.label,
            }))}
            onChange={(v) => {
              setDirection(v)
              setPage(1)
            }}
          />
          <Select
            placeholder="匹配类型"
            allowClear
            style={{ width: 140 }}
            value={matchType}
            options={Object.entries(MATCH_TYPE_META).map(([value, meta]) => ({
              value,
              label: meta.label,
            }))}
            onChange={(v) => {
              setMatchType(v)
              setPage(1)
            }}
          />
          <Select
            placeholder="动作"
            allowClear
            style={{ width: 120 }}
            value={action}
            options={Object.entries(ACTION_META).map(([value, meta]) => ({
              value,
              label: meta.label,
            }))}
            onChange={(v) => {
              setAction(v)
              setPage(1)
            }}
          />
          <Select
            placeholder="状态"
            allowClear
            style={{ width: 120 }}
            value={enabledFilter}
            options={[
              { value: true, label: '启用' },
              { value: false, label: '停用' },
            ]}
            onChange={(v) => {
              setEnabledFilter(v)
              setPage(1)
            }}
          />
          {batchDeleteButton}
        </Space>
        <SmartTable<ApiFileComplianceRule>
          storageKey="api-file-compliance-rules"
          rowKey="id"
          rowSelection={rowSelection}
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items ?? []}
          scroll={{ x: 1200 }}
          onRow={(record) => ({
            onDoubleClick: () => setDetailRecord(record),
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

        <RecordDetailDrawer
          open={detailRecord !== null}
          title="规则详情"
          record={detailRecord as Record<string, unknown> | null}
          onClose={() => setDetailRecord(null)}
        />

        <Modal
          title={
            editing ? `编辑规则：${ruleName(editing)}` : '新建文件合规规则'
          }
          open={modalOpen}
          onCancel={() => {
            setCreateOpen(false)
            setEditing(null)
          }}
          onOk={() => form.submit()}
          confirmLoading={createMut.isPending || updateMut.isPending}
          width={560}
          destroyOnHidden
        >
          <Form<RuleFormValues>
            form={form}
            layout="vertical"
            initialValues={{
              direction: 'UPLOAD',
              match_type: 'EXT',
              action: 'OBSERVE',
              enabled: true,
            }}
            onFinish={(v) => {
              const body: ApiFileComplianceRuleBody = {
                direction:
                  v.direction as ApiFileComplianceRuleBody['direction'],
                match_type: v.match_type,
                match_value: v.match_value.trim(),
                action: v.action as ApiFileComplianceRuleBody['action'],
                reason: v.reason?.trim() ?? '',
                enabled: v.enabled,
              }
              if (editing) {
                updateMut.mutate({ id: editing.id, body })
              } else {
                createMut.mutate(body)
              }
            }}
          >
            <Form.Item
              name="direction"
              label="传输方向"
              rules={[{ required: true, message: '请选择传输方向' }]}
            >
              <Select
                options={Object.entries(DIRECTION_META).map(
                  ([value, meta]) => ({
                    value,
                    label: `${meta.label}（${value}）`,
                  }),
                )}
              />
            </Form.Item>
            <Form.Item
              name="match_type"
              label="匹配类型"
              rules={[{ required: true, message: '请选择匹配类型' }]}
            >
              <Select
                options={Object.entries(MATCH_TYPE_META).map(
                  ([value, meta]) => ({
                    value,
                    label: `${meta.label}（${value}）`,
                  }),
                )}
                onChange={() => {
                  // 切换类型后按新口径重新校验匹配值
                  void form
                    .validateFields(['match_value'])
                    .catch(() => undefined)
                }}
              />
            </Form.Item>
            <Form.Item
              name="match_value"
              label="匹配值"
              extra={hint.extra}
              rules={[
                { required: true, message: '请填写匹配值' },
                {
                  validator: (_, value: string) => {
                    const err = validateMatchValue(formMatchType, value ?? '')
                    return err
                      ? Promise.reject(new Error(err))
                      : Promise.resolve()
                  },
                },
              ]}
            >
              <Input
                placeholder={hint.placeholder}
                style={{ fontFamily: 'monospace' }}
              />
            </Form.Item>
            <Form.Item
              name="action"
              label="命中动作"
              rules={[{ required: true, message: '请选择命中动作' }]}
            >
              <Select
                options={Object.entries(ACTION_META).map(([value, meta]) => ({
                  value,
                  label: `${meta.label}（${value}）`,
                }))}
              />
            </Form.Item>
            <Form.Item
              name="reason"
              label="理由（可选）"
              rules={[{ max: 256, message: '理由长度不能超过 256' }]}
            >
              <Input placeholder="如：禁止上传可执行文件" />
            </Form.Item>
            <Form.Item name="enabled" label="启用状态" valuePropName="checked">
              <Switch checkedChildren="启用" unCheckedChildren="停用" />
            </Form.Item>
          </Form>
        </Modal>
      </Card>
      <SignatureVerificationCard
        canVerify={hasPermission(permissions, 'api_data.read')}
      />
    </Space>
  )
}
