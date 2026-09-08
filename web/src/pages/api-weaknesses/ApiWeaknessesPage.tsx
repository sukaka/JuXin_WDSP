import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Button,
  Card,
  DatePicker,
  Descriptions,
  Drawer,
  Form,
  Input,
  Modal,
  Radio,
  Select,
  Space,
  Spin,
  Timeline,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import type { Dayjs } from 'dayjs'
import {
  apiWeaknessesApi,
  type ApiWeakness,
  type ApiWeaknessRetestResult,
  type ApiWeaknessStatus,
} from '../../api/apiWeakness'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime, formatJson } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import { API_FINDING_SEVERITY_META } from '../../utils/stage8'

/** 弱点状态（与 server/internal/apiweakness 状态机枚举一致） */
const WEAKNESS_STATUS_META: Record<string, { color: string; label: string }> = {
  NEW: { color: 'red', label: '待确认' },
  CONFIRMED: { color: 'volcano', label: '已确认' },
  TO_FIX: { color: 'orange', label: '待整改' },
  FIXED: { color: 'blue', label: '待复测' },
  REPRODUCED: { color: 'magenta', label: '复现' },
  IGNORED: { color: 'default', label: '已忽略' },
  ARCHIVED: { color: 'default', label: '已归档' },
}

/** 弱点分类 */
const WEAKNESS_CATEGORY_META: Record<string, { color: string; label: string }> = {
  AUTHN: { color: 'red', label: '认证缺失' },
  LIFECYCLE: { color: 'orange', label: '生命周期' },
  SENSITIVE: { color: 'magenta', label: '敏感数据' },
  SCHEMA: { color: 'geekblue', label: 'Schema 治理' },
}

/** 处置动作（写 api_weakness_actions.action 的取值） */
const WEAKNESS_ACTION_META: Record<string, { color: string; label: string }> = {
  DERIVED: { color: 'blue', label: '扫描发现' },
  CONFIRM: { color: 'volcano', label: '确认弱点' },
  ASSIGN: { color: 'orange', label: '指派整改' },
  MARK_FIXED: { color: 'blue', label: '标记整改完成' },
  RETEST_PASS: { color: 'green', label: '复测通过' },
  RETEST_FAIL: { color: 'red', label: '复测未通过' },
  IGNORE: { color: 'default', label: '忽略' },
  ARCHIVE: { color: 'default', label: '归档' },
  REPRODUCED: { color: 'magenta', label: '再次被命中' },
}

/**
 * 状态机可用性（与 server/internal/apiweakness transitions 迁移表一致）：
 * 操作按钮按当前状态禁用，表外组合后端一律 400。
 */
const ACTION_ALLOWED: Record<NoteAction | 'assign' | 'retest', ApiWeaknessStatus[]> = {
  confirm: ['NEW'],
  assign: ['CONFIRMED', 'TO_FIX', 'REPRODUCED'],
  fixed: ['TO_FIX'],
  retest: ['FIXED'],
  ignore: ['NEW', 'CONFIRMED', 'TO_FIX', 'REPRODUCED'],
  archive: ['CONFIRMED', 'TO_FIX', 'FIXED', 'REPRODUCED', 'IGNORED'],
}

/** 仅备注流转动作（confirm/fixed/ignore/archive 共用备注弹窗） */
type NoteAction = 'confirm' | 'fixed' | 'ignore' | 'archive'

const NOTE_ACTION_TITLE: Record<NoteAction, string> = {
  confirm: '确认弱点',
  fixed: '标记整改完成',
  ignore: '忽略弱点（接受风险/误报）',
  archive: '归档关闭',
}

interface AssignFormValues {
  owner: string
  due_date?: Dayjs | null
  note?: string
}

interface RetestFormValues {
  result: ApiWeaknessRetestResult
  note?: string
}

/** API 弱点中心（WDSP / 阶段8）：派生弱点的确认、指派、整改、复测与归档闭环 */
export default function ApiWeaknessesPage() {
  const { message } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canHandle = hasPermission(permissions, 'api_weakness.handle')

  const [status, setStatus] = useState<string | undefined>()
  const [severity, setSeverity] = useState<string | undefined>()
  const [category, setCategory] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  /** 备注弹窗当前动作（confirm/fixed/ignore/archive） */
  const [noteAction, setNoteAction] = useState<NoteAction | null>(null)
  const [noteText, setNoteText] = useState('')
  const [assignOpen, setAssignOpen] = useState(false)
  const [retestOpen, setRetestOpen] = useState(false)
  const [assignForm] = Form.useForm<AssignFormValues>()
  const [retestForm] = Form.useForm<RetestFormValues>()

  const listQuery = useQuery({
    queryKey: ['api-weaknesses', status, severity, category, page, pageSize],
    queryFn: () =>
      apiWeaknessesApi.list({ status, severity, category, page, page_size: pageSize }),
  })

  /** 详情抽屉数据源（选中时拉取，含整改/复测历史；流转后失效刷新保证状态最新） */
  const detailQuery = useQuery({
    queryKey: ['api-weakness-detail', selectedId],
    queryFn: () => apiWeaknessesApi.detail(selectedId as string),
    enabled: selectedId !== null,
  })

  /** 抽屉展示用弱点：详情未返回时先回退到列表行数据 */
  const current: ApiWeakness | null =
    detailQuery.data?.weakness ??
    listQuery.data?.items.find((w) => w.id === selectedId) ??
    null

  const transitionMut = useMutation({
    mutationFn: async (vars: {
      id: string
      action: NoteAction | 'assign' | 'retest'
      assign?: { owner: string; due_date?: string; note?: string }
      retest?: { result: ApiWeaknessRetestResult; note?: string }
      note?: string
    }) => {
      const { id, action } = vars
      switch (action) {
        case 'assign':
          return apiWeaknessesApi.assign(id, vars.assign as { owner: string })
        case 'retest':
          return apiWeaknessesApi.retest(id, vars.retest as { result: ApiWeaknessRetestResult })
        case 'confirm':
          return apiWeaknessesApi.confirm(id, vars.note ? { note: vars.note } : undefined)
        case 'fixed':
          return apiWeaknessesApi.fixed(id, vars.note ? { note: vars.note } : undefined)
        case 'ignore':
          return apiWeaknessesApi.ignore(id, vars.note ? { note: vars.note } : undefined)
        case 'archive':
          return apiWeaknessesApi.archive(id, vars.note ? { note: vars.note } : undefined)
      }
    },
    onSuccess: (r, vars) => {
      // 复测结果即时反馈：PASS 归档关闭，FAIL 转为复现待重新整改
      if (vars.action === 'retest') {
        message.success(
          r.weakness.status === 'ARCHIVED' ? '复测通过，弱点已归档关闭' : '复测未通过，弱点已转为复现',
        )
      } else {
        message.success('操作成功')
      }
      setNoteAction(null)
      setNoteText('')
      setAssignOpen(false)
      setRetestOpen(false)
      void qc.invalidateQueries({ queryKey: ['api-weaknesses'] })
      void qc.invalidateQueries({ queryKey: ['api-weakness-detail', vars.id] })
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '操作失败'),
  })

  const openNoteAction = (action: NoteAction) => {
    setNoteText('')
    setNoteAction(action)
  }

  const submitAssign = (v: AssignFormValues) => {
    if (!current) return
    transitionMut.mutate({
      id: current.id,
      action: 'assign',
      assign: {
        owner: v.owner.trim(),
        ...(v.due_date ? { due_date: v.due_date.toISOString() } : {}),
        ...(v.note?.trim() ? { note: v.note.trim() } : {}),
      },
    })
  }

  const submitRetest = (v: RetestFormValues) => {
    if (!current) return
    transitionMut.mutate({
      id: current.id,
      action: 'retest',
      retest: { result: v.result, ...(v.note?.trim() ? { note: v.note.trim() } : {}) },
    })
  }

  const columns: ColumnsType<ApiWeakness> = [
    {
      title: '弱点',
      dataIndex: 'weakness_name',
      ellipsis: true,
      render: (v: string, record) => (
        <Space size={4}>
          <Typography.Text strong>{v}</Typography.Text>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {record.weakness_code}
          </Typography.Text>
        </Space>
      ),
    },
    {
      title: '分类',
      dataIndex: 'category',
      width: 120,
      render: (v: string) => <StatusTag value={v} map={WEAKNESS_CATEGORY_META} />,
    },
    {
      title: '严重级别',
      dataIndex: 'severity',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={API_FINDING_SEVERITY_META} />,
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={WEAKNESS_STATUS_META} />,
    },
    {
      title: '接口',
      dataIndex: 'endpoint_key',
      width: 220,
      ellipsis: true,
      render: (v: string) =>
        v ? (
          <Tooltip title={v}>
            <Typography.Text code>{v}</Typography.Text>
          </Tooltip>
        ) : (
          '-'
        ),
    },
    { title: '触发次数', dataIndex: 'trigger_count', width: 90 },
    {
      title: '负责人',
      dataIndex: 'owner',
      width: 110,
      ellipsis: true,
      render: (v: string) => v || '-',
    },
    {
      title: '整改期限',
      dataIndex: 'due_date',
      width: 170,
      render: (v?: string | null) => formatDateTime(v),
    },
    {
      title: '最近命中',
      dataIndex: 'last_seen',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 80,
      fixed: 'right',
      render: (_, record) => (
        <Button type="link" size="small" onClick={() => setSelectedId(record.id)}>
          详情
        </Button>
      ),
    },
  ]

  /** 处置按钮区：按状态机可用性禁用，无处置权限整区不渲染 */
  const actionBar = current && canHandle && (
    <Space style={{ marginBottom: 16 }} wrap>
      <Button
        type="primary"
        disabled={!ACTION_ALLOWED.confirm.includes(current.status)}
        onClick={() => openNoteAction('confirm')}
      >
        确认
      </Button>
      <Button
        disabled={!ACTION_ALLOWED.assign.includes(current.status)}
        onClick={() => {
          assignForm.resetFields()
          assignForm.setFieldsValue({ owner: current.owner || undefined })
          setAssignOpen(true)
        }}
      >
        指派
      </Button>
      <Button
        disabled={!ACTION_ALLOWED.fixed.includes(current.status)}
        onClick={() => openNoteAction('fixed')}
      >
        整改完成
      </Button>
      <Button
        disabled={!ACTION_ALLOWED.retest.includes(current.status)}
        onClick={() => {
          retestForm.resetFields()
          setRetestOpen(true)
        }}
      >
        复测
      </Button>
      <Button
        disabled={!ACTION_ALLOWED.ignore.includes(current.status)}
        onClick={() => openNoteAction('ignore')}
      >
        忽略
      </Button>
      <Button
        danger
        disabled={!ACTION_ALLOWED.archive.includes(current.status)}
        onClick={() => openNoteAction('archive')}
      >
        归档
      </Button>
    </Space>
  )

  return (
    <Card title="API 弱点中心">
      <Typography.Paragraph type="secondary">
        运行时扫描派生的 API 弱点：未认证敏感接口、已下线仍被调用、敏感数据出现在查询串、Schema
        漂移长期存在等；按「确认 → 指派 → 整改 → 复测 → 归档」闭环处置。
      </Typography.Paragraph>
      <QueryErrorAlert error={listQuery.error} />
      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          placeholder="状态"
          allowClear
          style={{ width: 140 }}
          value={status}
          options={Object.entries(WEAKNESS_STATUS_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => {
            setStatus(v)
            setPage(1)
          }}
        />
        <Select
          placeholder="严重级别"
          allowClear
          style={{ width: 140 }}
          value={severity}
          options={Object.entries(API_FINDING_SEVERITY_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => {
            setSeverity(v)
            setPage(1)
          }}
        />
        <Select
          placeholder="分类"
          allowClear
          style={{ width: 140 }}
          value={category}
          options={Object.entries(WEAKNESS_CATEGORY_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => {
            setCategory(v)
            setPage(1)
          }}
        />
      </Space>
      <SmartTable<ApiWeakness>
        storageKey="api-weaknesses"
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        scroll={{ x: 1400 }}
        onRow={(record) => ({
          onDoubleClick: () => setSelectedId(record.id),
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
        title={current ? `弱点详情：${current.weakness_name}` : '弱点详情'}
        open={selectedId !== null}
        onClose={() => setSelectedId(null)}
        width={720}
      >
        {detailQuery.isLoading ? (
          <Spin />
        ) : current ? (
          <>
            {actionBar}
            <Descriptions column={2} size="small" style={{ marginBottom: 16 }}>
              <Descriptions.Item label="弱点名称">{current.weakness_name}</Descriptions.Item>
              <Descriptions.Item label="弱点编码">
                <Typography.Text code>{current.weakness_code}</Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label="分类">
                <StatusTag value={current.category} map={WEAKNESS_CATEGORY_META} />
              </Descriptions.Item>
              <Descriptions.Item label="严重级别">
                <StatusTag value={current.severity} map={API_FINDING_SEVERITY_META} />
              </Descriptions.Item>
              <Descriptions.Item label="状态">
                <StatusTag value={current.status} map={WEAKNESS_STATUS_META} />
              </Descriptions.Item>
              <Descriptions.Item label="接口">
                {current.endpoint_key ? (
                  <Typography.Text code>{current.endpoint_key}</Typography.Text>
                ) : (
                  '-'
                )}
              </Descriptions.Item>
              <Descriptions.Item label="负责人">{current.owner || '-'}</Descriptions.Item>
              <Descriptions.Item label="整改期限">
                {formatDateTime(current.due_date)}
              </Descriptions.Item>
              <Descriptions.Item label="触发次数">{current.trigger_count}</Descriptions.Item>
              <Descriptions.Item label="首次命中">
                {formatDateTime(current.first_seen)}
              </Descriptions.Item>
              <Descriptions.Item label="最近命中">
                {formatDateTime(current.last_seen)}
              </Descriptions.Item>
              <Descriptions.Item label="整改完成时间">
                {formatDateTime(current.fixed_at)}
              </Descriptions.Item>
              <Descriptions.Item label="最近复测时间">
                {formatDateTime(current.retested_at)}
              </Descriptions.Item>
              <Descriptions.Item label="弱点 ID" span={2}>
                <Typography.Text code>{current.id}</Typography.Text>
              </Descriptions.Item>
            </Descriptions>
            <Typography.Title level={5}>派生证据（evidence）</Typography.Title>
            <Typography.Paragraph>
              <pre
                style={{ background: '#fafafa', padding: 12, fontSize: 12, overflow: 'auto', margin: 0 }}
              >
                {formatJson(current.evidence)}
              </pre>
            </Typography.Paragraph>
            <Typography.Title level={5}>处置历史</Typography.Title>
            {(detailQuery.data?.actions ?? []).length === 0 ? (
              <Typography.Text type="secondary">暂无处置记录</Typography.Text>
            ) : (
              <Timeline
                items={(detailQuery.data?.actions ?? []).map((a) => {
                  const meta = WEAKNESS_ACTION_META[a.action]
                  return {
                    color: meta?.color ?? 'gray',
                    children: (
                      <Space direction="vertical" size={0}>
                        <Space size={8}>
                          <Typography.Text strong>{meta?.label ?? a.action}</Typography.Text>
                          <Typography.Text type="secondary">
                            {a.actor || 'system'} · {formatDateTime(a.created_at)}
                          </Typography.Text>
                        </Space>
                        {a.note ? (
                          <Typography.Text type="secondary">{a.note}</Typography.Text>
                        ) : null}
                      </Space>
                    ),
                  }
                })}
              />
            )}
          </>
        ) : null}
      </Drawer>

      <Modal
        title={noteAction ? NOTE_ACTION_TITLE[noteAction] : ''}
        open={noteAction !== null}
        onCancel={() => setNoteAction(null)}
        onOk={() => {
          if (!current || !noteAction) return
          transitionMut.mutate({
            id: current.id,
            action: noteAction,
            ...(noteText.trim() ? { note: noteText.trim() } : {}),
          })
        }}
        confirmLoading={transitionMut.isPending}
        destroyOnHidden
      >
        <Typography.Paragraph type="secondary">备注（可选，不超过 512 字符）</Typography.Paragraph>
        <Input.TextArea
          rows={3}
          maxLength={512}
          showCount
          value={noteText}
          onChange={(e) => setNoteText(e.target.value)}
          placeholder="处置原因、依据或说明"
        />
      </Modal>

      <Modal
        title="指派整改"
        open={assignOpen}
        onCancel={() => setAssignOpen(false)}
        onOk={() => assignForm.submit()}
        confirmLoading={transitionMut.isPending}
        destroyOnHidden
      >
        <Form<AssignFormValues> form={assignForm} layout="vertical" onFinish={submitAssign}>
          <Form.Item
            name="owner"
            label="整改负责人"
            rules={[
              { required: true, message: '请填写整改负责人' },
              { max: 128, message: '负责人不超过 128 字符' },
            ]}
          >
            <Input placeholder="负责人用户名或姓名" />
          </Form.Item>
          <Form.Item name="due_date" label="整改期限（可选）">
            <DatePicker showTime style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="note" label="备注（可选）" rules={[{ max: 512, message: '备注不超过 512 字符' }]}>
            <Input.TextArea rows={3} placeholder="整改要求、说明" />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title="复测"
        open={retestOpen}
        onCancel={() => setRetestOpen(false)}
        onOk={() => retestForm.submit()}
        confirmLoading={transitionMut.isPending}
        destroyOnHidden
      >
        <Typography.Paragraph type="secondary">
          复测通过后弱点归档关闭；未通过则转为「复现」，需重新指派整改。
        </Typography.Paragraph>
        <Form<RetestFormValues>
          form={retestForm}
          layout="vertical"
          initialValues={{ result: 'PASS' }}
          onFinish={submitRetest}
        >
          <Form.Item name="result" label="复测结果" rules={[{ required: true, message: '请选择复测结果' }]}>
            <Radio.Group
              options={[
                { value: 'PASS', label: '通过' },
                { value: 'FAIL', label: '未通过' },
              ]}
            />
          </Form.Item>
          <Form.Item name="note" label="备注（可选）" rules={[{ max: 512, message: '备注不超过 512 字符' }]}>
            <Input.TextArea rows={3} placeholder="复测结论、依据" />
          </Form.Item>
        </Form>
      </Modal>
    </Card>
  )
}
