import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Button,
  Descriptions,
  Drawer,
  Form,
  Input,
  Modal,
  Select,
  Space,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { apiScanApi, type ApiScanFinding } from '../../api/apiScan'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime, formatJson } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import {
  API_FINDING_SEVERITY_FILTER_OPTIONS,
  API_FINDING_SEVERITY_META,
} from '../../utils/stage8'
import {
  SCAN_CATEGORY_META,
  SCAN_FINDING_STATUS_META,
  SCAN_PROBE_SET_META,
} from './meta'

const SCAN_ENGINE_LABELS: Record<string, string> = {
  builtin: '内置引擎',
}

/** 样本展示框样式（与弱点中心证据展示一致） */
const SAMPLE_PRE_STYLE: React.CSSProperties = {
  background: '#fafafa',
  padding: 12,
  fontSize: 12,
  overflow: 'auto',
  margin: 0,
  whiteSpace: 'pre-wrap',
  wordBreak: 'break-all',
}

/**
 * 扫描发现 Tab：按任务/严重度过滤，详情抽屉展示脱敏证据与样本；
 * 确认/误报（api_scan.manage）与定向复测（api_scan.execute，须已关联弱点）。
 */
export default function FindingsTab() {
  const { message, modal } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'api_scan.manage')
  const canExecute = hasPermission(permissions, 'api_scan.execute')

  const [jobFilter, setJobFilter] = useState<string | undefined>()
  const [severityFilter, setSeverityFilter] = useState<string | undefined>()
  const [statusFilter, setStatusFilter] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [selected, setSelected] = useState<ApiScanFinding | null>(null)
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [retestOpen, setRetestOpen] = useState(false)
  const [confirmForm] = Form.useForm<{ weakness_id?: string }>()
  const [retestForm] = Form.useForm<{ note?: string }>()

  /** 任务选项（发现按任务过滤） */
  const jobsQuery = useQuery({
    queryKey: ['api-scan-jobs', 'options'],
    queryFn: () => apiScanApi.listJobs({ page: 1, page_size: 100 }),
  })
  const jobOptions = (jobsQuery.data?.items ?? []).map((j) => ({
    value: j.id,
    label: `#${j.id.slice(0, 8)}（${j.created_at.slice(0, 10)}）`,
  }))

  const listQuery = useQuery({
    queryKey: ['api-scan-findings', jobFilter, severityFilter, statusFilter, page, pageSize],
    queryFn: () =>
      apiScanApi.listFindings({
        job_id: jobFilter,
        severity: severityFilter,
        status: statusFilter,
        page,
        page_size: pageSize,
      }),
  })

  const invalidate = () => void qc.invalidateQueries({ queryKey: ['api-scan-findings'] })

  /** 抽屉内当前发现：处置成功后以响应为准更新本地选中态 */
  const current = selected

  const confirmMut = useMutation({
    mutationFn: (v: { weakness_id?: string }) =>
      apiScanApi.confirmFinding(
        (current as ApiScanFinding).id,
        v.weakness_id ? { weakness_id: v.weakness_id } : undefined,
      ),
    onSuccess: (r) => {
      message.success('发现已确认')
      setSelected(r.finding)
      setConfirmOpen(false)
      invalidate()
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '确认失败'),
  })

  const falsePositiveMut = useMutation({
    mutationFn: (id: string) => apiScanApi.falsePositiveFinding(id),
    onSuccess: (r) => {
      message.success('已判定为误报')
      setSelected(r.finding)
      invalidate()
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '操作失败'),
  })

  const retestMut = useMutation({
    mutationFn: (v: { note?: string }) =>
      apiScanApi.retestFinding(
        (current as ApiScanFinding).id,
        v.note ? { note: v.note } : undefined,
      ),
    onSuccess: (r) => {
      // 复测结果即时反馈：PASS = 未复现（弱点回写复测通过），FAIL = 复现（弱点回写复现）
      if (r.result === 'PASS') {
        message.success('复测通过：未复现，弱点已回写复测结论')
      } else {
        message.warning('复测未通过：探测复现，弱点已回写复测结论')
      }
      setRetestOpen(false)
      invalidate()
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '复测失败'),
  })

  const confirmFalsePositive = (record: ApiScanFinding) => {
    modal.confirm({
      title: '判定误报',
      content: `确定将 API「${record.endpoint_key}」的该发现判定为误报吗？`,
      onOk: () => falsePositiveMut.mutate(record.id),
    })
  }

  const columns: ColumnsType<ApiScanFinding> = [
    {
      title: 'API',
      dataIndex: 'endpoint_key',
      width: 220,
      ellipsis: true,
      render: (v: string) => (
        <Tooltip title={v}>
          <Typography.Text code>{v}</Typography.Text>
        </Tooltip>
      ),
    },
    {
      title: '探针集',
      dataIndex: 'template',
      width: 170,
      ellipsis: true,
      render: (v: string) => {
        const label = SCAN_PROBE_SET_META[v] ?? v
        return (
          <Tooltip title={label}>
            <Typography.Text>{label}</Typography.Text>
          </Tooltip>
        )
      },
    },
    {
      title: '分类',
      dataIndex: 'category',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={SCAN_CATEGORY_META} />,
    },
    {
      title: '严重级别',
      dataIndex: 'severity',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={API_FINDING_SEVERITY_META} />,
    },
    {
      title: '置信度',
      dataIndex: 'confidence',
      width: 90,
      render: (v: number) => `${Math.round(v * 100)}%`,
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 95,
      render: (v: string) => <StatusTag value={v} map={SCAN_FINDING_STATUS_META} />,
    },
    {
      title: '发现时间',
      dataIndex: 'created_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 80,
      fixed: 'right',
      render: (_, record) => (
        <Button type="link" size="small" onClick={() => setSelected(record)}>
          详情
        </Button>
      ),
    },
  ]

  /** 处置按钮区：确认/误报（manage，仅 NEW 可处置），复测（execute，须已关联弱点） */
  const actionBar = current && (canManage || canExecute) && (
    <Space style={{ marginBottom: 16 }} wrap>
      {canManage ? (
        <>
          <Button
            type="primary"
            disabled={current.status !== 'NEW'}
            onClick={() => {
              confirmForm.resetFields()
              setConfirmOpen(true)
            }}
          >
            确认
          </Button>
          <Button
            disabled={current.status !== 'NEW'}
            onClick={() => confirmFalsePositive(current)}
          >
            误报
          </Button>
        </>
      ) : null}
      {canExecute ? (
        <Tooltip title={current.weakness_id ? undefined : '须先确认并关联弱点后方可复测'}>
          <span>
            <Button
              disabled={!current.weakness_id}
              onClick={() => {
                retestForm.resetFields()
                setRetestOpen(true)
              }}
            >
              复测
            </Button>
          </span>
        </Tooltip>
      ) : null}
    </Space>
  )

  return (
    <>
      <QueryErrorAlert error={listQuery.error} />
      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          placeholder="任务"
          allowClear
          showSearch
          optionFilterProp="label"
          style={{ width: 220 }}
          value={jobFilter}
          options={jobOptions}
          onChange={(v) => {
            setJobFilter(v)
            setPage(1)
          }}
        />
        <Select
          placeholder="严重级别"
          allowClear
          style={{ width: 130 }}
          value={severityFilter}
          options={API_FINDING_SEVERITY_FILTER_OPTIONS}
          onChange={(v) => {
            setSeverityFilter(v)
            setPage(1)
          }}
        />
        <Select
          placeholder="状态"
          allowClear
          style={{ width: 130 }}
          value={statusFilter}
          options={Object.entries(SCAN_FINDING_STATUS_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => {
            setStatusFilter(v)
            setPage(1)
          }}
        />
      </Space>
      <SmartTable<ApiScanFinding>
        storageKey="api-scan-findings"
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        scroll={{ x: 1200 }}
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
        title={current ? `发现详情：${current.endpoint_key}` : '发现详情'}
        open={selected !== null}
        onClose={() => setSelected(null)}
        width={720}
      >
        {current ? (
          <>
            {actionBar}
            <Descriptions column={2} size="small" style={{ marginBottom: 16 }}>
              <Descriptions.Item label="API">
                <Typography.Text code>{current.endpoint_key}</Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label="探针集">
                {SCAN_PROBE_SET_META[current.template] ?? current.template}
              </Descriptions.Item>
              <Descriptions.Item label="分类">
                <StatusTag value={current.category} map={SCAN_CATEGORY_META} />
              </Descriptions.Item>
              <Descriptions.Item label="严重级别">
                <StatusTag value={current.severity} map={API_FINDING_SEVERITY_META} />
              </Descriptions.Item>
              <Descriptions.Item label="状态">
                <StatusTag value={current.status} map={SCAN_FINDING_STATUS_META} />
              </Descriptions.Item>
              <Descriptions.Item label="置信度">
                {Math.round(current.confidence * 100)}%
              </Descriptions.Item>
              <Descriptions.Item label="引擎">
                {current.engine ? (SCAN_ENGINE_LABELS[current.engine] ?? current.engine) : '-'}
              </Descriptions.Item>
              <Descriptions.Item label="发现时间">
                {formatDateTime(current.created_at)}
              </Descriptions.Item>
              <Descriptions.Item label="关联弱点" span={2}>
                {current.weakness_id ? (
                  <Typography.Text code>{current.weakness_id}</Typography.Text>
                ) : (
                  '-'
                )}
              </Descriptions.Item>
              <Descriptions.Item label="发现 ID" span={2}>
                <Typography.Text code>{current.id}</Typography.Text>
              </Descriptions.Item>
            </Descriptions>
            <Typography.Title level={5}>证据（已脱敏）</Typography.Title>
            <Typography.Paragraph>
              <pre style={SAMPLE_PRE_STYLE}>{formatJson(current.evidence)}</pre>
            </Typography.Paragraph>
            <Typography.Title level={5}>请求样本（凭据头已脱敏）</Typography.Title>
            <Typography.Paragraph>
              <pre style={SAMPLE_PRE_STYLE}>{current.request_sample || '-'}</pre>
            </Typography.Paragraph>
            <Typography.Title level={5}>响应样本（已截断；敏感类探针不落原文）</Typography.Title>
            <Typography.Paragraph>
              <pre style={SAMPLE_PRE_STYLE}>{current.response_sample || '-'}</pre>
            </Typography.Paragraph>
          </>
        ) : null}
      </Drawer>

      <Modal
        title="确认发现"
        open={confirmOpen}
        onCancel={() => setConfirmOpen(false)}
        onOk={() => confirmForm.submit()}
        confirmLoading={confirmMut.isPending}
        destroyOnHidden
      >
        <Typography.Paragraph type="secondary">
          确认后状态转为「已确认」；可携带弱点 ID 关联弱点中心已有弱点，关联后方可发起定向复测。
        </Typography.Paragraph>
        <Form<{ weakness_id?: string }>
          form={confirmForm}
          layout="vertical"
          onFinish={(v) => {
            const weaknessId = v.weakness_id?.trim()
            confirmMut.mutate(weaknessId ? { weakness_id: weaknessId } : {})
          }}
        >
          <Form.Item
            name="weakness_id"
            label="关联弱点 ID（可选）"
            rules={[
              {
                pattern: /^[0-9a-fA-F-]{36}$/,
                message: '弱点 ID 须为合法 UUID',
              },
            ]}
          >
            <Input placeholder="弱点中心弱点 UUID，留空 = 不关联" allowClear autoComplete="off" />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title="定向复测"
        open={retestOpen}
        onCancel={() => setRetestOpen(false)}
        onOk={() => retestForm.submit()}
        confirmLoading={retestMut.isPending}
        destroyOnHidden
      >
        <Typography.Paragraph type="secondary">
          对发现 API 做一次性定向重探：复现则弱点回写「复测未通过」，未复现则回写「复测通过」。
          弱点非已修复状态、授权失效或能力未启用时将如实报错，不伪造复测结论。
        </Typography.Paragraph>
        <Form<{ note?: string }>
          form={retestForm}
          layout="vertical"
          onFinish={(v) => {
            const note = v.note?.trim()
            retestMut.mutate(note ? { note } : {})
          }}
        >
          <Form.Item name="note" label="备注（可选）" rules={[{ max: 512, message: '备注不超过 512 字符' }]}>
            <Input.TextArea rows={3} placeholder="复测说明，留空使用默认备注" />
          </Form.Item>
        </Form>
      </Modal>
    </>
  )
}
