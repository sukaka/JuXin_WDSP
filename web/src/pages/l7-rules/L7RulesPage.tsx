import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App as AntdApp, Button, Card, Input, Select, Space, Switch, Tabs, Tooltip, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { CloudUploadOutlined, ExperimentOutlined, PlusOutlined } from '@ant-design/icons'
import { ApiError } from '../../api/client'
import { l7RulesApi, type L7RuleBody } from '../../api/l7Rules'
import SmartTable from '../../components/SmartTable'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import StatusTag from '../../components/StatusTag'
import useBatchDelete from '../../hooks/useBatchDelete'
import { PublishTaskProgress } from '../config-publish/ConfigPublishPage'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { generateIdempotencyKey } from '../../utils/idempotency'
import { hasPermission } from '../../utils/permission'
import { L7_RULE_ACTION_META, summarizeConditions } from '../../utils/l7rules'
import L7RuleFormDrawer from './L7RuleFormDrawer'
import L7RuleTesterModal from './L7RuleTesterModal'
import L7RuleHitsPanel from './L7RuleHitsPanel'
import { ruleToFormValues, type L7RuleFormValues } from './formValues'
import type { L7RuleItem } from '../../types'

interface Filters {
  keyword?: string
  enabled?: boolean
}

export default function L7RulesPage() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canCreate = hasPermission(permissions, 'l7rules.create')
  const canUpdate = hasPermission(permissions, 'l7rules.update')
  const canDelete = hasPermission(permissions, 'l7rules.delete')
  const canPublish = hasPermission(permissions, 'l7rules.publish')

  const [filters, setFilters] = useState<Filters>({})
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [formOpen, setFormOpen] = useState(false)
  const [editing, setEditing] = useState<L7RuleItem | null>(null)
  const [copyFrom, setCopyFrom] = useState<L7RuleFormValues | null>(null)
  const [testerOpen, setTesterOpen] = useState(false)
  const [activeTaskId, setActiveTaskId] = useState<string | null>(null)
  const [detailRecord, setDetailRecord] = useState<L7RuleItem | null>(null)

  const listQuery = useQuery({
    queryKey: ['l7-rules', filters, page, pageSize],
    queryFn: () => l7RulesApi.list({ ...filters, page, page_size: pageSize }),
  })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['l7-rules'] })
  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  /** 启停开关：PATCH 全量可编辑字段，仅翻转 enabled */
  const toggleMutation = useMutation({
    mutationFn: (record: L7RuleItem) => {
      const body: L7RuleBody = {
        name: record.name,
        priority: record.priority,
        enabled: !record.enabled,
        conditions: record.conditions ?? [],
        action: record.action,
        action_config: record.action_config ?? {},
      }
      return l7RulesApi.update(record.id, body)
    },
    onSuccess: (_data, record) => {
      message.success(`规则「${record.name}」已${record.enabled ? '停用' : '启用'}（发布后生效）`)
      void invalidate()
    },
    onError,
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => l7RulesApi.remove(id),
    onSuccess: () => {
      message.success('规则已删除（发布后生效）')
      void invalidate()
    },
    onError,
  })

  const { rowSelection, batchDeleteButton } = useBatchDelete<L7RuleItem>({
    remove: (id) => l7RulesApi.remove(id),
    invalidateKeys: [['l7-rules']],
    entityName: 'L7 规则',
    canDelete,
  })

  const publishMutation = useMutation({
    mutationFn: () => l7RulesApi.publish(generateIdempotencyKey()),
    onSuccess: (task) => {
      if (task?.id) setActiveTaskId(task.id)
      if (task?.status === 'SUCCESS') message.success('发布成功')
      else if (task?.status === 'FAILED') message.error('发布失败，请查看任务详情')
      else message.success('发布任务已提交')
    },
    onError: (e) => message.error(e instanceof ApiError ? e.message : '发布失败'),
  })

  const openCreate = () => {
    setEditing(null)
    setCopyFrom(null)
    setFormOpen(true)
  }

  const openEdit = (record: L7RuleItem) => {
    setEditing(record)
    setCopyFrom(null)
    setFormOpen(true)
  }

  /** 复制：以原规则内容预填新建表单（契约无独立复制接口） */
  const openCopy = (record: L7RuleItem) => {
    setEditing(null)
    setCopyFrom({ ...ruleToFormValues(record), name: `${record.name}-副本` })
    setFormOpen(true)
  }

  const confirmDelete = (record: L7RuleItem) => {
    modal.confirm({
      title: '删除确认',
      content: `确定删除规则「${record.name}」吗？删除后需发布才在网关生效。`,
      okButtonProps: { danger: true },
      onOk: () => deleteMutation.mutate(record.id),
    })
  }

  const confirmPublish = () => {
    modal.confirm({
      title: '高风险操作确认',
      content:
        '发布将把当前 L7 访问控制规则随访问控制配置下发到防护网关并立即生效；发布后生成新的访问控制版本，可在「访问控制版本」页查看差异与回滚。确定执行发布吗？',
      okText: '确认发布',
      okButtonProps: { danger: true },
      onOk: () => publishMutation.mutate(),
    })
  }

  const columns: ColumnsType<L7RuleItem> = [
    { title: '优先级', dataIndex: 'priority', width: 80 },
    { title: '名称', dataIndex: 'name', width: 180, ellipsis: true },
    {
      title: '条件摘要',
      key: 'conditions',
      ellipsis: true,
      render: (_, record) => {
        const conds = record.conditions ?? []
        const text = summarizeConditions(conds)
        // 条件超过折叠条数时，悬浮展示完整摘要
        return (
          <Tooltip
            title={conds.length > 2 ? summarizeConditions(conds, 10) : undefined}
            placement="topLeft"
          >
            <Typography.Text style={{ fontSize: 12 }}>{text}</Typography.Text>
          </Tooltip>
        )
      },
    },
    {
      title: '动作',
      dataIndex: 'action',
      width: 110,
      render: (v: string) => <StatusTag value={v} map={L7_RULE_ACTION_META} />,
    },
    {
      title: '启停',
      dataIndex: 'enabled',
      width: 80,
      render: (v: boolean, record) => (
        <Switch
          checked={v}
          disabled={!canUpdate || toggleMutation.isPending}
          onChange={() =>
            modal.confirm({
              title: `${v ? '停用' : '启用'}确认`,
              content: `确定${v ? '停用' : '启用'}规则「${record.name}」吗？${v ? '停用后该规则不再参与匹配' : '启用后按优先级参与匹配'}，发布后生效。`,
              onOk: () => toggleMutation.mutate(record),
            })
          }
        />
      ),
    },
    { title: '24h 命中', dataIndex: 'hit_count_24h', width: 90, render: (v?: number) => v ?? '-' },
    {
      title: '更新时间',
      dataIndex: 'updated_at',
      width: 165,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 170,
      fixed: 'right',
      render: (_, record) => (
        <Space size={0} wrap>
          {canUpdate && (
            <Button type="link" size="small" onClick={() => openEdit(record)}>
              编辑
            </Button>
          )}
          {canCreate && (
            <Button type="link" size="small" onClick={() => openCopy(record)}>
              复制
            </Button>
          )}
          {canDelete && (
            <Button type="link" size="small" danger onClick={() => confirmDelete(record)}>
              删除
            </Button>
          )}
        </Space>
      ),
    },
  ]

  const rulesTab = (
    <>
      {activeTaskId && <PublishTaskProgress taskId={activeTaskId} />}
      <Space style={{ marginBottom: 16, marginTop: activeTaskId ? 16 : 0 }} wrap>
        <Input.Search
          placeholder="规则名称"
          allowClear
          style={{ width: 200 }}
          onSearch={(v) => {
            setFilters((f) => ({ ...f, keyword: v || undefined }))
            setPage(1)
          }}
        />
        <Select
          placeholder="启停状态"
          allowClear
          style={{ width: 120 }}
          options={[
            { value: 'true', label: '启用' },
            { value: 'false', label: '停用' },
          ]}
          onChange={(v) => {
            setFilters((f) => ({ ...f, enabled: v === undefined ? undefined : v === 'true' }))
            setPage(1)
          }}
        />
        {batchDeleteButton}
      </Space>
      {listQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="加载 L7 访问控制规则失败"
          description={listQuery.error instanceof ApiError ? listQuery.error.message : undefined}
        />
      ) : (
        <SmartTable<L7RuleItem>
          storageKey="l7-rules"
          rowKey="id"
          rowSelection={rowSelection}
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          onRow={(record) => ({
            onDoubleClick: () => setDetailRecord(record),
            style: { cursor: 'pointer' },
          })}
          scroll={{ x: 1200 }}
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
    </>
  )

  return (
    <Card
      title="L7 访问控制"
      extra={
        <Space>
          <Button icon={<ExperimentOutlined />} onClick={() => setTesterOpen(true)}>
            规则测试器
          </Button>
          {canPublish && (
            <Button
              icon={<CloudUploadOutlined />}
              loading={publishMutation.isPending}
              onClick={confirmPublish}
            >
              发布
            </Button>
          )}
          {canCreate && (
            <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>
              新建规则
            </Button>
          )}
        </Space>
      }
    >
      <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
        按 URI / 请求域名（Host） / 请求方法 / 请求头 / Cookie / 查询参数 / 来源 IP / 请求体 / 返回头 / 返回体组合条件（多条件且（全部满足））。
        请求条件在源站前评估，响应条件在响应回程评估，各阶段按优先级首中即停；全部未命中则继续后续检查。规则的增删改需发布后才会下发网关生效。
      </Typography.Paragraph>
      <Tabs
        items={[
          { key: 'rules', label: '规则列表', children: rulesTab },
          { key: 'hits', label: '命中日志', children: <L7RuleHitsPanel /> },
        ]}
      />

      <L7RuleFormDrawer
        open={formOpen}
        editing={editing}
        initialValues={editing ? ruleToFormValues(editing) : copyFrom}
        onClose={() => {
          setFormOpen(false)
          setEditing(null)
          setCopyFrom(null)
        }}
        onSaved={() => {
          setFormOpen(false)
          setEditing(null)
          setCopyFrom(null)
          void invalidate()
        }}
      />
      <L7RuleTesterModal open={testerOpen} onClose={() => setTesterOpen(false)} />
      <RecordDetailDrawer
        open={detailRecord !== null}
        title="规则详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </Card>
  )
}
