import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Badge,
  Button,
  Card,
  Select,
  Space,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { PlusOutlined } from '@ant-design/icons'
import { applicationsApi } from '../../api/applications'
import {
  apiEndpointGroupsApi,
  toApiEndpointGroupUpdateInput,
  type ApiEndpointGroup,
} from '../../api/apiEndpointGroups'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import EndpointGroupFormModal from './EndpointGroupFormModal'
import EndpointGroupMembersDrawer from './EndpointGroupMembersDrawer'

export default function ApiEndpointGroupsPage() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((state) => state.user?.permissions)
  const canManage = hasPermission(permissions, 'api_endpoint_group.manage')
  const [applicationId, setApplicationId] = useState<string>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [editor, setEditor] = useState<ApiEndpointGroup | null | undefined>(
    undefined,
  )
  const [membersGroup, setMembersGroup] = useState<ApiEndpointGroup | null>(
    null,
  )

  const applicationsQuery = useQuery({
    queryKey: ['applications', 'endpoint-group-options'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
  })
  const groupsQuery = useQuery({
    queryKey: [
      'api-endpoint-groups',
      'list',
      applicationId ?? '',
      page,
      pageSize,
    ],
    queryFn: () =>
      apiEndpointGroupsApi.list({
        application_id: applicationId,
        page,
        page_size: pageSize,
      }),
  })

  const refreshGroups = () => {
    void queryClient.invalidateQueries({
      queryKey: ['api-endpoint-groups', 'list'],
    })
  }
  const showMutationError = (error: unknown, fallback: string) =>
    message.error(error instanceof ApiError ? error.message : fallback)

  const toggleMutation = useMutation({
    mutationFn: (group: ApiEndpointGroup) =>
      apiEndpointGroupsApi.update(
        group.id,
        toApiEndpointGroupUpdateInput(group, { enabled: !group.enabled }),
      ),
    onSuccess: (_, group) => {
      message.success(group.enabled ? '接口分组已停用' : '接口分组已启用')
      refreshGroups()
    },
    onError: (error: unknown) => showMutationError(error, '更新启用状态失败'),
  })
  const deleteMutation = useMutation({
    mutationFn: (group: ApiEndpointGroup) =>
      apiEndpointGroupsApi.remove(group.id),
    onSuccess: (_, group) => {
      message.success('接口分组已删除')
      if (membersGroup?.id === group.id) setMembersGroup(null)
      if (page > 1 && (groupsQuery.data?.items.length ?? 0) === 1) {
        setPage(page - 1)
      }
      refreshGroups()
    },
    onError: (error: unknown) => showMutationError(error, '删除接口分组失败'),
  })

  const confirmDelete = (group: ApiEndpointGroup) => {
    modal.confirm({
      title: `删除接口分组「${group.name}」？`,
      content: `该组当前关联 ${group.endpoint_count} 个接口。删除将解除这些成员关系，但不会删除接口资产；此操作不可撤销。`,
      okText: '删除',
      okButtonProps: { danger: true },
      cancelText: '取消',
      onOk: () => deleteMutation.mutate(group),
    })
  }

  const columns: ColumnsType<ApiEndpointGroup> = [
    {
      title: '分组名称',
      dataIndex: 'name',
      width: 190,
      ellipsis: true,
      render: (value: string, record) => (
        <Space orientation="vertical" size={2}>
          <Typography.Text strong>{value}</Typography.Text>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {record.code}
          </Typography.Text>
        </Space>
      ),
    },
    {
      title: '所属应用',
      dataIndex: 'application_name',
      width: 180,
      ellipsis: true,
      render: (value: string, record) => value || record.application_id,
    },
    {
      title: '业务说明',
      dataIndex: 'description',
      ellipsis: true,
      render: (value: string) => value || '-',
    },
    {
      title: '接口数',
      dataIndex: 'endpoint_count',
      width: 90,
      align: 'right',
      render: (value: number, record) => (
        <Button
          type="link"
          size="small"
          onClick={() => setMembersGroup(record)}
        >
          {value}
        </Button>
      ),
    },
    {
      title: '状态',
      dataIndex: 'enabled',
      width: 90,
      render: (value: boolean) => (
        <Badge
          status={value ? 'success' : 'default'}
          text={value ? '启用' : '停用'}
        />
      ),
    },
    {
      title: '更新时间',
      dataIndex: 'updated_at',
      width: 170,
      render: formatDateTime,
    },
    {
      title: '操作',
      key: 'actions',
      width: canManage ? 280 : 90,
      fixed: 'right',
      render: (_, record) => (
        <Space size={0} wrap>
          <Button
            type="link"
            size="small"
            aria-label={`管理成员-${record.name}`}
            onClick={() => setMembersGroup(record)}
          >
            成员
          </Button>
          {canManage ? (
            <>
              <Button
                type="link"
                size="small"
                aria-label={`编辑分组-${record.name}`}
                onClick={() => setEditor(record)}
              >
                编辑
              </Button>
              <Button
                type="link"
                size="small"
                loading={
                  toggleMutation.isPending &&
                  toggleMutation.variables?.id === record.id
                }
                onClick={() => toggleMutation.mutate(record)}
              >
                {record.enabled ? '停用' : '启用'}
              </Button>
              <Button
                type="link"
                size="small"
                danger
                aria-label={`删除分组-${record.name}`}
                onClick={() => confirmDelete(record)}
              >
                删除
              </Button>
            </>
          ) : null}
        </Space>
      ),
    },
  ]

  return (
    <Card
      title="业务功能分组"
      extra={
        <Space>
          {!canManage ? <Tag>只读</Tag> : null}
          {canManage ? (
            <Button
              type="primary"
              icon={<PlusOutlined />}
              onClick={() => setEditor(null)}
            >
              新建分组
            </Button>
          ) : null}
        </Space>
      }
    >
      <Typography.Paragraph type="secondary">
        按业务功能组织同应用的真实接口，形成可复用的接口组数据；一个接口可属于多个分组。
      </Typography.Paragraph>
      <Space
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          marginBottom: 16,
        }}
        wrap
      >
        <Select
          showSearch
          optionFilterProp="label"
          allowClear
          placeholder="全部应用"
          aria-label="按应用筛选"
          style={{ width: 280 }}
          value={applicationId}
          loading={applicationsQuery.isLoading}
          options={(applicationsQuery.data?.items ?? []).map((app) => ({
            value: app.id,
            label: `${app.name}（${app.code}）`,
          }))}
          onChange={(value) => {
            setApplicationId(value)
            setPage(1)
          }}
        />
      </Space>
      <QueryErrorAlert error={groupsQuery.error} message="加载接口分组失败" />
      <QueryErrorAlert
        error={applicationsQuery.error}
        message="加载应用列表失败"
      />
      <SmartTable<ApiEndpointGroup>
        storageKey="api-endpoint-groups"
        rowKey="id"
        loading={groupsQuery.isFetching}
        columns={columns}
        dataSource={groupsQuery.data?.items ?? []}
        scroll={{ x: 1180 }}
        locale={{
          emptyText: applicationId
            ? '该应用暂无接口分组'
            : canManage
              ? '暂无接口分组，可点击“新建分组”开始整理业务接口'
              : '暂无接口分组',
        }}
        pagination={{
          current: page,
          pageSize,
          total: groupsQuery.data?.total ?? 0,
          showSizeChanger: true,
          showTotal: (total) => `共 ${total} 个分组`,
        }}
        onChange={(pagination) => {
          const nextPageSize = pagination.pageSize ?? pageSize
          setPage(nextPageSize === pageSize ? (pagination.current ?? 1) : 1)
          setPageSize(nextPageSize)
        }}
      />
      {editor !== undefined ? (
        <EndpointGroupFormModal
          group={editor}
          onClose={() => setEditor(undefined)}
          onSaved={refreshGroups}
        />
      ) : null}
      {membersGroup ? (
        <EndpointGroupMembersDrawer
          group={membersGroup}
          canManage={canManage}
          onClose={() => setMembersGroup(null)}
          onChanged={refreshGroups}
        />
      ) : null}
    </Card>
  )
}
