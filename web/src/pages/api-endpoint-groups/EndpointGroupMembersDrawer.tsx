import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Drawer,
  Popconfirm,
  Select,
  Space,
  Table,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { PlusOutlined } from '@ant-design/icons'
import { apiEndpointsApi } from '../../api/apiAssets'
import {
  apiEndpointGroupsApi,
  type ApiEndpoint,
  type ApiEndpointGroup,
} from '../../api/apiEndpointGroups'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import StatusTag from '../../components/StatusTag'
import { formatDateTime } from '../../utils/format'
import { API_ENDPOINT_STATUS_META } from '../../utils/stage8'

export default function EndpointGroupMembersDrawer({
  group,
  canManage,
  onClose,
  onChanged,
}: {
  group: ApiEndpointGroup
  canManage: boolean
  onClose: () => void
  onChanged: () => void
}) {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [endpointId, setEndpointId] = useState<string>()
  const [keyword, setKeyword] = useState('')

  const membersQuery = useQuery({
    queryKey: ['api-endpoint-groups', 'members', group.id, page, pageSize],
    queryFn: () =>
      apiEndpointGroupsApi.listEndpoints(group.id, {
        page,
        page_size: pageSize,
      }),
  })
  const candidatesQuery = useQuery({
    queryKey: [
      'api-endpoints',
      'endpoint-group-options',
      group.application_id,
      keyword,
    ],
    queryFn: () =>
      apiEndpointsApi.list({
        application_id: group.application_id,
        keyword: keyword || undefined,
        page: 1,
        page_size: 100,
      }),
    enabled: canManage,
  })

  const refreshMembers = () => {
    void queryClient.invalidateQueries({
      queryKey: ['api-endpoint-groups', 'members', group.id],
    })
    onChanged()
  }
  const mutationError = (error: unknown, fallback: string) =>
    message.error(error instanceof ApiError ? error.message : fallback)

  const addMutation = useMutation({
    mutationFn: (id: string) => apiEndpointGroupsApi.addEndpoint(group.id, id),
    onSuccess: () => {
      message.success('接口成员已添加')
      setEndpointId(undefined)
      setKeyword('')
      refreshMembers()
    },
    onError: (error: unknown) => mutationError(error, '添加接口成员失败'),
  })
  const removeMutation = useMutation({
    mutationFn: (id: string) =>
      apiEndpointGroupsApi.removeEndpoint(group.id, id),
    onSuccess: () => {
      message.success('接口成员已移除')
      if (page > 1 && (membersQuery.data?.items.length ?? 0) === 1) {
        setPage(page - 1)
      }
      refreshMembers()
    },
    onError: (error: unknown) => mutationError(error, '移除接口成员失败'),
  })

  const columns: ColumnsType<ApiEndpoint> = [
    {
      title: '方法',
      dataIndex: 'http_method',
      width: 90,
      render: (value: string) => <Tag color="blue">{value}</Tag>,
    },
    {
      title: '接口路径',
      dataIndex: 'normalized_path',
      ellipsis: true,
      render: (value: string, record) => (
        <Typography.Text code>{value || record.endpoint_key}</Typography.Text>
      ),
    },
    {
      title: '资产状态',
      dataIndex: 'asset_status',
      width: 110,
      render: (value: string) => (
        <StatusTag value={value} map={API_ENDPOINT_STATUS_META} />
      ),
    },
    {
      title: '加入时间',
      dataIndex: 'added_at',
      width: 170,
      render: formatDateTime,
    },
    ...(canManage
      ? [
          {
            title: '操作',
            key: 'actions',
            width: 90,
            fixed: 'right' as const,
            render: (_: unknown, record: ApiEndpoint) => (
              <Popconfirm
                title="移除接口成员？"
                description={`仅解除「${record.endpoint_key}」与当前分组的关系，不删除接口资产。`}
                okText="移除"
                okButtonProps={{ danger: true }}
                cancelText="取消"
                onConfirm={() => removeMutation.mutate(record.id)}
              >
                <Button
                  type="link"
                  size="small"
                  danger
                  aria-label={`移除成员-${record.endpoint_key}`}
                >
                  移除
                </Button>
              </Popconfirm>
            ),
          },
        ]
      : []),
  ]

  return (
    <Drawer
      title={`接口成员 · ${group.name}`}
      open
      onClose={onClose}
      width={920}
      destroyOnHidden
    >
      <Alert
        type="info"
        showIcon
        message={`所属应用：${group.application_name || group.application_id}`}
        description="仅可添加同应用的真实接口；一个接口可加入多个业务分组。移除成员不会删除接口资产。"
        style={{ marginBottom: 16 }}
      />
      {canManage ? (
        <Space.Compact style={{ width: '100%', marginBottom: 16 }}>
          <Select
            showSearch
            filterOption={false}
            value={endpointId}
            onChange={setEndpointId}
            onSearch={setKeyword}
            loading={candidatesQuery.isFetching}
            placeholder="搜索并选择同应用接口"
            style={{ width: '100%' }}
            options={(candidatesQuery.data?.items ?? []).map((endpoint) => ({
              value: endpoint.id,
              label: endpoint.endpoint_key,
            }))}
            notFoundContent={
              candidatesQuery.isFetching ? '正在加载接口…' : '未找到匹配接口'
            }
          />
          <Button
            type="primary"
            icon={<PlusOutlined />}
            disabled={!endpointId}
            loading={addMutation.isPending}
            onClick={() => endpointId && addMutation.mutate(endpointId)}
          >
            添加成员
          </Button>
        </Space.Compact>
      ) : null}
      <QueryErrorAlert error={membersQuery.error} message="加载接口成员失败" />
      {canManage ? (
        <QueryErrorAlert
          error={candidatesQuery.error}
          message="加载可添加接口失败"
        />
      ) : null}
      <Table<ApiEndpoint>
        rowKey="id"
        loading={membersQuery.isFetching}
        columns={columns}
        dataSource={membersQuery.data?.items ?? []}
        scroll={{ x: 760 }}
        locale={{
          emptyText: canManage
            ? '暂无接口成员，请从上方选择真实接口添加'
            : '暂无接口成员',
        }}
        pagination={{
          current: page,
          pageSize,
          total: membersQuery.data?.total ?? 0,
          showSizeChanger: true,
          showTotal: (total) => `共 ${total} 个接口`,
        }}
        onChange={(pagination) => {
          const nextPageSize = pagination.pageSize ?? pageSize
          setPage(nextPageSize === pageSize ? (pagination.current ?? 1) : 1)
          setPageSize(nextPageSize)
        }}
      />
    </Drawer>
  )
}
