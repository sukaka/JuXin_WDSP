import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Card, Collapse, Descriptions, Drawer, Tag, Typography } from 'antd'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'
import type { ColumnsType } from 'antd/es/table'
import { ApiError } from '../../api/client'
import { rolesApi } from '../../api/roles'
import type { PermissionItem, RoleItem } from '../../types'

function groupByModule(permissions: PermissionItem[]): [string, PermissionItem[]][] {
  const map = new Map<string, PermissionItem[]>()
  for (const p of permissions) {
    const arr = map.get(p.module) ?? []
    arr.push(p)
    map.set(p.module, arr)
  }
  return [...map.entries()].sort(([a], [b]) => a.localeCompare(b))
}

export default function RolesPage() {
  const [selectedRoleId, setSelectedRoleId] = useState<string | null>(null)
  const [detailRecord, setDetailRecord] = useState<RoleItem | null>(null)
  const [permissionDetailRecord, setPermissionDetailRecord] = useState<PermissionItem | null>(null)

  const rolesQuery = useQuery({ queryKey: ['roles'], queryFn: rolesApi.list })
  const permissionsQuery = useQuery({ queryKey: ['permissions'], queryFn: rolesApi.permissions })
  const roleDetailQuery = useQuery({
    queryKey: ['role', selectedRoleId],
    queryFn: () => rolesApi.detail(selectedRoleId as string),
    enabled: selectedRoleId !== null,
  })

  const allPermissionGroups = useMemo(
    () => groupByModule(permissionsQuery.data?.items ?? []),
    [permissionsQuery.data],
  )
  const rolePermissionGroups = useMemo(
    () => groupByModule(roleDetailQuery.data?.permissions ?? []),
    [roleDetailQuery.data],
  )

  const columns: ColumnsType<RoleItem> = [
    { title: '角色名称', dataIndex: 'name', width: 140 },
    { title: '角色编码', dataIndex: 'code', width: 160, render: (v: string) => <Typography.Text code>{v}</Typography.Text> },
    { title: '描述', dataIndex: 'description' },
    {
      title: '内置',
      dataIndex: 'is_builtin',
      width: 80,
      render: (v: boolean) => (v ? <Tag color="blue">内置</Tag> : <Tag>自定义</Tag>),
    },
    {
      title: '操作',
      key: 'actions',
      width: 130,
      render: (_, record) => (
        <Button type="link" size="small" onClick={() => setSelectedRoleId(record.id)}>
          查看权限
        </Button>
      ),
    },
  ]

  const permissionColumns: ColumnsType<PermissionItem> = [
    { title: '权限码', dataIndex: 'code', width: 220, render: (v: string) => <Typography.Text code>{v}</Typography.Text> },
    { title: '名称', dataIndex: 'name', width: 160 },
    { title: '说明', dataIndex: 'description' },
  ]

  return (
    <>
      <Card title="角色权限" style={{ marginBottom: 16 }}>
        {rolesQuery.isError ? (
          <Alert
            type="error"
            showIcon
            message="加载角色列表失败"
            description={rolesQuery.error instanceof ApiError ? rolesQuery.error.message : undefined}
          />
        ) : (
          <SmartTable<RoleItem>
            storageKey="roles"
            rowKey="id"
            loading={rolesQuery.isLoading}
            columns={columns}
            dataSource={rolesQuery.data?.items}
            pagination={false}
            onRow={(record) => ({ onDoubleClick: () => setDetailRecord(record), style: { cursor: 'pointer' } })}
          />
        )}
      </Card>

      <Card title="全部权限清单">
        {permissionsQuery.isError ? (
          <Alert
            type="error"
            showIcon
            message="加载权限清单失败"
            description={permissionsQuery.error instanceof ApiError ? permissionsQuery.error.message : undefined}
          />
        ) : (
          <Collapse
            items={allPermissionGroups.map(([module, items]) => ({
              key: module,
              label: `${module}（${items.length}）`,
              children: (
                <SmartTable<PermissionItem>
                  storageKey="roles-2"
                  rowKey="id"
                  columns={permissionColumns}
                  dataSource={items}
                  pagination={false}
                  size="small"
                  onRow={(record) => ({ onDoubleClick: () => setPermissionDetailRecord(record), style: { cursor: 'pointer' } })}
                />
              ),
            }))}
          />
        )}
      </Card>

      <Drawer
        title={roleDetailQuery.data ? `角色权限：${roleDetailQuery.data.role.name}` : '角色权限'}
        open={selectedRoleId !== null}
        onClose={() => setSelectedRoleId(null)}
        width={720}
      >
        {roleDetailQuery.isLoading ? (
          <Typography.Text type="secondary">加载中...</Typography.Text>
        ) : roleDetailQuery.isError ? (
          <Alert
            type="error"
            showIcon
            message="加载角色详情失败"
            description={roleDetailQuery.error instanceof ApiError ? roleDetailQuery.error.message : undefined}
          />
        ) : roleDetailQuery.data ? (
          <>
            <Descriptions column={2} size="small" style={{ marginBottom: 16 }}>
              <Descriptions.Item label="角色编码">
                <Typography.Text code>{roleDetailQuery.data.role.code}</Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label="用户数">{roleDetailQuery.data.user_count}</Descriptions.Item>
              <Descriptions.Item label="描述" span={2}>
                {roleDetailQuery.data.role.description}
              </Descriptions.Item>
            </Descriptions>
            <Collapse
              items={rolePermissionGroups.map(([module, items]) => ({
                key: module,
                label: `${module}（${items.length}）`,
                children: (
                  <SmartTable<PermissionItem>
                    storageKey="roles-3"
                    rowKey="id"
                    columns={permissionColumns}
                    dataSource={items}
                    pagination={false}
                    size="small"
                  />
                ),
              }))}
            />
          </>
        ) : null}
      </Drawer>

      <RecordDetailDrawer
        open={detailRecord !== null}
        title="角色详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
      <RecordDetailDrawer
        open={permissionDetailRecord !== null}
        title="权限详情"
        record={permissionDetailRecord as Record<string, unknown> | null}
        onClose={() => setPermissionDetailRecord(null)}
      />
    </>
  )
}
