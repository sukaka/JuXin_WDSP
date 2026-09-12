import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { App as AntdApp, Button, Card, Select, Space, Table, Tabs, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { ArrowDownOutlined, ArrowUpOutlined, SaveOutlined } from '@ant-design/icons'
import { ApiError } from '../../api/client'
import { nodeInterfacesApi } from '../../api/nodeInterfaces'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import { useAuthStore } from '../../stores/auth'
import { hasPermission } from '../../utils/permission'
import type { NodeInterfaceItem } from '../../types'

/** 介质类型展示：TP 电口 / FIBRE 光口 / UNKNOWN 未知 */
const MEDIA_TYPE_META: Record<string, { label: string; color?: string }> = {
  TP: { label: '电口', color: 'cyan' },
  FIBRE: { label: '光口', color: 'purple' },
  UNKNOWN: { label: '未知' },
}

/** 网口用途角色（空值为未分配） */
const ROLE_OPTIONS = [
  { value: 'MANAGEMENT', label: '管理' },
  { value: 'TRAFFIC', label: '业务' },
  { value: 'MIRROR', label: '镜像' },
  { value: '', label: '未分配' },
]

/** 按 sort_order 升序，序号相同按接口名兜底保持稳定 */
function sortInterfaces(items: NodeInterfaceItem[]): NodeInterfaceItem[] {
  return [...items].sort((a, b) => a.sort_order - b.sort_order || a.ifname.localeCompare(b.ifname))
}

/** 网口管理：按节点分组展示物理网口，上下移动排序、编辑角色后保存（WDSP 阶段A） */
export default function NodeInterfacesPage() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canUpdate = hasPermission(permissions, 'system_settings.update')

  const listQuery = useQuery({
    queryKey: ['node-interfaces'],
    queryFn: () => nodeInterfacesApi.list(),
  })

  const nodes = useMemo(() => listQuery.data?.nodes ?? [], [listQuery.data])
  const [activeNode, setActiveNode] = useState<string>()
  const currentNode = activeNode ?? nodes[0]?.node_name ?? ''

  // 本地未保存的排序/角色修改（仅跟踪当前节点；保存成功或放弃后清空）
  const [edit, setEdit] = useState<{ nodeName: string; rows: NodeInterfaceItem[] } | null>(null)

  const [detailRecord, setDetailRecord] = useState<NodeInterfaceItem | null>(null)

  const serverRows = useMemo(() => {
    const node = nodes.find((n) => n.node_name === currentNode)
    return sortInterfaces(node?.interfaces ?? [])
  }, [nodes, currentNode])

  const rows = edit && edit.nodeName === currentNode ? edit.rows : serverRows
  const dirty = edit != null && edit.nodeName === currentNode

  const move = (index: number, delta: -1 | 1) => {
    const target = index + delta
    if (target < 0 || target >= rows.length) return
    const next = [...rows]
    ;[next[index], next[target]] = [next[target], next[index]]
    setEdit({ nodeName: currentNode, rows: next })
  }

  const changeRole = (ifname: string, role: string) => {
    setEdit({ nodeName: currentNode, rows: rows.map((r) => (r.ifname === ifname ? { ...r, role } : r)) })
  }

  const saveMutation = useMutation({
    mutationFn: () =>
      nodeInterfacesApi.saveOrder({
        node_name: currentNode,
        items: rows.map((r, i) => ({ ifname: r.ifname, sort_order: i + 1, role: r.role ?? '' })),
      }),
    onSuccess: (data) => {
      message.success(data.message || '排序已保存')
      setEdit(null)
      void queryClient.invalidateQueries({ queryKey: ['node-interfaces'] })
    },
    onError: (e) => {
      message.error(e instanceof ApiError ? e.message : '保存排序失败')
    },
  })

  /** 有未保存修改时切换节点需确认（确认后丢弃本地修改） */
  const switchNode = (key: string) => {
    if (!dirty) {
      setActiveNode(key)
      return
    }
    modal.confirm({
      title: '放弃未保存的修改？',
      content: '当前节点有未保存的排序/角色修改，切换节点将丢弃这些修改。',
      okText: '放弃修改',
      cancelText: '继续编辑',
      okButtonProps: { danger: true },
      onOk: () => {
        setEdit(null)
        setActiveNode(key)
      },
    })
  }

  const columns: ColumnsType<NodeInterfaceItem> = [
    {
      title: '排序',
      key: 'sort',
      width: 110,
      render: (_, __, index) => (
        <Space size={4}>
          <Typography.Text>{index + 1}</Typography.Text>
          <Button
            type="text"
            size="small"
            icon={<ArrowUpOutlined />}
            aria-label="上移"
            disabled={!canUpdate || index === 0}
            onClick={() => move(index, -1)}
          />
          <Button
            type="text"
            size="small"
            icon={<ArrowDownOutlined />}
            aria-label="下移"
            disabled={!canUpdate || index === rows.length - 1}
            onClick={() => move(index, 1)}
          />
        </Space>
      ),
    },
    {
      title: '接口名',
      dataIndex: 'ifname',
      width: 130,
      render: (v: string) => <Typography.Text strong>{v}</Typography.Text>,
    },
    {
      title: '介质类型',
      dataIndex: 'media_type',
      width: 100,
      render: (v: string) => {
        const meta = MEDIA_TYPE_META[v] ?? MEDIA_TYPE_META.UNKNOWN
        return <Tag color={meta.color}>{meta.label}</Tag>
      },
    },
    {
      title: '速率',
      dataIndex: 'link_speed',
      width: 110,
      render: (v: number | undefined, record) =>
        record.operstate?.toLowerCase() === 'down' || !v ? (
          <Typography.Text type="secondary">断开</Typography.Text>
        ) : (
          `${v} Mb/s`
        ),
    },
    {
      title: 'MAC',
      dataIndex: 'mac',
      width: 160,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: 'PCI 路径',
      dataIndex: 'pci_path',
      width: 120,
      render: (v?: string) => v || '-',
    },
    {
      title: '驱动',
      dataIndex: 'driver',
      width: 100,
      render: (v?: string) => v || '-',
    },
    {
      title: '角色',
      dataIndex: 'role',
      width: 120,
      render: (v: string | undefined, record) => (
        <Select
          size="small"
          style={{ width: 100 }}
          value={v ?? ''}
          options={ROLE_OPTIONS}
          disabled={!canUpdate}
          aria-label={`角色-${record.ifname}`}
          onChange={(role) => changeRole(record.ifname, role)}
        />
      ),
    },
    {
      title: '状态',
      dataIndex: 'present',
      width: 90,
      render: (v: boolean) => (v ? <Tag color="green">在线</Tag> : <Tag>已离线</Tag>),
    },
  ]

  return (
    <Card
      title="网口管理"
      extra={
        <Space>
          {dirty && <Typography.Text type="warning">有未保存的修改</Typography.Text>}
          {canUpdate && (
            <Button
              type="primary"
              icon={<SaveOutlined />}
              disabled={!dirty}
              loading={saveMutation.isPending}
              onClick={() => saveMutation.mutate()}
            >
              保存排序
            </Button>
          )}
        </Space>
      }
    >
      {listQuery.isError ? (
        <QueryErrorAlert error={listQuery.error} message="加载网口清单失败" />
      ) : (
        <>
          <Tabs
            activeKey={currentNode}
            onChange={switchNode}
            items={nodes.map((n) => ({ key: n.node_name, label: n.node_name }))}
          />
          <Table<NodeInterfaceItem>
            rowKey="ifname"
            loading={listQuery.isLoading}
            columns={columns}
            dataSource={rows}
            pagination={false}
            scroll={{ x: 1010 }}
            rowClassName={(record) => (record.present ? '' : 'node-interface-offline')}
            onRow={(record) => ({ onDoubleClick: () => setDetailRecord(record), style: { cursor: 'pointer' } })}
            locale={{ emptyText: '暂无网口数据，请确认网关节点已上报' }}
          />
          <Typography.Paragraph type="secondary" style={{ marginTop: 12, marginBottom: 0, fontSize: 12 }}>
            排序仅用于展示与部署配置引用顺序，不改写操作系统接口名；介质类型依赖宿主机 ethtool 采集，显示「未知」时需在宿主机运行
            ops 脚本补全识别。
          </Typography.Paragraph>
        </>
      )}
      <RecordDetailDrawer
        open={detailRecord !== null}
        title="网口详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </Card>
  )
}
