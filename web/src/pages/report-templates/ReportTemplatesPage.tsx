import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Button,
  Card,
  Checkbox,
  Drawer,
  Form,
  Input,
  Space,
  Table,
  Tag,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { PlusOutlined } from '@ant-design/icons'
import { ApiError } from '../../api/client'
import { reportTemplatesApi } from '../../api/reportTemplates'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import { REPORT_SECTION_OPTIONS } from '../../utils/stage6'
import type { ReportTemplateItem } from '../../types'

interface TemplateFormValues {
  name: string
  company_name: string
  product_name: string
  logo_text: string
  header_text: string
  footer_text: string
  report_no_format: string
  prepared_by: string
  reviewed_by: string
  description: string
  /** 表单态为选中章节 key 数组，提交时转换为后端 map[string]bool */
  sections: string[]
}

/** 章节数组 → 后端 sections map（未选中的章节为 false） */
function sectionsToMap(keys: string[]): Record<string, boolean> {
  const map: Record<string, boolean> = {}
  for (const opt of REPORT_SECTION_OPTIONS) map[opt.value] = keys.includes(opt.value)
  return map
}

/** 后端 sections map → 表单态数组（取值为 true 的章节） */
function sectionsFromMap(map: Record<string, boolean> | null): string[] {
  return Object.entries(map ?? {})
    .filter(([, v]) => v)
    .map(([k]) => k)
}

/** 报告模板：列表 + 新建/编辑抽屉（章节开关）；内置模板禁止修改删除 */
export default function ReportTemplatesPage() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'report_templates.manage')

  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [formOpen, setFormOpen] = useState(false)
  const [editing, setEditing] = useState<ReportTemplateItem | null>(null)
  const [form] = Form.useForm<TemplateFormValues>()

  const listQuery = useQuery({
    queryKey: ['report-templates', page, pageSize],
    queryFn: () => reportTemplatesApi.list({ page, page_size: pageSize }),
  })

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: ['report-templates'] })
  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const saveMutation = useMutation({
    mutationFn: (values: TemplateFormValues): Promise<unknown> => {
      const body = { ...values, sections: sectionsToMap(values.sections) }
      if (editing) {
        return reportTemplatesApi.update(editing.id, body)
      }
      return reportTemplatesApi.create(body)
    },
    onSuccess: () => {
      message.success(editing ? '模板已更新' : '模板已创建')
      setFormOpen(false)
      setEditing(null)
      form.resetFields()
      invalidate()
    },
    onError,
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => reportTemplatesApi.remove(id),
    onSuccess: () => {
      message.success('模板已删除')
      invalidate()
    },
    onError,
  })

  const openCreate = () => {
    setEditing(null)
    form.resetFields()
    setFormOpen(true)
  }

  const openEdit = (record: ReportTemplateItem) => {
    if (record.is_builtin) {
      message.warning('内置模板不可修改，可复制后另行创建')
      return
    }
    setEditing(record)
    form.setFieldsValue({
      name: record.name,
      company_name: record.company_name,
      product_name: record.product_name,
      logo_text: record.logo_text,
      header_text: record.header_text,
      footer_text: record.footer_text,
      report_no_format: record.report_no_format,
      prepared_by: record.prepared_by,
      reviewed_by: record.reviewed_by,
      description: record.description,
      sections: sectionsFromMap(record.sections),
    })
    setFormOpen(true)
  }

  const confirmDelete = (record: ReportTemplateItem) => {
    if (record.is_builtin) {
      message.warning('内置模板不可删除')
      return
    }
    modal.confirm({
      title: '删除确认',
      content: `确定删除报告模板「${record.name}」吗？已生成的报告不受影响。`,
      okButtonProps: { danger: true },
      onOk: () => deleteMutation.mutate(record.id),
    })
  }

  const columns: ColumnsType<ReportTemplateItem> = [
    {
      title: '模板名称',
      dataIndex: 'name',
      width: 180,
      render: (v: string, record) => (
        <Space size={4}>
          {v}
          {record.is_builtin && <Tag color="blue">内置</Tag>}
        </Space>
      ),
    },
    { title: '企业名称', dataIndex: 'company_name', width: 180, ellipsis: true },
    { title: '产品名称', dataIndex: 'product_name', width: 180, ellipsis: true },
    { title: '编号格式', dataIndex: 'report_no_format', width: 160, ellipsis: true },
    { title: '编制人', dataIndex: 'prepared_by', width: 100 },
    { title: '审核人', dataIndex: 'reviewed_by', width: 100 },
    {
      title: '更新时间',
      dataIndex: 'updated_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 140,
      fixed: 'right',
      render: (_, record) =>
        canManage ? (
          <Space size={0}>
            <Button type="link" size="small" disabled={record.is_builtin} onClick={() => openEdit(record)}>
              编辑
            </Button>
            <Button type="link" size="small" danger disabled={record.is_builtin} onClick={() => confirmDelete(record)}>
              删除
            </Button>
          </Space>
        ) : null,
    },
  ]

  return (
    <Card
      title="报告模板"
      extra={
        canManage && (
          <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>
            新建模板
          </Button>
        )
      }
    >
      {listQuery.isError ? (
        <QueryErrorAlert error={listQuery.error} message="加载报告模板失败" />
      ) : (
        <Table<ReportTemplateItem>
          rowKey="id"
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
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

      <Drawer
        title={editing ? '编辑模板' : '新建模板'}
        open={formOpen}
        onClose={() => {
          setFormOpen(false)
          setEditing(null)
        }}
        width={560}
        destroyOnHidden
        footer={
          <Space style={{ display: 'flex', justifyContent: 'flex-end' }}>
            <Button onClick={() => setFormOpen(false)}>取消</Button>
            <Button type="primary" loading={saveMutation.isPending} onClick={() => form.submit()}>
              {editing ? '保存' : '创建'}
            </Button>
          </Space>
        }
      >
        <Form<TemplateFormValues>
          form={form}
          layout="vertical"
          initialValues={{ sections: REPORT_SECTION_OPTIONS.map((s) => s.value) }}
          onFinish={(values) => saveMutation.mutate(values)}
        >
          <Form.Item name="name" label="模板名称" rules={[{ required: true, message: '请输入模板名称' }, { max: 100 }]}>
            <Input placeholder="如：月度安全运营报告模板" />
          </Form.Item>
          <Form.Item name="company_name" label="企业名称" rules={[{ required: true, message: '请输入企业名称' }, { max: 200 }]}>
            <Input placeholder="报告封面展示的企业名称" />
          </Form.Item>
          <Form.Item name="product_name" label="产品名称" rules={[{ required: true, message: '请输入产品名称' }, { max: 200 }]}>
            <Input placeholder="如：九章WEB应用智能防护系统" />
          </Form.Item>
          <Form.Item name="logo_text" label="标识文字" rules={[{ max: 50 }]}>
            <Input placeholder="以文字形式展示的标识（不加载外部图片）" />
          </Form.Item>
          <Form.Item name="header_text" label="页眉" rules={[{ max: 200 }]}>
            <Input placeholder="每页页眉文字（可选）" />
          </Form.Item>
          <Form.Item name="footer_text" label="页脚" rules={[{ max: 200 }]}>
            <Input placeholder="每页页脚文字（可选）" />
          </Form.Item>
          <Form.Item
            name="report_no_format"
            label="报告编号格式"
            rules={[{ max: 100 }]}
            extra="支持变量：{TYPE} 报告类型、{DATE} 日期、{SEQ} 序号"
          >
            <Input placeholder="如：防护报告-{类型}-{日期}-{序号}" />
          </Form.Item>
          <Form.Item name="prepared_by" label="编制人" rules={[{ max: 50 }]}>
            <Input />
          </Form.Item>
          <Form.Item name="reviewed_by" label="审核人" rules={[{ max: 50 }]}>
            <Input />
          </Form.Item>
          <Form.Item name="description" label="报告说明" rules={[{ max: 500 }]}>
            <Input.TextArea rows={2} placeholder="展示在报告正文前的说明文字" />
          </Form.Item>
          <Form.Item name="sections" label="章节开关" rules={[{ required: true, message: '请至少保留一个章节' }]}>
            <Checkbox.Group options={REPORT_SECTION_OPTIONS} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }} />
          </Form.Item>
        </Form>
      </Drawer>
    </Card>
  )
}
