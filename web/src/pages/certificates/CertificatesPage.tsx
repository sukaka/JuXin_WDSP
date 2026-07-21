import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Descriptions,
  Drawer,
  Form,
  Input,
  Modal,
  Select,
  Space,
  Table,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { PlusOutlined } from '@ant-design/icons'
import { ApiError } from '../../api/client'
import { applicationsApi } from '../../api/applications'
import { certificatesApi } from '../../api/certificates'
import type { UploadCertificateBody } from '../../api/certificates'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import { CERT_STATUS_META, certRemainingColor, certRemainingDays } from '../../utils/stage3'
import type { CertificateItem } from '../../types'

interface Filters {
  name?: string
  status?: string
}

/** PEM 文本基本格式前端校验（仅做头尾标记检查，真实解析由后端完成） */
function validatePem(value: string, beginPattern: RegExp, label: string): string | null {
  const v = value.trim()
  if (!v) return `请粘贴${label}`
  if (!beginPattern.test(v) || !v.includes('-----END')) return `${label}格式不正确，应为 PEM 文本`
  return null
}

/** 证书详情里的绑定应用列表（按 ID 反查应用名称） */
function BoundApplications({ certId }: { certId: string }) {
  const appsQuery = useQuery({
    queryKey: ['cert-applications', certId],
    queryFn: () => certificatesApi.applications(certId),
  })
  const appListQuery = useQuery({
    queryKey: ['applications', 'all-for-cert'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
    enabled: (appsQuery.data?.count ?? 0) > 0,
  })

  if (appsQuery.isLoading) return <Typography.Text type="secondary">加载中…</Typography.Text>
  if (appsQuery.isError) {
    return (
      <Typography.Text type="danger">
        {appsQuery.error instanceof ApiError ? appsQuery.error.message : '加载失败'}
      </Typography.Text>
    )
  }
  const ids = appsQuery.data?.application_ids ?? []
  if (ids.length === 0) return <Typography.Text type="secondary">未绑定任何应用</Typography.Text>
  const nameOf = (id: string) => {
    const app = (appListQuery.data?.items ?? []).find((a) => a.id === id)
    return app ? `${app.name}（${app.code}）` : id
  }
  return (
    <Space wrap>
      {ids.map((id) => (
        <Tag key={id} color="blue">
          {nameOf(id)}
        </Tag>
      ))}
    </Space>
  )
}

export default function CertificatesPage() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)

  const [filters, setFilters] = useState<Filters>({})
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [uploadOpen, setUploadOpen] = useState(false)
  const [detailId, setDetailId] = useState<string | null>(null)
  const [uploadForm] = Form.useForm<UploadCertificateBody>()

  const listQuery = useQuery({
    queryKey: ['certificates', filters, page, pageSize],
    queryFn: () => certificatesApi.list({ ...filters, page, page_size: pageSize }),
  })

  const detailQuery = useQuery({
    queryKey: ['certificate', detailId],
    queryFn: () => certificatesApi.get(detailId as string),
    enabled: detailId !== null,
  })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['certificates'] })

  const onError = (e: unknown) => {
    if (e instanceof ApiError && e.code === 'RESOURCE_CONFLICT') {
      message.error(e.message || '证书正在使用中，无法执行该操作')
      void invalidate()
      return
    }
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const uploadMutation = useMutation({
    mutationFn: (body: UploadCertificateBody) => certificatesApi.upload(body),
    onSuccess: (data) => {
      setUploadOpen(false)
      uploadForm.resetFields()
      message.success(`证书「${data.name}」上传成功`)
      void invalidate()
    },
    onError,
  })

  const removeMutation = useMutation({
    mutationFn: (id: string) => certificatesApi.remove(id),
    onSuccess: () => {
      message.success('删除成功')
      void invalidate()
    },
    onError,
  })

  const columns: ColumnsType<CertificateItem> = [
    {
      title: '名称',
      dataIndex: 'name',
      width: 180,
      render: (v: string, record) => <a onClick={() => setDetailId(record.id)}>{v}</a>,
    },
    { title: '通用名称(CN)', dataIndex: 'common_name', width: 180 },
    {
      title: '颁发者',
      dataIndex: 'issuer',
      width: 220,
      ellipsis: true,
      render: (v: string) => (
        <Tooltip title={v}>
          <span>{v}</span>
        </Tooltip>
      ),
    },
    {
      title: 'SAN 域名',
      dataIndex: 'san_domains',
      width: 100,
      render: (sans: string[]) =>
        sans && sans.length > 0 ? (
          <Tooltip title={sans.join('\n')}>
            <Tag>{sans.length} 个</Tag>
          </Tooltip>
        ) : (
          '-'
        ),
    },
    {
      title: '到期时间',
      dataIndex: 'not_after',
      width: 170,
      render: (v: string | null) => formatDateTime(v),
    },
    {
      title: '剩余天数',
      key: 'remaining',
      width: 120,
      render: (_, record) => {
        const days = certRemainingDays(record.not_after)
        if (days === null) return '-'
        return (
          <Tag color={certRemainingColor(days)}>
            {days < 0 ? `已过期 ${-days} 天` : `${days} 天`}
          </Tag>
        )
      },
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 110,
      render: (v: string) => <StatusTag value={v} map={CERT_STATUS_META} />,
    },
    {
      title: '使用应用数',
      dataIndex: 'usage_count',
      width: 100,
      align: 'right',
    },
    {
      title: '操作',
      key: 'actions',
      width: 140,
      fixed: 'right',
      render: (_, record) => (
        <Space>
          <Button type="link" size="small" onClick={() => setDetailId(record.id)}>
            详情
          </Button>
          {hasPermission(permissions, 'certificates.delete') && (
            <Button
              type="link"
              size="small"
              danger
              disabled={record.usage_count > 0}
              onClick={() =>
                modal.confirm({
                  title: '删除确认',
                  content: `确定删除证书「${record.name}」吗？删除后不可恢复。`,
                  okButtonProps: { danger: true },
                  onOk: () => removeMutation.mutate(record.id),
                })
              }
            >
              删除
            </Button>
          )}
        </Space>
      ),
    },
  ]

  const detail = detailQuery.data

  return (
    <Card
      title="HTTPS证书"
      extra={
        hasPermission(permissions, 'certificates.create') && (
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setUploadOpen(true)}>
            上传证书
          </Button>
        )
      }
    >
      <Space style={{ marginBottom: 16 }} wrap>
        <Input.Search
          placeholder="搜索名称或 CN"
          allowClear
          style={{ width: 240 }}
          onSearch={(v) => {
            setFilters((f) => ({ ...f, name: v || undefined }))
            setPage(1)
          }}
        />
        <Select
          placeholder="状态"
          allowClear
          style={{ width: 150 }}
          options={[
            { value: 'VALID', label: '有效' },
            { value: 'EXPIRING', label: '即将到期' },
            { value: 'EXPIRED', label: '已过期' },
            { value: 'INVALID', label: '无效' },
          ]}
          onChange={(v) => {
            setFilters((f) => ({ ...f, status: v }))
            setPage(1)
          }}
        />
      </Space>

      {listQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="加载证书列表失败"
          description={listQuery.error instanceof ApiError ? listQuery.error.message : undefined}
        />
      ) : (
        <Table<CertificateItem>
          rowKey="id"
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          scroll={{ x: 1250 }}
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

      <Modal
        title="上传证书"
        open={uploadOpen}
        onCancel={() => setUploadOpen(false)}
        onOk={() => uploadForm.submit()}
        confirmLoading={uploadMutation.isPending}
        width={640}
        destroyOnHidden
      >
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
          message="粘贴 PEM 文本上传，私钥仅用于服务端校验并加密存储，不会在任何接口中返回"
        />
        <Form
          form={uploadForm}
          layout="vertical"
          onFinish={(values) =>
            uploadMutation.mutate({
              name: values.name.trim(),
              cert_pem: values.cert_pem.trim(),
              key_pem: values.key_pem.trim(),
              chain_pem: (values.chain_pem ?? '').trim(),
            })
          }
        >
          <Form.Item
            name="name"
            label="证书名称"
            rules={[
              { required: true, message: '请输入证书名称' },
              { max: 128, message: '不超过 128 个字符' },
            ]}
          >
            <Input placeholder="如 example.com 2026 证书" autoComplete="off" />
          </Form.Item>
          <Form.Item
            name="cert_pem"
            label="证书 PEM（cert_pem）"
            rules={[
              { required: true, message: '请粘贴证书 PEM' },
              {
                validator: (_, v: string) => {
                  if (!v) return Promise.resolve()
                  const err = validatePem(v, /-----BEGIN CERTIFICATE-----/, '证书 PEM')
                  return err ? Promise.reject(new Error(err)) : Promise.resolve()
                },
              },
            ]}
          >
            <Input.TextArea
              rows={5}
              style={{ fontFamily: 'monospace', fontSize: 12 }}
              placeholder="-----BEGIN CERTIFICATE-----&#10;…&#10;-----END CERTIFICATE-----"
            />
          </Form.Item>
          <Form.Item
            name="key_pem"
            label="私钥 PEM（key_pem）"
            rules={[
              { required: true, message: '请粘贴私钥 PEM' },
              {
                validator: (_, v: string) => {
                  if (!v) return Promise.resolve()
                  const err = validatePem(v, /-----BEGIN [A-Z ]*PRIVATE KEY-----/, '私钥 PEM')
                  return err ? Promise.reject(new Error(err)) : Promise.resolve()
                },
              },
            ]}
          >
            <Input.TextArea
              rows={5}
              style={{ fontFamily: 'monospace', fontSize: 12 }}
              placeholder="-----BEGIN PRIVATE KEY-----&#10;…&#10;-----END PRIVATE KEY-----"
            />
          </Form.Item>
          <Form.Item
            name="chain_pem"
            label="证书链 PEM（chain_pem，可选）"
            rules={[
              {
                validator: (_, v: string) => {
                  if (!v || !v.trim()) return Promise.resolve()
                  const err = validatePem(v, /-----BEGIN CERTIFICATE-----/, '证书链 PEM')
                  return err ? Promise.reject(new Error(err)) : Promise.resolve()
                },
              },
            ]}
          >
            <Input.TextArea
              rows={4}
              style={{ fontFamily: 'monospace', fontSize: 12 }}
              placeholder="中间证书/根证书（可选）"
            />
          </Form.Item>
        </Form>
      </Modal>

      <Drawer
        title={detail ? `证书详情：${detail.name}` : '证书详情'}
        open={detailId !== null}
        onClose={() => setDetailId(null)}
        width={640}
      >
        {detailQuery.isLoading && <Typography.Text type="secondary">加载中…</Typography.Text>}
        {detailQuery.isError && (
          <Alert
            type="error"
            showIcon
            message="加载证书详情失败"
            description={detailQuery.error instanceof ApiError ? detailQuery.error.message : undefined}
          />
        )}
        {detail && (
          <Descriptions column={1} size="small" bordered>
            <Descriptions.Item label="名称">{detail.name}</Descriptions.Item>
            <Descriptions.Item label="状态">
              <StatusTag value={detail.status} map={CERT_STATUS_META} />
            </Descriptions.Item>
            <Descriptions.Item label="通用名称(CN)">{detail.common_name}</Descriptions.Item>
            <Descriptions.Item label="主题(Subject)">{detail.subject}</Descriptions.Item>
            <Descriptions.Item label="颁发者(Issuer)">{detail.issuer}</Descriptions.Item>
            <Descriptions.Item label="序列号">{detail.serial_number}</Descriptions.Item>
            <Descriptions.Item label="SAN 域名">
              {detail.san_domains && detail.san_domains.length > 0 ? (
                <Space wrap>
                  {detail.san_domains.map((d) => (
                    <Tag key={d}>{d}</Tag>
                  ))}
                </Space>
              ) : (
                '-'
              )}
            </Descriptions.Item>
            <Descriptions.Item label="有效期">
              {formatDateTime(detail.not_before)} ~ {formatDateTime(detail.not_after)}
              {(() => {
                const days = certRemainingDays(detail.not_after)
                if (days === null) return null
                return (
                  <Tag color={certRemainingColor(days)} style={{ marginLeft: 8 }}>
                    {days < 0 ? `已过期 ${-days} 天` : `剩余 ${days} 天`}
                  </Tag>
                )
              })()}
            </Descriptions.Item>
            <Descriptions.Item label="SHA256 指纹">
              <Typography.Text copyable style={{ fontFamily: 'monospace', fontSize: 12 }}>
                {detail.fingerprint_sha256}
              </Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="公钥算法">
              {detail.public_key_algorithm} {detail.public_key_bits > 0 ? `${detail.public_key_bits} 位` : ''}
            </Descriptions.Item>
            <Descriptions.Item label="签名算法">{detail.signature_algorithm}</Descriptions.Item>
            <Descriptions.Item label="绑定应用">
              <BoundApplications certId={detail.id} />
            </Descriptions.Item>
            <Descriptions.Item label="上传时间">{formatDateTime(detail.created_at)}</Descriptions.Item>
          </Descriptions>
        )}
      </Drawer>
    </Card>
  )
}
