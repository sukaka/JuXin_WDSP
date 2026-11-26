import { useMutation } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Col,
  Form,
  Input,
  Modal,
  Radio,
  Row,
  Space,
  Tag,
  Typography,
  Upload,
} from 'antd'
import {
  CheckCircleFilled,
  DeleteOutlined,
  InboxOutlined,
  SwapOutlined,
} from '@ant-design/icons'
import { certificatesApi, type UploadCertificateFilesBody } from '../../api/certificates'
import { ApiError } from '../../api/client'
import { formatBytes } from '../../utils/format'
import { isGMProtocol } from '../../utils/stage3'
import type { CertificateItem, CertificateProtocolType } from '../../types'

export const CERT_FILE_EXTENSIONS = ['.pem', '.crt', '.cer', '.der'] as const
export const KEY_FILE_EXTENSIONS = ['.key', '.pem', '.der'] as const
const PFX_EXTENSIONS = ['.pfx', '.p12'] as const

export const MAX_CERT_FILE_BYTES = 64 * 1024
export const MAX_CHAIN_FILE_BYTES = 128 * 1024

interface UploadFormValues {
  protocol_type: CertificateProtocolType
  name: string
  cert_file?: File | null
  key_file?: File | null
  enc_cert_file?: File | null
  enc_key_file?: File | null
  chain_file?: File | null
}

function hasExtension(filename: string, allowed: readonly string[]): boolean {
  const lower = filename.trim().toLowerCase()
  return allowed.some((ext) => lower.endsWith(ext))
}

function suggestCertName(filename: string): string {
  const trimmed = filename.trim()
  const lower = trimmed.toLowerCase()
  for (const ext of CERT_FILE_EXTENSIONS) {
    if (lower.endsWith(ext)) {
      return trimmed.slice(0, trimmed.length - ext.length).slice(0, 128)
    }
  }
  return trimmed.slice(0, 128)
}

interface CertFileFieldProps {
  id?: string
  value?: File | null
  onChange?: (file: File | null) => void
  allowedExtensions: readonly string[]
  maxBytes: number
  placeholder: string
  hint: string
  disabled?: boolean
  onSelectValidFile?: (file: File) => void
}

function CertFileField({
  id,
  value,
  onChange,
  allowedExtensions,
  maxBytes,
  placeholder,
  hint,
  disabled,
  onSelectValidFile,
}: CertFileFieldProps) {
  const { message } = AntdApp.useApp()
  const accept = allowedExtensions.join(',')

  const handleBeforeUpload = (file: File) => {
    if (hasExtension(file.name, PFX_EXTENSIONS)) {
      message.error('暂不支持 PFX/P12 打包格式，请先导出证书与私钥文件后再上传')
      return Upload.LIST_IGNORE
    }
    if (!hasExtension(file.name, allowedExtensions)) {
      message.error(`不支持的文件格式，仅支持 ${allowedExtensions.join(' / ')}`)
      return Upload.LIST_IGNORE
    }
    if (file.size === 0) {
      message.error('文件内容不能为空')
      return Upload.LIST_IGNORE
    }
    if (file.size > maxBytes) {
      message.error(`文件大小不能超过 ${Math.round(maxBytes / 1024)} KB`)
      return Upload.LIST_IGNORE
    }
    onChange?.(file)
    onSelectValidFile?.(file)
    return false
  }

  if (value) {
    return (
      <div
        style={{
          padding: '10px 12px',
          border: '1px solid #b7eb8f',
          background: '#f6ffed',
          borderRadius: 8,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 8,
          minHeight: 68,
        }}
      >
        <Space size={8} style={{ minWidth: 0, flex: 1 }}>
          <CheckCircleFilled style={{ color: '#52c41a', fontSize: 16, flexShrink: 0 }} />
          <div style={{ minWidth: 0, flex: 1 }}>
            <Typography.Text
              strong
              ellipsis={{ tooltip: value.name }}
              style={{ display: 'block', lineHeight: 1.4 }}
            >
              {value.name}
            </Typography.Text>
            <Tag style={{ marginTop: 4, marginInlineEnd: 0 }}>{formatBytes(value.size)}</Tag>
          </div>
        </Space>
        <Space size={0} style={{ flexShrink: 0 }}>
          <Upload
            id={id}
            accept={accept}
            maxCount={1}
            showUploadList={false}
            disabled={disabled}
            beforeUpload={handleBeforeUpload}
          >
            <Button type="link" size="small" icon={<SwapOutlined />} disabled={disabled}>
              更换
            </Button>
          </Upload>
          <Button
            type="link"
            size="small"
            danger
            icon={<DeleteOutlined />}
            disabled={disabled}
            aria-label={`移除 ${value.name}`}
            onClick={() => onChange?.(null)}
          >
            移除
          </Button>
        </Space>
      </div>
    )
  }

  return (
    <Upload.Dragger
      id={id}
      accept={accept}
      maxCount={1}
      showUploadList={false}
      disabled={disabled}
      beforeUpload={handleBeforeUpload}
      styles={{ root: { padding: 0 } }}
      style={{ padding: '12px 10px' }}
    >
      <p className="ant-upload-drag-icon" style={{ marginBottom: 4 }}>
        <InboxOutlined style={{ fontSize: 24 }} />
      </p>
      <p className="ant-upload-text" style={{ fontSize: 13, marginBottom: 2 }}>
        {placeholder}
      </p>
      <p className="ant-upload-hint" style={{ fontSize: 12, marginBottom: 0 }}>
        {hint}
      </p>
    </Upload.Dragger>
  )
}

interface CertificateUploadModalProps {
  open: boolean
  onClose: () => void
  onSuccess: (cert: CertificateItem) => void
  onConflict?: () => void
}

export default function CertificateUploadModal({
  open,
  onClose,
  onSuccess,
  onConflict,
}: CertificateUploadModalProps) {
  const { message } = AntdApp.useApp()
  const [form] = Form.useForm<UploadFormValues>()
  const protocolType = Form.useWatch('protocol_type', form) ?? 'INTERNATIONAL'
  const isGM = isGMProtocol(protocolType)

  const uploadMutation = useMutation({
    mutationFn: (body: UploadCertificateFilesBody) => certificatesApi.uploadFiles(body),
    onSuccess: (data) => {
      form.resetFields()
      message.success(`证书「${data.name}」上传成功`)
      onSuccess(data)
    },
    onError: (e: unknown) => {
      if (e instanceof ApiError && e.code === 'RESOURCE_CONFLICT') {
        message.error(e.message || '证书名称已存在')
        onConflict?.()
        return
      }
      message.error(e instanceof ApiError ? e.message : '证书上传失败')
    },
  })

  const handleClose = () => {
    form.resetFields()
    onClose()
  }

  const handlePrimaryCertSelected = (file: File) => {
    const currentName = (form.getFieldValue('name') as string | undefined) ?? ''
    if (!currentName.trim()) {
      const suggested = suggestCertName(file.name)
      if (suggested) {
        form.setFieldValue('name', suggested)
      }
    }
  }

  const handleFinish = (values: UploadFormValues) => {
    const proto = values.protocol_type ?? 'INTERNATIONAL'
    if (!values.cert_file || !values.key_file) return
    const payload: UploadCertificateFilesBody = {
      name: values.name.trim(),
      protocol_type: proto,
      cert_file: values.cert_file,
      key_file: values.key_file,
      chain_file: values.chain_file ?? null,
    }
    if (isGMProtocol(proto)) {
      if (!values.enc_cert_file || !values.enc_key_file) return
      payload.enc_cert_file = values.enc_cert_file
      payload.enc_key_file = values.enc_key_file
    }
    uploadMutation.mutate(payload)
  }

  return (
    <Modal
      title="上传证书"
      open={open}
      onCancel={handleClose}
      onOk={() => form.submit()}
      confirmLoading={uploadMutation.isPending}
      width={680}
      destroyOnHidden
    >
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        title={
          isGM
            ? '国密 TLCP 1.1 需同时上传 SM2 签名证书/私钥与加密证书/私钥文件（支持 PEM / DER）；所有私钥仅用于服务端校验并加密存储，不会在任何 API 中返回'
            : '请上传证书与私钥文件（支持 .pem / .crt / .cer / .der / .key），私钥仅用于服务端校验并加密存储，不会在任何 API 中返回'
        }
      />
      <Form<UploadFormValues>
        form={form}
        layout="vertical"
        initialValues={{ protocol_type: 'INTERNATIONAL' }}
        onFinish={handleFinish}
      >
        <Form.Item name="protocol_type" label="协议类型" rules={[{ required: true }]}>
          <Radio.Group
            optionType="button"
            buttonStyle="solid"
            disabled={uploadMutation.isPending}
            onChange={(e) => {
              if (!isGMProtocol(e.target.value as CertificateProtocolType)) {
                form.setFieldsValue({ enc_cert_file: undefined, enc_key_file: undefined })
              }
            }}
          >
            <Radio.Button value="INTERNATIONAL">
              通用协议证书 (RSA/ECDSA/Ed25519)
            </Radio.Button>
            <Radio.Button value="SM_TLCP">
              国密协议双证书 (SM2 签名+加密)
            </Radio.Button>
          </Radio.Group>
        </Form.Item>

        <Form.Item
          name="name"
          label="证书名称"
          rules={[
            { required: true, whitespace: true, message: '请输入证书名称' },
            { max: 128, message: '不超过 128 个字符' },
          ]}
        >
          <Input
            placeholder={
              isGM ? '如 example.com 2026 国密双证书' : '如 example.com 2026 证书（选择文件后自动填充）'
            }
            autoComplete="off"
            disabled={uploadMutation.isPending}
          />
        </Form.Item>

        <Row gutter={16}>
          <Col xs={24} sm={12}>
            <Form.Item
              name="cert_file"
              label={isGM ? '签名证书文件' : '证书文件'}
              rules={[
                { required: true, message: isGM ? '请上传签名证书文件' : '请上传证书文件' },
              ]}
            >
              <CertFileField
                allowedExtensions={CERT_FILE_EXTENSIONS}
                maxBytes={MAX_CERT_FILE_BYTES}
                placeholder={isGM ? '点击或拖拽签名证书文件' : '点击或拖拽证书文件'}
                hint=".pem / .crt / .cer / .der，≤ 64 KB"
                disabled={uploadMutation.isPending}
                onSelectValidFile={handlePrimaryCertSelected}
              />
            </Form.Item>
          </Col>
          <Col xs={24} sm={12}>
            <Form.Item
              name="key_file"
              label={isGM ? '签名私钥文件' : '私钥文件'}
              rules={[
                { required: true, message: isGM ? '请上传签名私钥文件' : '请上传私钥文件' },
              ]}
            >
              <CertFileField
                allowedExtensions={KEY_FILE_EXTENSIONS}
                maxBytes={MAX_CERT_FILE_BYTES}
                placeholder={isGM ? '点击或拖拽签名私钥文件' : '点击或拖拽私钥文件'}
                hint=".key / .pem / .der，≤ 64 KB"
                disabled={uploadMutation.isPending}
              />
            </Form.Item>
          </Col>
        </Row>

        {isGM && (
          <Row gutter={16}>
            <Col xs={24} sm={12}>
              <Form.Item
                name="enc_cert_file"
                label="加密证书文件"
                rules={[{ required: true, message: '请上传加密证书文件' }]}
              >
                <CertFileField
                  allowedExtensions={CERT_FILE_EXTENSIONS}
                  maxBytes={MAX_CERT_FILE_BYTES}
                  placeholder="点击或拖拽加密证书文件"
                  hint="SM2 加密证书（.pem / .crt / .cer / .der，≤ 64 KB）"
                  disabled={uploadMutation.isPending}
                />
              </Form.Item>
            </Col>
            <Col xs={24} sm={12}>
              <Form.Item
                name="enc_key_file"
                label="加密私钥文件"
                rules={[{ required: true, message: '请上传加密私钥文件' }]}
              >
                <CertFileField
                  allowedExtensions={KEY_FILE_EXTENSIONS}
                  maxBytes={MAX_CERT_FILE_BYTES}
                  placeholder="点击或拖拽加密私钥文件"
                  hint="SM2 加密私钥（.key / .pem / .der，≤ 64 KB）"
                  disabled={uploadMutation.isPending}
                />
              </Form.Item>
            </Col>
          </Row>
        )}

        <Form.Item name="chain_file" label="证书链文件（可选）">
          <CertFileField
            allowedExtensions={CERT_FILE_EXTENSIONS}
            maxBytes={MAX_CHAIN_FILE_BYTES}
            placeholder="点击或拖拽中间证书 / 根证书链文件（可选）"
            hint=".pem / .crt / .cer / .der，≤ 128 KB；如证书文件已包含完整链可留空"
            disabled={uploadMutation.isPending}
          />
        </Form.Item>
      </Form>
    </Modal>
  )
}
