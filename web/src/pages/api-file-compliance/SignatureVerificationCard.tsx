import { useRef, useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import {
  App as AntdApp,
  Alert,
  Button,
  Card,
  Descriptions,
  Form,
  Input,
  Typography,
  Upload,
} from 'antd'
import { UploadOutlined } from '@ant-design/icons'
import {
  apiFileSignatureApi,
  type ApiFileSignatureVerifyResult,
} from '../../api/apiFileSignature'
import { ApiError } from '../../api/client'
import FileLineagePanel from './FileLineagePanel'

const MAX_OOXML_FILE_BYTES = 2 * 1024 * 1024
const OOXML_EXTENSIONS = ['.docx', '.xlsx', '.pptx']

interface SelectedOOXMLFile {
  name: string
  contentBase64: string
}

function readFileAsBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => {
      if (typeof reader.result !== 'string') {
        reject(new Error('无法读取文件'))
        return
      }
      const separator = reader.result.indexOf(',')
      if (separator < 0) {
        reject(new Error('文件编码失败'))
        return
      }
      resolve(reader.result.slice(separator + 1))
    }
    reader.onerror = () => reject(new Error('无法读取文件'))
    reader.readAsDataURL(file)
  })
}

async function fileContentSHA256(contentBase64: string): Promise<string> {
  if (!globalThis.crypto?.subtle) {
    throw new Error('当前浏览器不支持文件指纹计算')
  }
  const raw = atob(contentBase64)
  const bytes = new Uint8Array(raw.length)
  for (let i = 0; i < raw.length; i++) {
    bytes[i] = raw.charCodeAt(i)
  }
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes)
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, '0'),
  ).join('')
}

export default function SignatureVerificationCard({
  canVerify,
}: {
  canVerify: boolean
}) {
  const { message } = AntdApp.useApp()
  const [selected, setSelected] = useState<SelectedOOXMLFile | null>(null)
  const [reading, setReading] = useState(false)
  const [result, setResult] = useState<ApiFileSignatureVerifyResult | null>(
    null,
  )
  const [lineageHash, setLineageHash] = useState('')
  const verificationInputRef = useRef<SelectedOOXMLFile | null>(null)

  const verifyMutation = useMutation({
    mutationFn: (body: {
      filename: string
      content_format: 'ooxml_zip'
      content_base64: string
      identity_fp?: string
    }) => apiFileSignatureApi.verify(body),
    onSuccess: (data) => {
      const input = verificationInputRef.current
      if (!input) return
      setResult(data)
      setLineageHash('')
      if (!data.valid) return
      void fileContentSHA256(input.contentBase64)
        .then((hash) => {
          if (verificationInputRef.current === input) {
            setLineageHash(hash)
          }
        })
        .catch(() => {
          message.warning('当前浏览器无法计算文件指纹，未执行传输关联查询')
        })
    },
    onError: (error: unknown) => {
      verificationInputRef.current = null
      setResult(null)
      setLineageHash('')
      message.error(error instanceof ApiError ? error.message : '文件验证失败')
    },
  })

  const selectFile = async (file: File) => {
    const extension = file.name.slice(file.name.lastIndexOf('.')).toLowerCase()
    if (!OOXML_EXTENSIONS.includes(extension)) {
      message.error('仅支持 DOCX、XLSX、PPTX 文件')
      return
    }
    if (file.size === 0) {
      message.error('文件不能为空')
      return
    }
    if (file.size > MAX_OOXML_FILE_BYTES) {
      message.error('文件不能超过 2 MiB')
      return
    }
    verificationInputRef.current = null
    setResult(null)
    setLineageHash('')
    setSelected(null)
    setReading(true)
    try {
      const contentBase64 = await readFileAsBase64(file)
      setSelected({ name: file.name, contentBase64 })
    } catch {
      message.error('文件读取失败，请重新选择')
    } finally {
      setReading(false)
    }
  }

  return (
    <Card title="文件签名验证">
      <Typography.Paragraph type="secondary">
        验证由 WDSP 网关在 DOCX、XLSX、PPTX
        下载文件中嵌入的来源与完整性签名。仅检查当前文件，不修改原文件。
      </Typography.Paragraph>
      {!canVerify ? (
        <Alert
          type="warning"
          showIcon
          title="当前账号无文件验证权限（api_data.read）"
        />
      ) : null}
      <Upload.Dragger
        accept={OOXML_EXTENSIONS.join(',')}
        maxCount={1}
        disabled={!canVerify || reading || verifyMutation.isPending}
        beforeUpload={(file) => {
          void selectFile(file)
          return false
        }}
        onRemove={() => {
          verificationInputRef.current = null
          setSelected(null)
          setResult(null)
          setLineageHash('')
        }}
      >
        <p className="ant-upload-drag-icon">
          <UploadOutlined />
        </p>
        <p className="ant-upload-text">点击或拖入待验证的 Office 文件</p>
        <p className="ant-upload-hint">
          支持 DOCX、XLSX、PPTX，单个文件不超过 2 MiB
        </p>
      </Upload.Dragger>
      <Form
        layout="vertical"
        style={{ marginTop: 16 }}
        onFinish={(values: { identity_fp?: string }) => {
          if (!selected) {
            message.warning('请先选择待验证文件')
            return
          }
          verificationInputRef.current = selected
          setResult(null)
          setLineageHash('')
          verifyMutation.mutate({
            filename: selected.name,
            content_format: 'ooxml_zip',
            content_base64: selected.contentBase64,
            identity_fp: values.identity_fp?.trim() || undefined,
          })
        }}
      >
        <Form.Item
          name="identity_fp"
          label="身份指纹（可选）"
          extra="匿名或签名时未绑定身份的文件可留空；如已绑定，须与签名时一致。"
          rules={[{ max: 128, message: '身份指纹不能超过 128 个字符' }]}
        >
          <Input placeholder="签名时绑定的身份指纹" autoComplete="off" />
        </Form.Item>
        <Button
          type="primary"
          htmlType="submit"
          disabled={!canVerify || !selected || reading}
          loading={verifyMutation.isPending}
        >
          验证签名
        </Button>
      </Form>
      {result ? (
        <div style={{ marginTop: 16 }}>
          <Alert
            type={result.valid ? 'success' : 'error'}
            showIcon
            title={
              result.valid
                ? '签名有效，文件完整性与来源校验通过'
                : '签名验证未通过'
            }
            description={result.reason || undefined}
          />
          <Descriptions
            size="small"
            column={1}
            style={{ marginTop: 12 }}
            items={[
              { key: 'kid', label: '密钥版本', children: result.kid || '-' },
              {
                key: 'signed_at',
                label: '签名时间',
                children: result.signed_at || '-',
              },
              {
                key: 'identity_fp_prefix',
                label: '身份指纹前缀',
                children: result.identity_fp_prefix || '-',
              },
            ]}
          />
          {lineageHash ? <FileLineagePanel sha256={lineageHash} /> : null}
        </div>
      ) : null}
    </Card>
  )
}
