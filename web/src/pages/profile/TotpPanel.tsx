import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Form,
  Input,
  Modal,
  QRCode,
  Space,
  Steps,
  Tag,
  Typography,
} from 'antd'
import { CopyOutlined, DownloadOutlined, SafetyCertificateOutlined } from '@ant-design/icons'
import { ApiError } from '../../api/client'
import { authApi } from '../../api/auth'
import { useAuthStore } from '../../stores/auth'
import type { TotpSetupData } from '../../types'

interface CodeFormValues {
  code: string
}

/** 双因子认证（TOTP）自助设置：开启（扫码绑定+恢复码+验证启用）与关闭 */
export default function TotpPanel() {
  const { message } = AntdApp.useApp()
  const totpEnabled = useAuthStore((s) => Boolean(s.user?.totp_enabled))
  const updateUser = useAuthStore((s) => s.updateUser)

  const [setup, setSetup] = useState<TotpSetupData | null>(null)
  const [setupOpen, setSetupOpen] = useState(false)
  const [step, setStep] = useState<0 | 1>(0)
  const [disableOpen, setDisableOpen] = useState(false)
  const [enableForm] = Form.useForm<CodeFormValues>()
  const [disableForm] = Form.useForm<CodeFormValues>()

  /** 启用/关闭成功后刷新当前用户状态（totp_enabled） */
  const refreshMe = async () => {
    try {
      const me = await authApi.me()
      updateUser(me.user)
    } catch {
      message.warning('状态刷新失败，请刷新页面查看最新状态')
    }
  }

  const setupMutation = useMutation({
    mutationFn: authApi.totpSetup,
    onSuccess: (data) => {
      setSetup(data)
      setStep(0)
      setSetupOpen(true)
      enableForm.resetFields()
    },
    onError: (e) => message.error(e instanceof ApiError ? e.message : '生成密钥失败，请稍后重试'),
  })

  const enableMutation = useMutation({
    mutationFn: (code: string) => authApi.totpEnable({ code }),
    onSuccess: () => {
      message.success('双因子认证已开启')
      setSetupOpen(false)
      setSetup(null)
      void refreshMe()
    },
    onError: (e) => message.error(e instanceof ApiError ? e.message : '启用失败，请稍后重试'),
  })

  const disableMutation = useMutation({
    mutationFn: (code: string) => authApi.totpDisable({ code }),
    onSuccess: () => {
      message.success('双因子认证已关闭')
      setDisableOpen(false)
      void refreshMe()
    },
    onError: (e) => message.error(e instanceof ApiError ? e.message : '关闭失败，请稍后重试'),
  })

  const copyRecoveryCodes = async () => {
    if (!setup) return
    try {
      await navigator.clipboard.writeText(setup.recovery_codes.join('\n'))
      message.success('恢复码已复制')
    } catch {
      message.error('复制失败，请手动复制或使用下载功能')
    }
  }

  const downloadRecoveryCodes = () => {
    if (!setup) return
    const content = [
      '九章 双因子认证一次性恢复码',
      '每个恢复码仅可使用一次，请妥善保管，泄露等同于账号凭证泄露。',
      '',
      ...setup.recovery_codes,
    ].join('\n')
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'jiuzhang-totp-recovery-codes.txt'
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  }

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Card title="双因子认证（TOTP）">
        <Space direction="vertical" size={12} style={{ width: '100%' }}>
          <div>
            当前状态：{totpEnabled ? <Tag color="green">已开启</Tag> : <Tag>未开启</Tag>}
          </div>
          <Typography.Paragraph type="secondary" style={{ marginBottom: 0 }}>
            开启后，登录时除密码外还需输入令牌 App 显示的 6 位动态验证码（兼容 Google
            Authenticator、谷歌令牌、微软 Authenticator 等标准令牌），并可获得 10
            个一次性恢复码用于令牌丢失时登录。
          </Typography.Paragraph>
          <div>
            {totpEnabled ? (
              <Button danger icon={<SafetyCertificateOutlined />} onClick={() => setDisableOpen(true)}>
                关闭双因子认证
              </Button>
            ) : (
              <Button
                type="primary"
                icon={<SafetyCertificateOutlined />}
                loading={setupMutation.isPending}
                onClick={() => setupMutation.mutate()}
              >
                开启双因子认证
              </Button>
            )}
          </div>
        </Space>
      </Card>

      {/* 开启流程：① 扫码绑定并保存恢复码 → ② 输入动态验证码确认启用 */}
      <Modal
        title="开启双因子认证"
        open={setupOpen}
        footer={null}
        width={560}
        maskClosable={false}
        onCancel={() => {
          setSetupOpen(false)
          setSetup(null)
        }}
        destroyOnHidden
      >
        <Steps
          size="small"
          current={step}
          items={[{ title: '绑定令牌并保存恢复码' }, { title: '验证启用' }]}
          style={{ marginBottom: 20 }}
        />
        {step === 0 && setup && (
          <Space direction="vertical" size={12} style={{ width: '100%' }}>
            <div style={{ textAlign: 'center' }}>
              <QRCode value={setup.otpauth_url} size={180} />
            </div>
            <Typography.Paragraph type="secondary" style={{ textAlign: 'center', marginBottom: 0 }}>
              使用令牌 App 扫码绑定；无法扫码时可手动输入下方密钥
            </Typography.Paragraph>
            <Typography.Paragraph
              copyable={{ text: setup.secret, tooltips: ['复制密钥', '已复制'] }}
              style={{
                fontFamily: 'monospace',
                textAlign: 'center',
                background: '#f5f5f5',
                padding: '8px 0',
                borderRadius: 6,
                userSelect: 'all',
              }}
            >
              {setup.secret}
            </Typography.Paragraph>
            <Alert
              type="warning"
              showIcon
              message="以下恢复码仅显示一次，请立即复制或下载并妥善保存。令牌丢失时可凭恢复码登录。"
            />
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(2, 1fr)',
                gap: '6px 24px',
                fontFamily: 'monospace',
                background: '#fafafa',
                border: '1px solid #f0f0f0',
                padding: 12,
                borderRadius: 6,
              }}
            >
              {setup.recovery_codes.map((code) => (
                <span key={code}>{code}</span>
              ))}
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <Space>
                <Button icon={<CopyOutlined />} onClick={() => void copyRecoveryCodes()}>
                  复制恢复码
                </Button>
                <Button icon={<DownloadOutlined />} onClick={downloadRecoveryCodes}>
                  下载 txt
                </Button>
              </Space>
              <Button type="primary" onClick={() => setStep(1)}>
                下一步
              </Button>
            </div>
          </Space>
        )}
        {step === 1 && (
          <>
            <Alert
              type="info"
              showIcon
              style={{ marginBottom: 16 }}
              message="绑定完成后，输入令牌 App 当前显示的 6 位动态验证码以确认启用。"
            />
            <Form
              form={enableForm}
              layout="vertical"
              onFinish={(values) => enableMutation.mutate(values.code.trim())}
            >
              <Form.Item
                name="code"
                label="动态验证码"
                rules={[
                  { required: true, message: '请输入动态验证码' },
                  { pattern: /^\d{6}$/, message: '动态验证码为 6 位数字' },
                ]}
              >
                <Input placeholder="6 位数字" maxLength={6} autoComplete="one-time-code" />
              </Form.Item>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <Button onClick={() => setStep(0)}>上一步</Button>
                <Button type="primary" htmlType="submit" loading={enableMutation.isPending}>
                  确认启用
                </Button>
              </div>
            </Form>
          </>
        )}
      </Modal>

      {/* 关闭流程：验证动态验证码或恢复码后关闭 */}
      <Modal
        title="关闭双因子认证"
        open={disableOpen}
        onCancel={() => setDisableOpen(false)}
        onOk={() => disableForm.submit()}
        confirmLoading={disableMutation.isPending}
        okButtonProps={{ danger: true }}
        okText="确认关闭"
        maskClosable={false}
        destroyOnHidden
      >
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 16 }}
          message="关闭后登录将不再需要动态验证码，密钥与恢复码将被清除，账号安全性降低。"
        />
        <Form
          form={disableForm}
          layout="vertical"
          onFinish={(values) => disableMutation.mutate(values.code.trim())}
        >
          <Form.Item
            name="code"
            label="动态验证码或恢复码"
            rules={[{ required: true, message: '请输入动态验证码或恢复码' }]}
          >
            <Input placeholder="6 位动态验证码，或 xxxx-xxxx 恢复码" autoComplete="one-time-code" />
          </Form.Item>
        </Form>
      </Modal>
    </Space>
  )
}
