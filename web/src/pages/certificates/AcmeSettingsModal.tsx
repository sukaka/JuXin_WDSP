import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Checkbox,
  Form,
  Input,
  InputNumber,
  Modal,
  Select,
  Space,
  Switch,
  Typography,
} from 'antd'
import { ApiError } from '../../api/client'
import { acmeApi, type UpdateAcmeConfigBody } from '../../api/acme'
import { useAuthStore } from '../../stores/auth'
import { hasPermission } from '../../utils/permission'
import type { AcmeKeyType, AcmeProvider, AcmeTestResult } from '../../types'

interface AcmeSettingsModalProps {
  open: boolean
  onClose: () => void
}

interface AcmeFormValues {
  enabled: boolean
  provider: AcmeProvider
  directory_url: string
  custom_directory_allowlist: string
  email: string
  tos_agreed: boolean
  eab_kid: string
  eab_hmac_key: string
  clear_eab_hmac_key: boolean
  key_type: AcmeKeyType
  renew_before_days: number
  auto_publish: boolean
}

export default function AcmeSettingsModal({ open, onClose }: AcmeSettingsModalProps) {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canUpdate = hasPermission(permissions, 'certificates.update')
  const [form] = Form.useForm<AcmeFormValues>()
  const [testResult, setTestResult] = useState<AcmeTestResult | null>(null)

  const provider = Form.useWatch('provider', form)
  const enabled = Form.useWatch('enabled', form)

  const configQuery = useQuery({
    queryKey: ['acme-config'],
    queryFn: () => acmeApi.getConfig(),
    enabled: open,
  })

  useEffect(() => {
    if (!open || !configQuery.data) return
    const c = configQuery.data
    form.setFieldsValue({
      enabled: c.enabled,
      provider: c.provider,
      directory_url: c.directory_url,
      custom_directory_allowlist: c.custom_directory_allowlist,
      email: c.email,
      tos_agreed: c.tos_agreed,
      eab_kid: c.eab_kid,
      eab_hmac_key: '',
      clear_eab_hmac_key: false,
      key_type: c.key_type || 'EC256',
      renew_before_days: c.renew_before_days || 30,
      auto_publish: c.auto_publish,
    })
    setTestResult(null)
  }, [open, configQuery.data, form])

  const saveMutation = useMutation({
    mutationFn: (body: UpdateAcmeConfigBody) => acmeApi.updateConfig(body),
    onSuccess: () => {
      message.success('自动证书（ACME）配置已保存')
      void queryClient.invalidateQueries({ queryKey: ['acme-config'] })
      void queryClient.invalidateQueries({ queryKey: ['app-auto-ssl'] })
      onClose()
    },
    onError: (e: unknown) => {
      message.error(e instanceof ApiError ? e.message : '保存配置失败')
      if (e instanceof ApiError && e.code === 'RESOURCE_CONFLICT') {
        void queryClient.invalidateQueries({ queryKey: ['acme-config'] })
      }
    },
  })

  const testMutation = useMutation({
    mutationFn: () => {
      const vals = form.getFieldsValue()
      return acmeApi.testConfig({
        provider: vals.provider ?? 'LETSENCRYPT',
        directory_url: (vals.directory_url ?? '').trim(),
        custom_directory_allowlist: (vals.custom_directory_allowlist ?? '').trim(),
      })
    },
    onSuccess: (res) => {
      setTestResult(res)
    },
    onError: (e: unknown) => {
      setTestResult({
        reachable: false,
        directory_url: form.getFieldValue('directory_url') || '',
        latency_ms: 0,
        external_account_required: false,
        message: e instanceof ApiError ? e.message : '目录连通性测试失败',
      })
    },
  })

  const handleFinish = (values: AcmeFormValues) => {
    const version = configQuery.data?.version ?? 1
    saveMutation.mutate({
      enabled: values.enabled,
      provider: values.provider,
      directory_url: (values.directory_url ?? '').trim(),
      custom_directory_allowlist: (values.custom_directory_allowlist ?? '').trim(),
      email: (values.email ?? '').trim(),
      tos_agreed: Boolean(values.tos_agreed),
      eab_kid: (values.eab_kid ?? '').trim(),
      eab_hmac_key: (values.eab_hmac_key ?? '').trim() || undefined,
      clear_eab_hmac_key: Boolean(values.clear_eab_hmac_key),
      key_type: values.key_type,
      renew_before_days: values.renew_before_days,
      auto_publish: values.auto_publish,
      version,
    })
  }

  return (
    <Modal
      title="自动申请与续约 SSL 证书（ACME）全局设置"
      open={open}
      onCancel={onClose}
      width={680}
      destroyOnHidden
      footer={
        <Space>
          {canUpdate && (
            <Button onClick={() => testMutation.mutate()} loading={testMutation.isPending}>
              测试目录连通性
            </Button>
          )}
          <Button onClick={onClose}>取消</Button>
          {canUpdate && (
            <Button type="primary" loading={saveMutation.isPending} onClick={() => form.submit()}>
              保存配置
            </Button>
          )}
        </Space>
      }
    >
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        message="基于 RFC 8555（ACME v2）HTTP-01 自动验证"
        description="开启后，在站点详情「证书绑定」中开启「自动 SSL」的站点若尚未绑定证书将自动申请，证书到期前按设定天数自动续约。HTTP-01 验证要求域名解析至本网关且公网 80 端口可达（不支持泛域名）。"
      />

      {configQuery.isError && (
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 16 }}
          message="加载 ACME 配置失败"
          description={configQuery.error instanceof ApiError ? configQuery.error.message : undefined}
        />
      )}

      {testResult && (
        <Alert
          type={testResult.reachable ? 'success' : 'error'}
          showIcon
          style={{ marginBottom: 16 }}
          message={testResult.reachable ? `连接正常（延迟 ${testResult.latency_ms} ms）` : '目录连通性测试未通过'}
          description={
            <>
              <div>{testResult.message}</div>
              {testResult.reachable && testResult.external_account_required && (
                <div>该 CA 要求外部账户绑定（EAB），请填写下方 EAB KID 与 EAB HMAC 密钥。</div>
              )}
            </>
          }
        />
      )}

      <Form<AcmeFormValues>
        form={form}
        layout="vertical"
        disabled={!canUpdate || configQuery.isLoading}
        onFinish={handleFinish}
      >
        <Form.Item name="enabled" label="启用全局自动证书（ACME）" valuePropName="checked">
          <Switch checkedChildren="已启用" unCheckedChildren="已关闭" />
        </Form.Item>

        <Form.Item name="provider" label="证书颁发机构（CA）" rules={[{ required: true }]}>
          <Select
            options={[
              { value: 'LETSENCRYPT', label: "Let's Encrypt 生产环境（正式受信任证书）" },
              { value: 'LETSENCRYPT_STAGING', label: "Let's Encrypt 测试环境（Staging，联调防限流）" },
              { value: 'CUSTOM', label: '自定义 ACME v2 目录（ZeroSSL / 私有 Step-CA / Pebble）' },
            ]}
          />
        </Form.Item>

        {provider === 'CUSTOM' && (
          <>
            <Form.Item
              name="directory_url"
              label="自定义 ACME 目录地址（HTTPS）"
              rules={[{ required: true, message: '请填写自定义 ACME 目录 URL' }]}
            >
              <Input placeholder="https://acme.zerossl.com/v2/DV90" autoComplete="off" />
            </Form.Item>
            <Form.Item
              name="custom_directory_allowlist"
              label="内网 CA 允许列表（可选，SSRF 防护放行）"
              extra="仅当自定义 CA 部署在内网时填写，支持逗号分隔的 CIDR 或主机名（如 10.0.0.0/8, ca.corp.local）；云元数据网段始终拒绝。"
            >
              <Input placeholder="例如：10.0.0.0/8, step-ca.internal" autoComplete="off" />
            </Form.Item>
          </>
        )}

        <Form.Item
          name="email"
          label="ACME 账户联系邮箱"
          rules={enabled ? [{ required: true, message: '启用时必须填写联系邮箱' }] : []}
          extra="用于向 CA 注册账户及接收紧急证书到期通知。"
        >
          <Input placeholder="ops@example.com" autoComplete="off" />
        </Form.Item>

        <Form.Item
          name="tos_agreed"
          valuePropName="checked"
          rules={[
            {
              validator: (_, checked: boolean) => {
                if (enabled && !checked) {
                  return Promise.reject(new Error('启用自动证书前须同意所选 CA 的服务条款'))
                }
                return Promise.resolve()
              },
            },
          ]}
        >
          <Checkbox>我已阅读并同意所选 ACME CA（如 Let's Encrypt / ZeroSSL）的服务条款</Checkbox>
        </Form.Item>

        <Space style={{ display: 'flex' }} size={16} align="start">
          <Form.Item name="key_type" label="证书私钥算法" style={{ width: 200 }}>
            <Select
              options={[
                { value: 'EC256', label: 'ECDSA P-256（推荐）' },
                { value: 'EC384', label: 'ECDSA P-384' },
                { value: 'RSA2048', label: 'RSA 2048' },
              ]}
            />
          </Form.Item>
          <Form.Item
            name="renew_before_days"
            label="到期前自动续约（天）"
            rules={[{ required: true, type: 'number', min: 7, max: 60, message: '须在 7~60 天之间' }]}
            style={{ width: 200 }}
          >
            <InputNumber min={7} max={60} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item
            name="auto_publish"
            label="签发/续约后自动发布网关"
            valuePropName="checked"
          >
            <Switch checkedChildren="自动发布" unCheckedChildren="手工发布" />
          </Form.Item>
        </Space>

        <Typography.Text strong style={{ display: 'block', marginBottom: 8 }}>
          外部账户绑定 EAB（可选，如 ZeroSSL / 企业私有 CA 需要）
        </Typography.Text>
        <Form.Item name="eab_kid" label="EAB Key ID（KID）">
          <Input placeholder="留空表示不需要 EAB" autoComplete="off" />
        </Form.Item>
        <Form.Item
          name="eab_hmac_key"
          label="EAB HMAC Key（Base64URL，AES-256-GCM 加密存储）"
          extra={
            configQuery.data?.eab_hmac_configured
              ? '当前已安全保存 EAB HMAC 密钥；留空将保持原密钥不变。'
              : undefined
          }
        >
          <Input.Password
            placeholder={
              configQuery.data?.eab_hmac_configured
                ? '已配置（留空保持不变）'
                : '粘贴 CA 提供的 EAB HMAC Key'
            }
            autoComplete="new-password"
          />
        </Form.Item>
        {configQuery.data?.eab_hmac_configured && (
          <Form.Item name="clear_eab_hmac_key" valuePropName="checked">
            <Checkbox>清空已保存的 EAB HMAC 密钥</Checkbox>
          </Form.Item>
        )}
      </Form>
    </Modal>
  )
}
