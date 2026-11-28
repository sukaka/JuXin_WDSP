import { useEffect } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Checkbox,
  Drawer,
  Form,
  Input,
  InputNumber,
  Space,
  Spin,
  Switch,
  Tag,
  Typography,
} from 'antd'
import { ApiError } from '../../api/client'
import {
  ipLibrariesApi,
  type UpdateOutboundSettingsBody,
} from '../../api/ipLibraries'
import QueryErrorAlert from '../../components/QueryErrorAlert'

interface OutboundFormValues {
  outbound_allowlist: string
  allow_insecure_http_mirror: boolean
  proxy_url: string
  proxy_auth?: string
  clear_proxy_auth?: boolean
  http_timeout_seconds: number
}

export interface OutboundSettingsDrawerProps {
  open: boolean
  canManage: boolean
  onClose: () => void
}

/**
 * 共用出站代理与内网镜像白名单配置抽屉（GeoIP 与威胁情报共用 ip_library 设置组）。
 * 代理认证凭据严格只写不回显（has_proxy_auth 仅展示状态标签）。
 */
export default function OutboundSettingsDrawer({
  open,
  canManage,
  onClose,
}: OutboundSettingsDrawerProps) {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const [form] = Form.useForm<OutboundFormValues>()

  const settingsQuery = useQuery({
    queryKey: ['ip-libraries', 'outbound-settings'],
    queryFn: () => ipLibrariesApi.getOutboundSettings(),
    enabled: open,
  })

  useEffect(() => {
    if (!open || !settingsQuery.data) return
    form.setFieldsValue({
      outbound_allowlist: settingsQuery.data.outbound_allowlist ?? '',
      allow_insecure_http_mirror: Boolean(settingsQuery.data.allow_insecure_http_mirror),
      proxy_url: settingsQuery.data.proxy_url ?? '',
      proxy_auth: '',
      clear_proxy_auth: false,
      http_timeout_seconds: settingsQuery.data.http_timeout_seconds || 120,
    })
  }, [open, settingsQuery.data, form])

  const saveMutation = useMutation({
    mutationFn: (values: OutboundFormValues) => {
      const body: UpdateOutboundSettingsBody = {
        outbound_allowlist: (values.outbound_allowlist ?? '').trim(),
        allow_insecure_http_mirror: Boolean(values.allow_insecure_http_mirror),
        proxy_url: (values.proxy_url ?? '').trim(),
        http_timeout_seconds: values.http_timeout_seconds ?? 120,
      }
      if (values.clear_proxy_auth) {
        body.clear_proxy_auth = true
      } else if (values.proxy_auth && values.proxy_auth.trim() !== '') {
        body.proxy_auth = values.proxy_auth.trim()
      }
      return ipLibrariesApi.updateOutboundSettings(body)
    },
    onSuccess: () => {
      message.success('出站代理与镜像白名单配置已保存')
      void queryClient.invalidateQueries({ queryKey: ['ip-libraries', 'outbound-settings'] })
      onClose()
    },
    onError: (e: unknown) => {
      message.error(e instanceof ApiError ? e.message : '保存出站设置失败')
    },
  })

  const hasProxyAuth = Boolean(settingsQuery.data?.has_proxy_auth)

  return (
    <Drawer
      title="出站代理与内网镜像白名单"
      open={open}
      width={560}
      destroyOnHidden
      onClose={onClose}
      extra={
        canManage ? (
          <Space>
            <Button onClick={onClose}>取消</Button>
            <Button
              type="primary"
              loading={saveMutation.isPending}
              disabled={settingsQuery.isLoading || settingsQuery.isError}
              onClick={() => form.submit()}
            >
              保存配置
            </Button>
          </Space>
        ) : (
          <Tag>只读</Tag>
        )
      }
    >
      <Space direction="vertical" size="middle" style={{ width: '100%' }}>
        <Alert
          type="info"
          showIcon
          message="出站 SSRF 防护基线"
          description="官方源仅允许硬编码官方域名且强制 HTTPS；自定义内网镜像必须登记至白名单，云元数据地址（如 169.254.169.254）永久硬拦截。纯离线环境无需配置。"
        />

        {settingsQuery.isError && (
          <QueryErrorAlert error={settingsQuery.error} message="加载出站设置失败" />
        )}

        <Spin spinning={settingsQuery.isLoading}>
          <Form<OutboundFormValues>
            form={form}
            layout="vertical"
            disabled={!canManage}
            onFinish={(values) => saveMutation.mutate(values)}
          >
            <Form.Item
              name="outbound_allowlist"
              label="内网镜像出站白名单（CIDR 或精确主机名，逗号分隔）"
              extra="示例：10.20.0.0/16, mirror.corp.local；未命中白名单的私网地址将被 SSRF 防护拦截。"
            >
              <Input.TextArea
                rows={3}
                placeholder="例如：10.20.30.0/24, geoip-mirror.internal"
              />
            </Form.Item>

            <Form.Item
              name="allow_insecure_http_mirror"
              label="允许白名单内网镜像使用明文 HTTP"
              valuePropName="checked"
              extra="仅对命中上方白名单的内网镜像地址生效；公网地址与官方源始终强制 HTTPS。"
            >
              <Switch />
            </Form.Item>

            <Form.Item
              name="proxy_url"
              label="正向代理地址（可选）"
              extra="支持 http:// 或 https://，请勿在 URL 中内嵌用户名和密码（请使用下方独立认证字段）。"
            >
              <Input placeholder="例如：http://proxy.corp.local:3128" />
            </Form.Item>

            <Form.Item
              noStyle
              shouldUpdate={(prev, cur) => prev.clear_proxy_auth !== cur.clear_proxy_auth}
            >
              {({ getFieldValue }) => (
                <Form.Item
                  label={
                    <Space size={8}>
                      <span>代理认证凭据（仅写入，不回显）</span>
                      {hasProxyAuth ? (
                        <Tag color="green">已保存凭据</Tag>
                      ) : (
                        <Tag>未配置</Tag>
                      )}
                    </Space>
                  }
                  name="proxy_auth"
                  extra="格式为 username:password，经系统主密钥加密落库；留空表示保持原有凭据不变。"
                >
                  <Input.Password
                    autoComplete="new-password"
                    disabled={!canManage || Boolean(getFieldValue('clear_proxy_auth'))}
                    placeholder={
                      hasProxyAuth
                        ? '已配置（留空不修改，输入新值覆盖）'
                        : '输入 username:password（无认证可留空）'
                    }
                  />
                </Form.Item>
              )}
            </Form.Item>

            {hasProxyAuth && (
              <Form.Item name="clear_proxy_auth" valuePropName="checked">
                <Checkbox>清除已保存的代理认证凭据</Checkbox>
              </Form.Item>
            )}

            <Form.Item
              name="http_timeout_seconds"
              label="单次出站下载超时（秒）"
              rules={[
                { required: true, message: '请填写超时秒数' },
                {
                  type: 'number',
                  min: 15,
                  max: 600,
                  message: '超时时间范围为 15–600 秒',
                },
              ]}
              extra="大文件（如 MaxMind GeoLite2 City）建议设为 120–300 秒。"
            >
              <InputNumber min={15} max={600} style={{ width: 180 }} addonAfter="秒" />
            </Form.Item>

            {!canManage && (
              <Typography.Text type="secondary">
                当前账号仅具查看权限，如需修改出站代理设置请联系具备 geoip.manage 权限的运维管理员。
              </Typography.Text>
            )}
          </Form>
        </Spin>
      </Space>
    </Drawer>
  )
}
