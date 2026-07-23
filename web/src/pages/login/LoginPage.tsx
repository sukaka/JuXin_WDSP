import { useCallback, useEffect, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { App as AntdApp, Button, Card, Form, Input, Tooltip } from 'antd'
import { LockOutlined, ReloadOutlined, SafetyCertificateOutlined, UserOutlined } from '@ant-design/icons'
import { ApiError } from '../../api/client'
import { authApi } from '../../api/auth'
import { useAuthStore } from '../../stores/auth'
import { useProductStore } from '../../stores/product'
import { SUPPORT_INFO, SYSTEM_NAME, SYSTEM_VERSION } from '../../constants'
import type { CaptchaData } from '../../types'

interface LoginFormValues {
  username: string
  password: string
  captcha_code?: string
}

export default function LoginPage() {
  const { message } = AntdApp.useApp()
  const navigate = useNavigate()
  const location = useLocation()
  const setSession = useAuthStore((s) => s.setSession)
  const [form] = Form.useForm<LoginFormValues>()
  const [captcha, setCaptcha] = useState<CaptchaData | null>(null)
  const [loading, setLoading] = useState(false)

  const refreshCaptcha = useCallback(async () => {
    try {
      const data = await authApi.captcha()
      setCaptcha(data)
    } catch {
      setCaptcha({ enabled: false })
    }
  }, [])

  useEffect(() => {
    void refreshCaptcha()
  }, [refreshCaptcha])

  const onFinish = async (values: LoginFormValues) => {
    if (loading) return
    setLoading(true)
    try {
      const data = await authApi.login({
        username: values.username,
        password: values.password,
        captcha_id: captcha?.enabled ? captcha.captcha_id : undefined,
        captcha_code: captcha?.enabled ? values.captcha_code : undefined,
      })
      setSession(data.user, data.csrf_token)
      await useProductStore.getState().load()
      message.success('登录成功')
      if (data.user.must_change_password) {
        navigate('/change-password', { replace: true })
        return
      }
      const from = (location.state as { from?: string } | null)?.from
      // from 可能是强制改密页（改密成功跳转登录页时由路由守卫写入），
      // 此时若回跳到 /change-password 会造成"改密后仍被要求改密"的死循环
      const target = from && from !== '/login' && from !== '/change-password' ? from : '/dashboard'
      navigate(target, { replace: true })
    } catch (e) {
      message.error(e instanceof ApiError ? e.message : '登录失败，请稍后重试')
      // 失败：保留用户名、清空密码、刷新验证码
      form.setFieldsValue({ password: '', captcha_code: '' })
      void refreshCaptcha()
    } finally {
      setLoading(false)
    }
  }

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'linear-gradient(135deg, #0f2027 0%, #203a43 50%, #2c5364 100%)',
        padding: 24,
      }}
    >
      <Card style={{ width: 400, boxShadow: '0 8px 32px rgba(0,0,0,0.35)' }}>
        <div style={{ textAlign: 'center', marginBottom: 24 }}>
          <SafetyCertificateOutlined style={{ fontSize: 40, color: '#2f54eb' }} />
          <div style={{ fontSize: 20, fontWeight: 600, marginTop: 8 }}>{SYSTEM_NAME}</div>
          <div style={{ color: '#888', marginTop: 4 }}>{SYSTEM_VERSION} 管理控制台</div>
        </div>
        <Form form={form} onFinish={onFinish} size="large" autoComplete="off">
          <Form.Item name="username" rules={[{ required: true, message: '请输入用户名' }]}>
            <Input prefix={<UserOutlined />} placeholder="用户名" autoComplete="username" />
          </Form.Item>
          <Form.Item name="password" rules={[{ required: true, message: '请输入密码' }]}>
            <Input.Password prefix={<LockOutlined />} placeholder="密码" autoComplete="current-password" />
          </Form.Item>
          {captcha?.enabled && (
            <Form.Item
              name="captcha_code"
              rules={[{ required: true, message: '请输入图形验证码' }]}
              style={{ marginBottom: 12 }}
            >
              <div style={{ display: 'flex', gap: 8 }}>
                <Input placeholder="图形验证码" maxLength={8} />
                <Tooltip title="点击刷新验证码">
                  <img
                    src={captcha.image}
                    alt="验证码"
                    onClick={() => void refreshCaptcha()}
                    style={{ height: 40, borderRadius: 6, cursor: 'pointer', border: '1px solid #d9d9d9' }}
                  />
                </Tooltip>
              </div>
            </Form.Item>
          )}
          <Form.Item style={{ marginBottom: 8, marginTop: 12 }}>
            <Button type="primary" htmlType="submit" block loading={loading} disabled={loading}>
              登 录
            </Button>
          </Form.Item>
        </Form>
        {captcha?.enabled && (
          <div style={{ textAlign: 'right' }}>
            <Button
              type="link"
              size="small"
              icon={<ReloadOutlined />}
              onClick={() => void refreshCaptcha()}
            >
              刷新验证码
            </Button>
          </div>
        )}
      </Card>
      <div style={{ color: 'rgba(255,255,255,0.65)', marginTop: 24, fontSize: 13 }}>{SUPPORT_INFO}</div>
    </div>
  )
}
