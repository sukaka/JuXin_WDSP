import { useCallback, useEffect, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { App as AntdApp, Button, Card, Form, Input, Tooltip, Typography } from 'antd'
import {
  KeyOutlined,
  LockOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
  UserOutlined,
} from '@ant-design/icons'
import { ApiError } from '../../api/client'
import { authApi } from '../../api/auth'
import { useAuthStore } from '../../stores/auth'
import { useLicenseStore } from '../../stores/license'
import { useProductStore } from '../../stores/product'
import { filterMenusByRoles } from '../../utils/menu'
import { SUPPORT_INFO, SYSTEM_NAME, SYSTEM_VERSION } from '../../constants'
import type { CaptchaData, LoginResult } from '../../types'

interface LoginFormValues {
  username: string
  password: string
  captcha_code?: string
}

interface TotpFormValues {
  code: string
}

export default function LoginPage() {
  const { message } = AntdApp.useApp()
  const navigate = useNavigate()
  const location = useLocation()
  const setSession = useAuthStore((s) => s.setSession)
  const [form] = Form.useForm<LoginFormValues>()
  const [totpForm] = Form.useForm<TotpFormValues>()
  const [captcha, setCaptcha] = useState<CaptchaData | null>(null)
  const [loading, setLoading] = useState(false)
  // 双因子第二步：challengeToken 非空表示密码已通过、待输入动态令牌/恢复码
  const [challengeToken, setChallengeToken] = useState<string | null>(null)
  const [challengeUser, setChallengeUser] = useState('')
  const [useRecovery, setUseRecovery] = useState(false)

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

  /** 登录成功（含第二步验证通过）的统一收尾：写会话、载产品与授权信息、按来源跳转 */
  const handleLoginSuccess = async (data: LoginResult) => {
    setSession(data.user, data.csrf_token)
    await useProductStore.getState().load()
    await useLicenseStore.getState().load()
    message.success('登录成功')
    if (data.user.must_change_password) {
      navigate('/change-password', { replace: true })
      return
    }
    const from = (location.state as { from?: string } | null)?.from
    // from 可能是强制改密页（改密成功跳转登录页时由路由守卫写入），
    // 此时若回跳到 /change-password 会造成"改密后仍被要求改密"的死循环
    let target = from && from !== '/login' && from !== '/change-password' ? from : '/dashboard'
    // 根路径等同于工作台，不参与可见性预检
    if (target === '/') target = '/dashboard'
    // 账号切换场景：from 属于上一账号有权访问的页面，新账号无权限时会被
    // RequirePermission 直接弹 403（表现为"登录后先看到无权限"）。
    // 按新账号的角色码/权限点/产品能力预检目标页（与菜单、路由守卫同一口径），
    // 不可见则回退工作台。
    if (target !== '/dashboard') {
      const product = useProductStore.getState()
      const visible = filterMenusByRoles(
        data.user.roles.map((r) => r.code),
        data.user.permissions,
        { apiDynamicProtection: product.apiDynamicProtection, webWafEnabled: product.webWafEnabled },
      )
      const canAccess = visible.some((m) => target === m.key || target.startsWith(`${m.key}/`))
      if (!canAccess) {
        target = '/dashboard'
        message.info('目标页面在当前账号下不可用，已为你跳转到工作台')
      }
    }
    navigate(target, { replace: true })
  }

  const onFinish = async (values: LoginFormValues) => {
    if (loading) return
    setLoading(true)
    try {
      const resp = await authApi.login({
        username: values.username,
        password: values.password,
        captcha_id: captcha?.enabled ? captcha.captcha_id : undefined,
        captcha_code: captcha?.enabled ? values.captcha_code : undefined,
      })
      if (resp.code === 'TOTP_REQUIRED') {
        // 密码已通过但该账号开启了双因子认证：进入令牌验证第二步
        setChallengeToken(resp.data.challenge_token)
        setChallengeUser(values.username)
        setUseRecovery(false)
        totpForm.resetFields()
        return
      }
      await handleLoginSuccess(resp.data)
    } catch (e) {
      message.error(e instanceof ApiError ? e.message : '登录失败，请稍后重试')
      // 失败：保留用户名、清空密码、刷新验证码
      form.setFieldsValue({ password: '', captcha_code: '' })
      void refreshCaptcha()
    } finally {
      setLoading(false)
    }
  }

  /** 放弃第二步验证，回到账号密码登录 */
  const backToPassword = () => {
    setChallengeToken(null)
    setChallengeUser('')
    setUseRecovery(false)
    totpForm.resetFields()
    form.setFieldsValue({ password: '', captcha_code: '' })
    void refreshCaptcha()
  }

  const onTotpFinish = async (values: TotpFormValues) => {
    if (loading || !challengeToken) return
    setLoading(true)
    try {
      const data = await authApi.totpVerify({ challenge_token: challengeToken, code: values.code.trim() })
      await handleLoginSuccess(data)
    } catch (e) {
      const err = e instanceof ApiError ? e : null
      message.error(err ? err.message : '验证失败，请稍后重试')
      totpForm.setFieldsValue({ code: '' })
      // 动态令牌错误可沿用当前挑战码重试（连续失败由后端计入账号锁定）；
      // 账号锁定、挑战码失效等其他错误回到密码登录第一步
      if (!err || err.code !== 'TOTP_INVALID') {
        backToPassword()
      }
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
        {challengeToken ? (
          <Form form={totpForm} onFinish={onTotpFinish} size="large" autoComplete="off">
            <Typography.Paragraph type="secondary" style={{ marginBottom: 16 }}>
              账号「{challengeUser}」已开启双因子认证
            </Typography.Paragraph>
            <Form.Item
              name="code"
              rules={
                useRecovery
                  ? [{ required: true, message: '请输入恢复码' }]
                  : [
                      { required: true, message: '请输入动态令牌' },
                      { pattern: /^\d{6}$/, message: '动态令牌为 6 位数字' },
                    ]
              }
            >
              {useRecovery ? (
                <Input
                  prefix={<KeyOutlined />}
                  placeholder="恢复码（格式 xxxx-xxxx）"
                  maxLength={16}
                  autoComplete="off"
                />
              ) : (
                <Input
                  prefix={<SafetyCertificateOutlined />}
                  placeholder="6 位动态令牌"
                  maxLength={6}
                  autoComplete="one-time-code"
                />
              )}
            </Form.Item>
            <Typography.Paragraph type="secondary" style={{ marginTop: -8, fontSize: 13 }}>
              {useRecovery
                ? '请输入开启双因子认证时保存的一次性恢复码'
                : '打开谷歌令牌（Google Authenticator 等令牌 App）查看动态验证码'}
            </Typography.Paragraph>
            <Form.Item style={{ marginBottom: 8 }}>
              <Button type="primary" htmlType="submit" block loading={loading} disabled={loading}>
                验 证
              </Button>
            </Form.Item>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <Button
                type="link"
                size="small"
                style={{ padding: 0 }}
                onClick={() => {
                  setUseRecovery((v) => !v)
                  totpForm.resetFields()
                }}
              >
                {useRecovery ? '使用动态令牌' : '使用恢复码'}
              </Button>
              <Button type="link" size="small" style={{ padding: 0 }} onClick={backToPassword}>
                返回重新登录
              </Button>
            </div>
          </Form>
        ) : (
          <>
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
          </>
        )}
      </Card>
      <div style={{ color: 'rgba(255,255,255,0.65)', marginTop: 24, fontSize: 13 }}>{SUPPORT_INFO}</div>
    </div>
  )
}
