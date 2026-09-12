import { useState } from 'react'
import { Alert, App as AntdApp, Button, Form, Input } from 'antd'
import { ApiError } from '../api/client'
import { authApi } from '../api/auth'
import { useAuthStore } from '../stores/auth'

interface ChangePasswordFormProps {
  onSuccess?: () => void
}

interface FormValues {
  old_password: string
  new_password: string
  confirm_password: string
}

/** 修改密码表单（个人中心与强制改密页共用） */
export default function ChangePasswordForm({ onSuccess }: ChangePasswordFormProps) {
  const { message } = AntdApp.useApp()
  const [form] = Form.useForm<FormValues>()
  const [loading, setLoading] = useState(false)

  const onFinish = async (values: FormValues) => {
    setLoading(true)
    try {
      await authApi.changePassword({
        old_password: values.old_password,
        new_password: values.new_password,
      })
      message.success('密码修改成功，请使用新密码重新登录')
      useAuthStore.getState().reset()
      onSuccess?.()
    } catch (e) {
      if (e instanceof ApiError) {
        if (Array.isArray(e.details) && e.details.length > 0) {
          e.details.forEach((d) => message.error(String(d)))
        } else {
          message.error(e.message)
        }
      } else {
        message.error('密码修改失败，请稍后重试')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <Form form={form} layout="vertical" onFinish={onFinish} style={{ maxWidth: 420 }}>
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        message="密码策略要求"
        description="新密码长度不少于 12 位，须同时包含大写字母、小写字母、数字和特殊字符；不得与用户名相同，且不得与最近使用过的密码重复。具体以系统设置的密码策略为准。"
      />
      <Form.Item
        name="old_password"
        label="当前密码"
        rules={[{ required: true, message: '请输入当前密码' }]}
      >
        <Input.Password placeholder="请输入当前密码" autoComplete="current-password" />
      </Form.Item>
      <Form.Item
        name="new_password"
        label="新密码"
        rules={[{ required: true, message: '请输入新密码' }]}
      >
        <Input.Password placeholder="请输入新密码" autoComplete="new-password" />
      </Form.Item>
      <Form.Item
        name="confirm_password"
        label="确认新密码"
        dependencies={['new_password']}
        rules={[
          { required: true, message: '请再次输入新密码' },
          ({ getFieldValue }) => ({
            validator(_, value: string) {
              if (!value || getFieldValue('new_password') === value) return Promise.resolve()
              return Promise.reject(new Error('两次输入的新密码不一致'))
            },
          }),
        ]}
      >
        <Input.Password placeholder="请再次输入新密码" autoComplete="new-password" />
      </Form.Item>
      <Form.Item>
        <Button type="primary" htmlType="submit" loading={loading}>
          确认修改
        </Button>
      </Form.Item>
    </Form>
  )
}
