import { useEffect, useState, type ReactNode } from 'react'
import { Input, Modal, Typography } from 'antd'

export interface PasswordConfirmModalProps {
  open: boolean
  title: string
  /** 风险说明 */
  content: ReactNode
  /** 可选：要求用户输入的确认文字（如「恢复出厂」），输入一致才允许确认 */
  confirmText?: string
  loading?: boolean
  onOk: (password: string) => void
  onCancel: () => void
}

/**
 * 高风险操作密码确认弹窗：必填当前账号密码，可附加确认文字输入。
 * 受控组件，关闭（onCancel / open 变为 false）时清空内部输入状态。
 */
export default function PasswordConfirmModal({
  open,
  title,
  content,
  confirmText,
  loading,
  onOk,
  onCancel,
}: PasswordConfirmModalProps) {
  const [password, setPassword] = useState('')
  const [confirmInput, setConfirmInput] = useState('')

  useEffect(() => {
    if (!open) {
      setPassword('')
      setConfirmInput('')
    }
  }, [open])

  const confirmMatched = !confirmText || confirmInput === confirmText
  const okDisabled = !password || !confirmMatched

  return (
    <Modal
      title={title}
      open={open}
      onCancel={onCancel}
      onOk={() => onOk(password)}
      okText="确认执行"
      cancelText="取消"
      okButtonProps={{ danger: true, disabled: okDisabled }}
      confirmLoading={loading}
      destroyOnHidden
    >
      <Typography.Paragraph type="danger" style={{ marginTop: 8 }}>
        {content}
      </Typography.Paragraph>
      {confirmText && (
        <>
          <Input
            value={confirmInput}
            onChange={(e) => setConfirmInput(e.target.value)}
            placeholder={`请输入「${confirmText}」以确认`}
            style={{ marginBottom: 12 }}
            status={confirmInput && !confirmMatched ? 'error' : ''}
          />
          {confirmInput && !confirmMatched && (
            <Typography.Text type="danger" style={{ display: 'block', marginTop: -8, marginBottom: 12, fontSize: 12 }}>
              请输入「{confirmText}」以确认
            </Typography.Text>
          )}
        </>
      )}
      <Input.Password
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        placeholder="请输入当前账号密码"
        autoComplete="current-password"
      />
    </Modal>
  )
}
