import { Alert, Modal, Typography } from 'antd'

interface TempPasswordModalProps {
  open: boolean
  password: string | null
  notice?: string
  onClose: () => void
}

/** 临时密码展示弹窗：仅在创建用户/重置密码后显示一次 */
export default function TempPasswordModal({ open, password, notice, onClose }: TempPasswordModalProps) {
  return (
    <Modal
      title="临时密码（仅显示一次）"
      open={open}
      footer={null}
      onCancel={onClose}
      maskClosable={false}
      destroyOnHidden
    >
      <Alert
        type="warning"
        showIcon
        style={{ marginBottom: 16 }}
        message={notice || '请立即复制并妥善保管该临时密码，关闭本窗口后将无法再次查看。用户首次登录后需修改密码。'}
      />
      <Typography.Paragraph
        copyable={password ? { text: password } : false}
        style={{
          fontFamily: 'monospace',
          fontSize: 18,
          textAlign: 'center',
          padding: '12px 0',
          background: '#f5f5f5',
          borderRadius: 6,
          userSelect: 'all',
        }}
      >
        {password}
      </Typography.Paragraph>
    </Modal>
  )
}
