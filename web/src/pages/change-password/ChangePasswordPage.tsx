import { useNavigate } from 'react-router-dom'
import { Card } from 'antd'
import { SafetyCertificateOutlined } from '@ant-design/icons'
import ChangePasswordForm from '../../components/ChangePasswordForm'
import { SYSTEM_NAME } from '../../constants'

/** 强制修改密码页：首次登录或密码过期时使用 */
export default function ChangePasswordPage() {
  const navigate = useNavigate()
  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'linear-gradient(135deg, #0f2027 0%, #203a43 50%, #2c5364 100%)',
        padding: 24,
      }}
    >
      <Card style={{ width: 480, boxShadow: '0 8px 32px rgba(0,0,0,0.35)' }}>
        <div style={{ textAlign: 'center', marginBottom: 16 }}>
          <SafetyCertificateOutlined style={{ fontSize: 36, color: '#2f54eb' }} />
          <div style={{ fontSize: 18, fontWeight: 600, marginTop: 8 }}>修改密码</div>
          <div style={{ color: '#888', marginTop: 4 }}>
            {SYSTEM_NAME}要求您先修改密码后才能继续使用
          </div>
        </div>
        <ChangePasswordForm onSuccess={() => navigate('/login', { replace: true })} />
      </Card>
    </div>
  )
}
