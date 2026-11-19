import type { CSSProperties } from 'react'
import { useNavigate } from 'react-router-dom'
import { ArrowRightOutlined } from '@ant-design/icons'
import { useAvailableScreens } from './screens'
import './big-screen.css'

/** 大屏展示大厅：列出当前用户可进入的全部大屏 */
export default function ScreenLobbyPage() {
  const navigate = useNavigate()
  const screens = useAvailableScreens()

  return (
    <div className="bs-lobby">
      <div className="bs-lobby-title">大屏展示中心</div>
      <div className="bs-lobby-subtitle">九章动态安全防护 · 选择一块大屏进入全屏态势监控</div>
      {screens.length === 0 ? (
        <div className="bs-lobby-empty">当前账号没有可访问的大屏，请联系管理员分配相应权限</div>
      ) : (
        <div className="bs-lobby-grid">
          {screens.map((s) => (
            <div
              key={s.id}
              className="bs-lobby-card"
              style={{ '--bs-accent': s.accent, '--bs-accent-glow': s.accentGlow } as CSSProperties}
              onClick={() => navigate(s.path)}
            >
              <div className="bs-lobby-card-icon">{s.icon}</div>
              <div className="bs-lobby-card-title">{s.title}</div>
              <div className="bs-lobby-card-desc">{s.description}</div>
              <div className="bs-lobby-card-enter">
                进入大屏 <ArrowRightOutlined />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
