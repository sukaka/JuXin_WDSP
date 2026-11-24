import { useEffect, useState, type ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import { ArrowLeftOutlined } from '@ant-design/icons'
import dayjs from 'dayjs'
import { useAvailableScreens, REFRESH_INTERVAL, type BigScreenDef } from '../screens'
import '../big-screen.css'

function useNow() {
  const [now, setNow] = useState(() => dayjs())
  useEffect(() => {
    const timer = setInterval(() => setNow(dayjs()), 1000)
    return () => clearInterval(timer)
  }, [])
  return now
}

/** 大屏全屏框架：顶部标题栏（返回/标题/时钟/切换）+ 内容区 */
export default function ScreenFrame({
  screen,
  refreshIntervalMs = REFRESH_INTERVAL,
  children,
}: {
  screen: BigScreenDef
  refreshIntervalMs?: number
  children: ReactNode
}) {
  const navigate = useNavigate()
  const now = useNow()
  const screens = useAvailableScreens()

  return (
    <div className="bs-root">
      <div className="bs-header">
        <div className="bs-header-side">
          <button className="bs-back-btn" onClick={() => navigate('/big-screen')}>
            <ArrowLeftOutlined /> 返回大厅
          </button>
        </div>
        <div className="bs-header-title">{screen.title}</div>
        <div className="bs-header-side">
          <span className="bs-refresh-hint">每 {Math.round(refreshIntervalMs / 1000)}s 自动刷新</span>
          <span className="bs-clock">{now.format('YYYY-MM-DD HH:mm:ss')}</span>
        </div>
      </div>
      <div className="bs-body">
        <div className="bs-switcher" style={{ justifyContent: 'center' }}>
          {screens.map((s) => (
            <button
              key={s.id}
              className={`bs-switcher-btn${s.id === screen.id ? ' active' : ''}`}
              onClick={() => s.id !== screen.id && navigate(s.path)}
            >
              {s.title}
            </button>
          ))}
        </div>
        {children}
      </div>
    </div>
  )
}
