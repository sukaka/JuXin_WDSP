import { useState } from 'react'
import { Alert, Radio, Space, Typography } from 'antd'
import { LockOutlined } from '@ant-design/icons'
import './detailTab.css'

/**
 * Bot 挑战页体验预览（WDSP P1-02 B4，BOT-006 核对的管理页入口）。
 * 静态示意：按网关 botchallenge/render.go 的真实文案与结构以 React 纯文本复刻，
 * 不嵌入、不执行任何真实挑战脚本；实际页面由网关以 CSP nonce + no-store 隔离渲染，
 * 样式/交互以真实浏览器实测为准（本预览只用于核对状态可读性与恢复入口）。
 */

type PreviewState = 'solving' | 'manual' | 'noscript' | 'unavailable'

const STATE_OPTIONS: { value: PreviewState; label: string }[] = [
  { value: 'solving', label: '等待状态（计算中）' },
  { value: 'manual', label: '手动重试（超时/失败可恢复）' },
  { value: 'noscript', label: 'JavaScript 不可用' },
  { value: 'unavailable', label: '服务故障（503）' },
]

/** 与 render.go 一致的用户可见文案（修改网关文案时需同步此处） */
const TEXTS = {
  title: '安全验证',
  solving: '正在完成安全验证，请稍候…',
  manualStatus: '需要手动操作',
  manualReason:
    '计算超时：您的设备未能在时限内完成验证计算。请点击重试，或刷新页面重新开始。',
  retry: '重试',
  noscript:
    '此安全验证需要启用 JavaScript。请在浏览器中启用 JavaScript 后刷新页面重试。',
  unavailableTitle: '服务暂不可用',
  unavailableMsg: '安全验证服务暂时不可用，请稍后重试。',
  requestID: '请求编号：',
}

function ReplicaFrame({ children }: { children: React.ReactNode }) {
  return (
    <div className="jz-detail-browser-frame">
      <div className="jz-detail-browser-bar">
        <span className="jz-detail-browser-dots" aria-hidden="true">
          <span />
          <span />
          <span />
        </span>
        <div className="jz-detail-browser-url">
          <LockOutlined style={{ marginRight: 6, color: '#16a34a' }} />
          https://your-site.example.com/docs
        </div>
      </div>
      <div className="jz-detail-browser-viewport">
        <div className="jz-detail-browser-card">{children}</div>
      </div>
    </div>
  )
}

function ReplicaButton({ children }: { children: React.ReactNode }) {
  return (
    <button
      type="button"
      disabled
      style={{
        fontSize: '0.95em',
        padding: '6px 18px',
        borderRadius: 6,
        border: '1px solid #cbd5e1',
        background: '#f8fafc',
        color: '#334155',
        cursor: 'not-allowed',
      }}
    >
      {children}
    </button>
  )
}

export default function BotChallengePreview() {
  const [state, setState] = useState<PreviewState>('solving')
  return (
    <Space orientation="vertical" size={14} style={{ display: 'flex' }}>
      <Radio.Group
        options={STATE_OPTIONS}
        value={state}
        onChange={(e) => setState(e.target.value as PreviewState)}
        optionType="button"
        buttonStyle="solid"
        size="small"
      />
      <ReplicaFrame>
        <h1 style={{ fontSize: '1.35em', marginTop: 0, marginBottom: 10 }}>
          {TEXTS.title}
        </h1>
        {state === 'solving' && <p role="status">{TEXTS.solving}</p>}
        {state === 'manual' && (
          <>
            <p role="status" style={{ fontWeight: 600 }}>
              {TEXTS.manualStatus}
            </p>
            <p style={{ color: '#475569' }}>{TEXTS.manualReason}</p>
            <Space style={{ marginBottom: 12 }}>
              <ReplicaButton>{TEXTS.retry}</ReplicaButton>
            </Space>
          </>
        )}
        {state === 'noscript' && <p>{TEXTS.noscript}</p>}
        {state === 'unavailable' && (
          <>
            <h1 style={{ fontSize: '1.2em', color: '#b91c1c' }}>
              {TEXTS.unavailableTitle}
            </h1>
            <p>{TEXTS.unavailableMsg}</p>
          </>
        )}
        <p
          style={{
            marginBottom: 0,
            paddingTop: 10,
            borderTop: '1px solid #eef1f7',
            fontSize: 12,
            color: '#64748b',
          }}
        >
          {TEXTS.requestID}
          <code>0192-demo-request-id</code>
        </p>
      </ReplicaFrame>
      <Alert
        type="info"
        showIcon
        title="静态示意，不含真实挑战脚本"
        description="实际页面由网关在响应时渲染：CSP nonce 仅允许第一方脚本、禁止被嵌入、Cache-Control no-store；状态文本以 role=status + aria-live 播报，手动重试按钮自动获得焦点（键盘/读屏可用）；验证通过后最多自动刷新一次，仍被挑战则显示可恢复原因，不会无限循环。完整可读性以 BOT-006 真实浏览器实测为准。"
      />
      <Typography.Paragraph
        type="secondary"
        style={{ fontSize: 12, marginBottom: 0 }}
      >
        合法 API/SDK 等机器客户端不会收到本页面：挑战仅覆盖显式配置路径上的 HTTPS
        GET 浏览器文档导航，其余请求仅观测并记录不适用原因。
      </Typography.Paragraph>
    </Space>
  )
}
