import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { SnapshotTable } from '../ConfigPublishPage'
import type { BusinessSnapshot } from '../../../types'

describe('SnapshotTable 部署模式展示 (P2-2)', () => {
  it('展示各应用部署模式 Tag（含 TRANSPARENT/MIRROR/ROUTED/REVERSE_PROXY）', () => {
    const snapshot: BusinessSnapshot = {
      apps: [
        { code: 'tproxy-app', mode: 'PROTECT', deployment_mode: 'TRANSPARENT', domains: 2, upstreams: 1 },
        { code: 'mirror-app', mode: 'OBSERVE', deployment_mode: 'MIRROR', domains: 1, upstreams: 0 },
        { code: 'rev-app', mode: 'PROTECT', deployment_mode: 'REVERSE_PROXY', domains: 1, upstreams: 2 },
      ],
    }
    render(<SnapshotTable snapshot={snapshot} />)
    expect(screen.getAllByText('部署模式').length).toBeGreaterThan(0)
    expect(screen.getByText('透明串接')).toBeInTheDocument()
    expect(screen.getByText('镜像')).toBeInTheDocument()
    expect(screen.getByText('反向代理')).toBeInTheDocument()
  })

  it('历史快照缺少 deployment_mode 字段时优雅降级为占位符', () => {
    const legacySnapshot: BusinessSnapshot = {
      apps: [{ code: 'legacy-app', mode: 'PROTECT', domains: 1, upstreams: 1 }],
    }
    render(<SnapshotTable snapshot={legacySnapshot} />)
    expect(screen.getByText('legacy-app')).toBeInTheDocument()
    expect(screen.getByText('-')).toBeInTheDocument()
  })

  it('空快照渲染无应用提示', () => {
    render(<SnapshotTable snapshot={null} />)
    expect(screen.getByText('无应用纳入本次配置')).toBeInTheDocument()
  })
})
