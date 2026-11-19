import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

const disposeMock = vi.fn()
const setOptionMock = vi.fn()
const resizeMock = vi.fn()

vi.mock('echarts/core', () => ({
  use: vi.fn(),
  init: vi.fn(() => ({
    setOption: setOptionMock,
    resize: resizeMock,
    dispose: disposeMock,
  })),
}))

vi.mock('echarts/components', () => ({ TooltipComponent: {} }))
vi.mock('echarts-gl/lib/component/globe', () => ({}))
vi.mock('echarts-gl/lib/chart/lines3D', () => ({}))
vi.mock('echarts-gl/lib/chart/scatter3D', () => ({}))

import GlobeAttackMap from '../components/GlobeAttackMap'

describe('GlobeAttackMap', () => {
  beforeEach(() => {
    disposeMock.mockReset()
    setOptionMock.mockReset()
    resizeMock.mockReset()
    vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue({
      fillStyle: '',
      strokeStyle: '',
      lineWidth: 1,
      fillRect: vi.fn(),
      beginPath: vi.fn(),
      moveTo: vi.fn(),
      lineTo: vi.fn(),
      closePath: vi.fn(),
      fill: vi.fn(),
      stroke: vi.fn(),
    } as unknown as CanvasRenderingContext2D)
    vi.spyOn(HTMLCanvasElement.prototype, 'toDataURL').mockReturnValue('data:image/png;base64,AA==')
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('setOption 抛出异常时优雅降级为不支持 WebGL 提示，不导致整个大屏白屏崩溃', async () => {
    setOptionMock.mockImplementation(() => {
      throw new Error('Invalid expression.')
    })

    render(<GlobeAttackMap routes={[]} />)

    expect(
      await screen.findByText('当前环境不支持 WebGL，无法渲染攻击路线地球'),
    ).toBeInTheDocument()
    expect(setOptionMock).toHaveBeenCalledTimes(1)
    expect(disposeMock).toHaveBeenCalled()
  })
})
