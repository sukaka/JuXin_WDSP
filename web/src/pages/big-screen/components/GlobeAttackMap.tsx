import { useEffect, useRef, useState } from 'react'
import * as echarts from 'echarts/core'
import { TooltipComponent } from 'echarts/components'
import 'echarts-gl/lib/component/globe'
import 'echarts-gl/lib/chart/lines3D'
import 'echarts-gl/lib/chart/scatter3D'
import { geoEquirectangular, geoPath } from 'd3-geo'
import { getCountryFeatures } from './geoData'
import { escapeHtml, safeCssColor } from '../../../utils/html'

// 本组件使用 tooltip，自行注册组件，不依赖其他模块的注册副作用
echarts.use([TooltipComponent])

/** 一条攻击路线（来源地 → 防护目标） */
export interface GlobeRoute {
  /** 来源地展示名（城市中文名或国家名） */
  name: string
  /** 来源地坐标 [经度, 纬度] */
  from: [number, number]
  /** 攻击事件数（决定光点大小与弧线粗细） */
  count: number
  /** 按最高严重级别映射的颜色 */
  color: string
}

/**
 * 被防护目标（本站点）的经纬度。
 * 大屏展示用的固定标记点，默认北京；部署时可按实际机房位置调整。
 */
const PROTECTED_TARGET: [number, number] = [116.4, 39.9]

const RAD = Math.PI / 180

/** 经纬度 → 单位球面三维向量 */
function toVec(lng: number, lat: number): [number, number, number] {
  const la = lat * RAD
  const lo = lng * RAD
  return [Math.cos(la) * Math.cos(lo), Math.sin(la), Math.cos(la) * Math.sin(lo)]
}

/** 球面三维向量 → 经纬度 */
function toLngLat(v: [number, number, number]): [number, number] {
  return [Math.atan2(v[2], v[0]) / RAD, Math.asin(Math.max(-1, Math.min(1, v[1]))) / RAD]
}

/** 球面线性插值（slerp） */
function slerp(
  a: [number, number, number],
  b: [number, number, number],
  t: number,
): [number, number, number] {
  const dot = Math.max(-1, Math.min(1, a[0] * b[0] + a[1] * b[1] + a[2] * b[2]))
  const theta = Math.acos(dot)
  if (theta < 1e-6) return a
  const s = Math.sin(theta)
  const wa = Math.sin((1 - t) * theta) / s
  const wb = Math.sin(t * theta) / s
  return [a[0] * wa + b[0] * wb, a[1] * wa + b[1] * wb, a[2] * wa + b[2] * wb]
}

/**
 * 生成两点间的飞越弧线（大圆插值 + 正弦高度剖面）。
 * 返回 lines3D 的 coords（[经度, 纬度, 离地高度] 序列），高度随跨度增大。
 */
function makeArc(from: [number, number], to: [number, number], segments = 48): [number, number, number][] {
  const va = toVec(from[0], from[1])
  const vb = toVec(to[0], to[1])
  const dot = Math.max(-1, Math.min(1, va[0] * vb[0] + va[1] * vb[1] + va[2] * vb[2]))
  const angle = Math.acos(dot)
  // 地球半径约 100：短弧峰高 ~3，跨洲长弧 ~11（约为常规高度的 1/3，低弧线风格）
  const peak = 2 + (angle / Math.PI) * 9
  const coords: [number, number, number][] = []
  for (let i = 0; i <= segments; i++) {
    const t = i / segments
    const [lng, lat] = toLngLat(slerp(va, vb, t))
    coords.push([lng, lat, Math.sin(t * Math.PI) * peak])
  }
  return coords
}

let textureUrl: string | null = null

/** 用 Natural Earth 国家面离线绘制地球底图纹理（等距圆柱投影，深海蓝底 + 霓虹描边）。
 *  注意：echarts-gl 对 canvas 形式的 baseTexture 兼容性不稳定（会退化为无贴图白模），
 *  因此导出为 dataURL 图像字符串传入。 */
function getGlobeTexture(): string {
  if (textureUrl) return textureUrl
  const canvas = document.createElement('canvas')
  canvas.width = 2048
  canvas.height = 1024
  const ctx = canvas.getContext('2d')!
  ctx.fillStyle = '#04122b'
  ctx.fillRect(0, 0, canvas.width, canvas.height)
  const projection = geoEquirectangular()
    .translate([canvas.width / 2, canvas.height / 2])
    .scale(canvas.width / (2 * Math.PI))
  const path = geoPath(projection, ctx)
  ctx.beginPath()
  path(getCountryFeatures())
  ctx.fillStyle = 'rgba(22, 64, 112, 0.96)'
  ctx.fill()
  ctx.strokeStyle = 'rgba(0, 229, 255, 0.55)'
  ctx.lineWidth = 1.0
  ctx.stroke()
  textureUrl = canvas.toDataURL('image/png')
  return textureUrl
}

/**
 * 全球攻击路线地球（echarts-gl WebGL）。
 * 攻击路线为离地弧线 + 沿弧流动的光点（方向：来源地 → 本站）；
 * 来源光点抬离球面，背面光点被球体遮挡；悬停显示来源地与次数。
 * 数据更新走 merge 模式，避免轮询重置地球视角。
 */
export default function GlobeAttackMap({
  routes,
  target = PROTECTED_TARGET,
}: {
  routes: GlobeRoute[]
  target?: [number, number]
}) {
  const containerRef = useRef<HTMLDivElement>(null)
  const chartRef = useRef<echarts.ECharts | null>(null)
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    if (!containerRef.current) return
    let chart: echarts.ECharts
    try {
      chart = echarts.init(containerRef.current)
    } catch {
      // 无 WebGL 环境（如部分虚拟化/远程桌面）时降级为提示
      setFailed(true)
      return
    }
    chartRef.current = chart
    chart.setOption({
      tooltip: {
        backgroundColor: 'rgba(5, 17, 41, 0.92)',
        borderColor: 'rgba(0, 229, 255, 0.4)',
        textStyle: { color: '#d6e4ff', fontSize: 12 },
        formatter: (params: { seriesId?: string; data?: { name?: string; count?: number; color?: string } }) => {
          const d = params.data
          if (params.seriesId === 'attack-arcs' && d) {
            return `<span style="color:${safeCssColor(d.color)}">●</span> ${escapeHtml(d.name)} → 本站<br/>攻击事件：${escapeHtml(d.count)} 次`
          }
          if (params.seriesId === 'attack-sources' && d) {
            return `${escapeHtml(d.name)}：${escapeHtml(d.count)} 次`
          }
          if (params.seriesId === 'protected-target') return '本站（被防护目标）'
          return ''
        },
      },
      globe: {
        baseTexture: getGlobeTexture(),
        shading: 'lambert',
        light: { ambient: { intensity: 0.55 }, main: { intensity: 1.4 }, displacementScale: 0 },
        atmosphere: { show: true, offset: 3, color: 'rgba(0, 229, 255, 0.35)' },
        viewControl: {
          autoRotate: true,
          autoRotateSpeed: 9,
          autoRotateAfterStill: 4,
          damping: 0.85,
          distance: 200,
          minDistance: 120,
          maxDistance: 320,
          alpha: 22,
          beta: 150,
          targetCoord: target,
        },
      },
      series: [
        {
          id: 'attack-arcs',
          type: 'lines3D',
          coordinateSystem: 'globe',
          blendMode: 'lighter',
          polyline: true,
          lineStyle: { width: 1.6, opacity: 0.85 },
          // 沿弧从来源地流向本站的流动光点，指示攻击方向
          effect: { show: true, period: 3.5, trailWidth: 3.5, trailLength: 0.35, trailOpacity: 1 },
          data: [],
        },
        {
          id: 'attack-sources',
          type: 'scatter3D',
          coordinateSystem: 'globe',
          // 不透明渲染：球体背面的光点被遮挡，避免透出光晕
          itemStyle: { opacity: 1 },
          symbolSize: 8,
          data: [],
        },
        {
          id: 'protected-target',
          type: 'scatter3D',
          coordinateSystem: 'globe',
          symbol: 'diamond',
          symbolSize: 14,
          itemStyle: { color: '#00e5ff', opacity: 1 },
          data: [],
        },
        {
          // 隐藏参考点：钉住 echarts-gl 高度轴的数据范围（高度轴按 dataMin/dataMax
          // 归一化到 [0, 50] 球面单位），保证光点高度不随数据波动
          id: 'alt-reference',
          type: 'scatter3D',
          coordinateSystem: 'globe',
          silent: true,
          symbolSize: 1,
          itemStyle: { opacity: 0 },
          tooltip: { show: false },
          data: [{ value: [0, -89.9, 0] }, { value: [0, 89.9, 10] }],
        },
      ],
    })
    const observer = new ResizeObserver(() => chart.resize())
    observer.observe(containerRef.current)
    return () => {
      observer.disconnect()
      chart.dispose()
      chartRef.current = null
    }
    // target 在组件生命周期内不变（页面级常量），仅在挂载时初始化
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    const chart = chartRef.current
    if (!chart) return
    chart.setOption(
      {
        series: [
          {
            id: 'attack-arcs',
            data: routes.map((r) => ({
              name: r.name,
              count: r.count,
              color: r.color,
              coords: makeArc(r.from, target),
              lineStyle: { color: r.color, width: Math.min(1.4 + r.count * 0.12, 3) },
              effect: { trailColor: r.color },
            })),
          },
          {
            id: 'attack-sources',
            // 第三维为离地高度：光点悬浮于球面之上，不再贴着地球
            data: routes.map((r) => ({
              name: r.name,
              count: r.count,
              value: [r.from[0], r.from[1], 1],
              itemStyle: { color: r.color },
            })),
            symbolSize: (val: number[]) => Math.min(5 + val[2] * 0.7, 14),
          },
          {
            id: 'protected-target',
            data: [{ value: [target[0], target[1], 2] }],
          },
          {
            id: 'alt-reference',
            data: [{ value: [0, -89.9, 0] }, { value: [0, 89.9, 10] }],
          },
        ],
      },
      { replaceMerge: 'series' },
    )
  }, [routes, target])

  if (failed) {
    return <div className="bs-empty">当前环境不支持 WebGL，无法渲染攻击路线地球</div>
  }
  return <div ref={containerRef} style={{ width: '100%', height: '100%', minHeight: 0, flex: 1 }} />
}
