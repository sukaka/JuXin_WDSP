/** 大屏通用配色与暗色图表基础配置（独立文件，避免组件文件导出常量） */

/** 大屏图表调色板 */
export const BS_COLORS = ['#00e5ff', '#2979ff', '#b388ff', '#69f0ae', '#ffd54f', '#ff8a65', '#ff5252']

/** 暗色坐标轴基础样式 */
export const BS_AXIS_BASE = {
  axisLine: { lineStyle: { color: 'rgba(0, 229, 255, 0.3)' } },
  axisLabel: { color: 'rgba(214, 228, 255, 0.75)' },
  splitLine: { lineStyle: { color: 'rgba(0, 229, 255, 0.1)' } },
} as const

/** 暗色提示框基础样式 */
export const BS_TOOLTIP = {
  backgroundColor: 'rgba(5, 17, 41, 0.92)',
  borderColor: 'rgba(0, 229, 255, 0.4)',
  textStyle: { color: '#d6e4ff' },
} as const
