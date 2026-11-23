import { describe, expect, it } from 'vitest'
import {
  API_FINDING_SEVERITY_FILTER_OPTIONS,
  API_FINDING_SEVERITY_META,
  EXPOSURE_CONFIDENCE_META,
  apiAssetValueReasonLabel,
  apiClassificationSourceLabel,
  apiExposureLabel,
  buildDirectoryTree,
  exposureConfidenceLabel,
} from '../stage8'

describe('buildDirectoryTree', () => {
  it('嵌套目录：/test 与 /test/php 组装为父子层级，计数写在节点标题', () => {
    const tree = buildDirectoryTree([
      { directory_path: '/test', endpoint_count: 4 },
      { directory_path: '/test/php', endpoint_count: 2 },
    ])
    expect(tree).toHaveLength(1)
    expect(tree[0].key).toBe('/test')
    expect(tree[0].title).toBe('test (4)')
    expect(tree[0].children).toHaveLength(1)
    expect(tree[0].children?.[0].key).toBe('/test/php')
    expect(tree[0].children?.[0].title).toBe('php (2)')
  })

  it('单段目录：生成顶层节点，key 为全路径', () => {
    const tree = buildDirectoryTree([{ directory_path: '/api', endpoint_count: 7 }])
    expect(tree).toHaveLength(1)
    expect(tree[0].key).toBe('/api')
    expect(tree[0].title).toBe('api (7)')
    expect(tree[0].children).toBeUndefined()
  })

  it("空目录 '' 归到根节点 '/'，'/' 也合并到同一根", () => {
    const tree = buildDirectoryTree([
      { directory_path: '', endpoint_count: 3 },
      { directory_path: '/', endpoint_count: 5 },
      { directory_path: '/api', endpoint_count: 1 },
    ])
    const root = tree.find((n) => n.key === '/')
    expect(root?.title).toBe('/ (5)')
    expect(tree.find((n) => n.key === '/api')?.title).toBe('api (1)')
  })

  it('中间层无独立计数时仅显示段名，且同一父节点不重复挂子节点', () => {
    const tree = buildDirectoryTree([
      { directory_path: '/test/php', endpoint_count: 2 },
      { directory_path: '/test/php/admin', endpoint_count: 1 },
    ])
    expect(tree).toHaveLength(1)
    expect(tree[0].key).toBe('/test')
    expect(tree[0].title).toBe('test')
    expect(tree[0].children).toHaveLength(1)
    expect(tree[0].children?.[0].children).toHaveLength(1)
    expect(tree[0].children?.[0].children?.[0].key).toBe('/test/php/admin')
  })

  it('空列表返回空数组', () => {
    expect(buildDirectoryTree([])).toEqual([])
  })
})

describe('apiExposureLabel', () => {
  it('暴露面枚举翻译为中文', () => {
    expect(apiExposureLabel('INTERNAL')).toBe('内网')
    expect(apiExposureLabel('PARTNER')).toBe('合作方')
    expect(apiExposureLabel('PUBLIC')).toBe('外网')
    expect(apiExposureLabel('UNKNOWN')).toBe('未知')
  })

  it('大小写/空白归一后命中词表', () => {
    expect(apiExposureLabel(' public ')).toBe('外网')
  })

  it('未知取值原样返回，不伪造映射', () => {
    expect(apiExposureLabel('CUSTOM_X')).toBe('CUSTOM_X')
  })
})

describe('apiClassificationSourceLabel', () => {
  it('分类来源枚举翻译为中文', () => {
    expect(apiClassificationSourceLabel('AUTO')).toBe('自动识别')
    expect(apiClassificationSourceLabel('MANUAL')).toBe('人工标记')
    expect(apiClassificationSourceLabel('CONFIG')).toBe('配置判定')
    expect(apiClassificationSourceLabel('TRAFFIC_OBSERVED')).toBe('流量观测')
  })

  it('未知来源原样返回', () => {
    expect(apiClassificationSourceLabel('SOMETHING_ELSE')).toBe('SOMETHING_ELSE')
  })
})

describe('exposureConfidenceLabel / EXPOSURE_CONFIDENCE_META', () => {
  it('评估置信度枚举翻译为中文', () => {
    expect(exposureConfidenceLabel('LOW')).toBe('低')
    expect(exposureConfidenceLabel('MEDIUM')).toBe('中')
    expect(exposureConfidenceLabel('HIGH')).toBe('高')
  })

  it('词表颜色与标签：LOW 蓝 / MEDIUM 橙 / HIGH 绿', () => {
    expect(EXPOSURE_CONFIDENCE_META.LOW).toEqual({ color: 'blue', label: '低' })
    expect(EXPOSURE_CONFIDENCE_META.MEDIUM).toEqual({ color: 'orange', label: '中' })
    expect(EXPOSURE_CONFIDENCE_META.HIGH).toEqual({ color: 'green', label: '高' })
  })

  it('大小写/空白归一后命中词表', () => {
    expect(exposureConfidenceLabel(' high ')).toBe('高')
  })

  it('未知取值原样返回，不伪造映射', () => {
    expect(exposureConfidenceLabel('VERY_HIGH')).toBe('VERY_HIGH')
  })
})

describe('apiAssetValueReasonLabel', () => {
  it('评分理由中的 exposure 枚举键翻译为中文', () => {
    expect(apiAssetValueReasonLabel('exposure=PUBLIC：互联网公开可达')).toBe('暴露面=外网：互联网公开可达')
    expect(apiAssetValueReasonLabel('exposure=PARTNER：对合作方开放')).toBe('暴露面=合作方：对合作方开放')
    expect(apiAssetValueReasonLabel('exposure=INTERNAL：仅内网')).toBe('暴露面=内网：仅内网')
  })

  it('未分类理由的英文键名翻译为中文', () => {
    expect(apiAssetValueReasonLabel('exposure 未分类，按内网与公开之间保守计分')).toBe('暴露面 未分类，按内网与公开之间保守计分')
  })

  it('不含 exposure 键的理由原样返回', () => {
    expect(apiAssetValueReasonLabel('含敏感数据类型')).toBe('含敏感数据类型')
  })
})

describe('API_FINDING_SEVERITY_FILTER_OPTIONS', () => {
  it('排除 NONE，仅包含服务端接受的五个严重级别，同时保留展示元数据', () => {
    expect(API_FINDING_SEVERITY_META.NONE).toEqual({ color: 'default', label: '无' })
    expect(API_FINDING_SEVERITY_FILTER_OPTIONS.map((o) => o.value)).toEqual([
      'CRITICAL',
      'HIGH',
      'MEDIUM',
      'LOW',
      'INFO',
    ])
  })
})
