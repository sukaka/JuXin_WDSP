import { describe, expect, it } from 'vitest'
import { buildDirectoryTree } from '../stage8'

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
