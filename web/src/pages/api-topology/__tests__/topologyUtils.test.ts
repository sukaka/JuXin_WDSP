import { describe, expect, it } from 'vitest'
import type { ApiGraphEdge, ApiTopologyGroup } from '../../../api/apiSecurity'
import {
  ALL_PREFIX_KEY,
  MODULE_VIEW_THRESHOLD,
  ROOT_PREFIX_KEY,
  buildPathPrefixTree,
  buildTopologyGraphOption,
  buildTopologyIndex,
  compactEndpointLabel,
  matchesPathPrefix,
  truncateMiddle,
} from '../topologyUtils'

function makeNode(
  id: string,
  method: string,
  path: string,
  overrides: Partial<ApiTopologyGroup['endpoints'][number]> = {},
) {
  return {
    id,
    endpoint_key: `${method} ${path}`,
    http_method: method,
    normalized_path: path,
    asset_status: 'DISCOVERED',
    learning_status: 'NOT_STARTED',
    hit_count: 10,
    open_findings_count: 0,
    ...overrides,
  }
}

describe('topologyUtils', () => {
  it('truncateMiddle 与 compactEndpointLabel 对长指纹和长路径安全收敛', () => {
    expect(truncateMiddle('')).toBe('-')
    expect(truncateMiddle('short')).toBe('short')
    expect(truncateMiddle('caller-fingerprint-1234567890abcdef', 8, 4)).toBe('caller-f…cdef')

    const longPath = '/admin-api/infra/file/{id}/get/{id}/favicon_264x263_1789992768080.jpg'
    const compact = compactEndpointLabel('GET', longPath, 28)
    expect(compact.length).toBeLessThanOrEqual(28)
    expect(compact.startsWith('GET ')).toBe(true)
  })

  it('buildPathPrefixTree 将单段探测路径归拢至根路径桶，多层路径按二级前缀聚合排序', () => {
    const groups: ApiTopologyGroup[] = [
      {
        application_id: 'app-1',
        application_name: '官网',
        endpoints: [
          makeNode('e1', 'GET', '/'),
          makeNode('e2', 'GET', '/.env'),
          makeNode('e3', 'GET', '/admin'),
          makeNode('e4', 'GET', '/.git'),
          makeNode('e5', 'GET', '/.git/HEAD'),
          makeNode('e6', 'GET', '/admin-api/system/role/page', { open_findings_count: 2 }),
          makeNode('e7', 'GET', '/admin-api/system/dept/simple-list'),
          makeNode('e8', 'GET', '/admin-api/infra/file/{id}/get/{id}/favicon.png'),
          makeNode('e9', 'GET', '/admin-api/health'),
        ],
      },
    ]
    const index = buildTopologyIndex(groups, [])
    const tree = buildPathPrefixTree(index.allEndpoints, index.endpointStats)

    expect(tree.totalCount).toBe(9)
    // /、/.env、/admin 无子路径，全部归拢到 ROOT_PREFIX_KEY；/.git 因为存在 /.git/HEAD 单独成组
    expect(tree.rootEndpointIds.has('e1')).toBe(true)
    expect(tree.rootEndpointIds.has('e2')).toBe(true)
    expect(tree.rootEndpointIds.has('e3')).toBe(true)
    expect(tree.rootEndpointIds.has('e4')).toBe(false)

    // 一级分组按接口数降序：/admin-api (4) > 根路径与单段 (3) > /.git (2)
    expect(tree.nodes.map((n) => [n.key, n.count])).toEqual([
      ['/admin-api', 4],
      [ROOT_PREFIX_KEY, 3],
      ['/.git', 2],
    ])

    const adminNode = tree.nodes[0]
    expect(adminNode.riskEndpointCount).toBe(1)
    expect(adminNode.openFindingsTotal).toBe(2)
    // /admin-api/system (2) 与 /admin-api/infra (有更深路径) 展开为二级节点；单条直属叶子 /admin-api/health 不制造冗余子目录
    expect(adminNode.children.map((c) => [c.key, c.count])).toEqual([
      ['/admin-api/system', 2],
      ['/admin-api/infra', 1],
    ])

    // 路径段边界匹配：/admin 不得误命中 /admin-api/*
    expect(matchesPathPrefix(index.nodeById.get('e6')!, '/admin', tree.rootEndpointIds)).toBe(false)
    expect(matchesPathPrefix(index.nodeById.get('e6')!, '/admin-api', tree.rootEndpointIds)).toBe(true)
    expect(matchesPathPrefix(index.nodeById.get('e6')!, '/admin-api/system', tree.rootEndpointIds)).toBe(true)
    expect(matchesPathPrefix(index.nodeById.get('e3')!, ROOT_PREFIX_KEY, tree.rootEndpointIds)).toBe(true)
  })

  it('buildTopologyGraphOption 在接口数超阈值时收敛为模块聚合拓扑，并在端点视图对路径做 XSS 转义', () => {
    const manyEndpoints = Array.from({ length: MODULE_VIEW_THRESHOLD + 12 }, (_, i) => {
      const mod = i < 20 ? 'admin-api' : 'open-api'
      return makeNode(`ep-${i}`, 'GET', `/${mod}/service-${i % 4}/item-${i}`, {
        hit_count: i + 1,
        open_findings_count: i === 0 ? 1 : 0,
      })
    })
    const edges: ApiGraphEdge[] = [
      {
        id: 'edge-1',
        caller_fingerprint: 'caller-alpha-123456',
        target_endpoint_id: 'ep-0',
        call_count: 42,
        identity_count: 3,
      },
    ]
    const index = buildTopologyIndex(
      [{ application_id: 'app-1', application_name: '官网', endpoints: manyEndpoints }],
      edges,
    )
    const tree = buildPathPrefixTree(index.allEndpoints, index.endpointStats)

    const moduleResult = buildTopologyGraphOption({
      scopeLabel: '官网',
      selectedPrefix: ALL_PREFIX_KEY,
      endpoints: index.allEndpoints,
      edges,
      prefixTree: tree,
      endpointStats: index.endpointStats,
    })
    expect(moduleResult.mode).toBe('module')
    expect(moduleResult.displayedModules).toBe(2)
    expect(moduleResult.displayedCallers).toBe(1)

    // 少量接口场景切换到端点明细视图，验证恶意路径在 tooltip formatter 中被严格转义
    const xssNode = makeNode('xss-1', 'GET', '/search/<img src=x onerror=alert(1)>', {
      endpoint_key: 'GET /search/<img src=x onerror=alert(1)>',
    })
    const smallIndex = buildTopologyIndex(
      [{ application_id: 'app-1', application_name: '官网', endpoints: [xssNode] }],
      [],
    )
    const smallTree = buildPathPrefixTree(smallIndex.allEndpoints, smallIndex.endpointStats)
    const endpointResult = buildTopologyGraphOption({
      scopeLabel: '官网',
      selectedPrefix: ALL_PREFIX_KEY,
      endpoints: smallIndex.allEndpoints,
      edges: [],
      prefixTree: smallTree,
      endpointStats: smallIndex.endpointStats,
    })
    expect(endpointResult.mode).toBe('endpoint')
    const tooltip = endpointResult.option.tooltip as {
      formatter?: (params: unknown) => string
    }
    const html = tooltip.formatter?.({
      dataType: 'node',
      data: {
        kind: 'endpoint',
        endpoint: smallIndex.allEndpoints[0],
        hitCount: 10,
        callCount: 0,
        riskCount: 0,
      },
    })
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;')
    expect(html).not.toContain('<img')
  })
})
