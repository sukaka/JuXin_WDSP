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
  formatApiFindingTitle,
  getApiFindingTypeMeta,
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

describe('formatApiFindingTitle', () => {
  it('生命周期与准入英文标题映射为中文', () => {
    expect(formatApiFindingTitle('endpoint not in known baseline (shadow candidate)')).toBe(
      '接口不在已知基线中（影子 API 候选）',
    )
    expect(formatApiFindingTitle('  DEPRECATED API STILL CALLED  ')).toBe('已下线接口仍被调用')
    expect(formatApiFindingTitle('endpoint not in admission baseline (never discovered)')).toBe(
      '接口不在准入基线中（从未发现的影子 API）',
    )
    expect(formatApiFindingTitle('endpoint in baseline but not confirmed for admission')).toBe(
      '接口已发现但尚未确认准入',
    )
  })

  it('动态模板英文消息格式化为中文', () => {
    expect(formatApiFindingTitle('type mismatch for amount')).toBe('参数 amount 类型不匹配')
    expect(formatApiFindingTitle('graphql admission rejected: introspection')).toBe(
      'GraphQL 准入拒绝：introspection',
    )
    expect(formatApiFindingTitle('graphql budget exceeded: depth (cost=12 budget=8)')).toBe(
      'GraphQL 复杂度预算超限：depth（实际 12，上限 8）',
    )
    expect(
      formatApiFindingTitle('PARSER-DUP-QUERY-001 v1: duplicate query parameter "id" (x3)'),
    ).toBe('检测到重复的查询参数「id」（共 3 次，规则 PARSER-DUP-QUERY-001）')
    expect(
      formatApiFindingTitle(
        'PARSER-FIELD-CAP-001 v1: field count cap reached (query,body), excess fields not parsed',
      ),
    ).toBe('请求字段数量达到解析上限（query,body），超出字段未解析')
  })

  it('已是中文、未知英文或空值按原样/空串处理', () => {
    expect(formatApiFindingTitle('未登记接口 POST /v1/internal/sync')).toBe(
      '未登记接口 POST /v1/internal/sync',
    )
    expect(formatApiFindingTitle('custom detector message')).toBe('custom detector message')
    expect(formatApiFindingTitle('')).toBe('')
    expect(formatApiFindingTitle(null)).toBe('')
  })

  it('补全检测器静态/动态标题、WAF 规则标题与空消息类型码兜底', () => {
    expect(formatApiFindingTitle('request blocked by downstream WAF (coraza interruption)')).toBe(
      '请求已被下游 WAF 引擎阻断',
    )
    expect(formatApiFindingTitle('sensitive value in url query')).toBe('URL 查询参数中检测到敏感数据值')
    expect(formatApiFindingTitle('many distinct object identifiers accessed in a short window')).toBe(
      '短时间内高频访问大量不同对象标识（疑似枚举）',
    )
    expect(formatApiFindingTitle('required companion parameter missing (REQUIRES relation)')).toBe(
      '缺少关联必填参数（REQUIRES 依赖关系违例）',
    )
    expect(formatApiFindingTitle('file compliance rule matched (EXT "exe")')).toBe(
      '命中文件合规规则（扩展名 "exe"）',
    )
    expect(formatApiFindingTitle('graphql admission rejected: DOC_TOO_LARGE')).toBe(
      'GraphQL 准入拒绝：文档体积超限',
    )
    expect(
      formatApiFindingTitle('graphql budget exceeded: GQL_COST_EXCEEDED (cost=120 budget=100)'),
    ).toBe('GraphQL 复杂度预算超限：单请求复杂度超限（实际 120，上限 100）')
    expect(formatApiFindingTitle('grpc frame budget exceeded')).toBe('gRPC 报文帧超出预算上限')
    expect(formatApiFindingTitle('Scanner fingerprint: crawler UA (zgrab)')).toBe(
      '扫描器指纹：爬虫 UA（zgrab）',
    )
    expect(
      formatApiFindingTitle('SQL Injection Attack Detected via libinjection', {
        findingType: 'WAF_942100',
      }),
    ).toBe('通过 libinjection 检测到 SQL 注入攻击')
    expect(
      formatApiFindingTitle('Inbound Anomaly Score Exceeded (Total Score: 5)', {
        findingType: 'WAF_949110',
      }),
    ).toBe('入站异常评分超限（总分：5）')
    expect(
      formatApiFindingTitle('Failed to parse request body.', {
        findingType: 'WAF_200002',
      }),
    ).toBe('请求体解析失败')
    expect(formatApiFindingTitle('WAF_942100')).toBe('通过 libinjection 检测到 SQL 注入攻击')
    expect(formatApiFindingTitle('AUTHZ_BOLA_001')).toBe('对象级越权（BOLA）')
    expect(formatApiFindingTitle('AUTHZ-BFLA-001')).toBe('功能级越权（BFLA）')
    expect(formatApiFindingTitle('MCP_TOOL_NOT_IN_CATALOG')).toBe('MCP 调用未审核目录外工具')
    expect(formatApiFindingTitle('MACHINEID_FAILED')).toBe('机器身份验证失败')
  })
})

describe('getApiFindingTypeMeta 全量风险类型中文化', () => {
  it('精确命中各安全域风险类型并兼容连字符/点号形式', () => {
    expect(getApiFindingTypeMeta('SENSITIVE_IN_QUERY').label).toBe('URL 查询含敏感字段')
    expect(getApiFindingTypeMeta('SENSITIVE_RESPONSE_FIELD').label).toBe('响应含敏感字段名')
    expect(getApiFindingTypeMeta('SERVER_VERSION_DISCLOSURE').label).toBe('服务端版本信息泄露')
    expect(getApiFindingTypeMeta('AUTHZ_BOLA_001').label).toBe('对象级越权（BOLA）')
    expect(getApiFindingTypeMeta('AUTHZ-BFLA-001').label).toBe('功能级越权（BFLA）')
    expect(getApiFindingTypeMeta('FLOW_STEP_SKIP').label).toBe('业务流程跳步执行')
    expect(getApiFindingTypeMeta('FLOWGUARD_VIOLATION').label).toBe('强流程状态违例')
    expect(getApiFindingTypeMeta('MCP_TOOL_NOT_IN_CATALOG').label).toBe('MCP 调用未审核目录外工具')
    expect(getApiFindingTypeMeta('MACHINEID_FAILED').label).toBe('机器身份验证失败')
    expect(getApiFindingTypeMeta('GQL_COST_V1').label).toBe('GraphQL 单请求复杂度超限')
    expect(getApiFindingTypeMeta('GRPCGUARD_BUDGET_EXCEEDED').label).toBe('gRPC 报文帧预算超限')
    expect(getApiFindingTypeMeta('RESPONSE_FAIL_CLOSED').label).toBe('响应安全抑制（故障关闭）')
    expect(getApiFindingTypeMeta('REQUEST_BODY_PRESERVE_SKIPPED').label).toBe('请求体超限跳过检测')
    expect(getApiFindingTypeMeta('WAF_DOWNSTREAM_INTERCEPT').label).toBe('WAF 下游阻断')
    expect(getApiFindingTypeMeta('FILE_BULK_DOWNLOAD').label).toBe('同身份文件批量下载')
    expect(getApiFindingTypeMeta('MIRROR_CAPTURE').label).toBe('镜像流量旁路观测')
  })

  it('动态解析 WAF_<数字规则号> 与新增检测域前缀兜底', () => {
    expect(getApiFindingTypeMeta('WAF_942100').label).toBe('WAF SQL 注入（942100）')
    expect(getApiFindingTypeMeta('WAF_920350').label).toBe('WAF 协议合规（920350）')
    expect(getApiFindingTypeMeta('WAF_1000001').label).toBe('WAF 高危 CVE 防护（1000001）')
    expect(getApiFindingTypeMeta('WAF_200002').label).toBe('WAF 报文解析异常（200002）')
    expect(getApiFindingTypeMeta('WAF_777777').label).toBe('WAF 规则命中（777777）')
    expect(getApiFindingTypeMeta('AUTHZ_FUTURE_RULE').label).toBe('授权安全异常')
    expect(getApiFindingTypeMeta('SENSITIVE_CUSTOM_RULE').label).toBe('敏感数据风险')
    expect(getApiFindingTypeMeta('FLOW_CUSTOM_RULE').label).toBe('业务流程异常')
    expect(getApiFindingTypeMeta('MCP_CUSTOM_RULE').label).toBe('MCP 工具安全告警')
    expect(getApiFindingTypeMeta('GQL_CUSTOM_RULE').label).toBe('GraphQL 安全告警')
  })
})
