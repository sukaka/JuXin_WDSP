import { describe, expect, it } from 'vitest'
import {
  AI_AUDIT_ACTION_LABELS,
  AI_DRAFT_TARGET_TYPE_LABELS,
  AI_MEMORY_SOURCE_LABELS,
  AI_PROMPT_GATE_STATE_META,
  AI_PROMPT_STATUS_META,
  AI_REPORT_FIELD_LABELS,
  AI_TOOL_SOURCE_LABELS,
  API_LIFECYCLE_STATUS_META,
  APM_DIAG_AUDIT_ACTION_LABELS,
  APM_DIAG_STOP_REASON_LABELS,
  APM_ENDPOINT_SPECIAL_LABELS,
  ASSET_VALUE_DIMENSION_LABELS,
  ASSET_VALUE_LEVEL_META,
  AUDIT_ACTION_LABELS,
  AUDIT_MODULE_LABELS,
  AUDIT_OBJECT_TYPE_LABELS,
  AUTHZ_DECISION_META,
  AUTHZ_REASON_CODE_LABELS,
  BACKUP_GROUP_LABELS,
  CLASSIFICATION_ACCESS_LABELS,
  CLASSIFICATION_ACTION_LABELS,
  CLASSIFICATION_DATA_LEVEL_LABELS,
  CLASSIFICATION_DIRECTION_LABELS,
  CLASSIFICATION_DOMAIN_LABELS,
  CLASSIFICATION_LIFECYCLE_LABELS,
  CLASSIFICATION_PURPOSE_LABELS,
  CLIENT_ADDRESS_SOURCE_LABELS,
  COMMON_DETAIL_FIELD_LABELS,
  COMMON_DETAIL_VALUE_LABELS,
  COMPONENT_METRIC_LABELS,
  CONFIDENCE_SOURCE_LABELS,
  CORAZA_VARIABLE_LABELS,
  CREDENTIAL_TYPE_META,
  DATA_FLOW_EVIDENCE_TYPE_LABELS,
  DATA_FLOW_MATCH_LABELS,
  DECISION_REASON_CODE_LABELS,
  DEVICE_TYPE_LABELS,
  DIFF_SUMMARY_KEY_LABELS,
  ENVIRONMENT_LABELS,
  FILE_SENSITIVE_TYPE_LABELS,
  LEARNING_EXCLUDE_REASON_LABELS,
  LLM_RULE_META,
  LOCATION_LABELS,
  MODEL_MATURITY_METRIC_LABELS,
  PARAM_CONSTRAINT_LABELS,
  PCAP_CAPTURE_POINT_LABELS,
  PCAP_MATCH_BASIS_LABELS,
  PCAP_VERIFY_ERROR_LABELS,
  PERMISSION_CODE_LABELS,
  PERMISSION_MODULE_LABELS,
  PRECHECK_NAME_LABELS,
  PRINCIPAL_SOURCE_LABELS,
  PUBLISH_FAILURE_CODE_LABELS,
  REG_FAMILY_LABELS,
  RULEPACK_ALERT_TYPE_LABELS,
  RULEPACK_FAILURE_CODE_LABELS,
  SOURCE_TABLE_LABELS,
  SPEC_FORMAT_LABELS,
  STRONG_FLOW_ACTION_LABELS,
  STRONG_FLOW_REASON_CODE_LABELS,
  STRONG_FLOW_STATUS_SEMANTICS_LABELS,
  UPSTREAM_ERROR_CODE_LABELS,
  formatApmEndpoint,
  formatAuditAction,
  formatAuditModule,
  formatAuditObjectType,
  formatAuthzReasonCode,
  formatAutomationBasis,
  formatEnvironment,
  formatLearningExcludeReason,
  formatLocation,
  formatPermissionModule,
} from '../i18nLabels'
import { APP_STATUS_META } from '../stage3'
import { ATTACK_TYPE_OPTIONS, RULE_SOURCE_META } from '../stage4'
import {
  API_ACTION_META,
  API_COUNTRY_META,
  API_DETECTOR_META,
  API_ENDPOINT_STATUS_META,
  API_FINDING_TYPE_META,
  API_SEMANTIC_TYPE_META,
  API_SENSITIVE_TYPE_META,
  API_VIOLATION_TYPE_META,
  getApiFindingTypeMeta,
} from '../stage8'
import { APM_WAF_ACTION_META, getApmWafActionMeta, parseApmUrlTimeWindow } from '../apm'
import {
  ACK_STATE_META,
  ENFORCEMENT_READINESS_META,
  ENFORCEMENT_VALUE_META,
  EVIDENCE_SOURCE_META,
  UNKNOWN_NEVER_BLOCKS_NOTE,
  buildAuthzConfirmTextV1,
} from '../authzEnforcement'
import {
  BOT_METRIC_SPECS,
  BOT_NODE_SYNC_META,
  formatBotParamOption,
} from '../botPolicy'
import { gateReasonAdvice, previewPublishUsability } from '../securityRegression'
import { KEY_STATUS_META, MACHINE_IDENTITY_MODE_META } from '../machineIdentity'
import { MCP_BINDING_MODE_META, parseArgConstraintsText } from '../mcp'

describe('i18nLabels 核心词表完整性', () => {
  it('资产价值 9 维指标与 4 级元数据完整', () => {
    expect(Object.keys(ASSET_VALUE_DIMENSION_LABELS)).toHaveLength(9)
    expect(ASSET_VALUE_DIMENSION_LABELS.business_sensitivity).toBe('业务敏感度')
    expect(ASSET_VALUE_DIMENSION_LABELS.traffic_scale).toBe('流量规模')
    expect(Object.keys(ASSET_VALUE_LEVEL_META)).toEqual(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
    expect(ASSET_VALUE_LEVEL_META.CRITICAL.label).toBe('极高')
  })

  it('权限模块覆盖全部 36 个后端模块且未知回退原值', () => {
    for (const mod of [
      'access_control',
      'api_protection',
      'apm',
      'ha',
      'license',
      'network_tools',
      'notification',
      'request_pcap',
      'security',
      'traffic',
      'waf_rules',
    ]) {
      expect(PERMISSION_MODULE_LABELS[mod], mod).toBeTruthy()
    }
    expect(formatPermissionModule('api_protection')).toBe('API 动态防护')
    expect(formatPermissionModule('apm')).toBe('应用性能监控')
    expect(formatPermissionModule('big_screen')).toBe('大屏展示')
    expect(formatPermissionModule('unknown_mod')).toBe('unknown_mod')
  })

  it('操作审计模块/动作/对象类型映射及回退', () => {
    expect(AUDIT_MODULE_LABELS.api_authorization).toBe('API 授权防护')
    expect(AUDIT_ACTION_LABELS.publish).toBe('发布')
    expect(AUDIT_OBJECT_TYPE_LABELS.exception_policy).toBe('例外策略')
    expect(formatAuditModule('applications')).toBe('应用管理')
    expect(formatAuditAction('ROLLBACK')).toBe('回滚')
    expect(formatAuditObjectType('backup_job')).toBe('备份任务')
    expect(formatAuditModule('')).toBe('-')
    expect(formatAuditAction('CUSTOM_UNKNOWN_ACTION')).toBe('CUSTOM_UNKNOWN_ACTION')
  })

  it('环境、源站错误码、发布失败码与决策原因码完整', () => {
    expect(ENVIRONMENT_LABELS.prod).toBe('生产')
    expect(formatEnvironment('PRODUCTION')).toBe('生产')
    expect(formatEnvironment('staging')).toBe('预发布')
    expect(formatEnvironment('dev')).toBe('开发')
    expect(formatEnvironment('canary')).toBe('canary')
    expect(Object.keys(UPSTREAM_ERROR_CODE_LABELS)).toHaveLength(13)
    expect(UPSTREAM_ERROR_CODE_LABELS.SSRF_BLOCKED).toBe('SSRF 防护拦截')
    expect(UPSTREAM_ERROR_CODE_LABELS.TLS_CERTIFICATE_ERROR).toBe('TLS 证书校验失败')
    expect(UPSTREAM_ERROR_CODE_LABELS.TLS_HANDSHAKE_FAILED).toBe('TLS 握手失败')
    expect(PUBLISH_FAILURE_CODE_LABELS.REGRESSION_GATE_REJECTED).toBe('安全回归门禁拒绝')
    expect(PUBLISH_FAILURE_CODE_LABELS.FIREWALL_ENSURE_FAILED).toBe('防火墙端口放行失败')
    expect(DECISION_REASON_CODE_LABELS.WAF_INTERCEPT).toBe('WAF 规则拦截')
    expect(DECISION_REASON_CODE_LABELS.L7_RESPONSE_RULE_BLOCK).toBe('L7 响应规则阻断')
  })

  it('授权原因码、决策元数据与主体来源映射正确', () => {
    expect(Object.keys(AUTHZ_REASON_CODE_LABELS).length).toBeGreaterThanOrEqual(13)
    expect(formatAuthzReasonCode('AUTHZ-BOLA-001')).toBe('对象级越权（他人属主）')
    expect(formatAuthzReasonCode('AUTHZ-CLOCK-001')).toBe('节点时钟偏差超限')
    expect(formatAuthzReasonCode('UNKNOWN_CODE')).toBe('UNKNOWN_CODE')
    expect(AUTHZ_DECISION_META.VERIFIED_VIOLATION.label).toBe('实断违规')
    expect(AUTHZ_DECISION_META.UNKNOWN.label).toBe('证据不足')
    expect(PRINCIPAL_SOURCE_LABELS.JWT_VERIFIED).toBe('JWT 可信验证')
    expect(PRINCIPAL_SOURCE_LABELS.MTLS_VERIFIED).toBe('双向 TLS 证书验证')
  })

  it('formatAutomationBasis 正确翻译 stages 与 indicator', () => {
    expect(
      formatAutomationBasis('stages=RECON,DISCOVERY,EXPLOIT;indicator=HEADLESS'),
    ).toBe('命中阶段：侦察、API发现、漏洞利用；指示信号：无头访问')
    expect(formatAutomationBasis('stages=AUTH_PROBE;indicator=URI_ENUMERATION')).toBe(
      '命中阶段：认证探测；指示信号：URI枚举',
    )
    expect(formatAutomationBasis('')).toBe('')
    expect(formatAutomationBasis('custom_raw_note')).toBe('custom_raw_note')
  })

  it('模型成熟度 18 项、Coraza 18 变量、预检 11 项、监控指标与位置词表完整', () => {
    expect(Object.keys(MODEL_MATURITY_METRIC_LABELS)).toHaveLength(18)
    expect(MODEL_MATURITY_METRIC_LABELS.enforced_formal_constraints).toBe('已下发生效约束')
    expect(Object.keys(CORAZA_VARIABLE_LABELS)).toHaveLength(18)
    expect(CORAZA_VARIABLE_LABELS.ARGS_GET).toBe('查询字符串参数')
    expect(Object.keys(PRECHECK_NAME_LABELS)).toHaveLength(11)
    expect(PRECHECK_NAME_LABELS.postgres_reachable).toBe('数据库连接检查')
    expect(COMPONENT_METRIC_LABELS.config_hash).toBe('配置哈希')
    expect(COMPONENT_METRIC_LABELS.software_bypass_enabled).toBe('自动软件旁路开关')
    expect(COMPONENT_METRIC_LABELS.bytes_in_per_second).toBe('入站带宽速率')
    expect(COMPONENT_METRIC_LABELS.bytes_out_per_second).toBe('出站带宽速率')
    expect(COMPONENT_METRIC_LABELS.http_requests_per_second).toBe('每秒 HTTP 请求数')
    expect(COMPONENT_METRIC_LABELS.http_sessions_new_per_second).toBe('每秒新建会话数')
    expect(COMPONENT_METRIC_LABELS.tcp_states).toBe('TCP 连接状态分布')
    expect(COMPONENT_METRIC_LABELS.load1).toBe('1 分钟系统负载')
    expect(COMPONENT_METRIC_LABELS.fd_open).toBe('已打开文件句柄数')
    expect(COMPONENT_METRIC_LABELS.status_2xx_total).toBe('累计 2xx 响应数')
    expect(COMPONENT_METRIC_LABELS.applications).toBe('应用实时负载明细')
    expect(LOCATION_LABELS.query).toBe('查询参数')
    expect(formatLocation('QUERY')).toBe('查询参数')
    expect(formatLocation('response_body')).toBe('响应体')
    expect(PARAM_CONSTRAINT_LABELS.enum_suspected).toBe('疑似枚举')
    expect(API_LIFECYCLE_STATUS_META.ZOMBIE.label).toBe('僵尸接口')
  })

  it('身份凭据/来源表/PCAP/数据流/强流程/LLM/学习排除/文件敏感/备份/回归/AI/APM/分类词表完整', () => {
    expect(SOURCE_TABLE_LABELS.identity_behavior_events).toBe('身份行为事件')
    expect(CREDENTIAL_TYPE_META.MTLS.label).toBe('双向 TLS 证书')
    expect(CONFIDENCE_SOURCE_LABELS['credential:mtls_verified']).toBe('双向 TLS 证书验证')
    expect(DEVICE_TYPE_LABELS.DESKTOP).toBe('桌面设备')
    expect(PCAP_CAPTURE_POINT_LABELS.GATEWAY_EGRESS).toBe('网关出口')
    expect(PCAP_MATCH_BASIS_LABELS.HTTP1_REQUEST_ID).toBe('HTTP/1 请求 ID 匹配')
    expect(PCAP_VERIFY_ERROR_LABELS.INTEGRITY_FAILED).toBe('完整性校验失败')
    expect(DATA_FLOW_EVIDENCE_TYPE_LABELS.OBSERVED_TRACE).toBe('调用链实测观测')
    expect(DATA_FLOW_MATCH_LABELS.OBSERVED).toBe('实测命中')
    expect(CLIENT_ADDRESS_SOURCE_LABELS.TRUSTED_PROXY).toBe('可信代理头')
    expect(STRONG_FLOW_ACTION_LABELS.RESERVE).toBe('步骤预留')
    expect(STRONG_FLOW_STATUS_SEMANTICS_LABELS.UNKNOWN_NOT_CONFIRMED).toBe('未知，不显示安全通过')
    expect(STRONG_FLOW_REASON_CODE_LABELS['FLOW-RESERVE-001']).toBe('步骤预留违规')
    expect(LLM_RULE_META['llm.prompt_injection'].label).toBe('提示词注入')
    expect(LEARNING_EXCLUDE_REASON_LABELS.scanner_traffic).toBe('主动扫描流量')
    expect(formatLearningExcludeReason('response_status_403')).toBe('响应状态码 403')
    expect(formatLearningExcludeReason('response_status_4xx')).toBe('响应状态码 4xx')
    expect(formatLearningExcludeReason('waf_hit')).toBe('命中 WAF 安全规则')
    expect(FILE_SENSITIVE_TYPE_LABELS.id_card).toBe('身份证号')
    expect(Object.keys(BACKUP_GROUP_LABELS)).toHaveLength(6)
    expect(REG_FAMILY_LABELS.sqli).toBe('SQL 注入')
    expect(DIFF_SUMMARY_KEY_LABELS.expected_action).toBe('预期动作')
    expect(SPEC_FORMAT_LABELS.openapi3).toBe('OpenAPI 3.x')
    expect(SPEC_FORMAT_LABELS.protobuf).toBe('Protobuf 描述')
    expect(SPEC_FORMAT_LABELS.wsdl).toBe('WSDL / SOAP')
    expect(SPEC_FORMAT_LABELS.xsd).toBe('XML Schema (XSD)')
    expect(SPEC_FORMAT_LABELS.raml).toBe('RAML')
    expect(SPEC_FORMAT_LABELS.apib).toBe('API Blueprint')
    expect(SPEC_FORMAT_LABELS.har).toBe('HAR 归档')
    expect(SPEC_FORMAT_LABELS.asyncapi).toBe('AsyncAPI')
    expect(AI_AUDIT_ACTION_LABELS.prompt_publish).toBe('发布提示词版本')
    expect(AI_DRAFT_TARGET_TYPE_LABELS.EXCEPTION).toBe('例外策略')
    expect(AI_DRAFT_TARGET_TYPE_LABELS.NOISE_CLUSTER).toBe('降噪簇')
    expect(AI_MEMORY_SOURCE_LABELS.MANUAL).toBe('人工录入')
    expect(AI_PROMPT_GATE_STATE_META.ADVERSARIAL_PASSED.label).toBe('对抗通过')
    expect(AI_PROMPT_STATUS_META.ACTIVE.label).toBe('已发布')
    expect(AI_TOOL_SOURCE_LABELS['security_event.search']).toBe('安全事件查询')
    expect(AI_REPORT_FIELD_LABELS.total_endpoints).toBe('端点总数')
    expect(APM_DIAG_STOP_REASON_LABELS['kill switch']).toBe('全局熔断终止')
    expect(APM_DIAG_AUDIT_ACTION_LABELS.kill_switch).toBe('触发全局诊断熔断')
    expect(APM_ENDPOINT_SPECIAL_LABELS.__UNCLASSIFIED__).toBe('未归类端点')
    expect(formatApmEndpoint('__OTHER__')).toBe('其它（超出 Top-N）')
    expect(formatApmEndpoint('GET /api/v1/orders')).toBe('GET /api/v1/orders')
    expect(CLASSIFICATION_PURPOSE_LABELS.TRADE).toBe('交易支付')
    expect(CLASSIFICATION_ACCESS_LABELS.READ).toBe('只读')
    expect(Object.keys(CLASSIFICATION_ACTION_LABELS).length).toBeGreaterThanOrEqual(43)
    expect(Object.keys(CLASSIFICATION_DOMAIN_LABELS)).toHaveLength(16)
    expect(CLASSIFICATION_DATA_LEVEL_LABELS.CORE).toBe('核心数据')
    expect(CLASSIFICATION_LIFECYCLE_LABELS.ZOMBIE).toBe('僵尸')
    expect(CLASSIFICATION_DIRECTION_LABELS.INBOUND).toBe('入向')
    expect(COMMON_DETAIL_FIELD_LABELS.username).toBe('用户名')
    expect(COMMON_DETAIL_VALUE_LABELS.status.ACTIVE).toBe('启用')
  })

  it('纯离线规则包权限码、审计动作/对象、失败码与系统告警词表完整', () => {
    expect(PERMISSION_CODE_LABELS['waf_rules.pack.manage']).toBe('离线规则包更新管理')
    expect(AUDIT_ACTION_LABELS.rulepack_upload).toBe('上传离线规则包')
    expect(AUDIT_ACTION_LABELS.rulepack_apply).toBe('应用离线规则包')
    expect(AUDIT_ACTION_LABELS.rulepack_rollback).toBe('回滚离线规则包')
    expect(AUDIT_ACTION_LABELS.rulepack_retry_node_sync).toBe('补发节点规则包并重同步')
    expect(formatAuditAction('rulepack_apply')).toBe('应用离线规则包')
    expect(AUDIT_OBJECT_TYPE_LABELS.waf_rule_pack).toBe('离线规则包')
    expect(formatAuditObjectType('waf_rule_pack')).toBe('离线规则包')
    expect(RULEPACK_FAILURE_CODE_LABELS.GATEWAY_PUBLISH_FAILED).toBe('网关发布验证失败')
    expect(RULEPACK_FAILURE_CODE_LABELS.STANDBY_STAGE_FAILED).toBe('备节点规则包落盘校验失败')
    expect(RULEPACK_ALERT_TYPE_LABELS.RULEPACK_APPLY_FAILED).toBe('离线规则包应用失败')
    expect(RULEPACK_ALERT_TYPE_LABELS.RULEPACK_NODE_DRIFT).toBe('HA 规则包版本漂移')
    expect(COMMON_DETAIL_VALUE_LABELS.failure_code.GATEWAY_PUBLISH_FAILED).toBe('网关发布验证失败')
    expect(COMMON_DETAIL_VALUE_LABELS.alert_type.RULEPACK_NODE_DRIFT).toBe('HA 规则包版本漂移')
  })
})

describe('共享 utils 词表补全与中文化回归检查', () => {
  it('stage3/stage4 补全枚举且 ATTACK_TYPE_OPTIONS 不含英文编码后缀', () => {
    expect(APP_STATUS_META.DELETED.label).toBe('已删除')
    expect(RULE_SOURCE_META.CUSTOM).toBeUndefined()
    expect(RULE_SOURCE_META.USER_CUSTOM.label).toBe('用户自定义')
    expect(RULE_SOURCE_META.CUSTOM_PACK.label).toBe('扩展规则包')
    expect(RULE_SOURCE_META.JIUZHANG_BUILTIN.label).toBe('九章内置规则')
    const sqli = ATTACK_TYPE_OPTIONS.find((o) => o.value === 'SQL_INJECTION')
    expect(sqli?.label).toBe('SQL注入')
    expect(sqli?.label).not.toContain('SQL_INJECTION')
  })

  it('stage8 补全枚举与 getApiFindingTypeMeta 动态前缀匹配', () => {
    expect(API_ENDPOINT_STATUS_META.ZOMBIE.label).toBe('僵尸接口')
    expect(API_SENSITIVE_TYPE_META.password.label).toBe('密码口令')
    expect(API_SENSITIVE_TYPE_META.jwt.label).toBe('JWT 令牌')
    expect(API_SEMANTIC_TYPE_META.captcha.label).toBe('验证码')
    expect(API_SEMANTIC_TYPE_META.id_card.label).toBe('身份证号')
    expect(API_ACTION_META.RATE_LIMIT.label).toBe('限速')
    expect(API_ACTION_META.MASK_RESPONSE.label).toBe('响应脱敏')
    expect(API_COUNTRY_META.UNKNOWN.label).toBe('未知')
    expect(API_VIOLATION_TYPE_META['schema.param_enum'].label).toBe('参数不在枚举范围')
    expect(API_VIOLATION_TYPE_META['schema.relation_sum_matches'].label).toBe('参数求和校验违例')
    expect(API_DETECTOR_META.flowguard.label).toBe('强流程防护')
    expect(API_DETECTOR_META.mcpguard.label).toBe('MCP 工具调用防护')
    expect(API_FINDING_TYPE_META.ADMISSION_UNCONFIRMED.label).toBe('未确认 API 准入命中')
    expect(getApiFindingTypeMeta('RESPONSE_SCHEMA_EXTRA_KEY').label).toBe('响应模型偏离')
    expect(getApiFindingTypeMeta('PARSER_NESTED_TOO_DEEP').label).toBe('报文解析异常')
    expect(getApiFindingTypeMeta('UNKNOWN_CUSTOM_TYPE').label).toBe('UNKNOWN_CUSTOM_TYPE')
  })

  it('apm.ts getApmWafActionMeta 兼容空串与大小写，时间窗错误文案已中文化', () => {
    expect(APM_WAF_ACTION_META.LOG.label).toBe('仅记录')
    expect(getApmWafActionMeta('').label).toBe('放行')
    expect(getApmWafActionMeta('block').label).toBe('阻断')
    expect(getApmWafActionMeta('temp_block').label).toBe('临时封禁')
    expect(getApmWafActionMeta('CUSTOM').label).toBe('CUSTOM')
    const missingErr = parseApmUrlTimeWindow('2026-08-30T00:25:00Z', null)
    expect(missingErr && 'error' in missingErr ? missingErr.error : '').not.toContain('start_time')
  })

  it('authzEnforcement 展示词表中文化且冻结确认文案 buildAuthzConfirmTextV1 未改', () => {
    expect(UNKNOWN_NEVER_BLOCKS_NOTE).toBe('证据不足永不阻断')
    expect(ACK_STATE_META.FRESH.label).toBe('最新')
    expect(ACK_STATE_META.NEVER_ACKED.label).toBe('从未确认')
    expect(ENFORCEMENT_READINESS_META.PROTECT_ACTIVE.label).toBe('实断中')
    expect(ENFORCEMENT_VALUE_META.OBSERVE.label).toBe('观察')
    expect(EVIDENCE_SOURCE_META.AUTHORITY_SYNC.label).toBe('权威同步')
    expect(
      buildAuthzConfirmTextV1({
        windowDays: 7,
        observeViolationCount: 1,
        distinctPrincipalCount: 1,
        confirmedByName: '测试员',
      }),
    ).toContain('403 AUTHZ_VIOLATION_DENIED')
  })

  it('botPolicy / securityRegression / machineIdentity / mcp 展示文案已中文化', () => {
    expect(BOT_NODE_SYNC_META.UNKNOWN.label).toBe('未同步')
    expect(BOT_METRIC_SPECS.method_enumeration_size.description).not.toContain('distinct')
    expect(formatBotParamOption(BOT_METRIC_SPECS.ua_class_match.params[0], 'BOT')).toBe('爬虫/机器人')
    expect(formatBotParamOption('field', 'cipher_suite')).toBe('密码套件')

    const usability = previewPublishUsability(
      {
        id: '1',
        run_id: 'r1',
        level: 'SMOKE',
        corpus_id: 'c1',
        declared_status: 'FAIL',
        verification_status: 'PASSED',
        counts: { total: 1, executed: 1, passed: 0, failed: 1, skipped: 0, blocked: 0, not_run: 0, mandatory_failed: 1 },
        created_at: '2026-10-01T00:00:00Z',
      } as never,
      { mode: 'ENFORCE', required_level: 'RELEASE', required_corpus_id: 'c1', evidence_max_age_seconds: 0 } as never,
      Date.parse('2026-10-01T00:01:00Z'),
    )
    expect(usability.usable).toBe(false)
    expect(usability.reasons.join(' ')).toContain('声明失败')
    expect(usability.reasons.join(' ')).toContain('冒烟')
    expect(usability.reasons.join(' ')).toContain('发布级')
    expect(usability.reasons.join(' ')).not.toContain('mandatory_failed')
    expect(gateReasonAdvice('证据级别不足')).toContain('全量/发布级')
    expect(gateReasonAdvice('强制用例未通过')).not.toContain('FAIL')

    expect(KEY_STATUS_META.ACTIVE.label).toBe('生效中（可签发可验证）')
    expect(MACHINE_IDENTITY_MODE_META.OBSERVE.label).toBe('观察')
    expect(MCP_BINDING_MODE_META.PROTECT.label).toBe('实断')
    expect(parseArgConstraintsText('[{"field":""}]').error).toBe('第 1 项参数字段名必填')
    expect(parseArgConstraintsText('[{"field":"p","kind":"bad","allow":["a"]}]').error).toContain('约束类型非法')
  })
})
