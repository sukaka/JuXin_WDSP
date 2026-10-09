#!/usr/bin/env python3
"""将 fragments/*.yaml 合并为完整的 WDSP 管理 API OpenAPI 文档。

用法：python3 server/openapi/merge.py
输入：server/openapi/fragments/*.yaml（CONTRACT.md 约定的片段格式）
输出：server/openapi/wdsp-api.yaml
"""
import glob
import os
import sys

import yaml

BASE = os.path.dirname(os.path.abspath(__file__))
FRAG_DIR = os.path.join(BASE, 'fragments')
OUT = os.path.join(BASE, 'wdsp-api.yaml')

TAG_DESCRIPTIONS = {
    'auth': '身份认证',
    'profile': '个人中心',
    'users': '用户管理',
    'roles': '角色权限',
    'login-logs': '登录日志',
    'audits': '操作审计',
    'system-settings': '系统设置',
    'system': '系统基础',
    'applications': 'Web 应用接入',
    'site-discovery': '站点资产发现',
    'APM': 'APM 业务性能监控（无 Agent 查询 + Agent 控制面）',
    'traffic-agents': '分布式流量采集 Agent 管理',
    'traffic-policies': '分布式流量采集策略',
    'agent-control': '分布式流量 Agent 机器控制面',
    'certificates': 'HTTPS 证书',
    'gateway-config': '网关配置与发布',
    'protection-policies': '防护策略',
    'waf-rules': '防护规则库',
    'vuln-refs': 'CNNVD 漏洞档案',
    'rule-overrides': '规则覆盖',
    'custom-rules': '自定义规则',
    'exceptions': '例外策略',
    'trusted-proxies': '可信代理',
    'protected-addresses': '防护地址',
    'access-rules': '访问控制规则（IP 黑白名单）',
    'rate-limit-policies': '频率与 CC 防护',
    'temporary-blocks': '临时封禁',
    'access-control-events': '访问控制事件',
    'access-control-versions': '访问控制版本',
    'l7-rules': 'L7 访问控制规则',
    'security-events': '安全事件',
    'security-identities': '客户身份与行为（client_identity）',
    'behavior-policy': '行为策略（侦察/枚举行为检测）',
    'risk-policy': '风险策略（身份风险处置）',
    'jwt-trust': 'JWT 信任策略（业务 JWT 信任链，WDSP P0-03）',
    'bot-policy': 'Bot 挑战策略（WDSP P1-02）',
    'security-regression': '安全回归证据与发布门禁（WDSP P1-04）',
    'attack-sessions': '攻击活动（Attack Session）',
    'access-logs': '访问日志',
    'dashboard': '态势总览',
    'analytics': '统计分析',
    'system-health': '系统健康',
    'system-alerts': '系统告警',
    'notifications': '告警通知渠道',
    'reports': '报告中心',
    'license': '离线授权',
    'ha': '主备高可用',
    'backups': '备份',
    'restores': '恢复',
    'upgrades': '系统升级',
    'delivery-checks': '交付检查',
    'system-ops': '系统控制（重启/关机/恢复出厂）',
    'network-tools': '网络诊断工具（ping/端口探测/路由追踪/DNS 查询/抓包）',
    'api-security': 'API 动态防护（WDSP）',
    'ai-assistant': 'AI 安全助手',
    'ai-analysis': 'AI 智能分析',
    'ai-drafts': 'AI 草稿与建议',
    'ai-noise': 'AI 自动降噪',
    'ai-evaluations': 'AI 质量评估',
    'ai-models': 'AI 模型管理',
    'ai-agents': 'AI 智能体管理',
    'ai-tools': 'AI 工具管理',
    'ai-prompts': 'AI 提示词管理',
    'ai-memories': 'AI 记忆管理',
    'ai-audits': 'AI 智能审计',
    'ai-usage': 'AI 配额与成本',
}

ERROR_SCHEMA = {
    'type': 'object',
    'required': ['error'],
    'properties': {
        'error': {
            'type': 'object',
            'required': ['code', 'message'],
            'properties': {
                'code': {'type': 'string', 'description': '错误码（如 VALIDATION_FAILED、PERMISSION_DENIED）'},
                'message': {'type': 'string', 'description': '错误描述'},
                'details': {'type': 'object', 'description': '字段级错误明细（可选）'},
            },
        }
    },
}

MESSAGE_SCHEMA = {
    'type': 'object',
    'required': ['message'],
    'properties': {'message': {'type': 'string', 'description': '操作结果提示'}},
}


def error_response(desc):
    return {
        'description': desc,
        'content': {'application/json': {'schema': {'$ref': '#/components/schemas/Error'}}},
    }


def build_skeleton():
    return {
        'openapi': '3.0.3',
        'info': {
            'title': '九章WEB动态安全管理平台（WDSP）管理 API',
            'version': '1.0.0',
            'description': '''九章WEB动态安全管理平台（WDSP，统一 Web 与 API 动态防护）管理后端 RESTful API 完整文档。

## 认证与安全

- 认证方式：HttpOnly Cookie 会话（`jiuzhang_session`），由 `POST /auth/login` 建立。
- CSRF：所有非 GET 请求必须携带 `X-CSRF-Token` 头（登录响应与 `GET /auth/me` 返回 `csrf_token`）。
- 权限：多数接口要求指定权限点（见各接口 description 的「权限：」说明）；无权限返回 403。
- 限流：登录、验证码、改密、导出等敏感接口有独立限流（超限返回 429）。

## 响应约定

- 统一信封：除 `/health` 与文件下载外，所有 JSON 响应外层为统一信封
  `{code, message, data, request_id}`。**本文档中各接口的响应 schema 描述的是信封内 `data` 载荷的结构。**
- 错误响应：HTTP 4xx/5xx 时正文为 `{error: {code, message, details?}}`（见 `components/schemas/Error`）。
- 分页：列表接口统一返回 `{items, page, page_size, total}`，分页参数为 `page`（默认 1）、`page_size`（默认 20）。
- 时间：除特别注明外均为 RFC3339（如 `2026-01-01T08:00:00+08:00`）。

## 产品形态

`/product/edition` 返回当前产品形态：`wdsp` 形态启用 API 动态防护（`/api-security/*` 命名空间）；
`waf` 形态下该命名空间不可用。AI 模块可通过配置整体关闭，关闭后 `/ai/*` 接口统一返回 503（`/ai/status` 除外）。
''',
            'contact': {'name': '聚信得仁'},
        },
        'servers': [{'url': '/api/v1', 'description': '管理 API 基础路径'}],
        'security': [{'cookieAuth': []}],
        'components': {
            'securitySchemes': {
                'cookieAuth': {
                    'type': 'apiKey',
                    'in': 'cookie',
                    'name': 'jiuzhang_session',
                    'description': '登录后下发的 HttpOnly 会话 Cookie',
                },
                'agentBearer': {
                    'type': 'http',
                    'scheme': 'bearer',
                    'bearerFormat': 'wda_<64hex>',
                    'description': '分布式流量 Agent 过渡期凭据；凭据必须属于路径中的 agent_id',
                },
                'agentCertificate': {
                    'type': 'apiKey',
                    'in': 'header',
                    'name': 'X-WDSP-Agent-Cert',
                    'description': 'Base64 编码的 Agent 客户端证书 PEM；须与时间戳和签名头同时提供',
                },
                'agentTimestamp': {
                    'type': 'apiKey',
                    'in': 'header',
                    'name': 'X-WDSP-Agent-Timestamp',
                    'description': 'Agent PoP 请求时间戳，允许时钟偏差 ±300 秒',
                },
                'agentSignature': {
                    'type': 'apiKey',
                    'in': 'header',
                    'name': 'X-WDSP-Agent-Signature',
                    'description': 'Agent 对请求方法、路径、时间戳和正文摘要生成的持有证明签名',
                },
            },
            'responses': {
                'BadRequest': error_response('请求参数或校验错误'),
                'Unauthorized': error_response('未登录或会话已失效'),
                'Forbidden': error_response('已登录但无所需权限点，或 CSRF 校验失败'),
                'NotFound': error_response('资源不存在'),
                'Conflict': error_response('状态冲突（如重复确认、版本已变更）'),
                'ServiceUnavailable': error_response('依赖能力未装配或未启用（如密钥未配置）'),
                'InternalError': error_response('服务内部错误'),
            },
            'schemas': {
                'Error': ERROR_SCHEMA,
                'MessageResponse': MESSAGE_SCHEMA,
            },
        },
    }


def main():
    doc = build_skeleton()
    errors = []
    used_tags = set()

    files = sorted(glob.glob(os.path.join(FRAG_DIR, '*.yaml')))
    if not files:
        print('no fragments found', file=sys.stderr)
        sys.exit(1)

    for path in files:
        name = os.path.basename(path)
        frag = yaml.safe_load(open(path, encoding='utf-8'))
        if not frag:
            continue
        extra_keys = set(frag) - {'paths', 'components'}
        if extra_keys:
            errors.append(f'{name}: 非法顶层键 {extra_keys}')
        for p, item in (frag.get('paths') or {}).items():
            if p in doc.setdefault('paths', {}):
                errors.append(f'{name}: 重复路径 {p}（已存在于 {doc["paths"][p]["x-source"]}）')
                continue
            item['x-source'] = name
            doc['paths'][p] = item
            for op in (item or {}).values():
                if isinstance(op, dict) and 'tags' in op:
                    used_tags.update(op['tags'])
        for s, schema in ((frag.get('components') or {}).get('schemas') or {}).items():
            schemas = doc['components']['schemas']
            if s in schemas:
                errors.append(f'{name}: schema 冲突 {s}')
                continue
            schemas[s] = schema

    undeclared = used_tags - set(TAG_DESCRIPTIONS)
    if undeclared:
        errors.append(f'未声明的 tag：{sorted(undeclared)}')

    doc['tags'] = [{'name': t, 'description': TAG_DESCRIPTIONS[t]} for t in TAG_DESCRIPTIONS if t in used_tags]

    if errors:
        for e in errors:
            print('ERROR:', e, file=sys.stderr)
        sys.exit(1)

    class NoAliasDumper(yaml.SafeDumper):
        def ignore_aliases(self, data):
            return True

    header = (
        '# 九章WEB动态安全管理平台（WDSP）管理 API —— OpenAPI 3.0.3 完整文档\n'
        '# 本文件由 server/openapi/merge.py 合并 fragments/*.yaml 自动生成，请勿手工编辑；\n'
        '# 修改请编辑对应片段后重新运行 merge.py。\n'
    )
    with open(OUT, 'w', encoding='utf-8') as f:
        f.write(header)
        yaml.dump(doc, f, Dumper=NoAliasDumper, allow_unicode=True, sort_keys=False, width=120)

    n_ops = sum(
        1 for item in doc['paths'].values()
        for k in item if k in ('get', 'post', 'put', 'delete', 'patch')
    )
    print(f'OK: {OUT}')
    print(f'paths={len(doc["paths"])} operations={n_ops} schemas={len(doc["components"]["schemas"])} tags={len(doc["tags"])}')


if __name__ == '__main__':
    main()
