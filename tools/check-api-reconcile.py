#!/usr/bin/env python3
"""路由 ↔ OpenAPI 片段对账（阶段8 评审整改）。

提取 server 端全部 Go 1.22 ServeMux 注册（mux.Handle("METHOD /api/v1/..."），
与 server/openapi/fragments/*.yaml 的 paths×methods 做双向差集：
  - 代码有、文档无：已注册路由未收录进 OpenAPI 文档；
  - 文档有、代码无：文档记载了不存在的路由（虚构/过期）。

用法：python3 tools/check-api-reconcile.py
退出码：0 = 双向零差集；1 = 存在差集（明细打印，供 CI 拦截）。
"""
import glob
import os
import re
import sys

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CODE_DIRS = [os.path.join(ROOT, 'server', 'cmd'), os.path.join(ROOT, 'server', 'internal')]
FRAG_DIR = os.path.join(ROOT, 'server', 'openapi', 'fragments')

METHODS = ('get', 'post', 'put', 'patch', 'delete', 'head', 'options')

# mux.Handle / mux.HandleFunc("GET /api/v1/..." 注册形态（首参为方法+路径字面量，可跨行）。
ROUTE_RE = re.compile(r'\.Handle(?:Func)?\(\s*"([A-Z]+)\s+(/api/v1[^"]*)"')

# 路径参数归一：{id}/{type}/{param...} 结构等价，统一为 {} 参与对账。
PARAM_RE = re.compile(r'\{[^{}]+?\}')


def norm_path(go_path):
    """/api/v1/license/status -> /license/status；{x...}/{x} -> {}。"""
    p = go_path[len('/api/v1'):] or '/'
    return PARAM_RE.sub('{}', p)


def code_routes():
    """扫描 Go 源码提取 (method, path) 集合；path 已去 /api/v1 前缀。"""
    routes = set()
    for base in CODE_DIRS:
        for dirpath, _dirs, files in os.walk(base):
            for fn in files:
                if not fn.endswith('.go') or fn.endswith('_test.go'):
                    continue
                fp = os.path.join(dirpath, fn)
                with open(fp, encoding='utf-8') as f:
                    src = f.read()
                for m in ROUTE_RE.finditer(src):
                    routes.add((m.group(1).lower(), norm_path(m.group(2))))
    return routes


def doc_routes():
    """解析 fragments/*.yaml 提取 (method, path) 集合。"""
    routes = set()
    for fp in sorted(glob.glob(os.path.join(FRAG_DIR, '*.yaml'))):
        frag = yaml.safe_load(open(fp, encoding='utf-8'))
        for path, item in (frag.get('paths') or {}).items():
            for method in (item or {}):
                if method.lower() in METHODS:
                    routes.add((method.lower(), PARAM_RE.sub('{}', path)))
    return routes


def main():
    code = code_routes()
    doc = doc_routes()
    undocumented = sorted(code - doc)
    phantom = sorted(doc - code)

    print(f'代码注册路由: {len(code)}  OpenAPI 片段收录: {len(doc)}')
    ok = True
    if undocumented:
        ok = False
        print(f'\n[未收录] 代码已注册但文档缺失 {len(undocumented)} 条：')
        for method, path in undocumented:
            print(f'  {method.upper():6s} /api/v1{path}')
    if phantom:
        ok = False
        print(f'\n[虚构/过期] 文档记载但代码未注册 {len(phantom)} 条：')
        for method, path in phantom:
            print(f'  {method.upper():6s} /api/v1{path}')
    if ok:
        print('对账通过：双向零差集')
        return 0
    return 1


if __name__ == '__main__':
    sys.exit(main())
