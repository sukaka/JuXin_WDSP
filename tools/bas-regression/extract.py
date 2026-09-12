#!/usr/bin/env python3
# =============================================================================
# 九章 BAS 回归覆盖矩阵生成工具（自研）
#
# 来源：本工具由本团队依据 BAS（入侵攻击模拟）报告 xlsx 的列结构、
#       gateway/rules/contrib/CUSTOM_PACK/ 自建规则包与 test/waf/ftw/crs-tests/
#       回归测试目录的现状自行编写，未复制任何第三方 WAF 产品的规则、
#       代码或文案。
#
# 口径：
#   - BAS 报告不含原始 payload（执行步骤列仅有状态码与判定结论），无法逐
#     payload 重放；本工具以「BAS 攻击类别 → 承担检测的规则包/规则 ID 段 →
#     go-ftw 回归测试」的静态映射做覆盖代理验证，详见 README.md。
#   - 只读规则库与测试目录，不写仓库内任何文件；输出到 stdout 或
#     tools/bas-regression/out/，多次运行结果一致（幂等）。
#
# 用法：
#   python3 extract.py                 # 生成 out/coverage-matrix.md 并打印缺口摘要
#   python3 extract.py --check         # 只输出「有规则无 ftw 测试」缺口报告
#   python3 extract.py --xlsx <path>   # 指定 BAS 报告 xlsx 路径
#   python3 extract.py --stdout        # 矩阵写到 stdout 而非文件
# =============================================================================
"""BAS 回归覆盖矩阵生成工具：解析 BAS 报告 xlsx，按类别映射自建规则包与 ftw 测试。"""

import argparse
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CUSTOM_PACK_DIR = REPO_ROOT / "gateway" / "rules" / "contrib" / "CUSTOM_PACK"
FTW_DIR = REPO_ROOT / "test" / "waf" / "ftw" / "crs-tests"
OUT_DIR = Path(__file__).resolve().parent / "out"

# BAS 报告默认路径（可用 --xlsx 覆盖）；文件缺失时矩阵仍生成，仅省略统计节
DEFAULT_XLSX = Path(
    "/Users/zhanglei/.kimi-code/sessions/wd_jiuzhang_waf_7c4fdb87ca19/"
    "session_bc096f86-418a-4ff1-b8b5-a894e80481d0/attachments/"
    "f_758f6a08-e9e0-4794-b5de-cc6d5da45def-WAF防护有效性测试_1_12.xlsx"
)
XLSX_SHEET = "结果详情"
COL_TAG, COL_NAME, COL_BLOCK = "标签信息", "用例名称", "阻断状态"

# -----------------------------------------------------------------------------
# 静态映射表：BAS 攻击类别 → 承担检测的自建规则包与 CRS 兜底组。
# 依据 CUSTOM_PACK 各文件头部注释与 docs/RULE_PACKS.md 的 ID 段分配人工维护；
# 规则数与 ID 范围由脚本动态扫描填入，映射关系本身静态书写。
# -----------------------------------------------------------------------------
CATEGORY_COVERAGE = {
    "通用组件漏洞": {
        "desc": "BAS 以公开 CVE/CNVD 利用包为主（Jira/Spring/海康/深信服/OA 等），"
                "由应急 CVE、近年组件 CVE 与开源 Web 系统利用包承担检测。",
        "custom": [
            ("cve-emergency.conf", "Log4j/Spring/Confluence/ProxyShell/Struts S2 等应急 CVE 利用特征"),
            ("cve-recent.conf", "Tomcat/JBoss/Jenkins/Nacos 等近年组件 CVE（含 Apache CVE-2021-41773/42013 目录穿越利用）"),
            ("oss-webapps-cve.conf", "开源 CMS/OA/框架公开利用面（WordPress/泛微/用友/通达/致远等）"),
            ("attack-coverage.conf", "1001135–1001151 高危 CVE 补充应急段"),
            ("unauth-access.conf", "组件未授权管理面/中间件未授权访问/拖库特征（OBSERVE 级叠加计分，不单条阻断）"),
        ],
        "crs": ["944 系列（Java 攻击/反序列化）", "932 系列（命令注入/RCE）", "933 系列（PHP 注入）"],
    },
    "XSS跨站脚本执行漏洞": {
        "desc": "BAS 以 GET/POST 反射型 XSS payload 集为主，CRS 941 主力，自研包补变种。",
        "custom": [
            ("attack-variants-evasion.conf", "C 段 1001214–1001218（SVG/MathML/事件/实体编码）、N 段 1001267–1001270（srcdoc/mXSS/属性截断/模板字面量）"),
            ("injection-variants.conf", "1001722–1001733 XSS 绕过变种（模板标签/事件处理器/GBK 宽字节/DOM sink 等）"),
        ],
        "crs": ["941 系列（XSS，主力）"],
    },
    "WebShell上传(流量)": {
        "desc": "BAS 覆盖各语言 WebShell 样本上传与连接流量，自研 WebShell 包群主力。",
        "custom": [
            ("webshell.conf", "一句话/菜刀/蚁剑/哥斯拉/冰蝎基础通信与上传特征、双扩展名与解析绕过"),
            ("webshell-obfuscation.conf", "加密/混淆/变种 WebShell（编码链、动态调用、密钥参数、工具协议痕迹）"),
            ("webshell-uploads.conf", "上传通道专项：危险可执行扩展名/%00 截断/图片马/压缩包投递/multipart 反规避"),
            ("webshell-content.conf", "WebShell 文件内容特征（JSP/ASP/ASPX/CFM/PERL/Python/SH 及跨语言一句话）"),
            ("attack-variants-evasion.conf", "J 段 1001245–1001249、T 段 1001289–1001293 WebShell/上传变种补强"),
            ("bot-protocol.conf", "上传与异常 Content-Type 段（可执行体/脚本类型上传）"),
        ],
        "crs": ["933 系列（PHP 注入，兜底）", "922 系列（Multipart 攻击）"],
    },
    "SQL注入漏洞": {
        "desc": "BAS 含组件 SQLi CVE 与通用注入 payload，CRS 942 主力，自研包补变形绕过。",
        "custom": [
            ("attack-variants-evasion.conf", "B 段 1001207–1001213（UNION/盲注/内嵌变形）、M 段 1001260–1001266（OOB/条件注释/HPP/二次编码）"),
            ("attack-coverage.conf", "1001129–1001134 NoSQL/LDAP 注入（同类注入面）"),
            ("injection-variants.conf", "1001701–1001711 SQLi 绕过变种（版本注释/等价函数/GBK 宽字节/时间盲注变形等）"),
        ],
        "crs": ["942 系列（SQLi，主力）"],
    },
    "任意文件包含漏洞": {
        "desc": "BAS 以读取 /etc/*、win.ini、伪协议 base64 等 LFI payload 为主。",
        "custom": [
            ("attack-variants-evasion.conf", "E 段 1001224–1001228 LFI/RFI/路径变种（含伪协议）"),
            ("sensitive-exposure.conf", "敏感文件路径直接访问（/etc/passwd、win.ini、备份等）"),
            ("xxe-lfi-variants.conf", "B 段 PHP 伪协议变种、C 段本地敏感文件目标、E 段空字节截断变种"),
        ],
        "crs": ["930 系列（LFI，主力）", "931 系列（RFI）"],
    },
    "命令注入漏洞": {
        "desc": "BAS 含组件命令执行 CVE 与通用命令注入 payload，CRS 932 主力。",
        "custom": [
            ("attack-variants-evasion.conf", "D 段 1001219–1001223（分隔符/反引号/PowerShell 编码）、O 段 1001271–1001274（Windows/brace/进程替换/解释器）"),
            ("deserialization-rce.conf", "LOLBins 与表达式/命令拼接补充段"),
            ("injection-variants.conf", "1001712–1001721 命令注入绕过变种（IFS/环境变量切片/大括号扩展/八进制编码等）"),
        ],
        "crs": ["932 系列（RCE，主力）"],
    },
    "任意文件上传漏洞": {
        "desc": "BAS 以 OA/CMS 上传 CVE 与可执行体上传为主。",
        "custom": [
            ("webshell.conf", "双扩展名/解析绕过、上传内容 WebShell 代码、配置文件上传绕过段"),
            ("webshell-uploads.conf", "上传通道专项：危险可执行扩展名/%00 截断/图片马/压缩包投递/multipart 反规避"),
            ("webshell-content.conf", "上传体中跨语言 WebShell 内容特征"),
            ("bot-protocol.conf", "上传与异常 Content-Type 段"),
            ("oss-webapps-cve.conf", "OA/CMS 任意文件上传 CVE（泛微/用友/通达/致远/帆软等）"),
            ("attack-variants-evasion.conf", "J 段 1001245–1001249、T 段 1001289–1001293 上传变种补强"),
        ],
        "crs": ["922 系列（Multipart 攻击）", "920 系列（协议约束）"],
    },
    "反序列化远程命令执行漏洞": {
        "desc": "BAS 覆盖 Java/PHP 反序列化 CVE（WebLogic/JBoss/Fastjson/Yii2 等）。",
        "custom": [
            ("deserialization-rce.conf", "Java/PHP/Python/.NET/YAML/OGNL 反序列化与表达式注入"),
            ("attack-coverage.conf", "1001101–1001115 SSTI 引擎级特征"),
            ("ssti-injection.conf", "1001801–1001816 SSTI 专项（Freemarker/Velocity/Thymeleaf·SpEL/Jinja2/Twig/ERB/Mako/Groovy/EL 模板注入，归入本类与既有 SSTI 归属一致）"),
            ("cve-emergency.conf", "Fastjson/Shiro/WebLogic 等应急 CVE"),
            ("attack-variants-evasion.conf", "P 段 1001275–1001277 SSTI/EL 变种、R 段 1001281–1001284 反序列化变种"),
        ],
        "crs": ["944 系列（Java 反序列化/Log4j）"],
    },
    "SSRF服务端请求伪造": {
        "desc": "BAS 含组件 SSRF CVE 与伪协议/进制 IP/本地绕过等高级 payload。",
        "custom": [
            ("cloud-abuse.conf", "SSRF 云元数据段（169.254.169.254 等锚定检测）"),
            ("attack-coverage.conf", "1001121–1001128 SSRF 变形（伪协议/进制 IP/重定向）"),
            ("attack-variants-evasion.conf", "H 段 1001237–1001241、Q 段 1001278–1001280 SSRF/DNS 变种增强"),
            ("ssrf-protocols.conf", "SSRF 专项：伪协议补充/IP 混淆绕过/URL 参数指向内网/短链跳板"),
        ],
        "crs": ["934 系列（通用注入，含部分 SSRF 网络层特征，弱兜底）"],
    },
    "XXE实体注入漏洞": {
        "desc": "BAS 以组件 XXE CVE 与 DOCTYPE/实体声明 payload 为主，依赖自研包。",
        "custom": [
            ("api-abuse.conf", "1000440–1000444 XXE DOCTYPE 内部子集/实体声明网络层兜底"),
            ("attack-variants-evasion.conf", "H 段 1001237–1001241、R 段 1001281–1001284 XXE 变种"),
            ("xxe-lfi-variants.conf", "A 段 XXE 变种（引用/启发式/包裹/编码/ARGS 目标）"),
        ],
        "crs": ["（CRS 无 XXE 专项组，依赖自研包）"],
    },
    "C&C通信": {
        "desc": "BAS 以重放哥斯拉/冰蝎/蚁剑 php/jsp/aspx WebShell 流量为主，对应 WebShell 通信特征。",
        "custom": [
            ("webshell.conf", "哥斯拉/冰蝎/蚁剑/菜刀通信特征段"),
            ("webshell-obfuscation.conf", "加密流量密钥参数与工具协议痕迹"),
        ],
        "crs": ["（无直接对应 CRS 组，依赖自研 WebShell 包）"],
    },
    "目录穿越漏洞": {
        "desc": "BAS 以 Apache/Spring/uWSGI 等目录穿越 CVE 利用为主。",
        "custom": [
            ("cve-recent.conf", "Apache CVE-2021-41773/42013 目录穿越利用特征"),
            ("api-abuse.conf", "1000450–1000455 路径穿越编码变体"),
            ("attack-variants-evasion.conf", "E 段 1001224–1001228 路径变种"),
            ("xxe-lfi-variants.conf", "D 段目录穿越编码变体、E 段空字节截断变种"),
        ],
        "crs": ["930 系列（LFI/路径穿越，主力）"],
    },
}

# 用例名称归一化：剥离报告套话前后缀，保留漏洞/payload 核心名
_NOISE_PREFIX_RE = re.compile(r"^(使用|通过发送|通过重放)\s*")
_NOISE_SUFFIX_RES = [
    re.compile(r"\s*(攻击包)?\s*(payload)?\s*(测试|验证)\s*"
               r"(WAF策略|防护设备|防护|WAF拦截|WAF)\s*(的)?\s*(策略)?\s*有效性\s*$"),
    re.compile(r"\s*攻击包\s*$"),
    re.compile(r"\s*payload\s*$", re.I),
]
_TRAILING_INDEX_RE = re.compile(r"\s*[（(]\d{1,3}[)）]\s*$")
_VULN_ID_RE = re.compile(r"(CVE[-_]\d{4}[-_]\d{4,7}|CNVD[-_]\d{4}[-_]\d{4,7}|CNNVD[-_]\d{4,}[-_]\d+)", re.I)
_RULE_ID_RE = re.compile(r"\bid:(\d{6,7})\b")
_FTW_RULE_ID_RE = re.compile(r"^rule_id:\s*(\d+)\s*$", re.M)


def normalize_case_name(name):
    """归一化用例名称：去套话前后缀与尾部序号，提取 CVE/CNVD 编号。"""
    core = _NOISE_PREFIX_RE.sub("", name.strip())
    changed = True
    while changed:  # 套话可能多层叠加（如「攻击包 验证防护设备有效性」）
        changed = False
        for rx in _NOISE_SUFFIX_RES:
            stripped = rx.sub("", core).strip()
            if stripped != core:
                core, changed = stripped, True
    core = _TRAILING_INDEX_RE.sub("", core).strip()
    core = re.sub(r"\s+", " ", core)
    vuln_ids = sorted({m.upper().replace("_", "-") for m in _VULN_ID_RE.findall(name)})
    return (core or name.strip()), vuln_ids


def cluster_key(tag, core):
    """聚类键：类别 + 去除空白并忽略大小写的核心名。"""
    return tag, re.sub(r"\s+", "", core).casefold()


def parse_xlsx(path):
    """解析 BAS 报告，返回 [(标签信息, 用例名称, 阻断状态)]；文件缺失返回 None。"""
    if not path.is_file():
        return None
    import openpyxl  # 延迟导入：--check 模式无需 openpyxl

    wb = openpyxl.load_workbook(path, read_only=True)
    if XLSX_SHEET not in wb.sheetnames:
        raise SystemExit(f"错误：xlsx 中不存在工作表 {XLSX_SHEET!r}，实际为 {wb.sheetnames}")
    rows = wb[XLSX_SHEET].iter_rows(values_only=True)
    header = next(rows)
    idx = {name: i for i, name in enumerate(header)}
    for col in (COL_TAG, COL_NAME, COL_BLOCK):
        if col not in idx:
            raise SystemExit(f"错误：xlsx 缺少列 {col!r}，实际表头 {list(header)}")
    out = []
    for r in rows:
        out.append((
            (r[idx[COL_TAG]] or "").strip(),
            (r[idx[COL_NAME]] or "").strip(),
            (r[idx[COL_BLOCK]] or "").strip(),
        ))
    wb.close()
    return out


def scan_custom_pack():
    """扫描 CUSTOM_PACK 各文件规则 ID（只读），返回 {文件名: 升序 ID 列表}。"""
    packs = {}
    for conf in sorted(CUSTOM_PACK_DIR.glob("*.conf")):
        ids = []
        for line in conf.read_text(encoding="utf-8").splitlines():
            if line.lstrip().startswith("#"):  # 跳过注释行
                continue
            ids.extend(int(m) for m in _RULE_ID_RE.findall(line))
        packs[conf.name] = sorted(set(ids))
    return packs


def scan_ftw_tests():
    """扫描 ftw 测试目录，返回 {规则ID: 文件名}（文件名与 rule_id 字段并集）。"""
    tests = {}
    for yml in sorted(FTW_DIR.glob("*.yaml")):
        ids = set()
        if yml.stem.isdigit():
            ids.add(int(yml.stem))
        for m in _FTW_RULE_ID_RE.findall(yml.read_text(encoding="utf-8")):
            ids.add(int(m))
        for rid in ids:
            tests.setdefault(rid, yml.name)
    return tests


def compute_gaps(packs, tests):
    """计算「有规则无 ftw 测试」缺口，返回 {文件名: 缺测 ID 列表}。"""
    return {name: [rid for rid in ids if rid not in tests]
            for name, ids in packs.items()}


def print_gap_report(packs, tests, gaps):
    """向 stdout 打印缺口报告，返回缺测总数。"""
    total, total_gap = 0, 0
    for name in sorted(packs):
        ids, missing = packs[name], gaps[name]
        total += len(ids)
        total_gap += len(missing)
        print(f"{name}: 规则 {len(ids)} 条，ftw 测试 {len(ids) - len(missing)} 条，缺测 {len(missing)} 条")
        if missing:
            print(f"  缺测 ID: {', '.join(str(i) for i in missing)}")
    print(f"合计: 规则 {total} 条，缺测 {total_gap} 条")
    return total_gap


def build_matrix(rows, packs, tests, gaps):
    """生成 coverage-matrix.md 内容（确定性输出，无时间戳）。"""
    lines = []
    a = lines.append
    a("# BAS 回归覆盖矩阵")
    a("")
    a("> 本文件由 `tools/bas-regression/extract.py` 自动生成，请勿手工编辑。")
    a("> 重新生成：`python3 tools/bas-regression/extract.py`")
    a("")
    a("## 口径说明")
    a("")
    a("- BAS 报告不含原始 payload（执行步骤列仅有状态码与判定结论），无法逐 payload")
    a("  重放；本矩阵以「BAS 攻击类别 → 承担检测的规则包/规则 ID 段 → go-ftw 回归")
    a("  测试」的静态映射做**覆盖代理验证**：每个类别用自建 ftw 用例代表该类的")
    a("  典型 payload 形态做回归，而非逐条复放 BAS 用例。")
    a("- BAS 侧判定只认**带防御特征的 403**（拦截页面/拦截响应头特征）；仅出安全")
    a("  事件但未拦截（如 DetectionOnly 观察模式）在 BAS 口径下记为「未阻断」。")
    a("- 规则数与 ID 范围为脚本对 `gateway/rules/contrib/CUSTOM_PACK/` 的动态扫描")
    a("  结果；类别 → 规则包的映射关系静态维护于 `extract.py` 的 `CATEGORY_COVERAGE`。")
    a("")

    # 一、BAS 报告统计
    a("## 一、BAS 报告统计")
    a("")
    if rows is None:
        a("> BAS 报告 xlsx 不可用（未找到文件），本节省略；映射与缺口节不受影响。")
        a("")
        tag_stats = {}
    else:
        tag_stats = defaultdict(Counter)
        for tag, _name, block in rows:
            tag_stats[tag][block or "（空）"] += 1
        a(f"- 数据源：`{DEFAULT_XLSX.name}`（工作表 `{XLSX_SHEET}`）")
        a(f"- 用例总数：**{len(rows)}**")
        a("")
        a("| BAS 攻击类别 | 用例数 | 阻断 | 未阻断 | 其他 |")
        a("|---|---|---|---|---|")
        for tag in sorted(tag_stats, key=lambda t: -sum(tag_stats[t].values())):
            c = tag_stats[tag]
            total = sum(c.values())
            other = total - c.get("阻断", 0) - c.get("未阻断", 0)
            a(f"| {tag} | {total} | {c.get('阻断', 0)} | {c.get('未阻断', 0)} | {other} |")
        a("")

    # 二、类别 → 规则覆盖矩阵
    a("## 二、类别 → 规则覆盖矩阵")
    a("")
    all_tags = sorted(set(CATEGORY_COVERAGE) | set(tag_stats),
                      key=lambda t: -sum(tag_stats.get(t, {0: 0}).values()))
    for tag in all_tags:
        cov = CATEGORY_COVERAGE.get(tag)
        c = tag_stats.get(tag, Counter())
        a(f"### {tag}")
        a("")
        if c:
            a(f"- BAS 用例数：**{sum(c.values())}**（报告阻断 {c.get('阻断', 0)} / 未阻断 {c.get('未阻断', 0)}）")
        if cov is None:
            a("- **覆盖缺口：静态映射表中尚无该类别的规则包映射**")
            a("")
            continue
        a(f"- 说明：{cov['desc']}")
        a("")
        a("承担检测的自建规则包（CUSTOM_PACK）：")
        a("")
        a("| 规则包文件 | 规则数 | 实际 ID 范围 | 承担内容 |")
        a("|---|---|---|---|")
        for fname, role in cov["custom"]:
            ids = packs.get(fname)
            if ids:
                a(f"| `{fname}` | {len(ids)} | {ids[0]}–{ids[-1]} | {role} |")
            else:
                a(f"| `{fname}` | — | — | {role}（**文件缺失，请检查映射表**） |")
        a("")
        a(f"CRS 兜底：{'；'.join(cov['crs'])}")
        a("")
        # ftw 测试链接（按覆盖包分组，仅列已存在的测试）
        a("go-ftw 回归测试：")
        a("")
        any_test = False
        for fname, _role in cov["custom"]:
            ids = packs.get(fname, [])
            hit = [rid for rid in ids if rid in tests]
            if hit:
                any_test = True
                links = "、".join(
                    f"[{tests[rid]}](../../../test/waf/ftw/crs-tests/{tests[rid]})" for rid in hit)
                a(f"- `{fname}`：{links}")
        if not any_test:
            a("- 暂无（缺口见第三节）")
        a("")
        # 归一化聚类（有报告数据时）：键为归一化核心名，展示用首个原始核心名
        if c:
            clusters = defaultdict(lambda: [0, set(), ""])
            for t, name, _block in rows:
                if t != tag:
                    continue
                core, vuln_ids = normalize_case_name(name)
                entry = clusters[cluster_key(t, core)]
                entry[0] += 1
                entry[1].update(vuln_ids)
                if not entry[2]:
                    entry[2] = core
            a(f"- 归一化聚类：**{len(clusters)}** 类（按 标签信息+用例名称 归一化）")
            a("")
            a("| 聚类（核心名） | 用例数 | 关联 CVE/CNVD |")
            a("|---|---|---|")
            top = sorted(clusters.items(), key=lambda kv: (-kv[1][0], kv[0][1]))[:20]
            for (_t, _key), (cnt, vuln_ids, disp) in top:
                ids_txt = ", ".join(sorted(vuln_ids)[:6]) or "—"
                a(f"| {disp.replace('|', '\\|')} | {cnt} | {ids_txt} |")
            if len(clusters) > 20:
                a(f"| …… 其余 {len(clusters) - 20} 类从略 | | |")
            a("")

    # 三、规则-测试缺口
    a("## 三、规则-测试缺口（有规则无 ftw 测试）")
    a("")
    a("按 `test/waf/ftw/crs-tests/` 下 `<规则ID>.yaml`（一条规则一个文件）口径统计，")
    a("随各规则包分片补齐后重跑本脚本即可收敛。")
    a("")
    a("| 规则包文件 | 规则数 | 已有测试 | 缺测 | 缺测 ID |")
    a("|---|---|---|---|---|")
    total, total_gap = 0, 0
    for name in sorted(packs):
        ids, missing = packs[name], gaps[name]
        total += len(ids)
        total_gap += len(missing)
        ids_txt = ", ".join(str(i) for i in missing) if missing else "—"
        a(f"| `{name}` | {len(ids)} | {len(ids) - len(missing)} | {len(missing)} | {ids_txt} |")
    a(f"| **合计** | **{total}** | **{total - total_gap}** | **{total_gap}** | |")
    a("")
    a("---")
    a("")
    a("Copyright © 聚信得仁")
    a("All Rights Reserved.")
    a("")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="BAS 回归覆盖矩阵生成工具（自研）")
    ap.add_argument("--xlsx", type=Path, default=DEFAULT_XLSX, help="BAS 报告 xlsx 路径")
    ap.add_argument("--check", action="store_true", help="只输出有规则无 ftw 测试的缺口报告")
    ap.add_argument("--strict", action="store_true", help="存在缺口时以退出码 1 结束（配合 --check）")
    ap.add_argument("--out", type=Path, default=OUT_DIR / "coverage-matrix.md", help="矩阵输出路径")
    ap.add_argument("--stdout", action="store_true", help="矩阵写到 stdout 而非文件")
    args = ap.parse_args()

    packs = scan_custom_pack()
    if not packs:
        raise SystemExit(f"错误：未在 {CUSTOM_PACK_DIR} 扫描到任何规则包")
    tests = scan_ftw_tests()
    gaps = compute_gaps(packs, tests)

    if args.check:
        missing = print_gap_report(packs, tests, gaps)
        return 1 if (args.strict and missing) else 0

    rows = parse_xlsx(args.xlsx)
    if rows is None:
        print(f"提示：未找到 BAS 报告 {args.xlsx}，统计节将省略", file=sys.stderr)
    matrix = build_matrix(rows, packs, tests, gaps)
    if args.stdout:
        sys.stdout.write(matrix)
    else:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(matrix, encoding="utf-8")
        print(f"已生成 {args.out}")
    print_gap_report(packs, tests, gaps)
    return 0


if __name__ == "__main__":
    sys.exit(main())
