# BAS 回归覆盖矩阵

> 本文件由 `tools/bas-regression/extract.py` 自动生成，请勿手工编辑。
> 重新生成：`python3 tools/bas-regression/extract.py`

## 口径说明

- BAS 报告不含原始 payload（执行步骤列仅有状态码与判定结论），无法逐 payload
  重放；本矩阵以「BAS 攻击类别 → 承担检测的规则包/规则 ID 段 → go-ftw 回归
  测试」的静态映射做**覆盖代理验证**：每个类别用自建 ftw 用例代表该类的
  典型 payload 形态做回归，而非逐条复放 BAS 用例。
- BAS 侧判定只认**带防御特征的 403**（拦截页面/拦截响应头特征）；仅出安全
  事件但未拦截（如 DetectionOnly 观察模式）在 BAS 口径下记为「未阻断」。
- 规则数与 ID 范围为脚本对 `gateway/rules/contrib/CUSTOM_PACK/` 的动态扫描
  结果；类别 → 规则包的映射关系静态维护于 `extract.py` 的 `CATEGORY_COVERAGE`。

## 一、BAS 报告统计

- 数据源：`f_758f6a08-e9e0-4794-b5de-cc6d5da45def-WAF防护有效性测试_1_12.xlsx`（工作表 `结果详情`）
- 用例总数：**4553**

| BAS 攻击类别 | 用例数 | 阻断 | 未阻断 | 其他 |
|---|---|---|---|---|
| 通用组件漏洞 | 1529 | 572 | 956 | 1 |
| XSS跨站脚本执行漏洞 | 893 | 580 | 313 | 0 |
| WebShell上传(流量) | 636 | 14 | 622 | 0 |
| SQL注入漏洞 | 497 | 314 | 183 | 0 |
| 任意文件包含漏洞 | 343 | 175 | 168 | 0 |
| 命令注入漏洞 | 321 | 104 | 217 | 0 |
| 任意文件上传漏洞 | 199 | 88 | 111 | 0 |
| 反序列化远程命令执行漏洞 | 52 | 4 | 48 | 0 |
| SSRF服务端请求伪造 | 47 | 12 | 35 | 0 |
| XXE实体注入漏洞 | 20 | 1 | 19 | 0 |
| C&C通信 | 9 | 3 | 6 | 0 |
| 目录穿越漏洞 | 7 | 0 | 7 | 0 |

## 二、类别 → 规则覆盖矩阵

### 通用组件漏洞

- BAS 用例数：**1529**（报告阻断 572 / 未阻断 956）
- 说明：BAS 以公开 CVE/CNVD 利用包为主（Jira/Spring/海康/深信服/OA 等），由应急 CVE、近年组件 CVE 与开源 Web 系统利用包承担检测。

承担检测的自建规则包（CUSTOM_PACK）：

| 规则包文件 | 规则数 | 实际 ID 范围 | 承担内容 |
|---|---|---|---|
| `cve-emergency.conf` | 42 | 1000001–1000042 | Log4j/Spring/Confluence/ProxyShell/Struts S2 等应急 CVE 利用特征 |
| `cve-recent.conf` | 35 | 1000801–1000835 | Tomcat/JBoss/Jenkins/Nacos 等近年组件 CVE（含 Apache CVE-2021-41773/42013 目录穿越利用） |
| `oss-webapps-cve.conf` | 50 | 1000901–1000950 | 开源 CMS/OA/框架公开利用面（WordPress/泛微/用友/通达/致远等） |
| `attack-coverage.conf` | 51 | 1001101–1001151 | 1001135–1001151 高危 CVE 补充应急段 |
| `unauth-access.conf` | 24 | 1001901–1001924 | 组件未授权管理面/中间件未授权访问/拖库特征（OBSERVE 级叠加计分，不单条阻断） |

CRS 兜底：944 系列（Java 攻击/反序列化）；932 系列（命令注入/RCE）；933 系列（PHP 注入）

go-ftw 回归测试：

- `unauth-access.conf`：[1001901.yaml](../../../test/waf/ftw/crs-tests/1001901.yaml)、[1001902.yaml](../../../test/waf/ftw/crs-tests/1001902.yaml)、[1001903.yaml](../../../test/waf/ftw/crs-tests/1001903.yaml)、[1001904.yaml](../../../test/waf/ftw/crs-tests/1001904.yaml)、[1001905.yaml](../../../test/waf/ftw/crs-tests/1001905.yaml)、[1001906.yaml](../../../test/waf/ftw/crs-tests/1001906.yaml)、[1001907.yaml](../../../test/waf/ftw/crs-tests/1001907.yaml)、[1001908.yaml](../../../test/waf/ftw/crs-tests/1001908.yaml)、[1001909.yaml](../../../test/waf/ftw/crs-tests/1001909.yaml)、[1001910.yaml](../../../test/waf/ftw/crs-tests/1001910.yaml)、[1001911.yaml](../../../test/waf/ftw/crs-tests/1001911.yaml)、[1001912.yaml](../../../test/waf/ftw/crs-tests/1001912.yaml)、[1001913.yaml](../../../test/waf/ftw/crs-tests/1001913.yaml)、[1001914.yaml](../../../test/waf/ftw/crs-tests/1001914.yaml)、[1001915.yaml](../../../test/waf/ftw/crs-tests/1001915.yaml)、[1001916.yaml](../../../test/waf/ftw/crs-tests/1001916.yaml)、[1001917.yaml](../../../test/waf/ftw/crs-tests/1001917.yaml)、[1001918.yaml](../../../test/waf/ftw/crs-tests/1001918.yaml)、[1001919.yaml](../../../test/waf/ftw/crs-tests/1001919.yaml)、[1001920.yaml](../../../test/waf/ftw/crs-tests/1001920.yaml)、[1001921.yaml](../../../test/waf/ftw/crs-tests/1001921.yaml)、[1001922.yaml](../../../test/waf/ftw/crs-tests/1001922.yaml)、[1001923.yaml](../../../test/waf/ftw/crs-tests/1001923.yaml)、[1001924.yaml](../../../test/waf/ftw/crs-tests/1001924.yaml)

- 归一化聚类：**1526** 类（按 标签信息+用例名称 归一化）

| 聚类（核心名） | 用例数 | 关联 CVE/CNVD |
|---|---|---|
| Apache Solr XML 实体注入(CVE-2017-12629) | 2 | CVE-2017-12629 |
| Ruby on Rails Sprockets任意文件读取(CVE-2018-3760) | 2 | CVE-2018-3760 |
| WebLogic未授权访问（CVE-2018-2894） | 2 | CVE-2018-2894 |
| .NET Framework - Leaking ObjRefs via HTTP .NET Remoting (CVE-2024-29059) | 1 | CVE-2024-29059 |
| 11in1 本地文件包含(CVE-2012-0996/CVE-2012-0997) | 1 | CVE-2012-0996, CVE-2012-0997 |
| 74cmsSE 任意文件读取（CVE-2022-26271） | 1 | CVE-2022-26271 |
| Accellion File Transfer Appliance 路径遍历(CVE-2015-2856) | 1 | CVE-2015-2856 |
| ACME Mini_httpd 任意文件读取漏洞 CVE-2018-18778 | 1 | CVE-2018-18778 |
| ACME mini_httpd 任意文件读取（CVE-2018-18778） | 1 | CVE-2018-18778 |
| Acrolinx Server for Windows 路径遍历漏洞（CVE-2018-7719） | 1 | CVE-2018-7719 |
| Adobe ColdFusion java反序列化漏洞（CVE-2017-3066） | 1 | CVE-2017-3066 |
| Adobe ColdFusion 文件读取（CVE-2010-2861） | 1 | CVE-2010-2861 |
| Adobe ColdFusion 目录遍历(CVE-2013-3336) | 1 | CVE-2013-3336 |
| Adobe ColdFusion管理控制台多个目录遍历漏洞（CVE-2010-2861） | 1 | CVE-2010-2861 |
| Advanced Comment System 1.0 - 目录遍历（CVE-2020-35598） | 1 | CVE-2020-35598 |
| Advanced Comment System 路径遍历漏洞（CVE-2020-35598） | 1 | CVE-2020-35598 |
| AfterLogic Aurora 路径遍历漏洞（CVE-2021-26293） | 1 | CVE-2021-26293 |
| AfterLogic WebMail 目录遍历漏洞（CVE-2021-26294） | 1 | CVE-2021-26294 |
| Agentejo Cockpit 跨站脚本攻击(CVE-2020-14408) | 1 | CVE-2020-14408 |
| AI Assistant with ChatGPT by AYS <= 2.0.9 - Unauthenticated AJAX Calls (CVE-2024-7714) | 1 | CVE-2024-7714 |
| …… 其余 1506 类从略 | | |

### XSS跨站脚本执行漏洞

- BAS 用例数：**893**（报告阻断 580 / 未阻断 313）
- 说明：BAS 以 GET/POST 反射型 XSS payload 集为主，CRS 941 主力，自研包补变种。

承担检测的自建规则包（CUSTOM_PACK）：

| 规则包文件 | 规则数 | 实际 ID 范围 | 承担内容 |
|---|---|---|---|
| `attack-variants-evasion.conf` | 99 | 1001201–1001299 | C 段 1001214–1001218（SVG/MathML/事件/实体编码）、N 段 1001267–1001270（srcdoc/mXSS/属性截断/模板字面量） |
| `injection-variants.conf` | 33 | 1001701–1001733 | 1001722–1001733 XSS 绕过变种（模板标签/事件处理器/GBK 宽字节/DOM sink 等） |

CRS 兜底：941 系列（XSS，主力）

go-ftw 回归测试：

- `injection-variants.conf`：[1001701.yaml](../../../test/waf/ftw/crs-tests/1001701.yaml)、[1001702.yaml](../../../test/waf/ftw/crs-tests/1001702.yaml)、[1001703.yaml](../../../test/waf/ftw/crs-tests/1001703.yaml)、[1001704.yaml](../../../test/waf/ftw/crs-tests/1001704.yaml)、[1001705.yaml](../../../test/waf/ftw/crs-tests/1001705.yaml)、[1001706.yaml](../../../test/waf/ftw/crs-tests/1001706.yaml)、[1001707.yaml](../../../test/waf/ftw/crs-tests/1001707.yaml)、[1001708.yaml](../../../test/waf/ftw/crs-tests/1001708.yaml)、[1001709.yaml](../../../test/waf/ftw/crs-tests/1001709.yaml)、[1001710.yaml](../../../test/waf/ftw/crs-tests/1001710.yaml)、[1001711.yaml](../../../test/waf/ftw/crs-tests/1001711.yaml)、[1001712.yaml](../../../test/waf/ftw/crs-tests/1001712.yaml)、[1001713.yaml](../../../test/waf/ftw/crs-tests/1001713.yaml)、[1001714.yaml](../../../test/waf/ftw/crs-tests/1001714.yaml)、[1001715.yaml](../../../test/waf/ftw/crs-tests/1001715.yaml)、[1001716.yaml](../../../test/waf/ftw/crs-tests/1001716.yaml)、[1001717.yaml](../../../test/waf/ftw/crs-tests/1001717.yaml)、[1001718.yaml](../../../test/waf/ftw/crs-tests/1001718.yaml)、[1001719.yaml](../../../test/waf/ftw/crs-tests/1001719.yaml)、[1001720.yaml](../../../test/waf/ftw/crs-tests/1001720.yaml)、[1001721.yaml](../../../test/waf/ftw/crs-tests/1001721.yaml)、[1001722.yaml](../../../test/waf/ftw/crs-tests/1001722.yaml)、[1001723.yaml](../../../test/waf/ftw/crs-tests/1001723.yaml)、[1001724.yaml](../../../test/waf/ftw/crs-tests/1001724.yaml)、[1001725.yaml](../../../test/waf/ftw/crs-tests/1001725.yaml)、[1001726.yaml](../../../test/waf/ftw/crs-tests/1001726.yaml)、[1001727.yaml](../../../test/waf/ftw/crs-tests/1001727.yaml)、[1001728.yaml](../../../test/waf/ftw/crs-tests/1001728.yaml)、[1001729.yaml](../../../test/waf/ftw/crs-tests/1001729.yaml)、[1001730.yaml](../../../test/waf/ftw/crs-tests/1001730.yaml)、[1001731.yaml](../../../test/waf/ftw/crs-tests/1001731.yaml)、[1001732.yaml](../../../test/waf/ftw/crs-tests/1001732.yaml)、[1001733.yaml](../../../test/waf/ftw/crs-tests/1001733.yaml)

- 归一化聚类：**880** 类（按 标签信息+用例名称 归一化）

| 聚类（核心名） | 用例数 | 关联 CVE/CNVD |
|---|---|---|
| GET跨站脚本攻击(XSS) | 10 | — |
| POST跨站脚本攻击(XSS) | 5 | — |
| 2 Click Socialmedia Buttons < 0.34 - Cross-Site Scripting (CVE-2012-4273) | 1 | CVE-2012-4273 |
| 74cms 跨站脚本漏洞（CVE-2022-41472） | 1 | CVE-2022-41472 |
| 8X8 Docker Jitsi Meet 跨站脚本漏洞（CVE-2021-26812） | 1 | CVE-2021-26812 |
| Aajoda Testimonials < 2.2.2 - Cross-Site Scripting (CVE-2023-2178) | 1 | CVE-2023-2178 |
| Academy Learning Management System <5.9.1 - Cross-Site Scripting (CVE-2022-38553) | 1 | CVE-2022-38553 |
| Academy LMS 6.0 - Cross-Site Scripting (CVE-2023-38964) | 1 | CVE-2023-38964 |
| Academy LMS 6.2 - Cross-Site Scripting (CVE-2023-4973) | 1 | CVE-2023-4973 |
| Accela Civic Platform 跨站脚本漏洞（CVE-2021-33904） | 1 | CVE-2021-33904 |
| Adiscon LogAnalyzer <4.1.7 - Cross-Site Scripting (CVE-2018-19877) | 1 | CVE-2018-19877 |
| Adiscon LogAnalyzer v.4.1.13 - Cross-Site Scripting (CVE-2023-36306) | 1 | CVE-2023-36306 |
| Admidio 跨站脚本漏洞（CVE-2021-43810） | 1 | CVE-2021-43810 |
| Adminer <=4.8.0 - Cross-Site Scripting (CVE-2021-29625) | 1 | CVE-2021-29625 |
| Adminimize 1.7.22 - Cross-Site Scripting (CVE-2011-4926) | 1 | CVE-2011-4926 |
| Adobe Coldfusion - Cross-Site Scripting (CVE-2023-44352) | 1 | CVE-2023-44352 |
| Adobe ColdFusion Server 服务器跨站脚本攻击漏洞（CVE-2009-1872） | 1 | CVE-2009-1872 |
| AdPush < 1.44 - Cross-Site Scripting (CVE-2017-18487) | 1 | CVE-2017-18487 |
| Advanced Custom Fields < 6.1.6 - Cross-Site Scripting (CVE-2023-30777) | 1 | CVE-2023-30777 |
| Advanced Text Widget < 2.0.2 - Cross-Site Scripting (CVE-2011-4618) | 1 | CVE-2011-4618 |
| …… 其余 860 类从略 | | |

### WebShell上传(流量)

- BAS 用例数：**636**（报告阻断 14 / 未阻断 622）
- 说明：BAS 覆盖各语言 WebShell 样本上传与连接流量，自研 WebShell 包群主力。

承担检测的自建规则包（CUSTOM_PACK）：

| 规则包文件 | 规则数 | 实际 ID 范围 | 承担内容 |
|---|---|---|---|
| `webshell.conf` | 34 | 1000101–1000134 | 一句话/菜刀/蚁剑/哥斯拉/冰蝎基础通信与上传特征、双扩展名与解析绕过 |
| `webshell-obfuscation.conf` | 39 | 1001001–1001040 | 加密/混淆/变种 WebShell（编码链、动态调用、密钥参数、工具协议痕迹） |
| `webshell-uploads.conf` | 26 | 1001301–1001326 | 上传通道专项：危险可执行扩展名/%00 截断/图片马/压缩包投递/multipart 反规避 |
| `webshell-content.conf` | 30 | 1001401–1001430 | WebShell 文件内容特征（JSP/ASP/ASPX/CFM/PERL/Python/SH 及跨语言一句话） |
| `attack-variants-evasion.conf` | 99 | 1001201–1001299 | J 段 1001245–1001249、T 段 1001289–1001293 WebShell/上传变种补强 |
| `bot-protocol.conf` | 35 | 1000701–1000735 | 上传与异常 Content-Type 段（可执行体/脚本类型上传） |

CRS 兜底：933 系列（PHP 注入，兜底）；922 系列（Multipart 攻击）

go-ftw 回归测试：

- `webshell-uploads.conf`：[1001301.yaml](../../../test/waf/ftw/crs-tests/1001301.yaml)、[1001302.yaml](../../../test/waf/ftw/crs-tests/1001302.yaml)、[1001303.yaml](../../../test/waf/ftw/crs-tests/1001303.yaml)、[1001304.yaml](../../../test/waf/ftw/crs-tests/1001304.yaml)、[1001305.yaml](../../../test/waf/ftw/crs-tests/1001305.yaml)、[1001306.yaml](../../../test/waf/ftw/crs-tests/1001306.yaml)、[1001307.yaml](../../../test/waf/ftw/crs-tests/1001307.yaml)、[1001308.yaml](../../../test/waf/ftw/crs-tests/1001308.yaml)、[1001309.yaml](../../../test/waf/ftw/crs-tests/1001309.yaml)、[1001310.yaml](../../../test/waf/ftw/crs-tests/1001310.yaml)、[1001311.yaml](../../../test/waf/ftw/crs-tests/1001311.yaml)、[1001312.yaml](../../../test/waf/ftw/crs-tests/1001312.yaml)、[1001313.yaml](../../../test/waf/ftw/crs-tests/1001313.yaml)、[1001314.yaml](../../../test/waf/ftw/crs-tests/1001314.yaml)、[1001315.yaml](../../../test/waf/ftw/crs-tests/1001315.yaml)、[1001316.yaml](../../../test/waf/ftw/crs-tests/1001316.yaml)、[1001317.yaml](../../../test/waf/ftw/crs-tests/1001317.yaml)、[1001318.yaml](../../../test/waf/ftw/crs-tests/1001318.yaml)、[1001319.yaml](../../../test/waf/ftw/crs-tests/1001319.yaml)、[1001320.yaml](../../../test/waf/ftw/crs-tests/1001320.yaml)、[1001321.yaml](../../../test/waf/ftw/crs-tests/1001321.yaml)、[1001322.yaml](../../../test/waf/ftw/crs-tests/1001322.yaml)、[1001323.yaml](../../../test/waf/ftw/crs-tests/1001323.yaml)、[1001324.yaml](../../../test/waf/ftw/crs-tests/1001324.yaml)、[1001325.yaml](../../../test/waf/ftw/crs-tests/1001325.yaml)、[1001326.yaml](../../../test/waf/ftw/crs-tests/1001326.yaml)
- `webshell-content.conf`：[1001401.yaml](../../../test/waf/ftw/crs-tests/1001401.yaml)、[1001402.yaml](../../../test/waf/ftw/crs-tests/1001402.yaml)、[1001403.yaml](../../../test/waf/ftw/crs-tests/1001403.yaml)、[1001404.yaml](../../../test/waf/ftw/crs-tests/1001404.yaml)、[1001405.yaml](../../../test/waf/ftw/crs-tests/1001405.yaml)、[1001406.yaml](../../../test/waf/ftw/crs-tests/1001406.yaml)、[1001407.yaml](../../../test/waf/ftw/crs-tests/1001407.yaml)、[1001408.yaml](../../../test/waf/ftw/crs-tests/1001408.yaml)、[1001409.yaml](../../../test/waf/ftw/crs-tests/1001409.yaml)、[1001410.yaml](../../../test/waf/ftw/crs-tests/1001410.yaml)、[1001411.yaml](../../../test/waf/ftw/crs-tests/1001411.yaml)、[1001412.yaml](../../../test/waf/ftw/crs-tests/1001412.yaml)、[1001413.yaml](../../../test/waf/ftw/crs-tests/1001413.yaml)、[1001414.yaml](../../../test/waf/ftw/crs-tests/1001414.yaml)、[1001415.yaml](../../../test/waf/ftw/crs-tests/1001415.yaml)、[1001416.yaml](../../../test/waf/ftw/crs-tests/1001416.yaml)、[1001417.yaml](../../../test/waf/ftw/crs-tests/1001417.yaml)、[1001418.yaml](../../../test/waf/ftw/crs-tests/1001418.yaml)、[1001419.yaml](../../../test/waf/ftw/crs-tests/1001419.yaml)、[1001420.yaml](../../../test/waf/ftw/crs-tests/1001420.yaml)、[1001421.yaml](../../../test/waf/ftw/crs-tests/1001421.yaml)、[1001422.yaml](../../../test/waf/ftw/crs-tests/1001422.yaml)、[1001423.yaml](../../../test/waf/ftw/crs-tests/1001423.yaml)、[1001424.yaml](../../../test/waf/ftw/crs-tests/1001424.yaml)、[1001425.yaml](../../../test/waf/ftw/crs-tests/1001425.yaml)、[1001426.yaml](../../../test/waf/ftw/crs-tests/1001426.yaml)、[1001427.yaml](../../../test/waf/ftw/crs-tests/1001427.yaml)、[1001428.yaml](../../../test/waf/ftw/crs-tests/1001428.yaml)、[1001429.yaml](../../../test/waf/ftw/crs-tests/1001429.yaml)、[1001430.yaml](../../../test/waf/ftw/crs-tests/1001430.yaml)

- 归一化聚类：**636** 类（按 标签信息+用例名称 归一化）

| 聚类（核心名） | 用例数 | 关联 CVE/CNVD |
|---|---|---|
| 2eba6bfd79ceb61c7f9dcb3e85d9c597 WebShell | 1 | — |
| aspx类型webshell（变形） | 1 | — |
| asp类型webshell | 1 | — |
| asp类型webshell（变形） | 1 | — |
| C99madShell v. 3.0 BLOG edition WebShell | 1 | — |
| Dark Shell WebShell | 1 | — |
| godzilla_webshell（变形） | 1 | — |
| h0ld-up-team web-shell WebShell | 1 | — |
| jsp类型webshell | 1 | — |
| K2LL33D SHELL WebShell | 1 | — |
| KA_uShell_0.1.6WebShell | 1 | — |
| Nshell (1).php WebShell | 1 | — |
| PHP Shell WebShell | 1 | — |
| root.shell WebShell | 1 | — |
| W3D webshell | 1 | — |
| WebShell | 1 | — |
| WebShell_ASHX_哥斯拉变种_1 | 1 | — |
| WebShell_ASHX_大马 | 1 | — |
| WebShell_ASMX_哥斯拉变种_1 | 1 | — |
| WebShell_ASMX_大马 | 1 | — |
| …… 其余 616 类从略 | | |

### SQL注入漏洞

- BAS 用例数：**497**（报告阻断 314 / 未阻断 183）
- 说明：BAS 含组件 SQLi CVE 与通用注入 payload，CRS 942 主力，自研包补变形绕过。

承担检测的自建规则包（CUSTOM_PACK）：

| 规则包文件 | 规则数 | 实际 ID 范围 | 承担内容 |
|---|---|---|---|
| `attack-variants-evasion.conf` | 99 | 1001201–1001299 | B 段 1001207–1001213（UNION/盲注/内嵌变形）、M 段 1001260–1001266（OOB/条件注释/HPP/二次编码） |
| `attack-coverage.conf` | 51 | 1001101–1001151 | 1001129–1001134 NoSQL/LDAP 注入（同类注入面） |
| `injection-variants.conf` | 33 | 1001701–1001733 | 1001701–1001711 SQLi 绕过变种（版本注释/等价函数/GBK 宽字节/时间盲注变形等） |

CRS 兜底：942 系列（SQLi，主力）

go-ftw 回归测试：

- `injection-variants.conf`：[1001701.yaml](../../../test/waf/ftw/crs-tests/1001701.yaml)、[1001702.yaml](../../../test/waf/ftw/crs-tests/1001702.yaml)、[1001703.yaml](../../../test/waf/ftw/crs-tests/1001703.yaml)、[1001704.yaml](../../../test/waf/ftw/crs-tests/1001704.yaml)、[1001705.yaml](../../../test/waf/ftw/crs-tests/1001705.yaml)、[1001706.yaml](../../../test/waf/ftw/crs-tests/1001706.yaml)、[1001707.yaml](../../../test/waf/ftw/crs-tests/1001707.yaml)、[1001708.yaml](../../../test/waf/ftw/crs-tests/1001708.yaml)、[1001709.yaml](../../../test/waf/ftw/crs-tests/1001709.yaml)、[1001710.yaml](../../../test/waf/ftw/crs-tests/1001710.yaml)、[1001711.yaml](../../../test/waf/ftw/crs-tests/1001711.yaml)、[1001712.yaml](../../../test/waf/ftw/crs-tests/1001712.yaml)、[1001713.yaml](../../../test/waf/ftw/crs-tests/1001713.yaml)、[1001714.yaml](../../../test/waf/ftw/crs-tests/1001714.yaml)、[1001715.yaml](../../../test/waf/ftw/crs-tests/1001715.yaml)、[1001716.yaml](../../../test/waf/ftw/crs-tests/1001716.yaml)、[1001717.yaml](../../../test/waf/ftw/crs-tests/1001717.yaml)、[1001718.yaml](../../../test/waf/ftw/crs-tests/1001718.yaml)、[1001719.yaml](../../../test/waf/ftw/crs-tests/1001719.yaml)、[1001720.yaml](../../../test/waf/ftw/crs-tests/1001720.yaml)、[1001721.yaml](../../../test/waf/ftw/crs-tests/1001721.yaml)、[1001722.yaml](../../../test/waf/ftw/crs-tests/1001722.yaml)、[1001723.yaml](../../../test/waf/ftw/crs-tests/1001723.yaml)、[1001724.yaml](../../../test/waf/ftw/crs-tests/1001724.yaml)、[1001725.yaml](../../../test/waf/ftw/crs-tests/1001725.yaml)、[1001726.yaml](../../../test/waf/ftw/crs-tests/1001726.yaml)、[1001727.yaml](../../../test/waf/ftw/crs-tests/1001727.yaml)、[1001728.yaml](../../../test/waf/ftw/crs-tests/1001728.yaml)、[1001729.yaml](../../../test/waf/ftw/crs-tests/1001729.yaml)、[1001730.yaml](../../../test/waf/ftw/crs-tests/1001730.yaml)、[1001731.yaml](../../../test/waf/ftw/crs-tests/1001731.yaml)、[1001732.yaml](../../../test/waf/ftw/crs-tests/1001732.yaml)、[1001733.yaml](../../../test/waf/ftw/crs-tests/1001733.yaml)

- 归一化聚类：**497** 类（按 标签信息+用例名称 归一化）

| 聚类（核心名） | 用例数 | 关联 CVE/CNVD |
|---|---|---|
| 1Panel SQL Injection - Authenticated (CVE-2024-39907) | 1 | CVE-2024-39907 |
| 360天擎 - sql注入 | 1 | — |
| 404 to 301 <= 2.0.2 - Authenticated Blind SQL Injection (CVE-2015-9323) | 1 | CVE-2015-9323 |
| Academy LMS 6.2 - SQL Injection (CVE-2023-4974) | 1 | CVE-2023-4974 |
| Adobe Magento SQL注入漏洞 （CVE-2020-24400） | 1 | CVE-2020-24400 |
| AEGON-LIFEv1.0存在SQL注入漏洞(CVE-2024-36597) | 1 | CVE-2024-36597 |
| Agentejo Cockpit SQL注入漏洞（CVE-2020-35846） | 1 | CVE-2020-35846 |
| AnteeoWMS < v4.7.34 - SQL Injection (CVE-2024-44349) | 1 | CVE-2024-44349 |
| Apache SkyWalking graphq SQL注入 | 1 | — |
| Apache SkyWalking SQL注入漏洞（CVE-2020-13921） | 1 | CVE-2020-13921 |
| Apache SkyWalking SQL注入（CVE-2020-9483） | 1 | CVE-2020-9483 |
| Apache StreamPark SQL 注入漏洞(CVE-2023-52290) | 1 | CVE-2023-52290 |
| Apache Superset < 4.0.2 - SQL Injection (CVE-2024-39887) | 1 | CVE-2024-39887 |
| AP Pricing Tables Lite <= 1.1.6 - SQL Injection (CVE-2023-0900) | 1 | CVE-2023-0900 |
| ArticaTech Artica Web Proxy SQL注入漏洞（CVE-2020-17506） | 1 | CVE-2020-17506 |
| ASIS - SQL Injection Authentication Bypass (CVE-2024-45622) | 1 | CVE-2024-45622 |
| Atom.CMS 2.0 - SQL Injection (CVE-2022-28033) | 1 | CVE-2022-28033 |
| Atom CMS SQL注入（CVE-2022-25488） | 1 | CVE-2022-25488 |
| Atom CMS v2.0 - SQL Injection (CVE-2022-28032) | 1 | CVE-2022-28032 |
| Automation By Autonami < 3.3.0 - SQL Injection (CVE-2024-9186) | 1 | CVE-2024-9186 |
| …… 其余 477 类从略 | | |

### 任意文件包含漏洞

- BAS 用例数：**343**（报告阻断 175 / 未阻断 168）
- 说明：BAS 以读取 /etc/*、win.ini、伪协议 base64 等 LFI payload 为主。

承担检测的自建规则包（CUSTOM_PACK）：

| 规则包文件 | 规则数 | 实际 ID 范围 | 承担内容 |
|---|---|---|---|
| `attack-variants-evasion.conf` | 99 | 1001201–1001299 | E 段 1001224–1001228 LFI/RFI/路径变种（含伪协议） |
| `sensitive-exposure.conf` | 40 | 1000501–1000540 | 敏感文件路径直接访问（/etc/passwd、win.ini、备份等） |
| `xxe-lfi-variants.conf` | 29 | 1001601–1001629 | B 段 PHP 伪协议变种、C 段本地敏感文件目标、E 段空字节截断变种 |

CRS 兜底：930 系列（LFI，主力）；931 系列（RFI）

go-ftw 回归测试：

- `xxe-lfi-variants.conf`：[1001601.yaml](../../../test/waf/ftw/crs-tests/1001601.yaml)、[1001602.yaml](../../../test/waf/ftw/crs-tests/1001602.yaml)、[1001603.yaml](../../../test/waf/ftw/crs-tests/1001603.yaml)、[1001604.yaml](../../../test/waf/ftw/crs-tests/1001604.yaml)、[1001605.yaml](../../../test/waf/ftw/crs-tests/1001605.yaml)、[1001606.yaml](../../../test/waf/ftw/crs-tests/1001606.yaml)、[1001607.yaml](../../../test/waf/ftw/crs-tests/1001607.yaml)、[1001608.yaml](../../../test/waf/ftw/crs-tests/1001608.yaml)、[1001609.yaml](../../../test/waf/ftw/crs-tests/1001609.yaml)、[1001610.yaml](../../../test/waf/ftw/crs-tests/1001610.yaml)、[1001611.yaml](../../../test/waf/ftw/crs-tests/1001611.yaml)、[1001612.yaml](../../../test/waf/ftw/crs-tests/1001612.yaml)、[1001613.yaml](../../../test/waf/ftw/crs-tests/1001613.yaml)、[1001614.yaml](../../../test/waf/ftw/crs-tests/1001614.yaml)、[1001615.yaml](../../../test/waf/ftw/crs-tests/1001615.yaml)、[1001616.yaml](../../../test/waf/ftw/crs-tests/1001616.yaml)、[1001617.yaml](../../../test/waf/ftw/crs-tests/1001617.yaml)、[1001618.yaml](../../../test/waf/ftw/crs-tests/1001618.yaml)、[1001619.yaml](../../../test/waf/ftw/crs-tests/1001619.yaml)、[1001620.yaml](../../../test/waf/ftw/crs-tests/1001620.yaml)、[1001621.yaml](../../../test/waf/ftw/crs-tests/1001621.yaml)、[1001622.yaml](../../../test/waf/ftw/crs-tests/1001622.yaml)、[1001623.yaml](../../../test/waf/ftw/crs-tests/1001623.yaml)、[1001624.yaml](../../../test/waf/ftw/crs-tests/1001624.yaml)、[1001625.yaml](../../../test/waf/ftw/crs-tests/1001625.yaml)、[1001626.yaml](../../../test/waf/ftw/crs-tests/1001626.yaml)、[1001627.yaml](../../../test/waf/ftw/crs-tests/1001627.yaml)、[1001628.yaml](../../../test/waf/ftw/crs-tests/1001628.yaml)、[1001629.yaml](../../../test/waf/ftw/crs-tests/1001629.yaml)

- 归一化聚类：**343** 类（按 标签信息+用例名称 归一化）

| 聚类（核心名） | 用例数 | 关联 CVE/CNVD |
|---|---|---|
| 11in1 CMS 1.2.1 - Local File Inclusion (LFI) (CVE-2012-0996) | 1 | CVE-2012-0996 |
| Adobe-ColdFusion任意文件读取漏洞CVE-2024-20767 | 1 | CVE-2024-20767 |
| Allied Telesis AT-GS950/8 - Local File Inclusion (CVE-2019-18922) | 1 | CVE-2019-18922 |
| AlquistManager Local File Inclusion (CVE-2021-43495) | 1 | CVE-2021-43495 |
| Apache OFBiz < 18.12.07 - Local File Inclusion (CVE-2022-47501) | 1 | CVE-2022-47501 |
| Aria2 WebUI - Path traversal (CVE-2023-39141) | 1 | CVE-2023-39141 |
| Atlassian Confluence Download Attachments - Remote Code Execution (CVE-2019-3398) | 1 | CVE-2019-3398 |
| Atlassian Jira Limited - Local File Inclusion (CVE-2021-26086) | 1 | CVE-2021-26086 |
| Belkin N150 Router 1.00.08/1.00.09 - Path Traversal (CVE-2014-2962) | 1 | CVE-2014-2962 |
| Camaleon CMS < 2.8.1 Arbitrary File Write to RCE (CVE-2024-46986) | 1 | CVE-2024-46986 |
| CData API Server < 23.4.8844 - Path Traversal (CVE-2024-31848) | 1 | CVE-2024-31848 |
| CData Arc < 23.4.8839 - Path Traversal (CVE-2024-31850) | 1 | CVE-2024-31850 |
| CData Connect < 23.4.8846 - Path Traversal (CVE-2024-31849) | 1 | CVE-2024-31849 |
| CData Sync < 23.4.8843 - Path Traversal (CVE-2024-31851) | 1 | CVE-2024-31851 |
| Centos Web Panel 0.9.8.480 - Local File Inclusion (CVE-2018-18323) | 1 | CVE-2018-18323 |
| cgit < 1.2.1 - Directory Traversal (CVE-2018-14912) | 1 | CVE-2018-14912 |
| Changedetection.io <= 0.47.4 - Path Traversal (CVE-2024-51483) | 1 | CVE-2024-51483 |
| Check-Point安全网关任意文件读取漏洞(CVE-2024-24919) | 1 | CVE-2024-24919 |
| Chuanhu Chat - Directory Traversal (CVE-2024-3234) | 1 | CVE-2024-3234 |
| Chyrp 2.x - Local File Inclusion (CVE-2011-2780) | 1 | CVE-2011-2780 |
| …… 其余 323 类从略 | | |

### 命令注入漏洞

- BAS 用例数：**321**（报告阻断 104 / 未阻断 217）
- 说明：BAS 含组件命令执行 CVE 与通用命令注入 payload，CRS 932 主力。

承担检测的自建规则包（CUSTOM_PACK）：

| 规则包文件 | 规则数 | 实际 ID 范围 | 承担内容 |
|---|---|---|---|
| `attack-variants-evasion.conf` | 99 | 1001201–1001299 | D 段 1001219–1001223（分隔符/反引号/PowerShell 编码）、O 段 1001271–1001274（Windows/brace/进程替换/解释器） |
| `deserialization-rce.conf` | 48 | 1000601–1000648 | LOLBins 与表达式/命令拼接补充段 |
| `injection-variants.conf` | 33 | 1001701–1001733 | 1001712–1001721 命令注入绕过变种（IFS/环境变量切片/大括号扩展/八进制编码等） |

CRS 兜底：932 系列（RCE，主力）

go-ftw 回归测试：

- `deserialization-rce.conf`：[1000631.yaml](../../../test/waf/ftw/crs-tests/1000631.yaml)、[1000632.yaml](../../../test/waf/ftw/crs-tests/1000632.yaml)、[1000633.yaml](../../../test/waf/ftw/crs-tests/1000633.yaml)、[1000634.yaml](../../../test/waf/ftw/crs-tests/1000634.yaml)、[1000635.yaml](../../../test/waf/ftw/crs-tests/1000635.yaml)、[1000636.yaml](../../../test/waf/ftw/crs-tests/1000636.yaml)、[1000637.yaml](../../../test/waf/ftw/crs-tests/1000637.yaml)、[1000638.yaml](../../../test/waf/ftw/crs-tests/1000638.yaml)、[1000639.yaml](../../../test/waf/ftw/crs-tests/1000639.yaml)、[1000640.yaml](../../../test/waf/ftw/crs-tests/1000640.yaml)、[1000641.yaml](../../../test/waf/ftw/crs-tests/1000641.yaml)、[1000642.yaml](../../../test/waf/ftw/crs-tests/1000642.yaml)、[1000643.yaml](../../../test/waf/ftw/crs-tests/1000643.yaml)、[1000644.yaml](../../../test/waf/ftw/crs-tests/1000644.yaml)、[1000645.yaml](../../../test/waf/ftw/crs-tests/1000645.yaml)、[1000646.yaml](../../../test/waf/ftw/crs-tests/1000646.yaml)、[1000647.yaml](../../../test/waf/ftw/crs-tests/1000647.yaml)、[1000648.yaml](../../../test/waf/ftw/crs-tests/1000648.yaml)
- `injection-variants.conf`：[1001701.yaml](../../../test/waf/ftw/crs-tests/1001701.yaml)、[1001702.yaml](../../../test/waf/ftw/crs-tests/1001702.yaml)、[1001703.yaml](../../../test/waf/ftw/crs-tests/1001703.yaml)、[1001704.yaml](../../../test/waf/ftw/crs-tests/1001704.yaml)、[1001705.yaml](../../../test/waf/ftw/crs-tests/1001705.yaml)、[1001706.yaml](../../../test/waf/ftw/crs-tests/1001706.yaml)、[1001707.yaml](../../../test/waf/ftw/crs-tests/1001707.yaml)、[1001708.yaml](../../../test/waf/ftw/crs-tests/1001708.yaml)、[1001709.yaml](../../../test/waf/ftw/crs-tests/1001709.yaml)、[1001710.yaml](../../../test/waf/ftw/crs-tests/1001710.yaml)、[1001711.yaml](../../../test/waf/ftw/crs-tests/1001711.yaml)、[1001712.yaml](../../../test/waf/ftw/crs-tests/1001712.yaml)、[1001713.yaml](../../../test/waf/ftw/crs-tests/1001713.yaml)、[1001714.yaml](../../../test/waf/ftw/crs-tests/1001714.yaml)、[1001715.yaml](../../../test/waf/ftw/crs-tests/1001715.yaml)、[1001716.yaml](../../../test/waf/ftw/crs-tests/1001716.yaml)、[1001717.yaml](../../../test/waf/ftw/crs-tests/1001717.yaml)、[1001718.yaml](../../../test/waf/ftw/crs-tests/1001718.yaml)、[1001719.yaml](../../../test/waf/ftw/crs-tests/1001719.yaml)、[1001720.yaml](../../../test/waf/ftw/crs-tests/1001720.yaml)、[1001721.yaml](../../../test/waf/ftw/crs-tests/1001721.yaml)、[1001722.yaml](../../../test/waf/ftw/crs-tests/1001722.yaml)、[1001723.yaml](../../../test/waf/ftw/crs-tests/1001723.yaml)、[1001724.yaml](../../../test/waf/ftw/crs-tests/1001724.yaml)、[1001725.yaml](../../../test/waf/ftw/crs-tests/1001725.yaml)、[1001726.yaml](../../../test/waf/ftw/crs-tests/1001726.yaml)、[1001727.yaml](../../../test/waf/ftw/crs-tests/1001727.yaml)、[1001728.yaml](../../../test/waf/ftw/crs-tests/1001728.yaml)、[1001729.yaml](../../../test/waf/ftw/crs-tests/1001729.yaml)、[1001730.yaml](../../../test/waf/ftw/crs-tests/1001730.yaml)、[1001731.yaml](../../../test/waf/ftw/crs-tests/1001731.yaml)、[1001732.yaml](../../../test/waf/ftw/crs-tests/1001732.yaml)、[1001733.yaml](../../../test/waf/ftw/crs-tests/1001733.yaml)

- 归一化聚类：**321** 类（按 标签信息+用例名称 归一化）

| 聚类（核心名） | 用例数 | 关联 CVE/CNVD |
|---|---|---|
| 1Panel面板最新前台RCE漏洞(CVE-2024-39911) | 1 | CVE-2024-39911 |
| Advantech iView 命令注入漏洞（CVE-2022-2143） | 1 | CVE-2022-2143 |
| Altenergy Power System Control命令执行漏洞(CVE-2023-28343) | 1 | CVE-2023-28343 |
| Apache ActiveMQ jolokia 代码执行漏洞（CVE-2022-41678） | 1 | CVE-2022-41678 |
| Apache Airflow OS命令注入（CVE-2022-24288） | 1 | CVE-2022-24288 |
| Apache AXIS 远程命令执行漏洞（CVE-2019-0227） | 1 | CVE-2019-0227 |
| Apache Camel 任意命令执行漏洞(CVE-2025-29891) | 1 | CVE-2025-29891 |
| Apache Druid 命令执行漏洞 CVE-2021-25646 | 1 | CVE-2021-25646 |
| Apache Druid 命令执行（CVE-2021-25646） | 1 | CVE-2021-25646 |
| Apache Kylin 命令注入漏洞 CVE-2020-1956 | 1 | CVE-2020-1956 |
| Apache Kylin命令注入漏洞（CVE-2020-13925） | 1 | CVE-2020-13925 |
| Apache Kylin 远程命令执行漏洞 CVE-2020-13925 | 1 | CVE-2020-13925 |
| Apache Kylin远程命令执行漏洞（CVE-2020-1956） | 1 | CVE-2020-1956 |
| Apache OFBiz 未授权命令执行 (CVE-2023-51467) | 1 | CVE-2023-51467 |
| Apache Ofbiz 远程命令执行漏洞 CVE-2020-9496 | 1 | CVE-2020-9496 |
| Apache Solr ConfigSet 代码执行漏洞（CVE-2023-50386） | 1 | CVE-2023-50386 |
| Apache Solr Velocity 注入远程命令执行（CVE-2019-17558） | 1 | CVE-2019-17558 |
| Apache Solr 远程命令执行漏洞 CVE-2019-0193 | 1 | CVE-2019-0193 |
| Apache Spark命令执行漏洞（CVE-2023-32007） | 1 | CVE-2023-32007 |
| Apache Tika-server 命令执行漏洞（CVE-2018-1335） | 1 | CVE-2018-1335 |
| …… 其余 301 类从略 | | |

### 任意文件上传漏洞

- BAS 用例数：**199**（报告阻断 88 / 未阻断 111）
- 说明：BAS 以 OA/CMS 上传 CVE 与可执行体上传为主。

承担检测的自建规则包（CUSTOM_PACK）：

| 规则包文件 | 规则数 | 实际 ID 范围 | 承担内容 |
|---|---|---|---|
| `webshell.conf` | 34 | 1000101–1000134 | 双扩展名/解析绕过、上传内容 WebShell 代码、配置文件上传绕过段 |
| `webshell-uploads.conf` | 26 | 1001301–1001326 | 上传通道专项：危险可执行扩展名/%00 截断/图片马/压缩包投递/multipart 反规避 |
| `webshell-content.conf` | 30 | 1001401–1001430 | 上传体中跨语言 WebShell 内容特征 |
| `bot-protocol.conf` | 35 | 1000701–1000735 | 上传与异常 Content-Type 段 |
| `oss-webapps-cve.conf` | 50 | 1000901–1000950 | OA/CMS 任意文件上传 CVE（泛微/用友/通达/致远/帆软等） |
| `attack-variants-evasion.conf` | 99 | 1001201–1001299 | J 段 1001245–1001249、T 段 1001289–1001293 上传变种补强 |

CRS 兜底：922 系列（Multipart 攻击）；920 系列（协议约束）

go-ftw 回归测试：

- `webshell-uploads.conf`：[1001301.yaml](../../../test/waf/ftw/crs-tests/1001301.yaml)、[1001302.yaml](../../../test/waf/ftw/crs-tests/1001302.yaml)、[1001303.yaml](../../../test/waf/ftw/crs-tests/1001303.yaml)、[1001304.yaml](../../../test/waf/ftw/crs-tests/1001304.yaml)、[1001305.yaml](../../../test/waf/ftw/crs-tests/1001305.yaml)、[1001306.yaml](../../../test/waf/ftw/crs-tests/1001306.yaml)、[1001307.yaml](../../../test/waf/ftw/crs-tests/1001307.yaml)、[1001308.yaml](../../../test/waf/ftw/crs-tests/1001308.yaml)、[1001309.yaml](../../../test/waf/ftw/crs-tests/1001309.yaml)、[1001310.yaml](../../../test/waf/ftw/crs-tests/1001310.yaml)、[1001311.yaml](../../../test/waf/ftw/crs-tests/1001311.yaml)、[1001312.yaml](../../../test/waf/ftw/crs-tests/1001312.yaml)、[1001313.yaml](../../../test/waf/ftw/crs-tests/1001313.yaml)、[1001314.yaml](../../../test/waf/ftw/crs-tests/1001314.yaml)、[1001315.yaml](../../../test/waf/ftw/crs-tests/1001315.yaml)、[1001316.yaml](../../../test/waf/ftw/crs-tests/1001316.yaml)、[1001317.yaml](../../../test/waf/ftw/crs-tests/1001317.yaml)、[1001318.yaml](../../../test/waf/ftw/crs-tests/1001318.yaml)、[1001319.yaml](../../../test/waf/ftw/crs-tests/1001319.yaml)、[1001320.yaml](../../../test/waf/ftw/crs-tests/1001320.yaml)、[1001321.yaml](../../../test/waf/ftw/crs-tests/1001321.yaml)、[1001322.yaml](../../../test/waf/ftw/crs-tests/1001322.yaml)、[1001323.yaml](../../../test/waf/ftw/crs-tests/1001323.yaml)、[1001324.yaml](../../../test/waf/ftw/crs-tests/1001324.yaml)、[1001325.yaml](../../../test/waf/ftw/crs-tests/1001325.yaml)、[1001326.yaml](../../../test/waf/ftw/crs-tests/1001326.yaml)
- `webshell-content.conf`：[1001401.yaml](../../../test/waf/ftw/crs-tests/1001401.yaml)、[1001402.yaml](../../../test/waf/ftw/crs-tests/1001402.yaml)、[1001403.yaml](../../../test/waf/ftw/crs-tests/1001403.yaml)、[1001404.yaml](../../../test/waf/ftw/crs-tests/1001404.yaml)、[1001405.yaml](../../../test/waf/ftw/crs-tests/1001405.yaml)、[1001406.yaml](../../../test/waf/ftw/crs-tests/1001406.yaml)、[1001407.yaml](../../../test/waf/ftw/crs-tests/1001407.yaml)、[1001408.yaml](../../../test/waf/ftw/crs-tests/1001408.yaml)、[1001409.yaml](../../../test/waf/ftw/crs-tests/1001409.yaml)、[1001410.yaml](../../../test/waf/ftw/crs-tests/1001410.yaml)、[1001411.yaml](../../../test/waf/ftw/crs-tests/1001411.yaml)、[1001412.yaml](../../../test/waf/ftw/crs-tests/1001412.yaml)、[1001413.yaml](../../../test/waf/ftw/crs-tests/1001413.yaml)、[1001414.yaml](../../../test/waf/ftw/crs-tests/1001414.yaml)、[1001415.yaml](../../../test/waf/ftw/crs-tests/1001415.yaml)、[1001416.yaml](../../../test/waf/ftw/crs-tests/1001416.yaml)、[1001417.yaml](../../../test/waf/ftw/crs-tests/1001417.yaml)、[1001418.yaml](../../../test/waf/ftw/crs-tests/1001418.yaml)、[1001419.yaml](../../../test/waf/ftw/crs-tests/1001419.yaml)、[1001420.yaml](../../../test/waf/ftw/crs-tests/1001420.yaml)、[1001421.yaml](../../../test/waf/ftw/crs-tests/1001421.yaml)、[1001422.yaml](../../../test/waf/ftw/crs-tests/1001422.yaml)、[1001423.yaml](../../../test/waf/ftw/crs-tests/1001423.yaml)、[1001424.yaml](../../../test/waf/ftw/crs-tests/1001424.yaml)、[1001425.yaml](../../../test/waf/ftw/crs-tests/1001425.yaml)、[1001426.yaml](../../../test/waf/ftw/crs-tests/1001426.yaml)、[1001427.yaml](../../../test/waf/ftw/crs-tests/1001427.yaml)、[1001428.yaml](../../../test/waf/ftw/crs-tests/1001428.yaml)、[1001429.yaml](../../../test/waf/ftw/crs-tests/1001429.yaml)、[1001430.yaml](../../../test/waf/ftw/crs-tests/1001430.yaml)

- 归一化聚类：**199** 类（按 标签信息+用例名称 归一化）

| 聚类（核心名） | 用例数 | 关联 CVE/CNVD |
|---|---|---|
| 3DPrint Lite < 1.9.1.5 - Arbitrary File Upload (CVE-2021-4436) | 1 | CVE-2021-4436 |
| Adobe ColdFusion 文件上传漏洞（CVE-2018-15961） | 1 | CVE-2018-15961 |
| apache flink任意文件上传漏洞(CVE-2020-17518) | 1 | CVE-2020-17518 |
| Apache HTTPd安全特性绕过漏洞（CVE-2017-15715） | 1 | CVE-2017-15715 |
| Apache Solr 未授权上传漏洞（CVE-2020-13957） | 1 | CVE-2020-13957 |
| Apache Struts CVE-2024-53677 文件上传漏洞 | 1 | CVE-2024-53677 |
| Apache Struts文件上传漏洞（CVE-2023-50164） | 1 | CVE-2023-50164 |
| Atom CMS v2.0 - Remote Code Execution (CVE-2022-25487) | 1 | CVE-2022-25487 |
| ATutor学习内容管理系统 任意文件上传漏洞（CVE-2019-12169） | 1 | CVE-2019-12169 |
| Badaso upload 任意文件上传漏洞（CVE-2022-41711） | 1 | CVE-2022-41711 |
| Cisco HyperFlex HX Data Platform文件上传漏洞（CVE-2021-1499） | 1 | CVE-2021-1499 |
| Cisco Small Business RV授权问题漏洞（CVE-2021-1472） | 1 | CVE-2021-1472 |
| Cleo Harmony < 5.8.0.21 - Arbitary File Read (CVE-2024-50623) | 1 | CVE-2024-50623 |
| CloudPanel makefile 任意文件上传漏洞 CVE-2023-35885 | 1 | CVE-2023-35885 |
| CMS Made Simple 代码问题漏洞（CVE-2022-23906） | 1 | CVE-2022-23906 |
| Cockpit < 2.4.1 - Arbitrary 文件上传漏洞 （CVE-2025-1025） | 1 | CVE-2025-1025 |
| Codoforum 5.1 - Arbitrary File Upload (CVE-2022-31854) | 1 | CVE-2022-31854 |
| Coremail /webinst/action.jsp 文件上传漏洞 | 1 | — |
| Cuppa CMS v1.0 - Arbitrary File Upload (CVE-2022-38296) | 1 | CVE-2022-38296 |
| Desdev DedeCMS 安全漏洞（CVE-2019-8933） | 1 | CVE-2019-8933 |
| …… 其余 179 类从略 | | |

### 反序列化远程命令执行漏洞

- BAS 用例数：**52**（报告阻断 4 / 未阻断 48）
- 说明：BAS 覆盖 Java/PHP 反序列化 CVE（WebLogic/JBoss/Fastjson/Yii2 等）。

承担检测的自建规则包（CUSTOM_PACK）：

| 规则包文件 | 规则数 | 实际 ID 范围 | 承担内容 |
|---|---|---|---|
| `deserialization-rce.conf` | 48 | 1000601–1000648 | Java/PHP/Python/.NET/YAML/OGNL 反序列化与表达式注入 |
| `attack-coverage.conf` | 51 | 1001101–1001151 | 1001101–1001115 SSTI 引擎级特征 |
| `ssti-injection.conf` | 16 | 1001801–1001816 | 1001801–1001816 SSTI 专项（Freemarker/Velocity/Thymeleaf·SpEL/Jinja2/Twig/ERB/Mako/Groovy/EL 模板注入，归入本类与既有 SSTI 归属一致） |
| `cve-emergency.conf` | 42 | 1000001–1000042 | Fastjson/Shiro/WebLogic 等应急 CVE |
| `attack-variants-evasion.conf` | 99 | 1001201–1001299 | P 段 1001275–1001277 SSTI/EL 变种、R 段 1001281–1001284 反序列化变种 |

CRS 兜底：944 系列（Java 反序列化/Log4j）

go-ftw 回归测试：

- `deserialization-rce.conf`：[1000631.yaml](../../../test/waf/ftw/crs-tests/1000631.yaml)、[1000632.yaml](../../../test/waf/ftw/crs-tests/1000632.yaml)、[1000633.yaml](../../../test/waf/ftw/crs-tests/1000633.yaml)、[1000634.yaml](../../../test/waf/ftw/crs-tests/1000634.yaml)、[1000635.yaml](../../../test/waf/ftw/crs-tests/1000635.yaml)、[1000636.yaml](../../../test/waf/ftw/crs-tests/1000636.yaml)、[1000637.yaml](../../../test/waf/ftw/crs-tests/1000637.yaml)、[1000638.yaml](../../../test/waf/ftw/crs-tests/1000638.yaml)、[1000639.yaml](../../../test/waf/ftw/crs-tests/1000639.yaml)、[1000640.yaml](../../../test/waf/ftw/crs-tests/1000640.yaml)、[1000641.yaml](../../../test/waf/ftw/crs-tests/1000641.yaml)、[1000642.yaml](../../../test/waf/ftw/crs-tests/1000642.yaml)、[1000643.yaml](../../../test/waf/ftw/crs-tests/1000643.yaml)、[1000644.yaml](../../../test/waf/ftw/crs-tests/1000644.yaml)、[1000645.yaml](../../../test/waf/ftw/crs-tests/1000645.yaml)、[1000646.yaml](../../../test/waf/ftw/crs-tests/1000646.yaml)、[1000647.yaml](../../../test/waf/ftw/crs-tests/1000647.yaml)、[1000648.yaml](../../../test/waf/ftw/crs-tests/1000648.yaml)
- `ssti-injection.conf`：[1001801.yaml](../../../test/waf/ftw/crs-tests/1001801.yaml)、[1001802.yaml](../../../test/waf/ftw/crs-tests/1001802.yaml)、[1001803.yaml](../../../test/waf/ftw/crs-tests/1001803.yaml)、[1001804.yaml](../../../test/waf/ftw/crs-tests/1001804.yaml)、[1001805.yaml](../../../test/waf/ftw/crs-tests/1001805.yaml)、[1001806.yaml](../../../test/waf/ftw/crs-tests/1001806.yaml)、[1001807.yaml](../../../test/waf/ftw/crs-tests/1001807.yaml)、[1001808.yaml](../../../test/waf/ftw/crs-tests/1001808.yaml)、[1001809.yaml](../../../test/waf/ftw/crs-tests/1001809.yaml)、[1001810.yaml](../../../test/waf/ftw/crs-tests/1001810.yaml)、[1001811.yaml](../../../test/waf/ftw/crs-tests/1001811.yaml)、[1001812.yaml](../../../test/waf/ftw/crs-tests/1001812.yaml)、[1001813.yaml](../../../test/waf/ftw/crs-tests/1001813.yaml)、[1001814.yaml](../../../test/waf/ftw/crs-tests/1001814.yaml)、[1001815.yaml](../../../test/waf/ftw/crs-tests/1001815.yaml)、[1001816.yaml](../../../test/waf/ftw/crs-tests/1001816.yaml)

- 归一化聚类：**52** 类（按 标签信息+用例名称 归一化）

| 聚类（核心名） | 用例数 | 关联 CVE/CNVD |
|---|---|---|
| Adobe ColdFusion - Deserialization of Untrusted Data (CVE-2023-38203) | 1 | CVE-2023-38203 |
| Adobe ColdFusion反序列化漏洞(CVE-2023-29300) | 1 | CVE-2023-29300 |
| Apache_Log4j远程代码执行绕过#2 | 1 | — |
| Apache_Log4j远程代码执行绕过#4 | 1 | — |
| Apache_Log4j远程代码执行绕过#5 | 1 | — |
| Apache_Log4j远程代码执行绕过#7 | 1 | — |
| Apache_Log4j远程代码执行绕过#8 | 1 | — |
| Apache Kafka 代码问题漏洞（CVE-2023-25194） | 1 | CVE-2023-25194 |
| Apache Log4j 反序列化漏洞（CVE-2017-5645） | 1 | CVE-2017-5645 |
| Apache Log4j 反序列化漏洞（CVE-2019-17571） | 1 | CVE-2019-17571 |
| Apache OFBiz RMI反序列化漏洞（CVE-2021-26295） | 1 | CVE-2021-26295 |
| Apache Ofbiz XML-RPC RCE 反序列化漏洞 （CVE-2023-49070） | 1 | CVE-2023-49070 |
| Apache OFBiz 反序列化 CVE-2021-26295 | 1 | CVE-2021-26295 |
| Apache Shiro反序列化漏洞（Shiro-550） | 1 | — |
| Apache Tomcat反序列化代码执行漏洞(CVE-2020-9484) | 1 | CVE-2020-9484 |
| Cacti < 1.2.25 Insecure Deserialization (CVE-2023-30534) | 1 | CVE-2023-30534 |
| devexpress 反序列化漏洞 | 1 | — |
| fastjson反序列化(v1.2.25-v1.2.47) 补丁绕过 | 1 | — |
| Fastjson 反序列化漏洞(CVE-2017-18349) | 1 | CVE-2017-18349 |
| Fastjson 反序列化漏洞(CVE-2022-25845) | 1 | CVE-2022-25845 |
| …… 其余 32 类从略 | | |

### SSRF服务端请求伪造

- BAS 用例数：**47**（报告阻断 12 / 未阻断 35）
- 说明：BAS 含组件 SSRF CVE 与伪协议/进制 IP/本地绕过等高级 payload。

承担检测的自建规则包（CUSTOM_PACK）：

| 规则包文件 | 规则数 | 实际 ID 范围 | 承担内容 |
|---|---|---|---|
| `cloud-abuse.conf` | 30 | 1000301–1000330 | SSRF 云元数据段（169.254.169.254 等锚定检测） |
| `attack-coverage.conf` | 51 | 1001101–1001151 | 1001121–1001128 SSRF 变形（伪协议/进制 IP/重定向） |
| `attack-variants-evasion.conf` | 99 | 1001201–1001299 | H 段 1001237–1001241、Q 段 1001278–1001280 SSRF/DNS 变种增强 |
| `ssrf-protocols.conf` | 23 | 1001501–1001523 | SSRF 专项：伪协议补充/IP 混淆绕过/URL 参数指向内网/短链跳板 |

CRS 兜底：934 系列（通用注入，含部分 SSRF 网络层特征，弱兜底）

go-ftw 回归测试：

- `ssrf-protocols.conf`：[1001501.yaml](../../../test/waf/ftw/crs-tests/1001501.yaml)、[1001502.yaml](../../../test/waf/ftw/crs-tests/1001502.yaml)、[1001503.yaml](../../../test/waf/ftw/crs-tests/1001503.yaml)、[1001504.yaml](../../../test/waf/ftw/crs-tests/1001504.yaml)、[1001505.yaml](../../../test/waf/ftw/crs-tests/1001505.yaml)、[1001506.yaml](../../../test/waf/ftw/crs-tests/1001506.yaml)、[1001507.yaml](../../../test/waf/ftw/crs-tests/1001507.yaml)、[1001508.yaml](../../../test/waf/ftw/crs-tests/1001508.yaml)、[1001509.yaml](../../../test/waf/ftw/crs-tests/1001509.yaml)、[1001510.yaml](../../../test/waf/ftw/crs-tests/1001510.yaml)、[1001511.yaml](../../../test/waf/ftw/crs-tests/1001511.yaml)、[1001512.yaml](../../../test/waf/ftw/crs-tests/1001512.yaml)、[1001513.yaml](../../../test/waf/ftw/crs-tests/1001513.yaml)、[1001514.yaml](../../../test/waf/ftw/crs-tests/1001514.yaml)、[1001515.yaml](../../../test/waf/ftw/crs-tests/1001515.yaml)、[1001516.yaml](../../../test/waf/ftw/crs-tests/1001516.yaml)、[1001517.yaml](../../../test/waf/ftw/crs-tests/1001517.yaml)、[1001518.yaml](../../../test/waf/ftw/crs-tests/1001518.yaml)、[1001519.yaml](../../../test/waf/ftw/crs-tests/1001519.yaml)、[1001520.yaml](../../../test/waf/ftw/crs-tests/1001520.yaml)、[1001521.yaml](../../../test/waf/ftw/crs-tests/1001521.yaml)、[1001522.yaml](../../../test/waf/ftw/crs-tests/1001522.yaml)、[1001523.yaml](../../../test/waf/ftw/crs-tests/1001523.yaml)

- 归一化聚类：**47** 类（按 标签信息+用例名称 归一化）

| 聚类（核心名） | 用例数 | 关联 CVE/CNVD |
|---|---|---|
| Apache APISIX batch_requests SSRF 漏洞（CVE_2022_24112） | 1 | CVE-2022-24112 |
| Apache httpd mod_proxy SSRF漏洞(CVE-2021-40438) | 1 | CVE-2021-40438 |
| Apache HTTP Server 2.4.48 mod_proxy SSRF漏洞（CVE_2021_40438） | 1 | CVE-2021-40438 |
| Apache Kafka Client 漏洞（CVE-2025-27817） | 1 | CVE-2025-27817 |
| Apache OFBiz _ Remote Code Execution (CVE-2024-45507) | 1 | CVE-2024-45507 |
| Apache OFBiz SSRF 漏洞(CVE-2024-47208) | 1 | CVE-2024-47208 |
| Apache SSRF漏洞 CVE-2021-40438 | 1 | CVE-2021-40438 |
| Atlassian Jira IconURIServlet _ Cross_Site Scripting/Server_Side Request Forgery (CVE-2017-9506) | 1 | CVE-2017-9506 |
| Atlassian Jira Mobile Plugin SSRF漏洞（CVE_2022_26135） | 1 | CVE-2022-26135 |
| Confluence Jira 服务端请求伪造漏洞（CVE_2019_8451） | 1 | CVE-2019-8451 |
| dict协议句号绕过SSRF(redis) | 1 | — |
| Drawio <18.0.4 _ Server_Side Request Forgery (CVE-2022-1713) | 1 | CVE-2022-1713 |
| Drawio <18.1.2 _ Server_Side Request Forgery (CVE-2022-1815) | 1 | CVE-2022-1815 |
| External Media without Import <=1.1.2 _ Authenticated Blind Server_Side Request Forgery (CVE-2022-1398) | 1 | CVE-2022-1398 |
| ffmpeg SSRF漏洞 （CVE_2016_1897） | 1 | CVE-2016-1897 |
| FlyteConsole SSRF漏洞（CVE_2022_24856） | 1 | CVE-2022-24856 |
| GeoServer SSRF漏洞（CVE_2021_40822） | 1 | CVE-2021-40822 |
| GitLab SSRF漏洞 CVE_2021_22214 | 1 | CVE-2021-22214 |
| Grafana服务端请求伪造漏洞(CVE_2020_13379) | 1 | CVE-2020-13379 |
| Hurrakify <= 2.4 _ Server_Side Request Forgery (CVE-2024-54330) | 1 | CVE-2024-54330 |
| …… 其余 27 类从略 | | |

### XXE实体注入漏洞

- BAS 用例数：**20**（报告阻断 1 / 未阻断 19）
- 说明：BAS 以组件 XXE CVE 与 DOCTYPE/实体声明 payload 为主，依赖自研包。

承担检测的自建规则包（CUSTOM_PACK）：

| 规则包文件 | 规则数 | 实际 ID 范围 | 承担内容 |
|---|---|---|---|
| `api-abuse.conf` | 30 | 1000401–1000455 | 1000440–1000444 XXE DOCTYPE 内部子集/实体声明网络层兜底 |
| `attack-variants-evasion.conf` | 99 | 1001201–1001299 | H 段 1001237–1001241、R 段 1001281–1001284 XXE 变种 |
| `xxe-lfi-variants.conf` | 29 | 1001601–1001629 | A 段 XXE 变种（引用/启发式/包裹/编码/ARGS 目标） |

CRS 兜底：（CRS 无 XXE 专项组，依赖自研包）

go-ftw 回归测试：

- `xxe-lfi-variants.conf`：[1001601.yaml](../../../test/waf/ftw/crs-tests/1001601.yaml)、[1001602.yaml](../../../test/waf/ftw/crs-tests/1001602.yaml)、[1001603.yaml](../../../test/waf/ftw/crs-tests/1001603.yaml)、[1001604.yaml](../../../test/waf/ftw/crs-tests/1001604.yaml)、[1001605.yaml](../../../test/waf/ftw/crs-tests/1001605.yaml)、[1001606.yaml](../../../test/waf/ftw/crs-tests/1001606.yaml)、[1001607.yaml](../../../test/waf/ftw/crs-tests/1001607.yaml)、[1001608.yaml](../../../test/waf/ftw/crs-tests/1001608.yaml)、[1001609.yaml](../../../test/waf/ftw/crs-tests/1001609.yaml)、[1001610.yaml](../../../test/waf/ftw/crs-tests/1001610.yaml)、[1001611.yaml](../../../test/waf/ftw/crs-tests/1001611.yaml)、[1001612.yaml](../../../test/waf/ftw/crs-tests/1001612.yaml)、[1001613.yaml](../../../test/waf/ftw/crs-tests/1001613.yaml)、[1001614.yaml](../../../test/waf/ftw/crs-tests/1001614.yaml)、[1001615.yaml](../../../test/waf/ftw/crs-tests/1001615.yaml)、[1001616.yaml](../../../test/waf/ftw/crs-tests/1001616.yaml)、[1001617.yaml](../../../test/waf/ftw/crs-tests/1001617.yaml)、[1001618.yaml](../../../test/waf/ftw/crs-tests/1001618.yaml)、[1001619.yaml](../../../test/waf/ftw/crs-tests/1001619.yaml)、[1001620.yaml](../../../test/waf/ftw/crs-tests/1001620.yaml)、[1001621.yaml](../../../test/waf/ftw/crs-tests/1001621.yaml)、[1001622.yaml](../../../test/waf/ftw/crs-tests/1001622.yaml)、[1001623.yaml](../../../test/waf/ftw/crs-tests/1001623.yaml)、[1001624.yaml](../../../test/waf/ftw/crs-tests/1001624.yaml)、[1001625.yaml](../../../test/waf/ftw/crs-tests/1001625.yaml)、[1001626.yaml](../../../test/waf/ftw/crs-tests/1001626.yaml)、[1001627.yaml](../../../test/waf/ftw/crs-tests/1001627.yaml)、[1001628.yaml](../../../test/waf/ftw/crs-tests/1001628.yaml)、[1001629.yaml](../../../test/waf/ftw/crs-tests/1001629.yaml)

- 归一化聚类：**20** 类（按 标签信息+用例名称 归一化）

| 聚类（核心名） | 用例数 | 关联 CVE/CNVD |
|---|---|---|
| Adobe Experience Manager - XML External Entity Injection (CVE-2019-8086) | 1 | CVE-2019-8086 |
| Akamai CloudTest < 60 2025.06.02 - XML External Entity (XML外部实体注入) （CVE-2025-49493） | 1 | CVE-2025-49493 |
| Akamai CloudTest SOAP XXE漏洞（CVE-2025-49493） | 1 | CVE-2025-49493 |
| Apache CloudStack SAML XXE漏洞（CVE-2022-35741） | 1 | CVE-2022-35741 |
| Apache OFBiz XXE（CVE-2018-8033） | 1 | CVE-2018-8033 |
| Apache Solr XML外部实体扩展漏洞（CVE-2018-1308） | 1 | CVE-2018-1308 |
| FreeIPA - XML Entity Injection (CVE-2022-2414) | 1 | CVE-2022-2414 |
| Journyx - XML External Entities Injection (XXE) (CVE-2024-6893) | 1 | CVE-2024-6893 |
| LumisXP 存在XXE（CVE-2021-27931） | 1 | CVE-2021-27931 |
| SAP Internet Graphics Server (IGS) - XML External Entity Injection (CVE-2018-2392) | 1 | CVE-2018-2392 |
| Sophos Mobile managed on-premises - XML External Entity Injection (CVE-2022-3980) | 1 | CVE-2022-3980 |
| TablePress < 2.4.3 - XXE Injection (CVE-2024-45293) | 1 | CVE-2024-45293 |
| WSO2 API Manager XXE漏洞（CVE-2020-24589） | 1 | CVE-2020-24589 |
| XML外部实体攻击(XXE)：POST-使用大量嵌套的实体引用进行拒绝服务攻击 | 1 | — |
| XML外部实体攻击(XXE)：POST-在SVG图像格式中使用XXE攻击 | 1 | — |
| Zimbra Collaboration Suite XXE漏洞（CVE-2019-9670） | 1 | CVE-2019-9670 |
| Zimbra XXE 攻击漏洞 CVE-2019-9670 | 1 | CVE-2019-9670 |
| Zoho ManageEngine ADAudit Plus XXE漏洞（CVE-2022-28219） | 1 | CVE-2022-28219 |
| 方正畅享全媒体新闻采编系统addOrUpdateOrg存在XXE漏洞 | 1 | — |
| 泛微 E-cology XXE ByMap | 1 | — |

### C&C通信

- BAS 用例数：**9**（报告阻断 3 / 未阻断 6）
- 说明：BAS 以重放哥斯拉/冰蝎/蚁剑 php/jsp/aspx WebShell 流量为主，对应 WebShell 通信特征。

承担检测的自建规则包（CUSTOM_PACK）：

| 规则包文件 | 规则数 | 实际 ID 范围 | 承担内容 |
|---|---|---|---|
| `webshell.conf` | 34 | 1000101–1000134 | 哥斯拉/冰蝎/蚁剑/菜刀通信特征段 |
| `webshell-obfuscation.conf` | 39 | 1001001–1001040 | 加密流量密钥参数与工具协议痕迹 |

CRS 兜底：（无直接对应 CRS 组，依赖自研 WebShell 包）

go-ftw 回归测试：

- 暂无（缺口见第三节）

- 归一化聚类：**9** 类（按 标签信息+用例名称 归一化）

| 聚类（核心名） | 用例数 | 关联 CVE/CNVD |
|---|---|---|
| 冰蝎 aspx 类型 webshell 流量 | 1 | — |
| 冰蝎 jsp 类型 webshell 流量 | 1 | — |
| 冰蝎 php 类型 webshell 流量 | 1 | — |
| 哥斯拉 aspx 类型 webshell 流量 | 1 | — |
| 哥斯拉 jsp 类型 webshell 流量 | 1 | — |
| 哥斯拉 php 类型 webshell 流量 | 1 | — |
| 蚁剑 aspx 类型 webshell 流量 | 1 | — |
| 蚁剑 jsp 类型 webshell 流量 | 1 | — |
| 蚁剑 php 类型 webshell 流量 | 1 | — |

### 目录穿越漏洞

- BAS 用例数：**7**（报告阻断 0 / 未阻断 7）
- 说明：BAS 以 Apache/Spring/uWSGI 等目录穿越 CVE 利用为主。

承担检测的自建规则包（CUSTOM_PACK）：

| 规则包文件 | 规则数 | 实际 ID 范围 | 承担内容 |
|---|---|---|---|
| `cve-recent.conf` | 35 | 1000801–1000835 | Apache CVE-2021-41773/42013 目录穿越利用特征 |
| `api-abuse.conf` | 30 | 1000401–1000455 | 1000450–1000455 路径穿越编码变体 |
| `attack-variants-evasion.conf` | 99 | 1001201–1001299 | E 段 1001224–1001228 路径变种 |
| `xxe-lfi-variants.conf` | 29 | 1001601–1001629 | D 段目录穿越编码变体、E 段空字节截断变种 |

CRS 兜底：930 系列（LFI/路径穿越，主力）

go-ftw 回归测试：

- `xxe-lfi-variants.conf`：[1001601.yaml](../../../test/waf/ftw/crs-tests/1001601.yaml)、[1001602.yaml](../../../test/waf/ftw/crs-tests/1001602.yaml)、[1001603.yaml](../../../test/waf/ftw/crs-tests/1001603.yaml)、[1001604.yaml](../../../test/waf/ftw/crs-tests/1001604.yaml)、[1001605.yaml](../../../test/waf/ftw/crs-tests/1001605.yaml)、[1001606.yaml](../../../test/waf/ftw/crs-tests/1001606.yaml)、[1001607.yaml](../../../test/waf/ftw/crs-tests/1001607.yaml)、[1001608.yaml](../../../test/waf/ftw/crs-tests/1001608.yaml)、[1001609.yaml](../../../test/waf/ftw/crs-tests/1001609.yaml)、[1001610.yaml](../../../test/waf/ftw/crs-tests/1001610.yaml)、[1001611.yaml](../../../test/waf/ftw/crs-tests/1001611.yaml)、[1001612.yaml](../../../test/waf/ftw/crs-tests/1001612.yaml)、[1001613.yaml](../../../test/waf/ftw/crs-tests/1001613.yaml)、[1001614.yaml](../../../test/waf/ftw/crs-tests/1001614.yaml)、[1001615.yaml](../../../test/waf/ftw/crs-tests/1001615.yaml)、[1001616.yaml](../../../test/waf/ftw/crs-tests/1001616.yaml)、[1001617.yaml](../../../test/waf/ftw/crs-tests/1001617.yaml)、[1001618.yaml](../../../test/waf/ftw/crs-tests/1001618.yaml)、[1001619.yaml](../../../test/waf/ftw/crs-tests/1001619.yaml)、[1001620.yaml](../../../test/waf/ftw/crs-tests/1001620.yaml)、[1001621.yaml](../../../test/waf/ftw/crs-tests/1001621.yaml)、[1001622.yaml](../../../test/waf/ftw/crs-tests/1001622.yaml)、[1001623.yaml](../../../test/waf/ftw/crs-tests/1001623.yaml)、[1001624.yaml](../../../test/waf/ftw/crs-tests/1001624.yaml)、[1001625.yaml](../../../test/waf/ftw/crs-tests/1001625.yaml)、[1001626.yaml](../../../test/waf/ftw/crs-tests/1001626.yaml)、[1001627.yaml](../../../test/waf/ftw/crs-tests/1001627.yaml)、[1001628.yaml](../../../test/waf/ftw/crs-tests/1001628.yaml)、[1001629.yaml](../../../test/waf/ftw/crs-tests/1001629.yaml)

- 归一化聚类：**7** 类（按 标签信息+用例名称 归一化）

| 聚类（核心名） | 用例数 | 关联 CVE/CNVD |
|---|---|---|
| apache 目录穿越 CVE-2021-41773 | 1 | CVE-2021-41773 |
| apache 目录穿越 CVE-2021-42013 | 1 | CVE-2021-42013 |
| Milesight VPN路径遍历漏洞 （CVE-2023-23907） | 1 | CVE-2023-23907 |
| Spring-Framework路径遍历漏洞(CVE-2024-38816) | 1 | CVE-2024-38816 |
| Spring Cloud Config 目录遍历漏洞 CVE-2020-5410 | 1 | CVE-2020-5410 |
| uWSGI 目录穿越 (CVE-2018-7490) | 1 | CVE-2018-7490 |
| 泛微E-cology 目录遍历漏洞 | 1 | — |

## 三、规则-测试缺口（有规则无 ftw 测试）

按 `test/waf/ftw/crs-tests/` 下 `<规则ID>.yaml`（一条规则一个文件）口径统计，
随各规则包分片补齐后重跑本脚本即可收敛。

| 规则包文件 | 规则数 | 已有测试 | 缺测 | 缺测 ID |
|---|---|---|---|---|
| `api-abuse.conf` | 30 | 0 | 30 | 1000401, 1000402, 1000403, 1000404, 1000405, 1000406, 1000407, 1000410, 1000411, 1000412, 1000420, 1000421, 1000422, 1000423, 1000424, 1000425, 1000430, 1000431, 1000432, 1000440, 1000441, 1000442, 1000443, 1000444, 1000450, 1000451, 1000452, 1000453, 1000454, 1000455 |
| `attack-coverage.conf` | 51 | 0 | 51 | 1001101, 1001102, 1001103, 1001104, 1001105, 1001106, 1001107, 1001108, 1001109, 1001110, 1001111, 1001112, 1001113, 1001114, 1001115, 1001116, 1001117, 1001118, 1001119, 1001120, 1001121, 1001122, 1001123, 1001124, 1001125, 1001126, 1001127, 1001128, 1001129, 1001130, 1001131, 1001132, 1001133, 1001134, 1001135, 1001136, 1001137, 1001138, 1001139, 1001140, 1001141, 1001142, 1001143, 1001144, 1001145, 1001146, 1001147, 1001148, 1001149, 1001150, 1001151 |
| `attack-variants-evasion.conf` | 99 | 0 | 99 | 1001201, 1001202, 1001203, 1001204, 1001205, 1001206, 1001207, 1001208, 1001209, 1001210, 1001211, 1001212, 1001213, 1001214, 1001215, 1001216, 1001217, 1001218, 1001219, 1001220, 1001221, 1001222, 1001223, 1001224, 1001225, 1001226, 1001227, 1001228, 1001229, 1001230, 1001231, 1001232, 1001233, 1001234, 1001235, 1001236, 1001237, 1001238, 1001239, 1001240, 1001241, 1001242, 1001243, 1001244, 1001245, 1001246, 1001247, 1001248, 1001249, 1001250, 1001251, 1001252, 1001253, 1001254, 1001255, 1001256, 1001257, 1001258, 1001259, 1001260, 1001261, 1001262, 1001263, 1001264, 1001265, 1001266, 1001267, 1001268, 1001269, 1001270, 1001271, 1001272, 1001273, 1001274, 1001275, 1001276, 1001277, 1001278, 1001279, 1001280, 1001281, 1001282, 1001283, 1001284, 1001285, 1001286, 1001287, 1001288, 1001289, 1001290, 1001291, 1001292, 1001293, 1001294, 1001295, 1001296, 1001297, 1001298, 1001299 |
| `bot-protocol.conf` | 35 | 0 | 35 | 1000701, 1000702, 1000703, 1000704, 1000705, 1000706, 1000707, 1000708, 1000709, 1000710, 1000711, 1000712, 1000713, 1000714, 1000715, 1000716, 1000717, 1000718, 1000719, 1000720, 1000721, 1000722, 1000723, 1000724, 1000725, 1000726, 1000727, 1000728, 1000729, 1000730, 1000731, 1000732, 1000733, 1000734, 1000735 |
| `cloud-abuse.conf` | 30 | 0 | 30 | 1000301, 1000302, 1000303, 1000304, 1000305, 1000306, 1000307, 1000308, 1000309, 1000310, 1000311, 1000312, 1000313, 1000314, 1000315, 1000316, 1000317, 1000318, 1000319, 1000320, 1000321, 1000322, 1000323, 1000324, 1000325, 1000326, 1000327, 1000328, 1000329, 1000330 |
| `cve-emergency.conf` | 42 | 0 | 42 | 1000001, 1000002, 1000003, 1000004, 1000005, 1000006, 1000007, 1000008, 1000009, 1000010, 1000011, 1000012, 1000013, 1000014, 1000015, 1000016, 1000017, 1000018, 1000019, 1000020, 1000021, 1000022, 1000023, 1000024, 1000025, 1000026, 1000027, 1000028, 1000029, 1000030, 1000031, 1000032, 1000033, 1000034, 1000035, 1000036, 1000037, 1000038, 1000039, 1000040, 1000041, 1000042 |
| `cve-recent.conf` | 35 | 0 | 35 | 1000801, 1000802, 1000803, 1000804, 1000805, 1000806, 1000807, 1000808, 1000809, 1000810, 1000811, 1000812, 1000813, 1000814, 1000815, 1000816, 1000817, 1000818, 1000819, 1000820, 1000821, 1000822, 1000823, 1000824, 1000825, 1000826, 1000827, 1000828, 1000829, 1000830, 1000831, 1000832, 1000833, 1000834, 1000835 |
| `deserialization-rce.conf` | 48 | 18 | 30 | 1000601, 1000602, 1000603, 1000604, 1000605, 1000606, 1000607, 1000608, 1000609, 1000610, 1000611, 1000612, 1000613, 1000614, 1000615, 1000616, 1000617, 1000618, 1000619, 1000620, 1000621, 1000622, 1000623, 1000624, 1000625, 1000626, 1000627, 1000628, 1000629, 1000630 |
| `injection-variants.conf` | 33 | 33 | 0 | — |
| `oss-webapps-cve.conf` | 50 | 0 | 50 | 1000901, 1000902, 1000903, 1000904, 1000905, 1000906, 1000907, 1000908, 1000909, 1000910, 1000911, 1000912, 1000913, 1000914, 1000915, 1000916, 1000917, 1000918, 1000919, 1000920, 1000921, 1000922, 1000923, 1000924, 1000925, 1000926, 1000927, 1000928, 1000929, 1000930, 1000931, 1000932, 1000933, 1000934, 1000935, 1000936, 1000937, 1000938, 1000939, 1000940, 1000941, 1000942, 1000943, 1000944, 1000945, 1000946, 1000947, 1000948, 1000949, 1000950 |
| `scanner-fingerprints.conf` | 30 | 0 | 30 | 1000201, 1000202, 1000203, 1000204, 1000205, 1000206, 1000207, 1000208, 1000209, 1000210, 1000211, 1000212, 1000213, 1000214, 1000215, 1000216, 1000217, 1000218, 1000219, 1000220, 1000221, 1000222, 1000223, 1000224, 1000225, 1000226, 1000227, 1000228, 1000229, 1000230 |
| `sensitive-exposure.conf` | 40 | 0 | 40 | 1000501, 1000502, 1000503, 1000504, 1000505, 1000506, 1000507, 1000508, 1000509, 1000510, 1000511, 1000512, 1000513, 1000514, 1000515, 1000516, 1000517, 1000518, 1000519, 1000520, 1000521, 1000522, 1000523, 1000524, 1000525, 1000526, 1000527, 1000528, 1000529, 1000530, 1000531, 1000532, 1000533, 1000534, 1000535, 1000536, 1000537, 1000538, 1000539, 1000540 |
| `ssrf-protocols.conf` | 23 | 23 | 0 | — |
| `ssti-injection.conf` | 16 | 16 | 0 | — |
| `unauth-access.conf` | 24 | 24 | 0 | — |
| `webshell-content.conf` | 30 | 30 | 0 | — |
| `webshell-obfuscation.conf` | 39 | 0 | 39 | 1001001, 1001002, 1001003, 1001004, 1001005, 1001006, 1001007, 1001008, 1001009, 1001010, 1001011, 1001012, 1001013, 1001014, 1001015, 1001016, 1001017, 1001018, 1001020, 1001021, 1001022, 1001023, 1001024, 1001025, 1001026, 1001027, 1001028, 1001029, 1001030, 1001031, 1001032, 1001033, 1001034, 1001035, 1001036, 1001037, 1001038, 1001039, 1001040 |
| `webshell-uploads.conf` | 26 | 26 | 0 | — |
| `webshell.conf` | 34 | 0 | 34 | 1000101, 1000102, 1000103, 1000104, 1000105, 1000106, 1000107, 1000108, 1000109, 1000110, 1000111, 1000112, 1000113, 1000114, 1000115, 1000116, 1000117, 1000118, 1000119, 1000120, 1000121, 1000122, 1000123, 1000124, 1000125, 1000126, 1000127, 1000128, 1000129, 1000130, 1000131, 1000132, 1000133, 1000134 |
| `xxe-lfi-variants.conf` | 29 | 29 | 0 | — |
| **合计** | **744** | **199** | **545** | |

---

Copyright © 聚信得仁
All Rights Reserved.
