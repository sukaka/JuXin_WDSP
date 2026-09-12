"""P0-02 隔离基准共享库（纯 Python 标准库）。

模块划分：
- plan:        run-plan 加载与结构校验（§7 预登记门槛；权威校验逻辑，schema 文件为文档镜像）
- isolation:   run_id / 资源归属 / 目标地址与重定向允许表判定（§3.1，BENCH-01/02）
- corpus:      语料 manifest 校验与哈希（§5）
- metrics:     分位数算法与检测/处置分离指标（BENCH-05/06）
- reconcile:   事件对账计数（§6.2.4，BENCH-08）
- collectors:  压测器输出、curl 时序、docker stats 解析与错误分类（§6.1）
- report_core: 只读 run 目录汇总与 report.md 渲染（§8，BENCH-05/06/07）

约束：不使用第三方包；不执行网络请求；不输出环境变量全集、原始 Authorization
或完整 docker inspect 数据。
"""
