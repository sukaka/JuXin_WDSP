# P1-03 G3 取证镜像（仅测试用途）。
# 基础镜像 tag+digest 双锁（仓库纪律；与 run.sh BASE_IMAGE 一致）：
#   envoyproxy/envoy v1.35.3（docker pull 报告 digest）
FROM envoyproxy/envoy:v1.35.3@sha256:4d496918618a7ebd6c71ae8285e31ebff092f3a0a5ad642d50decf4a54eb2456

COPY tapharness /usr/local/bin/tapharness
COPY tace2e /usr/local/bin/tace2e
# 相位 A 默认 h2+TLS 挂 tap；相位 B 由 run.sh 换入 envoy-h1.yaml（单管理流约束）
COPY envoy-h2.yaml /etc/envoy/envoy.yaml
COPY envoy-h1.yaml /usr/local/share/envoy-h1.yaml
COPY entrypoint.sh /usr/local/bin/e2e-entrypoint.sh

USER root
RUN chmod 0755 /usr/local/bin/tapharness /usr/local/bin/tace2e /usr/local/bin/e2e-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/e2e-entrypoint.sh"]
