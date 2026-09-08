# P1-03 G2 取证镜像：真实 Nginx（TLS 终止 + mirror）+ mirrorharness（adapter/origin）。
# 基础镜像 tag+digest 双锁（AGENTS.md 版本锁定纪律；manifest-list digest，跨架构适用）。
FROM nginx:1.28.0-alpine@sha256:30f1c0d78e0ad60901648be663a710bdadf19e4c10ac6782c235200619158284

# mirrorharness 由 run.sh 预构建（GOOS=linux，目标架构随 docker daemon）
COPY mirrorharness /usr/local/bin/mirrorharness
COPY nginx.conf /etc/nginx/nginx.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /usr/local/bin/mirrorharness /entrypoint.sh

EXPOSE 8443
ENTRYPOINT ["/entrypoint.sh"]
