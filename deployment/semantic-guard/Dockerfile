# 九章本地离线语义防火墙 sidecar（jiuzhang-semantic-guard）镜像
# 构建（仓库根目录）：
#   docker build -f deployment/semantic-guard/Dockerfile -t jiuzhang-semantic-guard:1.16.0 deployment/semantic-guard
#
# 安全边界：
#   - 严禁使用 latest 标签，基础镜像明确锁定为 python:3.12.8-slim（可选 PYTHON_IMAGE_DIGEST 摘要钉扎）；
#   - 仅监听本地 Unix Domain Socket（SEMANTIC_GUARD_SOCKET），不声明 EXPOSE，不监听任何 TCP/UDP 端口；
#   - 非 root（uid/gid 1000）运行，兼容只读根文件系统（--read-only）与无网络命名空间（network_mode: none）；
#   - 若挂载了 model-manifest.json，启动前强制执行 ONNX 模型 SHA-256 校验，篡改或校验失败立即 fail-closed 退出；
#   - 未挂载模型时以纯 stdlib 确定性启发式后端运行，并在 /healthz 如实上报 backend="heuristic_fallback"。

ARG PYTHON_IMAGE_DIGEST=
FROM python:3.12.8-slim${PYTHON_IMAGE_DIGEST:+@$PYTHON_IMAGE_DIGEST}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SEMANTIC_GUARD_SOCKET=/var/run/caddy/sidecars/semantic.sock \
    SEMANTIC_GUARD_MODEL_MANIFEST=

RUN groupadd --gid 1000 jiuzhang \
    && useradd --uid 1000 --gid 1000 --shell /usr/sbin/nologin --create-home jiuzhang \
    && mkdir -p /app /models /var/run/caddy/sidecars /run/jiuzhang \
    && chown -R jiuzhang:jiuzhang /app /models \
    && chown jiuzhang:jiuzhang /var/run/caddy/sidecars /run/jiuzhang \
    && chmod 0770 /var/run/caddy/sidecars /run/jiuzhang

WORKDIR /app
COPY --chown=jiuzhang:jiuzhang server.py /app/server.py
COPY --chown=jiuzhang:jiuzhang model-manifest.example.json /app/model-manifest.example.json

USER 1000:1000

# 仅通过本地 Unix Socket 探活（不开放、不探测任何 TCP 端口）
HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
    CMD python3 -c "import json, os, socket; s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(2); s.connect(os.environ.get('SEMANTIC_GUARD_SOCKET', '/var/run/caddy/sidecars/semantic.sock')); s.sendall(b'GET /healthz HTTP/1.1\r\nHost: unix\r\nConnection: close\r\n\r\n'); data=s.recv(4096); s.close(); body=data.split(b'\r\n\r\n',1)[1]; assert json.loads(body).get('status')=='ok'" || exit 1

# 不声明 EXPOSE：本组件严禁暴露任何 TCP 端口
ENTRYPOINT ["python3", "/app/server.py"]
