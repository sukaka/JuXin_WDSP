# 九章本地离线语义防火墙 Sidecar（`deployment/semantic-guard`）

本目录提供九章 WDSP Phase 9C-2 **可选独立离线语义防火墙 Sidecar**，仅通过本地 Unix Domain Socket 与网关（`jiuzhang_guard`）及管理面健康探针通信，无需访问外部云端 LLM API，满足内网/涉密离线部署要求。

## 安全架构与通信契约

- **仅限本地 Unix Socket**：默认监听 `/var/run/caddy/sidecars/semantic.sock`（允许目录：`/var/run/caddy/sidecars/` 或 `/run/jiuzhang/`），**不监听任何 TCP/UDP 端口**，容器模式建议配合 `network_mode: none` 与 `--read-only` 运行。
- **不透传凭据、不落明文**：网关客户端仅发送最小请求体 `{"request_id","channel","text"}`，不发送 `Cookie` / `Authorization`；sidecar 绝不在日志中输出 `text` 原文。
- **强制模型完整性校验（Fail-Closed）**：配置 `SEMANTIC_GUARD_MODEL_MANIFEST` 挂载 INT8 ONNX 模型时，启动阶段必须逐字节计算模型文件 SHA-256 并与 `model-manifest.json` 恒定时间比对；若摘要不符、路径穿越、文件缺失或缺少 `onnxruntime` 依赖，进程**直接拒绝加载并退出**，绝不静默降级或伪装运行。
- **诚实回退后端**：未配置/未挂载模型清单时，进程使用纯 Python 标准库零依赖的确定性词法/启发式分类后端，并在 `GET /healthz` 中如实上报 `backend: "heuristic_fallback"`（绝不谎报 `onnxruntime`）。

## HTTP over Unix Socket 接口

1. `GET /healthz`
   ```json
   {
     "status": "ok",
     "model_id": "heuristic-fallback-v1",
     "model_sha256": "",
     "backend": "heuristic_fallback"
   }
   ```
2. `POST /v1/classify`
   - 请求体（上限 64 KiB）：`{"request_id": "req-1", "channel": "llm_prompt|mcp_content|web_grayzone", "text": "..."}`
   - 响应体：`{"label": "safe|prompt_injection|jailbreak|indirect_injection|web_payload", "score": 0.92, "model_id": "...", "latency_ms": 1}`

## 部署方式

### 1. Docker（完全无网隔离）

```bash
docker build -f deployment/semantic-guard/Dockerfile \
  -t jiuzhang-semantic-guard:1.16.0 deployment/semantic-guard

docker run -d --name jiuzhang-semantic-guard \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -v caddy_sidecars:/var/run/caddy/sidecars \
  jiuzhang-semantic-guard:1.16.0
```

如需加载本地离线 INT8 ONNX 模型（镜像内需预安装对应版本的 `onnxruntime` 离线 wheel 包），额外挂载只读模型目录并指定清单路径：

```bash
docker run -d --name jiuzhang-semantic-guard \
  --network none --read-only --cap-drop ALL \
  -e SEMANTIC_GUARD_MODEL_MANIFEST=/models/model-manifest.json \
  -v /opt/jiuzhang/models/semantic:/models:ro \
  -v caddy_sidecars:/var/run/caddy/sidecars \
  jiuzhang-semantic-guard:1.16.0
```

### 2. 裸机 systemd

1. 将 `server.py` 部署到 `/opt/jiuzhang/semantic-guard/server.py`；
2. 复制 `jiuzhang-semantic-guard.service` 至 `/etc/systemd/system/`；
3. 如使用 ONNX 模型，在 `/etc/jiuzhang/semantic-guard/semantic-guard.env` 中配置 `SEMANTIC_GUARD_MODEL_MANIFEST=/opt/jiuzhang/models/semantic/model-manifest.json`；
4. 执行 `systemctl daemon-reload && systemctl enable --now jiuzhang-semantic-guard.service`。

## 本地单元测试

```bash
python3 -m unittest discover -s deployment/semantic-guard -p "test_*.py" -v
```
