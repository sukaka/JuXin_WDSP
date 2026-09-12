# 九章 WDSP 分布式流量采集 Agent — Phase 5 实施契约（Kubernetes Sensor）

**版本：V1.0（Phase 5 冻结契约，增量于 Phase 1-4，不修改既有契约任何条目）**
**上游设计：docs/agents/WDSP_DISTRIBUTED_AGENT_DESIGN.md（§39 Kubernetes Sensor、§5.4 模式 D、§59 Phase 5、§72 红线）**
**基线：Phase 1-4 契约继续有效（机器端点、PoP、采集等级、脱敏、定向规则、背压）**

## 1. 范围

- Agent 以 DaemonSet 形态运行于 K8s Node（每 Node 一个 Sensor），复用既有全部采集能力（宿主机网卡/容器网桥流量采集）。
- Pod 元数据关联：流量事件与 HTTP 记录附加 k8s 块（cluster/namespace/pod/workload/service）。
- 部署清单（DaemonSet/RBAC/ConfigMap）与 Agent 容器镜像 Dockerfile（版本锁定）。
- 管理端与前端展示 k8s 元数据。
- 明确不做：多集群联邦、NetworkPolicy 生成、K8s 事件流采集、CNI 级 eBPF 挂点优化（属 Phase 7 性能域）。

## 2. k8s 元数据块（事件 schema 加法）

flow 事件（Phase 1 §3.4）与 HTTP 记录（Phase 3 §3）均新增可选字段：

```json
"k8s": {
  "cluster": "prod",
  "namespace": "payment",
  "pod": "payment-api-7d9f8c6b5-x2v1a",
  "workload": "payment-api",
  "service": "payment-api",
  "side": "dst"
}
```

- 关联规则：src/dst 任一侧 IP 命中本 Node Pod IP 表时附加；两侧都命中（东西向）取 server 侧（dst，即命中采集端口的一侧），`side` 标明取自哪侧（src|dst）。
- `workload`：Pod 顶层 ownerReference 名（ReplicaSet 归属 Deployment 时取 Deployment 名——经 ownerReferences 链上溯一层）；无 owner 取 Pod 名。
- `service`：尽力而为（Endpoints/EndpointSlice 的 IP→Service 反查）；查不到省略该字段。
- `cluster`：Agent 本地配置（apiserver 不暴露集群名）。
- 非 K8s 环境或未命中时整个 `k8s` 字段缺省（omitempty），不产生空对象。
- 服务端校验：k8s 为可选对象，各字符串字段 ≤253 字节、side ∈ {src,dst}；非法整体忽略 k8s 字段不拒绝事件（fail-open，宽进）。

## 3. Agent 行为（internal/k8smeta）

- 依赖约束：**不引入 client-go**——stdlib HTTP 直连 kube-apiserver（in-cluster：KUBERNETES_SERVICE_HOST/PORT + /var/run/secrets/kubernetes.io/serviceaccount/{token,ca.crt}），go.mod 零新增依赖。
- 启用判定：`auto`（默认，检测到 in-cluster 环境即启用）| `on` | `off`（本地 config `k8s.enabled`；策略侧不控制）。
- 同步：每 30s 全量拉取 `GET /api/v1/pods?fieldSelector=spec.nodeName=<NODE_NAME>&status.phase=Running`（NODE_NAME 取 env，DaemonSet 经 downward API 注入）与 `GET /api/v1/endpoints?fieldSelector=...`（无 fieldSelector 可用时全量限量拉取，页大小 500 续传）；构建 IP→pod 映射与 IP→service 映射；同步失败保留旧表并 Warn（fail-open，不阻断采集）。
- RBAC 最小权限：pods/endpoints 的 list/watch（只读）。
- 热路径：map 查询 O(1)（atomic 快照替换）；不缓存 Pod 增删事件流（watch 属后续优化）。
-  enriched 时机：flow 事件与 HTTP 记录 emit 时查表附加；查表失败/禁用则字段缺省。

## 4. 服务端（迁移 000115_traffic_agent_k8s）

- `agent_flow_events` 与 `agent_http_events` 各加 `k8s jsonb NULL`；无新索引（Phase 5 不按 k8s 字段检索）。
- /flows 与 /http 机器端点接受并落库 k8s 块（§2 校验）；管理端 events/http-events 响应原样带出。
- 健康评分/资产联动不变。

## 5. 部署清单（deployment/kubernetes/，版本锁定）

- `wdsp-agent-daemonset.yaml`：DaemonSet（hostNetwork: false、hostPID 不需要；securityContext: capabilities NET_ADMIN+NET_RAW+SYS_ADMIN(eBPF 需要时) 或 privileged 说明档；volumeMounts 挂 /var/lib/wdsp-agent hostPath；env：WDSP_SERVER、WDSP_ENROLLMENT_TOKEN（Secret 引用）、NODE_NAME（fieldRef spec.nodeName）、K8S_CLUSTER_NAME）。
- `wdsp-agent-rbac.yaml`：ServiceAccount + ClusterRole（pods/endpoints list/watch）+ ClusterRoleBinding。
- `wdsp-agent-configmap.yaml`：默认采集配置示例。
- Agent 镜像：`deployment/docker/wdsp-agent/Dockerfile`（多阶段：golang:1.25.6 构建 CGO_ENABLED=0 + 锁定 digest 的 alpine 运行基镜像，ENTRYPOINT wdsp-agent run）；镜像发布名 `jiuzhang/wdsp-agent:<version>`（构建说明写入 README，不虚构已发布的 digest）。
- 安装文档：`deployment/kubernetes/README.md`（创建 Secret→apply RBAC→DaemonSet→验证 Agent 上线）。

## 6. 前端口径

- 流量事件表与 HTTP 事件详情：k8s 块存在时展示 `namespace/pod`（Tooltip 全量 cluster/workload/service/side）；无 k8s 不占位。
- 不做独立 K8s 拓扑/清单页（设计 §59 Phase 5 的"K8s UI"以元数据可见为准，集群级视图后续）。

## 7. 兼容性

- 事件/记录 schema 纯加法；旧 Agent（无 k8s 字段）与旧服务端（无 k8s 列）组合均正常（新 Agent 对旧服务端：k8s 字段被忽略——服务端反序列化需容忍未知字段或显式读取，实现时注意 /flows、/http 解码不得 DisallowUnknownFields 拒收）。
- 迁移增量无破坏。
