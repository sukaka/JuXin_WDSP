# WDSP Agent Kubernetes 部署

此清单以 DaemonSet 在每个 Node 运行一个 WDSP Agent。镜像名遵循
`jiuzhang/wdsp-agent:<version>`；示例使用 `2.3.0`，不代表该镜像已经发布。

## 构建镜像

在仓库根目录执行：

```bash
docker build -f deployment/docker/wdsp-agent/Dockerfile -t jiuzhang/wdsp-agent:2.3.0 .
```

将镜像推送到集群可访问的镜像仓库，并同步修改 DaemonSet 中的两个 `image` 字段。
发布到仓库后必须按 digest 锁定引用（当前 `2.3.0` 未发布，仓库内清单不虚构 digest）：

```bash
docker buildx imagetools inspect jiuzhang/wdsp-agent:2.3.0   # 取 Digest
# DaemonSet 改为 jiuzhang/wdsp-agent:2.3.0@sha256:<digest>
```

## 安装

先创建命名空间和最小只读 RBAC：

```bash
kubectl apply -f deployment/kubernetes/wdsp-agent-rbac.yaml
```

Enrollment Token 只能消费一次，因此每个尚未注册的节点都必须使用不同令牌。先查看节点名，
再在 WDSP 管理端为每个节点创建一个一次性 Token。不要把令牌写进清单或 Git：

```bash
kubectl get nodes -o name
kubectl -n wdsp-system create secret generic wdsp-agent-bootstrap \
  --from-literal=server='https://wdsp.example.com'
kubectl -n wdsp-system create secret generic wdsp-agent-bootstrap-tokens \
  --from-literal=node-a="$WDSP_TOKEN_NODE_A" \
  --from-literal=node-b="$WDSP_TOKEN_NODE_B"
```

`wdsp-agent-bootstrap-tokens` 的键必须与 `spec.nodeName` 完全一致；值是该节点专用的一次性 Token。
节点已经有 `/var/lib/wdsp-agent/agent.json` 时不会再次消费 Token。新增节点前，先为它签发 Token 并更新该 Secret。

`wdsp-agent-configmap.yaml` 中包含与 Agent 内置口径一致的配置参考。应用它和 DaemonSet，并把
`K8S_CLUSTER_NAME` 的 `change-me` 改为当前集群的稳定名称：

```bash
kubectl apply -f deployment/kubernetes/wdsp-agent-configmap.yaml
kubectl apply -f deployment/kubernetes/wdsp-agent-daemonset.yaml
kubectl -n wdsp-system rollout status daemonset/wdsp-agent
```

Agent 首次启动时注册，身份文件保存在节点 `/var/lib/wdsp-agent`；Pod 重启不会重复消耗一次性令牌。默认采集端口为
`80,443,8000,8001,8080,8081,8443,8888,9000,9443`，方向 `both`，输出 `FLOW`。

## 验证

```bash
kubectl -n wdsp-system get pods -l app.kubernetes.io/name=wdsp-agent -o wide
kubectl -n wdsp-system logs daemonset/wdsp-agent -c wdsp-agent --tail=100
kubectl auth can-i --as=system:serviceaccount:wdsp-system:wdsp-agent list pods --all-namespaces
kubectl auth can-i --as=system:serviceaccount:wdsp-system:wdsp-agent list endpoints --all-namespaces
kubectl auth can-i --as=system:serviceaccount:wdsp-system:wdsp-agent list replicasets.apps --all-namespaces
kubectl auth can-i --as=system:serviceaccount:wdsp-system:wdsp-agent watch pods --all-namespaces   # 应为 no（实现只用 list）
```

流量或 HTTP 事件命中 Pod IP 后，管理端应显示 `namespace/pod`。同步 Kubernetes API 失败时 Agent 保留最后一次成功快照，不中断采集；心跳 metrics 中的
`k8smeta_state` 显式显示 `STALE`（含距上次成功秒数 `k8smeta_stale_seconds`），持续失败超过 5 分钟升级为 `UNAVAILABLE`。
快照条目超过 10 分钟未被成功刷新再确认后不再参与解析，防止 Pod 删除 / IP 重用把流量串联到旧归属；
`k8smeta_inferred_owners` 计数工作负载名为 ReplicaSet 截尾推断（未经权威解析）的条目。

## 权限说明

- Pod 不使用 `hostNetwork`、`hostPID` 或 privileged。
- 主容器仅增加 AF_PACKET 所需的 `NET_RAW`、`NET_ADMIN`；默认不授予 `SYS_ADMIN`。若明确启用需要额外权限的 eBPF 模式，应先按集群内核和安全策略单独评估。
- ClusterRole 仅允许 list pods、endpoints 和 replicasets（无 watch、无 get；endpoints/replicasets 由 Agent 按本节点 Pod 所在 namespace 分别查询）。
- hostNetwork Pod 的 IP 即节点 IP，Agent 跳过其映射，不把节点级流量归属到该工作负载。
