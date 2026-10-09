# test/httpchain —— HTTP 解析链一致性测试台（NG-HTTP-01）

验证「客户实际接入链中的每一跳如何解释请求」，比对网关安全判断与源站实况；不是在业务检测器中写新 HTTP 解析器。

## 组成

| 件 | 说明 |
|---|---|
| `origin/` | 记录型测试源站（Go）：登记方法/原始路径/头名序/声明长度 vs 实际体长/体 sha256/每连接请求计数；`/__chain/records`、`/__chain/reset` 两个控制面；不落凭据（头值仅允许清单内几项） |
| `topology.yaml` | 链路清单（直连/可信代理/h2→h1.1/路径重写/连接复用），每条标注覆盖用例与验证状态（untested/pass/fail/partial） |
| `corpus/` | 隔离语料 HC-N01（正常）、HC-A01（CL/TE 冲突原始报文）、HC-A02（绝对形式/伪造转发头）、HC-A03（Host/authority 不一致）、HC-U01（罕见方法/超大头），全部合成数据 |
| `run.py` | 驱动：`sanity`（T0 直连源站自检，零依赖）、`via-gateway`（T1 经网关转述比对，需 GATEWAY_URL/HOST_HEADER 与指向记录源站的上游路由） |

## 使用

```bash
# 启动记录型源站（默认 127.0.0.1:18099，CHAIN_ORIGIN_ADDR 可改）
go run ./test/httpchain/origin &

# T0 自检（无需网关）
python3 test/httpchain/run.py sanity

# T1 经网关（需先把某测试应用上游指向记录型源站；stage5 专用拓扑在 NG-HTTP-01 实施时冻结）
GATEWAY_URL=http://127.0.0.1:18080 HOST_HEADER=waf-s5.local python3 test/httpchain/run.py via-gateway
```

## 纪律

- 危险样本只放 `corpus/`，只发隔离目标；不进生产运行包。
- 语料全部合成（example.com / RFC5737 段）；源站只记头名与允许清单头值、体只留 sha256 与长度。
- 无法可靠观察的畸形报文以底层服务器拒绝行为 + 源站连接计数验收，不凭客户端状态码下结论。

当前状态（2026-10-03）：T0 5/5 PASS；T1 待 stage5 专用上游拓扑冻结后启用。
