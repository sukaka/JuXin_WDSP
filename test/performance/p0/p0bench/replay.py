"""语料确定性回放请求生成器（P0-02 任务书 §5）。

generate_requests(manifest, profile) 产出逐条具体请求（JSONL 友好）：
- 正常样本：由模板 generator + 种子确定性生成（同一 seed 任何机器结果一致）。
- 攻击样本：使用 manifest 中 request_override 的字面量（自研合成，哈希覆盖）。
- deferred 样本不产出（不计入指标）。
- 声明 jwt_inject 的样本原样透传该标记；仅在 JWT 配对 profile（jwt_off/
  jwt_protect）回放时由 run.sh 从 run 目录 0600 临时头文件注入 Bearer Token
  （运行期本地测试私钥现场签发）；七模式基线回放不注入（JWT 关闭语义）。
- 每条请求分配 request_id = <case_id>-<seq>，由运行器经 X-Request-Id 注入；
  关联可信度依赖网关可信 request_id（§6.2.1），回放侧 ID 仅作对账键。
"""

from __future__ import annotations

import json
import random
import string

WORD_POOL = (
    "alpha beta gamma delta search report article vector tensor matrix "
    "chapter section Figure Table index query update draft review"
).split()


def _rng(seed: int) -> random.Random:
    return random.Random(seed)


def _gen_json_object(seed: int, params: dict) -> str:
    r = _rng(seed)
    size = int(params.get("size_bytes", 512))
    obj = {"title": "p0bench-" + str(seed), "tags": r.sample(WORD_POOL, 4), "payload": ""}
    base = json.dumps(obj, ensure_ascii=False)
    if len(base) < size:
        obj["payload"] = "x" * (size - len(base))
    return json.dumps(obj, ensure_ascii=False)


def _gen_form_pairs(seed: int, params: dict) -> str:
    r = _rng(seed)
    pairs = [
        ("user", "p0bench_user_%d" % r.randint(100, 999)),
        ("comment", "SELECT 语句示例：SELECT * FROM t WHERE id = 1（文本内容）"),
        ("note", "".join(r.choice(string.ascii_letters + " \"'();/%") for _ in range(48))),
    ]
    from urllib.parse import urlencode

    return urlencode(pairs)


def _gen_multipart_file(seed: int, params: dict) -> str:
    r = _rng(seed)
    size = int(params.get("size_bytes", 4096))
    content = "".join(r.choice(string.ascii_letters + string.digits + "\n") for _ in range(size))
    boundary = "p0benchBOUNDARY"
    return (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="desc"\r\n\r\np0bench seeded upload\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="seed{seed}.txt"\r\n'
        f"Content-Type: text/plain\r\n\r\n{content}\r\n"
        f"--{boundary}--\r\n"
    )


def _gen_search_query(seed: int, params: dict) -> str:
    r = _rng(seed)
    return "q=" + "+".join(r.sample(WORD_POOL, 3))


GENERATORS = {
    "json_object": _gen_json_object,
    "form_pairs": _gen_form_pairs,
    "multipart_file": _gen_multipart_file,
    "search_query": _gen_search_query,
}


def generate_request(case: dict, templates: dict, seq: int) -> dict:
    tpl = templates[case["template"]]
    params = dict(case.get("generator_params") or {})
    # 模板级参数兜底（如 multipart_upload.size_bytes）
    tpl_body = tpl.get("body") or {}
    if isinstance(tpl_body, dict) and "size_bytes" in tpl_body:
        params.setdefault("size_bytes", tpl_body["size_bytes"])

    req = {
        "request_id": f"{case['case_id']}-{seq:04d}",
        "case_id": case["case_id"],
        "method": tpl.get("method", "GET"),
        "path": tpl.get("path", "/"),
        "query": "",
        "headers": dict(tpl.get("headers") or {}),
        "body": None,
    }

    gen = tpl_body.get("generator") if isinstance(tpl_body, dict) else None
    if gen:
        if gen not in GENERATORS:
            raise ValueError(f"未知生成器 {gen!r}（case {case['case_id']}）")
        payload = GENERATORS[gen](case["seed"], params)
        if gen == "search_query":
            req["query"] = payload
        else:
            req["body"] = payload

    override = case.get("request_override") or {}
    for key in ("method", "path", "query", "body"):
        if key in override:
            req[key] = override[key]
    if "headers" in override:
        req["headers"].update(override["headers"])
    if case.get("jwt_inject"):
        req["jwt_inject"] = case["jwt_inject"]

    return req


def generate_requests(manifest: dict, profile: str | None = None) -> list[dict]:
    """产出全部活跃样本（deferred 跳过）的具体请求，顺序按 case_id 排序保证确定性。"""
    templates = manifest.get("request_templates") or {}
    cases = sorted(
        (c for c in manifest.get("cases", []) if not c.get("deferred")),
        key=lambda c: c["case_id"],
    )
    out = []
    for seq, case in enumerate(cases, 1):
        req = generate_request(case, templates, seq)
        req["expected_action"] = (case.get("expected_action") or {}).get(profile) if profile else None
        out.append(req)
    return out
