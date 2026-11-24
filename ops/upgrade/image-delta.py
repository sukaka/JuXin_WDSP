#!/usr/bin/env python3
"""WDSP Docker 镜像层差量（layer-delta）构建与宿主机重建工具。

仅使用 Python 3 标准库（零第三方依赖），支持经典 Docker Archive（docker save）
与 Docker 25+ containerd 存储导出的含 gzip 压缩 blob 归档。

安全边界（fail-closed）：
  - 所有层均按未压缩 tar 内容的 SHA-256（diff_id）严格校验；
  - apply 阶段要求外层已验签 manifest.json 声明的 base_layers 与内层
    delta-manifest.json 声明的基础层集合完全一致；
  - 拒绝路径穿越、绝对路径、符号链接/硬链接/特殊文件与超大解压体积。
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tempfile

DELTA_FORMAT = "wdsp-image-layer-delta-v1"
RUNTIME_POLICY_KEY = "com.jiuzhang.runtime.policy"
RUNTIME_POLICY_VAL = "no-docs-tests-v1"
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_REL_RE = re.compile(r"^[A-Za-z0-9._/-]+$")
MAX_EXPANDED_BYTES = 8 << 30
MAX_DELTA_MEMBERS = 256
CHUNK_BYTES = 1 << 20

COMPONENT_IMAGE_PREFIX = {
    "api": "jiuzhang-server",
    "web": "jiuzhang-web",
    "gateway": "jiuzhang-gateway",
    "netmgrd": "jiuzhang-netmgrd",
    "mirrorcap": "jiuzhang-mirrorcap",
    "tproxyd": "jiuzhang-tproxyd",
    "havipd": "jiuzhang-havipd",
    "hasyncd": "jiuzhang-hasyncd",
    "logrotator": "jiuzhang-logrotator",
    "containerops": "jiuzhang-containerops",
    "pcapd": "jiuzhang-pcapd",
}
IMAGE_TAR_TO_COMPONENT = {f"{img}.tar": comp for comp, img in COMPONENT_IMAGE_PREFIX.items()}


def fail(msg):
    sys.stderr.write(f"image-delta: {msg}\n")
    raise SystemExit(1)


def is_valid_diff_id(value):
    return isinstance(value, str) and bool(SHA256_RE.match(value))


def safe_rel_path(name):
    if not isinstance(name, str) or not name or "\x00" in name:
        fail(f"非法归档路径: {name!r}")
    norm = name.lstrip("./") if name.startswith("./") else name
    parts = PurePosixPath(norm).parts
    if not parts or norm.startswith("/") or "\\" in norm or ".." in parts:
        fail(f"归档路径不安全: {name!r}")
    return "/".join(parts)


def excluded_runtime_entry(name, is_directory=False):
    """与 ops/offline-package/runtime-image.py 保持完全一致的裁剪口径。"""
    parts = PurePosixPath(name).parts
    if name.startswith("/") or ".." in parts:
        raise ValueError("unsafe image member")
    lower = tuple(p.lower() for p in parts)
    leaf = lower[-1] if lower else ""
    directories = lower if is_directory else lower[:-1]
    if leaf.startswith(("license", "licence", "copying", "copyright", "notice")):
        return False
    return bool(
        set(directories) & {"test", "tests", "testdata", "__tests__", "__pycache__", ".git"}
        or set(directories) & {"doc", "docs", "man", "info"}
        or leaf.startswith(("readme", "changelog"))
        or leaf.endswith((".md", ".rst", "_test.go", ".test.ts", ".spec.ts", ".map"))
        or "usr/local/lib/postgresql/pgxs" in "/".join(parts)
    )


def add_bytes_member(archive, name, data):
    member = tarfile.TarInfo(name)
    member.size = len(data)
    member.mode = 0o644
    member.mtime = 0
    archive.addfile(member, io.BytesIO(data))


def lookup_member(tf, rel_path):
    """按归一化相对路径在 tarfile 中查找普通文件成员（兼容 ./ 前缀）。"""
    wanted = safe_rel_path(rel_path)
    for m in tf.getmembers():
        if not m.isfile():
            continue
        if safe_rel_path(m.name) == wanted:
            return m
    fail(f"归档缺少成员: {wanted}")


def stream_copy_bounded(src_fh, dst_fh, remaining_budget):
    digest = hashlib.sha256()
    written = 0
    while True:
        chunk = src_fh.read(CHUNK_BYTES)
        if not chunk:
            break
        written += len(chunk)
        if written > remaining_budget:
            fail("解压大小超出安全上限")
        digest.update(chunk)
        dst_fh.write(chunk)
    return written, "sha256:" + digest.hexdigest()


def extract_uncompressed_layer(tf, member_name, out_path, remaining_budget, sanitize=False):
    """将 docker save 中的单个层（raw tar 或 gzip blob）解出为未压缩 tar 并返回 (size, diff_id)。"""
    member = lookup_member(tf, member_name)
    raw_stream = tf.extractfile(member)
    if raw_stream is None:
        fail(f"无法读取镜像层: {member_name}")
    if sanitize:
        with tarfile.open(fileobj=raw_stream, mode="r|*") as src, tarfile.open(
            out_path, "w", format=tarfile.PAX_FORMAT
        ) as dst:
            for item in src:
                if excluded_runtime_entry(item.name, item.isdir()):
                    continue
                dst.addfile(item, src.extractfile(item) if item.isfile() else None)
        digest = hashlib.sha256()
        size = 0
        with open(out_path, "rb") as fh:
            while True:
                chunk = fh.read(CHUNK_BYTES)
                if not chunk:
                    break
                size += len(chunk)
                if size > remaining_budget:
                    fail("裁剪后镜像层大小超出安全上限")
                digest.update(chunk)
        return size, "sha256:" + digest.hexdigest()

    head = raw_stream.read(2)
    chained = io.BytesIO(head)

    class _PrefixReader(io.RawIOBase):
        def readable(self):
            return True

        def readinto(self, b):
            first = chained.read(len(b))
            if first:
                b[: len(first)] = first
                return len(first)
            rest = raw_stream.read(len(b))
            if not rest:
                return 0
            b[: len(rest)] = rest
            return len(rest)

    reader = io.BufferedReader(_PrefixReader())
    if head == b"\x1f\x8b":
        with gzip.GzipFile(fileobj=reader, mode="rb") as gz, open(out_path, "wb") as dst:
            return stream_copy_bounded(gz, dst, remaining_budget)
    with open(out_path, "wb") as dst:
        return stream_copy_bounded(reader, dst, remaining_budget)


def read_docker_archive_meta(tf):
    """读取 docker save 归档的唯一镜像 manifest + config。"""
    man_member = lookup_member(tf, "manifest.json")
    manifests = json.loads(tf.extractfile(man_member).read().decode("utf-8"))
    if not isinstance(manifests, list) or len(manifests) != 1:
        fail("镜像归档必须恰好包含单个平台/镜像条目")
    manifest = manifests[0]
    cfg_name = manifest.get("Config")
    layers = manifest.get("Layers")
    if not isinstance(cfg_name, str) or not isinstance(layers, list) or not layers:
        fail("镜像 manifest.json 缺少 Config 或 Layers")
    cfg_member = lookup_member(tf, cfg_name)
    cfg_bytes = tf.extractfile(cfg_member).read()
    config = json.loads(cfg_bytes.decode("utf-8"))
    diff_ids = (config.get("rootfs") or {}).get("diff_ids")
    if not isinstance(diff_ids, list) or len(diff_ids) != len(layers):
        fail("镜像 config.rootfs.diff_ids 与 manifest.Layers 数量不一致")
    for did in diff_ids:
        if not is_valid_diff_id(did):
            fail(f"镜像 diff_id 格式非法: {did!r}")
    labels = (config.get("config") or {}).get("Labels") or {}
    sanitized = labels.get(RUNTIME_POLICY_KEY) == RUNTIME_POLICY_VAL
    return manifest, config, cfg_bytes, diff_ids, sanitized


def inspect_single_image_stream(fileobj):
    with tarfile.open(fileobj=fileobj, mode="r:*") as tf:
        _, _, _, diff_ids, sanitized = read_docker_archive_meta(tf)
        return {"diff_ids": diff_ids, "runtime_sanitized": sanitized}


def inspect_archive_file(archive_path, explicit_component=None):
    """从离线完整包、升级包或单镜像 tar 中提取各组件的 diff_ids 与 runtime_sanitized。"""
    result = {}
    with tarfile.open(archive_path, mode="r:*") as tf:
        members = tf.getmembers()
        names = [safe_rel_path(m.name) for m in members if m.isfile()]
        if "manifest.json" in names and explicit_component:
            _, _, _, diff_ids, sanitized = read_docker_archive_meta(tf)
            result[explicit_component] = {
                "diff_ids": diff_ids,
                "runtime_sanitized": sanitized,
                "source": str(archive_path),
            }
            return result

        # 查找根级 <root>/manifest.json（离线包或升级包）
        top_manifests = [n for n in names if n.count("/") == 1 and n.endswith("/manifest.json")]
        if len(top_manifests) != 1:
            fail(f"无法识别基准归档结构（需为完整离线包、升级包或指定 --component 的单镜像归档）: {archive_path}")
        root_prefix = top_manifests[0].split("/", 1)[0]
        pkg_manifest = json.loads(
            tf.extractfile(lookup_member(tf, top_manifests[0])).read().decode("utf-8")
        )

        # 情况 1：升级包（package_type == "upgrade"）
        if pkg_manifest.get("package_type") == "upgrade":
            for img_entry in pkg_manifest.get("images") or []:
                comp = img_entry.get("component") or img_entry.get("service")
                if comp not in COMPONENT_IMAGE_PREFIX:
                    continue
                if isinstance(img_entry.get("diff_ids"), list) and img_entry["diff_ids"] and all(
                    is_valid_diff_id(d) for d in img_entry["diff_ids"]
                ):
                    result[comp] = {
                        "diff_ids": list(img_entry["diff_ids"]),
                        "runtime_sanitized": bool(img_entry.get("runtime_sanitized", False)),
                        "source": str(archive_path),
                    }
                    continue
                tar_rel = img_entry.get("tar")
                if not isinstance(tar_rel, str):
                    continue
                full_rel = f"{root_prefix}/{safe_rel_path(tar_rel)}"
                if full_rel not in names:
                    continue
                if img_entry.get("delivery_mode") == "layer-delta":
                    # 兼容：即便旧格式未在外部写 diff_ids，也可从内层 delta-manifest 读取
                    raw_sub = tf.extractfile(lookup_member(tf, full_rel)).read()
                    with tarfile.open(fileobj=io.BytesIO(raw_sub), mode="r:gz") as sub_tf:
                        dm = json.loads(
                            sub_tf.extractfile(lookup_member(sub_tf, "delta-manifest.json")).read().decode("utf-8")
                        )
                        cfg = json.loads(
                            sub_tf.extractfile(lookup_member(sub_tf, dm["config_file"])).read().decode("utf-8")
                        )
                        labels = (cfg.get("config") or {}).get("Labels") or {}
                        result[comp] = {
                            "diff_ids": [x["diff_id"] for x in dm["layers"]],
                            "runtime_sanitized": labels.get(RUNTIME_POLICY_KEY) == RUNTIME_POLICY_VAL,
                            "source": str(archive_path),
                        }
                else:
                    raw_sub = tf.extractfile(lookup_member(tf, full_rel)).read()
                    info = inspect_single_image_stream(io.BytesIO(raw_sub))
                    info["source"] = str(archive_path)
                    result[comp] = info
            return result

        # 情况 2：离线完整包 / update-full（images/jiuzhang-*.tar）
        for rel in names:
            if not rel.startswith(f"{root_prefix}/images/"):
                continue
            base = rel.rsplit("/", 1)[-1]
            comp = IMAGE_TAR_TO_COMPONENT.get(base)
            if not comp:
                continue
            sub_fh = tf.extractfile(lookup_member(tf, rel))
            info = inspect_single_image_stream(sub_fh)
            info["source"] = str(archive_path)
            result[comp] = info
        return result


def cmd_inspect_base(args):
    merged = {}
    for archive_path in args.archive:
        data = inspect_archive_file(archive_path, explicit_component=args.component)
        merged.update(data)
    print(json.dumps(merged, sort_keys=True))


def cmd_inspect_docker(args):
    comps = [c.strip() for c in args.components.replace(",", " ").split() if c.strip()]
    merged = {}
    for comp in comps:
        prefix = COMPONENT_IMAGE_PREFIX.get(comp)
        if not prefix:
            fail(f"未知组件: {comp}")
        ref = f"{prefix}:{args.from_version}"
        proc = subprocess.run(
            ["docker", "image", "inspect", ref],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            fail(f"本机不存在基准镜像: {ref}")
        arr = json.loads(proc.stdout)
        if not isinstance(arr, list) or len(arr) != 1:
            fail(f"无法解析基准镜像元数据: {ref}")
        item = arr[0]
        diff_ids = (item.get("RootFS") or {}).get("Layers") or []
        if not diff_ids or not all(is_valid_diff_id(d) for d in diff_ids):
            fail(f"基准镜像 RootFS.Layers 异常: {ref}")
        labels = (item.get("Config") or {}).get("Labels") or {}
        merged[comp] = {
            "diff_ids": diff_ids,
            "runtime_sanitized": labels.get(RUNTIME_POLICY_KEY) == RUNTIME_POLICY_VAL,
            "source": f"docker:{ref}",
        }
    print(json.dumps(merged, sort_keys=True))


def cmd_create(args):
    base_diff_ids = json.loads(args.base_diff_ids_json)
    if not isinstance(base_diff_ids, list) or not all(is_valid_diff_id(d) for d in base_diff_ids):
        fail("--base-diff-ids-json 必须为 sha256:... 字符串数组")
    base_set = set(base_diff_ids)

    with tempfile.TemporaryDirectory(prefix="wdsp-delta-create-") as tmp:
        tmp_dir = Path(tmp)
        budget = MAX_EXPANDED_BYTES
        extracted_layers = []
        with tarfile.open(args.target_tar, mode="r:*") as tf:
            manifest, config, _, orig_diff_ids, already_sanitized = read_docker_archive_meta(tf)
            sanitize = bool(args.sanitize_runtime)
            for idx, (layer_member, orig_did) in enumerate(zip(manifest["Layers"], orig_diff_ids)):
                layer_path = tmp_dir / f"layer-{idx:03d}.tar"
                size, actual_did = extract_uncompressed_layer(
                    tf, layer_member, layer_path, budget, sanitize=sanitize
                )
                budget -= size
                if not sanitize and actual_did != orig_did:
                    fail(
                        f"目标镜像层 #{idx} 摘要与 config.rootfs.diff_ids 不一致: "
                        f"actual={actual_did} expected={orig_did}"
                    )
                extracted_layers.append((idx, actual_did, layer_path, size))

        new_diff_ids = [did for _, did, _, _ in extracted_layers]
        config["rootfs"]["diff_ids"] = new_diff_ids
        runtime_sanitized = already_sanitized or sanitize
        if sanitize:
            labels = (config.setdefault("config", {}).get("Labels")) or {}
            labels.update(
                {
                    "com.jiuzhang.runtime.source": args.target_image,
                    RUNTIME_POLICY_KEY: RUNTIME_POLICY_VAL,
                }
            )
            config["config"]["Labels"] = labels
        cfg_bytes = json.dumps(config, sort_keys=True, separators=(",", ":")).encode("utf-8")
        cfg_sha = hashlib.sha256(cfg_bytes).hexdigest()
        cfg_file = f"{cfg_sha}.json"

        total_bytes = sum(sz for _, _, _, sz in extracted_layers)
        reused_bytes = sum(sz for _, did, _, sz in extracted_layers if did in base_set)
        delta_bytes = total_bytes - reused_bytes

        # 唯一有序的基础层清单（保持目标层序）
        used_base_layers = []
        seen_base = set()
        for _, did, _, _ in extracted_layers:
            if did in base_set and did not in seen_base:
                seen_base.add(did)
                used_base_layers.append(did)

        use_delta = bool(used_base_layers) and (reused_bytes >= args.min_savings_bytes)

        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_out = out_path.with_name(out_path.name + ".tmp")

        if use_delta:
            layer_entries = []
            with tarfile.open(tmp_out, "w:gz", format=tarfile.PAX_FORMAT) as out_tf:
                add_bytes_member(out_tf, cfg_file, cfg_bytes)
                for idx, did, layer_path, size in extracted_layers:
                    if did in base_set:
                        layer_entries.append(
                            {"index": idx, "diff_id": did, "source": "base"}
                        )
                    else:
                        hex_did = did.split(":", 1)[1]
                        rel_layer = f"layers/{idx:02d}-{hex_did}.tar"
                        ti = out_tf.gettarinfo(str(layer_path), arcname=rel_layer)
                        ti.uid = 0
                        ti.gid = 0
                        ti.uname = ""
                        ti.gname = ""
                        ti.mode = 0o644
                        ti.mtime = 0
                        with open(layer_path, "rb") as fh:
                            out_tf.addfile(ti, fh)
                        layer_entries.append(
                            {
                                "index": idx,
                                "diff_id": did,
                                "source": "delta",
                                "path": rel_layer,
                                "size": size,
                            }
                        )
                delta_manifest = {
                    "format": DELTA_FORMAT,
                    "target_image": args.target_image,
                    "config_file": cfg_file,
                    "config_sha256": cfg_sha,
                    "layers": layer_entries,
                }
                add_bytes_member(
                    out_tf,
                    "delta-manifest.json",
                    json.dumps(delta_manifest, sort_keys=True, separators=(",", ":")).encode("utf-8"),
                )
            os.replace(tmp_out, out_path)
            summary = {
                "delivery_mode": "layer-delta",
                "runtime_sanitized": runtime_sanitized,
                "base_layers": used_base_layers,
                "diff_ids": new_diff_ids,
                "reused_bytes": reused_bytes,
                "delta_bytes": delta_bytes,
                "total_bytes": total_bytes,
            }
        else:
            tar_layers = []
            with tarfile.open(tmp_out, "w:gz", format=tarfile.PAX_FORMAT) as out_tf:
                add_bytes_member(out_tf, cfg_file, cfg_bytes)
                for idx, did, layer_path, _ in extracted_layers:
                    hex_did = did.split(":", 1)[1]
                    rel_layer = f"{idx}-{hex_did}/layer.tar"
                    ti = out_tf.gettarinfo(str(layer_path), arcname=rel_layer)
                    ti.uid = 0
                    ti.gid = 0
                    ti.uname = ""
                    ti.gname = ""
                    ti.mode = 0o644
                    ti.mtime = 0
                    with open(layer_path, "rb") as fh:
                        out_tf.addfile(ti, fh)
                    tar_layers.append(rel_layer)
                add_bytes_member(
                    out_tf,
                    "manifest.json",
                    json.dumps(
                        [
                            {
                                "Config": cfg_file,
                                "RepoTags": [args.target_image],
                                "Layers": tar_layers,
                            }
                        ],
                        separators=(",", ":"),
                    ).encode("utf-8"),
                )
            os.replace(tmp_out, out_path)
            summary = {
                "delivery_mode": "full",
                "runtime_sanitized": runtime_sanitized,
                "base_layers": [],
                "diff_ids": new_diff_ids,
                "reused_bytes": 0,
                "delta_bytes": total_bytes,
                "total_bytes": total_bytes,
            }
    print(json.dumps(summary, sort_keys=True))


def cmd_check_base(args):
    required = json.loads(args.required_base_layers_json)
    actual = json.loads(args.actual_layers_json)
    if not isinstance(required, list) or not required or not all(is_valid_diff_id(d) for d in required):
        fail("required base_layers 清单为空或格式非法")
    if not isinstance(actual, list) or not all(is_valid_diff_id(d) for d in actual):
        fail("宿主机当前镜像 RootFS.Layers 格式非法")
    actual_set = set(actual)
    missing = [d for d in required if d not in actual_set]
    if missing:
        sample = ", ".join(m[:19] for m in missing[:3])
        fail(f"缺少 {len(missing)}/{len(required)} 个差量基础层（示例: {sample}）")
    print("OK")


def cmd_apply(args):
    expected_base = json.loads(args.expected_base_layers_json)
    if (
        not isinstance(expected_base, list)
        or not expected_base
        or not all(is_valid_diff_id(d) for d in expected_base)
    ):
        fail("外层 manifest base_layers 非法或为空")
    expected_base_set = set(expected_base)

    with tempfile.TemporaryDirectory(prefix="wdsp-delta-apply-") as tmp:
        tmp_dir = Path(tmp)
        delta_dir = tmp_dir / "delta"
        base_dir = tmp_dir / "base"
        delta_dir.mkdir()
        base_dir.mkdir()

        # 1. 安全扫描并验证 delta-tar 归档
        with tarfile.open(args.delta_tar, mode="r:gz") as dtf:
            members = dtf.getmembers()
            if not members or len(members) > MAX_DELTA_MEMBERS:
                fail("差量镜像归档成员数量异常")
            member_map = {}
            expanded = 0
            for m in members:
                rel = safe_rel_path(m.name)
                if not (m.isdir() or m.isfile()):
                    fail(f"差量镜像归档含不允许的文件类型: {m.name}")
                if m.isdir():
                    continue
                if not SAFE_REL_RE.match(rel):
                    fail(f"差量镜像归档路径含非法字符: {rel}")
                if m.size < 0 or expanded > MAX_EXPANDED_BYTES - m.size:
                    fail("差量镜像归档解压体积超限")
                expanded += m.size
                if rel in member_map:
                    fail(f"差量镜像归档含重复成员: {rel}")
                member_map[rel] = m

            if "delta-manifest.json" not in member_map:
                fail("差量镜像归档缺少 delta-manifest.json")
            dm = json.loads(
                dtf.extractfile(member_map["delta-manifest.json"]).read().decode("utf-8")
            )
            if dm.get("format") != DELTA_FORMAT:
                fail(f"不支持的差量镜像格式: {dm.get('format')!r}")
            if dm.get("target_image") != args.expected_image:
                fail(
                    f"差量镜像目标标签不匹配: inner={dm.get('target_image')!r} "
                    f"expected={args.expected_image!r}"
                )
            cfg_file = dm.get("config_file", "")
            cfg_sha = dm.get("config_sha256", "")
            if not isinstance(cfg_file, str) or not re.fullmatch(r"[0-9a-f]{64}\.json", cfg_file):
                fail(f"差量镜像 config_file 非法: {cfg_file!r}")
            if not isinstance(cfg_sha, str) or not HEX64_RE.fullmatch(cfg_sha) or cfg_file != f"{cfg_sha}.json":
                fail("差量镜像 config_sha256 与文件名不一致")
            if cfg_file not in member_map:
                fail(f"差量镜像缺少配置文件: {cfg_file}")
            cfg_bytes = dtf.extractfile(member_map[cfg_file]).read()
            if hashlib.sha256(cfg_bytes).hexdigest() != cfg_sha:
                fail("差量镜像 config JSON 摘要校验失败")
            config = json.loads(cfg_bytes.decode("utf-8"))
            cfg_diff_ids = (config.get("rootfs") or {}).get("diff_ids")

            layers = dm.get("layers")
            if not isinstance(layers, list) or not layers:
                fail("差量镜像 layers 清单为空")
            if cfg_diff_ids != [item.get("diff_id") for item in layers]:
                fail("差量镜像 layers 与 config.rootfs.diff_ids 不一致")

            inner_base_set = set()
            delta_extracted = {}
            budget = MAX_EXPANDED_BYTES
            for expected_idx, item in enumerate(layers):
                if not isinstance(item, dict) or item.get("index") != expected_idx:
                    fail(f"差量镜像层序号不连续: index={item!r}")
                did = item.get("diff_id")
                if not is_valid_diff_id(did):
                    fail(f"差量镜像 diff_id 非法: {did!r}")
                src_kind = item.get("source")
                if src_kind == "base":
                    inner_base_set.add(did)
                elif src_kind == "delta":
                    rel_layer = safe_rel_path(item.get("path", ""))
                    if rel_layer not in member_map:
                        fail(f"差量镜像缺少新增层文件: {rel_layer}")
                    m = member_map[rel_layer]
                    if item.get("size") != m.size:
                        fail(f"差量镜像新增层大小不匹配: {rel_layer}")
                    out_layer = delta_dir / f"delta-{expected_idx:03d}.tar"
                    with open(out_layer, "wb") as dst:
                        written, actual_did = stream_copy_bounded(dtf.extractfile(m), dst, budget)
                    budget -= written
                    if actual_did != did:
                        fail(f"差量镜像新增层摘要校验失败: {rel_layer} actual={actual_did} expected={did}")
                    delta_extracted[expected_idx] = out_layer
                else:
                    fail(f"未知的层来源类型: {src_kind!r}")

            if inner_base_set != expected_base_set:
                fail("内层 delta-manifest.json 所需基础层与外层签名 manifest.json 不一致")

        # 2. 从宿主机旧镜像 docker save 归档提取并逐层校验所需基础层
        base_extracted = {}
        with tarfile.open(args.base_tar, mode="r:*") as btf:
            b_manifest, _, _, b_diff_ids, _ = read_docker_archive_meta(btf)
            did_to_member = {}
            for member_name, did in zip(b_manifest["Layers"], b_diff_ids):
                if did not in did_to_member:
                    did_to_member[did] = member_name
            for did in sorted(inner_base_set):
                if did not in did_to_member:
                    fail(f"宿主机基准镜像归档缺少必需基础层: {did}")
                hex_did = did.split(":", 1)[1]
                out_layer = base_dir / f"base-{hex_did}.tar"
                size, actual_did = extract_uncompressed_layer(
                    btf, did_to_member[did], out_layer, budget, sanitize=False
                )
                budget -= size
                if actual_did != did:
                    fail(f"宿主机基准镜像层摘要校验失败: actual={actual_did} expected={did}")
                base_extracted[did] = out_layer

        # 3. 拼装标准 Docker Archive（供 docker load -i 加载）
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_out = out_path.with_name(out_path.name + ".tmp")
        tar_layers = []
        with tarfile.open(tmp_out, "w", format=tarfile.PAX_FORMAT) as out_tf:
            add_bytes_member(out_tf, cfg_file, cfg_bytes)
            for item in layers:
                idx = item["index"]
                did = item["diff_id"]
                hex_did = did.split(":", 1)[1]
                src_path = base_extracted[did] if item["source"] == "base" else delta_extracted[idx]
                rel_layer = f"{idx}-{hex_did}/layer.tar"
                ti = out_tf.gettarinfo(str(src_path), arcname=rel_layer)
                ti.uid = 0
                ti.gid = 0
                ti.uname = ""
                ti.gname = ""
                ti.mode = 0o644
                ti.mtime = 0
                with open(src_path, "rb") as fh:
                    out_tf.addfile(ti, fh)
                tar_layers.append(rel_layer)
            add_bytes_member(
                out_tf,
                "manifest.json",
                json.dumps(
                    [
                        {
                            "Config": cfg_file,
                            "RepoTags": [args.expected_image],
                            "Layers": tar_layers,
                        }
                    ],
                    separators=(",", ":"),
                ).encode("utf-8"),
            )
        os.replace(tmp_out, out_path)
    print("OK")


def main():
    parser = argparse.ArgumentParser(description="WDSP Docker 镜像层差量工具")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_ib = sub.add_parser("inspect-base", help="从基准离线包/升级包/镜像 tar 读取各组件 diff_ids")
    p_ib.add_argument("--archive", action="append", required=True)
    p_ib.add_argument("--component", default=None)
    p_ib.set_defaults(func=cmd_inspect_base)

    p_id = sub.add_parser("inspect-docker", help="从本机 Docker 基准镜像读取各组件 diff_ids")
    p_id.add_argument("--from-version", required=True)
    p_id.add_argument("--components", required=True)
    p_id.set_defaults(func=cmd_inspect_docker)

    p_cr = sub.add_parser("create", help="对比基准 diff_ids 生成 layer-delta 或完整镜像归档")
    p_cr.add_argument("--target-tar", required=True)
    p_cr.add_argument("--target-image", required=True)
    p_cr.add_argument("--base-diff-ids-json", required=True)
    p_cr.add_argument("--output", required=True)
    p_cr.add_argument("--sanitize-runtime", action="store_true")
    p_cr.add_argument("--min-savings-bytes", type=int, default=1048576)
    p_cr.set_defaults(func=cmd_create)

    p_cb = sub.add_parser("check-base", help="校验宿主机当前镜像是否包含所需基础层")
    p_cb.add_argument("--required-base-layers-json", required=True)
    p_cb.add_argument("--actual-layers-json", required=True)
    p_cb.set_defaults(func=cmd_check_base)

    p_ap = sub.add_parser("apply", help="结合宿主机旧镜像与差量包重建可 docker load 的完整镜像 tar")
    p_ap.add_argument("--delta-tar", required=True)
    p_ap.add_argument("--base-tar", required=True)
    p_ap.add_argument("--expected-base-layers-json", required=True)
    p_ap.add_argument("--expected-image", required=True)
    p_ap.add_argument("--output", required=True)
    p_ap.set_defaults(func=cmd_apply)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
