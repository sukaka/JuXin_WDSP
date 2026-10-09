#!/usr/bin/env python3
"""Derive a runtime-only Docker archive without retaining excluded old layers."""
import argparse
import hashlib
import io
import json
from pathlib import PurePosixPath, Path
import tarfile
import tempfile


def excluded(name, is_directory=False):
    parts = PurePosixPath(name).parts
    if name.startswith("/") or ".." in parts:
        raise ValueError("unsafe image member")
    lower = tuple(p.lower() for p in parts)
    leaf = lower[-1] if lower else ""
    directories = lower if is_directory else lower[:-1]
    # Attribution files are legal delivery requirements, not product manuals.
    if leaf.startswith(("license", "licence", "copying", "copyright", "notice")):
        return False
    return bool(
        set(directories) & {"test", "tests", "testdata", "__tests__", "__pycache__", ".git"}
        or set(directories) & {"doc", "docs", "man", "info"}
        or leaf.startswith(("readme", "changelog"))
        or leaf.endswith((".md", ".rst", "_test.go", ".test.ts", ".spec.ts", ".map"))
        or "usr/local/lib/postgresql/pgxs" in "/".join(parts)
    )


def add_bytes(archive, name, data):
    member = tarfile.TarInfo(name)
    member.size = len(data)
    member.mode = 0o644
    archive.addfile(member, io.BytesIO(data))


def sanitize(source, destination, repository, source_ref):
    removed = []
    with tarfile.open(source) as original, tempfile.TemporaryDirectory(prefix="wdsp-image-layers-") as tmp:
        manifests = json.load(original.extractfile("manifest.json"))
        if len(manifests) != 1:
            raise ValueError("exactly one image/platform required")
        manifest = manifests[0]
        config = json.load(original.extractfile(manifest["Config"]))
        layers, diff_ids = [], []
        with tarfile.open(destination, "w") as result:
            for index, layer_name in enumerate(manifest["Layers"]):
                layer_path = Path(tmp) / "layer.tar"
                with tarfile.open(fileobj=original.extractfile(layer_name), mode="r|*") as src, tarfile.open(layer_path, "w") as dst:
                    for member in src:
                        if excluded(member.name, member.isdir()):
                            removed.append(member.name)
                            continue
                        dst.addfile(member, src.extractfile(member) if member.isfile() else None)
                digest = hashlib.sha256()
                with layer_path.open("rb") as data:
                    for chunk in iter(lambda: data.read(1024 * 1024), b""):
                        digest.update(chunk)
                layer_digest = digest.hexdigest()
                path = f"{index}-{layer_digest}/layer.tar"
                result.add(layer_path, arcname=path, recursive=False)
                layers.append(path)
                diff_ids.append("sha256:" + layer_digest)
            config["rootfs"]["diff_ids"] = diff_ids
            labels = config.setdefault("config", {}).get("Labels") or {}
            labels.update({"com.jiuzhang.runtime.source": source_ref,
                           "com.jiuzhang.runtime.policy": "no-docs-tests-v1"})
            config["config"]["Labels"] = labels
            encoded = json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
            config_digest = hashlib.sha256(encoded).hexdigest()
            tag = f"{repository}:{config_digest[:24]}"
            config_name = config_digest + ".json"
            add_bytes(result, config_name, encoded)
            add_bytes(result, "manifest.json", json.dumps([{
                "Config": config_name, "RepoTags": [tag], "Layers": layers,
            }]).encode())
    return {"image": tag, "digest": "sha256:" + config_digest,
            "source_image": source_ref, "removed_entries": len(removed)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("source")
    parser.add_argument("destination")
    parser.add_argument("--repository", required=True)
    parser.add_argument("--source-ref", required=True)
    args = parser.parse_args()
    print(json.dumps(sanitize(args.source, args.destination, args.repository, args.source_ref)))
