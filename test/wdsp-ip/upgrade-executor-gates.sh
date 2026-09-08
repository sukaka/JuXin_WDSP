#!/usr/bin/env bash
# 验证升级执行器在任何容器操作前拒绝危险归档和错误架构包。
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EXECUTOR="$REPO_ROOT/ops/upgrade/upgrade-executor.sh"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/wdsp-upgrade-gates.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT

EXTRACTOR="$WORK_DIR/safe-extract.py"
awk '
  /^  python3 - / && /<<.PY./ { capture = 1; next }
  capture && /^PY$/ { exit }
  capture { print }
' "$EXECUTOR" >"$EXTRACTOR"
[[ -s "$EXTRACTOR" ]] || { printf '%s\n' '未能从升级执行器提取安全解压逻辑' >&2; exit 1; }

python3 - "$WORK_DIR" "$EXTRACTOR" <<'PY'
import io
import pathlib
import subprocess
import sys
import tarfile

root = pathlib.Path(sys.argv[1])
extractor = pathlib.Path(sys.argv[2])


def make_archive(name, entries):
    archive = root / f"{name}.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        for entry in entries:
            info = tarfile.TarInfo(entry["name"])
            kind = entry.get("kind", "file")
            if kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = entry["target"]
                info.size = 0
                tf.addfile(info)
            else:
                data = entry.get("data", b"")
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
    return archive


def extract_ok(name, entries):
    archive = make_archive(name, entries)
    destination = root / f"{name}-out"
    destination.mkdir()
    result = subprocess.run(
        [sys.executable, str(extractor), str(archive), str(destination)],
        text=True,
        capture_output=True,
    )
    if result.returncode:
        raise SystemExit(f"{name} 应可解压: {result.stderr}")
    if (destination / "release/manifest.json").read_bytes() != b"{}":
        raise SystemExit(f"{name} 解压内容不正确")


def extract_rejected(name, entries):
    archive = make_archive(name, entries)
    destination = root / f"{name}-out"
    destination.mkdir()
    result = subprocess.run(
        [sys.executable, str(extractor), str(archive), str(destination)],
        text=True,
        capture_output=True,
    )
    if result.returncode == 0:
        raise SystemExit(f"{name} 应被拒绝")
    if any(destination.iterdir()):
        raise SystemExit(f"{name} 在拒绝前写入了目标目录")


extract_ok("valid", [{"name": "release/manifest.json", "data": b"{}"}])
extract_rejected("traversal", [{"name": "release/../../outside", "data": b"x"}])
extract_rejected("symlink", [{"name": "release/link", "kind": "symlink", "target": "../../outside"}])
extract_rejected(
    "member-limit",
    [{"name": f"release/file-{index}", "data": b"x"} for index in range(21)],
)
PY

grep -Fq 'MAX_EXPANDED_BYTES = 8 << 30' "$EXECUTOR" || {
  printf '%s\n' '升级执行器缺少展开大小上限' >&2
  exit 1
}
architecture_line="$(rg -n 'architecture.*host_arch' "$EXECUTOR" | cut -d: -f1)"
docker_load_line="$(rg -n 'docker load -i' "$EXECUTOR" | cut -d: -f1)"
[[ "$architecture_line" =~ ^[0-9]+$ && "$docker_load_line" =~ ^[0-9]+$ ]] || {
  printf '%s\n' '未找到架构或镜像加载门禁' >&2
  exit 1
}
(( architecture_line < docker_load_line )) || {
  printf '%s\n' '架构校验必须在镜像加载前完成' >&2
  exit 1
}

printf '%s\n' '升级执行器归档与架构前置门禁通过'
