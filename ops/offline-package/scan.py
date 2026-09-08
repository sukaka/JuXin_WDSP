#!/usr/bin/env python3
"""Fail-closed build-time scanner for WDSP offline packages.

The scanner deliberately never extracts an archive. It walks directory trees and
archive members in memory, so traversal and symlink samples cannot write to the
host. It is a build-time tool and is not copied into customer packages.
"""

from __future__ import annotations

import argparse
import bz2
import gzip
import hashlib
import io
import json
import lzma
import os
import pathlib
import posixpath
import re
import sys
import tarfile
import time
import zipfile
from datetime import datetime, timezone


SCANNER_VERSION = "wdsp-offline-scan/1.2"
POLICY_VERSION = "WDSP_IP-01/IP-02.v1"
DEFAULT_MEMBER_BYTES = 256 * 1024 * 1024
DEFAULT_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
DEFAULT_DEPTH = 8
DEFAULT_ARCHIVES = 4096
DEFAULT_ARCHIVE_MEMBERS = 100000
CHUNK_SIZE = 64 * 1024

SOURCE_EXTENSIONS = {
    ".go",
    ".ts",
    ".tsx",
    ".map",
    ".sourcemap",
    ".pdb",
    ".dwo",
    ".debug",
    ".sym",
}
DEV_SEGMENTS = {
    ".git",
    ".svn",
    ".hg",
    ".idea",
    ".vscode",
    "test",
    "tests",
    "__tests__",
    "fixtures",
    "fixture",
    "testdata",
    "debug",
    "coverage",
}
PLACEHOLDERS = {
    "changeme",
    "change-me",
    "example",
    "example-secret",
    "placeholder",
    "redacted",
    "replace-me",
    "your-secret",
    "your-token",
    "********",
    # Literal parameter-name and truncated JWT examples in shipped WAF rules.
    "/jwt=/access_token=",
    "eyjhbgcioijub25l...",
}
CREDENTIAL_RE = re.compile(
    rb"(?i)\b(password|passwd|secret|token|api[_-]?key|access[_-]?key)\b"
    rb"[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_./+=:@$-]{8,})"
)
AWS_KEY_RE = re.compile(rb"\bAKIA[0-9A-Z]{16}\b")
PRIVATE_KEY_RE = re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
SOURCE_MAP_RE = re.compile(rb"(?:sourceMappingURL|sourcesContent)")


class ScanContext:
    def __init__(self, root: pathlib.Path, args: argparse.Namespace):
        self.root = root
        self.args = args
        self.started = time.monotonic()
        self.findings: list[dict[str, str]] = []
        self._finding_keys: set[tuple[str, str]] = set()
        self.coverage = {
            "complete": True,
            "files": 0,
            "archives": 0,
            "archive_members": 0,
            "bytes_scanned": 0,
        }
        self.manifest_sha256: str | None = None
        self.manifest_files_sha256: str | None = None
        self.stopped = False

    def stop(self, rule: str, location: str) -> None:
        self.add(rule, location)
        self.coverage["complete"] = False
        self.stopped = True

    def add(self, rule: str, location: str) -> None:
        key = (rule, location)
        if key not in self._finding_keys:
            self._finding_keys.add(key)
            self.findings.append({"rule": rule, "severity": "error", "location": location})

    def check_limits(self) -> bool:
        if self.stopped:
            return False
        if time.monotonic() - self.started > self.args.timeout_seconds:
            self.stop("timeout", "scanner")
            return False
        return True

    def account_member(self) -> bool:
        if not self.check_limits():
            return False
        self.coverage["archive_members"] += 1
        if self.coverage["archive_members"] > self.args.max_archive_members:
            self.stop("archive-budget", "member-count")
            return False
        return True


def safe_member_name(name: str) -> bool:
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:/", normalized):
        return False
    parts = [part for part in normalized.split("/") if part not in ("", ".")]
    depth = 0
    for part in parts:
        if part == "..":
            depth -= 1
            if depth < 0:
                return False
        else:
            depth += 1
    return True


def symlink_escapes(name: str, target: str) -> bool:
    if not safe_member_name(name) or not safe_member_name(target):
        return True
    parent = posixpath.dirname(name.replace("\\", "/"))
    return not safe_member_name(posixpath.normpath(posixpath.join(parent, target)))


def relative_location(path: pathlib.Path, root: pathlib.Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


def has_source_name(name: str) -> bool:
    path = pathlib.PurePosixPath(name.replace("\\", "/"))
    lower_parts = {part.lower() for part in path.parts}
    suffix = pathlib.PurePosixPath(path.name.lower()).suffix
    return suffix in SOURCE_EXTENSIONS or path.name.lower().endswith(".dsym") or bool(lower_parts & DEV_SEGMENTS)


def placeholder(value: bytes) -> bool:
    clean = value.strip().strip(b"\"'").lower()
    if clean.startswith((b"${", b"<", b"{{")):
        return True
    return clean in {item.encode() for item in PLACEHOLDERS}


def is_package_manifest(ctx: ScanContext, location: str) -> bool:
    # Bind only the delivery's manifest, not manifests inside images or runtime
    # assets. The final tar has one optional enclosing package directory.
    if ctx.root.is_dir():
        return location == "manifest.json"
    prefix = ctx.root.name + "!"
    if not location.startswith(prefix):
        return False
    relative = location[len(prefix):]
    if "!" in relative:
        return False
    parts = pathlib.PurePosixPath(relative).parts
    return len(parts) in (1, 2) and parts[-1] == "manifest.json"


def scan_content(ctx: ScanContext, data: bytes, location: str) -> None:
    lower_name = location.lower()
    if lower_name.endswith((".map", ".sourcemap")):
        ctx.add("source-map", location)
    if has_source_name(location):
        ctx.add("source-artifact", location)
    if SOURCE_MAP_RE.search(data):
        ctx.add("inline-source-map", location)
    if AWS_KEY_RE.search(data) or PRIVATE_KEY_RE.search(data):
        ctx.add("credential", location)
    if is_package_manifest(ctx, location):
        manifest_sha256 = hashlib.sha256(data).hexdigest()
        try:
            manifest = json.loads(data.decode("utf-8"))
            files_sha256 = manifest.get("files_manifest_sha256") if isinstance(manifest, dict) else None
            if not isinstance(files_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", files_sha256):
                ctx.add("manifest-binding", location)
            elif ctx.manifest_files_sha256 not in (None, files_sha256):
                ctx.add("manifest-binding", location)
            ctx.manifest_files_sha256 = files_sha256 if isinstance(files_sha256, str) else None
        except (UnicodeDecodeError, json.JSONDecodeError):
            ctx.add("manifest-parse", location)
        if ctx.manifest_sha256 not in (None, manifest_sha256):
            ctx.add("manifest-binding", location)
        ctx.manifest_sha256 = manifest_sha256
    for match in CREDENTIAL_RE.finditer(data):
        value = match.group(2)
        # Shell variables and rule-pattern fragments are references, not
        # embedded credentials. Real values still fail closed.
        if not placeholder(value) and not value.startswith(b"$"):
            ctx.add("credential", location)
            break


def read_stream(ctx: ScanContext, stream, location: str) -> bytes | None:
    chunks: list[bytes] = []
    total = 0
    while True:
        if not ctx.check_limits():
            return None
        remaining = ctx.args.max_total_bytes - ctx.coverage["bytes_scanned"]
        chunk = stream.read(max(1, min(CHUNK_SIZE, ctx.args.max_member_bytes - total + 1, remaining + 1)))
        if not chunk:
            break
        total += len(chunk)
        ctx.coverage["bytes_scanned"] += len(chunk)
        if total > ctx.args.max_member_bytes:
            ctx.stop("archive-budget", location)
            return None
        if ctx.coverage["bytes_scanned"] > ctx.args.max_total_bytes:
            ctx.stop("archive-budget", "scan-total")
            return None
        chunks.append(chunk)
    data = b"".join(chunks)
    scan_content(ctx, data, location)
    return data


def archive_kind(name: str, prefix: bytes) -> str | None:
    lower = name.lower()
    # macOS tar may emit AppleDouble metadata beside files with archive-like
    # names. It is scanned as opaque metadata, never interpreted as an archive.
    if (pathlib.PurePosixPath(name.replace("\\", "/")).name.startswith("._")
            and prefix.startswith(b"\x00\x05\x16\x07")):
        return None
    if prefix.startswith(b"\x28\xb5\x2f\xfd") or lower.endswith((".zst", ".tar.zst")):
        return "unsupported"
    if lower.endswith((".zip", ".jar", ".whl")) or prefix.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip"
    if lower.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")):
        return "tar"
    for kind, magic, suffix in (("gzip", b"\x1f\x8b", ".gz"),
                                ("bzip2", b"BZh", ".bz2"),
                                ("xz", b"\xfd7zXZ\x00", ".xz")):
        if prefix.startswith(magic) or lower.endswith(suffix):
            return kind
    if len(prefix) >= tarfile.BLOCKSIZE:
        try:
            tarfile.TarInfo.frombuf(prefix[:tarfile.BLOCKSIZE], "utf-8", "surrogateescape")
            return "tar"
        except tarfile.HeaderError:
            pass
    return None


def scan_archive_bytes(ctx: ScanContext, data: bytes, location: str, depth: int) -> None:
    with io.BytesIO(data) as stream:
        scan_archive_stream(ctx, stream, location, depth)


def scan_archive_path(ctx: ScanContext, path: pathlib.Path, location: str, depth: int) -> None:
    """Scan a top-level archive without loading the compressed container."""
    try:
        with path.open("rb") as stream:
            scan_archive_stream(ctx, stream, location, depth)
    except OSError:
        ctx.stop("unreadable", location)


def scan_archive_stream(ctx: ScanContext, stream, location: str, depth: int) -> None:
    if not ctx.check_limits():
        return
    try:
        prefix = stream.read(tarfile.BLOCKSIZE)
        stream.seek(0)
        kind = archive_kind(location, prefix)
        if kind is None:
            return
        if kind == "unsupported":
            ctx.stop("unsupported-archive", location)
            return
        if depth > ctx.args.max_depth:
            ctx.stop("archive-depth", location)
            return
        ctx.coverage["archives"] += 1
        if ctx.coverage["archives"] > ctx.args.max_archives:
            ctx.stop("archive-budget", "archive-count")
            return
        if kind in {"gzip", "bzip2", "xz"}:
            if not ctx.account_member():
                return
            opener, suffix = {"gzip": (gzip.GzipFile, ".gz"),
                              "bzip2": (bz2.BZ2File, ".bz2"),
                              "xz": (lzma.LZMAFile, ".xz")}[kind]
            name = location.rsplit("!", 1)[-1].rsplit("/", 1)[-1]
            name = name[:-len(suffix)] if name.lower().endswith(suffix) else "payload"
            member_location = f"{location}!{name}"
            compressed = opener(fileobj=stream, mode="rb") if kind == "gzip" else opener(stream, mode="rb")
            with compressed:
                payload = read_stream(ctx, compressed, member_location)
            if payload is not None:
                scan_archive_bytes(ctx, payload, member_location, depth + 1)
            return
        archive_context = (zipfile.ZipFile(stream) if kind == "zip"
                           else tarfile.open(fileobj=stream, mode="r|*"))
        with archive_context as archive:
            members = archive.infolist() if kind == "zip" else archive
            for member in members:
                if not ctx.account_member():
                    return
                member_name = member.filename if kind == "zip" else member.name
                member_location = f"{location}!{member_name}"
                if not safe_member_name(member_name):
                    ctx.add("path-traversal", member_location)
                if kind == "zip":
                    # Encryption and CRC checks apply to links as well as files.
                    if member.flag_bits & 0x1:
                        ctx.stop("unsupported-archive", member_location)
                        return
                    if member.is_dir():
                        continue
                    with archive.open(member, "r") as member_stream:
                        payload = read_stream(ctx, member_stream, member_location)
                    if (member.external_attr >> 16) & 0o170000 == 0o120000:
                        if payload is not None and symlink_escapes(member_name, payload.decode("utf-8", "replace")):
                            ctx.add("symlink-escape", member_location)
                        continue
                else:
                    if member.issym() or member.islnk():
                        if symlink_escapes(member_name, member.linkname):
                            ctx.add("symlink-escape", member_location)
                        continue
                    if not member.isfile():
                        continue
                    member_stream = archive.extractfile(member)
                    if member_stream is None:
                        ctx.stop("archive-parse", member_location)
                        return
                    with member_stream:
                        payload = read_stream(ctx, member_stream, member_location)
                if payload is not None:
                    scan_archive_bytes(ctx, payload, member_location, depth + 1)
                if not ctx.check_limits():
                    return
    except (tarfile.TarError, zipfile.BadZipFile, EOFError, OSError, ValueError, lzma.LZMAError):
        ctx.stop("archive-parse", location)


def validate_allowlist(root: pathlib.Path, allowlist: pathlib.Path, ctx: ScanContext) -> None:
    try:
        lines = allowlist.read_text(encoding="utf-8").splitlines()
    except OSError:
        ctx.add("allowlist-unreadable", allowlist.name)
        ctx.coverage["complete"] = False
        return
    version = None
    expected: list[str] = []
    for line_number, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("version="):
            if version is not None:
                ctx.add("allowlist-invalid", f"allowlist:{line_number}")
            version = line.split("=", 1)[1]
            continue
        if not line.startswith("file="):
            ctx.add("allowlist-invalid", f"allowlist:{line_number}")
            continue
        relative = line.split("=", 1)[1]
        if not relative or not safe_member_name(relative) or "*" in relative:
            ctx.add("allowlist-invalid", f"allowlist:{line_number}")
        expected.append(relative)
    if version != "1" or len(expected) != len(set(expected)):
        ctx.add("allowlist-invalid", allowlist.name)
    ops = root / "ops"
    if not ops.is_dir():
        ctx.add("allowlist-missing-root", "ops")
        return
    expected_set = set(expected)
    for relative in expected:
        target = ops / relative
        if not target.is_file() or target.is_symlink():
            ctx.add("allowlist-missing", f"ops/{relative}")
    for directory, dirs, files in os.walk(ops, followlinks=False):
        directory_path = pathlib.Path(directory)
        for dirname in dirs:
            candidate = directory_path / dirname
            if candidate.is_symlink():
                ctx.add("symlink-escape", relative_location(candidate, root))
        for filename in files:
            candidate = directory_path / filename
            relative = candidate.relative_to(ops).as_posix()
            if candidate.is_symlink():
                ctx.add("symlink-escape", f"ops/{relative}")
            elif relative not in expected_set:
                ctx.add("allowlist-extra", f"ops/{relative}")


def scan_directory(ctx: ScanContext) -> None:
    root = ctx.root.resolve()
    for directory, dirs, files in os.walk(root, followlinks=False):
        if not ctx.check_limits():
            return
        directory_path = pathlib.Path(directory)
        for dirname in list(dirs):
            candidate = directory_path / dirname
            if candidate.is_symlink():
                target = pathlib.Path(os.path.realpath(candidate))
                if root not in target.parents and target != root:
                    ctx.add("symlink-escape", relative_location(candidate, root))
                dirs.remove(dirname)
        for filename in files:
            if not ctx.check_limits():
                return
            candidate = directory_path / filename
            location = relative_location(candidate, root)
            if candidate.is_symlink():
                target = pathlib.Path(os.path.realpath(candidate))
                if root not in target.parents and target != root:
                    ctx.add("symlink-escape", location)
                continue
            ctx.coverage["files"] += 1
            try:
                with candidate.open("rb") as stream:
                    prefix = stream.read(tarfile.BLOCKSIZE)
                if archive_kind(location, prefix) is not None:
                    scan_archive_path(ctx, candidate, location, 0)
                else:
                    with candidate.open("rb") as stream:
                        payload = read_stream(ctx, stream, location)
                    if payload is not None:
                        scan_archive_bytes(ctx, payload, location, 0)
            except OSError:
                ctx.add("unreadable", location)
                ctx.coverage["complete"] = False


def digest_input(root: pathlib.Path) -> str:
    digest = hashlib.sha256()
    if root.is_file():
        with root.open("rb") as stream:
            for chunk in iter(lambda: stream.read(CHUNK_SIZE), b""):
                digest.update(chunk)
        return digest.hexdigest()
    for path in sorted(item for item in root.rglob("*") if item.is_file() and not item.is_symlink()):
        relative = path.relative_to(root).as_posix().encode()
        digest.update(relative + b"\0")
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(CHUNK_SIZE), b""):
                digest.update(chunk)
    return digest.hexdigest()


def build_report(ctx: ScanContext, args: argparse.Namespace, input_sha: str) -> dict:
    rejected = bool(ctx.findings) or not ctx.coverage["complete"]
    return {
        "scanner_version": SCANNER_VERSION,
        "policy_version": POLICY_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input": {"path": pathlib.Path(args.root).name, "sha256": input_sha},
        "scope": {
            "product": args.product,
            "version": args.version,
            "platform": args.platform,
            "allowlist": pathlib.Path(args.allowlist).name if args.allowlist else None,
            "allowlist_sha256": getattr(ctx, "allowlist_sha256", None),
        },
        "limits": {
            "timeout_seconds": args.timeout_seconds,
            "max_member_bytes": args.max_member_bytes,
            "max_total_bytes": args.max_total_bytes,
            "max_depth": args.max_depth,
            "max_archives": args.max_archives,
            "max_archive_members": args.max_archive_members,
        },
        "coverage": ctx.coverage,
        "findings": ctx.findings,
        "manifest": {
            "sha256": ctx.manifest_sha256,
            "files_manifest_sha256": ctx.manifest_files_sha256,
        },
        "result": "REJECT" if rejected else "PASS",
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument("--allowlist")
    parser.add_argument("--output", required=True)
    parser.add_argument("--product", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=60.0)
    parser.add_argument("--max-member-bytes", type=int, default=DEFAULT_MEMBER_BYTES)
    parser.add_argument("--max-total-bytes", type=int, default=DEFAULT_TOTAL_BYTES)
    parser.add_argument("--max-depth", type=int, default=DEFAULT_DEPTH)
    parser.add_argument("--max-archives", type=int, default=DEFAULT_ARCHIVES)
    parser.add_argument("--max-archive-members", type=int, default=DEFAULT_ARCHIVE_MEMBERS)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = pathlib.Path(args.root)
    ctx = ScanContext(root, args)
    try:
        if args.allowlist:
            allowlist_path = pathlib.Path(args.allowlist)
            try:
                ctx.allowlist_sha256 = hashlib.sha256(allowlist_path.read_bytes()).hexdigest()
            except OSError:
                ctx.add("allowlist-unreadable", allowlist_path.name)
                ctx.coverage["complete"] = False
        if not root.exists() or root.is_symlink():
            ctx.add("input-unreadable", root.name)
            ctx.coverage["complete"] = False
        elif args.allowlist:
            if root.is_dir():
                validate_allowlist(root, pathlib.Path(args.allowlist), ctx)
        if root.is_dir():
            scan_directory(ctx)
        elif root.is_file():
            try:
                with root.open("rb") as stream:
                    prefix = stream.read(tarfile.BLOCKSIZE)
                if archive_kind(root.name, prefix) is not None:
                    scan_archive_path(ctx, root, root.name, 0)
                else:
                    with root.open("rb") as stream:
                        data = read_stream(ctx, stream, root.name)
                    if data is not None:
                        scan_archive_bytes(ctx, data, root.name, 0)
            except OSError:
                ctx.add("input-unreadable", root.name)
                ctx.coverage["complete"] = False
        # An incomplete scan is already rejected. Do not traverse the same
        # rejected input again outside the resource budget just to hash it.
        input_sha = digest_input(root) if root.exists() and ctx.coverage["complete"] else ""
    except Exception:
        ctx.add("scanner-error", "scanner")
        ctx.coverage["complete"] = False
        input_sha = ""
    report = build_report(ctx, args, input_sha)
    try:
        output = pathlib.Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except OSError:
        print("offline package scan failed: report could not be written", file=sys.stderr)
        return 2
    if report["result"] != "PASS":
        print(f"offline package scan rejected: {len(ctx.findings)} finding(s)", file=sys.stderr)
        for finding in ctx.findings:
            print(f"  {finding['rule']}: {finding['location']}", file=sys.stderr)
        return 1
    print("offline package scan passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
