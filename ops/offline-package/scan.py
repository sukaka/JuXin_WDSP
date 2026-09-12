#!/usr/bin/env python3
"""Fail-closed build-time scanner for WDSP offline packages.

The scanner deliberately never extracts an archive. It walks directory trees and
archive members in memory, so traversal and symlink samples cannot write to the
host. It is a build-time tool and is not copied into customer packages.
"""

from __future__ import annotations

import argparse
import bz2
import errno
import gzip
import hashlib
import io
import json
import lzma
import os
import pathlib
import posixpath
import re
import stat
import sys
import tempfile
import tarfile
import time
import zipfile
from datetime import datetime, timezone
from contextlib import contextmanager


SCANNER_VERSION = "wdsp-offline-scan/1.9"
POLICY_VERSION = "WDSP_IP-01/IP-02.v1"
DEFAULT_MEMBER_BYTES = 256 * 1024 * 1024
DEFAULT_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
DEFAULT_DEPTH = 8
DEFAULT_ARCHIVES = 4096
DEFAULT_ARCHIVE_MEMBERS = 100000
DEFAULT_ARCHIVE_METADATA_BYTES = 32 * 1024 * 1024
CHUNK_SIZE = 64 * 1024
DEFAULT_SPOOL_MEMORY_BYTES = 1 * 1024 * 1024
CONTENT_SCAN_OVERLAP = 512

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
PRIVATE_KEY_RE = re.compile(
    rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----\s*"
    rb"(?:[A-Za-z0-9+/=]{16,}\s*){2,}"
    rb"-----END [A-Z0-9 ]*PRIVATE KEY-----"
)
SOURCE_MAP_RE = re.compile(rb"(?:sourceMappingURL|sourcesContent)")
# Exact reviewed third-party text payloads whose documentation/example values
# match the generic assignment heuristic. Every exception binds the complete
# file hash and an expiry; a same-named or changed file is rejected until it
# receives a new security review.
REVIEWED_TEXT_PAYLOAD_EXCEPTIONS = {
    "etc/ssl/openssl.cnf": {
        "sha256": {
            "a65a2cb9f4ee8ffdc7ef4f0ac600c0bdafb95b7b1ab457188ac610a62f5ad6b3",
            "3a0c65ff954aff207420846926d31d1b6056be525a0f3d38dff21f5b89f90688",
        },
        "id": "IP-02-EX-001",
        "owner": "WDSP Security Engineering",
        "supplier": "reviewed pinned Alpine-based runtime layers",
        "reason": "OpenSSL sample comments, not deployable credentials",
        "expires_at": "2027-09-08",
    },
    "etc/ssl/openssl.cnf.dist": {
        "sha256": {
            "a65a2cb9f4ee8ffdc7ef4f0ac600c0bdafb95b7b1ab457188ac610a62f5ad6b3",
            "3a0c65ff954aff207420846926d31d1b6056be525a0f3d38dff21f5b89f90688",
        },
        "id": "IP-02-EX-001",
        "owner": "WDSP Security Engineering",
        "supplier": "reviewed pinned Alpine-based runtime layers",
        "reason": "OpenSSL sample comments, not deployable credentials",
        "expires_at": "2027-09-08",
    },
    "etc/clickhouse-server/users.xml": {
        "sha256": {"1059ce402d328bff83706f9ab91646fab9f7cb67f3a1bab8abc146011012c7bc"},
        "id": "IP-02-EX-002",
        "owner": "WDSP Security Engineering",
        "supplier": "clickhouse/clickhouse-server:25.8-alpine@sha256:87e0a5b72f5465b18eacca7c76850e7ff551c9795c50e451f5646299e5e24146",
        "reason": "ClickHouse vendor example password, not an enabled deployment credential",
        "expires_at": "2027-09-08",
    },
    "usr/share/caddy/assets/CertificatesPage-xt4RWRP9.js": {
        "sha256": {"2ce6a59a5ef5c8428ff116e05b2a8a2141dd80d3864249cf31c9ddbed9f30873"},
        "id": "IP-02-EX-003",
        "owner": "WDSP Security Engineering",
        "supplier": "caddy web asset in jiuzhang-web:1.0.0",
        "reason": "Caddy UI runtime property reference, not a hard-coded credential",
        "expires_at": "2027-09-08",
    },
}

# Source artifacts are normally forbidden, including files inherited from
# upstream image layers.  This separate, exact-match registry exists only for
# reviewed supplier test utilities retained in a pinned runtime image. Entries
# must bind the leaf path and complete content digest, name the supplier and
# expire; it is never a glob or a layer-wide exemption.
REVIEWED_SOURCE_ARTIFACT_EXCEPTIONS: dict[str, dict[str, object]] = {
    "usr/local/lib/postgresql/pgxs/src/test/isolation/isolationtester": {
        "sha256": {
            "d7c884404eab42eadb7786c1885263e599a8b43ed208bf84da093b2b3cc8f1e0",
            "2fe65cb1415ed587302289467017496146ff146193f62a0a3fc26d5636b0f058",
        },
        "id": "IP-02-EX-004",
        "owner": "WDSP Security Engineering",
        "supplier": "postgres:16.4-alpine@sha256:5660c2cbfea50c7a9127d17dc4e48543eedd3d7a41a595a2dfa572471e37e64c",
        "reason": "Reviewed PostgreSQL supplier test utility retained in a pinned runtime layer",
        "expires_at": "2027-09-08",
    },
    "usr/local/lib/postgresql/pgxs/src/test/isolation/pg_isolation_regress": {
        "sha256": {
            "a9f3ac65399e26ee52e2a0989c214545acf07408124f2eab9971aa73f92bb1ce",
            "e3f45711cebc0504dd990b78da9cafc2db9d52f147bf5ad6aa28279667d9dafb",
        },
        "id": "IP-02-EX-005",
        "owner": "WDSP Security Engineering",
        "supplier": "postgres:16.4-alpine@sha256:5660c2cbfea50c7a9127d17dc4e48543eedd3d7a41a595a2dfa572471e37e64c",
        "reason": "Reviewed PostgreSQL supplier test utility retained in a pinned runtime layer",
        "expires_at": "2027-09-08",
    },
    "usr/local/lib/postgresql/pgxs/src/test/perl/PostgreSQL/Test/BackgroundPsql.pm": {
        "sha256": {"f5a56e9b8e9635190417a4b90b7f1dfeac1913eec7ac1467ff83350ac249ca99"},
        "id": "IP-02-EX-006",
        "owner": "WDSP Security Engineering",
        "supplier": "postgres:16.4-alpine@sha256:5660c2cbfea50c7a9127d17dc4e48543eedd3d7a41a595a2dfa572471e37e64c",
        "reason": "Reviewed PostgreSQL supplier test utility retained in a pinned runtime layer",
        "expires_at": "2027-09-08",
    },
    "usr/local/lib/postgresql/pgxs/src/test/perl/PostgreSQL/Test/Cluster.pm": {
        "sha256": {"1686e691dcf4180b87874c3702a0a435070d1dc4cd5eb5efb5b551611f22c83c"},
        "id": "IP-02-EX-007",
        "owner": "WDSP Security Engineering",
        "supplier": "postgres:16.4-alpine@sha256:5660c2cbfea50c7a9127d17dc4e48543eedd3d7a41a595a2dfa572471e37e64c",
        "reason": "Reviewed PostgreSQL supplier test utility retained in a pinned runtime layer",
        "expires_at": "2027-09-08",
    },
    "usr/local/lib/postgresql/pgxs/src/test/perl/PostgreSQL/Test/RecursiveCopy.pm": {
        "sha256": {"8d5cca28ed6d99dfe9ea07f23b0638672af0a6117b348964862159f1c05611dc"},
        "id": "IP-02-EX-008",
        "owner": "WDSP Security Engineering",
        "supplier": "postgres:16.4-alpine@sha256:5660c2cbfea50c7a9127d17dc4e48543eedd3d7a41a595a2dfa572471e37e64c",
        "reason": "Reviewed PostgreSQL supplier test utility retained in a pinned runtime layer",
        "expires_at": "2027-09-08",
    },
    "usr/local/lib/postgresql/pgxs/src/test/perl/PostgreSQL/Test/SimpleTee.pm": {
        "sha256": {"2b7e1246d80a8b172bf1d717c130ee98a75756afd2f4972bdd58499de8f8e63d"},
        "id": "IP-02-EX-009",
        "owner": "WDSP Security Engineering",
        "supplier": "postgres:16.4-alpine@sha256:5660c2cbfea50c7a9127d17dc4e48543eedd3d7a41a595a2dfa572471e37e64c",
        "reason": "Reviewed PostgreSQL supplier test utility retained in a pinned runtime layer",
        "expires_at": "2027-09-08",
    },
    "usr/local/lib/postgresql/pgxs/src/test/perl/PostgreSQL/Test/Utils.pm": {
        "sha256": {"6c264927f919ce9cde339fd58290e3c5ffc102c49e09d1ac572ecc34ea658418"},
        "id": "IP-02-EX-010",
        "owner": "WDSP Security Engineering",
        "supplier": "postgres:16.4-alpine@sha256:5660c2cbfea50c7a9127d17dc4e48543eedd3d7a41a595a2dfa572471e37e64c",
        "reason": "Reviewed PostgreSQL supplier test utility retained in a pinned runtime layer",
        "expires_at": "2027-09-08",
    },
    "usr/local/lib/postgresql/pgxs/src/test/perl/PostgreSQL/Version.pm": {
        "sha256": {"125bd3a935e33b73536c3a88606765e32a91e626f66c275fb7b35e0412c7e3af"},
        "id": "IP-02-EX-011",
        "owner": "WDSP Security Engineering",
        "supplier": "postgres:16.4-alpine@sha256:5660c2cbfea50c7a9127d17dc4e48543eedd3d7a41a595a2dfa572471e37e64c",
        "reason": "Reviewed PostgreSQL supplier test utility retained in a pinned runtime layer",
        "expires_at": "2027-09-08",
    },
    "usr/local/lib/postgresql/pgxs/src/test/regress/pg_regress": {
        "sha256": {
            "8ae3ceef9e3c1427d3dae66cd851f9053d749750d4c9d0076e462246785f98be",
            "fb442f47aa1c79904ca4acbb850da09850a715f5b2b1877f7265ed3a03b9f192",
        },
        "id": "IP-02-EX-012",
        "owner": "WDSP Security Engineering",
        "supplier": "postgres:16.4-alpine@sha256:5660c2cbfea50c7a9127d17dc4e48543eedd3d7a41a595a2dfa572471e37e64c",
        "reason": "Reviewed PostgreSQL supplier test utility retained in a pinned runtime layer",
        "expires_at": "2027-09-08",
    },
}


class ScanContext:
    def __init__(self, root: pathlib.Path, args: argparse.Namespace):
        self.root = root
        self.args = args
        self.started = time.monotonic()
        self.findings: list[dict[str, str]] = []
        self._finding_keys: set[tuple[str, str]] = set()
        self.exceptions: list[dict[str, str]] = []
        self._exception_keys: set[tuple[str, str]] = set()
        self.coverage = {
            "complete": True,
            "files": 0,
            "archives": 0,
            "archive_members": 0,
            "archive_metadata_bytes": 0,
            "bytes_scanned": 0,
        }
        self.manifest_sha256: str | None = None
        self.manifest_files_sha256: str | None = None
        self.container_layer_archives: set[str] = set()
        # Docker save manifests and OCI image manifests reference config JSON by
        # path/digest. The payload can precede its manifest in a tar stream, so
        # record both sides and bind them only after the complete input is read.
        self.container_config_locations: set[str] = set()
        self.container_config_manifest_locations: dict[str, set[str]] = {}
        self.container_config_platforms: dict[str, tuple[str, str]] = {}
        self.oci_declared_platforms: list[tuple[str, str | None, str | None]] = []
        self.oci_descriptor_platforms: dict[str, tuple[str | None, str | None]] = {}
        # OCI descriptor targets can precede their index or image manifest in a
        # tar stream. Retain their content digest and verify all references only
        # after the entire archive has been traversed.
        self.container_blob_digests: dict[str, str] = {}
        self.container_blob_references: list[tuple[str, str]] = []
        self._deferred_links: list[tuple[str, str, str, str]] = []
        self.stopped = False

    def stop(self, rule: str, location: str) -> None:
        self.add(rule, location)
        self.coverage["complete"] = False
        self.stopped = True

    def add(self, rule: str, location: str, *, content_sha256: str | None = None) -> None:
        key = (rule, location)
        if key not in self._finding_keys:
            self._finding_keys.add(key)
            finding = {"rule": rule, "severity": "error", "location": location}
            # A content digest is a non-reversible diagnostic reference. It
            # lets security reviewers create an exact, time-bounded exception
            # without retaining a suspicious payload in a rejection report.
            if content_sha256 is not None:
                finding["content_sha256"] = content_sha256
            self.findings.append(finding)

    def allow_exception(self, exception: dict[str, object], location: str,
                        content_sha256: str) -> None:
        key = (str(exception["id"]), location)
        if key in self._exception_keys:
            return
        self._exception_keys.add(key)
        self.exceptions.append({
            "id": str(exception["id"]),
            "location": location,
            "sha256": content_sha256,
            "owner": str(exception["owner"]),
            "supplier": str(exception["supplier"]),
            "reason": str(exception["reason"]),
            "expires_at": str(exception["expires_at"]),
        })

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

    def account_archive_metadata(self, count: int, location: str) -> bool:
        if not self.check_limits():
            return False
        self.coverage["archive_metadata_bytes"] += count
        if self.coverage["archive_metadata_bytes"] > self.args.max_archive_metadata_bytes:
            self.stop("archive-metadata-budget", location)
            return False
        return True

    def register_container_layer(self, location: str) -> None:
        self.container_layer_archives.add(normalize_archive_location(location))

    def is_container_layer_stream(self, location: str) -> bool:
        """Whether ``location`` is a container rootfs layer, not an inner tar.

        Compressed OCI layers gain exactly one synthetic ``!payload`` location
        while being decompressed.  Do not extend the virtual root to arbitrary
        descendants: an archive embedded in a layer remains an ordinary archive
        and must keep its traversal/link protections.
        """
        canonical = normalize_archive_location(location)
        if canonical in self.container_layer_archives:
            return True
        parent, separator, leaf = canonical.rpartition("!")
        return separator == "!" and leaf == "payload" and parent in self.container_layer_archives

    def register_container_config(self, location: str, manifest_location: str | None = None) -> None:
        canonical = normalize_archive_location(location)
        self.container_config_locations.add(canonical)
        if manifest_location is not None:
            self.container_config_manifest_locations.setdefault(canonical, set()).add(
                normalize_archive_location(manifest_location))

    def register_container_config_platform(self, location: str, os_name: object,
                                           architecture: object) -> None:
        if isinstance(os_name, str) and isinstance(architecture, str):
            self.container_config_platforms[normalize_archive_location(location)] = (
                os_name.lower(), architecture.lower())

    def register_oci_declared_platform(self, location: str, platform: object) -> None:
        if not isinstance(platform, dict):
            self.oci_declared_platforms.append((location, None, None))
            return
        os_name = platform.get("os")
        architecture = platform.get("architecture")
        self.oci_declared_platforms.append((location,
                                             os_name.lower() if isinstance(os_name, str) else None,
                                             architecture.lower() if isinstance(architecture, str) else None))

    def register_oci_descriptor_platform(self, location: str, platform: object) -> None:
        if not isinstance(platform, dict):
            return
        os_name = platform.get("os")
        architecture = platform.get("architecture")
        if isinstance(os_name, str) and isinstance(architecture, str):
            self.oci_descriptor_platforms[normalize_archive_location(location)] = (
                os_name.lower(), architecture.lower())

    def register_container_blob_digest(self, location: str, digest: str) -> None:
        self.container_blob_digests[normalize_archive_location(location)] = digest

    def register_container_blob_reference(self, location: str, digest: str) -> None:
        self.container_blob_references.append((normalize_archive_location(location), digest))

    def defer_link(self, archive_location: str, member_location: str,
                   name: str, target: str) -> None:
        # OCI metadata is frequently stored after the compressed rootfs layer.
        # Defer both absolute and relative links so containment is evaluated
        # only once the complete stream has identified verified layers.
        self._deferred_links.append((archive_location, member_location, name, target))

    def finalize_deferred_links(self) -> None:
        for archive_location, member_location, name, target in self._deferred_links:
            is_container_layer = self.is_container_layer_stream(archive_location)
            if symlink_escapes(name, target, virtual_root=is_container_layer):
                self.add("symlink-escape", member_location)
        for location, expected_digest in self.container_blob_references:
            actual_digest = self.container_blob_digests.get(location)
            if actual_digest is None:
                self.add("container-digest-unverified", location)
            elif actual_digest != expected_digest:
                self.add("container-digest-mismatch", location)
        expected = ("linux", self.args.platform.lower())
        for location in self.container_config_locations:
            actual = self.container_config_platforms.get(location)
            if actual is None:
                self.add("container-platform-unverified", location)
                continue
            origins = self.container_config_manifest_locations.get(location, set())
            declared = {self.oci_descriptor_platforms[origin] for origin in origins
                        if origin in self.oci_descriptor_platforms}
            # A multi-platform OCI index legitimately includes non-target image
            # configs. Validate the target descriptor's config and retain the
            # older strict behavior for Docker save images with no descriptor.
            if declared and expected not in declared:
                continue
            if actual != expected:
                self.add("container-platform-mismatch", location)
        if self.oci_declared_platforms:
            if not any((os_name, architecture) == expected
                       for _, os_name, architecture in self.oci_declared_platforms):
                self.add("container-platform-mismatch", self.oci_declared_platforms[0][0])


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


def normalize_archive_location(location: str) -> str:
    """Canonicalize member names without changing the top-level input path."""
    root, *members = location.split("!")
    normalized_members = []
    for member in members:
        normalized = posixpath.normpath(member.replace("\\", "/"))
        normalized_members.append("" if normalized == "." else normalized.removeprefix("./"))
    return "!".join([root, *normalized_members])


def archive_path_is_absolute(name: str) -> bool:
    normalized = name.replace("\\", "/")
    return normalized.startswith("/") or bool(re.match(r"^[A-Za-z]:/", normalized))


def symlink_escapes(name: str, target: str, *, virtual_root: bool = False) -> bool:
    normalized_target = target.replace("\\", "/")
    if not safe_member_name(name):
        return True
    if archive_path_is_absolute(normalized_target):
        # OCI/Docker rootfs layers use POSIX absolute symlinks within the image
        # root. Ordinary archives have no such containment guarantee.
        return not virtual_root or not safe_member_name(normalized_target.lstrip("/"))
    if not virtual_root and not safe_member_name(normalized_target):
        return True
    parent = posixpath.dirname(name.replace("\\", "/"))
    return not safe_member_name(posixpath.normpath(posixpath.join(parent, normalized_target)))


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


def is_oci_blob_location(location: str) -> bool:
    return bool(re.search(r"(?:^|!)blobs/sha256/[0-9a-f]{64}$", location))


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


def scan_content_name(ctx: ScanContext, location: str) -> None:
    lower_name = location.lower()
    if lower_name.endswith((".map", ".sourcemap")):
        ctx.add("source-map", location)


def unquoted_runtime_source_expression(data: bytes, match: re.Match[bytes]) -> bool:
    """Return true for JS object references such as ``api_key: client.api_key``.

    An unquoted property path is executable source syntax, not a hard-coded
    value. Quoted text with the same spelling remains subject to the credential
    rule, preserving fail-closed handling for string literals.
    """
    value = match.group(2)
    if not re.fullmatch(rb"[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+", value):
        return False
    return match.start(2) == 0 or data[match.start(2) - 1:match.start(2)] not in (b"'", b'"')


def contains_generic_credential(data: bytes) -> bool:
    for match in CREDENTIAL_RE.finditer(data):
        value = match.group(2)
        # Shell variables and rule-pattern fragments are references, not
        # embedded credentials. Runtime object-property expressions are also
        # references, but only in unquoted source form.
        if (not placeholder(value) and not value.startswith(b"$")
                and not unquoted_runtime_source_expression(data, match)):
            return True
    return False


def reviewed_text_payload_exception(location: str, content_sha256: str) -> dict[str, object] | None:
    """Return an exact, time-bounded reviewed text exception if one exists."""
    name = location.rsplit("!", 1)[-1].replace("\\", "/")
    exception = REVIEWED_TEXT_PAYLOAD_EXCEPTIONS.get(name)
    if exception is None or content_sha256 not in exception["sha256"]:
        return None
    try:
        expires_at = datetime.strptime(str(exception["expires_at"]), "%Y-%m-%d").date()
    except (KeyError, TypeError, ValueError):
        return None
    if datetime.now(timezone.utc).date() > expires_at:
        return None
    return exception


def reviewed_source_artifact_exception(location: str,
                                       content_sha256: str) -> dict[str, object] | None:
    """Return an exact, time-bounded reviewed source-artifact exception."""
    name = location.rsplit("!", 1)[-1].replace("\\", "/")
    exception = REVIEWED_SOURCE_ARTIFACT_EXCEPTIONS.get(name)
    if exception is None or content_sha256 not in exception["sha256"]:
        return None
    try:
        expires_at = datetime.strptime(str(exception["expires_at"]), "%Y-%m-%d").date()
    except (KeyError, TypeError, ValueError):
        return None
    if datetime.now(timezone.utc).date() > expires_at:
        return None
    return exception


def scan_content_patterns(ctx: ScanContext, data: bytes, location: str,
                          *, scan_generic: bool = True) -> None:
    if SOURCE_MAP_RE.search(data):
        ctx.add("inline-source-map", location)
    if AWS_KEY_RE.search(data) or PRIVATE_KEY_RE.search(data):
        ctx.add("credential", location)
    if scan_generic and is_text_payload(data) and contains_generic_credential(data):
        ctx.add("credential", location)


def is_text_payload(data: bytes) -> bool:
    """Whether a payload can be interpreted as text configuration or source.

    Generic ``password=...`` matching against executable bytes produces false
    positives from compiled dependency examples. High-confidence private-key and
    cloud-key signatures remain checked for every payload; only the ambiguous
    assignment-style rule is limited to text data.
    """
    if not data or b"\x00" in data:
        return False
    if any(byte < 0x20 and byte not in (0x09, 0x0A, 0x0D) for byte in data):
        return False
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def scan_content_metadata(ctx: ScanContext, data: bytes, location: str) -> None:
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
    register_container_image_layers(ctx, data, location)


def scan_content(ctx: ScanContext, data: bytes, location: str) -> None:
    """Scan an already bounded byte value (kept for direct/unit callers)."""
    scan_content_name(ctx, location)
    scan_content_patterns(ctx, data, location)
    if has_source_name(location):
        digest = hashlib.sha256(data).hexdigest()
        exception = reviewed_source_artifact_exception(location, digest)
        if exception is None:
            ctx.add("source-artifact", location)
        else:
            ctx.allow_exception(exception, location, digest)
    if re.search(r"(?:^|!)blobs/sha256/[0-9a-f]{64}$", location):
        ctx.register_container_blob_digest(location, hashlib.sha256(data).hexdigest())
    scan_content_metadata(ctx, data, location)


def register_container_image_layers(ctx: ScanContext, data: bytes, location: str) -> None:
    """Recognize image metadata for layer containment and platform binding.

    Manifest entries can occur after their layers in a Docker save archive, so
    link and platform findings are deliberately finalized only after the full
    input is read.
    """
    try:
        manifest = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return
    parent = location.rsplit("!", 1)[0]
    if isinstance(manifest, list):
        for entry in manifest:
            if not isinstance(entry, dict) or not isinstance(entry.get("Layers"), list):
                continue
            config = entry.get("Config")
            if isinstance(config, str) and safe_member_name(config):
                ctx.register_container_config(f"{parent}!{config}")
            else:
                ctx.add("container-platform-unverified", location)
            for layer in entry["Layers"]:
                if isinstance(layer, str) and safe_member_name(layer):
                    ctx.register_container_layer(f"{parent}!{layer}")
        return
    if not isinstance(manifest, dict):
        return
    ctx.register_container_config_platform(location, manifest.get("os"), manifest.get("architecture"))
    if isinstance(manifest.get("manifests"), list):
        for descriptor in manifest["manifests"]:
            if isinstance(descriptor, dict):
                digest = descriptor.get("digest")
                if isinstance(digest, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                    descriptor_location = f"{parent}!blobs/sha256/{digest.split(':', 1)[1]}"
                    ctx.register_container_blob_reference(descriptor_location, digest.split(":", 1)[1])
                    # Top-level OCI indexes can point to a nested image index
                    # without a platform. Only descriptors that state a
                    # platform participate in target-platform selection.
                    if isinstance(descriptor.get("platform"), dict):
                        ctx.register_oci_declared_platform(location, descriptor["platform"])
                        ctx.register_oci_descriptor_platform(descriptor_location,
                                                             descriptor["platform"])
                else:
                    ctx.add("container-digest-unverified", location)
        return
    if not isinstance(manifest.get("layers"), list):
        return
    marker = "!blobs/sha256/"
    if marker not in location:
        return
    layout_root = location.rsplit(marker, 1)[0]
    config = manifest.get("config")
    config_digest = config.get("digest") if isinstance(config, dict) else None
    if isinstance(config_digest, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", config_digest):
        config_location = f"{layout_root}{marker}{config_digest.split(':', 1)[1]}"
        ctx.register_container_config(config_location, manifest_location=location)
        ctx.register_container_blob_reference(config_location, config_digest.split(":", 1)[1])
    else:
        ctx.add("container-platform-unverified", location)
        ctx.add("container-digest-unverified", location)
    for layer in manifest["layers"]:
        digest = layer.get("digest") if isinstance(layer, dict) else None
        if isinstance(digest, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            layer_location = f"{layout_root}{marker}{digest.split(':', 1)[1]}"
            ctx.register_container_layer(layer_location)
            ctx.register_container_blob_reference(layer_location, digest.split(":", 1)[1])
        else:
            ctx.add("container-digest-unverified", location)


def scan_deferred_content_patterns(ctx: ScanContext, stream, location: str) -> None:
    """Run content rules in a second bounded pass after OCI blob classification.

    OCI manifests may follow their rootfs blobs.  For a compressed blob, the
    caller can therefore identify its decompressed archive only after it has
    already been read. This helper preserves high-confidence signature checks,
    full text validation and overlap handling for a non-archive blob.
    """
    tail = b""
    all_text = True
    generic_credential_found = False
    digest = hashlib.sha256()
    stream.seek(0)
    while True:
        if not ctx.check_limits():
            return
        chunk = stream.read(CHUNK_SIZE)
        if not chunk:
            break
        window = tail + chunk
        scan_content_patterns(ctx, window, location, scan_generic=False)
        all_text = all_text and is_text_payload(chunk)
        if all_text and contains_generic_credential(window):
            generic_credential_found = True
        tail = window[-CONTENT_SCAN_OVERLAP:]
        digest.update(chunk)
    if all_text and generic_credential_found:
        content_sha256 = digest.hexdigest()
        exception = reviewed_text_payload_exception(location, content_sha256)
        if exception is None:
            ctx.add("credential", location, content_sha256=content_sha256)
        else:
            ctx.allow_exception(exception, location, content_sha256)
    stream.seek(0)


def read_stream(ctx: ScanContext, stream, location: str, *, scan_generic: bool = True,
                scan_high_confidence: bool = True):
    """Scan one bounded stream and retain it without materialising it in RAM.

    Nested Docker layers routinely exceed the scanner's former 256 MiB
    byte-array boundary.  A bounded ``SpooledTemporaryFile`` preserves the
    no-extraction property while permitting archive parsers to make a second
    pass over a member.  The total/member limits still cap disk consumption.
    """
    payload = tempfile.SpooledTemporaryFile(
        max_size=ctx.args.max_in_memory_bytes, mode="w+b"
    )
    total = 0
    tail = b""
    metadata = bytearray()
    metadata_complete = True
    blob_digest = hashlib.sha256()
    content_digest = hashlib.sha256()
    all_text = True
    generic_credential_found = False
    is_blob = is_oci_blob_location(location)
    scan_content_name(ctx, location)
    try:
        while True:
            if not ctx.check_limits():
                payload.close()
                return None
            remaining = ctx.args.max_total_bytes - ctx.coverage["bytes_scanned"]
            chunk = stream.read(max(1, min(CHUNK_SIZE, ctx.args.max_member_bytes - total + 1, remaining + 1)))
            if not chunk:
                break
            total += len(chunk)
            ctx.coverage["bytes_scanned"] += len(chunk)
            if total > ctx.args.max_member_bytes:
                ctx.stop("archive-budget", location)
                payload.close()
                return None
            if ctx.coverage["bytes_scanned"] > ctx.args.max_total_bytes:
                ctx.stop("archive-budget", "scan-total")
                payload.close()
                return None
            payload.write(chunk)
            window = tail + chunk
            # High-confidence signatures are safe to inspect in every byte
            # window. Generic assignments are deferred until the whole stream
            # is known to be text; compressed OCI blobs can otherwise contain
            # accidental ASCII fragments before a later NUL byte.
            if scan_high_confidence:
                scan_content_patterns(ctx, window, location, scan_generic=False)
            all_text = all_text and is_text_payload(chunk)
            if scan_generic and all_text and contains_generic_credential(window):
                generic_credential_found = True
            tail = window[-CONTENT_SCAN_OVERLAP:]
            content_digest.update(chunk)
            if is_blob:
                blob_digest.update(chunk)
            if metadata_complete:
                remaining_metadata = ctx.args.max_structured_metadata_bytes - len(metadata)
                if len(chunk) <= remaining_metadata:
                    metadata.extend(chunk)
                else:
                    metadata_complete = False
                    metadata.clear()
        if is_blob:
            ctx.register_container_blob_digest(location, blob_digest.hexdigest())
        digest = content_digest.hexdigest()
        if has_source_name(location):
            exception = reviewed_source_artifact_exception(location, digest)
            if exception is None:
                ctx.add("source-artifact", location, content_sha256=digest)
            else:
                ctx.allow_exception(exception, location, digest)
        if all_text and generic_credential_found:
            exception = reviewed_text_payload_exception(location, digest)
            if exception is None:
                ctx.add("credential", location, content_sha256=digest)
            else:
                ctx.allow_exception(exception, location, digest)
        if metadata_complete:
            scan_content_metadata(ctx, bytes(metadata), location)
        elif is_package_manifest(ctx, location):
            # The delivery manifest must be small enough to parse and bind.
            ctx.add("manifest-parse", location)
        payload.seek(0)
        return payload
    except Exception:
        payload.close()
        raise


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
        with open_regular_file(path) as stream:
            scan_archive_stream(ctx, stream, location, depth)
    except OSError:
        ctx.stop("unreadable", location)


class MetadataBudgetStream:
    """Bound archive parser metadata reads without charging member content twice."""

    def __init__(self, ctx: ScanContext, stream, location: str):
        self.ctx = ctx
        self.stream = stream
        self.location = location
        self.accounting = True

    def read(self, size: int = -1) -> bytes:
        if not self.accounting:
            return self.stream.read(size)
        if not self.ctx.check_limits():
            return b""
        remaining = self.ctx.args.max_archive_metadata_bytes - self.ctx.coverage["archive_metadata_bytes"]
        if remaining < 0:
            self.ctx.stop("archive-metadata-budget", self.location)
            return b""
        requested = remaining + 1 if size is None or size < 0 else min(size, remaining + 1)
        data = self.stream.read(requested)
        if data and not self.ctx.account_archive_metadata(len(data), self.location):
            return b""
        return data

    def readinto(self, buffer) -> int:
        data = self.read(len(buffer))
        buffer[:len(data)] = data
        return len(data)

    def readline(self, size: int = -1) -> bytes:
        if not self.accounting:
            return self.stream.readline(size)
        if not self.ctx.check_limits():
            return b""
        remaining = self.ctx.args.max_archive_metadata_bytes - self.ctx.coverage["archive_metadata_bytes"]
        if remaining < 0:
            self.ctx.stop("archive-metadata-budget", self.location)
            return b""
        requested = remaining + 1 if size is None or size < 0 else min(size, remaining + 1)
        data = self.stream.readline(requested)
        if data and not self.ctx.account_archive_metadata(len(data), self.location):
            return b""
        return data

    def seek(self, *args):
        return self.stream.seek(*args)

    def tell(self):
        return self.stream.tell()

    def __getattr__(self, name):
        return getattr(self.stream, name)


@contextmanager
def open_regular_file(path: pathlib.Path):
    """Open one regular file without following a replacement symlink.

    ``O_NONBLOCK`` prevents a FIFO replacement from stalling a build gate and
    ``O_NOFOLLOW`` plus ``fstat`` closes the lstat/open race for the leaf.
    """
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(os.fspath(path), flags)
    stream = None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file", os.fspath(path))
        stream = os.fdopen(fd, "rb")
        fd = -1
        with stream:
            yield stream
    finally:
        if fd >= 0:
            os.close(fd)


def filesystem_symlink_escapes(candidate: pathlib.Path, root: pathlib.Path) -> bool:
    target = pathlib.Path(os.path.realpath(candidate))
    return root not in target.parents and target != root


def iter_directory_files(ctx: ScanContext, root: pathlib.Path):
    """Yield only stable regular files and fail closed on traversal errors."""
    def onerror(error: OSError) -> None:
        location = relative_location(pathlib.Path(error.filename or root), root)
        ctx.stop("unreadable", location)

    for directory, dirs, files in os.walk(root, followlinks=False, onerror=onerror):
        if not ctx.check_limits():
            return
        directory_path = pathlib.Path(directory)
        for dirname in list(dirs):
            candidate = directory_path / dirname
            if candidate.is_symlink():
                if filesystem_symlink_escapes(candidate, root):
                    ctx.add("symlink-escape", relative_location(candidate, root))
                dirs.remove(dirname)
        for filename in files:
            if not ctx.check_limits():
                return
            candidate = directory_path / filename
            location = relative_location(candidate, root)
            if candidate.is_symlink():
                if filesystem_symlink_escapes(candidate, root):
                    ctx.add("symlink-escape", location)
                continue
            try:
                mode = os.lstat(candidate).st_mode
            except OSError:
                ctx.stop("unreadable", location)
                continue
            if not stat.S_ISREG(mode):
                ctx.stop("unsupported-file", location)
                continue
            yield candidate, location


def scan_regular_path(ctx: ScanContext, path: pathlib.Path, location: str) -> None:
    try:
        with open_regular_file(path) as stream:
            prefix = stream.read(tarfile.BLOCKSIZE)
            stream.seek(0)
            if archive_kind(location, prefix) is not None:
                scan_archive_stream(ctx, stream, location, 0)
                return
            payload = read_stream(ctx, stream, location)
        if payload is not None:
            with payload:
                scan_archive_stream(ctx, payload, location, 0)
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
                # An OCI manifest may be stored after this blob, so its role is
                # not known yet.  Defer the ambiguous generic text rule for all
                # blob payloads until their decompressed content is classified.
                # High-confidence signatures still run in every byte window.
                deferred_blob_payload = member_location.endswith("!payload") and is_oci_blob_location(
                    member_location.rsplit("!", 1)[0])
                payload = read_stream(
                    ctx,
                    compressed,
                    member_location,
                    scan_generic=not deferred_blob_payload,
                    scan_high_confidence=not deferred_blob_payload,
                )
            if payload is not None:
                with payload:
                    payload_prefix = payload.read(tarfile.BLOCKSIZE)
                    payload.seek(0)
                    nested_kind = archive_kind(member_location, payload_prefix)
                    # A decompressed OCI layer is an aggregate archive, whose
                    # actual files are scanned below.  A non-archive blob gets
                    # the deferred generic scan before returning, so neither
                    # manifest ordering nor blob naming creates a blind spot.
                    if deferred_blob_payload and nested_kind is None:
                        scan_deferred_content_patterns(ctx, payload, member_location)
                    scan_archive_stream(ctx, payload, member_location, depth + 1)
            return
        metadata_stream = MetadataBudgetStream(ctx, stream, location)
        archive_context = (zipfile.ZipFile(metadata_stream) if kind == "zip"
                           else tarfile.open(fileobj=metadata_stream, mode="r|*"))
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
                        metadata_stream.accounting = False
                        try:
                            payload = read_stream(
                                ctx, member_stream, member_location,
                                scan_generic=not is_oci_blob_location(member_location),
                                scan_high_confidence=not is_oci_blob_location(member_location),
                            )
                        finally:
                            metadata_stream.accounting = True
                    if (member.external_attr >> 16) & 0o170000 == 0o120000:
                        if payload is not None:
                            with payload:
                                target = payload.read().decode("utf-8", "replace")
                                ctx.defer_link(location, member_location, member_name, target)
                        continue
                else:
                    if member.issym() or member.islnk():
                        ctx.defer_link(location, member_location, member_name, member.linkname)
                        continue
                    if not member.isfile():
                        continue
                    member_stream = archive.extractfile(member)
                    if member_stream is None:
                        ctx.stop("archive-parse", member_location)
                        return
                    with member_stream:
                        metadata_stream.accounting = False
                        try:
                            payload = read_stream(
                                ctx, member_stream, member_location,
                                scan_generic=not is_oci_blob_location(member_location),
                                scan_high_confidence=not is_oci_blob_location(member_location),
                            )
                        finally:
                            metadata_stream.accounting = True
                if payload is not None:
                    with payload:
                        payload_prefix = payload.read(tarfile.BLOCKSIZE)
                        payload.seek(0)
                        if (is_oci_blob_location(member_location)
                                and archive_kind(member_location, payload_prefix) is None):
                            scan_deferred_content_patterns(ctx, payload, member_location)
                        scan_archive_stream(ctx, payload, member_location, depth + 1)
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
    for candidate, location in iter_directory_files(ctx, ctx.root):
        ctx.coverage["files"] += 1
        scan_regular_path(ctx, candidate, location)
        if not ctx.check_limits():
            return


def digest_input(root: pathlib.Path, ctx: ScanContext) -> str:
    """Hash the same regular-file set without bypassing deadline checks."""
    digest = hashlib.sha256()
    if root.is_file():
        try:
            with open_regular_file(root) as stream:
                while True:
                    if not ctx.check_limits():
                        return ""
                    chunk = stream.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    digest.update(chunk)
        except OSError:
            ctx.stop("unreadable", root.name)
            return ""
        return digest.hexdigest()
    if not root.is_dir():
        ctx.stop("unsupported-file", root.name)
        return ""
    files = sorted(iter_directory_files(ctx, root), key=lambda item: item[1])
    if not ctx.coverage["complete"]:
        return ""
    for path, location in files:
        if not ctx.check_limits():
            return ""
        digest.update(location.encode() + b"\0")
        try:
            with open_regular_file(path) as stream:
                while True:
                    if not ctx.check_limits():
                        return ""
                    chunk = stream.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    digest.update(chunk)
        except OSError:
            ctx.stop("unreadable", location)
            return ""
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
            "max_archive_metadata_bytes": args.max_archive_metadata_bytes,
            "max_structured_metadata_bytes": args.max_structured_metadata_bytes,
            "max_in_memory_bytes": args.max_in_memory_bytes,
        },
        "coverage": ctx.coverage,
        "exceptions": ctx.exceptions,
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
    parser.add_argument("--max-archive-metadata-bytes", type=int, default=DEFAULT_ARCHIVE_METADATA_BYTES)
    parser.add_argument("--max-structured-metadata-bytes", type=int,
                        default=DEFAULT_SPOOL_MEMORY_BYTES)
    parser.add_argument("--max-in-memory-bytes", type=int, default=DEFAULT_SPOOL_MEMORY_BYTES)
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
        elif root.is_dir():
            if args.allowlist:
                validate_allowlist(root, pathlib.Path(args.allowlist), ctx)
            if ctx.check_limits():
                scan_directory(ctx)
        elif root.is_file():
            scan_regular_path(ctx, root, root.name)
        else:
            ctx.stop("unsupported-file", root.name)
        ctx.finalize_deferred_links()
        # An incomplete scan is already rejected. Do not traverse the same
        # rejected input again outside the resource budget just to hash it.
        input_sha = digest_input(root, ctx) if root.exists() and ctx.coverage["complete"] else ""
    except Exception as error:
        # Build diagnostics must distinguish an implementation failure from a
        # policy finding, but exception text can include untrusted file content
        # or paths. Keep the report safe by exposing only the exception class.
        ctx.add(f"scanner-error:{type(error).__name__}", "scanner")
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
