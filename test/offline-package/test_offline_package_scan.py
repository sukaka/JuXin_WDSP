#!/usr/bin/env python3
"""Executable IP-01/IP-02 tests for the build-time offline package scanner."""

from __future__ import annotations

import io
import bz2
import gzip
import importlib.util
import json
import hashlib
import lzma
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCANNER = REPO_ROOT / "ops" / "offline-package" / "scan.py"
ALLOWLIST = REPO_ROOT / "ops" / "offline-package" / "allowlist.v1"


def make_tar(path: pathlib.Path, members: list[tuple[str, bytes]]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, payload in members:
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))


def make_zip(path: pathlib.Path, members: list[tuple[str, bytes]]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, payload in members:
            archive.writestr(name, payload)


class OfflinePackageScannerTests(unittest.TestCase):
    def run_scan(self, root: pathlib.Path, *extra: str) -> tuple[subprocess.CompletedProcess[str], dict]:
        report = root.parent / "scan-report.json"
        allowlist = root.parent / "allowlist.v1"
        allowlist.write_text(
            "version=1\nfile=install/install.sh\nfile=lib/common.sh\n",
            encoding="utf-8",
        )
        command = [
            sys.executable,
            str(SCANNER),
            "--root",
            str(root),
            "--allowlist",
            str(allowlist),
            "--output",
            str(report),
            "--product",
            "wdsp",
            "--version",
            "1.0.0",
            "--platform",
            "amd64",
            *extra,
        ]
        result = subprocess.run(command, text=True, capture_output=True, check=False, timeout=5)
        self.assertTrue(report.exists(), result.stderr)
        return result, json.loads(report.read_text(encoding="utf-8"))

    def make_root(self) -> pathlib.Path:
        workspace = tempfile.TemporaryDirectory(prefix="offline-scan-test-")
        self.addCleanup(workspace.cleanup)
        temp = pathlib.Path(workspace.name) / "package"
        ops = temp / "ops"
        ops.mkdir(parents=True)
        for relative in ("install/install.sh", "lib/common.sh"):
            target = ops / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("#!/usr/bin/env bash\n", encoding="utf-8")
        return temp

    def test_extensionless_and_disguised_layers_are_scanned_by_content(self) -> None:
        for mode in ("w", "w:gz", "w:bz2", "w:xz"):
            for filename in ("blobs/sha256/digest", "._disguised"):
                with self.subTest(mode=mode, filename=filename):
                    root = self.make_root()
                    payload = io.BytesIO()
                    with tarfile.open(fileobj=payload, mode=mode) as archive:
                        source = b"package private\n"
                        info = tarfile.TarInfo("app/internal.go")
                        info.size = len(source)
                        archive.addfile(info, io.BytesIO(source))
                    make_tar(root / "image.tar", [(filename, payload.getvalue())])
                    result, report = self.run_scan(root)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("source-artifact", {f["rule"] for f in report["findings"]})
                    self.assertTrue(report["coverage"]["complete"])

    def test_single_compressed_files_scan_content_and_preserve_source_names(self) -> None:
        for suffix, compress in (("gz", gzip.compress), ("bz2", bz2.compress), ("xz", lzma.compress)):
            for filename, payload, expected in (
                ("manual.txt", b"safe documentation", None),
                ("config.json", b'{"password":"synthetic-credential-only"}', "credential"),
                ("private.go", b"package private", "source-artifact"),
            ):
                with self.subTest(suffix=suffix, filename=filename):
                    root = self.make_root()
                    (root / f"{filename}.{suffix}").write_bytes(compress(payload))
                    result, report = self.run_scan(root)
                    self.assertTrue(report["coverage"]["complete"], report["findings"])
                    if expected:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn(expected, {f["rule"] for f in report["findings"]})
                    else:
                        self.assertEqual(result.returncode, 0, report["findings"])

    def test_zip_symlink_payload_is_bounded_and_crc_failure_is_not_ignored(self) -> None:
        for nested in (False, True):
            for corrupt in (False, True):
                with self.subTest(nested=nested, corrupt=corrupt):
                    root = self.make_root()
                    archive = io.BytesIO()
                    with zipfile.ZipFile(archive, "w") as zf:
                        link = zipfile.ZipInfo("link")
                        link.create_system = 3
                        link.external_attr = 0o120777 << 16
                        zf.writestr(link, b"q" * (64 if corrupt else 1024),
                                    compress_type=zipfile.ZIP_STORED if corrupt else zipfile.ZIP_DEFLATED)
                    data = archive.getvalue()
                    if corrupt:
                        data = data.replace(b"q" * 64, b"p" * 64)
                    if nested:
                        make_tar(root / "outer.tar.gz", [("links.zip", data)])
                    else:
                        (root / "links.zip").write_bytes(data)
                    result, report = self.run_scan(root, "--max-member-bytes", "512")
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(report["coverage"]["complete"])
                    expected = "archive-parse" if corrupt else "archive-budget"
                    self.assertIn(expected, {f["rule"] for f in report["findings"]})

    def test_empty_members_are_subject_to_global_count_budget(self) -> None:
        for kind in ("tar", "zip"):
            root = self.make_root()
            target = root / f"empty.{kind}"
            members = [(f"empty-{i}", b"") for i in range(100)]
            (make_tar if kind == "tar" else make_zip)(target, members)
            result, report = self.run_scan(root, "--max-archive-members", "3")
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(report["coverage"]["complete"])
            self.assertIn("archive-budget", {f["rule"] for f in report["findings"]})
            self.assertLessEqual(report["coverage"]["archive_members"], 4)

    def test_archive_metadata_budget_bounds_zip_directory_and_tar_pax(self) -> None:
        for kind in ("zip", "tar"):
            with self.subTest(kind=kind):
                root = self.make_root()
                target = root / f"metadata.{kind}"
                if kind == "zip":
                    with zipfile.ZipFile(target, "w") as archive:
                        for number in range(80):
                            archive.writestr(f"metadata-{number:03d}-{'x' * 32}", b"")
                else:
                    with tarfile.open(target, "w", format=tarfile.PAX_FORMAT) as archive:
                        info = tarfile.TarInfo("safe.txt")
                        info.size = 0
                        info.pax_headers = {"comment": "x" * 2048}
                        archive.addfile(info)
                result, report = self.run_scan(target, "--max-archive-metadata-bytes", "1024")
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(report["coverage"]["complete"])
                self.assertIn("archive-metadata-budget", {f["rule"] for f in report["findings"]})

    def test_compressed_bombs_and_truncation_fail_closed(self) -> None:
        for suffix, compress in (("gz", gzip.compress), ("bz2", bz2.compress), ("xz", lzma.compress)):
            for truncated in (False, True):
                with self.subTest(suffix=suffix, truncated=truncated):
                    root = self.make_root()
                    data = compress(b"x" * (32 if truncated else 1000000))
                    (root / f"compressed.{suffix}").write_bytes(data[:-8] if truncated else data)
                    result, report = self.run_scan(root, "--max-member-bytes", "128")
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(report["coverage"]["complete"])
                    self.assertIn("archive-parse" if truncated else "archive-budget",
                                  {f["rule"] for f in report["findings"]})

    def test_total_budget_stops_stream_reads_and_does_not_hash_rejected_input(self) -> None:
        root = self.make_root()
        spec = importlib.util.spec_from_file_location("offline_scanner", SCANNER)
        scanner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(scanner)
        argv = [str(SCANNER), "--root", str(root), "--output", str(root.parent / "budget.json"),
                "--product", "wdsp", "--version", "1.0.0", "--platform", "amd64",
                "--max-total-bytes", "8"]
        with mock.patch.object(sys, "argv", argv):
            args = scanner.parse_args()
            ctx = scanner.ScanContext(root, args)
            stream = io.BytesIO(b"x" * 100000)
            self.assertIsNone(scanner.read_stream(ctx, stream, "first"))
            self.assertLessEqual(stream.tell(), 9)
            second = io.BytesIO(b"x" * 100000)
            self.assertIsNone(scanner.read_stream(ctx, second, "second"))
            self.assertEqual(second.tell(), 0)
            with mock.patch.object(scanner, "digest_input") as digest:
                self.assertEqual(scanner.main(), 1)
                digest.assert_not_called()

    def test_large_nested_member_spools_to_disk_and_remains_scannable(self) -> None:
        root = self.make_root()
        layer = io.BytesIO()
        with tarfile.open(fileobj=layer, mode="w") as archive:
            payload = b"safe-layer-data\n" * 180000
            info = tarfile.TarInfo("usr/share/application.data")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        make_tar(root / "image.tar", [("layer.tar", layer.getvalue())])

        result, report = self.run_scan(
            root,
            "--max-in-memory-bytes", "1024",
            "--max-member-bytes", "4194304",
        )

        self.assertEqual(result.returncode, 0, report["findings"])
        self.assertTrue(report["coverage"]["complete"])
        self.assertEqual(report["limits"]["max_in_memory_bytes"], 1024)

    def test_plain_member_at_depth_limit_is_not_an_extra_archive(self) -> None:
        root = self.make_root()
        make_tar(root / "single.tar", [("readme.txt", b"documentation")])
        result, report = self.run_scan(root, "--max-depth", "0")
        self.assertEqual(result.returncode, 0, report["findings"])

    def load_scanner(self):
        spec = importlib.util.spec_from_file_location("offline_scanner", SCANNER)
        scanner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(scanner)
        return scanner

    def scanner_args(self, scanner, root):
        with mock.patch.object(sys, "argv", [str(SCANNER), "--root", str(root),
                               "--output", str(root.parent / "direct-report.json"),
                               "--product", "wdsp", "--version", "1.0.0", "--platform", "amd64"]):
            return scanner.parse_args()

    def test_filesystem_fifo_is_rejected_without_opening_or_hanging(self) -> None:
        for top_level in (True, False):
            with self.subTest(top_level=top_level):
                root = self.make_root()
                fifo = root / "pipe"
                os.mkfifo(fifo)
                result, report = self.run_scan(fifo if top_level else root)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(report["coverage"]["complete"])
                self.assertIn("unsupported-file", {f["rule"] for f in report["findings"]})

    def test_input_root_symlink_is_not_followed(self) -> None:
        for directory in (True, False):
            root = self.make_root()
            target = root if directory else root / "ops/install/install.sh"
            link = root.parent / "input-link"
            link.symlink_to(target, target_is_directory=directory)
            scanner = self.load_scanner()
            args = self.scanner_args(scanner, link)
            with mock.patch.object(scanner, "parse_args", return_value=args), \
                    mock.patch.object(scanner, "scan_directory") as scan_directory, \
                    mock.patch.object(scanner, "read_stream") as read_stream, \
                    mock.patch.object(scanner, "digest_input") as digest:
                self.assertEqual(scanner.main(), 1)
                scan_directory.assert_not_called()
                read_stream.assert_not_called()
                digest.assert_not_called()

    def test_unreadable_subdirectory_marks_scan_incomplete(self) -> None:
        root = self.make_root()
        denied = root / "unreadable"
        denied.mkdir()
        scanner = self.load_scanner()
        ctx = scanner.ScanContext(root, self.scanner_args(scanner, root))
        real_scandir = scanner.os.scandir

        def scandir(path):
            if pathlib.Path(path) == denied:
                raise PermissionError(13, "denied", str(denied))
            return real_scandir(path)

        with mock.patch.object(scanner.os, "scandir", side_effect=scandir):
            scanner.scan_directory(ctx)
        self.assertFalse(ctx.coverage["complete"])
        self.assertIn("unreadable", {f["rule"] for f in ctx.findings})

    def test_digest_enforces_same_deadline_and_unreadable_directory_policy(self) -> None:
        root = self.make_root()
        scanner = self.load_scanner()
        args = self.scanner_args(scanner, root)
        ctx = scanner.ScanContext(root, args)
        with mock.patch.object(scanner.time, "monotonic", return_value=ctx.started + args.timeout_seconds + 1):
            self.assertEqual(scanner.digest_input(root, ctx), "")
        self.assertFalse(ctx.coverage["complete"])
        self.assertIn("timeout", {f["rule"] for f in ctx.findings})
        ctx = scanner.ScanContext(root, args)
        with mock.patch.object(scanner.os, "scandir", side_effect=PermissionError(13, "denied", str(root))):
            self.assertEqual(scanner.digest_input(root, ctx), "")
        self.assertFalse(ctx.coverage["complete"])

    def test_regular_reader_rejects_replaced_symlink_and_fifo(self) -> None:
        root = self.make_root()
        scanner = self.load_scanner()
        fifo = root / "pipe"
        os.mkfifo(fifo)
        link = root / "link"
        link.symlink_to(root / "ops/install/install.sh")
        for path in (fifo, link):
            with self.subTest(path=path.name), self.assertRaises(OSError):
                with scanner.open_regular_file(path):
                    self.fail("Special file or symlink opened as a regular file")

    def test_image_manifest_does_not_replace_package_manifest_binding(self) -> None:
        root = self.make_root()
        package_manifest = json.dumps({"files_manifest_sha256": "a" * 64}).encode()
        (root / "manifest.json").write_bytes(package_manifest)
        image_manifest = json.dumps([{"Config": "config.json", "Layers": ["layer.tar"]}]).encode()
        layer = io.BytesIO()
        with tarfile.open(fileobj=layer, mode="w") as archive:
            info = tarfile.TarInfo("usr/bin/application")
            info.size = 3
            archive.addfile(info, io.BytesIO(b"ELF"))
        make_tar(root / "image.tar", [
            ("./manifest.json", image_manifest),
            ("config.json", b'{"architecture":"amd64","os":"linux"}'),
            ("layer.tar", layer.getvalue()),
        ])
        for target in (root, root.parent / "delivery.tar.gz"):
            if target != root:
                make_tar(target, [("delivery/" + p.relative_to(root).as_posix(), p.read_bytes())
                                  for p in sorted(root.rglob("*")) if p.is_file()])
            with self.subTest(target=target.name):
                result, report = self.run_scan(target)
                self.assertEqual(result.returncode, 0, report["findings"])
                self.assertEqual(report["manifest"]["sha256"], hashlib.sha256(package_manifest).hexdigest())
                self.assertEqual(report["manifest"]["files_manifest_sha256"], "a" * 64)

    def test_container_layer_absolute_symlink_is_virtual_root_only(self) -> None:
        root = self.make_root()
        layer = io.BytesIO()
        with tarfile.open(fileobj=layer, mode="w") as archive:
            link = tarfile.TarInfo("bin/sh")
            link.type = tarfile.SYMTYPE
            link.linkname = "/bin/busybox"
            archive.addfile(link)
            relative_link = tarfile.TarInfo("etc/os-release")
            relative_link.type = tarfile.SYMTYPE
            relative_link.linkname = "../usr/lib/os-release"
            archive.addfile(relative_link)
        make_tar(root / "image.tar", [
            ("manifest.json", json.dumps([{"Config": "config.json", "Layers": ["layer.tar"]}]).encode()),
            ("config.json", b'{"architecture":"amd64","os":"linux"}'),
            ("layer.tar", layer.getvalue()),
        ])

        result, report = self.run_scan(root)

        self.assertEqual(result.returncode, 0, report["findings"])

    def test_compressed_oci_layer_absolute_symlink_uses_virtual_root(self) -> None:
        root = self.make_root()
        layer = io.BytesIO()
        with tarfile.open(fileobj=layer, mode="w") as archive:
            link = tarfile.TarInfo("bin/sh")
            link.type = tarfile.SYMTYPE
            link.linkname = "/bin/busybox"
            archive.addfile(link)
        compressed_layer = gzip.compress(layer.getvalue())
        layer_digest = hashlib.sha256(compressed_layer).hexdigest()
        config_data = b'{"architecture":"amd64","os":"linux"}'
        config_digest = hashlib.sha256(config_data).hexdigest()
        image_manifest_data = json.dumps({
            "schemaVersion": 2,
            "config": {"digest": f"sha256:{config_digest}"},
            "layers": [{"digest": f"sha256:{layer_digest}"}],
        }, sort_keys=True, separators=(",", ":")).encode()
        manifest_digest = hashlib.sha256(image_manifest_data).hexdigest()
        platform_index_data = json.dumps({
            "schemaVersion": 2,
            "manifests": [{
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": f"sha256:{manifest_digest}",
                "platform": {"os": "linux", "architecture": "amd64"},
            }],
        }, sort_keys=True, separators=(",", ":")).encode()
        platform_index_digest = hashlib.sha256(platform_index_data).hexdigest()
        index_data = json.dumps({
            "schemaVersion": 2,
            "manifests": [{
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "digest": f"sha256:{platform_index_digest}",
            }],
        }, sort_keys=True, separators=(",", ":")).encode()
        make_tar(root / "image.tar", [
            ("index.json", index_data),
            (f"blobs/sha256/{platform_index_digest}", platform_index_data),
            (f"blobs/sha256/{manifest_digest}", image_manifest_data),
            (f"blobs/sha256/{config_digest}", config_data),
            (f"blobs/sha256/{layer_digest}", compressed_layer),
        ])

        result, report = self.run_scan(root)

        self.assertEqual(result.returncode, 0, report["findings"])

    def test_docker_image_config_platform_must_match_scan_target(self) -> None:
        root = self.make_root()
        make_tar(root / "image.tar", [
            ("manifest.json", json.dumps([{"Config": "config.json", "Layers": []}]).encode()),
            ("config.json", b'{"architecture":"arm64","os":"linux"}'),
        ])

        result, report = self.run_scan(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("container-platform-mismatch", {item["rule"] for item in report["findings"]})

    def test_container_image_requires_referenced_config_platform(self) -> None:
        root = self.make_root()
        make_tar(root / "image.tar", [
            ("manifest.json", json.dumps([{"Config": "missing.json", "Layers": []}]).encode()),
        ])

        result, report = self.run_scan(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("container-platform-unverified", {item["rule"] for item in report["findings"]})

    def test_oci_index_declared_platform_must_match_scan_target(self) -> None:
        root = self.make_root()
        manifest_digest = "a" * 64
        config_digest = "b" * 64
        oci_index = {
            "schemaVersion": 2,
            "manifests": [{
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": f"sha256:{manifest_digest}",
                "platform": {"os": "linux", "architecture": "arm64"},
            }],
        }
        image_manifest = {
            "schemaVersion": 2,
            "config": {"digest": f"sha256:{config_digest}"},
            "layers": [],
        }
        make_tar(root / "image.tar", [
            ("index.json", json.dumps(oci_index).encode()),
            (f"blobs/sha256/{manifest_digest}", json.dumps(image_manifest).encode()),
            (f"blobs/sha256/{config_digest}", b'{"architecture":"amd64","os":"linux"}'),
        ])

        result, report = self.run_scan(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("container-platform-mismatch", {item["rule"] for item in report["findings"]})

    def test_oci_descriptor_digest_must_bind_the_referenced_blob(self) -> None:
        config_data = json.dumps({"architecture": "amd64", "os": "linux"},
                                 sort_keys=True, separators=(",", ":")).encode()
        config_digest = hashlib.sha256(config_data).hexdigest()
        image_manifest_data = json.dumps({
            "schemaVersion": 2,
            "config": {"digest": f"sha256:{config_digest}"},
            "layers": [],
        }, sort_keys=True, separators=(",", ":")).encode()
        actual_manifest_digest = hashlib.sha256(image_manifest_data).hexdigest()
        for tampered in (False, True):
            with self.subTest(tampered=tampered):
                root = self.make_root()
                declared_manifest_digest = "a" * 64 if tampered else actual_manifest_digest
                oci_index_data = json.dumps({
                    "schemaVersion": 2,
                    "manifests": [{
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": f"sha256:{declared_manifest_digest}",
                        "platform": {"os": "linux", "architecture": "amd64"},
                    }],
                }, sort_keys=True, separators=(",", ":")).encode()
                make_tar(root / "image.tar", [
                    ("index.json", oci_index_data),
                    (f"blobs/sha256/{declared_manifest_digest}", image_manifest_data),
                    (f"blobs/sha256/{config_digest}", config_data),
                ])

                result, report = self.run_scan(root)

                if tampered:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("container-digest-mismatch",
                                  {item["rule"] for item in report["findings"]})
                else:
                    self.assertEqual(result.returncode, 0, report["findings"])

    def test_non_container_absolute_symlink_remains_rejected(self) -> None:
        root = self.make_root()
        archive_path = root / "ordinary.tar"
        with tarfile.open(archive_path, "w") as archive:
            link = tarfile.TarInfo("bin/sh")
            link.type = tarfile.SYMTYPE
            link.linkname = "/bin/busybox"
            archive.addfile(link)

        result, report = self.run_scan(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlink-escape", {item["rule"] for item in report["findings"]})

    def test_json_credential_and_base64_padding_are_not_exempt(self) -> None:
        for payload in (b'{"password":"synthetic-credential-only"}',
                        b'{"token":"c3ludGhldGljLW9ubHk="}',
                        b"secret=c3ludGhldGljLW9ubHk="):
            with self.subTest(format=payload[:10]):
                root = self.make_root()
                (root / "config.json").write_bytes(payload)
                result, report = self.run_scan(root)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("credential", {f["rule"] for f in report["findings"]})
                self.assertNotIn(payload.decode(), result.stdout + result.stderr + json.dumps(report))

    def test_binary_credential_like_sequence_is_not_treated_as_text_credential(self) -> None:
        root = self.make_root()
        (root / "gateway").write_bytes(
            b"\x7fELF\x00\x01password=synthetic-binary-marker\x00\xff"
        )

        result, report = self.run_scan(root)

        self.assertEqual(result.returncode, 0)
        self.assertNotIn("credential", {f["rule"] for f in report["findings"]})

    def test_non_utf8_binary_credential_like_sequence_is_not_treated_as_text_credential(self) -> None:
        root = self.make_root()
        (root / "opaque-payload").write_bytes(
            b"password=synthetic-binary-marker\xff"
        )

        result, report = self.run_scan(root)

        self.assertEqual(result.returncode, 0)
        self.assertNotIn("credential", {f["rule"] for f in report["findings"]})

    def test_streamed_binary_fragment_is_not_treated_as_text_credential(self) -> None:
        root = self.make_root()
        scanner = self.load_scanner()
        ctx = scanner.ScanContext(root, self.scanner_args(scanner, root))
        marker = b"password=synthetic-stream-marker"
        binary = marker + b"x" * (scanner.CHUNK_SIZE - len(marker)) + b"\x00"

        payload = scanner.read_stream(ctx, io.BytesIO(binary), "opaque-blob")

        self.assertIsNotNone(payload)
        payload.close()
        self.assertNotIn("credential", {f["rule"] for f in ctx.findings})

    def test_streamed_text_credential_remains_rejected(self) -> None:
        root = self.make_root()
        scanner = self.load_scanner()
        ctx = scanner.ScanContext(root, self.scanner_args(scanner, root))
        text = b"x" * scanner.CHUNK_SIZE + b" password=synthetic-stream-marker"

        payload = scanner.read_stream(ctx, io.BytesIO(text), "text-config")

        self.assertIsNotNone(payload)
        payload.close()
        self.assertIn("credential", {f["rule"] for f in ctx.findings})

    def test_unquoted_runtime_property_expression_is_not_a_credential(self) -> None:
        for payload, rejected in (
            (b"const request = { api_key: client.api_key };", False),
            (b'const request = { api_key: "client.api_key" };', True),
        ):
            with self.subTest(rejected=rejected):
                root = self.make_root()
                (root / "client.js").write_bytes(payload)

                result, report = self.run_scan(root)

                self.assertEqual(result.returncode != 0, rejected)
                self.assertEqual("credential" in {f["rule"] for f in report["findings"]}, rejected)

    def test_reviewed_text_exception_requires_exact_digest_and_active_expiry(self) -> None:
        scanner = self.load_scanner()
        approved = "a65a2cb9f4ee8ffdc7ef4f0ac600c0bdafb95b7b1ab457188ac610a62f5ad6b3"

        self.assertIsNotNone(
            scanner.reviewed_text_payload_exception("image.tar!etc/ssl/openssl.cnf", approved)
        )
        self.assertIsNone(
            scanner.reviewed_text_payload_exception("image.tar!etc/ssl/openssl.cnf", "0" * 64)
        )
        self.assertIsNone(
            scanner.reviewed_text_payload_exception("image.tar!etc/ssl/other.cnf", approved)
        )
        expired = dict(scanner.REVIEWED_TEXT_PAYLOAD_EXCEPTIONS["etc/ssl/openssl.cnf"])
        expired["expires_at"] = "2000-01-01"
        with mock.patch.dict(scanner.REVIEWED_TEXT_PAYLOAD_EXCEPTIONS,
                             {"etc/ssl/openssl.cnf": expired}, clear=True):
            self.assertIsNone(
                scanner.reviewed_text_payload_exception("image.tar!etc/ssl/openssl.cnf", approved)
            )

    def test_reviewed_source_exception_requires_exact_digest_and_active_expiry(self) -> None:
        scanner = self.load_scanner()
        approved = "a" * 64
        exception = {
            "sha256": {approved},
            "id": "IP-02-TEST-SOURCE-EXCEPTION",
            "owner": "test-owner",
            "supplier": "test-supplier",
            "reason": "test reviewed upstream utility",
            "expires_at": "2099-01-01",
        }
        with mock.patch.dict(scanner.REVIEWED_SOURCE_ARTIFACT_EXCEPTIONS,
                             {"usr/local/test/helper.pm": exception}, clear=True):
            self.assertIsNotNone(
                scanner.reviewed_source_artifact_exception(
                    "image.tar!usr/local/test/helper.pm", approved)
            )
            self.assertIsNone(
                scanner.reviewed_source_artifact_exception(
                    "image.tar!usr/local/test/helper.pm", "b" * 64)
            )
            self.assertIsNone(
                scanner.reviewed_source_artifact_exception(
                    "image.tar!usr/local/test/other.pm", approved)
            )
            expired = dict(exception)
            expired["expires_at"] = "2000-01-01"
            with mock.patch.dict(scanner.REVIEWED_SOURCE_ARTIFACT_EXCEPTIONS,
                                 {"usr/local/test/helper.pm": expired}, clear=True):
                self.assertIsNone(
                    scanner.reviewed_source_artifact_exception(
                        "image.tar!usr/local/test/helper.pm", approved)
                )

    def test_reviewed_source_exception_only_allows_the_exact_file(self) -> None:
        root = self.make_root()
        target = root / "usr/local/lib/postgresql/pgxs/src/test/perl/PostgreSQL/Test/Utils.pm"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"reviewed-content")
        scanner = self.load_scanner()
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        exception = {
            "sha256": {digest},
            "id": "IP-02-TEST-EXACT",
            "owner": "test-owner",
            "supplier": "test-supplier",
            "reason": "test reviewed upstream utility",
            "expires_at": "2099-01-01",
        }
        with mock.patch.dict(scanner.REVIEWED_SOURCE_ARTIFACT_EXCEPTIONS,
                             {target.relative_to(root).as_posix(): exception}, clear=True):
            ctx = scanner.ScanContext(root, self.scanner_args(scanner, root))
            scanner.scan_directory(ctx)
            self.assertEqual(ctx.findings, [])
            self.assertEqual(ctx.exceptions[0]["id"], "IP-02-TEST-EXACT")

        target.write_bytes(b"changed-content")
        ctx = scanner.ScanContext(root, self.scanner_args(scanner, root))
        scanner.scan_directory(ctx)
        self.assertIn("source-artifact", {item["rule"] for item in ctx.findings})

    def test_postgres_source_exceptions_allow_reviewed_architecture_hashes(self) -> None:
        scanner = self.load_scanner()
        cases = (
            ("usr/local/lib/postgresql/pgxs/src/test/isolation/isolationtester",
             "d7c884404eab42eadb7786c1885263e599a8b43ed208bf84da093b2b3cc8f1e0",
             "2fe65cb1415ed587302289467017496146ff146193f62a0a3fc26d5636b0f058"),
            ("usr/local/lib/postgresql/pgxs/src/test/isolation/pg_isolation_regress",
             "a9f3ac65399e26ee52e2a0989c214545acf07408124f2eab9971aa73f92bb1ce",
             "e3f45711cebc0504dd990b78da9cafc2db9d52f147bf5ad6aa28279667d9dafb"),
            ("usr/local/lib/postgresql/pgxs/src/test/regress/pg_regress",
             "8ae3ceef9e3c1427d3dae66cd851f9053d749750d4c9d0076e462246785f98be",
             "fb442f47aa1c79904ca4acbb850da09850a715f5b2b1877f7265ed3a03b9f192"),
        )
        for path, amd64_hash, arm64_hash in cases:
            with self.subTest(path=path):
                location = f"images/postgres.tar!payload!{path}"
                self.assertIsNotNone(
                    scanner.reviewed_source_artifact_exception(location, amd64_hash)
                )
                self.assertIsNotNone(
                    scanner.reviewed_source_artifact_exception(location, arm64_hash)
                )
                self.assertIsNone(
                    scanner.reviewed_source_artifact_exception(location, "0" * 64)
                )

    def test_oci_layer_payload_does_not_duplicate_generic_credential_finding(self) -> None:
        root = self.make_root()
        layer = root / "layer.tar.gz"
        make_tar(layer, [("etc/runtime.conf", b"password=synthetic-layer-marker")])
        archive = root / "image.tar"
        blob = "a" * 64
        with tarfile.open(archive, "w") as outer:
            layer_payload = layer.read_bytes()
            info = tarfile.TarInfo(f"blobs/sha256/{blob}")
            info.size = len(layer_payload)
            outer.addfile(info, io.BytesIO(layer_payload))
        layer.unlink()

        scanner = self.load_scanner()
        ctx = scanner.ScanContext(root, self.scanner_args(scanner, root))
        scanner.scan_regular_path(ctx, archive, "image.tar")

        locations = [item["location"] for item in ctx.findings if item["rule"] == "credential"]
        self.assertEqual(locations, [
            f"image.tar!blobs/sha256/{blob}!payload!etc/runtime.conf"
        ])

    def test_non_archive_oci_blob_still_runs_deferred_generic_credential_scan(self) -> None:
        root = self.make_root()
        archive = root / "image.tar"
        blob = "b" * 64
        with tarfile.open(archive, "w") as outer:
            payload = b'{"password":"synthetic-blob-credential"}'
            info = tarfile.TarInfo(f"blobs/sha256/{blob}")
            info.size = len(payload)
            outer.addfile(info, io.BytesIO(payload))

        scanner = self.load_scanner()
        ctx = scanner.ScanContext(root, self.scanner_args(scanner, root))
        scanner.scan_regular_path(ctx, archive, "image.tar")

        self.assertEqual(
            [item["location"] for item in ctx.findings if item["rule"] == "credential"],
            [f"image.tar!blobs/sha256/{blob}"],
        )

    def test_private_key_rule_requires_complete_pem(self) -> None:
        root = self.make_root()
        (root / "documentation.txt").write_bytes(
            b"Use a -----BEGIN PRIVATE KEY----- label when describing PEM files."
        )
        result, report = self.run_scan(root)
        self.assertEqual(result.returncode, 0, report["findings"])

        key = root / "private-key.pem"
        key.write_bytes(
            b"-----BEGIN PRIVATE KEY-----\n"
            + b"A" * 64 + b"\n"
            + b"B" * 64 + b"\n"
            + b"-----END PRIVATE KEY-----\n"
        )
        result, report = self.run_scan(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("credential", {item["rule"] for item in report["findings"]})

    def test_malformed_package_manifest_remains_rejected(self) -> None:
        for payload in (b"not-json", b"[]", b'{"files_manifest_sha256":"invalid"}'):
            root = self.make_root()
            (root / "manifest.json").write_bytes(payload)
            result, report = self.run_scan(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue({"manifest-parse", "manifest-binding"} & {f["rule"] for f in report["findings"]})

    def test_shipped_rule_documentation_is_not_a_credential(self) -> None:
        root = self.make_root()
        (root / "rule.conf").write_bytes(
            b'# token=/jwt=/access_token=\n# "token":"eyJhbGciOiJub25l..."\n'
        )
        result, report = self.run_scan(root)
        self.assertEqual(result.returncode, 0, report["findings"])

    def test_nested_archive_source_map_is_rejected_without_extraction(self) -> None:
        root = self.make_root()
        nested = root / "nested.tar.gz"
        make_tar(nested, [("frontend/app.js.map", b'{"sourcesContent":["secret"]}')])
        outer = root / "images.tar"
        with tarfile.open(outer, "w") as archive:
            info = tarfile.TarInfo("layer.tar.gz")
            payload = nested.read_bytes()
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        nested.unlink()

        result, report = self.run_scan(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(report["result"], "REJECT")
        self.assertTrue(any(item["rule"] == "source-map" for item in report["findings"]))
        self.assertFalse((root.parent / "frontend").exists())
        self.assertNotIn("sourcesContent", result.stderr)

    def test_delivery_assets_reject_standalone_hidden_and_inline_source_maps(self) -> None:
        samples = {
            "standalone": ("web/assets/app.js.map", b'{"version":3,"sources":["app.ts"]}'),
            "hidden": ("web/assets/.runtime.map", b'{"version":3,"sources":["runtime.ts"]}'),
            "inline": (
                "web/assets/app.js",
                b'//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozfQ==',
            ),
        }
        for name, (asset_path, asset_content) in samples.items():
            with self.subTest(sample=name):
                root = self.make_root()
                archive = root / "web-assets.tar.gz"
                make_tar(archive, [(asset_path, asset_content)])

                result, report = self.run_scan(root)

                self.assertNotEqual(result.returncode, 0)
                rules = {item["rule"] for item in report["findings"]}
                self.assertIn("inline-source-map" if name == "inline" else "source-map", rules)
                self.assertNotIn(asset_content.decode(), result.stdout + result.stderr + json.dumps(report))

    def test_docker_metadata_credentials_are_rejected_without_report_echo(self) -> None:
        samples = {
            "history": {
                "history": [{"created_by": "RUN token=synthetic-history-marker-123456"}],
            },
            "tag": {
                "repo_tags": ["registry.invalid/wdsp:token=synthetic-tag-marker-123456"],
            },
            "config": {
                "config": {"Labels": {"org.example.note": "password=synthetic-config-marker-123456"}},
            },
        }
        for name, metadata in samples.items():
            with self.subTest(metadata=name):
                root = self.make_root()
                config = {
                    "architecture": "amd64",
                    "os": "linux",
                    **{key: value for key, value in metadata.items() if key != "repo_tags"},
                }
                image_manifest = [{
                    "Config": "config.json",
                    "RepoTags": metadata.get("repo_tags", ["registry.invalid/wdsp:clean"]),
                    "Layers": [],
                }]
                make_tar(root / "gateway-image.tar", [
                    ("manifest.json", json.dumps(image_manifest).encode()),
                    ("config.json", json.dumps(config).encode()),
                ])

                result, report = self.run_scan(root)

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("credential", {item["rule"] for item in report["findings"]})
                marker = "synthetic-" + name + "-marker-123456"
                self.assertNotIn(marker, result.stdout + result.stderr + json.dumps(report))

    def test_fake_credential_is_rejected_without_echoing_value(self) -> None:
        root = self.make_root()
        (root / "config.json").write_text(
            '{"AWS_ACCESS_KEY_ID":"AKIAIOSFODNN7EXAMPLE",'
            '"password":"definitely-not-a-real-secret"}',
            encoding="utf-8",
        )

        result, report = self.run_scan(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(any(item["rule"] == "credential" for item in report["findings"]))
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", result.stdout + result.stderr)
        self.assertNotIn("definitely-not-a-real-secret", result.stdout + result.stderr)

    def test_archive_traversal_and_symlink_escape_are_rejected(self) -> None:
        root = self.make_root()
        traversal = root / "traversal.tar"
        with tarfile.open(traversal, "w") as archive:
            info = tarfile.TarInfo("../../outside.txt")
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
            link = tarfile.TarInfo("inside/link")
            link.type = tarfile.SYMTYPE
            link.linkname = "../../outside"
            archive.addfile(link)

        result, report = self.run_scan(root)

        self.assertNotEqual(result.returncode, 0)
        rules = {item["rule"] for item in report["findings"]}
        self.assertIn("path-traversal", rules)
        self.assertIn("symlink-escape", rules)
        self.assertFalse((root.parent / "outside.txt").exists())

    def test_capability_failure_and_budget_failure_are_not_zero_findings_pass(self) -> None:
        root = self.make_root()
        (root / "unsupported.tar.zst").write_bytes(b"\x28\xb5\x2f\xfdpayload")

        result, report = self.run_scan(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(report["result"], "REJECT")
        self.assertTrue(any(item["rule"] == "unsupported-archive" for item in report["findings"]))

        root2 = self.make_root()
        make_zip(root2 / "bomb.zip", [("large.txt", b"0123456789")])
        result2, report2 = self.run_scan(root2, "--max-member-bytes", "4")
        self.assertNotEqual(result2.returncode, 0)
        self.assertTrue(any(item["rule"] == "archive-budget" for item in report2["findings"]))

        root3 = self.make_root()
        result3, report3 = self.run_scan(root3, "--timeout-seconds", "0")
        self.assertNotEqual(result3.returncode, 0)
        self.assertTrue(any(item["rule"] == "timeout" for item in report3["findings"]))

    def test_allowlist_rejects_unlisted_ops_file(self) -> None:
        root = self.make_root()
        extra = root / "ops" / "upgrade" / "build-patch.sh"
        extra.parent.mkdir(parents=True, exist_ok=True)
        extra.write_text("#!/usr/bin/env bash\n", encoding="utf-8")

        result, report = self.run_scan(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(any(item["rule"] == "allowlist-extra" for item in report["findings"]))

    def test_internal_scanner_error_reports_only_exception_type(self) -> None:
        root = self.make_root()
        report_path = root.parent / "scanner-error.json"
        spec = importlib.util.spec_from_file_location("offline_scanner", SCANNER)
        scanner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(scanner)
        argv = [str(SCANNER), "--root", str(root), "--output", str(report_path),
                "--product", "wdsp", "--version", "1.0.0", "--platform", "amd64"]

        with mock.patch.object(sys, "argv", argv), \
             mock.patch.object(scanner, "scan_directory",
                               side_effect=RuntimeError("synthetic-secret-123456")):
            self.assertEqual(scanner.main(), 1)

        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertIn("scanner-error:RuntimeError", {item["rule"] for item in report["findings"]})
        self.assertNotIn("synthetic-secret-123456", json.dumps(report))

    def test_reviewed_text_exception_is_hash_bound_and_reported(self) -> None:
        root = self.make_root()
        payload = b"password=example-value-123456\n"
        target = root / "reviewed.conf"
        target.write_bytes(payload)
        report_path = root.parent / "reviewed-exception.json"
        spec = importlib.util.spec_from_file_location("offline_scanner", SCANNER)
        scanner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(scanner)
        exception = {
            "sha256": {hashlib.sha256(payload).hexdigest()},
            "id": "IP-02-TEST-EXCEPTION",
            "owner": "test-owner",
            "supplier": "test-supplier",
            "reason": "test reviewed example",
            "expires_at": "2099-01-01",
        }
        argv = [str(SCANNER), "--root", str(root), "--output", str(report_path),
                "--product", "wdsp", "--version", "1.0.0", "--platform", "amd64"]

        with mock.patch.object(sys, "argv", argv), \
             mock.patch.dict(scanner.REVIEWED_TEXT_PAYLOAD_EXCEPTIONS,
                             {"reviewed.conf": exception}, clear=True):
            self.assertEqual(scanner.main(), 0)

        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["exceptions"][0]["id"], "IP-02-TEST-EXCEPTION")
        self.assertEqual(report["exceptions"][0]["sha256"], hashlib.sha256(payload).hexdigest())

        target.write_bytes(payload + b"changed\n")
        with mock.patch.object(sys, "argv", argv), \
             mock.patch.dict(scanner.REVIEWED_TEXT_PAYLOAD_EXCEPTIONS,
                             {"reviewed.conf": exception}, clear=True):
            self.assertEqual(scanner.main(), 1)
        changed_report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertIn("credential", {item["rule"] for item in changed_report["findings"]})

    def test_build_orders_allowlist_scan_digest_and_signature(self) -> None:
        build = (REPO_ROOT / "ops" / "offline-package" / "build.sh").read_text(encoding="utf-8")
        self.assertNotIn('cp -R "$SCRIPT_DIR/.."', build)
        self.assertIn("allowlist.v1", build)
        scan_at = build.index("scan.py")
        sign_at = build.index("ed25519_sign_file", scan_at)
        self.assertLess(scan_at, sign_at)
        self.assertLess(build.index("gateway_scan_report"), build.index("ed25519_sign_file"))
        self.assertIn("扫描后产物摘要不匹配", build)
        self.assertIn("最终扫描报告与 allowlist/manifest 绑定不一致", build)
        self.assertIn("final_sha256", build)

    def test_report_digest_is_binding_for_unchanged_input(self) -> None:
        root = self.make_root()
        result, report = self.run_scan(root)

        self.assertEqual(result.returncode, 0)
        digest = hashlib.sha256()
        for path in sorted(item for item in root.rglob("*") if item.is_file()):
            digest.update(path.relative_to(root).as_posix().encode() + b"\0")
            digest.update(path.read_bytes())
        self.assertEqual(report["input"]["sha256"], digest.hexdigest())


if __name__ == "__main__":
    unittest.main()
