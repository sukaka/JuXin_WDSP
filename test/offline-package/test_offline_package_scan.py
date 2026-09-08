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
