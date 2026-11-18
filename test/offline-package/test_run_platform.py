"""Host distribution boundaries and portable run payload metadata."""
import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / "ops/install/openeuler-zhaoxin-run-header.sh"


class RunPlatformTests(unittest.TestCase):
    def run_check(self, os_id, architecture="x86_64", compatible=False, bundled=False,
                  unified=False, version_id="4", version="", variant=""):
        with tempfile.TemporaryDirectory(prefix="wdsp-platform-") as tmp:
            release = Path(tmp) / "os-release"
            release.write_text(
                f'ID="{os_id}"\nVERSION_ID="{version_id}"\nVERSION="{version}"\n'
                f'VARIANT_ID="{variant}"\n'
            )
            # Load declarations only; never execute installer actions or require root.
            declarations = HEADER.read_text().split("\nwhile [[ $# -gt 0 ]]; do", 1)[0]
            script = declarations + "\n" + (
                "ALLOW_COMPATIBLE_OS=$3\nUNIFIED_PACKAGE=$5\n"
                "check_install_platform \"$1\" \"$2\"\n"
                "if [[ $4 == true ]]; then check_bundled_rpm_platform \"$1\"; fi\n"
                "printf '%s\\n' \"$INSTALL_PLATFORM\"\n"
            )
            return subprocess.run(
                ["bash", "-c", script, "platform-test", str(release), architecture,
                 str(compatible).lower(), str(bundled).lower(), str(unified).lower()],
                capture_output=True, text=True, timeout=10,
            )

    def test_openeuler_accepts_quoted_mixed_case_id(self):
        result = self.run_check("openEuler", bundled=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_alinux_requires_explicit_compatibility(self):
        result = self.run_check("alinux")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--allow-compatible-os", result.stderr)

    def test_compatible_host_without_bundled_rpms_remains_allowed(self):
        result = self.run_check("alinux", compatible=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_compatibility_flag_never_allows_openeuler_rpms_on_alinux(self):
        result = self.run_check("alinux", compatible=True, bundled=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("openEuler RPM", result.stderr)
        self.assertIn("alinux", result.stderr)

    def test_architecture_cannot_be_overridden(self):
        result = self.run_check("openEuler", architecture="aarch64", compatible=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("x86_64", result.stderr)

    def test_missing_distribution_is_rejected(self):
        result = self.run_check("")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("os-release", result.stderr)

    def test_unified_package_selects_os_specific_repository(self):
        for os_id, version_id, version, variant, expected in (
            ("openEuler", "24.03", "24.03 (LTS-SP4)", "", "openeuler"),
            ("alinux", "4", "4", "openanolis", "alinux4"),
        ):
            with self.subTest(os_id=os_id):
                result = self.run_check(os_id, unified=True, version_id=version_id,
                                        version=version, variant=variant)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), expected)

    def test_unified_package_rejects_unvalidated_os_or_architecture(self):
        for os_id, version_id, version, variant, architecture in (
            ("openEuler", "24.03", "24.03 (LTS-SP3)", "", "x86_64"),
            ("alinux", "3", "3", "openanolis", "x86_64"),
            ("alinux", "4", "4", "standard", "x86_64"),
            ("alinux", "4", "4", "openanolis", "aarch64"),
            ("rocky", "9", "9", "", "x86_64"),
        ):
            with self.subTest(os_id=os_id, version=version, variant=variant, arch=architecture):
                result = self.run_check(os_id, compatible=True, unified=True,
                                        version_id=version_id, version=version,
                                        variant=variant, architecture=architecture)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    @unittest.skipUnless(sys.platform.startswith("linux") or shutil.which("sha256sum"),
                         "sha256sum required for RPM repository verification")
    def test_rpm_manifest_rejects_modified_or_extra_repository_files(self):
        with tempfile.TemporaryDirectory(prefix="wdsp-rpm-integrity-") as tmp:
            folder = Path(tmp)
            repo = folder / "rpms/alinux4"
            metadata = repo / "repodata/repomd.xml"
            metadata.parent.mkdir(parents=True)
            rpm = repo / "moby-1-1.alnx4.x86_64.rpm"
            rpm.write_bytes(b"rpm")
            metadata.write_bytes(b"metadata")
            files = (rpm, metadata)
            manifest = repo / "rpms.sha256"
            manifest.write_text("".join(
                f"{hashlib.sha256(file.read_bytes()).hexdigest()}  {file.relative_to(folder)}\n"
                for file in files
            ))
            header = HEADER.read_text()
            verify = header.split("\nverify_rpm_repository() (", 1)[1].split(
                "\ninstall_selected_rpms() {", 1
            )[0]
            # Signature verification has its own harness. Check the exact file set here.
            script = (
                'verify_package_signature() { test "$1" = rpms/alinux4/rpms.sha256; }\n'
                'die() { echo "$1" >&2; exit 1; }\n'
                '\nverify_rpm_repository() (' + verify + '\nverify_rpm_repository "$1" alinux4'
            )
            command = ["bash", "-ec", script, "repo-test", tmp]
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            metadata.write_bytes(b"tampered")
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            metadata.write_bytes(b"metadata")
            (repo / "unexpected.rpm").write_bytes(b"extra")
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)

    def test_checks_precede_host_package_transactions(self):
        text = HEADER.read_text()
        self.assertLess(text.index('check_install_platform /etc/os-release'),
                        text.index('command -v tar'))
        self.assertLess(text.index('check_bundled_rpm_platform /etc/os-release'),
                        text.index('dnf -y install "${rpms[@]}"'))
        self.assertIn('[[ "$UNINSTALL" == "true" ]] || check_install_platform', text)

    def test_run_payload_excludes_source_extended_attributes(self):
        with tempfile.TemporaryDirectory(prefix="wdsp-run-metadata-") as tmp:
            folder = Path(tmp)
            archive = folder / "jiuzhang-wdsp-offline-9.9.9-amd64.tar.gz"
            with tarfile.open(archive, "w:gz") as target:
                member = tarfile.TarInfo("fixture")
                member.size = 7
                target.addfile(member, io.BytesIO(b"fixture"))
            if sys.platform == "darwin":
                subprocess.run(["xattr", "-w", "com.wdsp.fixture", "value", str(archive)], check=True)
            elif hasattr(os, "setxattr"):
                try:
                    os.setxattr(archive, "user.wdsp.fixture", b"value")
                except OSError as error:
                    self.skipTest(f"filesystem does not support xattrs: {error}")
            else:
                self.skipTest("extended attributes unavailable")
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            Path(str(archive) + ".sha256").write_text(f"{digest}  {archive.name}\n")
            env = dict(os.environ)
            env.pop("WDSP_SIGNING_KEY", None)
            result = subprocess.run(
                ["bash", str(ROOT / "ops/offline-package/build-openeuler-zhaoxin-run.sh"),
                 "--version", "9.9.9", "--offline-package", str(archive),
                 "--development", "--output", str(folder / "output")],
                env=env, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            run = (folder / "output/jiuzhang-wdsp-install-9.9.9-amd64.run").read_bytes()
            payload = run.split(b"\n__WDSP_PAYLOAD_BELOW__\n", 1)[1]
            with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as target:
                for member in target:
                    self.assertFalse([key for key in member.pax_headers if "xattr" in key], member.name)


if __name__ == "__main__":
    unittest.main()
