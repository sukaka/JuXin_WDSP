"""Tests for the one-command signed WDSP runtime .run package helper."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "ops/offline-package/package-runtime-run.sh"


class PackageRuntimeRunTests(unittest.TestCase):
    def run_script(self, *args, env=None):
        return subprocess.run(
            ["bash", str(SCRIPT), *args],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def make_rpm_dir(self, parent):
        rpm_dir = Path(parent) / "openeuler-rpms"
        rpm_dir.mkdir()
        (rpm_dir / "docker-compose-plugin-2.29.7-1.x86_64.rpm").touch()
        return rpm_dir

    def test_help_describes_signed_runtime_delivery(self):
        result = self.run_script("--help")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("--signing-key", result.stdout)
        self.assertIn("--rpm-dir", result.stdout)
        self.assertIn("--dry-run", result.stdout)
        self.assertIn("不包含测试代码或产品文档", result.stdout)

    def test_dry_run_lists_all_runtime_build_steps_without_writing_output(self):
        with tempfile.TemporaryDirectory(prefix="wdsp-runtime-run-test-") as tmp:
            output = Path(tmp) / "package-output"
            rpm_dir = self.make_rpm_dir(tmp)
            result = self.run_script(
                "--dry-run", "--version", "9.9.9", "--output", str(output),
                "--rpm-dir", str(rpm_dir),
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("jiuzhang-server:9.9.9", result.stdout)
            self.assertIn("jiuzhang-web:9.9.9", result.stdout)
            self.assertIn("jiuzhang-gateway:9.9.9", result.stdout)
            self.assertIn("jiuzhang-netmgrd:9.9.9", result.stdout)
            self.assertIn("jiuzhang-logrotator:9.9.9", result.stdout)
            self.assertIn("GOOS=linux", result.stdout)
            self.assertIn("build-openeuler-zhaoxin-run.sh", result.stdout)
            self.assertIn("--rpm-dir", result.stdout)
            self.assertFalse(output.exists())

    def test_dirty_workspace_requires_explicit_version(self):
        with tempfile.TemporaryDirectory(prefix="wdsp-runtime-run-test-") as tmp:
            rpm_dir = self.make_rpm_dir(tmp)
            marker = ROOT / ".wdsp-package-test-dirty"
            marker.write_text("test\n", encoding="utf-8")
            try:
                result = self.run_script(
                    "--dry-run", "--output", str(Path(tmp) / "package-output"),
                    "--rpm-dir", str(rpm_dir),
                )
            finally:
                marker.unlink(missing_ok=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("工作区存在未提交改动", result.stderr)
            self.assertIn("--version", result.stderr)

    def test_rejects_non_amd64_rpm(self):
        with tempfile.TemporaryDirectory(prefix="wdsp-runtime-run-test-") as tmp:
            rpm_dir = self.make_rpm_dir(tmp)
            (rpm_dir / "containerd.io-1.7.0-1.aarch64.rpm").touch()
            result = self.run_script(
                "--dry-run", "--version", "9.9.9", "--output", str(Path(tmp) / "out"),
                "--rpm-dir", str(rpm_dir),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("非 x86-64/noarch RPM", result.stderr)

    def test_rejects_private_key_that_does_not_match_release_trust_anchor(self):
        with tempfile.TemporaryDirectory(prefix="wdsp-runtime-run-test-") as tmp:
            private_key = Path(tmp) / "wrong-release.key"
            generated = subprocess.run(
                ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private_key)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(generated.returncode, 0, generated.stderr)
            rpm_dir = self.make_rpm_dir(tmp)
            result = self.run_script(
                "--dry-run", "--version", "9.9.9", "--output", str(Path(tmp) / "out"),
                "--signing-key", str(private_key), "--rpm-dir", str(rpm_dir),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("不匹配安装器信任公钥", result.stderr)

    def test_complete_package_requires_compose_plugin_rpm_directory(self):
        with tempfile.TemporaryDirectory(prefix="wdsp-runtime-run-test-") as tmp:
            result = self.run_script(
                "--dry-run", "--version", "9.9.9", "--output", str(Path(tmp) / "out")
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("--rpm-dir", result.stderr)

    def test_complete_package_rejects_rpm_directory_without_compose_plugin(self):
        with tempfile.TemporaryDirectory(prefix="wdsp-runtime-run-test-") as tmp:
            rpm_dir = Path(tmp) / "openeuler-rpms"
            rpm_dir.mkdir()
            (rpm_dir / "docker-ce-27.3.1-1.x86_64.rpm").touch()
            result = self.run_script(
                "--dry-run", "--version", "9.9.9", "--output", str(Path(tmp) / "out"),
                "--rpm-dir", str(rpm_dir),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("docker-compose-plugin", result.stderr)

    def test_production_run_requires_signing_key_before_building(self):
        with tempfile.TemporaryDirectory(prefix="wdsp-runtime-run-test-") as tmp:
            env = dict(os.environ)
            env.pop("WDSP_SIGNING_KEY", None)
            result = self.run_script("--version", "9.9.9", "--output", str(Path(tmp) / "out"), env=env)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("WDSP_SIGNING_KEY", result.stderr)


if __name__ == "__main__":
    unittest.main()
