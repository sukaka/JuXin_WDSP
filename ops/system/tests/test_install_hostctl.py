"""Reusable hostctl installer rendering and failure semantics."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
HELPER = ROOT / "ops/install/install-hostctl.sh"
INSTALL = ROOT / "ops/install/install.sh"


class InstallHostctlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wdsp-install-hostctl-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.target = self.work / "target-release"
        self.target.mkdir()
        self.units = self.work / "systemd-units"
        self.units.mkdir()
        self.systemd_runtime = self.work / "run-systemd"
        self.systemd_runtime.mkdir()
        self.bin = self.work / "bin"
        self.bin.mkdir()
        self.systemctl_log = self.work / "systemctl.log"
        self.chown_log = self.work / "chown.log"
        self.write_executable(
            "systemctl",
            '#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "$SYSTEMCTL_LOG"\nexit "${SYSTEMCTL_RC:-0}"\n',
        )
        self.write_executable(
            "chown",
            '#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "$CHOWN_LOG"\n',
        )
        self.write_executable(
            "id",
            '#!/usr/bin/env bash\nif [[ "${1:-}" == -u ]]; then printf "0\\n"; else exec /usr/bin/id "$@"; fi\n',
        )

    def write_executable(self, name, content):
        path = self.bin / name
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)

    def run_helper(self, *args, systemd=True):
        env = dict(os.environ)
        env.update({
            "PATH": str(self.bin) + os.pathsep + env["PATH"],
            "HOSTCTL_UNIT_TEMPLATE_DIR": str(ROOT / "deployment/systemd"),
            "HOSTCTL_SYSTEMD_UNIT_DIR": str(self.units),
            "HOSTCTL_SYSTEMD_RUNTIME_DIR": str(self.systemd_runtime if systemd else self.work / "missing"),
            "SYSTEMCTL_LOG": str(self.systemctl_log),
            "CHOWN_LOG": str(self.chown_log),
            "SYSTEMCTL_RC": "0",
        })
        return subprocess.run(
            ["bash", str(HELPER), *map(str, args)],
            env=env, capture_output=True, text=True, timeout=10,
        )

    def test_units_point_to_target_release_and_enable_path(self):
        result = self.run_helper("--install-root", self.target, "--strict")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        path_unit = (self.units / "jiuzhang-hostctl.path").read_text(encoding="utf-8")
        service_unit = (self.units / "jiuzhang-hostctl.service").read_text(encoding="utf-8")
        self.assertIn(f"PathExistsGlob={self.target.resolve()}/runtime/hostctl/*.json", path_unit)
        self.assertIn(
            f"ExecStart={self.target.resolve()}/ops/system/hostctl-exec.sh {self.target.resolve()}/runtime/hostctl",
            service_unit,
        )
        self.assertNotIn("__INSTALL_ROOT__", path_unit + service_unit)
        self.assertEqual(
            self.systemctl_log.read_text(encoding="utf-8").splitlines(),
            ["daemon-reload", "enable --now jiuzhang-hostctl.path"],
        )
        self.assertIn(f"1000:1000 {self.target.resolve()}/runtime/hostctl", self.chown_log.read_text())
        self.assertEqual((self.target / "runtime/hostctl").stat().st_mode & 0o777, 0o755)

    def test_strict_systemctl_failure_is_explicit(self):
        env_rc = "1"
        original = self.bin / "systemctl"
        original.write_text(
            '#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "$SYSTEMCTL_LOG"\nexit ' + env_rc + '\n',
            encoding="utf-8",
        )
        original.chmod(0o755)
        result = self.run_helper("--install-root", self.target, "--strict")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("systemctl daemon-reload/enable 失败", result.stderr)

    def test_non_systemd_keeps_warning_and_skip_semantics(self):
        result = self.run_helper("--install-root", self.target, "--strict", systemd=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("systemd 不可用或非 root", result.stderr)
        self.assertFalse((self.units / "jiuzhang-hostctl.path").exists())

    def test_full_installer_delegates_to_helper(self):
        source = INSTALL.read_text(encoding="utf-8")
        self.assertIn('bash "$SCRIPT_DIR/install-hostctl.sh" --install-root "$INSTALL_ROOT"', source)
        self.assertNotIn('sed "s|__INSTALL_ROOT__|$INSTALL_ROOT|g"', source)


if __name__ == "__main__":
    unittest.main()
