"""Lifecycle behavior tests with isolated files and a fake Docker command boundary."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("wdsp_lifecycle", ROOT / "ops/install/lifecycle.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
P = module.PROJECT
L = module.LABEL


class Docker:
    def __init__(self, product):
        self.calls = []
        self.containers = [{"Id": "c1", "Config": {"Labels": {L: P, L + ".working_dir": str(product)}}}]
        self.networks = [{"Id": "n1", "Labels": {L: P}, "Containers": {"c1": {}}}]
        self.volumes = [{"Name": P + "_" + name, "Labels": {L: P}, "CreatedAt": "2026-11-18T01:00:00Z", "Mountpoint": "/not-used"}
                        for name in ("postgres-data", "runtime-data")]
        self.foreign_consumer = False

    def __call__(self, args):
        self.calls.append(args)
        if args[:3] == ["docker", "ps", "-aq"]:
            if any(a.startswith("volume=") for a in args) and self.foreign_consumer:
                return "c1\nforeign\n"
            return "\n".join(c["Id"] for c in self.containers)
        if args[:2] == ["docker", "inspect"]:
            return json.dumps(self.containers)
        if args[:3] == ["docker", "network", "ls"]:
            return "n1" if self.networks else ""
        if args[:3] == ["docker", "network", "inspect"]:
            return json.dumps(self.networks)
        if args[:3] == ["docker", "volume", "ls"]:
            return "\n".join(v["Name"] for v in self.volumes)
        if args[:3] == ["docker", "volume", "inspect"]:
            return json.dumps(self.volumes)
        if args[:2] == ["docker", "stop"]:
            return ""
        if args[:2] == ["docker", "rm"]:
            self.containers = []
            self.networks[0]["Containers"] = {}
            return ""
        if args[:3] == ["docker", "network", "rm"]:
            self.networks = []
            return ""
        if args[:3] == ["docker", "volume", "rm"]:
            self.volumes = [v for v in self.volumes if v["Name"] != args[-1]]
            return ""
        if args[0] == "systemctl":
            return ""
        raise AssertionError(args)

    def mutations(self):
        return [a for a in self.calls if a[0] == "systemctl" or a[1:2] in (["rm"], ["stop"]) or a[2:3] == ["rm"]]


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.root = self.base / "wdsp"
        self.product = self.root / "releases/1.7.0/jiuzhang-wdsp-offline-1.7.0-amd64"
        self.product.mkdir(parents=True)
        (self.product / "manifest.json").write_text(json.dumps({"edition": "wdsp", "arch": "amd64"}))
        (self.product / "docker-compose.yml").write_text("name: jiuzhang-wdsp\n")
        (self.product / ".env").write_text("POSTGRES_PASSWORD=test-db\nVALKEY_PASSWORD=test-cache\nJIUZHANG_MASTER_KEY=test-key\n")
        (self.product / "runtime/certificates").mkdir(parents=True)
        (self.product / "runtime/certificates/console.crt").write_text("test-certificate")
        (self.root / "current").symlink_to(self.product)
        self.docker = Docker(self.product)
        self.units = self.base / "units"
        self.units.mkdir()
        self.config = self.base / "executor.conf"
        self.life = module.Lifecycle(self.root, self.docker, self.units, self.config, self.base / "executor")

    def test_keep_then_reinstall_preserves_credentials_runtime_and_accounts(self):
        original = (self.product / ".env").read_bytes()
        self.life.uninstall()
        self.assertFalse(self.docker.containers)
        self.assertEqual(len(self.docker.volumes), 2)
        self.assertEqual((self.product / ".env").read_bytes(), original)
        self.assertEqual(self.life.state_path.stat().st_mode & 0o777, 0o600)
        self.life.preflight()
        new = self.root / "releases/1.7.1/jiuzhang-wdsp-offline-1.7.1-amd64"
        new.mkdir(parents=True)
        self.life.restore(new)
        self.assertEqual((new / ".env").read_bytes(), original)
        self.assertEqual((new / ".env").stat().st_mode & 0o777, 0o600)
        self.assertEqual((new / "runtime").resolve(), self.product / "runtime")
        self.assertEqual((new / "runtime/certificates/console.crt").read_text(), "test-certificate")
        self.assertFalse(any(a[:3] == ["docker", "volume", "rm"] for a in self.docker.calls))

    def test_purge_requires_confirmation_before_any_mutation(self):
        with self.assertRaises(module.LifecycleError):
            self.life.uninstall(purge=True)
        self.assertFalse(self.docker.mutations())
        self.assertTrue(self.root.exists())

    def test_confirmed_purge_removes_only_owned_data_and_installation(self):
        unrelated = self.base / "other-system"
        unrelated.mkdir()
        (unrelated / "data").write_text("preserved")
        self.life.uninstall(purge=True, confirmed=True)
        self.assertFalse(self.root.exists())
        self.assertFalse(self.docker.volumes)
        self.assertEqual((unrelated / "data").read_text(), "preserved")
        self.assertFalse(any("prune" in a for a in self.docker.calls))

    def test_foreign_project_directory_refuses_before_stopping(self):
        self.docker.containers[0]["Config"]["Labels"][L + ".working_dir"] = str(self.base / "other")
        with self.assertRaises(module.LifecycleError):
            self.life.uninstall()
        self.assertFalse(self.docker.mutations())

    def test_shared_volume_refuses_even_in_keep_mode(self):
        self.docker.foreign_consumer = True
        with self.assertRaises(module.LifecycleError):
            self.life.uninstall()
        self.assertFalse(self.docker.mutations())

    def test_shared_network_refuses_before_stopping(self):
        self.docker.networks[0]["Containers"]["foreign"] = {}
        with self.assertRaises(module.LifecycleError):
            self.life.uninstall()
        self.assertFalse(self.docker.mutations())

    def test_purge_refuses_unknown_installation_files(self):
        (self.root / "other-app-data").mkdir()
        with self.assertRaises(module.LifecycleError):
            self.life.uninstall(purge=True, confirmed=True)
        self.assertFalse(self.docker.mutations())

    def test_retained_config_change_or_volume_replacement_blocks_reinstall(self):
        self.life.uninstall()
        self.docker.volumes[0]["CreatedAt"] = "2026-11-19T01:00:00Z"
        with self.assertRaises(module.LifecycleError):
            self.life.retained()
        self.docker.volumes[0]["CreatedAt"] = "2026-11-18T01:00:00Z"
        (self.product / ".env").write_text("changed")
        with self.assertRaises(module.LifecycleError):
            self.life.retained()

    def test_partial_uninstall_cannot_be_used_as_complete_retention(self):
        self.life.uninstall()
        state = json.loads(self.life.state_path.read_text())
        state["phase"] = "removing"
        self.life.write_state(state)
        with self.assertRaises(module.LifecycleError):
            self.life.preflight()

    def test_unmanaged_systemd_unit_refuses_before_stopping_containers(self):
        (self.units / "jiuzhang-hostctl.service").write_text("ExecStart=/usr/bin/true\n")
        with self.assertRaises(module.LifecycleError):
            self.life.uninstall()
        self.assertFalse(self.docker.mutations())

    def test_external_runtime_and_symlink_root_are_rejected(self):
        (self.product / "runtime").rename(self.base / "runtime-outside")
        (self.product / "runtime").symlink_to(self.base / "runtime-outside")
        with self.assertRaises(module.LifecycleError):
            self.life.uninstall()
        alias = self.base / "alias"
        alias.symlink_to(self.root)
        with self.assertRaises(module.LifecycleError):
            module.Lifecycle(alias)
        self.assertFalse(self.docker.mutations())

    def test_existing_installation_cannot_overwrite_env(self):
        with self.assertRaises(module.LifecycleError):
            self.life.preflight()
        self.assertFalse(self.docker.mutations())

    def test_help_exposes_default_retention_and_explicit_purge(self):
        import subprocess
        result = subprocess.run(["bash", str(ROOT / "ops/install/openeuler-zhaoxin-run-header.sh"), "--help"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        for option in ("--uninstall", "--keep-data", "--purge-data", "--confirm-delete-data"):
            self.assertIn(option, result.stdout)

    def test_executor_lock_rejects_symlink_parent_and_lockfile(self):
        runtime_vol = self.base / "runtime-vol"
        runtime_vol.mkdir()
        outside = self.base / "outside-lock-dir"
        outside.mkdir()
        (runtime_vol / "upgrade-executor").symlink_to(outside)
        volumes = [{"Name": P + "_runtime-data", "Mountpoint": str(runtime_vol)}]
        with self.assertRaises(module.LifecycleError):
            with self.life.executor_lock(runtime_vol, volumes):
                pass

        # Also reject symlink on HOST_STATE_DIR
        state_link = self.base / "host-state-link"
        state_link.symlink_to(outside)
        with self.assertRaises(module.LifecycleError):
            with self.life.executor_lock(None, volumes, host_state=state_link):
                pass

        # Also reject symlink on executor.lock inside real HOST_STATE_DIR
        real_state = self.base / "real-host-state"
        real_state.mkdir()
        (real_state / "executor.lock").symlink_to(outside / "target")
        with self.assertRaises(module.LifecycleError):
            with self.life.executor_lock(None, volumes, host_state=real_state):
                pass


if __name__ == "__main__":
    unittest.main()
