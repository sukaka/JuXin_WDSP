"""HA (havipd / hasyncd) full-upgrade introduction and rollback contract tests."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_gateway_runtime_contract as gateway_contract


class HaUpgradeContractTests(unittest.TestCase):
    BASE_SERVICES = ("api", "web", "gateway", "netmgrd", "logrotator", "containerops")
    EXTRA_SERVICES = ("web", "logrotator", "containerops")

    def setUp(self):
        self.base = gateway_contract.GatewayRuntimeContractTests(
            "test_apply_dual_compose_uses_old_ids_and_target_runtime"
        )
        self.base.setUp()
        self.work = self.base.work
        self._configure_composes(old_has_havipd=False, new_has_havipd=True)
        self.images = self.base.target_release / "images"
        self.images.mkdir()
        for name in (
            "jiuzhang-server",
            "jiuzhang-web",
            "jiuzhang-gateway",
            "jiuzhang-netmgrd",
            "jiuzhang-mirrorcap",
            "jiuzhang-tproxyd",
            "jiuzhang-havipd",
            "jiuzhang-hasyncd",
            "jiuzhang-logrotator",
            "jiuzhang-containerops",
            "jiuzhang-pcapd",
            "postgres",
            "valkey",
            "clickhouse",
            "opentelemetry-collector-contrib",
        ):
            (self.images / f"{name}.tar").write_bytes(b"fixture-image")
        self.current = self.work / "current"
        self.current.symlink_to(self.work, target_is_directory=True)

    def tearDown(self):
        self.base.tearDown()

    def _configure_composes(
        self,
        *,
        old_has_havipd,
        new_has_havipd,
        include_hasyncd=False,
        include_pcapd=False,
    ):
        for old, has_havipd in ((True, old_has_havipd), (False, new_has_havipd)):
            config = self.base.compose_config(old=old)
            suffix = "old" if old else "target"
            for service in self.EXTRA_SERVICES:
                config["services"][service] = {"image": f"fixture-{service}:{suffix}-stable"}
            config["services"]["mirrorcap"] = {"image": f"fixture-mirrorcap:{suffix}-stable"}
            config["services"]["tproxyd"] = {"image": f"fixture-tproxyd:{suffix}-stable"}
            if has_havipd:
                config["services"]["havipd"] = {"image": f"fixture-havipd:{suffix}-stable"}
            if include_hasyncd:
                config["services"]["hasyncd"] = {"image": f"fixture-hasyncd:{suffix}-stable"}
            if include_pcapd:
                config["services"]["pcapd"] = {"image": f"fixture-pcapd:{suffix}-stable"}
            path = self.base.old_compose if old else self.base.new_compose
            path.write_text(json.dumps(config))

        fixture = json.loads(self.base.fixture_file.read_text())
        for service in (*self.EXTRA_SERVICES, "mirrorcap", "tproxyd", "havipd", "hasyncd", "pcapd"):
            entrypoint = None
            if service in ("mirrorcap", "tproxyd", "havipd", "hasyncd"):
                entrypoint = [f"/usr/local/bin/{service}"]
            for suffix in ("old", "target"):
                fixture["images"][f"fixture-{service}:{suffix}-stable"] = {
                    "id": f"sha256:{service}-{suffix}",
                    "entrypoint": entrypoint,
                }
        fixture.update({
            "schema": 217,
            "target_schema": 221,
            "postgres_id": "a" * 64,
            "migrate_api": True,
        })
        self.base.fixture_file.write_text(json.dumps(fixture))

    def run_full(self):
        return self.base.run_script(
            self.base.apply,
            "--full",
            "--images-dir", self.images,
            "--server-image", "fixture-server:new",
            "--gateway-image", "fixture-gateway:new",
            "--compose-file", self.base.old_compose,
            "--env-file", self.base.env_file,
            "--new-compose-file", self.base.new_compose,
            "--previous-compose-file", self.base.old_compose,
            "--current-link", self.current,
            "--timeout", "2",
        )

    def test_full_upgrade_adds_havipd_and_runs_healthcheck(self):
        result = self.run_full()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        state = self.base.state_values()
        self.assertEqual(
            state["UPGRADE_SERVICES"],
            "api,web,gateway,netmgrd,logrotator,containerops,mirrorcap,tproxyd,havipd",
        )
        fixture = json.loads(self.base.fixture_file.read_text())
        havipd_running = fixture["running"]["havipd"]
        self.assertEqual(havipd_running["image"], "fixture-havipd:target-stable")
        self.assertEqual(havipd_running["image_id"], "sha256:havipd-target")

        events = self.base.events()
        self.assertEqual(len([e for e in events if e["kind"] == "load"]), 15)
        havipd_probes = [
            e for e in events
            if e["kind"] == "exec"
            and e["args"] == ["exec", havipd_running["id"], "/usr/local/bin/havipd", "--healthcheck"]
        ]
        self.assertGreaterEqual(len(havipd_probes), 1)

    def test_full_upgrade_upgrades_active_hasyncd_and_keeps_pcapd_last(self):
        self._configure_composes(
            old_has_havipd=False,
            new_has_havipd=True,
            include_hasyncd=True,
            include_pcapd=True,
        )
        result = self.run_full()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        state = self.base.state_values()
        self.assertEqual(
            state["UPGRADE_SERVICES"],
            "api,web,gateway,netmgrd,logrotator,containerops,mirrorcap,tproxyd,havipd,hasyncd,pcapd",
        )
        self.assertTrue(state["UPGRADE_SERVICES"].endswith(",pcapd"))
        fixture = json.loads(self.base.fixture_file.read_text())
        hasyncd_running = fixture["running"]["hasyncd"]
        self.assertEqual(hasyncd_running["image_id"], "sha256:hasyncd-target")
        events = self.base.events()
        hasyncd_probes = [
            e for e in events
            if e["kind"] == "exec"
            and e["args"] == ["exec", hasyncd_running["id"], "/usr/local/bin/hasyncd", "--healthcheck"]
        ]
        self.assertGreaterEqual(len(hasyncd_probes), 1)

    def test_havipd_healthcheck_failure_rolls_back_and_removes_new_havipd(self):
        self.base.write_executable(
            self.base.work / "ops/upgrade/install-executor.sh",
            '#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "$HOSTCTL_HELPER_LOG"\n',
        )
        orig_docker = self.base.bin / "docker-orig"
        (self.base.bin / "docker").rename(orig_docker)
        self.base.write_executable(
            self.base.bin / "docker",
            f'#!/usr/bin/env bash\n'
            f'if [[ "${{1:-}}" == "exec" && "$*" == *"/usr/local/bin/havipd --healthcheck"* ]]; then\n'
            f'  exit 1\n'
            f'fi\n'
            f'exec {str(orig_docker)!r} "$@"\n',
        )
        result = self.run_full()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("自动回滚完成", result.stderr)
        events = self.base.events()
        rm_havipd = [
            e for e in events
            if e["kind"] == "compose"
            and e["action"] == "rm"
            and e["files"] == [str(self.base.new_compose)]
            and e["args"][-3:] == ["rm", "-sf", "havipd"]
        ]
        self.assertEqual(len(rm_havipd), 1)


if __name__ == "__main__":
    unittest.main()
