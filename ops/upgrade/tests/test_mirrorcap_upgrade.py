"""Mirror-mode (mirrorcap) full-upgrade introduction and rollback contract tests."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_gateway_runtime_contract as gateway_contract


class MirrorcapUpgradeContractTests(unittest.TestCase):
    BASE_SERVICES = ("api", "web", "gateway", "netmgrd", "logrotator", "containerops")
    EXTRA_SERVICES = ("web", "logrotator", "containerops")

    def setUp(self):
        self.base = gateway_contract.GatewayRuntimeContractTests(
            "test_apply_dual_compose_uses_old_ids_and_target_runtime"
        )
        self.base.setUp()
        self.work = self.base.work
        self._configure_composes(old_has_mirrorcap=False, new_has_mirrorcap=True)
        self.images = self.base.target_release / "images"
        self.images.mkdir()
        for name in (
            "jiuzhang-server",
            "jiuzhang-web",
            "jiuzhang-gateway",
            "jiuzhang-netmgrd",
            "jiuzhang-mirrorcap",
            "jiuzhang-tproxyd",
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

    def _configure_composes(self, *, old_has_mirrorcap, new_has_mirrorcap):
        for old, has_mirrorcap in ((True, old_has_mirrorcap), (False, new_has_mirrorcap)):
            config = self.base.compose_config(old=old)
            suffix = "old" if old else "target"
            for service in self.EXTRA_SERVICES:
                config["services"][service] = {"image": f"fixture-{service}:{suffix}-stable"}
            if has_mirrorcap:
                config["services"]["mirrorcap"] = {
                    "image": f"fixture-mirrorcap:{suffix}-stable",
                }
            path = self.base.old_compose if old else self.base.new_compose
            path.write_text(json.dumps(config))

        fixture = json.loads(self.base.fixture_file.read_text())
        for service in (*self.EXTRA_SERVICES, "mirrorcap"):
            for suffix in ("old", "target"):
                fixture["images"][f"fixture-{service}:{suffix}-stable"] = {
                    "id": f"sha256:{service}-{suffix}",
                    "entrypoint": ["/usr/local/bin/mirrorcap"] if service == "mirrorcap" else None,
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

    def test_full_upgrade_adds_mirrorcap_starts_target_image_and_runs_healthcheck(self):
        result = self.run_full()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        state = self.base.state_values()
        self.assertEqual(
            state["UPGRADE_SERVICES"],
            "api,web,gateway,netmgrd,logrotator,containerops,mirrorcap",
        )
        self.assertEqual(state["SCHEMA_BEFORE"], "217")

        fixture = json.loads(self.base.fixture_file.read_text())
        self.assertEqual(
            set(fixture["running"]),
            {*self.BASE_SERVICES, "mirrorcap"},
        )
        mirrorcap_running = fixture["running"]["mirrorcap"]
        self.assertEqual(mirrorcap_running["image"], "fixture-mirrorcap:target-stable")
        self.assertEqual(mirrorcap_running["image_id"], "sha256:mirrorcap-target")

        events = self.base.events()
        self.assertEqual(len([e for e in events if e["kind"] == "load"]), 13)
        mirrorcap_healthchecks = [
            e for e in events
            if e["kind"] == "exec"
            and e["args"] == ["exec", mirrorcap_running["id"], "/usr/local/bin/mirrorcap", "--healthcheck"]
        ]
        self.assertGreaterEqual(
            len(mirrorcap_healthchecks),
            1,
            f"expected mirrorcap --healthcheck exec call, got events: {events}",
        )

    def test_post_switch_health_failure_rolls_back_and_removes_newly_introduced_mirrorcap(self):
        self.base.write_executable(
            self.base.work / "ops/upgrade/install-executor.sh",
            '#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "$HOSTCTL_HELPER_LOG"\n',
        )
        self.base.write_executable(
            self.base.work / "ops/healthcheck/check.sh",
            '#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "$HEALTH_LOG"\n'
            '[[ "$(wc -l < "$HEALTH_LOG")" -eq 1 ]]\n',
        )

        result = self.run_full()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("自动回滚完成", result.stderr)

        events = self.base.events()
        rm_mirrorcap = [
            e for e in events
            if e["kind"] == "compose"
            and e["action"] == "rm"
            and e["files"] == [str(self.base.new_compose)]
            and e["args"][-3:] == ["rm", "-sf", "mirrorcap"]
        ]
        self.assertEqual(
            len(rm_mirrorcap),
            1,
            f"expected rollback to run compose rm -sf mirrorcap on new compose, got: {events}",
        )

        ups = [e for e in events if e["kind"] == "compose" and e["action"] == "up"]
        self.assertEqual(len(ups), 2)
        rollback_up = ups[-1]
        self.assertEqual(rollback_up["files"], [str(self.base.old_compose)])
        self.assertNotIn("mirrorcap", rollback_up["args"])
        for service in self.BASE_SERVICES:
            self.assertIn(service, rollback_up["args"])

        fixture = json.loads(self.base.fixture_file.read_text())
        self.assertEqual(fixture["schema"], 217)
        expected_old_ids = {
            "api": "sha256:server-old",
            "web": "sha256:web-old",
            "gateway": "sha256:gateway-old",
            "netmgrd": "sha256:netmgrd-stable",
            "logrotator": "sha256:logrotator-old",
            "containerops": "sha256:containerops-old",
        }
        for service, expected_id in expected_old_ids.items():
            self.assertEqual(fixture["running"][service]["image_id"], expected_id, service)

        # Rollback must not probe removed mirrorcap after restoring old compose
        rollback_up_index = max(
            i for i, e in enumerate(events) if e["kind"] == "compose" and e["action"] == "up"
        )
        post_rollback_mirrorcap_execs = [
            e for e in events[rollback_up_index + 1:]
            if e["kind"] == "exec" and "/usr/local/bin/mirrorcap" in e["args"]
        ]
        self.assertEqual(post_rollback_mirrorcap_execs, [])

        self.assertEqual(self.current.resolve(), self.work.resolve())
        self.assertFalse(self.base.state.exists())
        archived = list(self.base.upgrade_dir.glob(".upgrade-state.env.rolled-back.*"))
        self.assertEqual(len(archived), 1)

    def test_existing_mirrorcap_rollback_restores_old_image_and_healthchecks_it(self):
        self._configure_composes(old_has_mirrorcap=True, new_has_mirrorcap=True)
        self.base.write_executable(
            self.base.work / "ops/upgrade/install-executor.sh",
            '#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "$HOSTCTL_HELPER_LOG"\n',
        )
        self.base.write_executable(
            self.base.work / "ops/healthcheck/check.sh",
            '#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "$HEALTH_LOG"\n'
            '[[ "$(wc -l < "$HEALTH_LOG")" -eq 1 ]]\n',
        )

        result = self.run_full()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("自动回滚完成", result.stderr)

        events = self.base.events()
        rm_only_mirrorcap = [
            e for e in events
            if e["kind"] == "compose"
            and e["action"] == "rm"
            and e["args"][-3:] == ["rm", "-sf", "mirrorcap"]
        ]
        self.assertEqual(rm_only_mirrorcap, [])

        fixture = json.loads(self.base.fixture_file.read_text())
        self.assertEqual(fixture["running"]["mirrorcap"]["image_id"], "sha256:mirrorcap-old")

        rollback_up_index = max(
            i for i, e in enumerate(events) if e["kind"] == "compose" and e["action"] == "up"
        )
        post_rollback_mirrorcap_execs = [
            e for e in events[rollback_up_index + 1:]
            if e["kind"] == "exec"
            and e["args"] == [
                "exec",
                fixture["running"]["mirrorcap"]["id"],
                "/usr/local/bin/mirrorcap",
                "--healthcheck",
            ]
        ]
        self.assertGreaterEqual(len(post_rollback_mirrorcap_execs), 1)

    def test_mirrorcap_healthcheck_failure_triggers_automatic_rollback(self):
        self.base.write_executable(
            self.base.work / "ops/upgrade/install-executor.sh",
            '#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "$HOSTCTL_HELPER_LOG"\n',
        )
        orig_docker = self.base.bin / "docker-orig"
        (self.base.bin / "docker").rename(orig_docker)
        self.base.write_executable(
            self.base.bin / "docker",
            f'#!/usr/bin/env bash\n'
            f'if [[ "${{1:-}}" == "exec" && "$*" == *"/usr/local/bin/mirrorcap --healthcheck"* ]]; then\n'
            f'  python3 -c \'import json, os, sys; open(os.environ["DOCKER_LOG"], "a").write(json.dumps({{"kind": "exec", "args": sys.argv[1:], "forced_fail": True}}, sort_keys=True) + "\\n")\' "$@"\n'
            f'  exit 1\n'
            f'fi\n'
            f'exec {str(orig_docker)!r} "$@"\n',
        )

        result = self.run_full()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("自动回滚完成", result.stderr)

        events = self.base.events()
        failed_probes = [
            e for e in events
            if e["kind"] == "exec" and e.get("forced_fail") is True
        ]
        self.assertGreaterEqual(len(failed_probes), 1)
        rm_mirrorcap = [
            e for e in events
            if e["kind"] == "compose"
            and e["action"] == "rm"
            and e["files"] == [str(self.base.new_compose)]
            and e["args"][-3:] == ["rm", "-sf", "mirrorcap"]
        ]
        self.assertEqual(len(rm_mirrorcap), 1)
        fixture = json.loads(self.base.fixture_file.read_text())
        self.assertEqual(fixture["schema"], 217)
        self.assertEqual(fixture["running"]["api"]["image_id"], "sha256:server-old")
        self.assertEqual(fixture["running"]["gateway"]["image_id"], "sha256:gateway-old")


if __name__ == "__main__":
    unittest.main()
