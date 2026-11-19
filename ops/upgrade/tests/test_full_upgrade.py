"""完整升级的组件、备份与数据库回滚契约；夹具不代表目标 Linux 实测。"""
import json
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_gateway_runtime_contract as gateway_contract


class FullUpgradeContractTests(unittest.TestCase):
    def setUp(self):
        self.base = gateway_contract.GatewayRuntimeContractTests("test_apply_dual_compose_uses_old_ids_and_target_runtime")
        self.base.setUp()
        self.work = self.base.work
        for old in (True, False):
            config = self.base.compose_config(old=old)
            suffix = "old" if old else "target"
            for service in ("web", "logrotator", "containerops"):
                config["services"][service] = {"image": f"fixture-{service}:{suffix}-stable"}
            path = self.base.old_compose if old else self.base.new_compose
            path.write_text(json.dumps(config))
        fixture = json.loads(self.base.fixture_file.read_text())
        for service in ("web", "logrotator", "containerops"):
            for suffix in ("old", "target"):
                fixture["images"][f"fixture-{service}:{suffix}-stable"] = {
                    "id": f"sha256:{service}-{suffix}", "entrypoint": None,
                }
        fixture.update({
            "schema": 217,
            "target_schema": 221,
            "postgres_id": "a" * 64,
            "migrate_api": True,
        })
        self.base.fixture_file.write_text(json.dumps(fixture))
        self.images = self.base.target_release / "images"
        self.images.mkdir()
        for name in (
            "jiuzhang-server", "jiuzhang-web", "jiuzhang-gateway", "jiuzhang-netmgrd",
            "jiuzhang-logrotator", "jiuzhang-containerops", "jiuzhang-pcapd",
            "postgres", "valkey", "clickhouse", "opentelemetry-collector-contrib",
        ):
            (self.images / f"{name}.tar").write_bytes(b"fixture-image")
        self.current = self.work / "current"
        self.current.symlink_to(self.work, target_is_directory=True)

    def tearDown(self):
        self.base.tearDown()

    def run_full(self):
        return self.base.run_script(
            self.base.apply,
            "--full", "--images-dir", self.images,
            "--server-image", "fixture-server:new", "--gateway-image", "fixture-gateway:new",
            "--compose-file", self.base.old_compose, "--env-file", self.base.env_file,
            "--new-compose-file", self.base.new_compose,
            "--previous-compose-file", self.base.old_compose,
            "--current-link", self.current, "--timeout", "2",
        )

    def test_wrapper_initializes_executor_directory_for_legacy_releases(self):
        source = (gateway_contract.ROOT / "ops/upgrade/update-full.sh").read_text()
        self.assertIn('HOST_STATE_DIR="/var/lib/jiuzhang/upgrade-executor"', source)
        self.assertIn('install -d -m 0700 -o root -g root "$HOST_STATE_DIR"', source)
        self.assertNotIn('install -d -m 0755 "$CURRENT_RELEASE/runtime/upgrade-executor"', source)
        self.assertIn('roots != {expected_root}', source)
        self.assertIn('RUNTIME_REAL="$(realpath "$CURRENT_RELEASE/runtime")"', source)
        self.assertNotIn("原升级执行器共享目录不存在", source)

    def test_target_gateway_entrypoint_is_read_after_images_load(self):
        fixture = json.loads(self.base.fixture_file.read_text())
        target = fixture["images"].pop("fixture-gateway:new")
        fixture["load_images"] = {"fixture-gateway:new": target}
        self.base.fixture_file.write_text(json.dumps(fixture))
        result = self.run_full()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        events = self.base.events()
        load_indexes = [i for i, event in enumerate(events) if event["kind"] == "load"]
        inspect_indexes = [i for i, event in enumerate(events)
                           if event["kind"] == "inspect" and event["ref"] == "fixture-gateway:new"]
        self.assertTrue(load_indexes and inspect_indexes)
        self.assertLess(max(load_indexes), min(inspect_indexes))

    def test_full_upgrade_reconciles_all_components_and_leaves_current_until_wrapper_finishes(self):
        result = self.run_full()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        state = self.base.state_values()
        self.assertEqual(state["UPGRADE_SERVICES"], "api,web,gateway,netmgrd,logrotator,containerops")
        self.assertEqual(state["SCHEMA_BEFORE"], "217")
        self.assertNotIn("pcapd", state["UPGRADE_SERVICES"])
        self.assertEqual(self.current.resolve(), self.work.resolve())
        fixture = json.loads(self.base.fixture_file.read_text())
        self.assertEqual(set(fixture["running"]), {
            "api", "web", "gateway", "netmgrd", "logrotator", "containerops",
        })
        for service in ("web", "logrotator", "containerops"):
            self.assertEqual(fixture["running"][service]["image_id"], f"sha256:{service}-target")
        self.assertEqual(len([e for e in self.base.events() if e["kind"] == "load"]), 11)

    def test_post_switch_health_failure_restores_all_old_images_and_only_new_migrations(self):
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
        fixture = json.loads(self.base.fixture_file.read_text())
        self.assertEqual(fixture["schema"], 217)
        migrations = [e for e in self.base.events() if e["kind"] == "run"]
        self.assertEqual(len(migrations), 4)
        for event in migrations:
            self.assertEqual(event["args"][-2:], ["migrate", "down"])
            self.assertIn("sha256:server-new", event["args"])
        for service in ("api", "web", "gateway", "netmgrd", "logrotator", "containerops"):
            expected = "server" if service == "api" else "gateway" if service == "gateway" else service
            if service == "netmgrd":
                expected = "netmgrd-stable"
            else:
                expected = f"{expected}-old"
            self.assertEqual(fixture["running"][service]["image_id"], f"sha256:{expected}")
        self.assertEqual(self.current.resolve(), self.work.resolve())
        helper_log = self.base.hostctl_log.read_text()
        self.assertIn(f"--compose-file {self.base.old_compose}", helper_log)
        # H-05: rollback must restore using PREVIOUS_COMPOSE_FILE without poisoning new tags
        self.assertEqual(fixture["images"]["fixture-server:target-stable"]["id"], "sha256:server-new")
        self.assertEqual(fixture["images"]["fixture-gateway:target-stable"]["id"], "sha256:gateway-new")
        self.assertEqual(fixture["images"]["fixture-web:target-stable"]["id"], "sha256:web-target")
        ups = [e for e in self.base.events() if e["kind"] == "compose" and e["action"] == "up"]
        self.assertEqual(ups[-1]["files"], [str(self.base.old_compose)])
        # H-05: state file must be archived/renamed so outer update-full.sh does not double-rollback
        self.assertFalse(self.base.state.exists())
        archived_states = list(self.base.upgrade_dir.glob(".upgrade-state.env.rolled-back.*"))
        self.assertEqual(len(archived_states), 1)
        # H-05: apply.sh passes --api-url to rollback.sh
        apply_src = (gateway_contract.ROOT / "ops/upgrade/apply.sh").read_text()
        self.assertIn('rollback.sh" --yes --timeout "$TIMEOUT" --api-url "$JZ_API_BASE"', apply_src)

    def test_non_contiguous_migrations_only_roll_back_actual_count(self):
        self.base.write_executable(
            self.base.work / "ops/upgrade/install-executor.sh",
            '#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "$HOSTCTL_HELPER_LOG"\n',
        )
        self.base.write_executable(
            self.base.work / "ops/healthcheck/check.sh",
            '#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "$HEALTH_LOG"\n'
            '[[ "$(wc -l < "$HEALTH_LOG")" -eq 1 ]]\n',
        )
        fixture = json.loads(self.base.fixture_file.read_text())
        fixture.update({
            "schema": 217,
            "migrations": [215, 217],
            "target_migrations": [215, 217, 219, 222],
        })
        self.base.fixture_file.write_text(json.dumps(fixture))
        result = self.run_full()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("自动回滚完成", result.stderr)
        fixture = json.loads(self.base.fixture_file.read_text())
        self.assertEqual(fixture["schema"], 217)
        migrations = [e for e in self.base.events() if e["kind"] == "run"]
        # Gap 222 - 217 = 5, but only 2 actual migrations (219, 222) were added!
        self.assertEqual(len(migrations), 2)

    def test_previously_enabled_pcap_is_upgraded_but_never_enabled_by_default(self):
        for path, suffix in ((self.base.old_compose, "old"), (self.base.new_compose, "target")):
            config = json.loads(path.read_text())
            config["services"]["pcapd"] = {"image": f"fixture-pcapd:{suffix}-stable"}
            path.write_text(json.dumps(config))
        fixture = json.loads(self.base.fixture_file.read_text())
        for suffix in ("old", "target"):
            fixture["images"][f"fixture-pcapd:{suffix}-stable"] = {
                "id": f"sha256:pcapd-{suffix}", "entrypoint": None,
            }
        self.base.fixture_file.write_text(json.dumps(fixture))
        result = self.run_full()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.base.state_values()["UPGRADE_SERVICES"].endswith(",pcapd"))
        fixture = json.loads(self.base.fixture_file.read_text())
        self.assertEqual(fixture["running"]["pcapd"]["image_id"], "sha256:pcapd-target")

    def test_backup_failure_does_not_load_or_switch_any_image(self):
        self.base.write_executable(
            self.base.bin / "curl",
            '#!/usr/bin/env python3\nimport sys\nargs = " ".join(sys.argv[1:])\n'
            'if "/api/v1/auth/login" in args:\n'
            ' print(\'{"code":"SUCCESS","data":{"csrf_token":"fixture-csrf"}}\')\n'
            'elif "-X POST" in args and "/api/v1/backups" in args:\n'
            ' print(\'{"code":"BACKUP_UNAVAILABLE","message":"fixture failure"}\')\n',
        )
        result = self.run_full()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("创建备份失败", result.stderr)
        self.assertFalse(self.base.state.exists())
        self.assertFalse([e for e in self.base.events() if e["kind"] in ("load", "tag")])
        self.assertFalse([e for e in self.base.events() if e["kind"] == "compose" and e["action"] == "up"])


if __name__ == "__main__":
    unittest.main()
