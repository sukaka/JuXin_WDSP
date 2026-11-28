"""Offline rulepack gateway-rules volume migration & non-downgrade upgrade contract tests."""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_gateway_runtime_contract as gateway_contract


def populate_rules_tree(root: Path, marker: str) -> None:
    files = {
        "coraza.conf": f"# coraza {marker}\nSecRuleEngine On\n",
        "crs/VERSION.txt": "4.28.0\n",
        "crs/crs-setup.conf": f"# crs-setup {marker}\n",
        "crs/rules/REQUEST-942.conf": f'SecRule ARGS "@contains {marker}" "id:942100,phase:2,block"\n',
        "contrib/CUSTOM_PACK/cve.conf": f"# contrib {marker}\n",
        "exclusions/before-crs.conf": f"# before {marker}\n",
        "exclusions/after-crs.conf": f"# after {marker}\n",
        "jiuzhang/jiuzhang-custom.conf": f"# custom {marker}\n",
        "jiuzhang/post-contrib-blocking.conf": f"# blocking {marker}\n",
    }
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


class RulePackVolumeMigrationContractTests(unittest.TestCase):
    def setUp(self):
        self.base = gateway_contract.GatewayRuntimeContractTests(
            "test_apply_dual_compose_uses_old_ids_and_target_runtime"
        )
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
            "schema": 254,
            "target_schema": 255,
            "postgres_id": "a" * 64,
            "migrate_api": True,
        })
        self.base.fixture_file.write_text(json.dumps(fixture))
        self.images = self.base.target_release / "images"
        self.images.mkdir()
        for name in (
            "jiuzhang-server", "jiuzhang-web", "jiuzhang-gateway", "jiuzhang-netmgrd",
            "jiuzhang-logrotator", "jiuzhang-containerops",
        ):
            (self.images / f"{name}.tar").write_bytes(b"fixture-image")
        self.current = self.work / "current"
        self.current.symlink_to(self.work, target_is_directory=True)

    def tearDown(self):
        self.base.tearDown()

    def _setup_rules_upgrade(self, *, to_version: str, old_has_rules_vol: bool):
        old_cfg = json.loads(self.base.old_compose.read_text())
        new_cfg = json.loads(self.base.new_compose.read_text())
        old_cfg["name"] = "jiuzhang-wdsp"
        new_cfg["name"] = "jiuzhang-wdsp"
        old_cfg["volumes"] = {
            "runtime-data": {"name": "jiuzhang-wdsp_runtime-data"},
            "gateway-config": {"name": "jiuzhang-wdsp_gateway-config"},
        }
        new_cfg["volumes"] = {
            "runtime-data": {"name": "jiuzhang-wdsp_runtime-data"},
            "gateway-config": {"name": "jiuzhang-wdsp_gateway-config"},
            "gateway-rules": {"name": "jiuzhang-wdsp_gateway-rules"},
        }
        old_cfg["services"]["api"]["volumes"] = [
            {"type": "volume", "source": "runtime-data", "target": "/app/runtime"},
        ]
        old_cfg["services"]["gateway"]["volumes"] = [
            {"type": "volume", "source": "gateway-config", "target": "/config"},
        ]
        if old_has_rules_vol:
            old_cfg["volumes"]["gateway-rules"] = {"name": "jiuzhang-wdsp_gateway-rules"}
            old_cfg["services"]["api"]["volumes"].append(
                {"type": "volume", "source": "gateway-rules", "target": "/app/runtime/rules"}
            )
            old_cfg["services"]["gateway"]["volumes"].append(
                {"type": "volume", "source": "gateway-rules", "target": "/etc/caddy/rules", "read_only": True}
            )
        new_cfg["services"]["api"]["volumes"] = [
            {"type": "volume", "source": "runtime-data", "target": "/app/runtime"},
            {"type": "volume", "source": "gateway-rules", "target": "/app/runtime/rules"},
        ]
        new_cfg["services"]["gateway"]["volumes"] = [
            {"type": "volume", "source": "gateway-config", "target": "/config"},
            {"type": "volume", "source": "gateway-rules", "target": "/etc/caddy/rules", "read_only": True},
        ]
        self.base.old_compose.write_text(json.dumps(old_cfg))
        self.base.new_compose.write_text(json.dumps(new_cfg))

        (self.base.target_release / "manifest.json").write_text(
            json.dumps({"version": to_version, "edition": "wdsp"})
        )
        populate_rules_tree(self.base.target_release / "gateway/rules", f"seed-{to_version}")

        vol_root = self.work / "volumes"
        cfg_dir = vol_root / "jiuzhang-wdsp_gateway-config" / "_data"
        (cfg_dir / "caddy").mkdir(parents=True, exist_ok=True)
        (cfg_dir / "caddy" / "autosave.json").write_text(json.dumps({
            "apps": {"http": {"servers": {"s": {"routes": [{"handle": [{"directives": "Include /etc/caddy/rules/coraza.conf\n"}]}]}}}}
        }))
        fixture = json.loads(self.base.fixture_file.read_text())
        fixture["volume_root"] = str(vol_root)
        fixture["volumes"] = {
            "jiuzhang-wdsp_gateway-config": {"mountpoint": str(cfg_dir), "labels": {}},
        }
        self.base.fixture_file.write_text(json.dumps(fixture))
        return vol_root / "jiuzhang-wdsp_gateway-rules" / "_data"

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

    def test_first_time_gateway_rules_migration_seeds_volume_with_labels_and_relative_symlink(self):
        rules_dst = self._setup_rules_upgrade(to_version="1.20.0", old_has_rules_vol=False)
        result = self.run_full()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        events = self.base.events()
        creates = [i for i, e in enumerate(events) if e["kind"] == "volume-create"]
        ups = [i for i, e in enumerate(events) if e["kind"] == "compose" and e["action"] == "up"]
        self.assertEqual(len(creates), 1)
        self.assertLess(creates[0], ups[0])
        self.assertEqual(events[creates[0]]["name"], "jiuzhang-wdsp_gateway-rules")
        self.assertEqual(events[creates[0]]["labels"], {
            "com.docker.compose.project": "jiuzhang-wdsp",
            "com.docker.compose.volume": "gateway-rules",
        })

        self.assertEqual(os.readlink(rules_dst / "current"), "releases/builtin-1.20.0")
        self.assertEqual(stat.S_IMODE(rules_dst.stat().st_mode), 0o750)
        self.assertEqual(stat.S_IMODE((rules_dst / "releases/builtin-1.20.0").stat().st_mode), 0o750)
        self.assertEqual(stat.S_IMODE((rules_dst / "releases/builtin-1.20.0/coraza.conf").stat().st_mode), 0o640)
        self.assertTrue((rules_dst / "coraza.conf").is_file())
        self.assertIn("seed-1.20.0", (rules_dst / "current/coraza.conf").read_text())

    def test_non_downgrade_preserves_customer_dated_rulepack_on_system_upgrade(self):
        rules_dst = self._setup_rules_upgrade(to_version="1.21.0", old_has_rules_vol=True)
        populate_rules_tree(rules_dst / "releases/20261201.1", "customer-0day")
        (rules_dst / "current").symlink_to("releases/20261201.1")
        fixture = json.loads(self.base.fixture_file.read_text())
        fixture["volumes"]["jiuzhang-wdsp_gateway-rules"] = {"mountpoint": str(rules_dst), "labels": {}}
        self.base.fixture_file.write_text(json.dumps(fixture))

        result = self.run_full()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(os.readlink(rules_dst / "current"), "releases/20261201.1")
        self.assertTrue((rules_dst / "releases/builtin-1.21.0/coraza.conf").is_file())
        self.assertIn("customer-0day", (rules_dst / "current/coraza.conf").read_text())

    def test_shell_harness_passes(self):
        harness = Path(__file__).resolve().parent / "rulepack-migration-harness.sh"
        res = subprocess.run(["bash", str(harness)], capture_output=True, text=True, timeout=60)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)


if __name__ == "__main__":
    unittest.main()
