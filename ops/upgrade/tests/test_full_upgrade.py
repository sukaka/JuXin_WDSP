"""完整升级的组件、备份与数据库回滚契约；夹具不代表目标 Linux 实测。"""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
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

    def _setup_cross_volume_upgrade_fixture(self, include_certs=True):
        old_cfg = json.loads(self.base.old_compose.read_text())
        new_cfg = json.loads(self.base.new_compose.read_text())
        old_cfg["name"] = "jiuzhang-wdsp"
        new_cfg["name"] = "jiuzhang-wdsp"
        old_cfg["services"]["api"]["volumes"] = [
            {"type": "volume", "source": "runtime-data", "target": "/app/runtime"},
            {"type": "volume", "source": "gateway-admin", "target": "/var/run/caddy"},
        ]
        old_cfg["services"]["gateway"]["volumes"] = [
            {"type": "volume", "source": "gateway-admin", "target": "/var/run/caddy"},
            {"type": "volume", "source": "gateway-config", "target": "/config"},
        ]
        old_cfg["volumes"] = {
            "runtime-data": {"name": "jiuzhang-wdsp_runtime-data"},
            "gateway-admin": {"name": "jiuzhang-wdsp_gateway-admin"},
            "gateway-config": {"name": "jiuzhang-wdsp_gateway-config"},
        }
        new_cfg["services"]["api"]["volumes"] = [
            {"type": "volume", "source": "runtime-data", "target": "/app/runtime"},
            {"type": "volume", "source": "gateway-certs", "target": "/app/runtime/certificates"},
            {"type": "volume", "source": "gateway-admin", "target": "/var/run/caddy"},
        ]
        new_cfg["services"]["gateway"]["volumes"] = [
            {"type": "volume", "source": "gateway-admin", "target": "/var/run/caddy"},
            {"type": "volume", "source": "gateway-config", "target": "/config"},
            {"type": "volume", "source": "gateway-certs", "target": "/etc/caddy/certs", "read_only": True},
        ]
        new_cfg["services"]["netmgrd"].update({
            "cap_drop": ["ALL"],
            "cap_add": ["NET_RAW", "NET_ADMIN"],
            "group_add": ["1000"],
            "volumes": [{"type": "volume", "source": "gateway-admin", "target": "/var/run/caddy"}],
        })
        new_cfg["volumes"] = {
            "runtime-data": {"name": "jiuzhang-wdsp_runtime-data"},
            "gateway-admin": {"name": "jiuzhang-wdsp_gateway-admin"},
            "gateway-config": {"name": "jiuzhang-wdsp_gateway-config"},
            "gateway-certs": {"name": "jiuzhang-wdsp_gateway-certs"},
        }
        self.base.old_compose.write_text(json.dumps(old_cfg))
        self.base.new_compose.write_text(json.dumps(new_cfg))

        vol_root = self.work / "volumes"
        rt_dir = vol_root / "jiuzhang-wdsp_runtime-data" / "_data"
        cert_src = rt_dir / "certificates"
        cert_src.mkdir(parents=True)
        if include_certs:
            (cert_src / "cert-a.pem").write_text("-----BEGIN CERTIFICATE-----\nFIXTURE-A\n-----END CERTIFICATE-----\n")
            (cert_src / "cert-a.key").write_text("-----BEGIN PRIVATE KEY-----\nFIXTURE-KEY-A\n-----END PRIVATE KEY-----\n")
            (cert_src / "cert-a.pem").chmod(0o600)
            (cert_src / "cert-a.key").chmod(0o600)

        cfg_dir = vol_root / "jiuzhang-wdsp_gateway-config" / "_data"
        (cfg_dir / "caddy").mkdir(parents=True)
        (cfg_dir / "caddy" / "autosave.json").write_text(json.dumps({
            "apps": {
                "tls": {
                    "certificates": {
                        "load_files": [
                            {
                                "certificate": "/etc/caddy/certs/cert-a.pem",
                                "key": "/etc/caddy/certs/cert-a.key",
                                "tags": ["cert-a"],
                            }
                        ]
                    }
                }
            }
        }))

        admin_dir = vol_root / "jiuzhang-wdsp_gateway-admin" / "_data"
        sidecars_dir = admin_dir / "sidecars"
        diag_dir = sidecars_dir / "diag"
        diag_dir.mkdir(parents=True)
        cap_file = sidecars_dir / "capability.json"
        cap_file.write_text('{"ok":true}\n')
        cap_file.chmod(0o600)
        req_file = diag_dir / "request-11111111-1111-4111-8111-111111111111.json"
        req_file.write_text('{"version":1}\n')
        req_file.chmod(0o600)
        stop_file = diag_dir / "stop-11111111-1111-4111-8111-111111111111"
        stop_file.write_text("")
        stop_file.chmod(0o600)
        diag_dir.chmod(0o750)
        sidecars_dir.chmod(0o750)
        admin_dir.chmod(0o755)

        fixture = json.loads(self.base.fixture_file.read_text())
        fixture["volume_root"] = str(vol_root)
        fixture["volumes"] = {
            "jiuzhang-wdsp_runtime-data": {"mountpoint": str(rt_dir), "labels": {}},
            "jiuzhang-wdsp_gateway-config": {"mountpoint": str(cfg_dir), "labels": {}},
            "jiuzhang-wdsp_gateway-admin": {"mountpoint": str(admin_dir), "labels": {}},
        }
        fixture["running"] = {
            "api": {
                "id": "1" * 64,
                "image": "fixture-server:old-stable",
                "image_id": "sha256:server-old",
                "mounts": [
                    {"Destination": "/app/runtime", "Source": str(rt_dir)},
                    {"Destination": "/var/run/caddy", "Source": str(admin_dir)},
                ],
            },
            "gateway": {
                "id": "2" * 64,
                "image": "fixture-gateway:old-stable",
                "image_id": "sha256:gateway-old",
                "mounts": [
                    {"Destination": "/config", "Source": str(cfg_dir)},
                    {"Destination": "/var/run/caddy", "Source": str(admin_dir)},
                ],
            },
        }
        self.base.fixture_file.write_text(json.dumps(fixture))
        return {
            "vol_root": vol_root,
            "cert_src": cert_src,
            "cert_dst": vol_root / "jiuzhang-wdsp_gateway-certs" / "_data",
            "admin_dir": admin_dir,
            "sidecars_dir": sidecars_dir,
            "diag_dir": diag_dir,
            "cap_file": cap_file,
            "req_file": req_file,
            "stop_file": stop_file,
        }

    def test_legacy_to_gateway_certs_upgrade_migrates_certs_and_reconciles_sidecars(self):
        paths = self._setup_cross_volume_upgrade_fixture(include_certs=True)
        result = self.run_full()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        events = self.base.events()
        vol_creates = [i for i, e in enumerate(events) if e["kind"] == "volume-create"]
        compose_ups = [i for i, e in enumerate(events) if e["kind"] == "compose" and e["action"] == "up"]
        self.assertEqual(len(vol_creates), 1)
        self.assertLess(vol_creates[0], compose_ups[0])
        created = events[vol_creates[0]]
        self.assertEqual(created["name"], "jiuzhang-wdsp_gateway-certs")
        self.assertEqual(created["labels"], {
            "com.docker.compose.project": "jiuzhang-wdsp",
            "com.docker.compose.volume": "gateway-certs",
        })

        # 证书卷目录与迁移文件权限及内容均正确，且旧卷原文件保持不变以支持回滚
        dst = paths["cert_dst"]
        self.assertEqual(stat.S_IMODE(dst.stat().st_mode), 0o700)
        for name in ("cert-a.pem", "cert-a.key"):
            self.assertEqual((dst / name).read_bytes(), (paths["cert_src"] / name).read_bytes())
            self.assertEqual(stat.S_IMODE((dst / name).stat().st_mode), 0o600)
            self.assertTrue((paths["cert_src"] / name).is_file())

        # sidecars 与 sidecars/diag 已对齐 0770，待消费 diag 文件 0640，capability.json 仍 0600
        self.assertEqual(stat.S_IMODE(paths["sidecars_dir"].stat().st_mode), 0o770)
        self.assertEqual(stat.S_IMODE(paths["diag_dir"].stat().st_mode), 0o770)
        self.assertEqual(stat.S_IMODE(paths["req_file"].stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE(paths["stop_file"].stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE(paths["cap_file"].stat().st_mode), 0o600)

    def test_gateway_certs_migration_fails_closed_before_switch_when_autosave_cert_missing(self):
        self._setup_cross_volume_upgrade_fixture(include_certs=False)
        result = self.run_full()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("缺少当前网关配置引用的证书文件: cert-a", result.stderr)
        self.assertFalse(self.base.state.exists())
        self.assertFalse([e for e in self.base.events() if e["kind"] == "compose" and e["action"] in ("rm", "up")])

    def test_gateway_certs_migration_is_idempotent_and_rejects_conflicting_existing_file(self):
        paths = self._setup_cross_volume_upgrade_fixture(include_certs=True)
        dst = paths["cert_dst"]
        dst.mkdir(parents=True)
        (dst / "cert-a.pem").write_bytes((paths["cert_src"] / "cert-a.pem").read_bytes())
        (dst / "cert-a.key").write_bytes((paths["cert_src"] / "cert-a.key").read_bytes())
        (dst / "cert-a.pem").chmod(0o644)
        (dst / "cert-a.key").chmod(0o600)

        fixture = json.loads(self.base.fixture_file.read_text())
        fixture["volumes"]["jiuzhang-wdsp_gateway-certs"] = {"mountpoint": str(dst), "labels": {}}
        self.base.fixture_file.write_text(json.dumps(fixture))

        # 已存在完全一致文件时幂等通过，不重复创建卷
        result = self.run_full()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse([e for e in self.base.events() if e["kind"] == "volume-create"])

        # 若已存在同名但内容不同的文件，切换前直接 fail-closed，且保留现场文件不被覆盖
        self.base.state.unlink(missing_ok=True)
        self.base.docker_log.unlink(missing_ok=True)
        (dst / "cert-a.pem").write_text("-----BEGIN CERTIFICATE-----\nCONFLICTING\n-----END CERTIFICATE-----\n")
        fixture = json.loads(self.base.fixture_file.read_text())
        fixture["running"] = {
            "api": {
                "id": "1" * 64,
                "image": "fixture-server:old-stable",
                "image_id": "sha256:server-old",
                "mounts": [{"Destination": "/app/runtime", "Source": str(paths["cert_src"].parent)}],
            },
            "gateway": {
                "id": "2" * 64,
                "image": "fixture-gateway:old-stable",
                "image_id": "sha256:gateway-old",
                "mounts": [{"Destination": "/config", "Source": str(paths["vol_root"] / "jiuzhang-wdsp_gateway-config" / "_data")}],
            },
        }
        self.base.fixture_file.write_text(json.dumps(fixture))
        result2 = self.run_full()
        self.assertNotEqual(result2.returncode, 0)
        self.assertIn("内容不同的文件: cert-a.pem", result2.stderr)
        self.assertIn("CONFLICTING", (dst / "cert-a.pem").read_text())
        self.assertFalse(self.base.state.exists())
        self.assertFalse([e for e in self.base.events() if e["kind"] == "compose" and e["action"] in ("rm", "up")])

    def _setup_api_extra_networks_fixture(self, api_nets, ch_nets, all_networks):
        for path in (self.base.old_compose, self.base.new_compose):
            cfg = json.loads(path.read_text())
            cfg["name"] = "jiuzhang-wdsp"
            cfg["networks"] = {"jiuzhang-internal": {"name": "jiuzhang-wdsp_jiuzhang-internal"}}
            cfg["services"]["api"]["networks"] = {"jiuzhang-internal": None}
            path.write_text(json.dumps(cfg))
        fixture = json.loads(self.base.fixture_file.read_text())
        fixture["networks"] = list(all_networks)
        fixture["running"] = {
            "api": {
                "id": "1" * 64,
                "image": "fixture-server:old-stable",
                "image_id": "sha256:server-old",
                "networks": list(api_nets),
            },
        }
        fixture["extra_containers"] = {
            "jiuzhang-apm-clickhouse": {
                "name": "/jiuzhang-apm-clickhouse",
                "running": True,
                "networks": list(ch_nets),
            },
        }
        self.base.fixture_file.write_text(json.dumps(fixture))

    def test_full_upgrade_preserves_api_extra_networks_and_auto_attaches_clickhouse(self):
        # 模拟旧 api 仅有手工接入的 Kafka 网、却在历史升级中丢失了 ClickHouse 网，同时同机 ClickHouse 正在运行
        self._setup_api_extra_networks_fixture(
            api_nets=["jiuzhang-wdsp_jiuzhang-internal", "jiuzhang-kafka_default"],
            ch_nets=["jiuzhang-apm_apm-data"],
            all_networks=["jiuzhang-wdsp_jiuzhang-internal", "jiuzhang-kafka_default", "jiuzhang-apm_apm-data"],
        )
        result = self.run_full()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        events = self.base.events()
        up_index = next(i for i, e in enumerate(events) if e["kind"] == "compose" and e["action"] == "up")
        connects = [(i, e["network"]) for i, e in enumerate(events) if e["kind"] == "network-connect"]
        self.assertEqual([net for _, net in connects], ["jiuzhang-apm_apm-data", "jiuzhang-kafka_default"])
        self.assertTrue(all(idx > up_index for idx, _ in connects))

        fixture = json.loads(self.base.fixture_file.read_text())
        self.assertEqual(
            set(fixture["running"]["api"]["networks"]),
            {"jiuzhang-wdsp_jiuzhang-internal", "jiuzhang-apm_apm-data", "jiuzhang-kafka_default"},
        )
        # 升级后健康检查携带 --strict-clickhouse-network
        health_lines = self.base.health_log.read_text().splitlines()
        self.assertEqual(len(health_lines), 2)
        self.assertNotIn("--strict-clickhouse-network", health_lines[0])
        self.assertIn("--strict-clickhouse-network", health_lines[1])

    def test_full_upgrade_network_reattach_failure_rolls_back_and_restores_networks(self):
        self.base.write_executable(
            self.base.work / "ops/upgrade/install-executor.sh",
            '#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "$HOSTCTL_HELPER_LOG"\n',
        )
        self._setup_api_extra_networks_fixture(
            api_nets=["jiuzhang-wdsp_jiuzhang-internal", "jiuzhang-apm_apm-data"],
            ch_nets=["jiuzhang-apm_apm-data"],
            all_networks=["jiuzhang-wdsp_jiuzhang-internal", "jiuzhang-apm_apm-data"],
        )
        fixture = json.loads(self.base.fixture_file.read_text())
        fixture["fail_network_connect_once"] = True
        self.base.fixture_file.write_text(json.dumps(fixture))

        result = self.run_full()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("恢复 api 附加网络失败", result.stderr)
        self.assertIn("自动回滚完成", result.stderr)

        # 回滚后旧 api 镜像已恢复，且 jiuzhang-apm_apm-data 网络已重新接入
        fixture = json.loads(self.base.fixture_file.read_text())
        self.assertEqual(fixture["running"]["api"]["image_id"], "sha256:server-old")
        self.assertIn("jiuzhang-apm_apm-data", fixture["running"]["api"]["networks"])


class FullUpgradeWrapperTests(unittest.TestCase):
    def setUp(self):
        self.base = gateway_contract.GatewayRuntimeContractTests("test_apply_dual_compose_uses_old_ids_and_target_runtime")
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.work = self.base.work
        self.current = self.work / "current"
        self.current.symlink_to(self.work, target_is_directory=True)
        self.runtime_file = self.work / "runtime" / "retained"
        self.runtime_file.parent.mkdir()
        self.runtime_file.write_text("original runtime data")
        (self.work / "manifest.json").write_text('{"version":"1.8.1"}')
        self.target = self.work / "jiuzhang-wdsp-offline-1.10.1-amd64"

    def run_after_package_preflight(self, stdin=None):
        package = self.work / "fixture.tar.gz"
        common = self.work / "ops/lib/common.sh"
        files = {
            "ops/lib/common.sh": common,
            "ops/upgrade/apply.sh": self.base.apply,
            "ops/upgrade/rollback.sh": self.base.rollback,
            "ops/healthcheck/check.sh": self.work / "ops/healthcheck/check.sh",
        }
        manifest = self.work / "target-manifest.json"
        manifest.write_text(json.dumps({"files": [
            {"path": name, "size": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            for name, path in files.items()
        ]}))
        with tarfile.open(package, "w:gz") as archive:
            archive.add(manifest, arcname=f"{self.target.name}/manifest.json")
            for name, path in files.items():
                archive.add(path, arcname=f"{self.target.name}/{name}")

        source = (gateway_contract.ROOT / "ops/upgrade/update-full.sh").read_text()
        script = self.work / "wrapper-after-preflight.sh"
        script.write_text('''set -euo pipefail
source "$1"
PACKAGE="$2" PARENT="$PWD" CURRENT_RELEASE="$PWD" CURRENT_LINK="$PWD/current"
OLD_MANIFEST="$PWD/manifest.json" OLD_COMPOSE="$3" OLD_ENV="$4"
PACKAGE_INFO='{"size":4096}' VERSION=1.10.1 ARCH=amd64
HOST_STATE_DIR="$PWD/host-state" PACKAGE_SHA=fixture
mkdir -p "$HOST_STATE_DIR"
API_URL=http://127.0.0.1:18081 TIMEOUT=2 USER=fixture-admin
''' + source[source.index('NEW_RELEASE="$PARENT/'):])
        return self.base.run_script(script, common, package, self.base.old_compose, self.base.env_file, stdin=stdin)

    def test_five_attempts_then_resume_at_password(self):
        curl = self.base.bin / "curl"
        curl.write_text("""#!/usr/bin/env bash
printf 'login\n' >> "$TMPDIR/requests"
printf '%s\n' '{"code":"UNAUTHENTICATED","message":"用户名或密码错误"}'
""")
        first = self.run_after_package_preflight(stdin="wrong\n" * 6)
        self.assertNotEqual(first.returncode, 0)
        requests = self.base.tmpdir / "requests"
        self.assertEqual(requests.read_text().splitlines(), ["login"] * 5)
        self.assertTrue(self.target.is_dir())
        original = curl.read_text()
        curl.write_text("""#!/usr/bin/env bash
case "${!#}" in
  */login) echo '{"code":"SUCCESS","data":{"csrf_token":"fixture"}}' ;;
  */backups) echo '{"code":"DENIED","message":"backup test boundary"}' ;;
esac
""")
        second = self.run_after_package_preflight(stdin="correct\n")
        self.assertIn("backup test boundary", second.stderr)
        self.assertNotIn("安全解压", second.stdout + second.stderr)
        self.assertNotIn("步骤 1/5", second.stdout + second.stderr)
        self.assertFalse(self.target.exists())
        curl.write_text(original)
        self.run_after_package_preflight(stdin="wrong\n" * 5)
        (self.target / "ops/upgrade/apply.sh").write_text("exit 97")
        third = self.run_after_package_preflight(stdin="correct\n")
        self.assertIn("断点", third.stderr)
        self.assertNotEqual(third.returncode, 97)
        self.assertTrue(self.target.exists())
        self.assertEqual(self.runtime_file.read_text(), "original runtime data")

    def test_second_password_can_succeed_in_same_run(self):
        (self.base.bin / "curl").write_text("""#!/usr/bin/env bash
case "${!#}" in
  */login)
    echo attempt >> "$TMPDIR/requests"
    if jq -e '.password == "fixture-correct"' >/dev/null; then
      echo '{"code":"SUCCESS","data":{"csrf_token":"fixture"}}'
    else
      echo '{"code":"UNAUTHENTICATED"}'
    fi ;;
  */backups) echo '{"code":"DENIED","message":"backup test boundary"}' ;;
esac
""")
        result = self.run_after_package_preflight(stdin="fixture-wrong\nfixture-correct\n")
        self.assertIn("backup test boundary", result.stderr)
        self.assertEqual((self.base.tmpdir / "requests").read_text().splitlines(), ["attempt"] * 2)
        self.assertNotIn("fixture-correct", result.stdout + result.stderr)

    def test_locked_account_stops_immediately(self):
        (self.base.bin / "curl").write_text("""#!/usr/bin/env bash
echo attempt >> "$TMPDIR/requests"
echo '{"code":"ACCOUNT_LOCKED","message":"fixture locked"}'
""")
        result = self.run_after_package_preflight(stdin="wrong\n" * 5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("fixture locked", result.stderr)
        self.assertEqual((self.base.tmpdir / "requests").read_text().splitlines(), ["attempt"])
        self.assertTrue(self.target.is_dir())

    def test_archived_rollback_state_and_existing_release_are_preserved(self):
        self.base.write_executable(
            self.base.apply,
            '#!/usr/bin/env bash\ntouch "$(dirname "$0")/.upgrade-state.env.rolled-back.fixture"\nexit 42\n',
        )
        result = self.run_after_package_preflight()
        self.assertEqual(result.returncode, 42, result.stdout + result.stderr)
        marker = self.target / "ops/upgrade/.upgrade-state.env.rolled-back.fixture"
        self.assertTrue(marker.is_file())
        result = self.run_after_package_preflight()
        self.assertIn("目标 release 已存在", result.stderr)
        self.assertTrue(marker.is_file())


if __name__ == "__main__":
    unittest.main()
