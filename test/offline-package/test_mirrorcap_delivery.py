"""Mirror-mode (mirrorcap) offline package, compose, Dockerfile, and baremetal delivery tests."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
BUILD_SCRIPT = ROOT / "ops/offline-package/build.sh"
PACKAGE_RUNTIME_RUN = ROOT / "ops/offline-package/package-runtime-run.sh"
BUILD_UPDATE_FULL = ROOT / "ops/offline-package/build-update-full.sh"
STAGE5_COMPOSE = ROOT / "deployment/docker-compose.stage5.yml"
MIRRORCAP_DOCKERFILE = ROOT / "gateway/images/mirrorcap/Dockerfile"
BAREMETAL_DIR = ROOT / "ops/baremetal"
BAREMETAL_UNIT = BAREMETAL_DIR / "package/systemd/jiuzhang-mirrorcap.service"
BAREMETAL_ENV = BAREMETAL_DIR / "package/env.template"

EXPECTED_MIRRORCAP_CAPS = sorted(["NET_ADMIN", "NET_RAW", "SETGID", "SETPCAP", "SETUID"])


class MirrorcapDeliveryTests(unittest.TestCase):
    def render_compose(self, compose_path, extra_env=None):
        if not shutil.which("docker"):
            self.skipTest("docker CLI unavailable")
        version = subprocess.run(
            ["docker", "compose", "version"],
            capture_output=True, text=True, timeout=10,
        )
        if version.returncode != 0:
            self.skipTest("docker compose plugin unavailable")
        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", ""),
            "POSTGRES_PASSWORD": "render-test-only",
            "VALKEY_PASSWORD": "render-test-only",
            "JIUZHANG_MASTER_KEY": "render-test-only",
        }
        if os.environ.get("DOCKER_HOST"):
            env["DOCKER_HOST"] = os.environ["DOCKER_HOST"]
        if extra_env:
            env.update(extra_env)
        result = subprocess.run(
            [
                "docker", "compose", "-f", str(compose_path),
                "--env-file", "/dev/null", "config", "--format", "json",
            ],
            cwd=compose_path.parent,
            env=env,
            capture_output=True,
            text=True,
            timeout=45,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(result.stdout)

    def assert_mirrorcap_security_hardening(self, mirrorcap):
        self.assertEqual(mirrorcap.get("user"), "0:0")
        self.assertIs(mirrorcap.get("read_only"), True)
        self.assertEqual(mirrorcap.get("cap_drop"), ["ALL"])
        self.assertEqual(sorted(mirrorcap.get("cap_add") or []), EXPECTED_MIRRORCAP_CAPS)
        self.assertIn("no-new-privileges:true", mirrorcap.get("security_opt") or [])
        self.assertEqual(mirrorcap.get("environment", {}).get("MIRROR_DROP_PRIVS"), "1")
        self.assertTrue(mirrorcap.get("tmpfs"), "mirrorcap should mount tmpfs for read_only root")

    def test_offline_package_manifest_and_rendered_compose_contract(self):
        version = "0.0.0-mirror-test"
        with tempfile.TemporaryDirectory(prefix="wdsp-mirrorcap-pkg-") as tmp:
            work = Path(tmp)
            out_dir = work / "out"
            env = {
                "PATH": os.environ.get("PATH", ""),
                "HOME": os.environ.get("HOME", ""),
                "TMPDIR": str(work),
            }
            result = subprocess.run(
                [
                    "bash", str(BUILD_SCRIPT),
                    "--skip-images", "--development", "--runtime-only",
                    "--version", version,
                    "--product", "wdsp",
                    "--arch", "amd64",
                    "--output", str(out_dir),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=120,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

            archive = out_dir / f"jiuzhang-wdsp-offline-{version}-amd64.tar.gz"
            self.assertTrue(archive.is_file(), f"missing package archive: {archive}")

            unpacked = (work / "unpacked").resolve()
            unpacked.mkdir(parents=True, exist_ok=True)
            with tarfile.open(archive, "r:gz") as tf:
                for member in tf.getmembers():
                    target = (unpacked / member.name).resolve()
                    self.assertTrue(target == unpacked or unpacked in target.parents)
                    self.assertFalse(member.issym() or member.islnk())
                    if hasattr(tarfile, "data_filter"):
                        tf.extract(member, path=unpacked, filter="data")
                    else:
                        tf.extract(member, path=unpacked)

            pkg_root = unpacked / f"jiuzhang-wdsp-offline-{version}-amd64"
            manifest = json.loads((pkg_root / "manifest.json").read_text(encoding="utf-8"))
            images = manifest.get("images") or []
            self.assertEqual(len(images), 15, f"expected 15 images, got {len(images)}: {images}")
            image_refs = [item.get("image") for item in images]
            self.assertIn(f"jiuzhang-mirrorcap:{version}", image_refs)
            for ref in image_refs:
                self.assertNotIn(":latest", ref or "")

            rendered = self.render_compose(pkg_root / "docker-compose.yml")
            services = rendered["services"]
            self.assertIn("mirrorcap", services)
            mirrorcap = services["mirrorcap"]
            self.assertEqual(mirrorcap.get("image"), f"jiuzhang-mirrorcap:{version}")
            self.assertEqual(mirrorcap.get("network_mode"), "host")
            self.assert_mirrorcap_security_hardening(mirrorcap)

            mounts = mirrorcap.get("volumes") or []
            admin_mounts = [m for m in mounts if m.get("target") == "/var/run/caddy"]
            self.assertEqual(len(admin_mounts), 1, mounts)
            self.assertEqual(admin_mounts[0].get("type"), "volume")
            self.assertEqual(admin_mounts[0].get("source"), "gateway-admin")
            self.assertIs(admin_mounts[0].get("read_only"), True)

            log_mounts = [m for m in mounts if m.get("target") == "/var/log/caddy"]
            self.assertEqual(len(log_mounts), 1, mounts)
            self.assertEqual(log_mounts[0].get("type"), "volume")
            self.assertEqual(log_mounts[0].get("source"), "gateway-logs")
            self.assertNotEqual(log_mounts[0].get("read_only"), True)

            rules_mounts = [m for m in mounts if m.get("target") == "/etc/caddy/rules"]
            self.assertEqual(len(rules_mounts), 1, mounts)
            self.assertEqual(rules_mounts[0].get("type"), "bind")
            self.assertEqual(
                Path(rules_mounts[0]["source"]).resolve(),
                (pkg_root / "gateway/rules").resolve(),
            )
            self.assertIs(rules_mounts[0].get("read_only"), True)

            allowed_services = (
                services["containerops"]
                .get("environment", {})
                .get("CONTAINEROPS_ALLOWED_SERVICES", "")
            )
            self.assertIn("mirrorcap", [s.strip() for s in allowed_services.split(",")])

            api_env = services["api"].get("environment", {})
            self.assertEqual(api_env.get("GATEWAY_AUDIT_LOG"), "/var/log/caddy/coraza-audit.log")
            self.assertEqual(
                api_env.get("GATEWAY_SITE_DISCOVERY_LOG"),
                "/var/log/caddy/site-discovery.jsonl",
            )

    def test_mirrorcap_dockerfile_hardening_and_healthcheck(self):
        dockerfile = MIRRORCAP_DOCKERFILE.read_text(encoding="utf-8")
        self.assertNotIn(":latest", dockerfile)
        self.assertRegex(dockerfile, r"ARG\s+GOLANG_IMAGE_DIGEST=sha256:[0-9a-f]{64}")
        self.assertRegex(dockerfile, r"ARG\s+ALPINE_IMAGE_DIGEST=sha256:[0-9a-f]{64}")
        self.assertIn("${GOLANG_IMAGE_DIGEST:+@$GOLANG_IMAGE_DIGEST}", dockerfile)
        self.assertIn("${ALPINE_IMAGE_DIGEST:+@$ALPINE_IMAGE_DIGEST}", dockerfile)
        self.assertRegex(dockerfile, r"apk\s+add\s+--no-cache\b[^\n]*\bethtool\b")
        self.assertRegex(dockerfile, r"(?m)^ENV\s+MIRROR_DROP_PRIVS=1\s*$")
        self.assertRegex(
            dockerfile,
            r'HEALTHCHECK\b[\s\S]*?CMD\s*\[\s*"/usr/local/bin/mirrorcap"\s*,\s*"--healthcheck"\s*\]',
        )

    def test_stage5_compose_renders_mirrorcap_with_gateway_netns_and_hardening(self):
        rendered = self.render_compose(STAGE5_COMPOSE)
        services = rendered["services"]
        self.assertIn("mirrorcap", services)
        mirrorcap = services["mirrorcap"]
        self.assertEqual(mirrorcap.get("network_mode"), "service:gateway")
        self.assert_mirrorcap_security_hardening(mirrorcap)

        mounts = mirrorcap.get("volumes") or []
        admin_mounts = [m for m in mounts if m.get("target") == "/var/run/caddy"]
        self.assertEqual(len(admin_mounts), 1, mounts)
        self.assertEqual(admin_mounts[0].get("source"), "stage5-gateway-admin")
        self.assertIs(admin_mounts[0].get("read_only"), True)

        log_mounts = [m for m in mounts if m.get("target") == "/var/log/caddy"]
        self.assertEqual(len(log_mounts), 1, mounts)
        self.assertEqual(log_mounts[0].get("source"), "stage5-gateway-logs")
        self.assertNotEqual(log_mounts[0].get("read_only"), True)

        rules_mounts = [m for m in mounts if m.get("target") == "/etc/caddy/rules"]
        self.assertEqual(len(rules_mounts), 1, mounts)
        self.assertEqual(
            Path(rules_mounts[0]["source"]).resolve(),
            (ROOT / "gateway/rules").resolve(),
        )
        self.assertIs(rules_mounts[0].get("read_only"), True)

        allowed_services = (
            services["containerops"]
            .get("environment", {})
            .get("CONTAINEROPS_ALLOWED_SERVICES", "")
        )
        self.assertIn("mirrorcap", [s.strip() for s in allowed_services.split(",")])

        api_env = services["api"].get("environment", {})
        self.assertEqual(api_env.get("GATEWAY_AUDIT_LOG"), "/var/log/caddy/coraza-audit.log")
        self.assertEqual(
            api_env.get("GATEWAY_SITE_DISCOVERY_LOG"),
            "/var/log/caddy/site-discovery.jsonl",
        )

    def test_package_runtime_run_dry_run_includes_mirrorcap_image(self):
        with tempfile.TemporaryDirectory(prefix="wdsp-mirrorcap-run-") as tmp:
            work = Path(tmp)
            rpm_dir = work / "openeuler-rpms"
            rpm_dir.mkdir()
            (rpm_dir / "docker-compose-plugin-2.29.7-1.x86_64.rpm").touch()
            output = work / "out"
            env = dict(os.environ)
            env.pop("WDSP_SIGNING_KEY", None)
            result = subprocess.run(
                [
                    "bash", str(PACKAGE_RUNTIME_RUN),
                    "--dry-run",
                    "--version", "9.9.9",
                    "--output", str(output),
                    "--rpm-dir", str(rpm_dir),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("jiuzhang-mirrorcap:9.9.9", result.stdout)
            self.assertIn("gateway/images/mirrorcap/Dockerfile", result.stdout)
            self.assertFalse(output.exists())

        update_full_src = BUILD_UPDATE_FULL.read_text(encoding="utf-8")
        self.assertIn("jiuzhang-mirrorcap", update_full_src)
        self.assertIn("gateway/images/mirrorcap/Dockerfile", update_full_src)

    def test_baremetal_delivery_unit_env_and_lifecycle_scripts(self):
        unit = BAREMETAL_UNIT.read_text(encoding="utf-8")
        self.assertRegex(unit, r"(?m)^User=__USER__\s*$")
        self.assertRegex(unit, r"(?m)^Group=__USER__\s*$")
        self.assertNotIn("User=root", unit)
        self.assertRegex(unit, r"(?m)^AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN\s*$")
        self.assertRegex(unit, r"(?m)^NoNewPrivileges=yes\s*$")
        self.assertRegex(unit, r"(?m)^ProtectSystem=strict\s*$")

        env_template = BAREMETAL_ENV.read_text(encoding="utf-8")
        for key in (
            "MIRROR_CONFIG_FILE",
            "MIRROR_RULES_DIR",
            "GATEWAY_AUDIT_LOG",
            "GATEWAY_SITE_DISCOVERY_LOG",
        ):
            self.assertRegex(env_template, rf"(?m)^{re.escape(key)}=.+")

        build_binaries = (BAREMETAL_DIR / "build-binaries.sh").read_text(encoding="utf-8")
        self.assertIn("mirrorcap", build_binaries)
        self.assertIn("./cmd/mirrorcap", build_binaries)

        assemble = (BAREMETAL_DIR / "assemble.sh").read_text(encoding="utf-8")
        self.assertIn("mirrorcap", assemble)

        for script_rel in (
            "package/install.sh",
            "package/restore.sh",
            "package/uninstall.sh",
        ):
            script_text = (BAREMETAL_DIR / script_rel).read_text(encoding="utf-8")
            self.assertIn("jiuzhang-mirrorcap", script_text, script_rel)

        for script_path in (
            BAREMETAL_DIR / "build-binaries.sh",
            BAREMETAL_DIR / "assemble.sh",
            BAREMETAL_DIR / "package/install.sh",
            BAREMETAL_DIR / "package/restore.sh",
            BAREMETAL_DIR / "package/uninstall.sh",
            BUILD_SCRIPT,
            PACKAGE_RUNTIME_RUN,
            BUILD_UPDATE_FULL,
        ):
            res = subprocess.run(
                ["bash", "-n", str(script_path)],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(res.returncode, 0, f"bash -n failed for {script_path}: {res.stderr}")


if __name__ == "__main__":
    unittest.main()
