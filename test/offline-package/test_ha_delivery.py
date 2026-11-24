"""HA (havipd / hasyncd) offline package, Stage5 compose, Dockerfile, and baremetal delivery tests."""
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
NETMGRD_DOCKERFILE = ROOT / "gateway/images/netmgrd/Dockerfile"
HAVIPD_DOCKERFILE = ROOT / "gateway/images/havipd/Dockerfile"
HASYNCD_DOCKERFILE = ROOT / "gateway/images/hasyncd/Dockerfile"
BAREMETAL_DIR = ROOT / "ops/baremetal"
HAVIPD_UNIT = BAREMETAL_DIR / "package/systemd/jiuzhang-havipd.service"
HASYNCD_UNIT = BAREMETAL_DIR / "package/systemd/jiuzhang-hasyncd.service"
BAREMETAL_ENV = BAREMETAL_DIR / "package/env.template"

EXPECTED_HAVIPD_CAPS = sorted(["NET_ADMIN", "NET_RAW", "NET_BROADCAST"])


class HaDeliveryTests(unittest.TestCase):
    def render_compose(self, compose_path, profiles=()):
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
        cmd = ["docker", "compose", "-f", str(compose_path)]
        for profile in profiles:
            cmd.extend(["--profile", profile])
        cmd.extend(["--env-file", "/dev/null", "config", "--format", "json"])
        result = subprocess.run(
            cmd,
            cwd=compose_path.parent,
            env=env,
            capture_output=True,
            text=True,
            timeout=45,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(result.stdout)

    def assert_havipd_hardening(self, havipd):
        self.assertEqual(havipd.get("network_mode"), "service:gateway")
        self.assertIn("1000", [str(g) for g in (havipd.get("group_add") or [])])
        self.assertIs(havipd.get("read_only"), True)
        self.assertEqual(havipd.get("cap_drop"), ["ALL"])
        self.assertEqual(sorted(havipd.get("cap_add") or []), EXPECTED_HAVIPD_CAPS)
        self.assertIn("no-new-privileges:true", havipd.get("security_opt") or [])
        self.assertIn("/tmp:size=8m,mode=1777", havipd.get("tmpfs") or [])

    def assert_hasyncd_hardening(self, hasyncd):
        self.assertEqual(hasyncd.get("user"), "1000:1000")
        self.assertIs(hasyncd.get("read_only"), True)
        self.assertEqual(hasyncd.get("cap_drop"), ["ALL"])
        self.assertEqual(hasyncd.get("cap_add") or [], [])
        self.assertIn("no-new-privileges:true", hasyncd.get("security_opt") or [])
        self.assertIn("/tmp:size=8m,mode=1777", hasyncd.get("tmpfs") or [])
        for vol in hasyncd.get("volumes") or []:
            self.assertNotIn("docker.sock", str(vol.get("source") or ""))

    def test_havipd_and_hasyncd_dockerfiles_lock_digests_and_hardening(self):
        netmgrd_df = NETMGRD_DOCKERFILE.read_text(encoding="utf-8")
        go_digest = re.search(r"ARG\s+GOLANG_IMAGE_DIGEST=(sha256:[0-9a-f]{64})", netmgrd_df)
        alpine_digest = re.search(r"ARG\s+ALPINE_IMAGE_DIGEST=(sha256:[0-9a-f]{64})", netmgrd_df)
        self.assertIsNotNone(go_digest)
        self.assertIsNotNone(alpine_digest)

        havipd_df = HAVIPD_DOCKERFILE.read_text(encoding="utf-8")
        self.assertNotIn(":latest", havipd_df)
        self.assertIn(f"ARG GOLANG_IMAGE_DIGEST={go_digest.group(1)}", havipd_df)
        self.assertIn(f"ARG ALPINE_IMAGE_DIGEST={alpine_digest.group(1)}", havipd_df)
        self.assertIn("CGO_ENABLED=0 GOAMD64=v1 GOOS=$TARGETOS GOARCH=$TARGETARCH", havipd_df)
        self.assertIn("-o /havipd ./cmd/havipd", havipd_df)
        self.assertRegex(havipd_df, r"apk\s+add\s+--no-cache\b[^\n]*\bkeepalived\b[^\n]*\biproute2\b")
        self.assertRegex(
            havipd_df,
            r'HEALTHCHECK\b[\s\S]*?CMD\s*\[\s*"/usr/local/bin/havipd"\s*,\s*"--healthcheck"\s*\]',
        )
        self.assertRegex(havipd_df, r'(?m)^ENTRYPOINT\s*\[\s*"/usr/local/bin/havipd"\s*\]\s*$')

        hasyncd_df = HASYNCD_DOCKERFILE.read_text(encoding="utf-8")
        self.assertNotIn(":latest", hasyncd_df)
        self.assertIn(f"ARG GOLANG_IMAGE_DIGEST={go_digest.group(1)}", hasyncd_df)
        self.assertIn(f"ARG ALPINE_IMAGE_DIGEST={alpine_digest.group(1)}", hasyncd_df)
        self.assertIn("CGO_ENABLED=0 GOAMD64=v1 GOOS=$TARGETOS GOARCH=$TARGETARCH", hasyncd_df)
        self.assertIn("-o /hasyncd ./cmd/hasyncd", hasyncd_df)
        self.assertRegex(hasyncd_df, r"addgroup\s+-g\s+1000\s+-S\s+jiuzhang")
        self.assertRegex(hasyncd_df, r"adduser\s+-u\s+1000\s+-S\s+-G\s+jiuzhang")
        self.assertRegex(hasyncd_df, r"(?m)^USER\s+1000:1000\s*$")
        self.assertRegex(
            hasyncd_df,
            r'HEALTHCHECK\b[\s\S]*?CMD\s*\[\s*"/usr/local/bin/hasyncd"\s*,\s*"--healthcheck"\s*\]',
        )
        self.assertRegex(hasyncd_df, r'(?m)^ENTRYPOINT\s*\[\s*"/usr/local/bin/hasyncd"\s*\]\s*$')

    def test_stage5_compose_renders_havipd_and_profiled_hasyncd(self):
        default_rendered = self.render_compose(STAGE5_COMPOSE)
        default_services = default_rendered["services"]
        self.assertIn("havipd", default_services)
        self.assertNotIn("hasyncd", default_services)
        self.assert_havipd_hardening(default_services["havipd"])

        allowed = [
            s.strip()
            for s in default_services["containerops"]
            .get("environment", {})
            .get("CONTAINEROPS_ALLOWED_SERVICES", "")
            .split(",")
        ]
        self.assertIn("havipd", allowed)
        self.assertIn("hasyncd", allowed)

        profiled = self.render_compose(STAGE5_COMPOSE, profiles=("ha-sync",))
        self.assertIn("hasyncd", profiled["services"])
        self.assert_hasyncd_hardening(profiled["services"]["hasyncd"])

    def test_offline_package_manifest_and_rendered_compose_ha_contract(self):
        version = "0.0.0-ha-test"
        with tempfile.TemporaryDirectory(prefix="wdsp-ha-pkg-") as tmp:
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
            unpacked = (work / "unpacked").resolve()
            unpacked.mkdir(parents=True, exist_ok=True)
            with tarfile.open(archive, "r:gz") as tf:
                if hasattr(tarfile, "data_filter"):
                    tf.extractall(path=unpacked, filter="data")
                else:
                    tf.extractall(path=unpacked)

            pkg_root = unpacked / f"jiuzhang-wdsp-offline-{version}-amd64"
            manifest = json.loads((pkg_root / "manifest.json").read_text(encoding="utf-8"))
            images = manifest.get("images") or []
            self.assertEqual(len(images), 15)
            image_refs = [item.get("image") for item in images]
            self.assertIn(f"jiuzhang-havipd:{version}", image_refs)
            self.assertIn(f"jiuzhang-hasyncd:{version}", image_refs)
            for ref in image_refs:
                self.assertNotIn(":latest", ref or "")

            rendered = self.render_compose(pkg_root / "docker-compose.yml")
            services = rendered["services"]
            self.assertIn("havipd", services)
            self.assertNotIn("hasyncd", services)
            self.assertEqual(services["havipd"].get("image"), f"jiuzhang-havipd:{version}")
            self.assert_havipd_hardening(services["havipd"])
            allowed = [
                s.strip()
                for s in services["containerops"]
                .get("environment", {})
                .get("CONTAINEROPS_ALLOWED_SERVICES", "")
                .split(",")
            ]
            self.assertIn("havipd", allowed)
            self.assertIn("hasyncd", allowed)

            profiled = self.render_compose(pkg_root / "docker-compose.yml", profiles=("ha-sync",))
            hasyncd = profiled["services"]["hasyncd"]
            self.assertEqual(hasyncd.get("image"), f"jiuzhang-hasyncd:{version}")
            self.assert_hasyncd_hardening(hasyncd)
            self.assertEqual(hasyncd.get("environment", {}).get("APP_VERSION"), version)
            self.assertEqual(
                hasyncd.get("environment", {}).get("UPGRADE_PACKAGES_DIR"),
                "/app/runtime/upgrade-packages",
            )
            self.assertEqual(
                hasyncd.get("environment", {}).get("UPGRADE_EXECUTOR_DIR"),
                "/app/runtime/upgrade-executor",
            )

            env_example = (pkg_root / ".env.example").read_text(encoding="utf-8")
            self.assertIn("HASYNC_SECRET_FILE=/app/runtime/hasync.secret", env_example)
            self.assertIn("HASYNC_BIND_ADDR=127.0.0.1", env_example)

    def test_package_runtime_run_and_build_update_full_include_ha_images(self):
        with tempfile.TemporaryDirectory(prefix="wdsp-ha-run-") as tmp:
            work = Path(tmp)
            rpm_dir = work / "openeuler-rpms"
            rpm_dir.mkdir()
            (rpm_dir / "docker-compose-plugin-2.29.7-1.x86_64.rpm").touch()
            env = dict(os.environ)
            env.pop("WDSP_SIGNING_KEY", None)
            result = subprocess.run(
                [
                    "bash", str(PACKAGE_RUNTIME_RUN),
                    "--dry-run", "--version", "9.9.9",
                    "--output", str(work / "out"),
                    "--rpm-dir", str(rpm_dir),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("jiuzhang-havipd:9.9.9", result.stdout)
            self.assertIn("gateway/images/havipd/Dockerfile", result.stdout)
            self.assertIn("jiuzhang-hasyncd:9.9.9", result.stdout)
            self.assertIn("gateway/images/hasyncd/Dockerfile", result.stdout)

        update_full_src = BUILD_UPDATE_FULL.read_text(encoding="utf-8")
        self.assertIn("jiuzhang-havipd", update_full_src)
        self.assertIn("jiuzhang-hasyncd", update_full_src)
        self.assertIn("(.services | has(\"hasyncd\") | not)", update_full_src)

    def test_baremetal_units_env_and_scripts_include_havipd_and_hasyncd(self):
        havipd_unit = HAVIPD_UNIT.read_text(encoding="utf-8")
        self.assertRegex(havipd_unit, r"(?m)^User=root\s*$")
        self.assertRegex(havipd_unit, r"(?m)^SupplementaryGroups=__USER__\s*$")
        self.assertIn("AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BROADCAST", havipd_unit)
        self.assertIn("--node __NODE_NAME__", havipd_unit)

        hasyncd_unit = HASYNCD_UNIT.read_text(encoding="utf-8")
        self.assertRegex(hasyncd_unit, r"(?m)^User=__USER__\s*$")
        self.assertRegex(hasyncd_unit, r"(?m)^Group=__USER__\s*$")
        self.assertRegex(hasyncd_unit, r"(?m)^ConditionPathExists=__ROOT__/data/runtime/hasync\.secret\s*$")
        self.assertRegex(hasyncd_unit, r"(?m)^CapabilityBoundingSet=\s*$")

        env_template = BAREMETAL_ENV.read_text(encoding="utf-8")
        self.assertIn("HASYNC_SECRET_FILE=__ROOT__/data/runtime/hasync.secret", env_template)

        build_binaries = (BAREMETAL_DIR / "build-binaries.sh").read_text(encoding="utf-8")
        self.assertIn("./cmd/havipd", build_binaries)
        self.assertIn("./cmd/hasyncd", build_binaries)

        assemble = (BAREMETAL_DIR / "assemble.sh").read_text(encoding="utf-8")
        self.assertIn("havipd", assemble)
        self.assertIn("hasyncd", assemble)

        install_sh = (BAREMETAL_DIR / "package/install.sh").read_text(encoding="utf-8")
        self.assertIn("jiuzhang-havipd", install_sh)
        self.assertIn("jiuzhang-hasyncd", install_sh)
        self.assertIn("keepalived", install_sh)
        self.assertIn("sidecars/keepalived", install_sh)

        for script_rel in ("package/uninstall.sh", "package/restore.sh"):
            text = (BAREMETAL_DIR / script_rel).read_text(encoding="utf-8")
            self.assertIn("jiuzhang-havipd", text, script_rel)
            self.assertIn("jiuzhang-hasyncd", text, script_rel)


if __name__ == "__main__":
    unittest.main()
