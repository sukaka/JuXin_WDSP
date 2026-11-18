import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class RequestPcapDeliveryTest(unittest.TestCase):
    def render(self, compose_path, extra=None):
        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", ""),
            "POSTGRES_PASSWORD": "render-test-only",
            "VALKEY_PASSWORD": "render-test-only",
            "JIUZHANG_MASTER_KEY": "render-test-only",
        }
        if os.environ.get("DOCKER_HOST"):
            env["DOCKER_HOST"] = os.environ["DOCKER_HOST"]
        if extra:
            env.update(extra)
        result = subprocess.run(
            ["docker", "compose", "-f", str(compose_path), "--env-file", "/dev/null", "config", "--format", "json"],
            cwd=compose_path.parent, env=env, capture_output=True, text=True, timeout=45,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(result.stdout)

    def build_package(self, work):
        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", ""),
            "TMPDIR": str(work),
        }
        env.pop("WDSP_SIGNING_KEY", None)
        result = subprocess.run(
            ["bash", str(ROOT / "ops/offline-package/build.sh"), "--skip-images", "--development", "--runtime-only",
             "--version", "0.0.0-pcap-test", "--product", "wdsp", "--arch", "arm64", "--output", str(work / "out")],
            cwd=ROOT, env=env, capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        archive = work / "out/jiuzhang-wdsp-offline-0.0.0-pcap-test-arm64.tar.gz"
        self.assertTrue(archive.is_file())
        with tarfile.open(archive, "r:gz") as package:
            destination = (work / "unpacked").resolve()
            destination.mkdir(parents=True, exist_ok=True)
            for member in package.getmembers():
                target = (destination / member.name).resolve()
                self.assertTrue(target == destination or destination in target.parents)
                self.assertFalse(member.issym() or member.islnk())
                package.extract(member, path=destination)
        return work / "unpacked/jiuzhang-wdsp-offline-0.0.0-pcap-test-arm64/docker-compose.yml"

    def test_default_and_enabled_compose_contract(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "runtime") as temporary:
            compose_path = self.build_package(Path(temporary))
            default = self.render(compose_path)
            self.assertNotIn("pcapd", default["services"])
            self.assertEqual(default["services"]["api"]["environment"].get("REQUEST_PCAP_HOT_DIR", ""), "")
            enabled = self.render(compose_path, {
                "COMPOSE_PROFILES": "request-pcap",
                "PCAP_SERVER_HOT_DIR": "/app/runtime/pcap-hot",
                "PCAP_SERVER_WARM_DIR": "/app/runtime/pcap-warm",
                "PCAP_SERVER_KEY_FILE": "/app/runtime/pcap-private/private.key",
                "REQUEST_PCAP_HOT_DIR": "/srv/jiuzhang-ssd/pcap",
                "REQUEST_PCAP_WARM_DIR": "/srv/jiuzhang-sas/pcap",
                "REQUEST_PCAP_IFACE": "eth0",
                "REQUEST_PCAP_PORTS": "80,443",
            })
            self.assertEqual(enabled["services"]["api"]["environment"]["REQUEST_PCAP_HOT_DIR"], "/app/runtime/pcap-hot")
            self.assertEqual(enabled["services"]["api"]["environment"]["REQUEST_PCAP_WARM_DIR"], "/app/runtime/pcap-warm")
            self.assertEqual(enabled["services"]["pcapd"]["environment"]["REQUEST_PCAP_PORTS"], "80,443")
            daemon_mounts = enabled["services"]["pcapd"]["volumes"]
            public = [mount for mount in daemon_mounts if mount["target"] == "/etc/jiuzhang"]
            self.assertEqual(len(public), 1)
            self.assertTrue(public[0]["read_only"])
            self.assertNotIn("/app/runtime/pcap-private", [mount["target"] for mount in daemon_mounts])
            hot = [mount for mount in daemon_mounts if mount["target"] == "/var/lib/jiuzhang/pcap-hot"]
            self.assertEqual(hot[0]["source"], "/srv/jiuzhang-ssd/pcap")

    def test_baremetal_and_daemon_security_contract(self):
        dockerfile = (ROOT / "gateway/images/pcapd/Dockerfile").read_text()
        unit = (ROOT / "deployment/systemd/jiuzhang-pcapd.service").read_text()
        self.assertNotIn(":latest", dockerfile)
        self.assertIn("sha256:", dockerfile)
        self.assertIn("CapabilityBoundingSet=CAP_NET_RAW", unit)
        self.assertIn("AmbientCapabilities=CAP_NET_RAW", unit)
        self.assertIn("NoNewPrivileges=yes", unit)
        self.assertIn("ProtectSystem=strict", unit)
        for script in ("ops/install/install.sh", "ops/install/pcap.sh", "ops/install/install-pcapd.sh", "ops/offline-package/build.sh"):
            subprocess.run(["bash", "-n", str(ROOT / script)], check=True)
        subprocess.run(["bash", str(ROOT / "scripts/tests/test-pcap-installer.sh")], check=True)


if __name__ == "__main__":
    unittest.main()
