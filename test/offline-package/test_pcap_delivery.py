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
            # H-02: pcapd needs SETUID/SETGID to drop evidence writer privileges to 1000:1000
            self.assertEqual(
                sorted(enabled["services"]["pcapd"]["cap_add"]),
                sorted(["NET_RAW", "SETUID", "SETGID"]),
            )
            # H-04/H-21: hardened container runtime flags + preserved 1.9.0 gateway-certs mounts
            for svc_name in ("api", "web", "netmgrd", "logrotator"):
                svc = default["services"][svc_name]
                self.assertTrue(svc.get("read_only"), svc_name)
                self.assertEqual(svc.get("cap_drop"), ["ALL"], svc_name)
                self.assertTrue(svc.get("tmpfs"), svc_name)
            self.assertEqual(
                sorted(default["services"]["netmgrd"]["cap_add"]),
                sorted(["NET_ADMIN", "NET_RAW"]),
            )
            self.assertIn(
                "1000",
                [str(g) for g in (default["services"]["netmgrd"].get("group_add") or [])],
            )
            self.assertTrue(any(
                m.get("source") == "gateway-certs" and m.get("target") == "/app/runtime/certificates"
                for m in default["services"]["api"]["volumes"]
            ))
            self.assertTrue(any(
                m.get("source") == "gateway-certs" and m.get("target") == "/etc/caddy/certs" and m.get("read_only") is True
                for m in default["services"]["gateway"]["volumes"]
            ))
            # LOW-01: valkey healthcheck uses REDISCLI_AUTH instead of -a argv
            valkey_test = " ".join(default["services"]["valkey"]["healthcheck"]["test"])
            self.assertIn("REDISCLI_AUTH=", valkey_test)
            self.assertNotIn("valkey-cli -a", valkey_test)
            # M-O1: standalone update launcher starts with #!/usr/bin/env bash
            launcher = Path(temporary) / "out/jiuzhang-wdsp-update-full-0.0.0-pcap-test-arm64.sh"
            self.assertTrue(launcher.is_file())
            self.assertTrue(launcher.read_text(encoding="utf-8").startswith("#!/usr/bin/env bash\n"))

    def test_baremetal_and_daemon_security_contract(self):
        dockerfile = (ROOT / "gateway/images/pcapd/Dockerfile").read_text()
        logrotator_dockerfile = (ROOT / "gateway/images/logrotator/Dockerfile").read_text()
        unit = (ROOT / "deployment/systemd/jiuzhang-pcapd.service").read_text()
        install_pcapd = (ROOT / "ops/install/install-pcapd.sh").read_text()
        release_pub = (ROOT / "ops/offline-package/release-signing.pub").read_text().strip()
        self.assertNotIn(":latest", dockerfile)
        self.assertIn("sha256:", dockerfile)
        self.assertIn("USER 1000:1000", logrotator_dockerfile)
        self.assertIn("User=1000", unit)
        self.assertIn("Group=1000", unit)
        self.assertNotIn("User=root", unit)
        self.assertIn("ReadWritePaths=__PCAP_HOT_DIR__", unit)
        self.assertIn("CapabilityBoundingSet=CAP_NET_RAW", unit)
        self.assertIn("AmbientCapabilities=CAP_NET_RAW", unit)
        self.assertIn("NoNewPrivileges=yes", unit)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn(release_pub, install_pcapd)
        self.assertIn("__PCAP_HOT_DIR__", install_pcapd)
        # H-02: install-pcapd.sh fails closed on tampered signature even with --allow-unsigned
        with tempfile.TemporaryDirectory(prefix="wdsp-pcapd-sig-") as tmp:
            tmp_path = Path(tmp)
            pkg = tmp_path / "jiuzhang-pcapd-test.tar.gz"
            with tarfile.open(pkg, "w:gz") as tf:
                import io
                info = tarfile.TarInfo("jiuzhang-pcapd")
                data = b"#!/bin/sh\necho ok\n"
                info.size = len(data)
                info.mode = 0o755
                tf.addfile(info, io.BytesIO(data))
            (tmp_path / "jiuzhang-pcapd-test.tar.gz.sig").write_text("AAAA\n", encoding="ascii")
            res = subprocess.run(
                [
                    "bash", str(ROOT / "ops/install/install-pcapd.sh"),
                    "--package", str(pkg),
                    "--allow-unsigned",
                    "--dry-run",
                    "--iface", "eth0",
                    "--ports", "80,443",
                    "--hot-dir", "/var/lib/jiuzhang-pcap/hot",
                    "--warm-dir", "/var/lib/jiuzhang-pcap/warm",
                ],
                capture_output=True, text=True, timeout=15,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("验签失败", res.stderr)
        for script in ("ops/install/install.sh", "ops/install/pcap.sh", "ops/install/install-pcapd.sh", "ops/offline-package/build.sh"):
            subprocess.run(["bash", "-n", str(ROOT / script)], check=True)
        subprocess.run(["bash", str(ROOT / "scripts/tests/test-pcap-installer.sh")], check=True)


if __name__ == "__main__":
    unittest.main()
