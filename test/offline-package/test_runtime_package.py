"""Runtime-only packaging integration checks (no Docker or deployment)."""
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class RuntimePackageTests(unittest.TestCase):
    def test_runtime_only_has_services_without_docs_or_tests(self):
        with tempfile.TemporaryDirectory(prefix="wdsp-runtime-package-") as output:
            env = dict(os.environ)
            env.pop("WDSP_SIGNING_KEY", None)
            env.pop("WDSP_AGENT_BINARY", None)
            result = subprocess.run(
                ["bash", str(ROOT / "ops/offline-package/build.sh"),
                 "-v", "9.9.9", "-p", "wdsp", "-a", "amd64", "--runtime-only",
                 "--skip-images", "--development", "-o", output],
                env=env, capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            with tarfile.open(Path(output) / "jiuzhang-wdsp-offline-9.9.9-amd64.tar.gz") as archive:
                names = archive.getnames()
                for name in names:
                    parts = Path(name).parts
                    self.assertFalse(set(parts) & {"docs", "tests", "test", "testdata", "__tests__", "__pycache__"}, name)
                    self.assertFalse(name.endswith((".md", "_test.go", ".spec.ts", ".test.ts")), name)
                compose_name = next(n for n in names if n.endswith("/docker-compose.yml"))
                compose = archive.extractfile(compose_name).read().decode()
                api = compose.split("\n  api:\n", 1)[1].split("\n  web:\n", 1)[0]
                self.assertIn("- runtime-data:/app/runtime", api)
                self.assertIn("- ./runtime/hostctl:/app/runtime/hostctl", api)
                gateway = compose.split("\n  gateway:\n", 1)[1].split("\n  # 日志轮转", 1)[0]
                self.assertIn('user: "0:0"', gateway)
                self.assertIn('entrypoint: ["/usr/local/bin/wdsp-gateway-bind"]', gateway)
                self.assertIn("HOME: /var/lib/caddy", gateway)
                self.assertIn("cap_drop: [ALL]", gateway)
                self.assertIn("cap_add: [NET_BIND_SERVICE, SETUID, SETGID, SETPCAP]", gateway)
                self.assertIn("security_opt: [no-new-privileges:true]", gateway)
                self.assertNotIn("wdsp-port82-hotfix", compose)
                self.assertNotIn("ip_unprivileged_port_start", compose)
                self.assertIn("image: jiuzhang-netmgrd:9.9.9", compose)
                self.assertIn("network_mode: service:gateway", compose)
                self.assertIn('tmpfs: ["/tmp:size=8m,mode=1777"]', compose)
                for relative in (
                    "ops/install/install-hostctl.sh",
                    "ops/system/hostctl-exec.sh",
                    "ops/system/firewall-ensure.sh",
                    "ops/system/factory-reset.sh",
                    "deployment/systemd/jiuzhang-hostctl.path",
                    "deployment/systemd/jiuzhang-hostctl.service",
                ):
                    self.assertTrue(any(n.endswith("/" + relative) for n in names), relative)
                self.assertIn("GATEWAY_NODE_NAME: ${GATEWAY_NODE_NAME:-gateway-poc-01}", compose)
                self.assertTrue(any(n.endswith("/licenses/THIRD_PARTY_NOTICES") for n in names))


if __name__ == "__main__":
    unittest.main()
