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
                self.assertIn("image: jiuzhang-netmgrd:9.9.9", compose)
                self.assertIn("network_mode: service:gateway", compose)
                self.assertIn("GATEWAY_NODE_NAME: ${GATEWAY_NODE_NAME:-gateway-poc-01}", compose)
                self.assertTrue(any(n.endswith("/licenses/THIRD_PARTY_NOTICES") for n in names))


if __name__ == "__main__":
    unittest.main()
