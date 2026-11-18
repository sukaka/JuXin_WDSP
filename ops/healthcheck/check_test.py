import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
CHECK = ROOT / "ops/healthcheck/check.sh"

DOCKER_STUB = r'''#!/usr/bin/env python3
import json
import os
import sys

args = sys.argv[1:]
if args[:1] == ["compose"]:
    if "ps" in args and "-q" in args:
        print("abc123")
    elif "ps" in args:
        print("fixture-gateway running")
    sys.exit(0)
if args[:1] == ["inspect"]:
    print(json.dumps([{"Destination": "/var/run/caddy", "Source": os.environ["SOCKET_DIR"]}]))
    sys.exit(0)
if args[:1] == ["ps"]:
    print("jiuzhang-postgres")
    print("jiuzhang-valkey")
    sys.exit(0)
if args[:1] == ["exec"]:
    sys.exit(0)
sys.exit(1)
'''

CURL_STUB = r'''#!/usr/bin/env python3
import os
import sys

args = " ".join(sys.argv[1:])
if "/api/v1/health" in args:
    print('{"status":"ok"}')
elif "/config/apps/http/servers" in args:
    print(os.environ["LISTENERS"], end="")
sys.exit(0)
'''


class GatewayHealthcheckTests(unittest.TestCase):
    def run_check(self, listeners):
        with tempfile.TemporaryDirectory(prefix="wdsp-health-") as directory:
            work = Path(directory)
            bin_dir = work / "bin"
            bin_dir.mkdir()
            for name, content in (("docker", DOCKER_STUB), ("curl", CURL_STUB)):
                path = bin_dir / name
                path.write_text(content)
                path.chmod(0o755)
            compose = work / "docker-compose.yml"
            env_file = work / "fixture.env"
            compose.write_text("{}")
            env_file.write_text("VALKEY_PASSWORD=fixture\n")
            server = socket.socket(socket.AF_UNIX)
            server.bind(str(work / "admin.sock"))
            self.addCleanup(server.close)
            env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ["PATH"],
                       SOCKET_DIR=str(work), LISTENERS=listeners)
            result = subprocess.run(
                ["bash", str(CHECK), "-c", str(compose), "-e", str(env_file),
                 "--api-url", "http://127.0.0.1:18081"],
                env=env, text=True, capture_output=True, timeout=10,
            )
            return result.returncode, result.stdout + result.stderr

    def test_empty_caddy_servers_are_healthy_when_admin_is_readable(self):
        code, output = self.run_check("{}")
        self.assertEqual(code, 0, output)
        self.assertIn("gateway", output)
        self.assertIn("Caddy Admin 可访问，当前无站点监听", output)

    def test_unreadable_or_invalid_caddy_servers_still_fail(self):
        for listeners in ("", "not-json", '{"unexpected":[]}'):
            with self.subTest(listeners=listeners):
                code, output = self.run_check(listeners)
                self.assertNotEqual(code, 0, output)
                self.assertIn("无法从 Caddy Admin Unix Socket 读取实际监听端口", output)


if __name__ == "__main__":
    unittest.main()
