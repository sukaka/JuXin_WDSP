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
        print("api123" if args[-1] == "api" else "abc123")
    elif "ps" in args:
        print("fixture-gateway running")
    sys.exit(0)
if args[:1] == ["inspect"]:
    fmt = args[args.index("--format") + 1] if "--format" in args else ""
    target = args[-1]
    if target == "jiuzhang-apm-clickhouse":
        if os.environ.get("CH_RUNNING") != "1":
            sys.exit(1)
        if fmt == "{{.State.Running}}|{{.Name}}":
            print("true|/jiuzhang-apm-clickhouse")
            sys.exit(0)
        if fmt == "{{json .NetworkSettings.Networks}}":
            nets = [n for n in os.environ.get("CH_NETS", "").split(",") if n]
            print(json.dumps({n: {} for n in nets}))
            sys.exit(0)
        sys.exit(1)
    if target == "api123" and fmt == "{{json .NetworkSettings.Networks}}":
        nets = [n for n in os.environ.get("API_NETS", "").split(",") if n]
        print(json.dumps({n: {} for n in nets}))
        sys.exit(0)
    print(json.dumps([{"Destination": "/var/run/caddy", "Source": os.environ["SOCKET_DIR"]}]))
    sys.exit(0)
if args[:1] == ["ps"]:
    print("jiuzhang-postgres")
    print("jiuzhang-valkey")
    sys.exit(0)
if args[:1] == ["exec"]:
    if len(args) >= 2 and args[1] == "jiuzhang-apm-clickhouse" and os.environ.get("CH_PING_FAIL") == "1":
        sys.exit(1)
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
    def run_check(self, listeners, extra_args=(), extra_env=None):
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
            if extra_env:
                env.update(extra_env)
            result = subprocess.run(
                ["bash", str(CHECK), "-c", str(compose), "-e", str(env_file),
                 "--api-url", "http://127.0.0.1:18081", *extra_args],
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

    def test_colocated_clickhouse_network_check_warns_before_upgrade_and_fails_strict(self):
        # 1) api 已接入同机 ClickHouse 网络：严格模式通过
        code, output = self.run_check(
            "{}",
            extra_args=("--strict-clickhouse-network",),
            extra_env={
                "CH_RUNNING": "1",
                "CH_NETS": "jiuzhang-apm_apm-data",
                "API_NETS": "jiuzhang-wdsp_jiuzhang-internal,jiuzhang-apm_apm-data",
            },
        )
        self.assertEqual(code, 0, output)
        self.assertIn("[OK]   clickhouse", output)
        self.assertIn("jiuzhang-apm_apm-data", output)

        # 2) api 缺失 ClickHouse 网络：非严格模式（升级前）仅告警不阻断升级
        code, output = self.run_check(
            "{}",
            extra_env={
                "CH_RUNNING": "1",
                "CH_NETS": "jiuzhang-apm_apm-data",
                "API_NETS": "jiuzhang-wdsp_jiuzhang-internal",
            },
        )
        self.assertEqual(code, 0, output)
        self.assertIn("[WARN]", output)
        self.assertIn("未接入其网络", output)

        # 3) api 缺失 ClickHouse 网络：严格模式（升级后）强制失败
        code, output = self.run_check(
            "{}",
            extra_args=("--strict-clickhouse-network",),
            extra_env={
                "CH_RUNNING": "1",
                "CH_NETS": "jiuzhang-apm_apm-data",
                "API_NETS": "jiuzhang-wdsp_jiuzhang-internal",
            },
        )
        self.assertEqual(code, 1, output)
        self.assertIn("[FAIL] clickhouse", output)

        # 4) ClickHouse ping 失败：直接失败
        code, output = self.run_check(
            "{}",
            extra_env={
                "CH_RUNNING": "1",
                "CH_PING_FAIL": "1",
                "CH_NETS": "jiuzhang-apm_apm-data",
                "API_NETS": "jiuzhang-wdsp_jiuzhang-internal,jiuzhang-apm_apm-data",
            },
        )
        self.assertEqual(code, 1, output)
        self.assertIn("[FAIL] clickhouse", output)


if __name__ == "__main__":
    unittest.main()
