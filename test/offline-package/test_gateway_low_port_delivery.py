"""Gateway low-port Compose and complete .run delivery regression tests."""
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
STAGE5 = ROOT / "deployment/docker-compose.stage5.yml"
BUILD = ROOT / "ops/offline-package/build.sh"
RUN_BUILD = ROOT / "ops/offline-package/build-openeuler-zhaoxin-run.sh"
ENTRYPOINT = "/usr/local/bin/wdsp-gateway-bind"


def run_script(*args, timeout=120):
    env = dict(os.environ)
    env.pop("WDSP_SIGNING_KEY", None)
    env.pop("WDSP_AGENT_BINARY", None)
    return subprocess.run(
        ["bash", *map(str, args)], cwd=ROOT, env=env,
        capture_output=True, text=True, timeout=timeout,
    )


def service_block(compose, service, next_service):
    return compose.split(f"\n  {service}:\n", 1)[1].split(f"\n  {next_service}:", 1)[0]


def render_compose(test, compose_path):
    if not shutil.which("docker"):
        test.skipTest("docker CLI unavailable")
    version = subprocess.run(
        ["docker", "compose", "version"], capture_output=True, text=True, timeout=10,
    )
    if version.returncode != 0:
        test.skipTest("docker compose plugin unavailable")
    env = dict(
        os.environ,
        POSTGRES_PASSWORD="render-test-only",
        VALKEY_PASSWORD="render-test-only",
        JIUZHANG_MASTER_KEY="render-test-only",
    )
    result = subprocess.run(
        ["docker", "compose", "-f", str(compose_path), "--env-file", "/dev/null",
         "config", "--format", "json"],
        cwd=compose_path.parent, env=env, capture_output=True, text=True, timeout=30,
    )
    test.assertEqual(result.returncode, 0, result.stdout + result.stderr)
    return json.loads(result.stdout)


def assert_rendered_contract(test, rendered, stage5=False):
    gateway = rendered["services"]["gateway"]
    test.assertEqual(gateway["user"], "0:0")
    test.assertEqual(gateway["entrypoint"], [ENTRYPOINT])
    test.assertEqual(gateway["environment"]["HOME"], "/var/lib/caddy")
    test.assertEqual(gateway["cap_drop"], ["ALL"])
    test.assertEqual(
        sorted(gateway["cap_add"]),
        sorted(["NET_BIND_SERVICE", "SETUID", "SETGID", "SETPCAP"]),
    )
    test.assertIn("no-new-privileges:true", gateway["security_opt"])
    test.assertEqual(rendered["services"]["netmgrd"]["network_mode"], "service:gateway")
    test.assertEqual(rendered["services"]["containerops"]["tmpfs"], ["/tmp:size=8m,mode=1777"])
    test.assertNotIn("ip_unprivileged_port_start", json.dumps(rendered))
    if stage5:
        test.assertTrue(any(
            port.get("target") == 82 and port.get("published") == "82"
            for port in gateway["ports"]
        ))
    else:
        test.assertEqual(gateway["network_mode"], "host")
        api = rendered["services"]["api"]
        test.assertEqual(api["environment"]["GATEWAY_PUBLISH_SMOKE_ADDR"], "host.docker.internal")
        test.assertIn(api["extra_hosts"], [
            ["host.docker.internal:host-gateway"],
            ["host.docker.internal=host-gateway"],
        ])
        api_volumes = api["volumes"]
        runtime_volume = next(v for v in api_volumes if v.get("target") == "/app/runtime")
        test.assertEqual(runtime_volume["type"], "volume")
        test.assertEqual(runtime_volume["source"], "runtime-data")
        hostctl_volume = next(v for v in api_volumes if v.get("target") == "/app/runtime/hostctl")
        test.assertEqual(hostctl_volume["type"], "bind")
        test.assertTrue(hostctl_volume["source"].endswith("/runtime/hostctl"))
        test.assertNotEqual(hostctl_volume.get("read_only"), True)


class GatewayLowPortDeliveryTests(unittest.TestCase):
    def test_stage5_source_and_rendered_contract(self):
        compose = STAGE5.read_text(encoding="utf-8")
        gateway = service_block(compose, "gateway", "netmgrd")
        self.assertIn('user: "0:0"', gateway)
        self.assertIn(f'entrypoint: ["{ENTRYPOINT}"]', gateway)
        self.assertIn("HOME: /var/lib/caddy", gateway)
        self.assertIn("${GATEWAY_SITE_HTTP_PORT:-82}:82", gateway)
        self.assertNotIn("ip_unprivileged_port_start", compose)
        assert_rendered_contract(self, render_compose(self, STAGE5), stage5=True)

    def test_complete_run_embeds_the_same_locked_gateway_contract(self):
        with tempfile.TemporaryDirectory(prefix="wdsp-low-port-run-") as directory:
            output = Path(directory) / "offline"
            result = run_script(
                BUILD, "-v", "9.9.9", "-p", "wdsp", "-a", "amd64",
                "--runtime-only", "--skip-images", "--development", "-o", output,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            offline = output / "jiuzhang-wdsp-offline-9.9.9-amd64.tar.gz"
            run_output = Path(directory) / "run"
            result = run_script(
                RUN_BUILD, "--version", "9.9.9", "--offline-package", offline,
                "--development", "--output", run_output,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            run_file = run_output / "jiuzhang-wdsp-openeuler-zhaoxin-9.9.9-amd64.run"
            result = run_script(run_file, "--help")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

            run_bytes = run_file.read_bytes()
            marker = b"\n__WDSP_PAYLOAD_BELOW__\n"
            self.assertIn(marker, run_bytes)
            payload = run_bytes.split(marker, 1)[1]
            with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as outer:
                embedded_name = next(
                    name for name in outer.getnames()
                    if name.endswith("jiuzhang-wdsp-offline-9.9.9-amd64.tar.gz")
                )
                embedded = outer.extractfile(embedded_name).read()
            with tarfile.open(fileobj=io.BytesIO(embedded), mode="r:gz") as package:
                compose_name = next(
                    name for name in package.getnames() if name.endswith("/docker-compose.yml")
                )
                compose_bytes = package.extractfile(compose_name).read()
            compose = compose_bytes.decode()
            gateway = service_block(compose, "gateway", "netmgrd")
            self.assertIn('user: "0:0"', gateway)
            self.assertIn(f'entrypoint: ["{ENTRYPOINT}"]', gateway)
            self.assertIn("cap_drop: [ALL]", gateway)
            self.assertIn("cap_add: [NET_BIND_SERVICE, SETUID, SETGID, SETPCAP]", gateway)
            self.assertIn("image: jiuzhang-gateway:9.9.9", gateway)
            self.assertIn("image: jiuzhang-netmgrd:9.9.9", compose)
            self.assertNotIn(":latest", compose)
            self.assertNotIn("wdsp-port82-hotfix", compose)
            self.assertNotIn("ip_unprivileged_port_start", compose)

            packaged_compose = Path(directory) / "docker-compose.yml"
            packaged_compose.write_bytes(compose_bytes)
            rendered = render_compose(self, packaged_compose)
            assert_rendered_contract(self, rendered)

            package_runtime = (ROOT / "ops/offline-package/package-runtime-run.sh").read_text()
            predicate = package_runtime.split("  jq -e '\n", 1)[1].split(
                "\n  ' <<<\"$compose_json\"", 1
            )[0]
            result = subprocess.run(
                ["jq", "-e", predicate], input=json.dumps(rendered),
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
