"""Gateway upgrades must recreate the sidecar sharing its network namespace."""
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[3]
EXECUTOR = ROOT / "ops/upgrade/upgrade-executor.sh"
APPLY = ROOT / "ops/upgrade/apply.sh"
ROLLBACK = ROOT / "ops/upgrade/rollback.sh"
SOURCE = EXECUTOR.read_text(encoding="utf-8")
START = SOURCE.index("  # gateway 重建会使 network_mode: service:gateway")
END = SOURCE.index("  # API 镜像入口会在启动服务前执行 migrate up", START)
INCLUDE_NETMGRD = SOURCE[START:END]


class GatewayNetworkRecreateTests(unittest.TestCase):
    def run_include(self, services, compose_services, scenario="healthy"):
        initial_images = [f"image-{service}" for service in services]
        initial_ids = [f"sha256:{service}-old" for service in services]
        script = f'''
set -euo pipefail
SCENARIO={scenario}
SERVICES=({" ".join(services)})
STABLE_IMAGES=({" ".join(initial_images)})
OLD_IDS=({" ".join(initial_ids)})
compose_services=({" ".join(compose_services)})
CURRENT_MESSAGE=""
compose() {{
  [[ "$SCENARIO" != compose-error ]] || return 1
  [[ "$*" == "config --format json" ]] || return 1
  printf '%s\\n' '{{"services":{{"netmgrd":{{"image":"image-netmgrd"}}}}}}'
}}
docker() {{
  [[ "$1 $2" == "image inspect" ]] || return 1
  [[ "$SCENARIO" != inspect-error ]] || return 1
  printf 'sha256:netmgrd-old\\n'
}}
include_netmgrd() {{
  local stable old
{INCLUDE_NETMGRD}
}}
if include_netmgrd; then result=0; else result=1; fi
printf 'RESULT=%s SERVICES=%s IMAGES=%s IDS=%s MESSAGE=%s\\n' \
  "$result" "${{SERVICES[*]}}" "${{STABLE_IMAGES[*]}}" "${{OLD_IDS[*]}}" "$CURRENT_MESSAGE"
'''
        result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_gateway_only_upgrade_adds_existing_netmgrd(self):
        output = self.run_include(["gateway"], ["api", "gateway", "netmgrd"])
        self.assertIn("RESULT=0", output)
        self.assertIn("SERVICES=gateway netmgrd", output)
        self.assertIn("IMAGES=image-gateway image-netmgrd", output)
        self.assertIn("IDS=sha256:gateway-old sha256:netmgrd-old", output)

    def test_no_duplicate_and_no_unrelated_service_changes(self):
        output = self.run_include(["gateway", "netmgrd"], ["gateway", "netmgrd"])
        self.assertIn("SERVICES=gateway netmgrd", output)
        self.assertIn("IMAGES=image-gateway image-netmgrd", output)
        output = self.run_include(["api"], ["api", "gateway", "netmgrd"])
        self.assertIn("SERVICES=api ", output)
        output = self.run_include(["gateway"], ["api", "gateway"])
        self.assertIn("SERVICES=gateway ", output)

    def test_netmgrd_lookup_is_fail_closed(self):
        for scenario in ("compose-error", "inspect-error"):
            with self.subTest(scenario=scenario):
                output = self.run_include(["gateway"], ["gateway", "netmgrd"], scenario)
                self.assertIn("RESULT=1", output)
                self.assertIn("netmgrd", output.split("MESSAGE=", 1)[1])

    def test_manual_apply_and_rollback_recreate_netmgrd(self):
        for script in (APPLY, ROLLBACK):
            with self.subTest(script=script.name):
                self.assertIn(
                    "compose up -d --no-deps --force-recreate api gateway netmgrd",
                    script.read_text(),
                )
        self.assertIn(
            'compose up -d --no-deps --force-recreate "${SERVICES[@]}"',
            SOURCE,
        )
        self.assertIn(
            'compose up -d --no-deps --force-recreate "${existed[@]}"',
            SOURCE,
        )


if __name__ == "__main__":
    unittest.main()
