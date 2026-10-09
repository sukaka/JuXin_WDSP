"""执行真实就绪函数，所有 Docker/HTTP/等待均为本地桩，不操作宿主服务。"""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


EXECUTOR = Path(__file__).resolve().parents[1] / "upgrade-executor.sh"
SOURCE = EXECUTOR.read_text()
# 保留旧函数名作为起始点，以便同一回归能复现修复前行为。
FUNCTIONS = SOURCE[SOURCE.index("wait_service() {"):SOURCE.index("declare -a SERVICES=")]

MOCKS = r'''
set -euo pipefail
TIMEOUT=16
SECONDS=0
API_URL=http://127.0.0.1:18081
CURRENT_MESSAGE=""
SERVICES=(api web gateway netmgrd)
STABLE_IMAGES=(image-api image-web image-gateway image-netmgrd)
sleep() { SECONDS=$((SECONDS + $1)); }
timeout() { shift; "$@"; }
compose() {
  [[ "$SCENARIO" != compose-error ]] || return 1
  [[ "$SCENARIO" != multiple ]] || { printf 'cid-web\ncid-extra\n'; return; }
  printf 'cid-%s\n' "$3"
}
docker() {
  if [[ "$1" == image && "$2" == inspect ]]; then
    [[ "$SCENARIO" != image-error ]] || return 1
    local image="${@: -1}"
    printf 'sha256:%s\n' "${image#image-}"
    return
  fi
  if [[ "$1" == inspect ]]; then
    local format="$3" cid="${@: -1}" state=running health=healthy restart=0 started=start image
    image="sha256:${cid#cid-}"
    [[ "$SCENARIO" != inspect-error ]] || return 1
    [[ "$SCENARIO" != health-inspect-error || "$format" != *Health* ]] || return 1
    if [[ "$format" == *Mounts* ]]; then
      [[ "$SCENARIO" != missing-socket ]] || { printf '[]\n'; return; }
      printf '[{"Destination":"/var/run/caddy","Source":"/mock/caddy"}]\n'
      return
    fi
    [[ "$SCENARIO" != no-health ]] || health=""
    [[ "$SCENARIO" != unhealthy || "$cid" != cid-gateway ]] || health=unhealthy
    [[ "$SCENARIO" != old-image ]] || image=sha256:old
    if [[ "$SCENARIO" == crash-during-api && -e "$MARKER" && "$cid" == cid-web ]]; then state=exited; fi
    if [[ "$SCENARIO" == restart-loop ]]; then restart=$SECONDS; fi
    if [[ "$SCENARIO" == recover && "$SECONDS" -lt 4 ]]; then state=restarting; fi
    if [[ "$format" == *RestartCount* ]]; then
      printf '%s|%s|%s|%s|%s\n' "$state" "$health" "$image" "$restart" "$started"
    elif [[ "$format" == *Health* ]]; then printf '%s\n' "$health"
    else printf '%s\n' "$state"; fi
    return
  fi
  if [[ "$1" == exec ]]; then
    printf '%s\n' "$*" >>"$PROBES"
    [[ "$SCENARIO" != "probe-${2#cid-}-error" ]] || return 1
    return
  fi
  return 1
}
curl() {
  printf '%s\n' "$*" >>"$PROBES"
  if [[ "$*" == *--unix-socket* ]]; then
    [[ "$SCENARIO" != probe-gateway-error ]]
  else
    [[ "$SCENARIO" != api-error ]] || return 1
    if [[ "$SCENARIO" == crash-during-api ]]; then : >"$MARKER"; fi
  fi
}
'''


class ExecutorReadinessTest(unittest.TestCase):
    def run_case(self, scenario):
        with tempfile.TemporaryDirectory(prefix="wdsp-ready-") as directory:
            probes = Path(directory) / "probes"
            script = MOCKS + "\n" + FUNCTIONS + r'''
if wait_selected_services; then result=0; else result=1; fi
printf 'RESULT=%s SECONDS=%s MESSAGE=%s\n' "$result" "$SECONDS" "$CURRENT_MESSAGE"
'''
            env = dict(os.environ, SCENARIO=scenario, PROBES=str(probes), MARKER=directory + "/crash")
            result = subprocess.run(["bash", "-c", script], env=env, text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout, probes.read_text() if probes.exists() else ""

    def test_fail_closed(self):
        for scenario in ("compose-error", "multiple", "inspect-error", "health-inspect-error", "image-error", "old-image",
                         "unhealthy", "missing-socket", "probe-api-error", "probe-web-error",
                         "probe-gateway-error", "probe-netmgrd-error", "api-error",
                         "crash-during-api", "restart-loop"):
            with self.subTest(scenario=scenario):
                output, _ = self.run_case(scenario)
                self.assertIn("RESULT=1", output)
                self.assertNotIn("MESSAGE=\n", output)

    def test_real_probes_and_stability(self):
        for scenario in ("healthy", "no-health", "recover"):
            with self.subTest(scenario=scenario):
                output, probes = self.run_case(scenario)
                self.assertIn("RESULT=0", output)
                elapsed = int(output.split("SECONDS=")[1].split()[0])
                self.assertGreaterEqual(elapsed, 14 if scenario == "recover" else 10)
                self.assertIn("cid-api", probes)
                self.assertIn("http://127.0.0.1:8080/", probes)
                self.assertIn("--unix-socket /mock/caddy/admin.sock", probes)
                self.assertIn("/usr/local/bin/netmgrd --healthcheck", probes)


if __name__ == "__main__":
    unittest.main()
