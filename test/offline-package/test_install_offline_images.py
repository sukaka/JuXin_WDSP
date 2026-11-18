"""Exercise the installer startup step without touching host services."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class InstallOfflineImagesTests(unittest.TestCase):
    def run_startup(self, *, offline=True, manifest_verified=True, load_error=False,
                    missing=False, config_error=False):
        installer = (ROOT / "ops/install/install.sh").read_text()
        startup = installer.split('log_info "步骤 7/9', 1)[1].split(
            'log_info "等待管理 API', 1
        )[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({
                "files": [{"path": "images/web.tar"}, {"path": "docker-compose.yml"}],
            }))
            script = r"""
set -euo pipefail
pkg_dir=$1
pkg_manifest=$2
mfv_rc=$3
load_error=$4
missing=$5
config_error=$6
log_info() { :; }
die() { printf '%s\n' "$*" >&2; exit 1; }
docker() {
  printf 'docker %s\n' "$*" >&3
  case "$1 $2" in
    'image load') [[ "$load_error" != true ]] ;;
    'image inspect') [[ "$missing" != true ]] ;;
    *) return 99 ;;
  esac
}
compose() {
  printf 'compose %s\n' "$*" >&3
  case "$*" in
    'config --images')
      [[ "$config_error" != true ]] || return 1
      printf '%s\n' 'jiuzhang-runtime-jiuzhang-web:50c8996de63e5299b2ce35b0'
      ;;
    'up -d'|'up -d --pull never --no-build') ;;
    *) return 99 ;;
  esac
}
exec 3>"$pkg_dir/calls"
""" + 'log_info "步骤 7/9' + startup
            result = subprocess.run(
                ["bash", "-c", script, "installer-test", str(root),
                 str(manifest) if offline else "", "0" if manifest_verified else "2",
                 str(load_error).lower(), str(missing).lower(), str(config_error).lower()],
                capture_output=True, text=True, timeout=10,
            )
            return result, [
                line.replace(str(root) + "/", "") for line in (root / "calls").read_text().splitlines()
            ]

    def test_loads_manifest_images_and_validates_compose_tags_before_offline_start(self):
        result, calls = self.run_startup()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, [
            "compose config --images",
            "docker image load -i images/web.tar",
            "docker image inspect jiuzhang-runtime-jiuzhang-web:50c8996de63e5299b2ce35b0",
            "compose up -d --pull never --no-build",
        ])

    def test_missing_tag_blocks_startup(self):
        result, calls = self.run_startup(missing=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("jiuzhang-runtime-jiuzhang-web:50c8996de63e5299b2ce35b0", result.stderr)
        self.assertFalse(any(call.startswith("compose up") for call in calls))

    def test_failed_load_blocks_startup(self):
        result, calls = self.run_startup(load_error=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("images/web.tar", result.stderr)
        self.assertEqual(calls, ["compose config --images", "docker image load -i images/web.tar"])

    def test_invalid_compose_does_not_load_images(self):
        result, calls = self.run_startup(config_error=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, ["compose config --images"])

    def test_historical_package_can_use_preloaded_images(self):
        result, calls = self.run_startup(manifest_verified=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(call.startswith("docker image load") for call in calls))
        self.assertEqual(calls[-1], "compose up -d --pull never --no-build")

    def test_checkout_keeps_existing_startup(self):
        result, calls = self.run_startup(offline=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, ["compose up -d"])
