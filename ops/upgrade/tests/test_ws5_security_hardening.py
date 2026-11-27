"""WS-5 运维供应链与升级执行器安全加固回归测试。"""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
EXECUTOR = ROOT / "ops/upgrade/upgrade-executor.sh"
RUN_HEADER = ROOT / "ops/install/openeuler-zhaoxin-run-header.sh"


def extract_compose_policy_python() -> str:
    src = EXECUTOR.read_text(encoding="utf-8")
    start_marker = 'if ! sec_err="$(python3 - "$manifest" "$added" "$merged_after_tmp" <<\'PY\' 2>&1\n'
    start = src.index(start_marker) + len(start_marker)
    end = src.index("\nPY\n", start)
    return src[start:end]


class WS5SecurityHardeningTests(unittest.TestCase):
    def run_compose_policy(self, service_def, service_name="netmgrd"):
        script = extract_compose_policy_python()
        with tempfile.TemporaryDirectory(prefix="ws5-compose-policy-") as td:
            base = Path(td)
            merged = base / "merged.json"
            manifest = base / "manifest.json"
            image = f"jiuzhang-{service_name}:1.17.1"
            svc = dict(service_def)
            svc.setdefault("image", image)
            merged.write_text(json.dumps({"services": {service_name: svc}}), encoding="utf-8")
            manifest.write_text(
                json.dumps({"images": [{"service": service_name, "image": image}]}),
                encoding="utf-8",
            )
            return subprocess.run(
                ["python3", "-", str(manifest), service_name, str(merged)],
                input=script,
                capture_output=True,
                text=True,
            )

    def test_forbidden_host_bind_prefixes_reject_runtime_and_opt_paths(self):
        for bad_bind in (
            "/var/run/containerd/containerd.sock:/run/containerd.sock",
            "/run/systemd:/host-run",
            "/var/lib/docker:/host-var",
            "/opt/jiuzhang:/host-opt",
            "/home/ops/.ssh:/host-ssh",
        ):
            with self.subTest(bind=bad_bind):
                res = self.run_compose_policy({"volumes": [bad_bind]})
                self.assertNotEqual(res.returncode, 0, f"expected reject for {bad_bind}")
                self.assertIn("绑定宿主机系统路径", res.stderr)

    def test_named_volume_targeting_var_run_remains_allowed(self):
        res = self.run_compose_policy(
            {
                "volumes": [
                    {
                        "type": "volume",
                        "source": "gateway-admin",
                        "target": "/var/run/caddy",
                    }
                ]
            }
        )
        self.assertEqual(res.returncode, 0, res.stderr)

    def test_failed_job_cleans_up_work_dir(self):
        src = EXECUTOR.read_text(encoding="utf-8")
        self.assertIn('mv "$processing" "${processing%.processing}.failed"', src)
        loop_tail = src[src.index('for queued in "$JOBS_DIR"/*.json; do'):]
        with tempfile.TemporaryDirectory(prefix="ws5-work-cleanup-") as td:
            base = Path(td)
            jobs_dir = base / "jobs"
            work_dir = base / "work"
            jobs_dir.mkdir()
            work_dir.mkdir()
            (jobs_dir / "job-fail-1.json").write_text("{}", encoding="utf-8")
            job_work = work_dir / "job-fail-1"
            job_work.mkdir()
            (job_work / "partial.tar").write_text("stale", encoding="utf-8")
            harness = f"""
set -euo pipefail
JOBS_DIR={json.dumps(str(jobs_dir))}
WORK_DIR={json.dumps(str(work_dir))}
IMAGE_SWITCH_STARTED=false
CURRENT_STAGE="APPLYING"
process_job() {{ return 1; }}
rollback_images() {{ return 0; }}
write_result() {{ return 0; }}
shopt -s nullglob
{loop_tail}
"""
            res = subprocess.run(["bash", "-c", harness], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertFalse(job_work.exists(), "failed job work directory must be cleaned up")
            self.assertTrue((jobs_dir / "job-fail-1.failed").exists())

    def test_openeuler_non_unified_rpms_fail_closed_without_manifest(self):
        src = RUN_HEADER.read_text(encoding="utf-8")
        start = src.index('if [[ "$UNIFIED_PACKAGE" == "true" ]]; then\n  install_selected_rpms')
        end = src.index('RELEASE_DIR="$INSTALL_ROOT/releases/$VERSION_PART"', start)
        snippet = src[start:end]
        with tempfile.TemporaryDirectory(prefix="ws5-rpm-failclosed-") as td:
            work_dir = Path(td)
            rpms_dir = work_dir / "rpms"
            rpms_dir.mkdir()
            (rpms_dir / "unsigned-pkg.rpm").write_bytes(b"fake-rpm")
            dnf_marker = work_dir / "dnf-called"
            harness = f"""
set -euo pipefail
UNIFIED_PACKAGE=false
WORK_DIR={json.dumps(str(work_dir))}
die() {{ printf '%s\\n' "$*" >&2; exit 42; }}
log() {{ :; }}
check_bundled_rpm_platform() {{ return 0; }}
verify_package_signature() {{ return 0; }}
dnf() {{ touch {json.dumps(str(dnf_marker))}; }}
yum() {{ touch {json.dumps(str(dnf_marker))}; }}
{snippet}
"""
            res = subprocess.run(["bash", "-c", harness], capture_output=True, text=True)
            self.assertEqual(res.returncode, 42, res.stdout + res.stderr)
            self.assertIn("缺少清单 rpms/rpms.sha256", res.stderr)
            self.assertFalse(dnf_marker.exists(), "dnf must not execute when rpms.sha256 is missing")


if __name__ == "__main__":
    unittest.main()
