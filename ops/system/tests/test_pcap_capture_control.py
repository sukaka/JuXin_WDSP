import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
import uuid
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[3]
DOCKER_STUB = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ["FAKE_DOCKER_LOG"], "a") as stream:
    stream.write(json.dumps(args) + "\n")
if args[:1] == ["compose"]:
    if "ps" in args:
        print("a" * 64 if args[-1] == "api" else "b" * 64)
        sys.exit(0)
    if "up" in args:
        if args[-1] == "api":
            public = pathlib.Path(os.environ["FAKE_REPO_ROOT"]) / "runtime/pcap-public"
            public.mkdir(parents=True, exist_ok=True)
            (public / "pcap-public.json").write_text('{"fixture":true}')
            (public / "pcap-release.pub").write_text('fixture-public-key')
        sys.exit(0)
    if "stop" in args:
        sys.exit(0)
if args[:1] == ["inspect"]:
    if args[-1] == "jiuzhang-pcapd" and "--format" not in args and os.environ.get("PCAP_PRESENT") != "1":
        sys.exit(1)
    if "{{.State.Running}}" in args:
        print("false")
    else:
        print("running|healthy")
    sys.exit(0)
sys.exit(1)
'''


class CaptureControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wdsp-pcap-control-")
        self.root = Path(self.temp.name).resolve()
        self.repo = self.root / "release"
        (self.repo / "runtime/hostctl").mkdir(parents=True)
        (self.repo / "ops/system").mkdir(parents=True)
        (self.repo / "ops/lib").mkdir(parents=True)
        shutil.copy2(ROOT / "ops/system/hostctl-exec.sh", self.repo / "ops/system/hostctl-exec.sh")
        shutil.copy2(ROOT / "ops/system/pcap_capture_control.py", self.repo / "ops/system/pcap_capture_control.py")
        shutil.copy2(ROOT / "ops/lib/common.sh", self.repo / "ops/lib/common.sh")
        (self.repo / "docker-compose.yml").write_text("services: {}\n")
        self.original_env = "FIXTURE_ONLY=1\n"
        (self.repo / ".env").write_text(self.original_env)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        docker = self.bin / "docker"
        docker.write_text(DOCKER_STUB)
        docker.chmod(0o755)
        self.log = self.root / "docker.jsonl"
        self.nonce_file = self.root / "hostctl-nonces.json"
        self.lock_file = self.root / "hostctl.lock"
        self.env = dict(os.environ)
        self.env.update({
            "PATH": str(self.bin) + os.pathsep + self.env["PATH"],
            "HOSTCTL_EXPECT_UID": str(os.getuid()),
            "HOSTCTL_NONCE_FILE": str(self.nonce_file),
            "HOSTCTL_LOCK_FILE": str(self.lock_file),
            "PCAP_TEST_ALLOW_NON_ROOT": "1",
            "PCAP_TEST_ALLOWED_ROOT": str(self.root),
            "FAKE_DOCKER_LOG": str(self.log),
            "FAKE_REPO_ROOT": str(self.repo),
        })
        self.hostctl = self.repo / "runtime/hostctl"
        self.hot = self.root / "hot"
        self.warm = self.root / "warm"
        self.secret = os.urandom(32).hex()
        (self.hostctl / ".hostctl-secret").write_text(self.secret + "\n")
        (self.hostctl / ".hostctl-secret").chmod(0o600)

    def tearDown(self):
        self.temp.cleanup()

    def command(self, enabled=True):
        request_id = str(uuid.uuid4())
        ports = [443, 80]
        fields = ["v3", "pcap_capture", "system-admin", str(uuid.uuid4()), request_id,
                  datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), "0",
                  "80,443", "eth0", str(self.hot), str(self.warm), "gw-test", str(enabled).lower()]
        payload = "\n".join(fields)
        command = {
            "action": "pcap_capture", "requestedBy": fields[2], "userID": fields[3],
            "requestID": request_id, "requestedAt": fields[5], "delaySeconds": 0,
            "ports": ports, "interface": "eth0", "hot_dir": str(self.hot),
            "warm_dir": str(self.warm), "node_id": "gw-test", "enabled": enabled,
            "hmac": hmac.new(self.secret.encode(), payload.encode(), hashlib.sha256).hexdigest(),
        }
        path = self.hostctl / f"pcap_capture-{time.time_ns()}-{request_id}.json"
        path.write_text(json.dumps(command))
        return path

    def run_hostctl(self):
        return subprocess.run(["bash", str(self.repo / "ops/system/hostctl-exec.sh"), str(self.hostctl)],
                              env=self.env, capture_output=True, text=True, timeout=35)

    def calls(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def status(self):
        return json.loads((self.hostctl / "pcap-status.state").read_text())

    def test_enable_signs_prepares_api_then_starts_capture(self):
        self.command()
        result = self.run_hostctl()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.status()["state"], "ENABLED")
        self.assertFalse((self.hostctl / "pcap-status.json").exists())
        control = (self.repo / "runtime/pcap-control.env").read_text()
        self.assertIn("REQUEST_PCAP_CAPTURE_ENABLED=true", control)
        self.assertIn("REQUEST_PCAP_PORTS=80,443", control)
        self.assertEqual((self.repo / ".env").read_text(), self.original_env)
        self.assertIn("FIXTURE_ONLY=1", (self.repo / "runtime/pcap-runtime.env").read_text())
        calls = self.calls()
        api = next(i for i, args in enumerate(calls) if "up" in args and args[-1] == "api")
        capture = next(i for i, args in enumerate(calls) if "up" in args and args[-1] == "pcapd")
        self.assertLess(api, capture)
        self.assertTrue(self.hot.is_dir() and self.warm.is_dir())

    def test_status_state_survives_second_hostctl_run(self):
        self.command()
        first = self.run_hostctl()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        state_file = self.hostctl / "pcap-status.state"
        self.assertTrue(state_file.is_file())
        before = state_file.read_text()
        # Defensive check: even a stray pcap-status.json must be ignored by hostctl-exec.sh
        stray = self.hostctl / "pcap-status.json"
        stray.write_text('{"state":"LEGACY"}\n')
        second = self.run_hostctl()
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertTrue(state_file.is_file())
        self.assertEqual(state_file.read_text(), before)
        self.assertTrue(stray.is_file())
        self.assertFalse((self.hostctl / "pcap-status.json.done").exists())

    def test_merges_existing_compose_profiles(self):
        (self.repo / ".env").write_text("FIXTURE_ONLY=1\nCOMPOSE_PROFILES=apm,custom\n")
        self.command()
        result = self.run_hostctl()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        control = (self.repo / "runtime/pcap-control.env").read_text()
        self.assertIn("COMPOSE_PROFILES=apm,custom,request-pcap", control)
        runtime_env = (self.repo / "runtime/pcap-runtime.env").read_text()
        self.assertIn("COMPOSE_PROFILES=apm,custom,request-pcap", runtime_env)

    def test_allowed_roots_restrict_to_jiuzhang_prefixes(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("pcap_ctrl", ROOT / "ops/system/pcap_capture_control.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        saved_mode = mod.TEST_MODE
        try:
            mod.TEST_MODE = False
            roots = mod.allowed_roots()
            self.assertEqual(roots, (
                "/var/lib/jiuzhang-pcap/",
                "/var/lib/jiuzhang/",
                "/srv/jiuzhang-",
                "/srv/jiuzhang/",
                "/data/jiuzhang-",
                "/data/jiuzhang/",
                "/mnt/jiuzhang-",
                "/mnt/jiuzhang/",
                "/media/jiuzhang-",
                "/media/jiuzhang/",
            ))
            for bad in ("/var/lib/postgresql/data", "/var/lib/docker/volumes", "/srv/other/pcap", "/data/postgres"):
                self.assertFalse(any(bad.startswith(p) and len(bad) > len(p) for p in roots), bad)
            for good in ("/var/lib/jiuzhang-pcap/hot", "/var/lib/jiuzhang/pcap/warm", "/srv/jiuzhang-ssd/pcap", "/data/jiuzhang/hot"):
                self.assertTrue(any(good.startswith(p) and len(good) > len(p) for p in roots), good)
        finally:
            mod.TEST_MODE = saved_mode

    def test_rejects_symlink_storage_component_and_nonempty_foreign_dir(self):
        # 1) Symlink parent component must be rejected before mkdir
        real_outside = self.root / "outside-target"
        real_outside.mkdir()
        link_parent = self.root / "link-parent"
        link_parent.symlink_to(real_outside)
        self.hot = link_parent / "subhot"
        self.command()
        result = self.run_hostctl()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((real_outside / "subhot").exists())
        self.assertEqual(self.calls(), [])

        # 2) Pre-existing non-empty directory not owned by 1000:1000 must be rejected
        if os.getuid() != 1000:
            self.hot = self.root / "existing-nonempty"
            self.hot.mkdir()
            (self.hot / "keep.txt").write_text("existing-data")
            self.command()
            result = self.run_hostctl()
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(self.calls(), [])

    def test_hostctl_blocks_replay_symlinks_and_processes_fifo(self):
        # No secret passed on openssl -hmac argv
        hostctl_src = (ROOT / "ops/system/hostctl-exec.sh").read_text(encoding="utf-8")
        self.assertNotIn("-hmac", hostctl_src)

        # Replay of identical requestID within skew window must be rejected
        flag1 = self.command(enabled=True)
        payload = flag1.read_text()
        self.assertEqual(self.run_hostctl().returncode, 0)
        self.log.unlink()
        replay_flag = self.hostctl / f"pcap_capture-{time.time_ns()}-replay.json"
        replay_flag.write_text(payload)
        replay_res = self.run_hostctl()
        self.assertNotEqual(replay_res.returncode, 0)
        self.assertIn("重放", replay_res.stderr)
        self.assertEqual(self.calls(), [])

        # Symlink flag file must be rejected without following
        outside_file = self.root / "outside.json"
        outside_file.write_text(payload)
        sym_flag = self.hostctl / "symlink-flag.json"
        sym_flag.symlink_to(outside_file)
        sym_res = self.run_hostctl()
        self.assertNotEqual(sym_res.returncode, 0)
        self.assertIn("符号链接", sym_res.stderr)
        self.assertEqual(self.calls(), [])

        # Symlink HOSTCTL_DIR must be rejected
        sym_dir = self.root / "hostctl-symlink"
        sym_dir.symlink_to(self.hostctl)
        sym_dir_res = subprocess.run(
            ["bash", str(self.repo / "ops/system/hostctl-exec.sh"), str(sym_dir)],
            env=self.env, capture_output=True, text=True, timeout=15,
        )
        self.assertNotEqual(sym_dir_res.returncode, 0)
        self.assertIn("符号链接", sym_dir_res.stderr)

        # FIFO ordering: older flag processed before newer flag (using --dry-run reboot then shutdown)
        def write_v1(action, req_id, mtime):
            ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            canon = "\n".join(["v1", action, "admin", "u1", req_id, ts, "1"])
            mac = hmac.new(self.secret.encode(), canon.encode(), hashlib.sha256).hexdigest()
            p = self.hostctl / f"{action}-{req_id}.json"
            p.write_text(json.dumps({
                "action": action, "requestedBy": "admin", "userID": "u1",
                "requestID": req_id, "requestedAt": ts, "delaySeconds": 1, "hmac": mac,
            }))
            os.utime(p, (mtime, mtime))
            return p

        now = time.time()
        write_v1("shutdown", str(uuid.uuid4()), now - 10)
        write_v1("reboot", str(uuid.uuid4()), now - 2)
        fifo_res = subprocess.run(
            ["bash", str(self.repo / "ops/system/hostctl-exec.sh"), "--dry-run", str(self.hostctl)],
            env=self.env, capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(fifo_res.returncode, 0, fifo_res.stdout + fifo_res.stderr)
        self.assertLess(fifo_res.stdout.index("动作=shutdown"), fifo_res.stdout.index("动作=reboot"))

    def test_disable_stops_capture_and_preserves_evidence_directories(self):
        self.command()
        self.assertEqual(self.run_hostctl().returncode, 0)
        self.log.unlink()
        self.command(enabled=False)
        self.env["PCAP_PRESENT"] = "1"
        result = self.run_hostctl()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.status()["state"], "DISABLED")
        self.assertIn("REQUEST_PCAP_CAPTURE_ENABLED=false", (self.repo / "runtime/pcap-control.env").read_text())
        calls = self.calls()
        stop = next(i for i, args in enumerate(calls) if "stop" in args)
        api = next(i for i, args in enumerate(calls) if "up" in args and args[-1] == "api")
        self.assertLess(stop, api)
        self.assertFalse(any("up" in args and args[-1] == "pcapd" for args in calls))
        self.assertTrue(self.hot.is_dir() and self.warm.is_dir())
        self.assertEqual((self.repo / ".env").read_text(), self.original_env)

    def test_invalid_scope_never_invokes_docker(self):
        flag = self.command()
        data = json.loads(flag.read_text())
        data["interface"] = "eth0;id"
        flag.write_text(json.dumps(data))
        result = self.run_hostctl()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_tampered_scope_is_rejected_before_execution(self):
        flag = self.command()
        data = json.loads(flag.read_text())
        data["interface"] = "eth1"
        flag.write_text(json.dumps(data))
        result = self.run_hostctl()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("HMAC", result.stderr)
        self.assertEqual(self.calls(), [])


if __name__ == "__main__":
    unittest.main()
