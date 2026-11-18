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
        self.env = dict(os.environ)
        self.env.update({
            "PATH": str(self.bin) + os.pathsep + self.env["PATH"],
            "HOSTCTL_EXPECT_UID": str(os.getuid()),
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
        return json.loads((self.hostctl / "pcap-status.json").read_text())

    def test_enable_signs_prepares_api_then_starts_capture(self):
        self.command()
        result = self.run_hostctl()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.status()["state"], "ENABLED")
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
