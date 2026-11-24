"""手动 apply.sh/rollback.sh 的 gateway 跨启动契约回归。

Docker 与 API 均为临时目录内的夹具；这些用例不代表真实 1.3.0 镜像往返。
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
BIND_ENTRYPOINT = "/usr/local/bin/wdsp-gateway-bind"
LEGACY_ENTRYPOINT = "/usr/local/bin/docker-entrypoint.sh"

DOCKER_STUB = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import stat
import sys

fixture = json.loads(Path(os.environ["DOCKER_FIXTURE"]).read_text())
args = sys.argv[1:]

def log(event):
    with open(os.environ["DOCKER_LOG"], "a") as stream:
        stream.write(json.dumps(event, sort_keys=True) + "\n")

def image(ref):
    if ref in fixture["images"]:
        return fixture["images"][ref]
    for candidate in fixture["images"].values():
        if candidate["id"] == ref:
            return candidate
    return None

if args[:2] == ["image", "inspect"]:
    fmt = ""
    ref = ""
    rest = args[2:]
    index = 0
    while index < len(rest):
        value = rest[index]
        if value == "--format":
            fmt = rest[index + 1]
            index += 2
            continue
        if value.startswith("--format="):
            fmt = value.split("=", 1)[1]
        elif not value.startswith("-"):
            ref = value
        index += 1
    log({"kind": "inspect", "ref": ref, "format": fmt})
    found = image(ref)
    if found is None:
        sys.exit(1)
    if fmt == "{{.Id}}":
        print(found["id"])
    elif fmt == "{{json .Config.Entrypoint}}":
        print(json.dumps(found.get("entrypoint")))
    sys.exit(0)

if args[:1] == ["tag"]:
    log({"kind": "tag", "source": args[1], "target": args[2]})
    found = image(args[1])
    if found is None:
        sys.exit(1)
    fixture["images"][args[2]] = dict(found)
    Path(os.environ["DOCKER_FIXTURE"]).write_text(json.dumps(fixture))
    sys.exit(0)

if args[:1] == ["load"]:
    log({"kind": "load", "args": args})
    for ref, loaded in fixture.get("load_images", {}).items():
        fixture["images"][ref] = loaded
    Path(os.environ["DOCKER_FIXTURE"]).write_text(json.dumps(fixture))
    sys.exit(0)

if args[:1] == ["run"]:
    log({"kind": "run", "args": args})
    if fixture.get("fail_migration_rollback"):
        sys.exit(1)
    if "migrations" in fixture and fixture["migrations"]:
        fixture["migrations"].pop()
        fixture["schema"] = max(fixture["migrations"]) if fixture["migrations"] else 0
        Path(os.environ["DOCKER_FIXTURE"]).write_text(json.dumps(fixture))
    elif "schema" in fixture:
        fixture["schema"] -= 1
        Path(os.environ["DOCKER_FIXTURE"]).write_text(json.dumps(fixture))
    sys.exit(0)

if args[:1] == ["inspect"]:
    fmt = args[args.index("--format") + 1]
    container_id = args[-1]
    running = next((v for v in fixture.get("running", {}).values() if v["id"] == container_id), None)
    extra_c = fixture.get("extra_containers", {}).get(container_id)
    target = running if running is not None else extra_c
    if target is None:
        sys.exit(1)
    log({"kind": "container-inspect", "id": container_id, "format": fmt})
    if fmt == "{{.State.Status}}":
        print(target.get("state", "running"))
    elif fmt == "{{.State.Running}}|{{.Name}}":
        is_running = "true" if target.get("running", target.get("state", "running") == "running") else "false"
        cname = target.get("name", container_id)
        if not cname.startswith("/"):
            cname = "/" + cname
        print(f"{is_running}|{cname}")
    elif fmt == "{{json .NetworkSettings.Networks}}":
        print(json.dumps({n: {} for n in target.get("networks", [])}))
    elif fmt == "{{json .Mounts}}":
        print(json.dumps(target.get("mounts", [])))
    else:
        image_id = target.get("image_id", target.get("image", ""))
        if fmt.endswith("{{.State.StartedAt}}"):
            print(f"{target.get('state', 'running')}|{target.get('health', 'healthy')}|{image_id}|0|2026-11-18T00:00:00Z")
        else:
            print(f"{target.get('state', 'running')}|{target.get('health', 'healthy')}|{image_id}")
    sys.exit(0)

if args[:1] == ["network"]:
    sub = args[1] if len(args) > 1 else ""
    if sub == "inspect" and len(args) >= 3:
        net = args[2]
        log({"kind": "network-inspect", "network": net})
        sys.exit(0 if net in fixture.get("networks", []) else 1)
    if sub == "connect" and len(args) >= 4:
        net, cid = args[2], args[3]
        log({"kind": "network-connect", "network": net, "container": cid})
        if fixture.get("fail_network_connect_once"):
            fixture["fail_network_connect_once"] = False
            Path(os.environ["DOCKER_FIXTURE"]).write_text(json.dumps(fixture))
            sys.exit(1)
        if fixture.get("fail_network_connect"):
            sys.exit(1)
        if net not in fixture.get("networks", []):
            sys.exit(1)
        target = next((v for v in fixture.get("running", {}).values() if v["id"] == cid), None)
        if target is None:
            sys.exit(1)
        nets = target.setdefault("networks", [])
        if net not in nets:
            nets.append(net)
        Path(os.environ["DOCKER_FIXTURE"]).write_text(json.dumps(fixture))
        sys.exit(0)
    sys.exit(1)

if args[:1] == ["exec"]:
    log({"kind": "exec", "args": args})
    cmd_str = " ".join(args)
    if "schema" in fixture and args[1] == fixture.get("postgres_id"):
        if "SELECT COUNT(*)" in cmd_str and "WHERE version >" in cmd_str:
            after = cmd_str.split("WHERE version >", 1)[1].strip().split()[0].strip("'\"")
            before_v = int(after)
            if "migrations" in fixture:
                print(sum(1 for v in fixture["migrations"] if v > before_v))
            else:
                print(max(0, int(fixture["schema"]) - before_v))
        else:
            print(fixture["schema"])
    elif fixture.get("migrate_api") and args[1] == fixture.get("running", {}).get("api", {}).get("id") \
            and fixture["running"]["api"].get("image_id") == "sha256:server-new":
        if "target_migrations" in fixture:
            fixture["migrations"] = list(fixture["target_migrations"])
            fixture["schema"] = max(fixture["migrations"])
        else:
            fixture["schema"] = fixture["target_schema"]
        Path(os.environ["DOCKER_FIXTURE"]).write_text(json.dumps(fixture))
    sys.exit(0 if not fixture.get("fail_probe") else 1)

if args[:1] == ["volume"]:
    sub = args[1] if len(args) > 1 else ""
    volumes = fixture.setdefault("volumes", {})
    if sub == "inspect":
        fmt = ""
        name = ""
        rest = args[2:]
        idx = 0
        while idx < len(rest):
            if rest[idx] == "--format":
                fmt = rest[idx + 1]
                idx += 2
                continue
            if rest[idx].startswith("--format="):
                fmt = rest[idx].split("=", 1)[1]
            elif not rest[idx].startswith("-"):
                name = rest[idx]
            idx += 1
        log({"kind": "volume-inspect", "name": name, "format": fmt})
        vol = volumes.get(name)
        if vol is None:
            sys.exit(1)
        if fmt == "{{.Mountpoint}}":
            print(vol["mountpoint"])
        else:
            print(json.dumps(vol))
        sys.exit(0)
    if sub == "create":
        labels = {}
        name = ""
        rest = args[2:]
        idx = 0
        while idx < len(rest):
            if rest[idx] == "--label":
                k, _, v = rest[idx + 1].partition("=")
                labels[k] = v
                idx += 2
                continue
            if rest[idx].startswith("--label="):
                k, _, v = rest[idx].split("=", 1)[1].partition("=")
                labels[k] = v
            elif not rest[idx].startswith("-"):
                name = rest[idx]
            idx += 1
        root = Path(fixture.get("volume_root", str(Path(os.environ["DOCKER_FIXTURE"]).parent / "volumes")))
        mp = root / name / "_data"
        mp.mkdir(parents=True, exist_ok=True)
        volumes[name] = {"mountpoint": str(mp), "labels": labels}
        Path(os.environ["DOCKER_FIXTURE"]).write_text(json.dumps(fixture))
        log({"kind": "volume-create", "name": name, "labels": labels, "mountpoint": str(mp)})
        print(name)
        sys.exit(0)
    sys.exit(1)

if args[:1] == ["compose"]:
    files = []
    env_file = ""
    index = 1
    while index < len(args):
        value = args[index]
        if value == "-f":
            files.append(args[index + 1])
            index += 2
            continue
        if value == "--env-file":
            env_file = args[index + 1]
            index += 2
            continue
        index += 1
    action = next((a for a in ("config", "up", "ps", "rm", "stop") if a in args), "other")
    log({"kind": "compose", "action": action, "files": files, "env_file": env_file, "args": args})
    if action == "up":
        if fixture.get("fail_up"):
            sys.exit(1)
        rendered = json.loads(Path(files[0]).read_text())
        running = fixture.setdefault("running", {})
        for service in args[args.index("up") + 1:]:
            if service.startswith("-") or service not in rendered["services"]:
                continue
            ref = rendered["services"][service]["image"]
            svc_nets = rendered["services"][service].get("networks")
            top_nets = rendered.get("networks") or {}
            proj = rendered.get("name") or ""
            resolved_nets = []
            if isinstance(svc_nets, list):
                keys = svc_nets
            elif isinstance(svc_nets, dict):
                keys = list(svc_nets.keys())
            else:
                keys = []
            for key in keys:
                explicit = (top_nets.get(key) or {}).get("name") if isinstance(top_nets.get(key), dict) else None
                if explicit:
                    resolved_nets.append(explicit)
                elif proj:
                    resolved_nets.append(f"{proj}_{key}")
                else:
                    resolved_nets.append(key)
            running[service] = {
                "id": f"{list(rendered['services']).index(service) + 1:064x}",
                "image": ref,
                "image_id": image(ref)["id"],
                "networks": resolved_nets,
            }
        Path(os.environ["DOCKER_FIXTURE"]).write_text(json.dumps(fixture))
        sys.exit(0)
    if action == "ps":
        service = args[-1]
        if service == "postgres" and "schema" in fixture:
            print(fixture.get("postgres_id", "a" * 64))
            sys.exit(0)
        running = fixture.get("running", {}).get(service)
        if running:
            print(running["id"])
            sys.exit(0)
        sys.exit(1)
    if action in ("rm", "stop"):
        sys.exit(0)
    if action != "config":
        sys.exit(1)
    rendered = json.loads(Path(files[0]).read_text())
    if len(files) > 1:
        override = Path(files[1])
        text = override.read_text()
        required = [
            "entrypoint: !override",
            "cap_add: !reset",
            "cap_drop: !reset",
        ]
        if not all(item in text for item in required):
            sys.exit(1)
        gateway = rendered["services"]["gateway"]
        gateway["entrypoint"] = ["/usr/local/bin/docker-entrypoint.sh"]
        gateway["user"] = "1000:1000"
        if fixture.get("reset_ignores_values"):
            gateway.pop("cap_add", None)
            gateway.pop("cap_drop", None)
        else:
            gateway["cap_add"] = ["NET_BIND_SERVICE"]
            gateway["cap_drop"] = ["ALL"]
        if fixture.get("bad_override"):
            gateway["cap_add"].append("SETUID")
        value_overrides = []
        if len(files) > 2:
            for value_file in files[2:]:
                value_path = Path(value_file)
                value_text = value_path.read_text()
                if 'cap_add: ["NET_BIND_SERVICE"]' not in value_text or 'cap_drop: ["ALL"]' not in value_text:
                    sys.exit(1)
                value_overrides.append({
                    "path": str(value_path),
                    "mode": stat.S_IMODE(value_path.stat().st_mode),
                    "text": value_text,
                })
            gateway["cap_add"] = ["NET_BIND_SERVICE"]
            gateway["cap_drop"] = ["ALL"]
        Path(os.environ["OVERRIDE_CAPTURE"]).write_text(json.dumps({
            "path": str(override),
            "mode": stat.S_IMODE(override.stat().st_mode),
            "text": text,
            "value_overrides": value_overrides,
        }))
    print(json.dumps(rendered))
    sys.exit(0)

log({"kind": "other", "args": args})
sys.exit(1)
'''

CURL_STUB = r'''#!/usr/bin/env python3
import sys

args = " ".join(sys.argv[1:])
if "/api/v1/auth/login" in args:
    print('{"code":"SUCCESS","data":{"csrf_token":"fixture-csrf"}}')
elif "-X POST" in args and "/api/v1/backups" in args:
    print('{"code":"SUCCESS","data":{"job":{"id":"00000000-0000-4000-8000-000000000001"}}}')
elif "/api/v1/backups/00000000-0000-4000-8000-000000000001" in args:
    print('{"data":{"job":{"status":"SUCCESS","verified":true}}}')
sys.exit(0)
'''


class GatewayRuntimeContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.work = Path(self.temp.name)
        self.upgrade_dir = self.work / "ops/upgrade"
        self.upgrade_dir.mkdir(parents=True)
        (self.work / "ops/lib").mkdir(parents=True)
        (self.work / "ops/healthcheck").mkdir(parents=True)
        self.apply = self.upgrade_dir / "apply.sh"
        self.rollback = self.upgrade_dir / "rollback.sh"
        shutil.copy2(ROOT / "ops/upgrade/apply.sh", self.apply)
        shutil.copy2(ROOT / "ops/upgrade/rollback.sh", self.rollback)
        shutil.copy2(ROOT / "ops/lib/common.sh", self.work / "ops/lib/common.sh")

        self.bin = self.work / "bin"
        self.bin.mkdir()
        self.write_executable(self.bin / "docker", DOCKER_STUB)
        self.write_executable(self.bin / "curl", CURL_STUB)
        self.write_executable(
            self.bin / "timeout",
            '#!/usr/bin/env bash\nshift\nexec "$@"\n',
        )
        self.write_executable(
            self.bin / "mv",
            '#!/usr/bin/env python3\nimport os, sys\n'
            'if sys.argv[1:2] == ["-Tf"]:\n'
            ' os.replace(sys.argv[2], sys.argv[3])\n'
            'else:\n'
            ' os.execv("/bin/mv", ["mv"] + sys.argv[1:])\n',
        )
        self.health_log = self.work / "health.log"
        self.write_executable(
            self.work / "ops/healthcheck/check.sh",
            '#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "$HEALTH_LOG"\n',
        )
        self.target_release = self.work / "target-release"
        target_install = self.target_release / "ops/install"
        target_install.mkdir(parents=True)
        self.hostctl_log = self.work / "hostctl-helper.log"
        self.hostctl_helper = target_install / "install-hostctl.sh"
        self.write_executable(
            self.hostctl_helper,
            '#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "$HOSTCTL_HELPER_LOG"\n',
        )

        self.old_compose = (self.work / "old-compose.yml").resolve()
        self.new_compose = (self.target_release / "new-compose.yml").resolve()
        self.env_file = (self.work / "fixture.env").resolve()
        self.old_compose.write_text(json.dumps(self.compose_config(old=True)))
        self.new_compose.write_text(json.dumps(self.compose_config(old=False)))
        self.env_file.write_text("FIXTURE_ONLY=1\n")
        self.state = self.upgrade_dir / ".upgrade-state.env"
        self.fixture_file = self.work / "docker-fixture.json"
        self.docker_log = self.work / "docker-events.jsonl"
        self.override_capture = self.work / "override-capture.json"
        self.tmpdir = self.work / "tmp"
        self.tmpdir.mkdir()
        self.write_fixture()

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def write_executable(path, content):
        path.write_text(content)
        path.chmod(0o755)

    @staticmethod
    def compose_config(old):
        gateway = {
            "image": "fixture-gateway:old-stable" if old else "fixture-gateway:target-stable",
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
        }
        if old:
            gateway["cap_add"] = ["NET_BIND_SERVICE"]
        else:
            gateway.update({
                "user": "0:0",
                "entrypoint": [BIND_ENTRYPOINT],
                "cap_add": ["NET_BIND_SERVICE", "SETUID", "SETGID", "SETPCAP"],
            })
        return {
            "services": {
                "api": {"image": "fixture-server:old-stable" if old else "fixture-server:target-stable"},
                "gateway": gateway,
                "netmgrd": {"image": "fixture-netmgrd:stable"},
            }
        }

    def write_fixture(self, new_entrypoint=BIND_ENTRYPOINT, old_entrypoint=LEGACY_ENTRYPOINT, bad_override=False):
        images = {
            "fixture-server:old-stable": {"id": "sha256:server-old", "entrypoint": None},
            "fixture-gateway:old-stable": {"id": "sha256:gateway-old", "entrypoint": [old_entrypoint]},
            "fixture-server:target-stable": {"id": "sha256:server-target-tag", "entrypoint": None},
            "fixture-gateway:target-stable": {"id": "sha256:gateway-target-tag", "entrypoint": [BIND_ENTRYPOINT]},
            "fixture-server:new": {"id": "sha256:server-new", "entrypoint": None},
            "fixture-netmgrd:stable": {"id": "sha256:netmgrd-stable", "entrypoint": None},
            "fixture-gateway:new": {"id": "sha256:gateway-new", "entrypoint": [new_entrypoint]},
        }
        self.fixture_file.write_text(json.dumps({"images": images, "bad_override": bad_override}))

    def run_script(self, script, *args, stdin=None, timeout=120):
        env = os.environ.copy()
        env.update({
            "PATH": str(self.bin) + os.pathsep + env["PATH"],
            "TMPDIR": str(self.tmpdir),
            "DOCKER_FIXTURE": str(self.fixture_file),
            "DOCKER_LOG": str(self.docker_log),
            "OVERRIDE_CAPTURE": str(self.override_capture),
            "HEALTH_LOG": str(self.health_log),
            "HOSTCTL_HELPER_LOG": str(self.hostctl_log),
            "JZ_ADMIN_PASSWORD": "fixture-only-password",
            "JZ_CAPTCHA_CODE": "fixture-captcha",
            "LC_ALL": "C",
            "LANG": "C",
        })
        if stdin is not None:
            env.pop("JZ_ADMIN_PASSWORD", None)
        # Full-upgrade + automatic rollback across 7-9 services and 13 images runs 120+
        # docker stub subprocesses plus apply.sh's 10s post-start stability hold,
        # which can exceed 45s under concurrent test load without any real hang.
        return subprocess.run(
            ["/bin/bash", str(script)] + [str(arg) for arg in args],
            cwd=self.work,
            input=stdin,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def run_apply(self, dual_compose=True):
        args = [
            "--server-image", "fixture-server:new",
            "--gateway-image", "fixture-gateway:new",
            "--compose-file", self.old_compose,
            "--env-file", self.env_file,
            "--timeout", "1",
        ]
        if dual_compose:
            args.extend(["--new-compose-file", self.new_compose])
        return self.run_script(self.apply, *args)

    def write_state(self, target=None):
        target = Path(target) if target else self.new_compose
        self.state.write_text(
            "OLD_SERVER_IMAGE=fixture-server:old-stable\n"
            "OLD_GATEWAY_IMAGE=fixture-gateway:old-stable\n"
            "OLD_SERVER_IMAGE_ID=sha256:server-old\n"
            "OLD_GATEWAY_IMAGE_ID=sha256:gateway-old\n"
            "NEW_SERVER_IMAGE=fixture-server:new\n"
            "NEW_GATEWAY_IMAGE=fixture-gateway:new\n"
            f"TARGET_COMPOSE_FILE={target}\n"
            f"TARGET_ENV_FILE={self.env_file}\n"
            "BACKUP_JOB_ID=00000000-0000-4000-8000-000000000001\n"
        )
        self.state.chmod(0o600)

    def events(self):
        if not self.docker_log.exists():
            return []
        return [json.loads(line) for line in self.docker_log.read_text().splitlines()]

    def state_values(self):
        return dict(
            line.split("=", 1)
            for line in self.state.read_text().splitlines()
            if line and not line.startswith("#")
        )

    def digest(self, path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def assert_user_files_unchanged(self, before):
        for path, expected in before.items():
            self.assertEqual(self.digest(path), expected)

    def test_apply_dual_compose_uses_old_ids_and_target_runtime(self):
        before = {path: self.digest(path) for path in (self.old_compose, self.new_compose, self.env_file)}
        result = self.run_apply()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        state = self.state_values()
        self.assertEqual(state["OLD_SERVER_IMAGE"], "fixture-server:old-stable")
        self.assertEqual(state["OLD_GATEWAY_IMAGE"], "fixture-gateway:old-stable")
        self.assertEqual(state["OLD_SERVER_IMAGE_ID"], "sha256:server-old")
        self.assertEqual(state["OLD_GATEWAY_IMAGE_ID"], "sha256:gateway-old")
        self.assertNotEqual(state["OLD_GATEWAY_IMAGE_ID"], "sha256:gateway-target-tag")
        self.assertEqual(state["TARGET_COMPOSE_FILE"], str(self.new_compose.resolve()))
        self.assertEqual(state["TARGET_ENV_FILE"], str(self.env_file.resolve()))
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o600)

        events = self.events()
        tags = [(event["source"], event["target"]) for event in events if event["kind"] == "tag"]
        self.assertEqual(tags, [
            ("fixture-server:new", "fixture-server:target-stable"),
            ("fixture-gateway:new", "fixture-gateway:target-stable"),
        ])
        ups = [event for event in events if event["kind"] == "compose" and event["action"] == "up"]
        self.assertEqual(len(ups), 1)
        self.assertEqual(ups[0]["files"], [str(self.new_compose)])
        self.assertEqual(ups[0]["env_file"], str(self.env_file))
        self.assertIn("--force-recreate", ups[0]["args"])
        health = self.health_log.read_text().splitlines()
        self.assertEqual(len(health), 2)
        self.assertIn(str(self.old_compose), health[0])
        self.assertIn(str(self.new_compose), health[1])
        self.assertEqual(
            self.hostctl_log.read_text(encoding="utf-8").splitlines(),
            [f"--install-root {self.target_release.resolve()} --strict"],
        )
        self.assert_user_files_unchanged(before)

    def test_apply_target_hostctl_helper_failure_is_explicit(self):
        self.write_executable(
            self.hostctl_helper,
            '#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "$HOSTCTL_HELPER_LOG"\nexit 1\n',
        )
        result = self.run_apply()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("升级后 hostctl 单元更新失败", result.stderr)
        self.assertIn(str(self.target_release.resolve()), result.stderr)
        self.assertEqual(
            self.hostctl_log.read_text(encoding="utf-8").splitlines(),
            [f"--install-root {self.target_release.resolve()} --strict"],
        )

    def test_apply_bind_image_with_old_compose_fails_before_state_or_retag(self):
        result = self.run_apply(dual_compose=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--new-compose-file", result.stderr)
        self.assertFalse(self.state.exists())
        self.assertFalse([event for event in self.events() if event["kind"] == "tag"])
        self.assertFalse([event for event in self.events() if event["kind"] == "compose" and event["action"] == "up"])

    def test_apply_rejects_unknown_actual_entrypoint(self):
        self.write_fixture(new_entrypoint="/usr/local/bin/unknown-entrypoint")
        result = self.run_apply()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("未知 gateway 镜像入口", result.stderr)
        self.assertFalse(self.state.exists())
        self.assertFalse([event for event in self.events() if event["kind"] == "tag"])

    def test_rollback_legacy_on_new_compose_renders_exact_override_and_cleans_up(self):
        self.write_state()
        before = {path: self.digest(path) for path in (self.old_compose, self.new_compose, self.env_file)}
        result = self.run_script(self.rollback, "--yes", "--timeout", "1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        capture = json.loads(self.override_capture.read_text())
        override = Path(capture["path"])
        self.assertFalse(override.exists())
        self.assertEqual(capture["mode"], 0o600)
        text = capture["text"]
        self.assertIn(f'entrypoint: !override ["{LEGACY_ENTRYPOINT}"]', text)
        self.assertIn('user: "1000:1000"', text)
        self.assertIn('cap_add: !reset ["NET_BIND_SERVICE"]', text)
        self.assertIn('cap_drop: !reset ["ALL"]', text)
        self.assertNotIn("security_opt", text)

        events = self.events()
        rendered_index = next(
            index for index, event in enumerate(events)
            if event["kind"] == "compose" and event["action"] == "config" and len(event["files"]) == 2
        )
        first_tag = next(index for index, event in enumerate(events) if event["kind"] == "tag")
        up_index = next(
            index for index, event in enumerate(events)
            if event["kind"] == "compose" and event["action"] == "up"
        )
        self.assertLess(rendered_index, first_tag)
        self.assertLess(first_tag, up_index)
        self.assertEqual(events[up_index]["files"], [str(self.new_compose), str(override)])
        self.assertEqual(events[up_index]["env_file"], str(self.env_file))
        self.assertIn("--force-recreate", events[up_index]["args"])
        tags = [(event["source"], event["target"]) for event in events if event["kind"] == "tag"]
        self.assertEqual(tags, [
            ("sha256:server-old", "fixture-server:target-stable"),
            ("sha256:gateway-old", "fixture-gateway:target-stable"),
            ("sha256:netmgrd-stable", "fixture-netmgrd:stable"),
        ])
        self.assert_user_files_unchanged(before)

    def test_rollback_reset_ignoring_compose_uses_and_cleans_value_overlay(self):
        self.write_state()
        fixture = json.loads(self.fixture_file.read_text())
        fixture["reset_ignores_values"] = True
        self.fixture_file.write_text(json.dumps(fixture))
        result = self.run_script(self.rollback, "--yes", "--timeout", "1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        capture = json.loads(self.override_capture.read_text())
        self.assertFalse(Path(capture["path"]).exists())
        self.assertEqual(len(capture["value_overrides"]), 1)
        value_override = capture["value_overrides"][0]
        self.assertEqual(value_override["mode"], 0o600)
        self.assertFalse(Path(value_override["path"]).exists())
        self.assertIn('cap_add: ["NET_BIND_SERVICE"]', value_override["text"])
        self.assertIn('cap_drop: ["ALL"]', value_override["text"])
        ups = [event for event in self.events() if event["kind"] == "compose" and event["action"] == "up"]
        self.assertEqual(len(ups), 1)
        self.assertEqual(ups[0]["files"], [
            str(self.new_compose), capture["path"], value_override["path"],
        ])
        final_render = [
            event for event in self.events()
            if event["kind"] == "compose" and event["action"] == "config" and len(event["files"]) == 3
        ]
        self.assertEqual(len(final_render), 1)

    def test_rollback_bad_override_render_fails_before_retag_and_cleans_up(self):
        self.write_state()
        self.write_fixture(bad_override=True)
        result = self.run_script(self.rollback, "--yes", "--timeout", "1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("禁止 retag/up", result.stderr)
        capture = json.loads(self.override_capture.read_text())
        self.assertFalse(Path(capture["path"]).exists())
        self.assertFalse([event for event in self.events() if event["kind"] == "tag"])
        self.assertFalse([event for event in self.events() if event["kind"] == "compose" and event["action"] == "up"])

    def test_rollback_bind_image_with_old_compose_fails_closed(self):
        self.write_state(target=self.old_compose)
        self.write_fixture(old_entrypoint=BIND_ENTRYPOINT)
        result = self.run_script(self.rollback, "--yes", "--timeout", "1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("旧 Compose 不符合新运行契约", result.stderr)
        self.assertFalse([event for event in self.events() if event["kind"] == "tag"])
        self.assertFalse([event for event in self.events() if event["kind"] == "compose" and event["action"] == "up"])

    def test_rollback_rejects_unknown_old_entrypoint(self):
        self.write_state()
        self.write_fixture(old_entrypoint="/usr/local/bin/unknown-entrypoint")
        result = self.run_script(self.rollback, "--yes", "--timeout", "1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("未知 gateway 镜像入口", result.stderr)
        self.assertFalse(self.override_capture.exists())
        self.assertFalse([event for event in self.events() if event["kind"] == "tag"])

    def test_rollback_legacy_on_old_compose_does_not_need_override(self):
        self.write_state(target=self.old_compose)
        result = self.run_script(self.rollback, "--yes", "--timeout", "1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.override_capture.exists())
        ups = [event for event in self.events() if event["kind"] == "compose" and event["action"] == "up"]
        self.assertEqual(len(ups), 1)
        self.assertEqual(ups[0]["files"], [str(self.old_compose)])


if __name__ == "__main__":
    unittest.main()
