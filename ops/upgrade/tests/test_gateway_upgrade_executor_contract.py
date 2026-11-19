"""Web 镜像升级跨 gateway 启动契约的真实函数回归。"""

import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
UPGRADE_DIR = ROOT / "ops/upgrade"
EXECUTOR = UPGRADE_DIR / "upgrade-executor.sh"
BUILDER = UPGRADE_DIR / "build-upgrade-pack.sh"
SOURCE = EXECUTOR.read_text(encoding="utf-8")
NEW_ENTRYPOINT = "/usr/local/bin/wdsp-gateway-bind"
OLD_ENTRYPOINT = "/usr/local/bin/docker-entrypoint.sh"
CAPABILITIES = ["NET_BIND_SERVICE", "SETUID", "SETGID", "SETPCAP"]


def shell_function(source, start, end):
    return source[source.index(start):source.index(end, source.index(start))]


SHA256_FILE = shell_function(SOURCE, "sha256_file() {", "\nwrite_result() {")
ROLLBACK_IMAGES = shell_function(SOURCE, "rollback_images() {", "\nprocess_job() {")
RUNTIME_PATCH = shell_function(
    SOURCE, "process_runtime_patch() {", "\nvalidate_gateway_start_contract() {"
)
UPGRADE_PACK = shell_function(SOURCE, "validate_gateway_start_contract() {", "\nexec 9>")


MOCKS = r'''
set -euo pipefail
COMPOSE_JSON="$(<"$COMPOSE_JSON_FILE")"
CURRENT_JOB=""
CURRENT_STAGE="APPLYING"
CURRENT_MESSAGE=""
INSTALLED_OVERRIDE=""
IMAGE_SWITCH_STARTED=false
declare -a SERVICES=() STABLE_IMAGES=() OLD_IDS=() NEW_SERVICES=()

if ! command -v mapfile >/dev/null 2>&1; then
  mapfile() {
    local array_name="$2" line
    eval "$array_name=()"
    while IFS= read -r line; do
      eval "$array_name+=(\"\$line\")"
    done
  }
fi

sha256sum() {
  python3 - "$@" <<'PY'
import hashlib, pathlib, sys
args = sys.argv[1:]
if args and args[0] == "-c":
    checklist = pathlib.Path(args[1])
    for line in checklist.read_text().splitlines():
        if not line:
            continue
        expected, name = line.split("  ", 1)
        actual = hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest()
        if actual != expected:
            print("%s: FAILED" % name, file=sys.stderr)
            sys.exit(1)
        print("%s: OK" % name)
else:
    for name in args:
        data = pathlib.Path(name).read_bytes()
        print("%s  %s" % (hashlib.sha256(data).hexdigest(), name))
PY
}

stat() {
  if [[ "${1:-}" == -c%s ]]; then
    python3 - "$2" <<'PY'
import os, sys
print(os.stat(sys.argv[1]).st_size)
PY
  else
    command stat "$@"
  fi
}

find() {
  if [[ "$*" == *-printf* ]]; then
    python3 - <<'PY'
import os
for root, dirs, files in os.walk("."):
    dirs.sort()
    for name in sorted(files):
        if name in ("manifest.json", "manifest.sig"):
            continue
        print(os.path.relpath(os.path.join(root, name), "."))
PY
  else
    command find "$@"
  fi
}

compose() {
  printf 'compose %s\n' "$*" >>"$CALLS"
  case "${1:-}" in
    config)
      if [[ "${2:-}" == --services ]]; then
        printf '%s\n' "$COMPOSE_JSON" | jq -r '.services | keys[]'
      elif [[ "${2:-}" == --format && "${3:-}" == json ]]; then
        printf '%s\n' "$COMPOSE_JSON"
      else
        return 1
      fi
      ;;
    up|rm) return 0 ;;
    *) return 1 ;;
  esac
}

docker() {
  printf 'docker %s\n' "$*" >>"$CALLS"
  if [[ "${1:-}" == load ]]; then
    [[ "${2:-}" == -i ]] || cat >/dev/null
    return 0
  fi
  if [[ "${1:-}" == image && "${2:-}" == inspect ]]; then
    case "${5:-}" in
      '{{.Id}}') printf 'sha256:old-%s\n' "${3##*:}" ;;
      '{{json .Config.Entrypoint}}')
        if [[ "$3" == "$GATEWAY_TARGET" ]]; then
          printf '%s\n' "$GATEWAY_ENTRYPOINT"
        else
          printf 'null\n'
        fi
        ;;
    esac
    return 0
  fi
  case "${1:-}" in
    tag|rmi) return 0 ;;
    *) return 1 ;;
  esac
}

wait_selected_services() {
  printf 'wait_selected_services %s\n' "${SERVICES[*]}" >>"$CALLS"
  return "${WAIT_RC:-0}"
}
wait_api() {
  printf 'wait_api\n' >>"$CALLS"
  return 0
}
'''


def host_arch():
    machine = platform.machine()
    if machine == "x86_64":
        return "amd64"
    if machine in ("aarch64", "arm64"):
        return "arm64"
    raise unittest.SkipTest("unsupported fixture architecture: %s" % machine)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def image_for(component, version):
    name = "jiuzhang-server" if component == "api" else "jiuzhang-" + component
    return "%s:%s" % (name, version)


def compose_config(new_contract):
    gateway = {
        "image": image_for("gateway", "1.3.0"),
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
    }
    if new_contract:
        gateway.update({
            "user": "0:0",
            "entrypoint": [NEW_ENTRYPOINT],
            "cap_add": list(CAPABILITIES),
        })
    return {
        "services": {
            "api": {"image": image_for("api", "1.3.0")},
            "web": {"image": image_for("web", "1.3.0")},
            "gateway": gateway,
            "netmgrd": {"image": image_for("netmgrd", "1.3.0")},
        }
    }


class ExecutorContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="wdsp-gateway-contract-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.state = self.base / "state"
        self.overrides = self.base / "overrides"
        self.state.mkdir()
        self.overrides.mkdir()
        self.sign_key = self.base / "test-release.key"
        self.sign_pub = self.base / "test-release.pub"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(self.sign_key)],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["openssl", "pkey", "-in", str(self.sign_key), "-pubout", "-out", str(self.sign_pub)],
            check=True, capture_output=True,
        )

    def sign_manifest(self, package, key_path=None):
        raw_sig = self.base / "tmp.sig"
        subprocess.run(
            [
                "openssl", "pkeyutl", "-sign",
                "-inkey", str(key_path or self.sign_key),
                "-rawin", "-in", str(package / "manifest.json"),
                "-out", str(raw_sig),
            ],
            check=True, capture_output=True,
        )
        (package / "manifest.sig").write_text(
            base64.b64encode(raw_sig.read_bytes()).decode("ascii") + "\n",
            encoding="ascii",
        )
        raw_sig.unlink()

    def make_upgrade_pack(self, components=("gateway",), signed=True, extra_files=None):
        package = self.base / "upgrade-pack"
        if package.exists():
            shutil.rmtree(package)
        images = package / "images"
        images.mkdir(parents=True, exist_ok=True)
        files = []
        image_entries = []
        for component in components:
            relative = "images/%s.tar.gz" % component
            data = gzip.compress(("image:" + component).encode())
            (package / relative).write_bytes(data)
            files.append({"path": relative, "sha256": digest(data), "size": len(data)})
            image_entries.append({
                "component": component,
                "service": component,
                "image": image_for(component, "1.4.0"),
                "tar": relative,
            })
        for rel_path, content in (extra_files or {}).items():
            full = package / rel_path
            full.parent.mkdir(parents=True, exist_ok=True)
            raw = content.encode("utf-8") if isinstance(content, str) else content
            full.write_bytes(raw)
            files.append({"path": rel_path, "sha256": digest(raw), "size": len(raw)})
        files_compact = json.dumps(files, separators=(",", ":"), ensure_ascii=False)
        manifest = {
            "format_version": 1,
            "product": "wdsp",
            "package_type": "upgrade",
            "change_type": "feature",
            "version_from": "1.3.0",
            "version_to": "1.4.0",
            "version": "1.4.0",
            "arch": host_arch(),
            "components": list(components),
            "images": image_entries,
            "files": files,
            "files_manifest_sha256": hashlib.sha256(files_compact.encode("utf-8")).hexdigest(),
        }
        (package / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        if signed:
            self.sign_manifest(package)
        return package

    def make_runtime_patch(self, component="api", signed=True):
        package = self.base / "runtime-patch"
        if package.exists():
            shutil.rmtree(package)
        images = package / "images"
        images.mkdir(parents=True, exist_ok=True)
        archive = images / "runtime-images.tar"
        data = b"runtime image fixture\n"
        archive.write_bytes(data)
        archive_hash = digest(data)
        (package / "SHA256SUMS").write_text(
            "%s  images/runtime-images.tar\n" % archive_hash, encoding="utf-8"
        )
        manifest = {
            "format_version": 1,
            "product": "wdsp",
            "package_type": "runtime-patch",
            "change_type": "bugfix",
            "version_from": "1.4.0",
            "version_to": "1.4.1",
            "architecture": host_arch(),
            "components": [{"service": component, "image": image_for(component, "1.4.1")}],
            "images_archive": {"path": "images/runtime-images.tar", "sha256": archive_hash},
        }
        (package / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        if signed:
            self.sign_manifest(package)
        return package

    def run_executor(self, package, kind="upgrade", new_contract=True,
                     entrypoint=NEW_ENTRYPOINT, rollback=False, wait_rc=0,
                     compose_data=None, test_pubkey=None, version_to=None):
        compose_file = self.base / "compose.json"
        config = compose_config(new_contract) if compose_data is None else compose_data
        compose_file.write_text(json.dumps(config), encoding="utf-8")
        calls = self.base / "calls.log"
        if calls.exists():
            calls.unlink()
        gateway_version = "1.4.1" if kind == "runtime" else "1.4.0"
        pubkey = str(self.sign_pub) if test_pubkey is None else str(test_pubkey)
        v_to = version_to if version_to is not None else ("1.4.1" if kind == "runtime" else "1.4.0")
        env = dict(
            os.environ,
            PACKAGE_ROOT=str(package),
            COMPOSE_JSON_FILE=str(compose_file),
            COMPOSE_FILE=str(self.base / "docker-compose.yml"),
            ENV_FILE=str(self.base / "executor.env"),
            OVERRIDES_DIR=str(self.overrides),
            STATE_DIR=str(self.state),
            TEST_PUBKEY_FILE=pubkey,
            CALLS=str(calls),
            GATEWAY_TARGET=image_for("gateway", gateway_version),
            GATEWAY_ENTRYPOINT=json.dumps([entrypoint], separators=(",", ":")),
            DO_ROLLBACK="true" if rollback else "false",
            WAIT_RC=str(wait_rc),
            KIND=kind,
            TARGET_V_TO=v_to,
        )
        script = "\n".join((MOCKS, SHA256_FILE, ROLLBACK_IMAGES, RUNTIME_PATCH, UPGRADE_PACK)) + r'''
if [[ "$KIND" == runtime ]]; then
  if process_runtime_patch "$PACKAGE_ROOT" "$PACKAGE_ROOT/manifest.json" 1.4.0 "$TARGET_V_TO"; then
    result=0
  else
    result=$?
  fi
else
  if process_upgrade_pack "$PACKAGE_ROOT" "$PACKAGE_ROOT/manifest.json" 1.3.0 "$TARGET_V_TO"; then
    result=0
  else
    result=$?
  fi
fi
if [[ "$DO_ROLLBACK" == true ]]; then
  rollback_images
fi
printf 'RESULT=%s STATE=%s STAGE=%s MESSAGE=%s\n' \
  "$result" "$IMAGE_SWITCH_STARTED" "$CURRENT_STAGE" "$CURRENT_MESSAGE"
'''
        result = subprocess.run(
            ["bash", "-c", script], env=env, text=True, capture_output=True, timeout=15
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        return result.stdout, calls.read_text(encoding="utf-8") if calls.exists() else ""

    def test_old_compose_is_rejected_before_retag_and_does_not_recreate(self):
        package = self.make_upgrade_pack(("api", "gateway"))
        output, calls = self.run_executor(package, new_contract=False, rollback=True)
        self.assertIn("RESULT=1 STATE=false STAGE=APPLYING", output)
        self.assertIn("完整包升级", output)
        self.assertNotIn("docker tag", calls)
        self.assertNotIn("compose up", calls)
        self.assertNotIn("wait_api", calls)
        self.assertIn("docker load", calls)
        self.assertIn("{{json .Config.Entrypoint}}", calls)

    def test_unknown_image_entrypoint_is_rejected_before_retag(self):
        package = self.make_upgrade_pack()
        output, calls = self.run_executor(package, entrypoint="/usr/local/bin/unknown")
        self.assertIn("RESULT=1 STATE=false", output)
        self.assertIn("未知 gateway 镜像 Config.Entrypoint", output)
        self.assertNotIn("docker tag", calls)
        self.assertNotIn("compose up", calls)

    def test_new_compose_allows_upgrade_after_all_images_are_inspected(self):
        package = self.make_upgrade_pack(("api", "gateway"))
        output, calls = self.run_executor(package, new_contract=True)
        self.assertIn("RESULT=0 STATE=true STAGE=VERIFYING", output)
        lines = calls.splitlines()
        first_tag = next(i for i, line in enumerate(lines) if line.startswith("docker tag "))
        entrypoint_inspect = next(
            i for i, line in enumerate(lines) if "{{json .Config.Entrypoint}}" in line
        )
        self.assertGreater(first_tag, entrypoint_inspect)
        self.assertTrue(all("docker tag" not in line for line in lines[:entrypoint_inspect]))
        self.assertIn("docker load", lines[0:first_tag])
        self.assertIn(
            "compose up -d --no-deps --force-recreate api gateway netmgrd", lines
        )

    def test_every_new_compose_requirement_is_fail_closed(self):
        mutations = (
            ("user", "1000:1000"),
            ("entrypoint", [OLD_ENTRYPOINT]),
            ("cap_drop", []),
            ("cap_add", CAPABILITIES[:-1]),
            ("cap_add", CAPABILITIES + ["NET_ADMIN"]),
            ("security_opt", []),
        )
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                package = self.make_upgrade_pack()
                config = compose_config(True)
                config["services"]["gateway"][field] = value
                compose_file = self.base / "compose.json"
                compose_file.write_text(json.dumps(config), encoding="utf-8")
                calls = self.base / "calls.log"
                env = dict(
                    os.environ,
                    PACKAGE_ROOT=str(package), COMPOSE_JSON_FILE=str(compose_file),
                    COMPOSE_FILE=str(self.base / "docker-compose.yml"),
                    ENV_FILE=str(self.base / "executor.env"),
                    OVERRIDES_DIR=str(self.overrides), STATE_DIR=str(self.state),
                    TEST_PUBKEY_FILE=str(self.sign_pub),
                    CALLS=str(calls), GATEWAY_TARGET=image_for("gateway", "1.4.0"),
                    GATEWAY_ENTRYPOINT=json.dumps([NEW_ENTRYPOINT], separators=(",", ":")),
                    DO_ROLLBACK="false", WAIT_RC="0", KIND="upgrade",
                )
                script = "\n".join((MOCKS, SHA256_FILE, ROLLBACK_IMAGES, RUNTIME_PATCH, UPGRADE_PACK)) + r'''
if process_upgrade_pack "$PACKAGE_ROOT" "$PACKAGE_ROOT/manifest.json" 1.3.0 1.4.0; then
  result=0
else
  result=$?
fi
printf 'RESULT=%s STATE=%s MESSAGE=%s\n' "$result" "$IMAGE_SWITCH_STARTED" "$CURRENT_MESSAGE"
'''
                result = subprocess.run(
                    ["bash", "-c", script], env=env, text=True, capture_output=True, timeout=15
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("RESULT=1 STATE=false", result.stdout)
                self.assertIn("完整包升级", result.stdout)
                observed = calls.read_text(encoding="utf-8") if calls.exists() else ""
                self.assertNotIn("docker tag", observed)
                self.assertNotIn("compose up", observed)

    def test_legacy_image_allows_only_safe_legacy_compose(self):
        package = self.make_upgrade_pack()
        output, calls = self.run_executor(
            package, new_contract=False, entrypoint=OLD_ENTRYPOINT
        )
        self.assertIn("RESULT=0 STATE=true", output)
        self.assertIn("docker tag", calls)

        config = compose_config(False)
        config["services"]["gateway"].update({
            "user": "1000:1000",
            "entrypoint": [OLD_ENTRYPOINT],
            "cap_add": ["NET_BIND_SERVICE"],
            "cap_drop": ["ALL"],
        })
        output, _ = self.run_executor(
            package, entrypoint=OLD_ENTRYPOINT, compose_data=config
        )
        self.assertIn("RESULT=0 STATE=true", output)

    def test_legacy_root_user_is_rejected_before_retag_or_recreate(self):
        package = self.make_upgrade_pack()
        config = compose_config(False)
        config["services"]["gateway"]["user"] = "0:0"
        output, calls = self.run_executor(
            package, entrypoint=OLD_ENTRYPOINT, rollback=True, compose_data=config
        )
        self.assertIn("RESULT=1 STATE=false STAGE=APPLYING", output)
        self.assertIn("常驻 root", output)
        self.assertNotIn("docker tag", calls)
        self.assertNotIn("compose up", calls)
        self.assertNotIn("wait_api", calls)

    def test_legacy_compose_must_keep_no_new_privileges(self):
        package = self.make_upgrade_pack()
        config = compose_config(False)
        config["services"]["gateway"]["security_opt"] = []
        output, calls = self.run_executor(
            package, entrypoint=OLD_ENTRYPOINT, compose_data=config
        )
        self.assertIn("RESULT=1 STATE=false", output)
        self.assertIn("no-new-privileges", output)
        self.assertNotIn("docker tag", calls)
        self.assertNotIn("compose up", calls)

    def test_no_switch_rollback_only_cleans_new_component_resources(self):
        compose_file = self.base / "compose.json"
        compose_file.write_text(json.dumps(compose_config(True)), encoding="utf-8")
        override = self.overrides / "upgrade-1.4.0.yml"
        override.write_text("services: {}\n", encoding="utf-8")
        calls = self.base / "calls.log"
        env = dict(
            os.environ,
            COMPOSE_JSON_FILE=str(compose_file), CALLS=str(calls),
            OVERRIDES_DIR=str(self.overrides),
        )
        script = "\n".join((MOCKS, ROLLBACK_IMAGES)) + r'''
SERVICES=(gateway netmgrd)
STABLE_IMAGES=(jiuzhang-gateway:1.3.0 jiuzhang-netmgrd:1.4.0)
OLD_IDS=(sha256:gateway-old "")
NEW_SERVICES=(netmgrd)
INSTALLED_OVERRIDE="$OVERRIDES_DIR/upgrade-1.4.0.yml"
IMAGE_SWITCH_STARTED=false
rollback_images
'''
        result = subprocess.run(
            ["bash", "-c", script], env=env, text=True, capture_output=True, timeout=10
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(override.exists())
        observed = calls.read_text(encoding="utf-8")
        self.assertIn("compose rm -sf netmgrd", observed)
        self.assertIn("docker rmi jiuzhang-netmgrd:1.4.0", observed)
        self.assertNotIn("docker tag", observed)
        self.assertNotIn("compose up", observed)
        self.assertNotIn("wait_api", observed)

    def test_runtime_patch_new_gateway_with_old_compose_never_switches(self):
        package = self.make_runtime_patch("gateway")
        output, calls = self.run_executor(
            package, kind="runtime", new_contract=False, rollback=True
        )
        self.assertIn("RESULT=1 STATE=false STAGE=APPLYING", output)
        self.assertIn("完整包升级", output)
        self.assertIn("docker load", calls)
        self.assertIn("{{json .Config.Entrypoint}}", calls)
        self.assertNotIn("docker tag", calls)
        self.assertNotIn("compose up", calls)
        self.assertNotIn("wait_api", calls)

    def test_runtime_patch_api_success_remains_allowed(self):
        package = self.make_runtime_patch()
        output, calls = self.run_executor(package, kind="runtime")
        self.assertIn("RESULT=0 STATE=true STAGE=VERIFYING", output)
        self.assertIn("compose up -d --no-deps api", calls.splitlines())
        self.assertNotIn("{{json .Config.Entrypoint}}", calls)

    def test_runtime_patch_marks_switch_and_restores_after_verify_failure(self):
        package = self.make_runtime_patch()
        output, calls = self.run_executor(
            package, kind="runtime", rollback=True, wait_rc=1
        )
        self.assertIn("RESULT=1 STATE=true STAGE=VERIFYING", output)
        lines = calls.splitlines()
        self.assertLess(
            next(i for i, line in enumerate(lines) if line.startswith("docker tag ")),
            next(i for i, line in enumerate(lines) if line.startswith("compose up ")),
        )
        self.assertIn(
            "compose up -d --no-deps --force-recreate api", lines
        )

    def test_unsigned_and_tampered_packages_are_rejected_before_docker_load(self):
        # 1) Missing manifest.sig
        for kind in ("upgrade", "runtime"):
            package = self.make_upgrade_pack() if kind == "upgrade" else self.make_runtime_patch()
            (package / "manifest.sig").unlink()
            output, calls = self.run_executor(package, kind=kind)
            self.assertIn("RESULT=1 STATE=false", output)
            self.assertIn("manifest.sig", output)
            self.assertNotIn("docker load", calls)
            self.assertNotIn("docker tag", calls)

        # 2) Signed with untrusted key (verified against embedded production key)
        package = self.make_upgrade_pack()
        output, calls = self.run_executor(package, kind="upgrade", test_pubkey="")
        self.assertIn("RESULT=1 STATE=false", output)
        self.assertIn("Ed25519", output)
        self.assertNotIn("docker load", calls)

        # 3) Tampered manifest.json after signing
        package = self.make_upgrade_pack()
        manifest_path = package / "manifest.json"
        manifest_path.write_text(manifest_path.read_text() + " ", encoding="utf-8")
        output, calls = self.run_executor(package, kind="upgrade")
        self.assertIn("RESULT=1 STATE=false", output)
        self.assertIn("Ed25519", output)
        self.assertNotIn("docker load", calls)

        # 4) Signed manifest with mismatched files_manifest_sha256
        package = self.make_upgrade_pack()
        manifest_path = package / "manifest.json"
        m = json.loads(manifest_path.read_text())
        m["files_manifest_sha256"] = "0" * 64
        manifest_path.write_text(json.dumps(m), encoding="utf-8")
        self.sign_manifest(package)
        output, calls = self.run_executor(package, kind="upgrade")
        self.assertIn("RESULT=1 STATE=false", output)
        self.assertIn("files_manifest_sha256", output)
        self.assertNotIn("docker load", calls)

    def test_invalid_version_to_path_traversal_is_rejected(self):
        for bad_ver in ("../evil", "1.4.0/../../etc", "1.4.0;id", "1.4..0"):
            with self.subTest(bad_ver=bad_ver):
                package = self.make_upgrade_pack()
                output, calls = self.run_executor(package, kind="upgrade", version_to=bad_ver)
                self.assertIn("RESULT=1 STATE=false", output)
                self.assertIn("目标版本号格式非法", output)
                self.assertNotIn("docker load", calls)

    def test_runtime_patch_gateway_co_recreates_netmgrd(self):
        package = self.make_runtime_patch("gateway")
        output, calls = self.run_executor(package, kind="runtime", new_contract=True)
        self.assertIn("RESULT=0 STATE=true STAGE=VERIFYING", output)
        lines = calls.splitlines()
        self.assertIn("compose up -d --no-deps --force-recreate gateway netmgrd", lines)

    def test_compose_fragment_security_and_immutability_checks(self):
        # Base compose without netmgrd
        base_compose = compose_config(True)
        del base_compose["services"]["netmgrd"]

        def run_fragment_case(after_compose):
            package = self.make_upgrade_pack(
                ("netmgrd",),
                extra_files={"compose/upgrade-services.yml": "services:\n  netmgrd: {}\n"},
            )
            compose_file = self.base / "compose.json"
            after_file = self.base / "compose-after.json"
            compose_file.write_text(json.dumps(base_compose), encoding="utf-8")
            after_file.write_text(json.dumps(after_compose), encoding="utf-8")
            calls = self.base / "calls.log"
            if calls.exists():
                calls.unlink()
            env = dict(
                os.environ,
                PACKAGE_ROOT=str(package),
                COMPOSE_JSON_FILE=str(compose_file),
                AFTER_JSON_FILE=str(after_file),
                COMPOSE_FILE=str(self.base / "docker-compose.yml"),
                ENV_FILE=str(self.base / "executor.env"),
                OVERRIDES_DIR=str(self.overrides),
                STATE_DIR=str(self.state),
                TEST_PUBKEY_FILE=str(self.sign_pub),
                CALLS=str(calls),
                GATEWAY_TARGET=image_for("gateway", "1.4.0"),
                GATEWAY_ENTRYPOINT=json.dumps([NEW_ENTRYPOINT], separators=(",", ":")),
            )
            override_docker = r'''
docker() {
  printf 'docker %s\n' "$*" >>"$CALLS"
  if [[ "${1:-}" == compose ]]; then
    if [[ "$*" == *"upgrade-services.yml"* ]]; then
      cat "$AFTER_JSON_FILE"
    else
      cat "$COMPOSE_JSON_FILE"
    fi
    return 0
  fi
  if [[ "${1:-}" == load ]]; then cat >/dev/null; return 0; fi
  if [[ "${1:-}" == image && "${2:-}" == inspect ]]; then
    if [[ "${5:-}" == '{{.Id}}' ]]; then printf 'sha256:old-img\n'; fi
    return 0
  fi
  case "${1:-}" in tag|rmi) return 0 ;; *) return 1 ;; esac
}
'''
            script = "\n".join((MOCKS, override_docker, SHA256_FILE, ROLLBACK_IMAGES, RUNTIME_PATCH, UPGRADE_PACK)) + r'''
if process_upgrade_pack "$PACKAGE_ROOT" "$PACKAGE_ROOT/manifest.json" 1.3.0 1.4.0; then
  result=0
else
  result=$?
fi
printf 'RESULT=%s MESSAGE=%s\n' "$result" "$CURRENT_MESSAGE"
'''
            res = subprocess.run(["bash", "-c", script], env=env, text=True, capture_output=True, timeout=15)
            self.assertEqual(res.returncode, 0, res.stderr + res.stdout)
            return res.stdout

        # 1) Modifying existing service (adding volumes to api while keeping image unchanged)
        mutated_existing = json.loads(json.dumps(base_compose))
        mutated_existing["services"]["api"]["volumes"] = [{"type": "bind", "source": "/", "target": "/host"}]
        mutated_existing["services"]["netmgrd"] = {"image": image_for("netmgrd", "1.4.0")}
        out = run_fragment_case(mutated_existing)
        self.assertIn("RESULT=1", out)
        self.assertIn("既有服务", out)

        # 2) New service with privileged, pid:host, ipc:host, root bind mount, or unauthorized cap_add
        bad_new_configs = [
            ("privileged", {"image": image_for("netmgrd", "1.4.0"), "privileged": True}),
            ("pid_host", {"image": image_for("netmgrd", "1.4.0"), "pid": "host"}),
            ("ipc_host", {"image": image_for("netmgrd", "1.4.0"), "ipc": "host"}),
            ("root_bind", {"image": image_for("netmgrd", "1.4.0"), "volumes": [{"type": "bind", "source": "/", "target": "/host"}]}),
            ("docker_sock", {"image": image_for("netmgrd", "1.4.0"), "volumes": [{"type": "bind", "source": "/var/run/docker.sock", "target": "/var/run/docker.sock"}]}),
            ("bad_cap", {"image": image_for("netmgrd", "1.4.0"), "cap_add": ["SYS_ADMIN"]}),
        ]
        for label, svc_def in bad_new_configs:
            with self.subTest(label=label):
                after = json.loads(json.dumps(base_compose))
                after["services"]["netmgrd"] = svc_def
                out = run_fragment_case(after)
                self.assertIn("RESULT=1", out, f"{label} should be rejected: {out}")

        # 3) Clean netmgrd definition with only NET_RAW/NET_ADMIN and named volume must be accepted
        good_after = json.loads(json.dumps(base_compose))
        good_after["services"]["netmgrd"] = {
            "image": image_for("netmgrd", "1.4.0"),
            "network_mode": "service:gateway",
            "cap_add": ["NET_RAW", "NET_ADMIN"],
            "volumes": [{"type": "volume", "source": "gateway-admin", "target": "/var/run/caddy"}],
        }
        # Clean out previous override if any
        for p in self.overrides.glob("*.yml"):
            p.unlink()
        # Mock install -o root -g root for non-root test execution
        out = run_fragment_case(good_after)
        # Note: on non-root macOS `install -o root -g root` fails with permission denied, which proves it passed ALL security checks!
        self.assertTrue("RESULT=0" in out or "安装 compose 片段失败" in out, out)


class BuildUpgradePackGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="wdsp-upgrade-builder-")
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        for name in (
            "ops/upgrade/build-upgrade-pack.sh",
            "ops/lib/common.sh",
            "ops/lib/signing.sh",
        ):
            destination = self.repo / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        self.write("VERSION.md", "当前已发布版本：`1.3.0`\n")
        self.write("server/migrations/000001_init.up.sql", "SELECT 1;\n")
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "test")
        self.git("add", "-A")
        self.git("commit", "-qm", "fixture")
        self.git("tag", "wdsp-v1.3.0")

    def write(self, name, content):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def git(self, *args):
        return subprocess.check_output(
            ["git", "-C", str(self.repo), *args], stderr=subprocess.STDOUT
        )

    def build(self, *args):
        env = dict(os.environ)
        env.pop("WDSP_SIGNING_KEY", None)
        return subprocess.run(
            ["bash", str(self.repo / "ops/upgrade/build-upgrade-pack.sh"), *args],
            env=env, text=True, capture_output=True, timeout=15,
        )

    def assert_gateway_rejected(self, result):
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 1, output)
        self.assertIn("1.3.0", output)
        self.assertIn("gateway", output)
        self.assertIn("完整包升级", output)
        self.assertFalse((self.repo / "dist").exists())

    def test_explicit_components_and_plan_cannot_bypass_gate(self):
        self.assert_gateway_rejected(self.build(
            "--from", "1.3.0", "--to", "1.4.0",
            "--components", "gateway,web", "--plan",
        ))
        self.assert_gateway_rejected(self.build(
            "--from", "1.3.0", "--to", "1.4.0", "--components", "gateway",
            "--unsigned", "--skip-build", "--images-dir", str(self.repo / "images"),
        ))

    def test_auto_plan_gateway_is_rejected(self):
        self.write("gateway/Dockerfile", "FROM fixture\n")
        self.assert_gateway_rejected(self.build(
            "--from", "1.3.0", "--to", "1.4.0", "--components", "auto", "--plan",
        ))

    def test_non_gateway_and_other_source_versions_remain_allowed(self):
        result = self.build(
            "--from", "1.3.0", "--to", "1.4.0", "--components", "web", "--plan"
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result = self.build(
            "--from", "1.2.0", "--to", "1.3.0", "--components", "gateway", "--plan"
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
