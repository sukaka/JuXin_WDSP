"""End-to-end contract tests for Web layer-delta upgrade packages, 9-component probes, and pcapd profile guard."""
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
UPGRADE_DIR = ROOT / "ops" / "upgrade"
BUILDER = UPGRADE_DIR / "build-upgrade-pack.sh"
EXECUTOR = UPGRADE_DIR / "upgrade-executor.sh"
DELTA_TOOL = UPGRADE_DIR / "image-delta.py"
COMMON = ROOT / "ops" / "lib" / "common.sh"
SIGNING = ROOT / "ops" / "lib" / "signing.sh"

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_image_delta as delta_helpers

SOURCE = EXECUTOR.read_text(encoding="utf-8")


def shell_slice(start_marker, end_marker):
    start = SOURCE.index(start_marker)
    end = SOURCE.index(end_marker, start)
    return SOURCE[start:end]


WAIT_FUNCS = shell_slice("wait_service() {", "declare -a SERVICES=")
SHA256_FILE = shell_slice("sha256_file() {", "\nwrite_result() {")
ROLLBACK_IMAGES = shell_slice("rollback_images() {", "\nprocess_job() {")
UPGRADE_PACK = shell_slice("validate_gateway_start_contract() {", "\nexec 9>")


def host_arch():
    m = platform.machine()
    return {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}[m]


class LayerDeltaExecutorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="wdsp-delta-exec-")
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.arch = host_arch()

        # Generate isolated Ed25519 keypair for test fixture repo
        self.priv = self.dir / "rel.key"
        self.pub = self.dir / "rel.pub"
        subprocess.check_call(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(self.priv)],
            stderr=subprocess.DEVNULL,
        )
        subprocess.check_call(
            ["openssl", "pkey", "-in", str(self.priv), "-pubout", "-out", str(self.pub)],
            stderr=subprocess.DEVNULL,
        )

        # Build isolated mini repo for build-upgrade-pack.sh
        self.repo = self.dir / "repo"
        for sub in ("ops/upgrade", "ops/lib", "ops/offline-package", "server/migrations"):
            (self.repo / sub).mkdir(parents=True, exist_ok=True)
        for f in (BUILDER, EXECUTOR, UPGRADE_DIR / "install-executor.sh", DELTA_TOOL):
            shutil.copy2(f, self.repo / "ops/upgrade" / f.name)
        for f in (COMMON, SIGNING):
            shutil.copy2(f, self.repo / "ops/lib" / f.name)
        shutil.copy2(self.pub, self.repo / "ops/offline-package/release-signing.pub")
        (self.repo / "VERSION.md").write_text("当前已发布版本：`1.11.1`\n", encoding="utf-8")
        (self.repo / "server/migrations/000001_init.up.sql").write_text("SELECT 1;\n", encoding="utf-8")

    def _build_real_signed_delta_pack(self, *, components=("web",), base_layers_extra=None):
        """Build a real signed Ed25519 layer-delta upgrade package via build-upgrade-pack.sh."""
        big_static = delta_helpers.make_layer_tar({"usr/share/caddy/assets/geo/city.mmdb": b"G" * (2 * 1024 * 1024)})
        old_app = delta_helpers.make_layer_tar({"usr/share/caddy/index.html": b"v1.11.1"})
        new_app = delta_helpers.make_layer_tar({"usr/share/caddy/index.html": b"v1.11.2"})

        base_tars = {}
        base_dids = {}
        target_dids = {}
        images_in = self.dir / "images-in"
        images_in.mkdir(exist_ok=True)

        # Build base offline archive containing all requested components
        offline_pkg = self.dir / f"jiuzhang-wdsp-update-full-1.11.1-{self.arch}.tar.gz"
        root_off = f"jiuzhang-wdsp-offline-1.11.1-{self.arch}"
        with tarfile.open(offline_pkg, "w:gz") as otf:
            man_bytes = json.dumps({"edition": "wdsp", "version": "1.11.1"}).encode()
            mti = tarfile.TarInfo(f"{root_off}/manifest.json")
            mti.size = len(man_bytes)
            otf.addfile(mti, io.BytesIO(man_bytes))

            for comp in components:
                prefix = delta_helpers.make_layer_tar  # silence unused lint
                _ = prefix
                img_name = "jiuzhang-server" if comp == "api" else f"jiuzhang-{comp}"
                b_tar = self.dir / f"base-{comp}.tar"
                t_tar = self.dir / f"target-{comp}.tar"
                b_layers = [big_static, old_app] if base_layers_extra is None else base_layers_extra
                base_dids[comp] = delta_helpers.make_docker_save(
                    b_tar, f"{img_name}:1.11.1", b_layers
                )
                target_dids[comp] = delta_helpers.make_docker_save(
                    t_tar, f"{img_name}:1.11.2", [big_static, new_app]
                )
                base_tars[comp] = b_tar
                otf.add(b_tar, arcname=f"{root_off}/images/{img_name}.tar")
                # gzipped target tar for --images-dir
                gz_target = images_in / f"{comp}-{self.arch}.tar.gz"
                with open(t_tar, "rb") as src_f, open(gz_target, "wb") as dst_f:
                    import gzip as _gzip
                    dst_f.write(_gzip.compress(src_f.read()))

        out_dir = self.dir / "dist-delta"
        env = dict(os.environ, WDSP_SIGNING_KEY=str(self.priv), WDSP_DELTA_MIN_SAVINGS_BYTES="1024")
        proc = subprocess.run(
            [
                "bash",
                str(self.repo / "ops/upgrade/build-upgrade-pack.sh"),
                "--from",
                "1.11.1",
                "--to",
                "1.11.2",
                "--arch",
                self.arch,
                "--components",
                " ".join(components),
                "--images-dir",
                str(images_in),
                "--base-archive",
                str(offline_pkg),
                "--output-dir",
                str(out_dir),
            ],
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        pkg_path = out_dir / f"jiuzhang-wdsp-upgrade-1.11.2-{self.arch}.tar.gz"
        self.assertTrue(pkg_path.is_file())
        # Verify delta archive is tiny (<100KB vs 2MB static layer)
        self.assertLess(pkg_path.stat().st_size, 150 * 1024)
        return pkg_path, base_tars, base_dids, target_dids

    def _run_executor_upgrade(
        self,
        pkg_path,
        base_tars,
        host_layers_by_service,
        *,
        compose_services,
        pcapd_running=False,
        hasyncd_running=False,
    ):
        extract_dir = self.dir / "exec-work"
        if extract_dir.exists():
            shutil.rmtree(extract_dir)
        extract_dir.mkdir()
        with tarfile.open(pkg_path, "r:gz") as tf:
            tf.extractall(extract_dir, filter="data")
        pkg_root = next(p for p in extract_dir.iterdir() if p.is_dir())
        state_dir = self.dir / "state"
        state_dir.mkdir(exist_ok=True)
        overrides_dir = self.dir / "overrides"
        overrides_dir.mkdir(exist_ok=True)
        log_file = self.dir / "docker-compose.log"
        if log_file.exists():
            log_file.unlink()
        loaded_tar = self.dir / "loaded-reconstructed.tar"
        if loaded_tar.exists():
            loaded_tar.unlink()

        compose_cfg = {
            "services": {
                svc: {"image": f"jiuzhang-runtime-jiuzhang-{'server' if svc == 'api' else svc}:old"}
                for svc in compose_services
            }
        }
        compose_json_file = self.dir / "compose.json"
        compose_json_file.write_text(json.dumps(compose_cfg), encoding="utf-8")
        layers_json_file = self.dir / "host-layers.json"
        layers_json_file.write_text(json.dumps(host_layers_by_service), encoding="utf-8")
        base_tars_file = self.dir / "base-tars.json"
        base_tars_file.write_text(
            json.dumps({k: str(v) for k, v in base_tars.items()}), encoding="utf-8"
        )

        script = (
            r'''
set -euo pipefail
CONFIG_FILE="/tmp/test-executor.conf"
TEST_PUBKEY_FILE="$PUB_PATH"
STATE_DIR="$STATE_PATH"
OVERRIDES_DIR="$OVERRIDES_PATH"
IMAGE_DELTA_HELPER="$HELPER_PATH"
COMPOSE_FILE="$COMPOSE_JSON_PATH"
ENV_FILE="$COMPOSE_JSON_PATH"
CURRENT_JOB="test-job"
CURRENT_STAGE="APPLYING"
CURRENT_MESSAGE=""
INSTALLED_OVERRIDE=""
IMAGE_SWITCH_STARTED=false
PCAPD_SKIP_START=false
HASYNCD_SKIP_START=false
declare -a SERVICES=() STABLE_IMAGES=() OLD_IDS=() NEW_SERVICES=() API_EXTRA_NETWORKS=()

if ! command -v mapfile >/dev/null 2>&1; then
  mapfile() {
    local array_name="$2" line
    eval "$array_name=()"
    while IFS= read -r line; do
      eval "$array_name+=(\"\$line\")"
    done
  }
fi
stat() {
  if [[ "${1:-}" == "-c%s" ]]; then
    python3 -c 'import os,sys; print(os.stat(sys.argv[1]).st_size)' "$2"
  else
    command stat "$@"
  fi
}
find() {
  if [[ "$*" == *"-printf %P\n"* ]]; then
    python3 -c '
import os
for root, dirs, files in os.walk("."):
    dirs.sort()
    for f in sorted(files):
        if f in ("manifest.json", "manifest.sig"):
            continue
        p = os.path.relpath(os.path.join(root, f), ".").replace(os.sep, "/")
        print(p)
'
  else
    command find "$@"
  fi
}
sha256sum() {
  if [[ "${1:-}" == "-c" ]]; then
    python3 - "$2" <<'PY'
import hashlib, sys
for line in open(sys.argv[1], encoding="utf-8"):
    line = line.strip()
    if not line: continue
    want, path = line.split(None, 1)
    h = hashlib.sha256(open(path, "rb").read()).hexdigest()
    if h != want:
        raise SystemExit(1)
PY
  else
    shasum -a 256 "$@"
  fi
}
wait_selected_services() { printf 'WAIT_SELECTED services=%s pcapd_skip=%s hasyncd_skip=%s\n' "${SERVICES[*]}" "${PCAPD_SKIP_START}" "${HASYNCD_SKIP_START}" >>"$LOG_FILE"; return 0; }
wait_api() { return 0; }
compose() {
  printf 'COMPOSE %s\n' "$*" >>"$LOG_FILE"
  if [[ "$1" == "--profile" ]]; then
    shift 2
  fi
  case "$1 $2" in
    "config --services")
      jq -r '.services | keys[]' "$COMPOSE_JSON_PATH"
      ;;
    "config --format")
      cat "$COMPOSE_JSON_PATH"
      ;;
    "ps -q")
      if [[ "$3" == "pcapd" ]]; then
        [[ "$PCAPD_RUNNING" == "1" ]] && printf 'cid-pcapd\n'
      elif [[ "$3" == "hasyncd" ]]; then
        [[ "$HASYNCD_RUNNING" == "1" ]] && printf 'cid-hasyncd\n'
      else
        printf 'cid-%s\n' "$3"
      fi
      ;;
    "up -d")
      return 0
      ;;
    *)
      return 0
      ;;
  esac
}
docker() {
  printf 'DOCKER %s\n' "$*" >>"$LOG_FILE"
  if [[ "$1 $2" == "image inspect" ]]; then
    local ref="$3" fmt="${5:-}"
    if [[ "$fmt" == "{{.Id}}" ]]; then
      printf 'sha256:old-%s\n' "$ref"
      return 0
    elif [[ "$fmt" == *"RootFS.Layers"* ]]; then
      python3 - "$LAYERS_JSON_PATH" "$ref" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
ref = sys.argv[2]
for svc, layers in data.items():
    key = "server" if svc == "api" else svc
    if f"jiuzhang-{key}:" in ref:
        print(json.dumps(layers))
        raise SystemExit(0)
print("[]")
PY
      return 0
    else
      # Target image existence check after load
      [[ -f "$LOADED_TAR" ]] && return 0 || return 1
    fi
  elif [[ "$1" == "inspect" && "$*" == *"cid-pcapd"* ]]; then
    [[ "$PCAPD_RUNNING" == "1" ]] && printf 'running\n' || printf 'exited\n'
    return 0
  elif [[ "$1" == "inspect" && "$*" == *"cid-hasyncd"* ]]; then
    [[ "$HASYNCD_RUNNING" == "1" ]] && printf 'running\n' || printf 'exited\n'
    return 0
  elif [[ "$1" == "save" ]]; then
    local ref="$2" out="$4"
    python3 - "$BASE_TARS_PATH" "$ref" "$out" <<'PY'
import json, shutil, sys
data = json.load(open(sys.argv[1]))
ref, out = sys.argv[2], sys.argv[3]
for svc, path in data.items():
    key = "server" if svc == "api" else svc
    if f"jiuzhang-{key}:" in ref:
        shutil.copyfile(path, out)
        raise SystemExit(0)
raise SystemExit(1)
PY
    return 0
  elif [[ "$1" == "load" ]]; then
    if [[ "${2:-}" == "-i" ]]; then
      cp "$3" "$LOADED_TAR"
    else
      cat > "$LOADED_TAR"
    fi
    return 0
  elif [[ "$1" == "tag" ]]; then
    return 0
  fi
  return 0
}
'''
            + SHA256_FILE
            + "\n"
            + ROLLBACK_IMAGES
            + "\n"
            + UPGRADE_PACK
            + r'''
if process_upgrade_pack "$PKG_ROOT" "$PKG_ROOT/manifest.json" "1.11.1" "1.11.2"; then
  printf 'RESULT=0 MESSAGE=%s\n' "$CURRENT_MESSAGE"
else
  printf 'RESULT=1 MESSAGE=%s\n' "$CURRENT_MESSAGE"
fi
'''
        )
        env = dict(
            os.environ,
            PUB_PATH=str(self.pub),
            STATE_PATH=str(state_dir),
            OVERRIDES_PATH=str(overrides_dir),
            HELPER_PATH=str(DELTA_TOOL),
            COMPOSE_JSON_PATH=str(compose_json_file),
            LAYERS_JSON_PATH=str(layers_json_file),
            BASE_TARS_PATH=str(base_tars_file),
            PKG_ROOT=str(pkg_root),
            LOG_FILE=str(log_file),
            LOADED_TAR=str(loaded_tar),
            PCAPD_RUNNING="1" if pcapd_running else "0",
            HASYNCD_RUNNING="1" if hasyncd_running else "0",
        )
        proc = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return proc.stdout, log_file.read_text(encoding="utf-8") if log_file.exists() else "", loaded_tar

    def test_signed_layer_delta_upgrade_succeeds_and_reconstructs_exact_target_image(self):
        pkg_path, base_tars, base_dids, target_dids = self._build_real_signed_delta_pack(components=("web",))
        out, log, loaded_tar = self._run_executor_upgrade(
            pkg_path,
            base_tars,
            {"web": base_dids["web"]},
            compose_services=("api", "web", "gateway", "netmgrd"),
        )
        self.assertIn("RESULT=0", out, out + "\n" + log)
        self.assertIn("DOCKER save jiuzhang-runtime-jiuzhang-web:old", log)
        self.assertIn("DOCKER load -i", log)
        self.assertIn("COMPOSE up -d --no-deps --force-recreate web", log)
        self.assertTrue(loaded_tar.is_file())
        with tarfile.open(loaded_tar, "r") as tf:
            man = json.loads(tf.extractfile("manifest.json").read())[0]
            self.assertEqual(man["RepoTags"], ["jiuzhang-web:1.11.2"])
            cfg = json.loads(tf.extractfile(man["Config"]).read())
            self.assertEqual(cfg["rootfs"]["diff_ids"], target_dids["web"])

    def test_layer_delta_fails_closed_before_save_or_switch_when_host_missing_base_layer(self):
        pkg_path, base_tars, _, _ = self._build_real_signed_delta_pack(components=("web",))
        out, log, loaded_tar = self._run_executor_upgrade(
            pkg_path,
            base_tars,
            {"web": ["sha256:" + "f" * 64]},
            compose_services=("api", "web", "gateway", "netmgrd"),
        )
        self.assertIn("RESULT=1", out, out)
        self.assertIn("不满足差量升级基础层要求", out)
        self.assertNotIn("DOCKER save", log)
        self.assertNotIn("DOCKER load", log)
        self.assertNotIn("DOCKER tag", log)
        self.assertNotIn("COMPOSE up", log)
        self.assertFalse(loaded_tar.exists())

    def test_pcapd_profile_guard_does_not_start_disabled_pcapd_and_recreates_running_pcapd(self):
        pkg_path, base_tars, base_dids, _ = self._build_real_signed_delta_pack(components=("pcapd",))

        # 1. pcapd NOT running: image retagged, NEVER started
        out1, log1, _ = self._run_executor_upgrade(
            pkg_path,
            base_tars,
            {"pcapd": base_dids["pcapd"]},
            compose_services=("api", "pcapd"),
            pcapd_running=False,
        )
        self.assertIn("RESULT=0", out1, out1 + "\n" + log1)
        self.assertIn("DOCKER tag jiuzhang-pcapd:1.11.2 jiuzhang-runtime-jiuzhang-pcapd:old", log1)
        self.assertNotIn("up -d", log1)
        self.assertIn("pcapd_skip=true", log1)

        # 2. pcapd IS running: recreated under --profile request-pcap
        out2, log2, _ = self._run_executor_upgrade(
            pkg_path,
            base_tars,
            {"pcapd": base_dids["pcapd"]},
            compose_services=("api", "pcapd"),
            pcapd_running=True,
        )
        self.assertIn("RESULT=0", out2, out2 + "\n" + log2)
        self.assertIn("COMPOSE --profile request-pcap up -d --no-deps --force-recreate pcapd", log2)
        self.assertIn("pcapd_skip=false", log2)

    def test_hasyncd_profile_guard_does_not_start_disabled_hasyncd_and_recreates_running_hasyncd(self):
        pkg_path, base_tars, base_dids, _ = self._build_real_signed_delta_pack(components=("hasyncd",))

        # 1. hasyncd NOT running: image retagged, NEVER started
        out1, log1, _ = self._run_executor_upgrade(
            pkg_path,
            base_tars,
            {"hasyncd": base_dids["hasyncd"]},
            compose_services=("api", "hasyncd"),
            hasyncd_running=False,
        )
        self.assertIn("RESULT=0", out1, out1 + "\n" + log1)
        self.assertIn("DOCKER tag jiuzhang-hasyncd:1.11.2 jiuzhang-runtime-jiuzhang-hasyncd:old", log1)
        self.assertNotIn("up -d", log1)
        self.assertIn("hasyncd_skip=true", log1)

        # 2. hasyncd IS running: recreated under --profile ha-sync
        out2, log2, _ = self._run_executor_upgrade(
            pkg_path,
            base_tars,
            {"hasyncd": base_dids["hasyncd"]},
            compose_services=("api", "hasyncd"),
            hasyncd_running=True,
        )
        self.assertIn("RESULT=0", out2, out2 + "\n" + log2)
        self.assertIn("COMPOSE --profile ha-sync up -d --no-deps --force-recreate hasyncd", log2)
        self.assertIn("hasyncd_skip=false", log2)

    def test_havipd_layer_delta_upgrade_succeeds(self):
        pkg_path, base_tars, base_dids, target_dids = self._build_real_signed_delta_pack(components=("havipd",))
        out, log, loaded_tar = self._run_executor_upgrade(
            pkg_path,
            base_tars,
            {"havipd": base_dids["havipd"]},
            compose_services=("api", "web", "gateway", "netmgrd", "havipd"),
        )
        self.assertIn("RESULT=0", out, out + "\n" + log)
        self.assertIn("COMPOSE up -d --no-deps --force-recreate havipd", log)
        with tarfile.open(loaded_tar, "r") as tf:
            man = json.loads(tf.extractfile("manifest.json").read())[0]
            self.assertEqual(man["RepoTags"], ["jiuzhang-havipd:1.11.2"])
            cfg = json.loads(tf.extractfile(man["Config"]).read())
            self.assertEqual(cfg["rootfs"]["diff_ids"], target_dids["havipd"])

    def test_readiness_probes_cover_all_five_new_sidecar_services(self):
        script = (
            r'''
set -euo pipefail
TIMEOUT=16
SECONDS=0
API_URL=http://127.0.0.1:18081
CURRENT_MESSAGE=""
PCAPD_SKIP_START=false
HASYNCD_SKIP_START=false
SERVICES=(mirrorcap tproxyd havipd hasyncd logrotator containerops pcapd)
STABLE_IMAGES=(image-mirrorcap image-tproxyd image-havipd image-hasyncd image-logrotator image-containerops image-pcapd)
sleep() { SECONDS=$((SECONDS + $1)); }
timeout() { shift; "$@"; }
compose() {
  if [[ "$1" == "--profile" ]]; then shift 2; fi
  printf 'cid-%s\n' "$3"
}
docker() {
  if [[ "$1 $2" == "image inspect" ]]; then
    local image="${@: -1}"
    printf 'sha256:%s\n' "${image#image-}"
    return
  fi
  if [[ "$1" == "inspect" ]]; then
    local cid="${@: -1}"
    printf 'running|healthy|sha256:%s|0|start\n' "${cid#cid-}"
    return
  fi
  if [[ "$1" == "exec" ]]; then
    printf '%s\n' "$*" >>"$PROBES"
    return 0
  fi
  return 1
}
curl() { return 0; }
'''
            + WAIT_FUNCS
            + r'''
if wait_selected_services; then printf 'RESULT=0\n'; else printf 'RESULT=1 MSG=%s\n' "$CURRENT_MESSAGE"; fi
'''
        )
        probes = self.dir / "probes.log"
        proc = subprocess.run(
            ["bash", "-c", script],
            env=dict(os.environ, PROBES=str(probes)),
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("RESULT=0", proc.stdout, proc.stdout)
        text = probes.read_text(encoding="utf-8")
        self.assertIn("cid-mirrorcap /usr/local/bin/mirrorcap --healthcheck", text)
        self.assertIn("cid-tproxyd /usr/local/bin/tproxyd --healthcheck", text)
        self.assertIn("cid-havipd /usr/local/bin/havipd --healthcheck", text)
        self.assertIn("cid-hasyncd /usr/local/bin/hasyncd --healthcheck", text)
        self.assertIn("cid-logrotator kill -0 1", text)
        self.assertIn("cid-containerops sh -ec test -S", text)
        self.assertIn("cid-pcapd kill -0 1", text)


if __name__ == "__main__":
    unittest.main()
