"""Transparent-mode (tproxyd / netmgrd) offline package, compose, Dockerfile, baremetal, healthcheck, host-prep, and diagnostics delivery tests."""
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tarfile
import tempfile
import threading
import unittest


ROOT = Path(__file__).resolve().parents[2]
BUILD_SCRIPT = ROOT / "ops/offline-package/build.sh"
PACKAGE_RUNTIME_RUN = ROOT / "ops/offline-package/package-runtime-run.sh"
BUILD_UPDATE_FULL = ROOT / "ops/offline-package/build-update-full.sh"
STAGE5_COMPOSE = ROOT / "deployment/docker-compose.stage5.yml"
TPROXYD_DOCKERFILE = ROOT / "gateway/images/tproxyd/Dockerfile"
NETMGRD_DOCKERFILE = ROOT / "gateway/images/netmgrd/Dockerfile"
BAREMETAL_DIR = ROOT / "ops/baremetal"
BAREMETAL_UNIT = BAREMETAL_DIR / "package/systemd/jiuzhang-tproxyd.service"
BAREMETAL_ENV = BAREMETAL_DIR / "package/env.template"
HEALTHCHECK_SCRIPT = ROOT / "ops/healthcheck/check.sh"
PREPARE_SCRIPT = ROOT / "ops/install/prepare-openeuler-zhaoxin.sh"
COLLECT_SCRIPT = ROOT / "ops/diagnostics/collect.sh"

EXPECTED_GATEWAY_CAPS = sorted(["NET_BIND_SERVICE", "SETGID", "SETPCAP", "SETUID"])
EXPECTED_NETMGRD_CAPS = sorted(["NET_ADMIN", "NET_RAW"])


class TproxydDeliveryTests(unittest.TestCase):
    def render_compose(self, compose_path, extra_env=None):
        if not shutil.which("docker"):
            self.skipTest("docker CLI unavailable")
        version = subprocess.run(
            ["docker", "compose", "version"],
            capture_output=True, text=True, timeout=10,
        )
        if version.returncode != 0:
            self.skipTest("docker compose plugin unavailable")
        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", ""),
            "POSTGRES_PASSWORD": "render-test-only",
            "VALKEY_PASSWORD": "render-test-only",
            "JIUZHANG_MASTER_KEY": "render-test-only",
        }
        if os.environ.get("DOCKER_HOST"):
            env["DOCKER_HOST"] = os.environ["DOCKER_HOST"]
        if extra_env:
            env.update(extra_env)
        result = subprocess.run(
            [
                "docker", "compose", "-f", str(compose_path),
                "--env-file", "/dev/null", "config", "--format", "json",
            ],
            cwd=compose_path.parent,
            env=env,
            capture_output=True,
            text=True,
            timeout=45,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(result.stdout)

    def assert_tproxyd_security_hardening(self, tproxyd):
        self.assertEqual(tproxyd.get("user"), "1000:1000")
        self.assertIs(tproxyd.get("read_only"), True)
        self.assertEqual(tproxyd.get("cap_drop"), ["ALL"])
        self.assertEqual(tproxyd.get("cap_add") or [], [])
        self.assertIn("no-new-privileges:true", tproxyd.get("security_opt") or [])
        self.assertIn("/tmp:size=8m,mode=1777", tproxyd.get("tmpfs") or [])
        env = tproxyd.get("environment") or {}
        self.assertEqual(env.get("TPROXY_CONFIG_FILE"), "/var/run/caddy/sidecars/tproxyd.json")
        self.assertEqual(env.get("TPROXY_LISTEN"), "0.0.0.0:15000")
        self.assertEqual(env.get("TPROXY_TARGET"), "127.0.0.1:15080")
        self.assertEqual(env.get("TPROXY_TARGET_TLS"), "127.0.0.1:15443")

    def test_offline_package_manifest_and_rendered_compose_contract(self):
        version = "0.0.0-tproxy-test"
        with tempfile.TemporaryDirectory(prefix="wdsp-tproxyd-pkg-") as tmp:
            work = Path(tmp)
            out_dir = work / "out"
            env = {
                "PATH": os.environ.get("PATH", ""),
                "HOME": os.environ.get("HOME", ""),
                "TMPDIR": str(work),
            }
            result = subprocess.run(
                [
                    "bash", str(BUILD_SCRIPT),
                    "--skip-images", "--development", "--runtime-only",
                    "--version", version,
                    "--product", "wdsp",
                    "--arch", "amd64",
                    "--output", str(out_dir),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=120,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

            archive = out_dir / f"jiuzhang-wdsp-offline-{version}-amd64.tar.gz"
            self.assertTrue(archive.is_file(), f"missing package archive: {archive}")

            unpacked = (work / "unpacked").resolve()
            unpacked.mkdir(parents=True, exist_ok=True)
            with tarfile.open(archive, "r:gz") as tf:
                for member in tf.getmembers():
                    target = (unpacked / member.name).resolve()
                    self.assertTrue(target == unpacked or unpacked in target.parents)
                    self.assertFalse(member.issym() or member.islnk())
                    if hasattr(tarfile, "data_filter"):
                        tf.extract(member, path=unpacked, filter="data")
                    else:
                        tf.extract(member, path=unpacked)

            pkg_root = unpacked / f"jiuzhang-wdsp-offline-{version}-amd64"
            manifest = json.loads((pkg_root / "manifest.json").read_text(encoding="utf-8"))
            images = manifest.get("images") or []
            self.assertEqual(len(images), 15, f"expected 15 images, got {len(images)}: {images}")
            image_refs = [item.get("image") for item in images]
            self.assertIn(f"jiuzhang-tproxyd:{version}", image_refs)
            for ref in image_refs:
                self.assertNotIn(":latest", ref or "")

            rendered = self.render_compose(pkg_root / "docker-compose.yml")
            services = rendered["services"]
            self.assertIn("tproxyd", services)
            tproxyd = services["tproxyd"]
            self.assertEqual(tproxyd.get("image"), f"jiuzhang-tproxyd:{version}")
            self.assertEqual(tproxyd.get("network_mode"), "host")
            self.assert_tproxyd_security_hardening(tproxyd)

            mounts = tproxyd.get("volumes") or []
            admin_mounts = [m for m in mounts if m.get("target") == "/var/run/caddy"]
            self.assertEqual(len(admin_mounts), 1, mounts)
            self.assertEqual(admin_mounts[0].get("type"), "volume")
            self.assertEqual(admin_mounts[0].get("source"), "gateway-admin")
            self.assertIs(admin_mounts[0].get("read_only"), True)

            # Gateway cap_add contract stays locked (no NET_ADMIN creep)
            self.assertEqual(sorted(services["gateway"].get("cap_add") or []), EXPECTED_GATEWAY_CAPS)

            allowed_services = (
                services["containerops"]
                .get("environment", {})
                .get("CONTAINEROPS_ALLOWED_SERVICES", "")
            )
            self.assertIn("tproxyd", [s.strip() for s in allowed_services.split(",")])

            api_env = services["api"].get("environment", {})
            self.assertEqual(api_env.get("GATEWAY_TPROXY_LISTEN"), "0.0.0.0:15000")
            self.assertEqual(api_env.get("GATEWAY_TPROXY_TARGET"), "127.0.0.1:15080")
            self.assertEqual(api_env.get("GATEWAY_TPROXY_TARGET_TLS"), "127.0.0.1:15443")

    def test_tproxyd_and_netmgrd_dockerfiles_hardening_and_tools(self):
        tproxyd_df = TPROXYD_DOCKERFILE.read_text(encoding="utf-8")
        self.assertNotIn(":latest", tproxyd_df)
        self.assertRegex(tproxyd_df, r"ARG\s+GOLANG_IMAGE_DIGEST=sha256:[0-9a-f]{64}")
        self.assertRegex(tproxyd_df, r"ARG\s+ALPINE_IMAGE_DIGEST=sha256:[0-9a-f]{64}")
        self.assertIn("${GOLANG_IMAGE_DIGEST:+@$GOLANG_IMAGE_DIGEST}", tproxyd_df)
        self.assertIn("${ALPINE_IMAGE_DIGEST:+@$ALPINE_IMAGE_DIGEST}", tproxyd_df)
        self.assertIn("CGO_ENABLED=0 GOAMD64=v1 GOOS=$TARGETOS GOARCH=$TARGETARCH", tproxyd_df)
        self.assertIn("COPY pcapevidence/go.mod", tproxyd_df)
        self.assertIn("COPY tproxyd/", tproxyd_df)
        self.assertIn("COPY cmd/tproxyd/", tproxyd_df)
        self.assertRegex(tproxyd_df, r"(?m)^USER\s+1000:1000\s*$")
        self.assertRegex(
            tproxyd_df,
            r'HEALTHCHECK\b[\s\S]*?CMD\s*\[\s*"/usr/local/bin/tproxyd"\s*,\s*"--healthcheck"\s*\]',
        )
        self.assertRegex(tproxyd_df, r'(?m)^ENTRYPOINT\s*\[\s*"/usr/local/bin/tproxyd"\s*\]\s*$')

        netmgrd_df = NETMGRD_DOCKERFILE.read_text(encoding="utf-8")
        self.assertNotIn(":latest", netmgrd_df)
        self.assertIn("COPY pcapevidence/go.mod", netmgrd_df)
        self.assertRegex(
            netmgrd_df,
            r"apk\s+add\s+--no-cache\b[^\n]*\biptables\b[^\n]*\bnftables\b",
        )
        for tool in ("iproute2", "iputils", "tcpdump", "traceroute"):
            self.assertRegex(netmgrd_df, rf"apk\s+add\s+--no-cache\b[^\n]*\b{tool}\b")

    def test_stage5_compose_renders_tproxyd_and_hardened_netmgrd(self):
        rendered = self.render_compose(STAGE5_COMPOSE)
        services = rendered["services"]
        self.assertIn("tproxyd", services)
        tproxyd = services["tproxyd"]
        self.assertEqual(tproxyd.get("network_mode"), "service:gateway")
        self.assert_tproxyd_security_hardening(tproxyd)

        mounts = tproxyd.get("volumes") or []
        admin_mounts = [m for m in mounts if m.get("target") == "/var/run/caddy"]
        self.assertEqual(len(admin_mounts), 1, mounts)
        self.assertEqual(admin_mounts[0].get("source"), "stage5-gateway-admin")
        self.assertIs(admin_mounts[0].get("read_only"), True)

        # netmgrd hardening synced with offline build.sh
        netmgrd = services["netmgrd"]
        self.assertEqual(netmgrd.get("network_mode"), "service:gateway")
        self.assertIs(netmgrd.get("read_only"), True)
        self.assertEqual(netmgrd.get("cap_drop"), ["ALL"])
        self.assertEqual(sorted(netmgrd.get("cap_add") or []), EXPECTED_NETMGRD_CAPS)
        self.assertIn("1000", [str(g) for g in (netmgrd.get("group_add") or [])])
        self.assertIn("no-new-privileges:true", netmgrd.get("security_opt") or [])
        self.assertIn("/tmp:size=16m,mode=1777", netmgrd.get("tmpfs") or [])

        # Gateway cap_add contract stays locked
        self.assertEqual(sorted(services["gateway"].get("cap_add") or []), EXPECTED_GATEWAY_CAPS)

        allowed_services = (
            services["containerops"]
            .get("environment", {})
            .get("CONTAINEROPS_ALLOWED_SERVICES", "")
        )
        self.assertIn("tproxyd", [s.strip() for s in allowed_services.split(",")])

        api_env = services["api"].get("environment", {})
        self.assertEqual(api_env.get("GATEWAY_TPROXY_LISTEN"), "0.0.0.0:15000")
        self.assertEqual(api_env.get("GATEWAY_TPROXY_TARGET"), "127.0.0.1:15080")
        self.assertEqual(api_env.get("GATEWAY_TPROXY_TARGET_TLS"), "127.0.0.1:15443")

    def test_package_runtime_run_and_build_update_full_include_tproxyd(self):
        with tempfile.TemporaryDirectory(prefix="wdsp-tproxyd-run-") as tmp:
            work = Path(tmp)
            rpm_dir = work / "openeuler-rpms"
            rpm_dir.mkdir()
            (rpm_dir / "docker-compose-plugin-2.29.7-1.x86_64.rpm").touch()
            output = work / "out"
            env = dict(os.environ)
            env.pop("WDSP_SIGNING_KEY", None)
            result = subprocess.run(
                [
                    "bash", str(PACKAGE_RUNTIME_RUN),
                    "--dry-run",
                    "--version", "9.9.9",
                    "--output", str(output),
                    "--rpm-dir", str(rpm_dir),
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("jiuzhang-tproxyd:9.9.9", result.stdout)
            self.assertIn("gateway/images/tproxyd/Dockerfile", result.stdout)
            self.assertFalse(output.exists())

        runtime_run_src = PACKAGE_RUNTIME_RUN.read_text(encoding="utf-8")
        self.assertIn("(.images | length) == 15", runtime_run_src)
        self.assertIn("jiuzhang-tproxyd", runtime_run_src)

        update_full_src = BUILD_UPDATE_FULL.read_text(encoding="utf-8")
        self.assertIn("jiuzhang-tproxyd", update_full_src)
        self.assertIn("gateway/images/tproxyd/Dockerfile", update_full_src)
        self.assertIn("(.images | length) == 15", update_full_src)
        self.assertIn("([.images[].image] | unique | length) == 15", update_full_src)
        self.assertIn(".services.tproxyd.user == \"1000:1000\"", update_full_src)

    def test_baremetal_delivery_unit_env_and_lifecycle_scripts(self):
        unit = BAREMETAL_UNIT.read_text(encoding="utf-8")
        self.assertRegex(unit, r"(?m)^User=__USER__\s*$")
        self.assertRegex(unit, r"(?m)^Group=__USER__\s*$")
        self.assertNotIn("User=root", unit)
        self.assertRegex(unit, r"(?m)^CapabilityBoundingSet=\s*$")
        self.assertRegex(unit, r"(?m)^NoNewPrivileges=yes\s*$")
        self.assertRegex(unit, r"(?m)^ProtectSystem=strict\s*$")
        self.assertRegex(unit, r"(?m)^EnvironmentFile=__ROOT__/env\s*$")
        self.assertRegex(unit, r"(?m)^ExecStart=__ROOT__/bin/tproxyd\s*$")

        env_template = BAREMETAL_ENV.read_text(encoding="utf-8")
        for key, expected in (
            ("GATEWAY_TPROXY_LISTEN", "0.0.0.0:15000"),
            ("GATEWAY_TPROXY_TARGET", "127.0.0.1:15080"),
            ("GATEWAY_TPROXY_TARGET_TLS", "127.0.0.1:15443"),
            ("TPROXY_CONFIG_FILE", "__ROOT__/data/run/caddy/sidecars/tproxyd.json"),
            ("TPROXY_LISTEN", "0.0.0.0:15000"),
            ("TPROXY_TARGET", "127.0.0.1:15080"),
            ("TPROXY_TARGET_TLS", "127.0.0.1:15443"),
            ("TPROXY_HEALTH_ADDR", "127.0.0.1:15001"),
        ):
            self.assertRegex(env_template, rf"(?m)^{re.escape(key)}={re.escape(expected)}\s*$")

        build_binaries = (BAREMETAL_DIR / "build-binaries.sh").read_text(encoding="utf-8")
        self.assertIn("tproxyd", build_binaries)
        self.assertIn("./cmd/tproxyd", build_binaries)

        assemble = (BAREMETAL_DIR / "assemble.sh").read_text(encoding="utf-8")
        self.assertIn("tproxyd", assemble)

        install_sh = (BAREMETAL_DIR / "package/install.sh").read_text(encoding="utf-8")
        self.assertIn("jiuzhang-tproxyd", install_sh)
        self.assertIn("iptables", install_sh)
        self.assertIn("/etc/modules-load.d/jiuzhang-transparent.conf", install_sh)
        self.assertIn("br_netfilter", install_sh)
        self.assertIn("nf_conntrack", install_sh)
        self.assertIn("xt_REDIRECT", install_sh)

        for script_rel in ("package/restore.sh", "package/uninstall.sh", "package/README.md"):
            text = (BAREMETAL_DIR / script_rel).read_text(encoding="utf-8")
            self.assertIn("jiuzhang-tproxyd", text, script_rel)

        for script_path in (
            BAREMETAL_DIR / "build-binaries.sh",
            BAREMETAL_DIR / "assemble.sh",
            BAREMETAL_DIR / "package/install.sh",
            BAREMETAL_DIR / "package/restore.sh",
            BAREMETAL_DIR / "package/uninstall.sh",
            BUILD_SCRIPT,
            PACKAGE_RUNTIME_RUN,
            BUILD_UPDATE_FULL,
            HEALTHCHECK_SCRIPT,
            PREPARE_SCRIPT,
            COLLECT_SCRIPT,
        ):
            res = subprocess.run(
                ["bash", "-n", str(script_path)],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(res.returncode, 0, f"bash -n failed for {script_path}: {res.stderr}")

    def test_healthcheck_probes_sidecars_and_handles_proxy_protocol_and_bind_hosts(self):
        # Start a local TCP server to verify proxy_protocol PROXY UNKNOWN probe and avoid false 127.0.0.1 dialing.
        received = []
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(5)
        listen_port = listener.getsockname()[1]
        stop_event = threading.Event()

        def serve():
            listener.settimeout(0.2)
            while not stop_event.is_set():
                try:
                    conn, _ = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                with conn:
                    conn.settimeout(1.0)
                    try:
                        data = conn.recv(64)
                    except OSError:
                        data = b""
                    received.append(data)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        self.addCleanup(lambda: (stop_event.set(), listener.close(), thread.join(timeout=2)))

        docker_stub = r'''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
if args[:1] == ["compose"]:
    if "config" in args and "--services" in args:
        for svc in os.environ.get("DECLARED_SERVICES", "").split(","):
            if svc:
                print(svc)
        sys.exit(0)
    if "ps" in args and "-q" in args:
        svc = args[-1]
        print({"gateway": "aaa111", "api": "bbb222", "netmgrd": "ccc333", "tproxyd": "ddd444"}.get(svc, ""))
        sys.exit(0)
    if "ps" in args:
        print(os.environ.get("PS_OUT", "fixture-gateway running healthy"))
        sys.exit(0)
if args[:1] == ["inspect"]:
    print(json.dumps([{"Destination": "/var/run/caddy", "Source": os.environ["SOCKET_DIR"]}]))
    sys.exit(0)
if args[:1] == ["ps"]:
    print("jiuzhang-postgres")
    print("jiuzhang-valkey")
    sys.exit(0)
if args[:1] == ["exec"]:
    with open(os.environ["EXEC_LOG"], "a", encoding="utf-8") as fh:
        fh.write(" ".join(args) + "\n")
    if os.environ.get("FAIL_SIDECAR") and os.environ["FAIL_SIDECAR"] in " ".join(args):
        sys.exit(1)
    sys.exit(0)
sys.exit(1)
'''
        curl_stub = r'''#!/usr/bin/env python3
import os, sys
args = " ".join(sys.argv[1:])
if "/api/v1/health" in args:
    print('{"status":"ok"}')
elif "/config/apps/http/servers" in args:
    print(os.environ["LISTENERS"], end="")
sys.exit(0)
'''

        def run_check(listeners, declared_services="gateway,netmgrd,tproxyd", fail_sidecar="", ps_out="fixture-gateway running healthy"):
            with tempfile.TemporaryDirectory(prefix="wdsp-tproxy-hc-") as tmp:
                work = Path(tmp)
                bin_dir = work / "bin"
                bin_dir.mkdir()
                for name, body in (("docker", docker_stub), ("curl", curl_stub)):
                    p = bin_dir / name
                    p.write_text(body, encoding="utf-8")
                    p.chmod(0o755)
                compose = work / "docker-compose.yml"
                env_file = work / "fixture.env"
                exec_log = work / "exec.log"
                compose.write_text("{}\n", encoding="utf-8")
                env_file.write_text("VALKEY_PASSWORD=fixture\n", encoding="utf-8")
                sock = socket.socket(socket.AF_UNIX)
                sock.bind(str(work / "admin.sock"))
                try:
                    env = dict(
                        os.environ,
                        PATH=str(bin_dir) + os.pathsep + os.environ["PATH"],
                        SOCKET_DIR=str(work),
                        LISTENERS=listeners,
                        DECLARED_SERVICES=declared_services,
                        FAIL_SIDECAR=fail_sidecar,
                        PS_OUT=ps_out,
                        EXEC_LOG=str(exec_log),
                    )
                    res = subprocess.run(
                        [
                            "bash", str(HEALTHCHECK_SCRIPT),
                            "-c", str(compose), "-e", str(env_file),
                            "--api-url", "http://127.0.0.1:18081",
                        ],
                        env=env, capture_output=True, text=True, timeout=10,
                    )
                    log_text = exec_log.read_text(encoding="utf-8") if exec_log.exists() else ""
                    return res.returncode, res.stdout + res.stderr, log_text
                finally:
                    sock.close()

        # 1) proxy_protocol listener sends PROXY UNKNOWN cleanly and netmgrd/tproxyd --healthcheck run
        pp_listeners = json.dumps({
            "srv_tproxy_http": {
                "listen": [f"127.0.0.1:{listen_port}"],
                "listener_wrappers": [{"wrapper": "proxy_protocol"}],
            }
        })
        code, out, execs = run_check(pp_listeners)
        self.assertEqual(code, 0, out)
        self.assertIn("[OK]   netmgrd", out)
        self.assertIn("[OK]   tproxyd", out)
        self.assertIn("exec ccc333 /usr/local/bin/netmgrd --healthcheck", execs)
        self.assertIn("exec ddd444 /usr/local/bin/tproxyd --healthcheck", execs)
        if not shutil.which("ss"):
            self.assertTrue(any(b"PROXY UNKNOWN\r\n" in chunk for chunk in received), received)

        # 2) tproxyd --healthcheck failure fails check.sh
        code, out, _ = run_check(pp_listeners, fail_sidecar="/usr/local/bin/tproxyd")
        self.assertEqual(code, 1, out)
        self.assertIn("[FAIL] tproxyd", out)

        # 3) netmgrd --healthcheck failure fails check.sh
        code, out, _ = run_check(pp_listeners, fail_sidecar="/usr/local/bin/netmgrd")
        self.assertEqual(code, 1, out)
        self.assertIn("[FAIL] netmgrd", out)

        # 4) unhealthy container is flagged by containers check
        code, out, _ = run_check("{}", ps_out="fixture-tproxyd running unhealthy")
        self.assertEqual(code, 1, out)
        self.assertIn("[FAIL] containers", out)
        self.assertIn("fixture-tproxyd(unhealthy)", out)

        # 5) parse_caddy_listen preserves non-loopback bind host (never rewrites 192.168.50.1 -> 127.0.0.1)
        parse_check = subprocess.run(
            [
                "bash", "-c",
                f"""
                set -euo pipefail
                eval "$(awk '/^parse_caddy_listen\\(\\)/,/^\\}}/' {str(HEALTHCHECK_SCRIPT)!r})"
                parse_caddy_listen "192.168.50.1:80"
                parse_caddy_listen "127.0.0.1:15080"
                parse_caddy_listen ":443"
                parse_caddy_listen "[fd00::1]:8443"
                """,
            ],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(parse_check.returncode, 0, parse_check.stderr)
        lines = parse_check.stdout.strip().splitlines()
        self.assertEqual(lines, [
            "192.168.50.1\t80\tfalse\t192.168.50.1:80",
            "127.0.0.1\t15080\tfalse\t127.0.0.1:15080",
            "127.0.0.1\t443\ttrue\t:443",
            "fd00::1\t8443\tfalse\t[fd00::1]:8443",
        ])

    def test_prepare_openeuler_persists_transparent_modules_and_guards_bridge_sysctl(self):
        with tempfile.TemporaryDirectory(prefix="wdsp-prep-tproxy-") as tmp:
            base = Path(tmp)
            etc_root = base / "etc"
            proc_with_bridge = base / "proc_with"
            proc_without_bridge = base / "proc_without"
            (proc_with_bridge / "net/bridge").mkdir(parents=True)
            (proc_with_bridge / "net/bridge/bridge-nf-call-iptables").touch()
            (proc_without_bridge / "net/ipv4").mkdir(parents=True)

            # With br_netfilter sysctl present
            res = subprocess.run(
                [
                    "bash", "-c",
                    f"""
                    set -euo pipefail
                    source {str(PREPARE_SCRIPT)!r}
                    ETC_ROOT={str(etc_root)!r}
                    PROC_SYS_ROOT={str(proc_with_bridge)!r}
                    DRY_RUN=false
                    write_transparent_modules_config
                    write_sysctl_config
                    """,
                ],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            mod_conf = (etc_root / "modules-load.d/jiuzhang-transparent.conf").read_text(encoding="utf-8")
            for mod in ("br_netfilter", "nf_conntrack", "xt_REDIRECT"):
                self.assertRegex(mod_conf, rf"(?m)^{mod}\s*$")
            sysctl_with = (etc_root / "sysctl.d/99-jiuzhang-wdsp.conf").read_text(encoding="utf-8")
            self.assertIn("net.bridge.bridge-nf-call-iptables = 1", sysctl_with)

            # Without br_netfilter sysctl present -> omitted safely
            res = subprocess.run(
                [
                    "bash", "-c",
                    f"""
                    set -euo pipefail
                    source {str(PREPARE_SCRIPT)!r}
                    ETC_ROOT={str(etc_root)!r}
                    PROC_SYS_ROOT={str(proc_without_bridge)!r}
                    DRY_RUN=false
                    write_sysctl_config
                    """,
                ],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            sysctl_without = (etc_root / "sysctl.d/99-jiuzhang-wdsp.conf").read_text(encoding="utf-8")
            self.assertNotIn("net.bridge.bridge-nf-call-iptables", sysctl_without)

    def test_diagnostics_collect_includes_redacted_transparent_and_allowlisted_sidecars(self):
        with tempfile.TemporaryDirectory(prefix="wdsp-diag-tproxy-") as tmp:
            work = Path(tmp)
            out_dir = work / "out"
            sidecars = work / "sidecars"
            sidecars.mkdir()
            (sidecars / "network.json").write_text('{"mode":"TRANSPARENT","bridges":[{"name":"br0"}]}\n', encoding="utf-8")
            (sidecars / "network-status.json").write_text('{"ok":true,"token":"secret-sidecar-token"}\n', encoding="utf-8")
            (sidecars / "tproxyd.json").write_text('{"enabled":true,"listen":"0.0.0.0:15000","target":"127.0.0.1:15080"}\n', encoding="utf-8")
            # Sensitive non-allowlisted files MUST NOT be collected
            (sidecars / "ha-vip.json").write_text('{"auth_pass":"TOP_SECRET_VRRP_PASS"}\n', encoding="utf-8")
            (sidecars / "capability.json").write_text('{"secret_cap":"TOP_SECRET_CAP"}\n', encoding="utf-8")

            env_file = work / ".env"
            env_file.write_text("POSTGRES_PASSWORD=supersecret\n", encoding="utf-8")
            compose_file = work / "docker-compose.yml"
            compose_file.write_text("services: {}\n", encoding="utf-8")

            bin_dir = work / "bin"
            bin_dir.mkdir()
            (bin_dir / "docker").write_text(
                "#!/usr/bin/env bash\n"
                "case \"$*\" in\n"
                "  *--version*) echo 'Docker version 28.0.0' ;;\n"
                "  *'compose version'*) echo 'Docker Compose version v2.36.0' ;;\n"
                "  *'system df'*) echo 'Images space usage: 0B' ;;\n"
                "  *) echo 'NAME IMAGE STATUS' ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            (bin_dir / "curl").write_text(
                "#!/usr/bin/env bash\nprintf '{\"status\":\"ok\"}\\n'\n",
                encoding="utf-8",
            )
            (bin_dir / "iptables").write_text(
                "#!/usr/bin/env bash\n"
                "echo '-A PREROUTING -i br0 -p tcp --dport 80 -j REDIRECT --to-ports 15000'\n",
                encoding="utf-8",
            )
            for tool in ("docker", "curl", "iptables"):
                (bin_dir / tool).chmod(0o755)

            env = dict(
                os.environ,
                PATH=str(bin_dir) + os.pathsep + os.environ["PATH"],
                GATEWAY_SIDECAR_DIR=str(sidecars),
            )
            res = subprocess.run(
                [
                    "bash", str(COLLECT_SCRIPT),
                    "--output", str(out_dir),
                    "--compose-file", str(compose_file),
                    "--env-file", str(env_file),
                    "--api-url", "http://127.0.0.1:18081",
                ],
                env=env, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            archives = list(out_dir.glob("diagnostics-*.tar.gz"))
            self.assertEqual(len(archives), 1, archives)

            unpacked = work / "unpacked"
            unpacked.mkdir()
            with tarfile.open(archives[0], "r:gz") as tf:
                if hasattr(tarfile, "data_filter"):
                    tf.extractall(unpacked, filter="data")
                else:
                    tf.extractall(unpacked)

            net_diag = (unpacked / "network-transparent.txt").read_text(encoding="utf-8")
            self.assertIn("== ip -d link show ==", net_diag)
            self.assertIn("== bridge link show ==", net_diag)
            self.assertIn("== ip route show ==", net_diag)
            self.assertIn("== sysctl (transparent allowlist) ==", net_diag)
            self.assertIn("== netfilter (iptables/nft read-only) ==", net_diag)
            self.assertIn("REDIRECT --to-ports 15000", net_diag)

            sidecars_diag = (unpacked / "sidecars.txt").read_text(encoding="utf-8")
            self.assertIn("TRANSPARENT", sidecars_diag)
            self.assertIn("0.0.0.0:15000", sidecars_diag)
            self.assertNotIn("secret-sidecar-token", sidecars_diag)
            self.assertIn("[REDACTED]", sidecars_diag)
            self.assertNotIn("TOP_SECRET_VRRP_PASS", sidecars_diag)
            self.assertNotIn("TOP_SECRET_CAP", sidecars_diag)


if __name__ == "__main__":
    unittest.main()
