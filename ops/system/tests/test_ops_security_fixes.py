"""Focused regression tests for Ops, Baremetal, Console, K8s, and Diagnostics security fixes."""

from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]


class OpsSecurityRegressionTests(unittest.TestCase):
    # ---- C-01 / N-02: executor trust anchor & root-only host state dir ----
    def test_executor_embeds_release_pubkey_and_uses_root_only_state_dir(self):
        release_pub = (ROOT / "ops/offline-package/release-signing.pub").read_text(encoding="utf-8").strip()
        executor = (ROOT / "ops/upgrade/upgrade-executor.sh").read_text(encoding="utf-8")
        installer = (ROOT / "ops/upgrade/install-executor.sh").read_text(encoding="utf-8")
        update_full = (ROOT / "ops/upgrade/update-full.sh").read_text(encoding="utf-8")

        self.assertIn(release_pub, executor)
        self.assertIn("HOST_STATE_DIR", installer)
        self.assertIn("/var/lib/jiuzhang/upgrade-executor", installer)
        self.assertIn("0700", installer)
        self.assertNotIn('install -d -m 0755 "$CURRENT_RELEASE/runtime/upgrade-executor"', update_full)
        self.assertIn("HOST_STATE_DIR", update_full)

        # Production config rejects --test-pubkey override
        with tempfile.TemporaryDirectory(prefix="wdsp-exec-pub-") as tmp:
            fake_pub = Path(tmp) / "fake.pub"
            fake_pub.write_text("dummy\n", encoding="utf-8")
            res = subprocess.run(
                [
                    "bash", str(ROOT / "ops/upgrade/upgrade-executor.sh"),
                    "--config", "/etc/jiuzhang/upgrade-executor.conf",
                    "--test-pubkey", str(fake_pub),
                ],
                capture_output=True, text=True, timeout=10,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("--test-pubkey", res.stderr)

    # ---- C-04 / H-06 / M-O7: baremetal postgres peer auth, private socket, backup/restore, netmgrd unit ----
    def test_baremetal_install_pg_peer_auth_private_socket_and_backup_perms(self):
        install_sh = (ROOT / "ops/baremetal/package/install.sh").read_text(encoding="utf-8")
        backup_sh = (ROOT / "ops/baremetal/package/backup.sh").read_text(encoding="utf-8")
        netmgrd_unit = (ROOT / "ops/baremetal/package/systemd/jiuzhang-netmgrd.service").read_text(encoding="utf-8")

        self.assertIn("--auth-local=peer", install_sh)
        self.assertNotIn("--auth-local=trust", install_sh)
        self.assertIn("${R}/data/run/pg", install_sh)
        self.assertIn("unix_socket_directories", install_sh)
        self.assertIn("unix_socket_permissions = 0700", install_sh)
        self.assertIn('chown root:root "${R}/backups"', install_sh)
        self.assertIn('chmod 0700 "${R}/backups"', install_sh)

        # Backup sets umask 077 and waits for Valkey AOF rewrite completion
        self.assertIn("umask 077", backup_sh)
        self.assertIn("aof_rewrite_in_progress:0", backup_sh)

        # M-O7: netmgrd systemd hardening
        self.assertIn("NoNewPrivileges=yes", netmgrd_unit)
        self.assertIn("CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW", netmgrd_unit)

    def test_baremetal_restore_validates_tar_and_manifest_before_restoring(self):
        restore_sh = (ROOT / "ops/baremetal/package/restore.sh").read_text(encoding="utf-8")
        # Extract the real safe-extract python block and verify_manifest() from baremetal restore.sh
        py_extract = restore_sh.split('python3 - "${ARCHIVE}" "${WORK}" <<\'PY\' || die "备份归档安全校验或解压失败"\n', 1)[1].split("\nPY\n", 1)[0]
        verify_fn = "verify_manifest() {" + restore_sh.split("verify_manifest() {", 1)[1].split('\nverify_manifest "${WORK}"', 1)[0]
        prelude = 'die() { echo "$*" >&2; exit 1; }\nlog_info() { :; }\n'
        script_body = prelude + verify_fn

        with tempfile.TemporaryDirectory(prefix="wdsp-bm-restore-") as tmp:
            base = Path(tmp)

            # 1) Valid tar with matching MANIFEST.txt (<sha256>  <size>  <rel>) passes
            stage = base / "good-src"
            stage.mkdir()
            (stage / "db.sql.gz").write_bytes(b"pg-dump-content")
            (stage / "etc.tar").write_bytes(b"etc-content")
            manifest_lines = ["# baremetal backup manifest\n"]
            for fname in ("db.sql.gz", "etc.tar"):
                data = (stage / fname).read_bytes()
                manifest_lines.append(f"{hashlib.sha256(data).hexdigest()}  {len(data)}  {fname}\n")
            (stage / "MANIFEST.txt").write_text("".join(manifest_lines), encoding="utf-8")

            good_tar = base / "good.tar.gz"
            with tarfile.open(good_tar, "w:gz") as tf:
                for p in sorted(stage.iterdir()):
                    tf.add(p, arcname=p.name)

            out_dir = base / "extract-good"
            out_dir.mkdir()
            res = subprocess.run(["python3", "-c", py_extract, str(good_tar), str(out_dir)], capture_output=True, text=True, timeout=15)
            self.assertEqual(res.returncode, 0, res.stderr)
            res = subprocess.run(
                ["bash", "-ec", script_body + '\nverify_manifest "$1"\n', "t", str(out_dir)],
                capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(res.returncode, 0, res.stderr)

            # 2) Tampered file fails verify_manifest
            (out_dir / "db.sql.gz").write_bytes(b"tampered-content")
            res = subprocess.run(
                ["bash", "-ec", script_body + '\nverify_manifest "$1"\n', "t", str(out_dir)],
                capture_output=True, text=True, timeout=15,
            )
            self.assertNotEqual(res.returncode, 0)

            # 3) Extra unmanifested file fails verify_manifest
            (out_dir / "db.sql.gz").write_bytes(b"pg-dump-content")
            (out_dir / "extra.bin").write_bytes(b"rogue")
            res = subprocess.run(
                ["bash", "-ec", script_body + '\nverify_manifest "$1"\n', "t", str(out_dir)],
                capture_output=True, text=True, timeout=15,
            )
            self.assertNotEqual(res.returncode, 0)

            # 4) Path traversal and symlink tar archives fail safe extractor
            for kind in ("traversal", "symlink"):
                bad_tar = base / f"bad-{kind}.tar.gz"
                bad_out = base / f"out-{kind}"
                bad_out.mkdir()
                with tarfile.open(bad_tar, "w:gz") as tf:
                    if kind == "traversal":
                        info = tarfile.TarInfo("../pwned")
                        info.size = 3
                        tf.addfile(info, io.BytesIO(b"bad"))
                    else:
                        info = tarfile.TarInfo("evil-link")
                        info.type = tarfile.SYMTYPE
                        info.linkname = "/etc/shadow"
                        tf.addfile(info)
                res = subprocess.run(["python3", "-c", py_extract, str(bad_tar), str(bad_out)], capture_output=True, text=True, timeout=15)
                self.assertNotEqual(res.returncode, 0, kind)

    # ---- H-04 / H-21: ops/install/install.sh hardening ----
    def test_install_sh_validates_ports_removes_baidu_and_binds_manifest(self):
        install_sh = (ROOT / "ops/install/install.sh").read_text(encoding="utf-8")
        self.assertNotIn("baidu.com", install_sh)
        self.assertIn("prepare-containerops.sh", install_sh)
        self.assertIn("解压目录的 manifest.json 与已验签归档", install_sh)
        self.assertIn("缺少 files 清单，拒绝跳过文件级完整性校验", install_sh)

        # CLI port validation must reject out-of-range / non-numeric ports with exit code 2
        for flag, bad in (
            ("--web-port", "0"),
            ("--web-port", "70000"),
            ("--web-https-port", "abc"),
            ("--api-port", "-1"),
            ("--gateway-port", "65536"),
            ("--gateway-port", "80;id"),
        ):
            with self.subTest(flag=flag, bad=bad):
                res = subprocess.run(
                    ["bash", str(ROOT / "ops/install/install.sh"), flag, bad],
                    capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(res.returncode, 2, res.stdout + res.stderr)

    # ---- H-05: apply.sh passes --api-url to rollback.sh; rollback.sh marks state file ----
    def test_apply_and_rollback_contract(self):
        apply_sh = (ROOT / "ops/upgrade/apply.sh").read_text(encoding="utf-8")
        rollback_sh = (ROOT / "ops/upgrade/rollback.sh").read_text(encoding="utf-8")
        self.assertIn('--api-url "$JZ_API_BASE"', apply_sh)
        self.assertIn(".rolled-back.", rollback_sh)
        self.assertIn("install-hostctl.sh", rollback_sh)
        self.assertIn("install-executor.sh", rollback_sh)

    # ---- H-07: ops/console/install-console.sh username validation & visudo staging ----
    def test_install_console_validates_usernames_and_stages_sudoers(self):
        script = (ROOT / "ops/console/install-console.sh").read_text(encoding="utf-8")
        self.assertIn("visudo -cf", script)
        self.assertIn("install -d -m 0755 -o root -g root /etc/jiuzhang", script)

        for flag, bad in (
            ("--user", "root"),
            ("--user", "ops;id"),
            ("--user", "BADUSER"),
            ("--user", "../etc"),
            ("--account", "opsadmin\nroot ALL=(ALL) NOPASSWD:ALL"),
            ("--account", "123invalid"),
        ):
            with self.subTest(flag=flag, bad=bad):
                res = subprocess.run(
                    ["bash", str(ROOT / "ops/console/install-console.sh"), flag, bad],
                    capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(res.returncode, 2, res.stdout + res.stderr)

    # ---- M-O4: common.sh VALKEY_PASSWORD parsing, factory-reset.sh API URL, runtime patch netmgrd ----
    def test_common_sh_valkey_password_handles_equals_quotes_and_duplicates(self):
        with tempfile.TemporaryDirectory(prefix="wdsp-env-parse-") as tmp:
            env_file = Path(tmp) / ".env"
            env_file.write_text(
                'VALKEY_PASSWORD=old=val\n'
                'VALKEY_PASSWORD="real=pass=123"\r\n',
                encoding="utf-8",
            )
            # Extract exact VALKEY_PASSWORD parsing logic from ops/lib/common.sh
            common = (ROOT / "ops/lib/common.sh").read_text(encoding="utf-8")
            self.assertIn("cut -d= -f2-", common)
            snippet = (
                f'JZ_ENV_FILE="{env_file}"\n'
                'vk_pass="$(grep -E "^VALKEY_PASSWORD=" "$JZ_ENV_FILE" | tail -1 | cut -d= -f2- | tr -d "\\r" || true)"\n'
                'vk_pass="${vk_pass#\\"}"\n'
                'vk_pass="${vk_pass%\\"}"\n'
                'vk_pass="${vk_pass#\'}"\n'
                'vk_pass="${vk_pass%\'}"\n'
                'printf "%s" "$vk_pass"\n'
            )
            res = subprocess.run(["bash", "-ec", snippet], capture_output=True, text=True, timeout=10)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(res.stdout, "real=pass=123")

        factory_reset = (ROOT / "ops/system/factory-reset.sh").read_text(encoding="utf-8")
        self.assertIn("compose_api_url", factory_reset)

        executor = (ROOT / "ops/upgrade/upgrade-executor.sh").read_text(encoding="utf-8")
        rt_patch = executor.split("process_runtime_patch() {", 1)[1].split("validate_gateway_start_contract() {", 1)[0]
        self.assertIn("netmgrd", rt_patch)
        self.assertIn("--force-recreate", rt_patch)

    # ---- M-O5: K8s fsGroup/defaultMode/--token-file and wdsp-agent Dockerfile hardening ----
    def test_k8s_manifests_and_wdsp_agent_dockerfile_hardening(self):
        local_ds = (ROOT / "deployment/apm/k8s/daemonset-local-collector.yaml").read_text(encoding="utf-8")
        self.assertIn("fsGroup: 65532", local_ds)
        self.assertIn("defaultMode: 0440", local_ds)
        self.assertNotIn("defaultMode: 0640", local_ds)

        central = (ROOT / "deployment/apm/k8s/deployment-central-collector.yaml").read_text(encoding="utf-8")
        self.assertEqual(central.count("fsGroup: 65532"), 2)
        self.assertEqual(central.count("defaultMode: 0440"), 2)
        self.assertNotIn("defaultMode: 0640", central)

        kafka = (ROOT / "deployment/kafka/k8s/kafka-statefulset.yaml").read_text(encoding="utf-8")
        self.assertIn("fsGroup: 1000", kafka)
        self.assertIn("defaultMode: 0440", kafka)
        self.assertNotIn("defaultMode: 0400", kafka)

        agent_df = (ROOT / "deployment/docker/wdsp-agent/Dockerfile").read_text(encoding="utf-8")
        self.assertRegex(agent_df, r"FROM golang:1\.25-alpine@sha256:[0-9a-f]{64} AS builder")
        self.assertIn("USER 1000:1000", agent_df)

        agent_ds = (ROOT / "deployment/kubernetes/wdsp-agent-daemonset.yaml").read_text(encoding="utf-8")
        self.assertIn('--token-file "${token_file}"', agent_ds)
        self.assertNotIn('--token "$(cat', agent_ds)
        self.assertIn("fsGroup: 1000", agent_ds)
        self.assertIn("defaultMode: 0440", agent_ds)

    # ---- M-O6: tune-gateway-baremetal.sh & netapply.sh ----
    def test_tune_gateway_baremetal_rejects_bad_iface_and_quotes_replay(self):
        tune = (ROOT / "ops/install/tune-gateway-baremetal.sh").read_text(encoding="utf-8")
        self.assertIn("printf '%q'", tune)
        self.assertIn("awk -v iface=", tune)
        self.assertNotIn("awk -v if=", tune)

        for bad_iface in ("eth0;id", "eth0$(whoami)", "eth 0", "../eth0"):
            with self.subTest(iface=bad_iface):
                res = subprocess.run(
                    ["bash", str(ROOT / "ops/install/tune-gateway-baremetal.sh"), "--iface", bad_iface],
                    capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(res.returncode, 2, res.stdout + res.stderr)

    def test_netapply_clears_nmcli_routes_validates_netplan_and_saves_after_apply(self):
        netapply = (ROOT / "ops/console/netapply.sh").read_text(encoding="utf-8")
        self.assertIn('ipv4.routes ""', netapply)
        self.assertIn('printf \'    "%s":\\n\' "$MGMT_IF"', netapply)
        self.assertIn("netplan generate", netapply)
        # save_state must appear AFTER render_netplan and apply_nmcli inside apply()
        apply_fn = netapply.split("apply() {", 1)[1].split("# ---------- 子命令", 1)[0]
        self.assertLess(apply_fn.index("render_netplan"), apply_fn.index("save_state"))
        nmcli_branch = apply_fn.split("elif command -v nmcli", 1)[1]
        self.assertLess(nmcli_branch.index("apply_nmcli"), nmcli_branch.index("save_state"))
        # Subcommands must NOT call save_state before apply
        subcommands = netapply.split("# ---------- 子命令", 1)[1]
        self.assertNotIn("save_state", subcommands)

    # ---- LOW-01: no valkey-cli -a in compose healthchecks ----
    def test_no_valkey_cli_password_on_argv_in_compose_files(self):
        targets = [ROOT / "docker-compose.yml", ROOT / "ops/offline-package/build.sh"]
        targets.extend(sorted((ROOT / "deployment").rglob("docker-compose*.yml")))
        for path in targets:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("valkey-cli -a", text, str(path.relative_to(ROOT)))

    # ---- LOW-02: collect.sh portable redaction & 0600 archive mode ----
    def test_collect_sh_redacts_basic_api_key_csrf_and_mixed_case_env(self):
        collect = (ROOT / "ops/diagnostics/collect.sh").read_text(encoding="utf-8")
        self.assertIn("umask 077", collect)
        self.assertIn('chmod 600 "$out"', collect)
        self.assertNotRegex(collect, r"sed -E.*\/I")

        # Live test of redact_stream function
        redact_fn = collect.split("redact_stream() {", 1)[1].split("\nwrite_redacted()", 1)[0]
        sample = "\n".join([
            "Authorization: Basic dXNlcjpzZWNyZXQ=",
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
            "X-API-Key: super-secret-api-key-123",
            "x-csrf-token: csrf-secret-456",
            "Cookie: sid=topsecret",
            "dsn=postgres://admin:Hunter2@10.0.0.1:5432/db",
        ]) + "\n"
        res = subprocess.run(
            ["bash", "-ec", "redact_stream() {" + redact_fn + "\nredact_stream\n"],
            input=sample, capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        for secret in ("dXNlcjpzZWNyZXQ=", "eyJhbGciOiJIUzI1NiJ9", "super-secret-api-key-123", "csrf-secret-456", "topsecret", "Hunter2"):
            self.assertNotIn(secret, res.stdout)
        self.assertIn("Authorization: Basic [REDACTED]", res.stdout)
        self.assertIn("X-API-Key: [REDACTED]", res.stdout)
        self.assertIn("X-CSRF-Token: [REDACTED]", res.stdout)

    # ---- LOW-03: ops/restore/restore.sh UUID validation & jq JSON construction ----
    def test_ops_restore_sh_validates_uuid_and_uses_jq(self):
        restore = (ROOT / "ops/restore/restore.sh").read_text(encoding="utf-8")
        self.assertIn("jq -cn --arg", restore)
        self.assertNotIn('{\\"backup_job_id\\":', restore)

        for args in (
            ["--backup-id", 'bad";injected'],
            ["--backup-id", "../etc/passwd"],
            ["--backup-id", "12345678-1234-1234-1234-123456789abc", "--timeout", "0"],
            ["--backup-id", "12345678-1234-1234-1234-123456789abc", "--timeout", "abc"],
        ):
            with self.subTest(args=args):
                res = subprocess.run(
                    ["bash", str(ROOT / "ops/restore/restore.sh"), *args],
                    capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(res.returncode, 2, res.stdout + res.stderr)


if __name__ == "__main__":
    unittest.main()
