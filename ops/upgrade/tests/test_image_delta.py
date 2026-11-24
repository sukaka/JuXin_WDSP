"""Unit tests for ops/upgrade/image-delta.py (layer-delta create, inspect, check-base, apply)."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
DELTA_TOOL = ROOT / "ops" / "upgrade" / "image-delta.py"
RUNTIME_IMG = ROOT / "ops" / "offline-package" / "runtime-image.py"


def make_layer_tar(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for name, data in files.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mode = 0o644
            ti.mtime = 1700000000
            tf.addfile(ti, io.BytesIO(data))
    raw = buf.getvalue()
    return raw, "sha256:" + hashlib.sha256(raw).hexdigest()


def make_docker_save(path, repo_tag, layer_blobs, *, compress_blobs=False, labels=None):
    diff_ids = [did for _, did in layer_blobs]
    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {"Labels": dict(labels or {})},
        "rootfs": {"type": "layers", "diff_ids": diff_ids},
    }
    cfg_bytes = json.dumps(config, sort_keys=True, separators=(",", ":")).encode("utf-8")
    cfg_name = hashlib.sha256(cfg_bytes).hexdigest() + ".json"
    layer_names = []
    with tarfile.open(path, "w") as tf:
        ti = tarfile.TarInfo(cfg_name)
        ti.size = len(cfg_bytes)
        tf.addfile(ti, io.BytesIO(cfg_bytes))
        for idx, (raw, did) in enumerate(layer_blobs):
            payload = gzip.compress(raw) if compress_blobs else raw
            name = (
                f"blobs/sha256/{hashlib.sha256(payload).hexdigest()}"
                if compress_blobs
                else f"{idx}-{did.split(':', 1)[1]}/layer.tar"
            )
            lti = tarfile.TarInfo(name)
            lti.size = len(payload)
            tf.addfile(lti, io.BytesIO(payload))
            layer_names.append(name)
        man_bytes = json.dumps(
            [{"Config": cfg_name, "RepoTags": [repo_tag], "Layers": layer_names}]
        ).encode("utf-8")
        mti = tarfile.TarInfo("manifest.json")
        mti.size = len(man_bytes)
        tf.addfile(mti, io.BytesIO(man_bytes))
    return diff_ids


def run_tool(*args, check=True):
    proc = subprocess.run(
        [sys.executable, str(DELTA_TOOL), *map(str, args)],
        capture_output=True,
        text=True,
    )
    if check and proc.returncode != 0:
        raise AssertionError(f"image-delta failed ({proc.returncode}): {proc.stderr}\n{proc.stdout}")
    return proc


class ImageDeltaTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="wdsp-delta-test-")
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_roundtrip_classic_and_containerd_gzip_blobs_with_duplicate_empty_layers(self):
        big_base = make_layer_tar({"assets/geo/city.mmdb": b"A" * (2 * 1024 * 1024)})
        empty = make_layer_tar({})
        old_app = make_layer_tar({"usr/share/caddy/index.html": b"v1.0.0"})
        new_app = make_layer_tar({"usr/share/caddy/index.html": b"v1.0.1"})

        base_tar = self.dir / "base-containerd.tar"
        target_tar = self.dir / "target.tar"
        base_dids = make_docker_save(
            base_tar,
            "jiuzhang-web:1.0.0",
            [big_base, empty, old_app, empty],
            compress_blobs=True,
        )
        target_dids = make_docker_save(
            target_tar,
            "jiuzhang-web:1.0.1",
            [big_base, empty, new_app, empty],
            compress_blobs=True,
        )

        delta_out = self.dir / "web-amd64.tar.gz"
        res = json.loads(
            run_tool(
                "create",
                "--target-tar",
                target_tar,
                "--target-image",
                "jiuzhang-web:1.0.1",
                "--base-diff-ids-json",
                json.dumps(base_dids),
                "--output",
                delta_out,
                "--min-savings-bytes",
                "1024",
            ).stdout
        )
        self.assertEqual(res["delivery_mode"], "layer-delta")
        self.assertEqual(res["diff_ids"], target_dids)
        self.assertEqual(res["base_layers"], [big_base[1], empty[1]])
        # Delta archive should be tiny compared to 2MB base layer
        self.assertLess(delta_out.stat().st_size, 100 * 1024)

        # check-base succeeds with actual base layers, fails if missing
        run_tool(
            "check-base",
            "--required-base-layers-json",
            json.dumps(res["base_layers"]),
            "--actual-layers-json",
            json.dumps(base_dids),
        )
        bad_check = run_tool(
            "check-base",
            "--required-base-layers-json",
            json.dumps(res["base_layers"]),
            "--actual-layers-json",
            json.dumps([empty[1]]),
            check=False,
        )
        self.assertNotEqual(bad_check.returncode, 0)

        # apply reconstructs a valid full docker archive matching target diff_ids
        reconstructed = self.dir / "reconstructed.tar"
        run_tool(
            "apply",
            "--delta-tar",
            delta_out,
            "--base-tar",
            base_tar,
            "--expected-base-layers-json",
            json.dumps(res["base_layers"]),
            "--expected-image",
            "jiuzhang-web:1.0.1",
            "--output",
            reconstructed,
        )
        with tarfile.open(reconstructed, "r") as tf:
            man = json.loads(tf.extractfile("manifest.json").read())[0]
            self.assertEqual(man["RepoTags"], ["jiuzhang-web:1.0.1"])
            cfg = json.loads(tf.extractfile(man["Config"]).read())
            self.assertEqual(cfg["rootfs"]["diff_ids"], target_dids)
            self.assertEqual(len(man["Layers"]), 4)
            # Verify actual layer hashes match diff_ids
            for layer_name, expected_did in zip(man["Layers"], target_dids):
                actual = "sha256:" + hashlib.sha256(tf.extractfile(layer_name).read()).hexdigest()
                self.assertEqual(actual, expected_did)

    def test_sanitize_runtime_matches_runtime_image_py_diff_ids(self):
        layer0 = make_layer_tar(
            {
                "app/bin/server": b"ELF" * 200000,
                "docs/manual.md": b"should be removed",
                "LICENSE.txt": b"Apache-2.0 keep me",
                "app/foo_test.go": b"remove test",
            }
        )
        raw_tar = self.dir / "raw.tar"
        make_docker_save(raw_tar, "jiuzhang-server:1.11.1", [layer0])

        # Reference output from ops/offline-package/runtime-image.py
        ref_tar = self.dir / "ref-runtime.tar"
        subprocess.check_call(
            [
                sys.executable,
                str(RUNTIME_IMG),
                str(raw_tar),
                str(ref_tar),
                "--repository",
                "jiuzhang-runtime-jiuzhang-server",
                "--source-ref",
                "jiuzhang-server:1.11.1",
            ],
            stdout=subprocess.DEVNULL,
        )
        ref_info = json.loads(
            run_tool("inspect-base", "--archive", ref_tar, "--component", "api").stdout
        )
        self.assertTrue(ref_info["api"]["runtime_sanitized"])

        # Now build target 1.11.2 with identical layer0 + new layer1 and --sanitize-runtime
        layer1 = make_layer_tar({"app/bin/delta": b"new-binary"})
        target_tar = self.dir / "target-1.11.2.tar"
        make_docker_save(target_tar, "jiuzhang-server:1.11.2", [layer0, layer1])

        out_delta = self.dir / "api-amd64.tar.gz"
        res = json.loads(
            run_tool(
                "create",
                "--target-tar",
                target_tar,
                "--target-image",
                "jiuzhang-server:1.11.2",
                "--base-diff-ids-json",
                json.dumps(ref_info["api"]["diff_ids"]),
                "--output",
                out_delta,
                "--sanitize-runtime",
                "--min-savings-bytes",
                "1024",
            ).stdout
        )
        self.assertEqual(res["delivery_mode"], "layer-delta")
        self.assertTrue(res["runtime_sanitized"])
        self.assertEqual(res["base_layers"], ref_info["api"]["diff_ids"])

    def test_fallback_to_full_when_savings_below_threshold(self):
        small_base = make_layer_tar({"a.txt": b"tiny"})
        new_app = make_layer_tar({"b.txt": b"app"})
        target_tar = self.dir / "t.tar"
        dids = make_docker_save(target_tar, "jiuzhang-logrotator:1.11.2", [small_base, new_app])
        out = self.dir / "logrotator-amd64.tar.gz"
        res = json.loads(
            run_tool(
                "create",
                "--target-tar",
                target_tar,
                "--target-image",
                "jiuzhang-logrotator:1.11.2",
                "--base-diff-ids-json",
                json.dumps([small_base[1]]),
                "--output",
                out,
                "--min-savings-bytes",
                "1048576",
            ).stdout
        )
        self.assertEqual(res["delivery_mode"], "full")
        self.assertEqual(res["base_layers"], [])
        self.assertEqual(res["diff_ids"], dids)
        with tarfile.open(out, "r:gz") as tf:
            self.assertIn("manifest.json", tf.getnames())

    def test_inspect_base_merges_offline_and_chained_upgrade_archives(self):
        l_api_v1 = make_layer_tar({"api": b"v1"})
        l_web_v1 = make_layer_tar({"web": b"v1"})
        l_web_v2 = make_layer_tar({"web": b"v2"})

        api_v1_tar = self.dir / "jiuzhang-server.tar"
        web_v1_tar = self.dir / "jiuzhang-web.tar"
        d_api_v1 = make_docker_save(api_v1_tar, "jiuzhang-server:1.11.0", [l_api_v1])
        d_web_v1 = make_docker_save(web_v1_tar, "jiuzhang-web:1.11.0", [l_web_v1])

        offline_pkg = self.dir / "jiuzhang-wdsp-update-full-1.11.0-amd64.tar.gz"
        with tarfile.open(offline_pkg, "w:gz") as tf:
            root = "jiuzhang-wdsp-offline-1.11.0-amd64"
            man = json.dumps({"edition": "wdsp", "version": "1.11.0"}).encode()
            ti = tarfile.TarInfo(f"{root}/manifest.json")
            ti.size = len(man)
            tf.addfile(ti, io.BytesIO(man))
            tf.add(api_v1_tar, arcname=f"{root}/images/jiuzhang-server.tar")
            tf.add(web_v1_tar, arcname=f"{root}/images/jiuzhang-web.tar")

        upgrade_pkg = self.dir / "jiuzhang-wdsp-upgrade-1.11.1-amd64.tar.gz"
        with tarfile.open(upgrade_pkg, "w:gz") as tf:
            root = "jiuzhang-wdsp-upgrade-1.11.1-amd64"
            man = json.dumps(
                {
                    "package_type": "upgrade",
                    "version": "1.11.1",
                    "images": [
                        {
                            "component": "web",
                            "service": "web",
                            "image": "jiuzhang-web:1.11.1",
                            "tar": "images/web-amd64.tar.gz",
                            "delivery_mode": "layer-delta",
                            "base_layers": d_web_v1,
                            "diff_ids": [l_web_v1[1], l_web_v2[1]],
                            "runtime_sanitized": True,
                        }
                    ],
                }
            ).encode()
            ti = tarfile.TarInfo(f"{root}/manifest.json")
            ti.size = len(man)
            tf.addfile(ti, io.BytesIO(man))

        merged = json.loads(
            run_tool("inspect-base", "--archive", offline_pkg, "--archive", upgrade_pkg).stdout
        )
        self.assertEqual(merged["api"]["diff_ids"], d_api_v1)
        self.assertEqual(merged["web"]["diff_ids"], [l_web_v1[1], l_web_v2[1]])
        self.assertTrue(merged["web"]["runtime_sanitized"])

    def test_apply_rejects_tampered_delta_or_outer_base_mismatch_or_symlink(self):
        base_layer = make_layer_tar({"geo.mmdb": b"X" * 10000})
        new_layer = make_layer_tar({"app.js": b"console.log(1)"})
        base_tar = self.dir / "base.tar"
        target_tar = self.dir / "target.tar"
        base_dids = make_docker_save(base_tar, "jiuzhang-web:1.0.0", [base_layer])
        make_docker_save(target_tar, "jiuzhang-web:1.0.1", [base_layer, new_layer])
        delta_out = self.dir / "delta.tar.gz"
        res = json.loads(
            run_tool(
                "create",
                "--target-tar",
                target_tar,
                "--target-image",
                "jiuzhang-web:1.0.1",
                "--base-diff-ids-json",
                json.dumps(base_dids),
                "--output",
                delta_out,
                "--min-savings-bytes",
                "1024",
            ).stdout
        )

        # 1. Outer base_layers mismatch
        p1 = run_tool(
            "apply",
            "--delta-tar",
            delta_out,
            "--base-tar",
            base_tar,
            "--expected-base-layers-json",
            json.dumps(["sha256:" + "0" * 64]),
            "--expected-image",
            "jiuzhang-web:1.0.1",
            "--output",
            self.dir / "out1.tar",
            check=False,
        )
        self.assertNotEqual(p1.returncode, 0)

        # 2. Expected image name mismatch
        p2 = run_tool(
            "apply",
            "--delta-tar",
            delta_out,
            "--base-tar",
            base_tar,
            "--expected-base-layers-json",
            json.dumps(res["base_layers"]),
            "--expected-image",
            "jiuzhang-web:9.9.9",
            "--output",
            self.dir / "out2.tar",
            check=False,
        )
        self.assertNotEqual(p2.returncode, 0)

        # 3. Tampered delta layer payload
        tampered = self.dir / "tampered.tar.gz"
        with tarfile.open(delta_out, "r:gz") as src, tarfile.open(tampered, "w:gz") as dst:
            for m in src.getmembers():
                data = src.extractfile(m).read()
                if m.name.startswith("layers/"):
                    data = b"Z" + data[1:]
                ti = tarfile.TarInfo(m.name)
                ti.size = len(data)
                dst.addfile(ti, io.BytesIO(data))
        p3 = run_tool(
            "apply",
            "--delta-tar",
            tampered,
            "--base-tar",
            base_tar,
            "--expected-base-layers-json",
            json.dumps(res["base_layers"]),
            "--expected-image",
            "jiuzhang-web:1.0.1",
            "--output",
            self.dir / "out3.tar",
            check=False,
        )
        self.assertNotEqual(p3.returncode, 0)

        # 4. Symlink entry rejected
        evil = self.dir / "evil.tar.gz"
        with tarfile.open(evil, "w:gz") as tf:
            ti = tarfile.TarInfo("evil-link")
            ti.type = tarfile.SYMTYPE
            ti.linkname = "/etc/passwd"
            tf.addfile(ti)
        p4 = run_tool(
            "apply",
            "--delta-tar",
            evil,
            "--base-tar",
            base_tar,
            "--expected-base-layers-json",
            json.dumps(res["base_layers"]),
            "--expected-image",
            "jiuzhang-web:1.0.1",
            "--output",
            self.dir / "out4.tar",
            check=False,
        )
        self.assertNotEqual(p4.returncode, 0)


if __name__ == "__main__":
    unittest.main()
