import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("runtime_image", Path(__file__).resolve().parents[2] / "ops/offline-package/runtime-image.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RuntimeImageTests(unittest.TestCase):
    def test_preserves_runtime_config_and_rehashes_layers(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, dst = Path(tmp) / "in.tar", Path(tmp) / "out.tar"
            layer = io.BytesIO()
            with tarfile.open(fileobj=layer, mode="w") as archive:
                for name in ["usr/bin/app", "usr/share/doc/manual.txt", "app/README.md", "src/test/run.pl", "usr/share/licenses/LICENSE"]:
                    MODULE.add_bytes(archive, name, b"payload")
            runtime = {"Entrypoint": ["/usr/bin/app"], "Env": ["MODE=prod"], "User": "1000",
                       "Volumes": {"/data": {}}, "Healthcheck": {"Test": ["CMD", "/usr/bin/app", "check"]}}
            config = {"architecture": "amd64", "os": "linux", "config": runtime,
                      "rootfs": {"type": "layers", "diff_ids": ["sha256:old"]}}
            with tarfile.open(src, "w") as archive:
                MODULE.add_bytes(archive, "config.json", json.dumps(config).encode())
                MODULE.add_bytes(archive, "layer.tar", layer.getvalue())
                MODULE.add_bytes(archive, "manifest.json", json.dumps([{"Config": "config.json", "Layers": ["layer.tar"]}]).encode())
            metadata = MODULE.sanitize(src, dst, "runtime-app", "source:1.0")
            self.assertEqual(metadata["removed_entries"], 3)
            with tarfile.open(dst) as archive:
                manifest = json.load(archive.extractfile("manifest.json"))[0]
                self.assertEqual(manifest["RepoTags"], [metadata["image"]])
                raw_config = archive.extractfile(manifest["Config"]).read()
                new_config = json.loads(raw_config)
                for key, value in runtime.items():
                    self.assertEqual(new_config["config"][key], value)
                self.assertEqual(metadata["digest"], "sha256:" + hashlib.sha256(raw_config).hexdigest())
                raw_layer = archive.extractfile(manifest["Layers"][0]).read()
                self.assertEqual(new_config["rootfs"]["diff_ids"], ["sha256:" + hashlib.sha256(raw_layer).hexdigest()])
                with tarfile.open(fileobj=io.BytesIO(raw_layer)) as contents:
                    self.assertEqual(contents.getnames(), ["usr/bin/app", "usr/share/licenses/LICENSE"])

    def test_rejects_unsafe_paths(self):
        for name in ["/etc/passwd", "a/../../etc/passwd"]:
            with self.assertRaises(ValueError):
                MODULE.excluded(name)

    def test_preserves_runtime_test_command(self):
        self.assertFalse(MODULE.excluded("usr/bin/test"))
        self.assertTrue(MODULE.excluded("src/test", True))
        self.assertTrue(MODULE.excluded("src/test/run.pl"))
