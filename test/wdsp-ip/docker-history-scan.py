#!/usr/bin/env python3
"""AT-02: scan a real Docker image after a later layer deletes source code.

Requires the pinned Alpine image to already be cached. No image pulls, network,
live-service changes, or customer inputs are used. Evidence stays in --output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import uuid
from datetime import datetime, timezone


REPO = Path(__file__).resolve().parents[2]
SCANNER = REPO / "ops/offline-package/scan.py"
BASE = "sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d"
SOURCE_PATH = "wdsp-ip-sample/internal.go"


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command, text=True, capture_output=True, check=True,
                          timeout=120, **kwargs)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True,
                        help="New evidence directory; existing directories are never overwritten")
    args = parser.parse_args()
    base = run(["docker", "image", "inspect", BASE, "--format",
                "{{.Id}} {{.Os}}/{{.Architecture}}"]).stdout.strip().split()
    if len(base) != 2 or base[0] != BASE:
        raise RuntimeError("Pinned cached image identity mismatch")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    identity = uuid.uuid4().hex
    image_tag = f"wdsp-ip-history-test:{identity}"
    container_name = f"wdsp-ip-history-test-{identity}"
    image_created = False
    container_created = False
    try:
        with tempfile.TemporaryDirectory(prefix="wdsp-ip-history-context-") as directory:
            context = Path(directory)
            source = b"// Synthetic first-party source for AT-02; not a credential.\npackage historical\n"
            (context / "internal.go").write_bytes(source)
            dockerfile = (f"FROM {BASE}\n"
                          f"COPY internal.go /{SOURCE_PATH}\n"
                          f"RUN rm /{SOURCE_PATH}\n")
            (context / "Dockerfile").write_text(dockerfile, encoding="utf-8")
            # Legacy builder consumes the local image ID without registry resolution.
            result = run(["docker", "build", "--pull=false", "--network=none",
                          "--no-cache", "--rm", "--force-rm", "--tag", image_tag, str(context)],
                         env={**os.environ, "DOCKER_BUILDKIT": "0"})
            image_created = True
            (output / "build.log").write_text(result.stdout + result.stderr, encoding="utf-8")
        image_id = run(["docker", "image", "inspect", image_tag, "--format", "{{.Id}}"]).stdout.strip()
        run(["docker", "create", "--network=none", "--name", container_name,
             image_tag, "/bin/true"])
        container_created = True
        flattened = output / "final-filesystem.tar"
        run(["docker", "export", "--output", str(flattened), container_name])
        with tarfile.open(flattened) as archive:
            if any(member.name.lstrip("./") == SOURCE_PATH for member in archive):
                raise AssertionError("Source is still present in the final filesystem")
        images = output / "input/images"
        images.mkdir(parents=True)
        image_archive = images / "history.tar"
        run(["docker", "save", "--output", str(image_archive), image_tag])
        report_path = output / "scan.json"
        command = [sys.executable, str(SCANNER), "--root", str(output / "input"),
                   "--output", str(report_path), "--product", "wdsp", "--version", "1.0.0",
                   "--platform", base[1]]
        scan = subprocess.run(command, text=True, capture_output=True, timeout=120, check=False)
        (output / "scan.log").write_text(scan.stdout + scan.stderr, encoding="utf-8")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        source_findings = [finding for finding in report["findings"]
                           if finding["rule"] == "source-artifact"
                           and finding["location"].endswith("!" + SOURCE_PATH)]
        if scan.returncode != 1 or report["result"] != "REJECT" or not source_findings:
            raise AssertionError("Historical source was not detected and rejected")
        if not report["coverage"]["complete"]:
            raise AssertionError("Incomplete scan cannot prove historical layer coverage")
        evidence = {
            "acceptance": "AT-02",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "result": "PASS",
            "scope": "Real local Docker image; source deleted in a subsequent layer",
            "platform": base[1],
            "base_image_id": base[0],
            "image_id": image_id,
            "image_archive_sha256": sha256(image_archive),
            "final_filesystem_sha256": sha256(flattened),
            "fixture_sha256": hashlib.sha256(source).hexdigest(),
            "dockerfile": dockerfile,
            "scanner_sha256": sha256(SCANNER),
            "scanner_version": report["scanner_version"],
            "policy_version": report["policy_version"],
            "scan_report_sha256": sha256(report_path),
            "scanner_exit_code": scan.returncode,
            "final_filesystem_source_present": False,
            "historical_source_findings": source_findings,
            "coverage": report["coverage"],
            "limitations": ["Single cached linux/arm64 test image, not the delivery platform matrix",
                            "Scanner rejection verified; no formal signing or release attempted"],
        }
        (output / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        print(f"Docker historical source scan passed; evidence: {output / 'evidence.json'}")
    finally:
        # Only the unique test-owned names are removed; cached base and evidence stay.
        if container_created:
            run(["docker", "rm", container_name])
        if image_created:
            run(["docker", "image", "rm", "--no-prune", image_tag])


if __name__ == "__main__":
    main()
